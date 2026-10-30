/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Blind signing of client assertions and delegations (§10.7, RFC 9474).
 *
 * `BlindJoseSigner` is a `pap.signer` that runs on the User's device: it writes the JWT,
 * draws nothing the key holder could guess, blinds the signing input with
 * RSABSSA-SHA384-PSS-Deterministic, and sends only the blinded message to a
 * `BlindSigningKey`, the holder of a key in `jwks_uri`. It unblinds the answer into an
 * ordinary `PS384` signature, which any company verifies like another.
 *
 * The variant adds no prefix to the message, so the signature verifies as a JWT's; it is
 * safe only because the message holds a value the signer can't guess: the `jti`, which the
 * device draws (`buildClientAssertionClaims`, `delegationClaims`). One signer signs both
 * client assertions and delegations: a key that signs blindly signs whatever a device sends
 * it, so its signature never means the agent's own systems approved what it signed (§10.7).
 */

import type { JWK } from "jose";

import { SIGNER_TYPES, base64Url } from "./crypto.js";
import { ProofError } from "./errors.js";
import type { Signer } from "./reactor.js";
import { SecretValue } from "./secret.js";

/**
 * RSABSSA-SHA384-PSS-Deterministic (RFC 9474 §5): SHA-384, MGF1 with SHA-384, a 48-byte salt,
 * and the identity preparation function. "Deterministic" names the message preparation: the
 * salt is random, so `PS384` verifies the signature.
 */
const HASH_LENGTH = 48;
const SALT_LENGTH = 48;
/** Smaller moduli are refused (RFC 9474 §7; 3072 bits is suggested). */
export const MIN_MODULUS_BITS = 2048;
/** A `jti` carries at least 128 random bits: 22 base64url characters (§5.2, §10.7). */
const MIN_JTI_LENGTH = 22;

/** The holder of a key in `jwks_uri`: it signs a blinded message, never seeing the JWT. */
export interface BlindSigningKey {
  blindSign(blinded: Uint8Array): Promise<Uint8Array>;
}

function fromBase64Url(value: string): Uint8Array {
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function toBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function toBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let rest = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return bytes;
}

function bitLength(value: bigint): number {
  return value.toString(2).length;
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let factor = base % modulus;
  let rest = exponent;
  while (rest > 0n) {
    if (rest & 1n) result = (result * factor) % modulus;
    factor = (factor * factor) % modulus;
    rest >>= 1n;
  }
  return result;
}

function gcd(left: bigint, right: bigint): bigint {
  let [a, b] = [left, right];
  while (b !== 0n) [a, b] = [b, a % b];
  return a;
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let [oldR, r] = [value % modulus, modulus];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldS, s] = [s, oldS - quotient * s];
  }
  return ((oldS % modulus) + modulus) % modulus;
}

async function sha384(...parts: readonly Uint8Array[]): Promise<Uint8Array> {
  const joined = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-384", joined));
}

async function mgf1(seed: Uint8Array, length: number): Promise<Uint8Array> {
  const output = new Uint8Array(length);
  let offset = 0;
  for (let counter = 0; offset < length; counter += 1) {
    const block = await sha384(seed, toBytes(BigInt(counter), 4));
    output.set(block.subarray(0, Math.min(block.byteLength, length - offset)), offset);
    offset += block.byteLength;
  }
  return output;
}

/** EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-384, MGF1-SHA-384, and `salt`. */
export async function emsaPssEncode(
  message: Uint8Array,
  modulusBits: number,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const emBits = modulusBits - 1;
  const emLength = Math.ceil(emBits / 8);
  if (emLength < HASH_LENGTH + salt.byteLength + 2) {
    throw new ProofError("signing_failed", "The modulus is too short for PS384");
  }
  const messageHash = await sha384(message);
  const digest = await sha384(new Uint8Array(8), messageHash, salt);
  const dataBlock = new Uint8Array(emLength - HASH_LENGTH - 1);
  dataBlock[dataBlock.length - salt.byteLength - 1] = 1;
  dataBlock.set(salt, dataBlock.length - salt.byteLength);
  const mask = await mgf1(digest, dataBlock.byteLength);
  const masked = dataBlock.map((byte, index) => byte ^ (mask[index] as number));
  masked[0] = (masked[0] as number) & (0xff >> (8 * emLength - emBits));
  const encoded = new Uint8Array(emLength);
  encoded.set(masked);
  encoded.set(digest, masked.byteLength);
  encoded[emLength - 1] = 0xbc;
  return encoded;
}

function rsaNumber(jwk: JWK, member: "n" | "e" | "d"): bigint {
  const value = jwk[member];
  if (typeof value !== "string" || !value) {
    throw new TypeError(`an RSA key needs its ${member}`);
  }
  return toBigInt(fromBase64Url(value));
}

/**
 * A reference `BlindSigningKey`: an RSA key of 2048 bits or more (3072 suggested).
 *
 * BlindSign (RFC 9474 §4.3): it raises the blinded message to its private exponent and checks
 * the result. Whoever holds it sees integers, never a claim. A real one sits in the agent's
 * KMS, and limits how many signatures each User can get (§10.7).
 */
export class RsaBlindSigningKey implements BlindSigningKey {
  readonly #n: bigint;
  readonly #e: bigint;
  readonly #d: bigint;

  /** `privateJwk`: the RSA key as a JWK (`n`, `e`, `d`). */
  constructor(privateJwk: JWK) {
    if (privateJwk.kty !== "RSA") throw new TypeError("a blind signing key is an RSA key");
    this.#n = rsaNumber(privateJwk, "n");
    this.#e = rsaNumber(privateJwk, "e");
    this.#d = rsaNumber(privateJwk, "d");
    if (bitLength(this.#n) < MIN_MODULUS_BITS) {
      throw new RangeError("a blind signing key has 2048 bits or more");
    }
  }

  async blindSign(blinded: Uint8Array): Promise<Uint8Array> {
    const message = toBigInt(blinded);
    if (blinded.byteLength !== Math.ceil(bitLength(this.#n) / 8) || message >= this.#n) {
      throw new ProofError("signing_failed", "The blinded message is out of range");
    }
    const signature = modPow(message, this.#d, this.#n);
    if (modPow(signature, this.#e, this.#n) !== message) {
      throw new ProofError("signing_failed", "The blind signature did not verify");
    }
    return toBytes(signature, blinded.byteLength);
  }
}

export interface BlindJoseSignerOptions {
  readonly key: BlindSigningKey;
  /** The public half of the `jwks_uri` key named `keyId`, as a JWK. */
  readonly publicKey: JWK;
  readonly keyId: string;
  readonly randomBytes?: (length: number) => Uint8Array;
}

/**
 * `pap.signer` on the User's device: PS384 signatures a key signs blindly (§10.7).
 *
 * `key` holds the private half. It signs client assertions and delegations alike, both
 * blindly, each with a `jti` the device drew.
 */
export class BlindJoseSigner implements Signer {
  readonly #key: BlindSigningKey;
  readonly #publicKey: JWK;
  readonly #n: bigint;
  readonly #e: bigint;
  readonly #keyId: string;
  readonly #randomBytes: (length: number) => Uint8Array;

  constructor(options: BlindJoseSignerOptions) {
    this.#key = options.key;
    this.#publicKey = options.publicKey;
    this.#n = rsaNumber(options.publicKey, "n");
    this.#e = rsaNumber(options.publicKey, "e");
    if (bitLength(this.#n) < MIN_MODULUS_BITS) {
      throw new RangeError("a blind signing key has 2048 bits or more");
    }
    this.#keyId = options.keyId;
    this.#randomBytes =
      options.randomBytes ??
      ((length) => globalThis.crypto.getRandomValues(new Uint8Array(length)));
  }

  /** A compact `PS384` JWT, its signing input never shown to the key holder. */
  async sign(
    claims: Readonly<Record<string, unknown>>,
    options: { readonly purpose: string },
  ): Promise<SecretValue> {
    const typ = SIGNER_TYPES[options.purpose];
    if (typ === undefined) {
      throw new ProofError("unknown_purpose", `Nothing is signed for ${options.purpose}`);
    }
    const { jti } = claims;
    if (typeof jti !== "string" || jti.length < MIN_JTI_LENGTH) {
      // The value the signer can't guess: the variant is unsafe without it (§10.7).
      throw new ProofError("weak_randomness", "A blindly signed JWT needs a device-drawn jti");
    }
    const encode = (part: unknown): string =>
      base64Url(new TextEncoder().encode(JSON.stringify(part)));
    const signingInput = `${encode({ alg: "PS384", typ, kid: this.#keyId })}.${encode(claims)}`;
    const signature = await this.#blindSignature(new TextEncoder().encode(signingInput));
    return new SecretValue(`${signingInput}.${base64Url(signature)}`);
  }

  async #blindSignature(message: Uint8Array): Promise<Uint8Array> {
    const n = this.#n;
    const bits = bitLength(n);
    const modulusLength = Math.ceil(bits / 8);
    const salt = this.#randomBytes(SALT_LENGTH);
    if (salt.byteLength < SALT_LENGTH) {
      throw new ProofError("weak_randomness", "PS384 needs a 48-byte salt");
    }
    const encoded = toBigInt(await emsaPssEncode(message, bits, salt));
    if (gcd(encoded, n) !== 1n) {
      throw new ProofError("signing_failed", "The encoded message is not invertible");
    }
    const blind = this.#blindingFactor(modulusLength);
    const blinded = (encoded * modPow(blind, this.#e, n)) % n;
    const answer = await this.#key.blindSign(toBytes(blinded, modulusLength));
    const final = toBytes((toBigInt(answer) * modInverse(blind, n)) % n, modulusLength);
    // Finalize verifies (RFC 9474 §4.4): a bad answer never leaves the device.
    const { kty, n: modulus, e } = this.#publicKey;
    const key = await globalThis.crypto.subtle.importKey(
      "jwk",
      { kty, n: modulus, e, ext: true } as JsonWebKey,
      { name: "RSA-PSS", hash: "SHA-384" },
      false,
      ["verify"],
    );
    const verified = await globalThis.crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: SALT_LENGTH },
      key,
      final as BufferSource,
      message as BufferSource,
    );
    if (!verified) throw new ProofError("signing_failed", "The blind signature did not verify");
    return final;
  }

  /** A uniform `r` in [1, n) with an inverse (RFC 9474 §4.2). */
  #blindingFactor(length: number): bigint {
    for (;;) {
      const candidate = toBigInt(this.#randomBytes(length));
      if (candidate >= 1n && candidate < this.#n && gcd(candidate, this.#n) === 1n) return candidate;
    }
  }
}
