/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import {
  SignJWT,
  calculateJwkThumbprint,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
  type KeyInput,
} from "jose";

import { ProofError, SecretValue } from "./index.js";
import type { DpopProofProvider, DpopProofRequest, Signer } from "./reactor.js";

export type JoseAlgorithm = "ES256" | "RS256";

const privateJwkMembers = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);

function algorithm(value: string): JoseAlgorithm {
  if (value !== "ES256" && value !== "RS256") {
    throw new TypeError("PAP JOSE algorithms must be ES256 or RS256");
  }
  return value;
}

function publicJwk(value: JWK, alg: JoseAlgorithm): JWK {
  for (const member of privateJwkMembers) {
    if (member in value) {
      throw new TypeError("DPoP public JWK must not contain private key material");
    }
  }
  const expected = alg === "ES256" ? "EC" : "RSA";
  if (value.kty !== expected) throw new TypeError(`${alg} requires a ${expected} public JWK`);
  if (alg === "ES256") {
    if (value.crv !== "P-256" || !value.x || !value.y) {
      throw new TypeError("ES256 requires a complete P-256 public JWK");
    }
  } else if (!value.n || !value.e) {
    throw new TypeError("RS256 requires a complete RSA public JWK");
  }
  return { ...value };
}

function normalizedHtu(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new ProofError("invalid_htu", "DPoP target must be an HTTPS URL", { cause });
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new ProofError("invalid_htu", "DPoP target must be an HTTPS URL");
  }
  url.search = "";
  url.hash = "";
  return url.href;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function randomBytes(length: number): Uint8Array {
  if (!globalThis.crypto) throw new ProofError("crypto_unavailable", "Web Crypto is required");
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

async function accessTokenHash(token: SecretValue): Promise<string> {
  if (!globalThis.crypto) throw new ProofError("crypto_unavailable", "Web Crypto is required");
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token.reveal()),
  );
  return base64Url(new Uint8Array(digest));
}

export interface JoseSignerOptions {
  readonly privateKey: KeyInput;
  readonly algorithm?: JoseAlgorithm;
  readonly keyId?: string;
}

/** Sign PAP assertions with an injected asymmetric private key or handle. */
export class JoseSigner implements Signer {
  readonly #privateKey: KeyInput;
  readonly #algorithm: JoseAlgorithm;
  readonly #keyId: string | undefined;

  constructor(options: JoseSignerOptions) {
    this.#privateKey = options.privateKey;
    this.#algorithm = algorithm(options.algorithm ?? "ES256");
    this.#keyId = options.keyId;
  }

  async sign(
    claims: Readonly<Record<string, unknown>>,
    _options: { readonly purpose: string },
  ): Promise<SecretValue> {
    try {
      const token = await new SignJWT(claims as JWTPayload)
        .setProtectedHeader({
          alg: this.#algorithm,
          typ: "JWT",
          ...(this.#keyId === undefined ? {} : { kid: this.#keyId }),
        })
        .sign(this.#privateKey);
      return new SecretValue(token);
    } catch (cause) {
      throw new ProofError("signing_failed", "Could not sign PAP assertion", { cause });
    }
  }
}

export interface DpopKeyMaterial {
  readonly privateKey: KeyInput;
  readonly publicJwk: JWK;
  readonly algorithm?: JoseAlgorithm;
}

/**
 * Where Session Keys live: made one per Session, found by thumbprint, then forgotten.
 *
 * A host keeps them in its KMS or HSM; `InMemorySessionKeys` is for one process.
 */
export interface SessionKeyCustody {
  generate(options: { readonly tenantId: string; readonly issuer: string }): Promise<DpopKeyMaterial>;
  get(options: {
    readonly tenantId: string;
    readonly issuer: string;
    readonly thumbprint: string;
  }): Promise<DpopKeyMaterial | undefined>;
  discard(options: {
    readonly tenantId: string;
    readonly issuer: string;
    readonly thumbprint: string;
  }): Promise<void>;
}

/** A public JWK's RFC 7638 SHA-256 thumbprint: a Session Key's name (§4.3). */
export function jwkThumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, "sha256");
}

/** Session Keys in this process's memory: a new P-256 key for each Session (§4.3). */
export class InMemorySessionKeys implements SessionKeyCustody {
  readonly #keys = new Map<string, DpopKeyMaterial>();

  async generate(options: {
    readonly tenantId: string;
    readonly issuer: string;
  }): Promise<DpopKeyMaterial> {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const exported = await exportJWK(publicKey);
    const publicJwk: JWK = {
      kty: exported.kty as string,
      crv: exported.crv as string,
      x: exported.x as string,
      y: exported.y as string,
    };
    const material: DpopKeyMaterial = { privateKey, publicJwk };
    const thumbprint = await jwkThumbprint(material.publicJwk);
    this.#keys.set(JSON.stringify([options.tenantId, options.issuer, thumbprint]), material);
    return material;
  }

  async get(options: {
    readonly tenantId: string;
    readonly issuer: string;
    readonly thumbprint: string;
  }): Promise<DpopKeyMaterial | undefined> {
    return this.#keys.get(JSON.stringify([options.tenantId, options.issuer, options.thumbprint]));
  }

  async discard(options: {
    readonly tenantId: string;
    readonly issuer: string;
    readonly thumbprint: string;
  }): Promise<void> {
    this.#keys.delete(JSON.stringify([options.tenantId, options.issuer, options.thumbprint]));
  }
}

export interface JoseDpopProofProviderOptions {
  readonly keys: SessionKeyCustody;
  readonly now?: () => Date;
  readonly randomBytes?: (length: number) => Uint8Array;
}

/** Create fresh RFC 9449 proofs, each with the key of its own Session (§4.3). */
export class JoseDpopProofProvider implements DpopProofProvider {
  readonly keys: SessionKeyCustody;
  readonly #now: () => Date;
  readonly #randomBytes: (length: number) => Uint8Array;

  constructor(options: JoseDpopProofProviderOptions) {
    this.keys = options.keys;
    this.#now = options.now ?? (() => new Date());
    this.#randomBytes = options.randomBytes ?? randomBytes;
  }

  async newSessionKey(options: {
    readonly tenantId: string;
    readonly issuer: string;
  }): Promise<string> {
    const material = await this.keys.generate(options);
    return jwkThumbprint(material.publicJwk);
  }

  async discardSessionKey(options: {
    readonly tenantId: string;
    readonly issuer: string;
    readonly sessionKey: string;
  }): Promise<void> {
    await this.keys.discard({
      tenantId: options.tenantId,
      issuer: options.issuer,
      thumbprint: options.sessionKey,
    });
  }

  async create(request: DpopProofRequest): Promise<SecretValue> {
    const material = await this.keys.get({
      tenantId: request.tenantId,
      issuer: request.issuer,
      thumbprint: request.sessionKey,
    });
    if (material === undefined) {
      // A key this provider never made, or one it discarded: never a stand-in (§4.2).
      throw new ProofError("unknown_session_key", "No Session Key with that thumbprint");
    }
    const alg = algorithm(material.algorithm ?? "ES256");
    const jwk = publicJwk(material.publicJwk, alg);
    const entropy = this.#randomBytes(16);
    if (entropy.byteLength < 16) {
      throw new ProofError("weak_randomness", "DPoP proof IDs require 128 random bits");
    }
    const claims: JWTPayload = {
      jti: base64Url(entropy),
      htm: request.method.toUpperCase(),
      htu: normalizedHtu(request.url),
      iat: Math.floor(this.#now().getTime() / 1000),
      ...(request.nonce === undefined ? {} : { nonce: request.nonce }),
      ...(request.accessToken === undefined
        ? {}
        : { ath: await accessTokenHash(request.accessToken) }),
    };
    try {
      const token = await new SignJWT(claims)
        .setProtectedHeader({ typ: "dpop+jwt", alg, jwk })
        .sign(material.privateKey);
      return new SecretValue(token);
    } catch (cause) {
      throw new ProofError("signing_failed", "Could not sign DPoP proof", { cause });
    }
  }
}

export interface DpopReplayCache {
  markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean>;
}

export interface VerifyDpopProofOptions {
  readonly method: string;
  readonly url: string;
  readonly replayCache: DpopReplayCache;
  readonly accessToken?: SecretValue;
  readonly nonce?: string;
  readonly now?: Date;
  readonly acceptanceWindowSeconds?: number;
}

export interface VerifiedDpopProof {
  readonly jti: string;
  readonly issuedAt: Date;
  readonly publicJwk: JWK;
  readonly keyThumbprint: string;
  /** The `nonce` the proof carried, for a company that requires ones it issued (§4.3). */
  readonly nonce?: string;
}

/** Verify signature, binding, freshness, nonce, token hash, and replay state. */
export async function verifyDpopProof(
  proof: SecretValue | string,
  options: VerifyDpopProofOptions,
): Promise<VerifiedDpopProof> {
  const compact = proof instanceof SecretValue ? proof.reveal() : proof;
  if (compact.split(".").length !== 3 || /[, \t]/u.test(compact)) {
    // One `DPoP` header holding one compact JWT: two headers joined are refused (§4.3).
    throw new ProofError("invalid_dpop_proof", "DPoP header is not one compact JWT");
  }
  const now = options.now ?? new Date();
  const windowSeconds = options.acceptanceWindowSeconds ?? 60;
  if (!Number.isInteger(windowSeconds) || windowSeconds <= 0) {
    throw new RangeError("acceptanceWindowSeconds must be a positive integer");
  }
  let jwk: JWK;
  let payload: JWTPayload;
  try {
    const header = decodeProtectedHeader(compact);
    const alg = algorithm(header.alg ?? "");
    if (header.typ !== "dpop+jwt" || typeof header.jwk !== "object") {
      throw new ProofError("invalid_dpop_proof", "DPoP protected header is invalid");
    }
    jwk = publicJwk(header.jwk, alg);
    const key = await importJWK(jwk, alg);
    ({ payload } = await jwtVerify(compact, key, {
      algorithms: [alg],
      typ: "dpop+jwt",
      requiredClaims: ["jti", "htm", "htu", "iat"],
      // A proof's optional exp/nbf are read on the verifier's clock, not the wall's.
      currentDate: now,
    }));
  } catch (cause) {
    if (cause instanceof ProofError) throw cause;
    throw new ProofError("invalid_dpop_proof", "DPoP signature or claims are invalid", {
      cause,
    });
  }
  // At least 16 characters (96+ bits): a short `jti` is guessable, so a replay key collides.
  if (
    typeof payload.jti !== "string" ||
    payload.jti.length < 16 ||
    payload.jti.length > 256 ||
    typeof payload.iat !== "number"
  ) {
    throw new ProofError("invalid_dpop_proof", "DPoP proof identity is invalid");
  }
  const issuedAt = new Date(payload.iat * 1000);
  const difference = Math.abs(now.getTime() - issuedAt.getTime());
  if (difference > windowSeconds * 1000) {
    throw new ProofError("invalid_dpop_proof", "DPoP proof is outside the acceptance window");
  }
  if (payload.htm !== options.method.toUpperCase() || payload.htu !== normalizedHtu(options.url)) {
    throw new ProofError("invalid_dpop_proof", "DPoP proof does not match the request");
  }
  if (options.nonce !== undefined && payload.nonce !== options.nonce) {
    throw new ProofError("use_dpop_nonce", "DPoP proof nonce is missing or invalid");
  }
  if (options.accessToken !== undefined) {
    if (
      typeof payload.ath !== "string" ||
      !constantTimeEqual(payload.ath, await accessTokenHash(options.accessToken))
    ) {
      throw new ProofError("invalid_dpop_proof", "DPoP access-token hash is invalid");
    }
  } else if (payload.ath !== undefined) {
    throw new ProofError(
      "invalid_dpop_proof",
      "Token-endpoint DPoP proof must not contain ath",
    );
  }
  const keyThumbprint = await calculateJwkThumbprint(jwk);
  if (
    !(await options.replayCache.markOnce(`${keyThumbprint}:${payload.jti}`, {
      // Remembered for as long as the proof would be accepted: until `iat` leaves the window.
      expiresAt: new Date(issuedAt.getTime() + windowSeconds * 1000),
    }))
  ) {
    throw new ProofError("invalid_dpop_proof", "DPoP proof has already been used");
  }
  const carried = payload.nonce;
  return {
    jti: payload.jti,
    issuedAt,
    publicJwk: jwk,
    keyThumbprint,
    ...(typeof carried === "string" ? { nonce: carried } : {}),
  };
}

/** Whether two strings are equal, in time that does not depend on where they differ. */
function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}
