/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * JOSE signing, delegated keys, and the Session JWT (§4.1, §5.2).
 *
 * - `JoseSigner` is the `pap.signer` default: a key from the agent's `jwks_uri` signs client
 *   assertions (`purpose: "client_assertion"`, `typ: JWT`) and delegations
 *   (`purpose: "delegation"`, `typ: pap-delegation+jwt`), with `ES256` or `PS384`.
 * - `DelegatedSessionSigner` is the `pap.sessionSigner` default: one delegated P-256 key per
 *   User ID (tenant, issuer, `sub`), vouched for by a delegation the `pap.signer` key signs,
 *   and a fresh Session JWT for each request. Keys live in a `DelegatedKeyCustody`;
 *   `InMemoryDelegatedKeys` is for one process.
 */

import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  type JWK,
  type JWTPayload,
  type KeyInput,
} from "jose";

import { ProofError } from "./errors.js";
import {
  Signers,
  firstContribution,
  type SessionJwtRequest,
  type SessionSigner,
  type Signer,
} from "./reactor.js";
import { SecretValue } from "./secret.js";
import type { ReactorPlatformView } from "@datalayer/reactor";

export type JoseAlgorithm = "ES256" | "PS384";

/** The algorithms a key in `jwks_uri` signs client assertions and delegations with (§4.1, §5.2). */
export const JOSE_ALGORITHMS: readonly JoseAlgorithm[] = ["ES256", "PS384"];
/** A Session JWT's `typ` and `alg` (§5.2). */
export const SESSION_JWT_TYPE = "poppy-session+jwt";
export const SESSION_JWT_ALGORITHM = "ES256";
/** A delegation's `typ` (§5.2). */
export const DELEGATION_TYPE = "pap-delegation+jwt";
/** A delegation expires at most this long after it is issued (§5.2). */
export const DELEGATION_MAX_LIFETIME_SECONDS = 24 * 60 * 60;
/** The `typ` each `pap.signer` purpose signs with. */
export const SIGNER_TYPES: Readonly<Record<string, string>> = {
  client_assertion: "JWT",
  delegation: DELEGATION_TYPE,
};
/** A Session ID: the characters of a Conversation ID, at least 128 random bits (§5.2, §8.2). */
export const SESSION_ID = /^[A-Za-z0-9_-]{22,256}$/;

const privateJwkMembers = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

function algorithm(value: string): JoseAlgorithm {
  if (value !== "ES256" && value !== "PS384") {
    throw new TypeError("PAP JOSE algorithms are ES256 and PS384");
  }
  return value;
}

export function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function systemRandomBytes(length: number): Uint8Array {
  if (!globalThis.crypto) throw new ProofError("crypto_unavailable", "Web Crypto is required");
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

/** `ath`: the access token's SHA-256, base64url-encoded (§5.2, as RFC 9449 §4.2). */
export async function tokenHash(accessToken: SecretValue | string): Promise<string> {
  if (!globalThis.crypto) throw new ProofError("crypto_unavailable", "Web Crypto is required");
  const value = accessToken instanceof SecretValue ? accessToken.reveal() : accessToken;
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest));
}

/** `htu`: the request's URL without its query or fragment (§5.2). */
export function normalizedHtu(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new ProofError("invalid_htu", "A Session JWT's target must be an HTTPS URL", { cause });
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new ProofError("invalid_htu", "A Session JWT's target must be an HTTPS URL");
  }
  url.search = "";
  url.hash = "";
  return url.href;
}

/** A public JWK with no private member: refused otherwise (§5.2). */
export function publicJwk(value: JWK): JWK {
  for (const member of privateJwkMembers) {
    if (member in value) throw new TypeError("a public JWK must not contain private key material");
  }
  return { ...value };
}

/** A public JWK's RFC 7638 SHA-256 thumbprint: a Session JWT's `kid` (§5.2). */
export function jwkThumbprint(jwk: JWK): Promise<string> {
  return calculateJwkThumbprint(jwk, "sha256");
}

export interface JoseSignerOptions {
  readonly privateKey: KeyInput;
  readonly algorithm?: JoseAlgorithm;
  readonly keyId?: string;
}

/**
 * Sign client assertions and delegations with a key from the agent's `jwks_uri`.
 *
 * `purpose` sets the header's `typ`: `client_assertion` signs a `JWT`, and `delegation` a
 * `pap-delegation+jwt` (§4.1, §5.2). `ES256` or `PS384`.
 */
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
    options: { readonly purpose: string },
  ): Promise<SecretValue> {
    const typ = SIGNER_TYPES[options.purpose];
    if (typ === undefined) {
      throw new ProofError("unknown_purpose", `Nothing is signed for ${options.purpose}`);
    }
    try {
      const token = await new SignJWT(claims as JWTPayload)
        .setProtectedHeader({
          alg: this.#algorithm,
          typ,
          ...(this.#keyId === undefined ? {} : { kid: this.#keyId }),
        })
        .sign(this.#privateKey);
      return new SecretValue(token);
    } catch (cause) {
      throw new ProofError("signing_failed", `Could not sign ${options.purpose}`, { cause });
    }
  }
}

/** The `pap.signer` contribution, asked each time it signs: whichever the host contributes. */
export class ContributedSigner implements Signer {
  readonly #reactor: ReactorPlatformView;

  constructor(reactor: ReactorPlatformView) {
    this.#reactor = reactor;
  }

  sign(
    claims: Readonly<Record<string, unknown>>,
    options: { readonly purpose: string },
  ): Promise<SecretValue> {
    return firstContribution(this.#reactor, Signers, "signer").sign(claims, options);
  }
}

/**
 * One delegated key, its delegation, and when the delegation expires (§5.2).
 *
 * `thumbprint` is the public key's RFC 7638 thumbprint, the `kid` of every Session JWT it
 * signs; `delegation` is the compact JWT carried in `pap_dlg`.
 */
export interface DelegatedKey {
  readonly privateKey: KeyInput;
  readonly publicJwk: JWK;
  readonly thumbprint: string;
  readonly delegation: SecretValue;
  readonly clientId: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
}

export interface DelegatedKeyWho {
  readonly tenantId: string;
  readonly issuer: string;
  readonly sub: string;
}

/**
 * Where delegated keys live: one current key per User ID, replaced when it rotates.
 *
 * The key of `(tenantId, issuer, sub)` signs that User ID's Session JWTs only (§5.2). A host
 * keeps them on the User's device or in its KMS; `InMemoryDelegatedKeys` is for one process.
 */
export interface DelegatedKeyCustody {
  current(who: DelegatedKeyWho): Promise<DelegatedKey | undefined>;
  replace(who: DelegatedKeyWho & { readonly key: DelegatedKey }): Promise<void>;
  forget(who: DelegatedKeyWho): Promise<void>;
}

/** Delegated keys in this process's memory, one per User ID. */
export class InMemoryDelegatedKeys implements DelegatedKeyCustody {
  readonly #keys = new Map<string, DelegatedKey>();

  static #name(who: DelegatedKeyWho): string {
    return JSON.stringify([who.tenantId, who.issuer, who.sub]);
  }

  async current(who: DelegatedKeyWho): Promise<DelegatedKey | undefined> {
    return this.#keys.get(InMemoryDelegatedKeys.#name(who));
  }

  async replace(who: DelegatedKeyWho & { readonly key: DelegatedKey }): Promise<void> {
    this.#keys.set(InMemoryDelegatedKeys.#name(who), who.key);
  }

  async forget(who: DelegatedKeyWho): Promise<void> {
    this.#keys.delete(InMemoryDelegatedKeys.#name(who));
  }

  get size(): number {
    return this.#keys.size;
  }
}

/**
 * A delegation's claims (§5.2): `iss`, `cnf.jwk`, `iat`, `exp`, `jti`, nothing else.
 *
 * Nothing about the User or the Company: no User ID, Agent ID, or issuer.
 */
export function delegationClaims(options: {
  readonly clientId: string;
  readonly publicKey: JWK;
  readonly issuedAt: Date;
  readonly lifetimeSeconds: number;
  readonly randomBytes?: (length: number) => Uint8Array;
}): Record<string, unknown> {
  const { lifetimeSeconds } = options;
  if (!(lifetimeSeconds > 0 && lifetimeSeconds <= DELEGATION_MAX_LIFETIME_SECONDS)) {
    throw new RangeError("a delegation lives more than 0 seconds and at most 24 hours");
  }
  const entropy = (options.randomBytes ?? systemRandomBytes)(16);
  if (entropy.byteLength < 16) {
    throw new ProofError("weak_randomness", "A delegation ID needs 128 random bits");
  }
  const iat = Math.floor(options.issuedAt.getTime() / 1000);
  return {
    iss: options.clientId,
    cnf: { jwk: publicJwk(options.publicKey) },
    iat,
    exp: iat + Math.floor(lifetimeSeconds),
    jti: base64Url(entropy),
  };
}

/**
 * A Session JWT's claims for one request (§5.2).
 *
 * Every claim but `agent_id`, and `ath` only when the request carries an access token.
 */
export async function sessionJwtClaims(
  request: SessionJwtRequest,
  options: {
    readonly issuedAt: Date;
    readonly randomBytes?: (length: number) => Uint8Array;
  },
): Promise<Record<string, unknown>> {
  if (!SESSION_ID.test(request.sid)) {
    throw new ProofError("invalid_session_id", "A Session ID is 22 to 256 URL-safe characters");
  }
  if (!request.sub) throw new ProofError("invalid_user_id", "A Session JWT names its User ID");
  const entropy = (options.randomBytes ?? systemRandomBytes)(16);
  if (entropy.byteLength < 16) {
    throw new ProofError("weak_randomness", "A Session JWT's jti needs 128 random bits");
  }
  return {
    iss: request.clientId,
    aud: request.issuer,
    sid: request.sid,
    sub: request.sub,
    htm: request.method.toUpperCase(),
    htu: normalizedHtu(request.url),
    iat: Math.floor(options.issuedAt.getTime() / 1000),
    jti: base64Url(entropy),
    ...(request.agentId === undefined ? {} : { agent_id: request.agentId }),
    ...(request.accessToken === undefined ? {} : { ath: await tokenHash(request.accessToken) }),
  };
}

export interface DelegatedSessionSignerOptions {
  readonly custody: DelegatedKeyCustody;
  /** The `pap.signer` key from `jwks_uri`, which signs each delegation. */
  readonly signer: Signer;
  readonly delegationLifetimeSeconds?: number;
  readonly rotateBeforeSeconds?: number;
  readonly now?: () => Date;
  readonly randomBytes?: (length: number) => Uint8Array;
}

/**
 * `pap.sessionSigner`: a delegated key per User ID signs each request's Session JWT (§5.2).
 *
 * The key of a User ID is made on first use, with a delegation the `signer` (the `pap.signer`
 * key from `jwks_uri`) signs for `delegationLifetimeSeconds`, and replaced by a new key and
 * delegation `rotateBeforeSeconds` before its expiry: a JWT is never signed after its
 * delegation's `exp`. A key is never shared by two User IDs, so its thumbprint and its
 * delegation's `jti` name one User at one Company.
 */
export class DelegatedSessionSigner implements SessionSigner {
  readonly custody: DelegatedKeyCustody;
  readonly signer: Signer;
  readonly #lifetime: number;
  readonly #rotateBefore: number;
  readonly #now: () => Date;
  readonly #randomBytes: (length: number) => Uint8Array;

  constructor(options: DelegatedSessionSignerOptions) {
    const lifetime = options.delegationLifetimeSeconds ?? 3600;
    const rotateBefore = options.rotateBeforeSeconds ?? 300;
    if (!(lifetime > 0 && lifetime <= DELEGATION_MAX_LIFETIME_SECONDS)) {
      throw new RangeError("delegationLifetimeSeconds is more than 0 and at most 24 hours");
    }
    if (!(rotateBefore >= 0 && rotateBefore < lifetime)) {
      throw new RangeError("rotateBeforeSeconds is shorter than delegationLifetimeSeconds");
    }
    this.custody = options.custody;
    this.signer = options.signer;
    this.#lifetime = lifetime;
    this.#rotateBefore = rotateBefore;
    this.#now = options.now ?? (() => new Date());
    this.#randomBytes = options.randomBytes ?? systemRandomBytes;
  }

  async sign(request: SessionJwtRequest): Promise<SecretValue> {
    const issuedAt = this.#now();
    const key = await this.keyFor(request, issuedAt);
    const claims = await sessionJwtClaims(request, { issuedAt, randomBytes: this.#randomBytes });
    try {
      const token = await new SignJWT(claims as JWTPayload)
        .setProtectedHeader({
          alg: SESSION_JWT_ALGORITHM,
          typ: SESSION_JWT_TYPE,
          kid: key.thumbprint,
          pap_dlg: key.delegation.reveal(),
        })
        .sign(key.privateKey);
      return new SecretValue(token);
    } catch (cause) {
      throw new ProofError("signing_failed", "Could not sign the Session JWT", { cause });
    }
  }

  /** The User ID's current delegated key, or a new one when it is due to rotate. */
  async keyFor(request: SessionJwtRequest, now: Date): Promise<DelegatedKey> {
    const who = { tenantId: request.tenantId, issuer: request.issuer, sub: request.sub };
    const current = await this.custody.current(who);
    if (
      current !== undefined &&
      current.clientId === request.clientId &&
      now.getTime() < current.expiresAt.getTime() - this.#rotateBefore * 1000
    ) {
      return current;
    }
    const key = await this.#newKey(request.clientId, now);
    await this.custody.replace({ ...who, key });
    return key;
  }

  async #newKey(clientId: string, now: Date): Promise<DelegatedKey> {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const exported = await exportJWK(publicKey);
    const publicKeyJwk: JWK = {
      kty: exported.kty as string,
      crv: exported.crv as string,
      x: exported.x as string,
      y: exported.y as string,
    };
    const claims = delegationClaims({
      clientId,
      publicKey: publicKeyJwk,
      issuedAt: now,
      lifetimeSeconds: this.#lifetime,
      randomBytes: this.#randomBytes,
    });
    const delegation = await this.signer.sign(claims, { purpose: "delegation" });
    return {
      privateKey,
      publicJwk: publicKeyJwk,
      thumbprint: await jwkThumbprint(publicKeyJwk),
      delegation,
      clientId,
      issuedAt: new Date((claims.iat as number) * 1000),
      expiresAt: new Date((claims.exp as number) * 1000),
    };
  }
}

/** Whether two strings are equal, in time that does not depend on where they differ. */
export function constantTimeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}
