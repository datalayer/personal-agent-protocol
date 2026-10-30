/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/** Verify a personal agent's client assertions, Session JWTs and DPoP proofs (§4.1, §4.5, §5.3). */

import {
  compactVerify,
  decodeJwt,
  decodeProtectedHeader,
  errors as joseErrors,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from "jose";

import {
  DELEGATION_MAX_LIFETIME_SECONDS,
  DELEGATION_TYPE,
  DPOP_ALGORITHM,
  DPOP_PROOF_TYPE,
  SESSION_ID,
  SESSION_JWT_ALGORITHM,
  SESSION_JWT_TYPE,
  constantTimeEqual,
  jwkThumbprint,
  normalizedHtu,
  publicJwk,
  tokenHash,
} from "../crypto.js";
import { ProofError, SessionError } from "../errors.js";
import type { ClientMetadata, JsonWebKeySet } from "../models.js";
import { SecretValue } from "../secret.js";
import type { ReplayCache } from "./points.js";

/** Companies accept client assertions and delegations signed with these (§4.1, §5.2). */
const ALGORITHMS = new Set(["ES256", "PS384"]);
/**
 * An assertion lives at most this long: `exp` at most five minutes after `iat` (§4.1).
 * The SDKs' own assertions live 60 seconds.
 */
const MAX_LIFETIME_SECONDS = 300;
/** A `jti` this short is guessable: its replay key could collide with another's. */
const MIN_JTI = 16;
const SKEW_SECONDS = 30;

export interface VerifyAssertionOptions {
  readonly keys: JsonWebKeySet;
  readonly issuer: string;
  /**
   * The one value `aud` must be, compared character for character: the company's
   * issuer, never an endpoint URL (§4.1, §10.4).
   */
  readonly audience: string;
  readonly replayCache: ReplayCache;
  readonly now: Date;
  /** A client assertion's `sub` is its `client_id`; omitted, `sub` is returned unchecked. */
  readonly subject?: string;
  /** The one error every failure is, so nothing about which check failed leaks. */
  readonly error?: string;
}

function status(error: string): number {
  return error === "invalid_client" ? 401 : 400;
}

/**
 * Verify signature, `iss`, `aud`, lifetime, and one-time `jti`.
 *
 * The `jti` is remembered per `client_id` (the assertion's `iss`) until it expires.
 *
 * A client assertion's `sub` is the `client_id` (`subject: issuer`). Every failure is the
 * same `error`, so nothing about which check failed leaks to the caller.
 */
export async function verifyAssertion(
  assertion: SecretValue | string,
  options: VerifyAssertionOptions,
): Promise<JWTPayload> {
  const error = options.error ?? "invalid_client";
  const refuse = (message: string, cause?: unknown): SessionError =>
    new SessionError(error, message, { statusCode: status(error), cause });
  const compact = assertion instanceof SecretValue ? assertion.reveal() : assertion;
  let claims: JWTPayload | undefined;
  try {
    claims = await decode(compact, options.keys, options.issuer, options.audience, options.now);
  } catch (cause) {
    throw refuse("Assertion is invalid", cause);
  }
  if (claims === undefined) throw refuse("Assertion signature is invalid");
  if (claims.aud !== options.audience) {
    // `aud` is one string, the issuer, exactly: an array, or the token endpoint, is
    // refused, so the assertion works at one company (§4.1).
    throw refuse("Assertion audience is invalid");
  }
  const iat = Number(claims.iat);
  const exp = Number(claims.exp);
  if (!Number.isFinite(iat) || !Number.isFinite(exp)) throw refuse("Assertion is invalid");
  if (exp - iat > MAX_LIFETIME_SECONDS || exp <= iat) throw refuse("Assertion lifetime is invalid");
  if (typeof claims.jti !== "string" || claims.jti.length < MIN_JTI || claims.jti.length > 256) {
    throw refuse("Assertion jti is invalid");
  }
  if (options.subject !== undefined && claims.sub !== options.subject) {
    throw refuse("Assertion subject is invalid");
  }
  const now = options.now.getTime() / 1000;
  if (now > exp + SKEW_SECONDS || iat > now + SKEW_SECONDS) {
    throw refuse("Assertion is not active");
  }
  const fresh = await options.replayCache.markOnce(
    `assertion:${options.issuer}:${String(claims.jti)}`,
    // Remembered for as long as the assertion would be accepted: `exp` and the skew.
    { expiresAt: new Date((exp + SKEW_SECONDS) * 1000) },
  );
  if (!fresh) throw refuse("Assertion has already been used");
  return claims;
}

/** The verified claims, or `undefined` when no published key signed them. */
async function decode(
  compact: string,
  keys: JsonWebKeySet,
  issuer: string,
  audience: string,
  now: Date,
): Promise<JWTPayload | undefined> {
  const header = decodeProtectedHeader(compact);
  const algorithm = String(header.alg ?? "");
  if (!ALGORITHMS.has(algorithm)) throw new TypeError("assertion algorithm is not allowed");
  if (header.typ !== undefined && header.typ !== "JWT") {
    // A Session JWT or a delegation is never a client assertion (§5.2, RFC 8725 §3.11).
    throw new TypeError("assertion type is not allowed");
  }
  const kid = header.kid;
  for (const key of keys.keys) {
    if (kid !== undefined && key.kid !== undefined && key.kid !== kid) continue;
    if (key.alg !== undefined && key.alg !== algorithm) continue;
    const publicKey = await importJWK({ ...key } as JWK, algorithm);
    try {
      const { payload } = await jwtVerify(compact, publicKey, {
        algorithms: [algorithm],
        issuer,
        audience,
        requiredClaims: ["iss", "sub", "aud", "iat", "exp", "jti"],
        // The company's own clock, with the same skew the caller allows.
        currentDate: now,
        clockTolerance: SKEW_SECONDS,
      });
      return payload;
    } catch (cause) {
      if (cause instanceof joseErrors.JWSSignatureVerificationFailed) continue;
      throw cause;
    }
  }
  return undefined;
}

// Session JWTs (§5.2, §5.3) ---------------------------------------------------------

/** The acceptance window of a Session JWT's `iat`, in seconds (§5.3: such as one minute). */
export const SESSION_JWT_WINDOW_SECONDS = 60;
const JTI = /^[A-Za-z0-9_-]{16,256}$/u;
const AGENT_ID = /^[A-Za-z0-9_-]{1,256}$/u;
/** Members a JWK must not have for `cnf.jwk` to be a public key (§5.2). */
const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/** A personal agent's metadata and keys, the key `kid` names fetched when not cached. */
export type ResolveClient = (
  clientId: string,
  kid: string | undefined,
) => Promise<readonly [ClientMetadata, JsonWebKeySet]>;

/** A delegation that verified (§5.2): its agent, its delegated key, until when. */
export interface VerifiedDelegation {
  readonly clientId: string;
  readonly publicJwk: JWK;
  readonly thumbprint: string;
  /** When it expires, in seconds since the epoch. */
  readonly expiresAt: number;
}

/** A Session JWT that verified (§5.3): who sent the request, in which Session. */
export interface VerifiedSessionJwt {
  readonly clientId: string;
  readonly sid: string;
  readonly sub: string;
  readonly agentId?: string;
  readonly jti: string;
  /** Its `iat`, in seconds since the epoch. */
  readonly issuedAt: number;
  readonly delegation: VerifiedDelegation;
}

/**
 * Verified delegations, until each expires (§5.2: a resource MAY cache them).
 *
 * Keyed by the delegation itself; bounded, the oldest dropped first.
 */
export class DelegationCache {
  readonly #entries = new Map<string, VerifiedDelegation>();
  readonly maxEntries: number;

  constructor(maxEntries = 4096) {
    this.maxEntries = maxEntries;
  }

  get size(): number {
    return this.#entries.size;
  }

  get(compact: string, now: Date): VerifiedDelegation | undefined {
    const found = this.#entries.get(compact);
    if (found !== undefined && now.getTime() >= found.expiresAt * 1000) {
      this.#entries.delete(compact);
      return undefined;
    }
    return found;
  }

  put(compact: string, delegation: VerifiedDelegation): void {
    this.#entries.set(compact, delegation);
    for (const oldest of this.#entries.keys()) {
      if (this.#entries.size <= this.maxEntries) break;
      this.#entries.delete(oldest);
    }
  }
}

function refused(message: string, cause?: unknown): SessionError {
  return new SessionError("invalid_session", message, { statusCode: 400, cause });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The `iss` a Session JWT names, unverified: whose policy to ask before fetching anything. */
export function unverifiedSessionIssuer(compact: string): string {
  let claims: JWTPayload;
  try {
    claims = decodeJwt(compact);
  } catch (cause) {
    throw refused("The Session header is not a JWT", cause);
  }
  if (typeof claims.iss !== "string" || !claims.iss.startsWith("https://")) {
    throw refused("The Session JWT names no personal agent");
  }
  return claims.iss;
}

/** A JWS's payload, read as JSON once its signature verified. */
async function verifiedClaims(compact: string, key: JWK, algorithm: string): Promise<Record<string, unknown>> {
  const publicKey = await importJWK(key, algorithm);
  const { payload } = await compactVerify(compact, publicKey, { algorithms: [algorithm] });
  const claims: unknown = JSON.parse(new TextDecoder().decode(payload));
  if (!isRecord(claims)) throw new TypeError("a JWT's claims are a JSON object");
  return claims;
}

/** Steps 1 and 2 of §5.2: the jwks key its `kid` names signed it, and its claims hold. */
export async function verifyDelegation(
  compact: string,
  options: {
    readonly clientId: string;
    readonly resolve: ResolveClient;
    readonly now: Date;
    readonly cache?: DelegationCache;
  },
): Promise<VerifiedDelegation> {
  const { clientId, resolve, now, cache } = options;
  const cached = cache?.get(compact, now);
  if (cached !== undefined) {
    if (cached.clientId !== clientId) throw refused("The delegation is another agent's");
    return cached;
  }
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(compact);
  } catch (cause) {
    throw refused("The delegation is not a JWT", cause);
  }
  const { alg: algorithm, kid } = header;
  if (typeof algorithm !== "string" || !ALGORITHMS.has(algorithm) || typeof kid !== "string" || !kid) {
    throw refused("The delegation's algorithm or key ID is not allowed");
  }
  if (header.typ !== DELEGATION_TYPE) throw refused("A delegation's typ is pap-delegation+jwt");
  let keys: JsonWebKeySet;
  try {
    [, keys] = await resolve(clientId, kid);
  } catch (cause) {
    throw refused("The agent's keys could not be fetched", cause);
  }
  const key = keys.keys.find((candidate) => candidate.kid === kid);
  if (key === undefined || (key.alg !== undefined && key.alg !== algorithm)) {
    throw refused("No key of the agent's jwks_uri signed the delegation");
  }
  let claims: Record<string, unknown>;
  try {
    claims = await verifiedClaims(compact, { ...key } as JWK, algorithm);
  } catch (cause) {
    throw refused("The delegation's signature is invalid", cause);
  }
  if (claims.iss !== clientId) throw refused("The delegation's iss is not the Session JWT's");
  const { iat, exp, jti, cnf } = claims;
  if (typeof jti !== "string" || !jti) throw refused("A delegation has a jti");
  if (!Number.isInteger(iat) || !Number.isInteger(exp)) {
    throw refused("The delegation's times are not NumericDates");
  }
  const issued = iat as number;
  const expires = exp as number;
  if (now.getTime() >= expires * 1000) throw refused("The delegation has expired");
  if (expires - issued > DELEGATION_MAX_LIFETIME_SECONDS || expires <= issued) {
    throw refused("A delegation expires at most 24 hours after it is issued");
  }
  const jwk = isRecord(cnf) ? cnf.jwk : undefined;
  if (
    !isRecord(jwk) ||
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    PRIVATE_MEMBERS.some((member) => member in jwk)
  ) {
    // The delegated key signs ES256 Session JWTs: a public P-256 key, nothing private.
    throw refused("The delegation's cnf.jwk is not a public P-256 key");
  }
  let thumbprint: string;
  try {
    thumbprint = await jwkThumbprint(jwk as JWK);
  } catch (cause) {
    throw refused("The delegation's cnf.jwk is incomplete", cause);
  }
  const verified: VerifiedDelegation = {
    clientId,
    publicJwk: { ...(jwk as JWK) },
    thumbprint,
    expiresAt: expires,
  };
  cache?.put(compact, verified);
  return verified;
}

export interface VerifySessionJwtOptions {
  /** This company's issuer, which `aud` must be, exactly. */
  readonly issuer: string;
  readonly method: string;
  readonly url: string;
  readonly resolve: ResolveClient;
  readonly replayCache: ReplayCache;
  readonly now: Date;
  /** The access token the request carries, if any. */
  readonly accessToken?: string;
  readonly delegations?: DelegationCache;
  readonly windowSeconds?: number;
}

/**
 * Verify the Session header of one request (§5.2, §5.3); `invalid_session` on any failure.
 *
 * The delegation first (`verifyDelegation`, cached), then the JWT's signature with the
 * delegated key, its `kid` that key's thumbprint, its `iat` no later than the delegation's
 * `exp`; then `typ`, `alg`, `aud` (this company's issuer, exactly), `htm` and `htu`, `iat`
 * within the window, and `ath` against the access token, or absent without one. A JWT
 * signed directly by a key from `jwks_uri` has no delegation and is refused. A reused `jti`
 * is refused (§5.3: a company MAY).
 */
export async function verifySessionJwt(
  compact: string,
  options: VerifySessionJwtOptions,
): Promise<VerifiedSessionJwt> {
  const { issuer, method, url, resolve, replayCache, now, accessToken, delegations } = options;
  const window = options.windowSeconds ?? SESSION_JWT_WINDOW_SECONDS;
  if (compact.split(".").length !== 3 || /[, \t]/u.test(compact)) {
    throw refused("The Session header is not one compact JWT");
  }
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(compact);
  } catch (cause) {
    throw refused("The Session header is not a JWT", cause);
  }
  if (header.typ !== SESSION_JWT_TYPE || header.alg !== SESSION_JWT_ALGORITHM) {
    throw refused("A Session JWT's typ is poppy-session+jwt and its alg ES256");
  }
  const delegationCompact = header.pap_dlg;
  if (typeof delegationCompact !== "string" || !delegationCompact) {
    // Signed with a key from jwks_uri itself, or by anyone: never accepted (§5.2).
    throw refused("A Session JWT carries its delegation");
  }
  if (typeof header.kid !== "string") throw refused("A Session JWT names its delegated key");
  const clientId = unverifiedSessionIssuer(compact);
  const delegation = await verifyDelegation(delegationCompact, {
    clientId,
    resolve,
    now,
    ...(delegations === undefined ? {} : { cache: delegations }),
  });
  if (!constantTimeEqual(header.kid, delegation.thumbprint)) {
    throw refused("The Session JWT's kid is not its delegated key's thumbprint");
  }
  let claims: Record<string, unknown>;
  try {
    claims = await verifiedClaims(compact, delegation.publicJwk, SESSION_JWT_ALGORITHM);
  } catch (cause) {
    throw refused("The Session JWT's signature is invalid", cause);
  }
  const { iat, aud, htm, htu, sid, sub, agent_id: agentId, jti, ath } = claims;
  if (!Number.isInteger(iat)) throw refused("The Session JWT's iat is not a NumericDate");
  const issued = iat as number;
  if (issued > delegation.expiresAt) {
    throw refused("The Session JWT was signed after its delegation expired");
  }
  // One string, this company's issuer, exactly (§5.2, §10.4).
  if (aud !== issuer) throw refused("The Session JWT is for another company");
  let target: string;
  try {
    target = normalizedHtu(url);
  } catch (cause) {
    if (cause instanceof ProofError) throw refused("The request URL is not HTTPS", cause);
    throw cause;
  }
  if (htm !== method.toUpperCase() || htu !== target) throw refused("The Session JWT is for another request");
  const seconds = now.getTime() / 1000;
  if (issued < seconds - window || issued > seconds + window) {
    throw refused("The Session JWT is outside the acceptance window");
  }
  if (typeof sid !== "string" || !SESSION_ID.test(sid)) throw refused("The Session ID is malformed");
  if (typeof sub !== "string" || !sub || sub.length > 256) throw refused("The User ID is malformed");
  if (agentId !== undefined && (typeof agentId !== "string" || !AGENT_ID.test(agentId))) {
    throw refused("The Agent ID is malformed");
  }
  if (typeof jti !== "string" || !JTI.test(jti)) throw refused("The Session JWT's jti is malformed");
  if (accessToken !== undefined) {
    if (typeof ath !== "string" || !constantTimeEqual(ath, await tokenHash(accessToken))) {
      throw refused("The Session JWT's ath does not match the access token");
    }
  } else if (ath !== undefined) {
    throw refused("A Session JWT without an access token has no ath");
  }
  // Remembered for as long as the JWT would be accepted (§5.3: a company MAY).
  const first = await replayCache.markOnce(`session:${clientId}:${jti}`, {
    expiresAt: new Date((issued + window) * 1000),
  });
  if (!first) throw refused("The Session JWT has already been used");
  return {
    clientId,
    sid,
    sub,
    ...(agentId === undefined ? {} : { agentId }),
    jti,
    issuedAt: issued,
    delegation,
  };
}

// DPoP proofs (§4.5, RFC 9449) ---------------------------------------------------------

/** What a verified, newly accepted DPoP proof says: its key's thumbprint, and its nonce. */
export interface VerifiedDpopProof {
  readonly thumbprint: string;
  readonly nonce?: string;
}

export interface VerifyDpopProofOptions {
  readonly method: string;
  readonly url: string;
  readonly replayCache: ReplayCache;
  readonly now: Date;
  /** The acceptance window of the proof's `iat`, in seconds. */
  readonly windowSeconds: number;
  /** The access token the request carries, if any. */
  readonly accessToken?: string;
}

function refusedProof(message: string, cause?: unknown): ProofError {
  return new ProofError("invalid_dpop_proof", message, { cause });
}

/** The proof's public key, a P-256 JWK: a private member or another curve is refused. */
function dpopKey(header: Record<string, unknown>): JWK {
  const { jwk } = header;
  if (!isRecord(jwk)) throw refusedProof("A DPoP proof carries its public key");
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") throw refusedProof("A DPoP proof's key is P-256");
  return publicJwk(jwk as JWK);
}

/**
 * Verify one DPoP proof as RFC 9449 §4.3 says.
 *
 * One `DPoP` header holding one JWT: `typ` `dpop+jwt`, `alg` ES256, a public P-256 `jwk` that
 * signed it, `htm` and `htu` matching the request, `iat` within the window, a `jti` not seen
 * while the proof would be accepted, and `ath` for `accessToken`, or none without one. Any
 * failure is `ProofError` (`invalid_dpop_proof`). Whether the key and the nonce are the right
 * ones is the caller's to decide.
 */
export async function verifyDpopProof(
  proof: SecretValue | string,
  options: VerifyDpopProofOptions,
): Promise<VerifiedDpopProof> {
  const { method, url, replayCache, now, windowSeconds, accessToken } = options;
  const compact = proof instanceof SecretValue ? proof.reveal() : proof;
  if (compact.split(".").length !== 3 || /[, \t]/u.test(compact)) {
    // Two `DPoP` headers arrive joined: refused (RFC 9449 §4.3).
    throw refusedProof("A DPoP header is one compact JWT");
  }
  let claims: Record<string, unknown>;
  let thumbprint: string;
  try {
    const header = decodeProtectedHeader(compact);
    if (header.typ !== DPOP_PROOF_TYPE || header.alg !== DPOP_ALGORITHM) {
      throw refusedProof("A DPoP proof's typ or alg is wrong");
    }
    const key = dpopKey(header as Record<string, unknown>);
    claims = await verifiedClaims(compact, key, DPOP_ALGORITHM);
    thumbprint = await jwkThumbprint(key);
  } catch (cause) {
    if (cause instanceof ProofError) throw cause;
    throw refusedProof("A DPoP proof's signature is invalid", cause);
  }
  const { jti, iat, htm, htu, ath, nonce } = claims;
  if (typeof jti !== "string" || jti.length < MIN_JTI || jti.length > 256 || !Number.isInteger(iat)) {
    throw refusedProof("A DPoP proof's jti or iat is invalid");
  }
  const issued = iat as number;
  if (Math.abs(issued - now.getTime() / 1000) > windowSeconds) {
    throw refusedProof("A DPoP proof is outside its acceptance window");
  }
  if (htm !== method.toUpperCase() || htu !== normalizedHtu(url)) {
    throw refusedProof("A DPoP proof is for another request");
  }
  if (accessToken === undefined) {
    if (ath !== undefined && ath !== null) throw refusedProof("A proof without an access token has no ath");
  } else if (typeof ath !== "string" || !constantTimeEqual(ath, await tokenHash(accessToken))) {
    throw refusedProof("A DPoP proof's ath does not match the token");
  }
  // Remembered for as long as the proof would be accepted: until `iat` leaves the window.
  const first = await replayCache.markOnce(`dpop:${thumbprint}:${jti}`, {
    expiresAt: new Date((issued + windowSeconds) * 1000),
  });
  if (!first) throw refusedProof("A DPoP proof is used once");
  return { thumbprint, ...(typeof nonce === "string" ? { nonce } : {}) };
}
