/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/** Verify a personal agent's client and Session assertions (§4.1, §4.2). */

import {
  decodeProtectedHeader,
  errors as joseErrors,
  importJWK,
  jwtVerify,
  type JWK,
  type JWTPayload,
} from "jose";

import { SessionError } from "../errors.js";
import type { JsonWebKeySet } from "../models.js";
import { SecretValue } from "../secret.js";
import type { ReplayCache } from "./points.js";

const ALGORITHMS = new Set(["ES256", "RS256"]);
/**
 * An assertion lives at most this long (`exp - iat`): long enough for any clock, short
 * enough that a captured one is soon useless. The SDKs' own assertions live 60 seconds.
 */
const MAX_LIFETIME_SECONDS = 120;
/** A `jti` this short is guessable: its replay key could collide with another's. */
const MIN_JTI = 16;
const SKEW_SECONDS = 30;

export interface VerifyAssertionOptions {
  readonly keys: JsonWebKeySet;
  readonly issuer: string;
  /**
   * The one value `aud` must be, or the values it may be: a client assertion names the
   * authorization server's issuer, its token endpoint, or the endpoint it is sent to
   * (RFC 7523 §3).
   */
  readonly audience: string | readonly string[];
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
 * A client assertion's `sub` is the `client_id` (`subject: issuer`); a
 * Session assertion's is the pairwise user ID (`subject` omitted returns it
 * unchecked for the caller to read).
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
  if (typeof claims.aud !== "string") {
    // `aud` is one string, the token endpoint, so the assertion works at one company (§4.2).
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
  audience: string | readonly string[],
  now: Date,
): Promise<JWTPayload | undefined> {
  const header = decodeProtectedHeader(compact);
  const algorithm = String(header.alg ?? "");
  if (!ALGORITHMS.has(algorithm)) throw new TypeError("assertion algorithm is not allowed");
  if (header.typ !== undefined && header.typ !== "JWT") {
    // A browser assertion (`poppy-browser+jwt`) or a DPoP proof is never a token assertion.
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
        audience: typeof audience === "string" ? audience : [...audience],
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
