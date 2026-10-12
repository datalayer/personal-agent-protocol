/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { decodeProtectedHeader, jwtVerify, type KeyInput } from "jose";

import {
  BROWSER_ASSERTION_TYPE,
  assertCompanyReturnTo,
  browserAssertionError,
  validateBrowserClaimIdentity,
  type BrowserAssertionClaims,
} from "./browser.js";
import { BrowserSessionError } from "./errors.js";
import { SecretValue } from "./secret.js";

export interface BrowserAssertionReplayCache {
  markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean>;
}

export interface VerifyBrowserAssertionOptions {
  readonly publicKey: KeyInput | Uint8Array;
  readonly expectedEndpoint: string;
  readonly companyDomain: string;
  readonly expectedClientId: string;
  readonly expectedPairwiseUserId: string;
  readonly expectedSessionId: string;
  readonly replayCache: BrowserAssertionReplayCache;
  readonly now?: Date;
}

export interface VerifiedBrowserAssertion {
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly sessionId: string;
  readonly returnTo: string;
  readonly expiresAt: Date;
}

export async function verifyBrowserAssertion(
  assertion: SecretValue | string,
  options: VerifyBrowserAssertionOptions,
): Promise<VerifiedBrowserAssertion> {
  const compact = assertion instanceof SecretValue ? assertion.reveal() : assertion;
  let claims: BrowserAssertionClaims;
  try {
    const header = decodeProtectedHeader(compact);
    if (header.typ !== BROWSER_ASSERTION_TYPE || (header.alg !== "ES256" && header.alg !== "RS256")) {
      throw browserAssertionError();
    }
    const verified = await jwtVerify(compact, options.publicKey, {
      algorithms: [header.alg],
      typ: BROWSER_ASSERTION_TYPE,
      requiredClaims: ["iss", "sub", "aud", "session_id", "return_to", "iat", "exp", "jti"],
      ...(options.now === undefined ? {} : { currentDate: options.now }),
    });
    const payload = verified.payload;
    claims = {
      iss: validateBrowserClaimIdentity(payload.iss, "iss"),
      sub: validateBrowserClaimIdentity(payload.sub, "sub"),
      aud: validateBrowserClaimIdentity(payload.aud, "aud"),
      session_id: validateBrowserClaimIdentity(payload.session_id, "session_id"),
      return_to: validateBrowserClaimIdentity(payload.return_to, "return_to"),
      iat: Number(payload.iat),
      exp: Number(payload.exp),
      jti: validateBrowserClaimIdentity(payload.jti, "jti"),
    };
  } catch (cause) {
    if (cause instanceof BrowserSessionError) throw cause;
    throw browserAssertionError(cause);
  }
  const now = options.now ?? new Date();
  const nowSeconds = Math.floor(now.getTime() / 1000);
  if (!Number.isInteger(claims.iat) || !Number.isInteger(claims.exp) ||
      claims.exp <= claims.iat || claims.exp - claims.iat > 60 ||
      claims.iat > nowSeconds || claims.exp <= nowSeconds) {
    throw browserAssertionError();
  }
  const endpoint = new URL(options.expectedEndpoint).toString();
  const returnTo = assertCompanyReturnTo(claims.return_to, options.companyDomain);
  if (claims.aud !== endpoint || claims.iss !== options.expectedClientId ||
      claims.sub !== options.expectedPairwiseUserId || claims.session_id !== options.expectedSessionId) {
    throw browserAssertionError();
  }
  const expiresAt = new Date(claims.exp * 1000);
  if (!(await options.replayCache.markOnce(`browser:${claims.iss}:${claims.jti}`, { expiresAt }))) {
    throw new BrowserSessionError("invalid_browser_assertion", "Browser assertion has already been used");
  }
  return {
    clientId: claims.iss,
    pairwiseUserId: claims.sub,
    sessionId: claims.session_id,
    returnTo,
    expiresAt,
  };
}
