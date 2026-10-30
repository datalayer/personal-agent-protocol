/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError } from "./errors.js";
import { isLoopbackRedirect } from "./models.js";
import { SecretValue } from "./secret.js";
import { SessionClient, finishSignIn, type RandomBytes, type SignInResult } from "./sessions.js";
import {
  AuthorizationStateStores,
  BrowserHandoffs,
  Clocks,
  RandomSources,
  firstContribution,
} from "./reactor.js";
import { byIssuer, signInResult, traced } from "./telemetry.js";

function defaultRandomBytes(length: number): Uint8Array {
  if (!globalThis.crypto) {
    throw new AuthorizationError("crypto_unavailable", "Web Crypto is required");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function entropy(length: number, randomBytes: RandomBytes): Uint8Array {
  const value = randomBytes(length);
  if (value.byteLength < length) {
    throw new AuthorizationError(
      "weak_entropy",
      `Authorization requires ${length * 8} random bits`,
    );
  }
  return value;
}

function base64Url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += alphabet[first >>> 2];
    output += alphabet[((first & 3) << 4) | ((second ?? 0) >>> 4)];
    if (second !== undefined) {
      output += alphabet[((second & 15) << 2) | ((third ?? 0) >>> 6)];
    }
    if (third !== undefined) {
      output += alphabet[third & 63];
    }
  }
  return output;
}

function httpsUrl(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`, { cause });
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return parsed;
}

/** A redirect URI: HTTPS, or a loopback URI for an app on the User's computer (§4.1). */
function redirectUrl(value: string, label: string): URL {
  return isLoopbackRedirect(value) ? new URL(value) : httpsUrl(value, label);
}

function validScopes(values: readonly string[]): readonly string[] {
  const scopes = [...new Set(values)];
  const token = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
  if (scopes.length === 0 || scopes.some((scope) => !token.test(scope))) {
    throw new AuthorizationError("invalid_scope", "At least one valid OAuth scope is required");
  }
  return scopes;
}

export interface DirectSignInOptions {
  readonly authorizationEndpoint: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly randomBytes?: RandomBytes;
}

export interface DirectSignInRequest {
  readonly authorizationUrl: SecretValue;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly state: SecretValue;
  readonly codeVerifier: SecretValue;
}

export async function buildDirectSignInRequest(
  options: DirectSignInOptions,
): Promise<DirectSignInRequest> {
  const randomBytes = options.randomBytes ?? defaultRandomBytes;
  const state = base64Url(entropy(16, randomBytes));
  const verifier = base64Url(entropy(32, randomBytes));
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi) {
    throw new AuthorizationError("crypto_unavailable", "Web Crypto is required");
  }
  const challenge = base64Url(
    new Uint8Array(await cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  const endpoint = httpsUrl(options.authorizationEndpoint, "authorizationEndpoint");
  const scopes = validScopes(options.scopes);
  const clientId = httpsUrl(options.clientId, "clientId").toString();
  const redirectUri = redirectUrl(options.redirectUri, "redirectUri").toString();
  // Kept exactly as written: the callback's `iss` is compared character for character (§3.2).
  httpsUrl(options.issuer, "issuer");
  const issuer = options.issuer;
  endpoint.searchParams.set("response_type", "code");
  endpoint.searchParams.set("client_id", clientId);
  endpoint.searchParams.set("redirect_uri", redirectUri);
  endpoint.searchParams.set("scope", scopes.join(" "));
  endpoint.searchParams.set("state", state);
  endpoint.searchParams.set("code_challenge", challenge);
  endpoint.searchParams.set("code_challenge_method", "S256");
  endpoint.hash = "";
  return {
    authorizationUrl: new SecretValue(endpoint.toString()),
    issuer,
    clientId,
    redirectUri,
    scopes,
    state: new SecretValue(state),
    codeVerifier: new SecretValue(verifier),
  };
}

export interface DirectSignInCallback {
  readonly code: SecretValue;
  readonly issuer: string;
}

function equalConstantTime(left: string, right: string): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

export function validateDirectSignInCallback(
  request: DirectSignInRequest,
  callbackUrl: string,
): DirectSignInCallback {
  const expected = redirectUrl(request.redirectUri, "redirectUri");
  const callback = redirectUrl(callbackUrl, "callbackUrl");
  if (callback.hash) {
    throw new AuthorizationError("invalid_callback", "Authorization callback has a fragment");
  }
  // A loopback redirect URI matches with any port (RFC 8252 §7.3, §4.5).
  const loopback = isLoopbackRedirect(request.redirectUri);
  const place = (url: URL) => (loopback ? `${url.protocol}//${url.hostname}` : url.origin);
  if (place(callback) !== place(expected) || callback.pathname !== expected.pathname) {
    throw new AuthorizationError("redirect_mismatch", "Callback does not match redirect URI");
  }
  for (const [key, value] of expected.searchParams) {
    if (callback.searchParams.get(key) !== value) {
      throw new AuthorizationError(
        "redirect_mismatch",
        "Callback changed redirect URI parameters",
      );
    }
  }
  for (const key of ["code", "state", "iss", "error"]) {
    if (callback.searchParams.getAll(key).length > 1) {
      throw new AuthorizationError(
        "invalid_callback",
        "Authorization callback repeats a security parameter",
      );
    }
  }
  if (callback.searchParams.has("error")) {
    throw new AuthorizationError("authorization_denied", "Company did not authorize the request");
  }
  if (!equalConstantTime(callback.searchParams.get("state") ?? "", request.state.reveal())) {
    throw new AuthorizationError("state_mismatch", "Authorization state does not match");
  }
  if (callback.searchParams.get("iss") !== request.issuer) {
    throw new AuthorizationError("issuer_mismatch", "Authorization issuer does not match");
  }
  const code = callback.searchParams.get("code");
  if (!code) {
    throw new AuthorizationError("invalid_callback", "Authorization callback has no code");
  }
  return { code: new SecretValue(code), issuer: request.issuer };
}

interface PendingDirectSignIn {
  readonly kind: "pap.direct-sign-in.v1";
  readonly request: DirectSignInRequest;
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  readonly expiresAt: Date;
}

export interface DirectSignInStart {
  readonly expiresAt: Date;
  readonly requestedScopes: readonly string[];
}

/** A completed Direct Sign-In: the access token, and the refresh token's reference. */
export type DirectSignInResult = SignInResult;

/** Plain OAuth: the sign-in names no Session, and any of the User's Sessions uses its tokens (§5.4). */
export interface DirectSignInBeginOptions extends DirectSignInOptions {
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  readonly lifetimeSeconds?: number;
}

export interface DirectSignInCompleteOptions {
  readonly callbackUrl: string;
  readonly signal?: AbortSignal;
}

export interface DirectSignInClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

async function stateReference(state: string): Promise<string> {
  const bytes = new TextEncoder().encode(state);
  if ([...bytes].some((byte) => byte > 0x7f)) {
    throw new AuthorizationError("invalid_callback", "Authorization state is invalid");
  }
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi) {
    throw new AuthorizationError("crypto_unavailable", "Web Crypto is required");
  }
  const digest = await cryptoApi.subtle.digest("SHA-256", bytes);
  return `direct:${Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function callbackState(callbackUrl: string): string {
  const callback = redirectUrl(callbackUrl, "callbackUrl");
  if (callback.hash) {
    throw new AuthorizationError("invalid_callback", "Authorization callback has a fragment");
  }
  const states = callback.searchParams.getAll("state");
  if (states.length !== 1 || !states[0]) {
    throw new AuthorizationError(
      "invalid_callback",
      "Authorization callback must contain one state value",
    );
  }
  return states[0];
}

function isPendingDirectSignIn(value: unknown): value is PendingDirectSignIn {
  if (typeof value !== "object" || value === null) return false;
  const pending = value as Partial<PendingDirectSignIn>;
  return (
    pending.kind === "pap.direct-sign-in.v1" &&
    typeof pending.tokenEndpoint === "string" &&
    typeof pending.tenantId === "string" &&
    pending.expiresAt instanceof Date &&
    typeof pending.request === "object" &&
    pending.request !== null
  );
}

/** Orchestrate one-use browser authorization and proof-bound code exchange. */
export class DirectSignInClient {
  readonly #reactor: ReactorPlatformView;
  readonly #sessions: SessionClient;

  constructor(options: DirectSignInClientOptions) {
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) {
      throw new AuthorizationError("fetch_unavailable", "A fetch implementation is required");
    }
    const maxResponseBytes = options.maxResponseBytes ?? 100 * 1024;
    if (!Number.isInteger(maxResponseBytes) || maxResponseBytes <= 0) {
      throw new RangeError("maxResponseBytes must be a positive integer");
    }
    this.#reactor = options.reactor;
    this.#sessions = new SessionClient({
      reactor: options.reactor,
      fetch: fetcher,
      maxResponseBytes,
    });
  }

  begin(options: DirectSignInBeginOptions): Promise<DirectSignInStart> {
    return traced(
      this.#reactor,
      "pap.sign_in.direct.begin",
      byIssuer(options.issuer, "direct"),
      () => this.#begin(options),
      () => ({ "pap.sign_in.status": "started" }),
    );
  }

  async #begin(options: DirectSignInBeginOptions): Promise<DirectSignInStart> {
    const lifetimeSeconds = options.lifetimeSeconds ?? 600;
    if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 900) {
      throw new RangeError("Direct Sign-In state lifetime must be between 1 and 900 seconds");
    }
    if (!options.tenantId || options.tenantId.length > 256) {
      throw new RangeError("tenantId must contain between 1 and 256 characters");
    }
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const store = firstContribution(
      this.#reactor,
      AuthorizationStateStores,
      "authorization state store",
    );
    const browser = firstContribution(this.#reactor, BrowserHandoffs, "browser handoff");
    const request = await buildDirectSignInRequest({
      authorizationEndpoint: options.authorizationEndpoint,
      issuer: options.issuer,
      clientId: options.clientId,
      redirectUri: options.redirectUri,
      scopes: options.scopes,
      randomBytes: (length) => random.bytes(length),
    });
    const tokenEndpoint = httpsUrl(options.tokenEndpoint, "tokenEndpoint").toString();
    const expiresAt = new Date(clock.now().getTime() + lifetimeSeconds * 1000);
    const reference = await stateReference(request.state.reveal());
    const pending: PendingDirectSignIn = {
      kind: "pap.direct-sign-in.v1",
      request,
      tokenEndpoint,
      tenantId: options.tenantId,
      expiresAt,
    };
    await store.put(reference, pending, { expiresAt });
    try {
      await browser.open(request.authorizationUrl);
    } catch (cause) {
      await store.take(reference);
      throw new AuthorizationError("browser_handoff_failed", "Browser handoff failed", { cause });
    }
    return { expiresAt, requestedScopes: request.scopes };
  }

  complete(options: DirectSignInCompleteOptions): Promise<DirectSignInResult> {
    return traced(
      this.#reactor,
      "pap.sign_in.direct.complete",
      { "pap.sign_in.method": "direct" },
      () => this.#complete(options),
      signInResult,
    );
  }

  async #complete(options: DirectSignInCompleteOptions): Promise<DirectSignInResult> {
    const state = callbackState(options.callbackUrl);
    const store = firstContribution(
      this.#reactor,
      AuthorizationStateStores,
      "authorization state store",
    );
    const pending = await store.take(await stateReference(state));
    if (!isPendingDirectSignIn(pending)) {
      throw new AuthorizationError(
        "invalid_or_expired_state",
        "Authorization state is unknown, expired, or already used",
      );
    }
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    if (clock.now().getTime() > pending.expiresAt.getTime()) {
      throw new AuthorizationError("invalid_or_expired_state", "Authorization state has expired");
    }
    const callback = validateDirectSignInCallback(pending.request, options.callbackUrl);
    return this.#exchange(pending, callback, options.signal);
  }

  async #exchange(
    pending: PendingDirectSignIn,
    callback: DirectSignInCallback,
    signal?: AbortSignal,
  ): Promise<DirectSignInResult> {
    const request = pending.request;
    const form = {
      grant_type: "authorization_code",
      code: callback.code.reveal(),
      redirect_uri: request.redirectUri,
      code_verifier: request.codeVerifier.reveal(),
    };
    const response = await this.#sessions.tokenRequest({
      clientId: request.clientId,
      issuer: request.issuer,
      tokenEndpoint: pending.tokenEndpoint,
      form: () => form,
      error: AuthorizationError,
      ...(signal === undefined ? {} : { signal }),
    });
    return finishSignIn(this.#reactor, response, request.scopes, { error: AuthorizationError });
  }
}
