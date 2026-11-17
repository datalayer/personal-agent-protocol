/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { readLimitedText } from "./limits.js";
import { isLoopbackRedirect } from "./models.js";
import { SecretValue } from "./secret.js";
import {
  DPOP_HEADER,
  DPOP_NONCE_HEADER,
  SessionClient,
  finishSignIn,
  provesWithDpop,
  type RandomBytes,
  type SignInResult,
} from "./sessions.js";
import {
  AuthorizationStateStores,
  BrowserHandoffs,
  Clocks,
  DpopProvers,
  RandomSources,
  firstContribution,
} from "./reactor.js";
import { refusalCode, refuseRedirect, refusedWithoutBody } from "./refusals.js";
import { byIssuer, signInResult, traced } from "./telemetry.js";

/** The parameters a Direct Sign-In request sets: an endpoint's own values for them are dropped. */
const AUTHORIZATION_PARAMETERS = [
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
  "prompt",
  "request_uri",
] as const;

/**
 * The OpenID Connect `prompt` a Direct Sign-In request carries (OpenID Connect Core §3.1.2.1,
 * §4.2): the Company shows its consent page even when the account granted every scope to the
 * `client_id` before (§10.8).
 */
export const PROMPT_CONSENT = "consent";

/** The authorization endpoint with none of the parameters a Direct Sign-In request sets. */
function bareEndpoint(endpoint: string): URL {
  const url = new URL(endpoint);
  for (const name of AUTHORIZATION_PARAMETERS) url.searchParams.delete(name);
  url.hash = "";
  return url;
}

/**
 * The authorization URL after a push (RFC 9126 §4): `client_id` and `request_uri` only, on the
 * authorization endpoint.
 */
function pushedUrl(authorizationEndpoint: string, clientId: string, requestUri: string): SecretValue {
  const url = bareEndpoint(authorizationEndpoint);
  url.searchParams.append("client_id", clientId);
  url.searchParams.append("request_uri", requestUri);
  return new SecretValue(url.toString());
}

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
  /**
   * Add `prompt=consent` (§4.2, §10.8): a request MUST carry it unless the Personal Agent
   * receives the redirect only on the device that opened the authorization URL; only then is it
   * `false`. Default `true`.
   */
  readonly promptConsent?: boolean;
}

/**
 * Authorization request state; its URL and PKCE values are secrets.
 *
 * `authorizationUrl` carries every parameter; `parameters`, the same parameters form encoded, is
 * what a Pushed Authorization Request sends (RFC 9126, §4.2), after which the browser opens
 * `pushedAuthorizationUrl(requestUri)` with only `client_id` and `request_uri`.
 */
export interface DirectSignInRequest {
  readonly authorizationUrl: SecretValue;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly state: SecretValue;
  readonly codeVerifier: SecretValue;
  /** The authorization endpoint, as given. */
  readonly authorizationEndpoint: string;
  /** The request's parameters, form encoded: what a push sends (RFC 9126 §2.1). */
  readonly parameters: SecretValue;
  /**
   * The authorization URL after a push (RFC 9126 §4): `client_id` and `requestUri` only, on the
   * authorization endpoint.
   */
  pushedAuthorizationUrl(requestUri: string): SecretValue;
}

/**
 * Build a user-browser authorization URL with random state and S256 PKCE (§4.2).
 *
 * Plain OAuth: the sign-in names no Session, and any of the User's Sessions uses the tokens it
 * returns (§5.4). It names no `resource` either: one sign-in covers every service the Company
 * offers, and each token request names one (§4.5). It carries `prompt=consent` unless
 * `promptConsent` is `false` (§4.2, §10.8).
 */
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
  const parameters: [string, string][] = [
    ["response_type", "code"],
    ["client_id", clientId],
    ["redirect_uri", redirectUri],
    ["scope", scopes.join(" ")],
    ["state", state],
    ["code_challenge", challenge],
    ["code_challenge_method", "S256"],
  ];
  if (options.promptConsent !== false) parameters.push(["prompt", PROMPT_CONSENT]);
  const url = bareEndpoint(endpoint.toString());
  for (const [name, value] of parameters) url.searchParams.append(name, value);
  const authorizationEndpoint = endpoint.toString();
  return {
    authorizationUrl: new SecretValue(url.toString()),
    issuer,
    clientId,
    redirectUri,
    scopes,
    state: new SecretValue(state),
    codeVerifier: new SecretValue(verifier),
    authorizationEndpoint,
    parameters: new SecretValue(new URLSearchParams(parameters).toString()),
    pushedAuthorizationUrl: (requestUri: string) => pushedUrl(authorizationEndpoint, clientId, requestUri),
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
  readonly dpopSigningAlgs: readonly string[] | undefined;
  readonly pairwiseUserId: string | undefined;
  /** Where the request is pushed (RFC 9126), when it is: each opening pushes it again. */
  readonly pushedAuthorizationRequestEndpoint: string | undefined;
}

export interface DirectSignInStart {
  readonly expiresAt: Date;
  readonly requestedScopes: readonly string[];
  /**
   * Whether the authorization URL opens on a device other than the one the User is using
   * (§4.2): a cross-device flow, as Device Sign-In always is (§10.8).
   */
  readonly crossDevice: boolean;
}

/**
 * The longest a Direct Sign-In request lives when its link opens on another device: a
 * cross-device request is short-lived (RFC 10027 §2, which §4.2 makes a MUST there).
 */
export const CROSS_DEVICE_LIFETIME_SECONDS = 300;

/** A completed Direct Sign-In: the access token, and the refresh token's reference. */
export type DirectSignInResult = SignInResult;

/** Plain OAuth: the sign-in names no Session, and any of the User's Sessions uses its tokens (§5.4). */
export interface DirectSignInBeginOptions extends Omit<DirectSignInOptions, "promptConsent"> {
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  /** How long the one-use state lives: 600 seconds by default, 300 at most with `crossDevice`. */
  readonly lifetimeSeconds?: number;
  /**
   * The URL opens on a device other than the one the User is using, such as a link sent to a
   * phone. Nothing in the redirect says who approved the sign-in (§10.8): the request then
   * lives at most `CROSS_DEVICE_LIFETIME_SECONDS` (RFC 10027 §2), the host asks only for the
   * scopes the task needs, and it says who the link is for when it shows it. Whenever it can,
   * the host receives the redirect only on the device that opened the URL (a loopback
   * `redirectUri`, or its own app signed in as the User who started), and names the User it
   * finds there to `complete({ completedBy })`.
   */
  readonly crossDevice?: boolean;
  /**
   * The issuer's `dpop_signing_alg_values_supported`: the code exchange sends a DPoP proof
   * when it includes ES256 (§4.5), by the DPoP key of `pairwiseUserId`, which proving needs.
   */
  readonly dpopSigningAlgs?: readonly string[] | undefined;
  /** The User ID the sign-in is for: its DPoP key proves the code exchange (§4.5). */
  readonly pairwiseUserId?: string | undefined;
  /**
   * The host receives the redirect only on the device that opened the URL (a loopback
   * `redirectUri`, or its own app signed in as the User who started): only then does the request
   * go without `prompt=consent`, which otherwise has the Company show its consent page even for
   * scopes the account granted before (§4.2, §10.8).
   */
  readonly sameDeviceRedirect?: boolean;
  /**
   * The issuer's `pushed_authorization_request_endpoint` (RFC 9126, §3.2): the request is pushed
   * there with a client assertion, and a DPoP proof when tokens are bound, and the browser opens
   * the authorization endpoint with only `client_id` and `request_uri` (§4.2: a SHOULD whenever
   * it is listed, a MUST when required).
   */
  readonly pushedAuthorizationRequestEndpoint?: string | undefined;
  /**
   * The issuer's `require_pushed_authorization_requests`: refused (`RangeError`) without
   * `pushedAuthorizationRequestEndpoint`, before anything is sent (RFC 9126 §5).
   */
  readonly requirePushedAuthorizationRequests?: boolean;
  /**
   * The agent's own page for a link the User opens later, an HTTPS URL with `{link}`: a
   * `request_uri` expires quickly, so the browser handoff gets this page, and the page calls
   * `openLink(link)` when opened, which pushes the request and returns the authorization URL to
   * redirect to (§4.2).
   */
  readonly linkPage?: string;
}

export interface DirectSignInCompleteOptions {
  readonly callbackUrl: string;
  /**
   * The `tenantId` of the User the host found in the browser at `redirectUri`, when it can
   * tell, such as by its own sign-in there: a redirect that arrives for another User than the
   * one who started the sign-in is refused (`sign_in_started_by_another_user`), the state used
   * up and no code exchanged, so a link someone forwarded gives its sender no tokens (§4.2,
   * §10.8).
   */
  readonly completedBy?: string;
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

/** A sign-in link's key in the authorization state store: its digest, never the link. */
async function linkReference(link: string): Promise<string> {
  if ([...link].some((character) => character.charCodeAt(0) > 0x7f)) {
    throw new AuthorizationError("invalid_or_expired_state", "The sign-in link is invalid");
  }
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi) {
    throw new AuthorizationError("crypto_unavailable", "Web Crypto is required");
  }
  const digest = await cryptoApi.subtle.digest("SHA-256", new TextEncoder().encode(link));
  return `direct-link:${Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/** A response's JSON body, or `undefined` when it has none that parses. */
function jsonBody(response: Response, text: string): unknown {
  if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json") return undefined;
  try {
    return parseJsonStrict(text);
  } catch {
    return undefined;
  }
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

/** Orchestrate one-use browser authorization and the code exchange. */
export class DirectSignInClient {
  readonly #reactor: ReactorPlatformView;
  readonly #sessions: SessionClient;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxResponseBytes: number;

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
    this.#fetch = fetcher;
    this.#maxResponseBytes = maxResponseBytes;
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
    const crossDevice = options.crossDevice === true;
    const longest = crossDevice ? CROSS_DEVICE_LIFETIME_SECONDS : 900;
    const lifetimeSeconds = options.lifetimeSeconds ?? Math.min(600, longest);
    if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > longest) {
      throw new RangeError(`Direct Sign-In state lifetime must be between 1 and ${longest} seconds`);
    }
    if (!options.tenantId || options.tenantId.length > 256) {
      throw new RangeError("tenantId must contain between 1 and 256 characters");
    }
    if (options.requirePushedAuthorizationRequests === true && options.pushedAuthorizationRequestEndpoint === undefined) {
      throw new RangeError("a Company that requires PAR lists where to push (RFC 9126 §5)");
    }
    const linkPage = options.linkPage;
    if (linkPage !== undefined) {
      if (!linkPage.includes("{link}")) throw new RangeError("linkPage is an HTTPS URL with {link}");
      httpsUrl(linkPage.replaceAll("{link}", "x"), "linkPage");
    }
    const pushedEndpoint =
      options.pushedAuthorizationRequestEndpoint === undefined
        ? undefined
        : httpsUrl(options.pushedAuthorizationRequestEndpoint, "pushedAuthorizationRequestEndpoint").toString();
    provesWithDpop(options.dpopSigningAlgs, options.pairwiseUserId);
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
      promptConsent: options.sameDeviceRedirect !== true,
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
      dpopSigningAlgs: options.dpopSigningAlgs,
      pairwiseUserId: options.pairwiseUserId,
      pushedAuthorizationRequestEndpoint: pushedEndpoint,
    };
    await store.put(reference, pending, { expiresAt });
    let link: string | undefined;
    let opened: SecretValue;
    try {
      if (linkPage !== undefined) {
        link = base64Url(entropy(16, (length) => random.bytes(length)));
        await store.put(await linkReference(link), reference, { expiresAt });
        opened = new SecretValue(linkPage.replaceAll("{link}", link));
      } else {
        opened = await this.#authorizationUrl(pending);
      }
    } catch (error) {
      await store.take(reference);
      if (link !== undefined) await store.take(await linkReference(link));
      throw error;
    }
    try {
      await browser.open(opened);
    } catch (cause) {
      await store.take(reference);
      if (link !== undefined) await store.take(await linkReference(link));
      throw new AuthorizationError("browser_handoff_failed", "Browser handoff failed", { cause });
    }
    return { expiresAt, requestedScopes: request.scopes, crossDevice };
  }

  /**
   * The authorization URL for a sign-in link the User opened on the agent's own page
   * (`begin({ linkPage })`, §4.2): the request pushed now when the Company takes PAR, so its
   * short-lived `request_uri` is fresh, else the full URL. The page redirects the browser there.
   * A link may be opened again until the sign-in completes or expires; `AuthorizationError`
   * (`invalid_or_expired_state`) for an unknown or expired one.
   */
  async openLink(link: string): Promise<SecretValue> {
    const store = firstContribution(this.#reactor, AuthorizationStateStores, "authorization state store");
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const linkKey = await linkReference(link);
    const reference = await store.take(linkKey);
    const pending = typeof reference === "string" ? await store.take(reference) : undefined;
    if (!isPendingDirectSignIn(pending) || clock.now().getTime() > pending.expiresAt.getTime()) {
      throw new AuthorizationError("invalid_or_expired_state", "The sign-in link is unknown or has expired");
    }
    await store.put(reference as string, pending, { expiresAt: pending.expiresAt });
    await store.put(linkKey, reference, { expiresAt: pending.expiresAt });
    return this.#authorizationUrl(pending);
  }

  /** The URL the browser opens: after a push when the Company takes PAR (§4.2). */
  async #authorizationUrl(pending: PendingDirectSignIn): Promise<SecretValue> {
    if (pending.pushedAuthorizationRequestEndpoint === undefined) return pending.request.authorizationUrl;
    const request = pending.request;
    return pushedUrl(request.authorizationEndpoint, request.clientId, await this.#push(pending));
  }

  /**
   * Push the request (RFC 9126 §2): its parameters, a fresh client assertion, and a DPoP proof
   * when tokens are bound, so the code is bound to the key (RFC 9449 §10.1); a `use_dpop_nonce`
   * refusal is retried once. The `request_uri`.
   */
  async #push(pending: PendingDirectSignIn): Promise<string> {
    const request = pending.request;
    const endpoint = pending.pushedAuthorizationRequestEndpoint as string;
    const proves = provesWithDpop(pending.dpopSigningAlgs, pending.pairwiseUserId);
    let nonce: string | undefined;
    let response: Response;
    let payload: unknown;
    while (true) {
      const body = new URLSearchParams(request.parameters.reveal());
      for (const [name, value] of Object.entries(
        await this.#sessions.clientAuthentication({ clientId: request.clientId, issuer: request.issuer }),
      )) {
        body.set(name, value);
      }
      const headers: Record<string, string> = { Accept: "application/json" };
      if (proves) {
        const proof = await firstContribution(this.#reactor, DpopProvers, "DPoP prover").prove({
          method: "POST",
          url: endpoint,
          tenantId: pending.tenantId,
          issuer: request.issuer,
          sub: pending.pairwiseUserId as string,
          ...(nonce === undefined ? {} : { nonce }),
        });
        headers[DPOP_HEADER] = proof.reveal();
      }
      try {
        response = await this.#fetch(endpoint, {
          method: "POST",
          headers,
          body,
          credentials: "omit",
          redirect: "manual",
        });
      } catch (cause) {
        throw new AuthorizationError("request_failed", "Pushed authorization failed", { cause });
      }
      await refuseRedirect(response, AuthorizationError);
      const text = await readLimitedText(response, this.#maxResponseBytes);
      if (new TextEncoder().encode(text).byteLength > this.#maxResponseBytes) {
        throw new AuthorizationError("response_too_large", "Pushed authorization response exceeds size limit", {
          statusCode: response.status,
        });
      }
      payload = refusedWithoutBody(response, text) ? undefined : jsonBody(response, text);
      const given = response.headers.get(DPOP_NONCE_HEADER);
      if (
        proves &&
        nonce === undefined &&
        given !== null &&
        response.status === 400 &&
        (payload as { error?: unknown } | undefined)?.error === "use_dpop_nonce"
      ) {
        nonce = given;
        continue;
      }
      break;
    }
    if (response.status !== 200 && response.status !== 201) {
      throw new AuthorizationError(
        refusalCode(response, payload, "http_error"),
        "The company refused the pushed authorization request",
        { statusCode: response.status },
      );
    }
    const answer = (typeof payload === "object" && payload !== null ? payload : {}) as Record<string, unknown>;
    const requestUri = answer.request_uri;
    const expiresIn = answer.expires_in;
    if (typeof requestUri !== "string" || !requestUri || !Number.isInteger(expiresIn) || (expiresIn as number) <= 0) {
      throw new AuthorizationError("invalid_par_response", "The pushed authorization response is malformed");
    }
    return requestUri;
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
    if (options.completedBy !== undefined && options.completedBy !== pending.tenantId) {
      throw new AuthorizationError(
        "sign_in_started_by_another_user",
        "The redirect arrived for another User than the one who started the sign-in",
      );
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
      tenantId: pending.tenantId,
      dpopSigningAlgs: pending.dpopSigningAlgs,
      pairwiseUserId: pending.pairwiseUserId,
      ...(signal === undefined ? {} : { signal }),
    });
    return finishSignIn(this.#reactor, response, request.scopes, { error: AuthorizationError });
  }
}
