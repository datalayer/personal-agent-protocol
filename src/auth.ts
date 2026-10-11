import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { SecretValue } from "./secret.js";
import {
  JWT_CLIENT_ASSERTION,
  parseSessionToken,
  type RandomBytes,
  type SessionToken,
} from "./sessions.js";
import {
  AuthorizationStateStores,
  BrowserHandoffs,
  Clocks,
  DpopProofProviders,
  RandomSources,
  Signers,
  TokenStores,
  firstContribution,
} from "./reactor.js";

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
  const redirectUri = httpsUrl(options.redirectUri, "redirectUri").toString();
  const issuer = httpsUrl(options.issuer, "issuer").toString().replace(/\/$/, "");
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
  const expected = httpsUrl(request.redirectUri, "redirectUri");
  const callback = httpsUrl(callbackUrl, "callbackUrl");
  if (callback.hash) {
    throw new AuthorizationError("invalid_callback", "Authorization callback has a fragment");
  }
  if (callback.origin !== expected.origin || callback.pathname !== expected.pathname) {
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

export interface AuthorizationCodeGrantOptions {
  readonly code: string;
  readonly redirectUri: string;
  readonly codeVerifier: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly clientAssertion: string;
}

export class AuthorizationCodeGrant {
  readonly code: SecretValue;
  readonly redirectUri: string;
  readonly codeVerifier: SecretValue;
  readonly sessionId: string;
  readonly clientId: string;
  readonly clientAssertion: SecretValue;

  constructor(options: AuthorizationCodeGrantOptions) {
    this.code = new SecretValue(options.code);
    this.redirectUri = httpsUrl(options.redirectUri, "redirectUri").toString();
    this.codeVerifier = new SecretValue(options.codeVerifier);
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(options.sessionId)) {
      throw new AuthorizationError("invalid_session_id", "Invalid PAP session ID");
    }
    this.sessionId = options.sessionId;
    this.clientId = httpsUrl(options.clientId, "clientId").toString();
    this.clientAssertion = new SecretValue(options.clientAssertion);
  }

  toForm(): URLSearchParams {
    return new URLSearchParams({
      grant_type: "authorization_code",
      code: this.code.reveal(),
      redirect_uri: this.redirectUri,
      code_verifier: this.codeVerifier.reveal(),
      session_id: this.sessionId,
      client_id: this.clientId,
      client_assertion_type: JWT_CLIENT_ASSERTION,
      client_assertion: this.clientAssertion.reveal(),
    });
  }

  toJSON(): Record<string, unknown> {
    return {
      grant_type: "authorization_code",
      code: this.code,
      redirect_uri: this.redirectUri,
      code_verifier: this.codeVerifier,
      session_id: this.sessionId,
      client_id: this.clientId,
      client_assertion_type: JWT_CLIENT_ASSERTION,
      client_assertion: this.clientAssertion,
    };
  }
}

interface PendingDirectSignIn {
  readonly kind: "pap.direct-sign-in.v1";
  readonly request: DirectSignInRequest;
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly sessionId: string;
  readonly expiresAt: Date;
}

export interface DirectSignInStart {
  readonly expiresAt: Date;
  readonly requestedScopes: readonly string[];
}

/**
 * The signed-in Session, its scopes, and a reference to its stored Account Token.
 *
 * The Account Token never stays in `token`: it is moved into `pap.tokenStore`
 * behind `accountTokenReference` (§4.8).
 */
export interface DirectSignInResult {
  readonly token: SessionToken;
  readonly grantedScopes: readonly string[];
  readonly missingScopes: readonly string[];
  readonly accountTokenReference?: string;
}

export interface DirectSignInBeginOptions extends DirectSignInOptions {
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly sessionId: string;
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
  const callback = httpsUrl(callbackUrl, "callbackUrl");
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
    typeof pending.pairwiseUserId === "string" &&
    typeof pending.sessionId === "string" &&
    pending.expiresAt instanceof Date &&
    typeof pending.request === "object" &&
    pending.request !== null
  );
}

/** Orchestrate one-use browser authorization and proof-bound code exchange. */
export class DirectSignInClient {
  readonly #reactor: ReactorPlatformView;
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
  }

  async begin(options: DirectSignInBeginOptions): Promise<DirectSignInStart> {
    const lifetimeSeconds = options.lifetimeSeconds ?? 600;
    if (!Number.isInteger(lifetimeSeconds) || lifetimeSeconds < 1 || lifetimeSeconds > 900) {
      throw new RangeError("Direct Sign-In state lifetime must be between 1 and 900 seconds");
    }
    if (!options.tenantId || options.tenantId.length > 256) {
      throw new RangeError("tenantId must contain between 1 and 256 characters");
    }
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(options.pairwiseUserId)) {
      throw new AuthorizationError(
        "invalid_user_id",
        "Pairwise user ID must be an opaque URL-safe identifier",
      );
    }
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(options.sessionId)) {
      throw new AuthorizationError("invalid_session_id", "Invalid PAP session ID");
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
      pairwiseUserId: options.pairwiseUserId,
      sessionId: options.sessionId,
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

  async complete(options: DirectSignInCompleteOptions): Promise<DirectSignInResult> {
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
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const signer = firstContribution(this.#reactor, Signers, "signer");
    const dpop = firstContribution(
      this.#reactor,
      DpopProofProviders,
      "DPoP proof provider",
    );
    let nonce: string | undefined;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const iat = Math.floor(clock.now().getTime() / 1000);
      const clientAssertion = await signer.sign(
        {
          iss: pending.request.clientId,
          sub: pending.request.clientId,
          aud: pending.tokenEndpoint,
          iat,
          exp: iat + 60,
          jti: `jti_${base64Url(entropy(16, (length) => random.bytes(length)))}`,
        },
        { purpose: "client_assertion" },
      );
      const proof = await dpop.create({
        method: "POST",
        url: pending.tokenEndpoint,
        tenantId: pending.tenantId,
        subject: pending.pairwiseUserId,
        issuer: pending.request.issuer,
        ...(nonce === undefined ? {} : { nonce }),
      });
      const grant = new AuthorizationCodeGrant({
        code: callback.code.reveal(),
        redirectUri: pending.request.redirectUri,
        codeVerifier: pending.request.codeVerifier.reveal(),
        sessionId: pending.sessionId,
        clientId: pending.request.clientId,
        clientAssertion: clientAssertion.reveal(),
      });
      let response: Response;
      try {
        response = await this.#fetch(pending.tokenEndpoint, {
          method: "POST",
          headers: { Accept: "application/json", DPoP: proof.reveal() },
          body: grant.toForm(),
          credentials: "omit",
          redirect: "error",
          ...(signal === undefined ? {} : { signal }),
        });
      } catch (cause) {
        throw new AuthorizationError(
          "request_failed",
          "Direct Sign-In token exchange failed",
          { cause },
        );
      }
      const payload = await this.#decode(response);
      if (response.ok) return await this.#result(response, payload, pending);

      const source = typeof payload === "object" && payload !== null ? payload : {};
      const remoteCode = "error" in source ? (source as { error?: unknown }).error : undefined;
      const code = typeof remoteCode === "string" ? remoteCode : "http_error";
      if (code === "use_dpop_nonce" && attempt === 0) {
        nonce = response.headers.get("dpop-nonce") ?? undefined;
        if (!nonce) {
          throw new AuthorizationError(
            "missing_dpop_nonce",
            "Company requested a DPoP nonce but did not send one",
            { statusCode: response.status },
          );
        }
        continue;
      }
      throw new AuthorizationError(code, "Company refused the Direct Sign-In token exchange", {
        statusCode: response.status,
      });
    }
    throw new AuthorizationError("use_dpop_nonce", "Company rejected the refreshed DPoP proof");
  }

  async #decode(response: Response): Promise<unknown> {
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    if (contentType !== "application/json") {
      throw new AuthorizationError(
        "invalid_content_type",
        "Direct Sign-In token endpoint must return JSON",
        { statusCode: response.status },
      );
    }
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > this.#maxResponseBytes) {
      throw new AuthorizationError(
        "response_too_large",
        "Direct Sign-In response exceeds size limit",
        { statusCode: response.status },
      );
    }
    try {
      return parseJsonStrict(body);
    } catch (cause) {
      throw new AuthorizationError(
        "invalid_json",
        "Direct Sign-In token endpoint returned invalid JSON",
        { statusCode: response.status, cause },
      );
    }
  }

  async #result(
    response: Response,
    payload: unknown,
    pending: PendingDirectSignIn,
  ): Promise<DirectSignInResult> {
    let token: SessionToken;
    try {
      token = parseSessionToken(payload);
    } catch (cause) {
      throw new AuthorizationError(
        "invalid_token_response",
        "Direct Sign-In token response is malformed",
        { statusCode: response.status, cause },
      );
    }
    if (token.tokenType !== "DPoP" || !token.signedIn) {
      throw new AuthorizationError(
        "invalid_token_response",
        "Direct Sign-In must return a signed-in DPoP Session Token",
        { statusCode: response.status },
      );
    }
    if (token.sessionId !== pending.sessionId) {
      throw new AuthorizationError(
        "session_mismatch",
        "Direct Sign-In response changed the existing Session",
        { statusCode: response.status },
      );
    }
    if (token.scopes.some((scope) => !pending.request.scopes.includes(scope))) {
      throw new AuthorizationError(
        "scope_escalation",
        "Company returned a scope that was not requested",
        { statusCode: response.status },
      );
    }
    let accountTokenReference: string | undefined;
    if (token.accountToken !== undefined) {
      // The Account Token is a secret (§4.8): behind an opaque reference, never returned.
      const random = firstContribution(this.#reactor, RandomSources, "random source");
      accountTokenReference = `account_${base64Url(random.bytes(16))}`;
      await firstContribution(this.#reactor, TokenStores, "token store").put(
        accountTokenReference,
        token.accountToken,
      );
    }
    const { accountToken: _account, ...publicToken } = token;
    return {
      token: publicToken,
      grantedScopes: publicToken.scopes,
      missingScopes: pending.request.scopes.filter((scope) => !publicToken.scopes.includes(scope)),
      ...(accountTokenReference === undefined ? {} : { accountTokenReference }),
    };
  }
}
