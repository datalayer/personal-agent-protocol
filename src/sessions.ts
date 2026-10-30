/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Sessions, client assertions, and plain OAuth token responses (§4, §5).
 *
 * A Session is local: `SessionClient.start` chooses its `sid` at random and asks the company
 * nothing (§5.2). Every request then carries a Session JWT the `pap.sessionSigner` signs for
 * it (`SessionFetchClient`). Account access is plain OAuth: sign-in and refresh return an
 * access token and a refresh token (§4.4, §4.5, §4.7); the token endpoint gets a client
 * assertion and nothing else.
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { SESSION_ID } from "./crypto.js";
import { PersonalAgentProtocolError, ProtocolValidationError, SessionError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { readLimitedText } from "./limits.js";
import {
  Clocks,
  PairwiseUserIdStores,
  RandomSources,
  Signers,
  TokenStores,
  firstContribution,
  type PairwiseUserIdStore,
} from "./reactor.js";
import { refusalCode, refusalDetails, refuseRedirect, refusedWithoutBody } from "./refusals.js";
import { SecretValue } from "./secret.js";
import { byIssuer, sessionResult, traced } from "./telemetry.js";

export const JWT_CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/** A client assertion's `exp` is at most this long after its `iat` (§4.1). */
export const ASSERTION_MAX_LIFETIME_SECONDS = 300;

export type RandomBytes = (length: number) => Uint8Array;

function defaultRandomBytes(length: number): Uint8Array {
  const cryptoApi = globalThis.crypto;
  if (!cryptoApi) {
    throw new Error("A cryptographically secure random source is required");
  }
  return cryptoApi.getRandomValues(new Uint8Array(length));
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

function randomId(randomBytes: RandomBytes): string {
  const bytes = randomBytes(16);
  if (bytes.byteLength < 16) {
    throw new Error("Opaque PAP identifiers require at least 128 random bits");
  }
  return base64Url(bytes);
}

export function opaqueId(prefix: string, randomBytes: RandomBytes): string {
  return `${prefix}_${randomId(randomBytes)}`;
}

export function generatePairwiseUserId(randomBytes: RandomBytes = defaultRandomBytes): string {
  return opaqueId("usr", randomBytes);
}

/** A new `sid`: 128 random bits, 22 URL-safe characters, never used again (§5.2). */
export function newSessionId(randomBytes: RandomBytes = defaultRandomBytes): string {
  return randomId(randomBytes);
}

export async function resolvePairwiseUserId(
  reactor: ReactorPlatformView,
  options: {
    readonly tenantId: string;
    readonly localUserId: string;
    readonly companyIssuer: string;
  },
): Promise<string> {
  const store = firstContribution(
    reactor,
    PairwiseUserIdStores,
    "pairwise user ID store",
  ) as PairwiseUserIdStore;
  return store.getOrCreate(options);
}

/** The claims of a `private_key_jwt` client assertion (§4.1). */
export interface ClientAssertionClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
}

export interface ClientAssertionOptions {
  readonly clientId: string;
  /** The company's issuer, whichever endpoint the assertion goes to (§4.1, §10.4). */
  readonly issuer: string;
  readonly now?: Date;
  readonly lifetimeSeconds?: number;
  readonly randomBytes?: RandomBytes;
}

function issuedAt(now: Date | undefined, lifetime: number): number {
  if (!Number.isInteger(lifetime) || lifetime <= 0 || lifetime > ASSERTION_MAX_LIFETIME_SECONDS) {
    throw new ProtocolValidationError(
      "invalid_assertion_lifetime",
      "Assertion lifetime must be between 1 and 300 seconds",
    );
  }
  return Math.floor((now ?? new Date()).getTime() / 1000);
}

function httpsUrl(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause) {
    throw new ProtocolValidationError("invalid_url", `${label} must be an HTTPS URL`, {
      cause,
    });
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new ProtocolValidationError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return value;
}

/**
 * Build unsigned `private_key_jwt` claims for any request to the company's OAuth server.
 *
 * `aud` is the company's issuer, one string, whichever endpoint the assertion goes to: token,
 * revocation, or device authorization (§4.1, §10.4). `jti` is drawn here, on the device, so a
 * blind signer never chooses it (§10.7).
 */
export function buildClientAssertionClaims(options: ClientAssertionOptions): ClientAssertionClaims {
  const lifetime = options.lifetimeSeconds ?? 60;
  const iat = issuedAt(options.now, lifetime);
  const clientId = httpsUrl(options.clientId, "clientId");
  return {
    iss: clientId,
    sub: clientId,
    aud: httpsUrl(options.issuer, "issuer"),
    iat,
    exp: iat + lifetime,
    jti: randomId(options.randomBytes ?? defaultRandomBytes),
  };
}

/** What a Session is, as a host keeps it (`PapSession.toJson`). */
export interface PapSessionJson {
  readonly sid: string;
  readonly sub: string;
  readonly issuer: string;
  readonly client_id: string;
  readonly tenant_id: string;
  readonly agent_id: string | null;
}

/**
 * One Session: a User at one Company through this personal agent (§5).
 *
 * Local: `sid` names it, chosen at random; `sub` is the User ID for the Company's `issuer`,
 * `agentId` the optional Agent ID, both the same for its whole life. When the company answers
 * `invalid_session`, `restart` gives it a new `sid` once (§5.5, §7); its handle for a person
 * is `ses_` and the `sid`.
 */
export class PapSession {
  sid: string;
  readonly sub: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly tenantId: string;
  readonly agentId: string | undefined;

  constructor(options: {
    readonly sid: string;
    readonly sub: string;
    readonly issuer: string;
    readonly clientId: string;
    readonly tenantId: string;
    readonly agentId?: string | undefined;
  }) {
    if (!SESSION_ID.test(options.sid)) {
      throw new ProtocolValidationError(
        "invalid_session_id",
        "a Session ID is 22 to 256 URL-safe characters",
      );
    }
    if (!options.sub) {
      throw new ProtocolValidationError("invalid_user_id", "a Session names its User ID");
    }
    if (options.agentId !== undefined && !/^[A-Za-z0-9_-]{1,256}$/.test(options.agentId)) {
      throw new ProtocolValidationError(
        "invalid_agent_id",
        "Agent ID must use the URL-safe base64 alphabet",
      );
    }
    if (!options.tenantId || options.tenantId.length > 256) {
      throw new RangeError("tenantId must contain between 1 and 256 characters");
    }
    this.sid = options.sid;
    this.sub = options.sub;
    this.issuer = httpsUrl(options.issuer, "issuer");
    this.clientId = httpsUrl(options.clientId, "clientId");
    this.tenantId = options.tenantId;
    this.agentId = options.agentId;
  }

  /** The Session's name for a person or a CLI: `ses_` and its `sid`. */
  get handle(): string {
    return `ses_${this.sid}`;
  }

  get pairwiseUserId(): string {
    return this.sub;
  }

  /** Start a new Session in its place: a new `sid`, the same User and Agent ID. */
  restart(randomBytes: RandomBytes = defaultRandomBytes): string {
    this.sid = newSessionId(randomBytes);
    return this.sid;
  }

  toJson(): PapSessionJson {
    return {
      sid: this.sid,
      sub: this.sub,
      issuer: this.issuer,
      client_id: this.clientId,
      tenant_id: this.tenantId,
      agent_id: this.agentId ?? null,
    };
  }

  static fromJson(value: PapSessionJson): PapSession {
    return new PapSession({
      sid: value.sid,
      sub: value.sub,
      issuer: value.issuer,
      clientId: value.client_id,
      tenantId: value.tenant_id,
      ...(value.agent_id === null ? {} : { agentId: value.agent_id }),
    });
  }
}

/**
 * A token endpoint's answer, as on the wire (§4.7): plain OAuth.
 *
 * `token_type` is compared ignoring case (RFC 6749 §5.1). This SDK does not send DPoP proofs
 * yet (§4.5: a SHOULD), so a `DPoP` token is refused.
 */
export interface TokenResponse {
  readonly accessToken: SecretValue;
  readonly tokenType: "Bearer";
  readonly expiresIn?: number;
  readonly scope?: string;
  readonly refreshToken?: SecretValue;
}

/**
 * An access token for one account, kept beside what the SDK knows of it (§4.5).
 *
 * `resource` is the service it was issued for, or absent for the default token that works at
 * all of the Company's services but one that asks for its own. `scopes` is what was granted:
 * a response that leaves `scope` out granted exactly the scopes requested (RFC 6749 §5.1).
 * Never the refresh token: that one stays in `pap.tokenStore`.
 */
export interface AccessToken {
  readonly accessToken: SecretValue;
  readonly tokenType: "Bearer";
  readonly expiresIn?: number;
  readonly scopes: readonly string[];
  readonly resource?: string;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProtocolValidationError("invalid_type", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) {
    throw new ProtocolValidationError("invalid_type", `${label} must be a string`);
  }
  return value;
}

/** A token endpoint's JSON answer (§4.7). */
export function parseTokenResponse(value: unknown): TokenResponse {
  const source = object(value, "token response");
  const tokenType = nonEmptyString(source.token_type, "token_type").toLowerCase();
  if (tokenType === "dpop") {
    throw new ProtocolValidationError(
      "unsupported_token_type",
      "DPoP-bound access tokens are not supported by this SDK yet",
    );
  }
  if (tokenType !== "bearer") {
    throw new ProtocolValidationError("invalid_token_type", "an access token is Bearer");
  }
  const expiresIn = source.expires_in;
  if (
    expiresIn !== undefined &&
    expiresIn !== null &&
    (!Number.isInteger(expiresIn) || (expiresIn as number) <= 0)
  ) {
    throw new ProtocolValidationError("invalid_expiry", "expires_in must be positive");
  }
  const scope = source.scope;
  if (scope !== undefined && scope !== null && typeof scope !== "string") {
    throw new ProtocolValidationError("invalid_type", "scope must be a string");
  }
  const refresh = source.refresh_token;
  return {
    accessToken: new SecretValue(nonEmptyString(source.access_token, "access_token")),
    tokenType: "Bearer",
    ...(expiresIn === undefined || expiresIn === null ? {} : { expiresIn: expiresIn as number }),
    ...(typeof scope === "string" ? { scope } : {}),
    ...(refresh === undefined || refresh === null
      ? {}
      : { refreshToken: new SecretValue(nonEmptyString(refresh, "refresh_token")) }),
  };
}

/**
 * An access token from a token response (§4.7).
 *
 * A response without `scope` granted exactly `requestedScopes`, and one that grants none is
 * refused: approving none is a decline.
 */
export function accessTokenFromResponse(
  response: TokenResponse,
  options: { readonly requestedScopes?: readonly string[]; readonly resource?: string } = {},
): AccessToken {
  const scope = response.scope ?? (options.requestedScopes ?? []).join(" ");
  if (!scope.trim()) {
    throw new ProtocolValidationError("invalid_token_response", "A token response grants no scope");
  }
  return {
    accessToken: response.accessToken,
    tokenType: "Bearer",
    ...(response.expiresIn === undefined ? {} : { expiresIn: response.expiresIn }),
    scopes: scope.split(" ").filter(Boolean),
    ...(options.resource === undefined ? {} : { resource: options.resource }),
  };
}

/**
 * A completed sign-in (§4.7): the access token, and the refresh token's reference.
 *
 * The refresh token never stays in `token`: it is moved into `pap.tokenStore` behind
 * `refreshTokenReference`. `missingScopes` are requested scopes the User didn't approve.
 */
export interface SignInResult {
  readonly token: AccessToken;
  readonly grantedScopes: readonly string[];
  readonly missingScopes: readonly string[];
  readonly refreshTokenReference?: string;
}

/** Error classes a token request raises: each takes `(code, message, options)`. */
export type TokenErrorClass = new (
  code: string,
  message: string,
  options?: {
    readonly statusCode?: number;
    readonly details?: Readonly<Record<string, unknown>>;
    readonly cause?: unknown;
  },
) => PersonalAgentProtocolError;

/**
 * Check a sign-in's token response and keep its refresh token behind a reference.
 *
 * At least one scope is granted, and none beyond those requested (§4.7).
 */
export async function finishSignIn(
  reactor: ReactorPlatformView,
  response: TokenResponse,
  requested: readonly string[],
  options: { readonly error: TokenErrorClass },
): Promise<SignInResult> {
  const Failure = options.error;
  let token: AccessToken;
  try {
    token = accessTokenFromResponse(response, { requestedScopes: requested });
  } catch (cause) {
    if (!(cause instanceof ProtocolValidationError)) throw cause;
    throw new Failure("invalid_token_response", cause.message, { cause });
  }
  if (token.scopes.some((scope) => !requested.includes(scope))) {
    throw new Failure("scope_escalation", "Company returned a scope that was not requested");
  }
  let refreshTokenReference: string | undefined;
  if (response.refreshToken !== undefined) {
    const random = firstContribution(reactor, RandomSources, "random source");
    refreshTokenReference = opaqueId("refresh", (length) => random.bytes(length));
    await firstContribution(reactor, TokenStores, "token store").put(
      refreshTokenReference,
      response.refreshToken,
    );
  }
  return {
    token,
    grantedScopes: token.scopes,
    missingScopes: requested.filter((scope) => !token.scopes.includes(scope)),
    ...(refreshTokenReference === undefined ? {} : { refreshTokenReference }),
  };
}

export interface SessionStartOptions {
  readonly clientId: string;
  /** The User ID for the Company's `issuer` (§5.1). */
  readonly pairwiseUserId: string;
  readonly issuer: string;
  readonly tenantId: string;
  /** When the User has several agents, which one (§5.1). */
  readonly agentId?: string;
}

export interface TokenRequestOptions {
  readonly clientId: string;
  readonly issuer: string;
  readonly tokenEndpoint: string;
  /** The grant's own fields. */
  readonly form: () => Record<string, string> | Promise<Record<string, string>>;
  readonly error: TokenErrorClass;
  readonly signal?: AbortSignal;
}

export interface SessionClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

/** Start Sessions, and send grants to the company's token endpoint (§4, §5). */
export class SessionClient {
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxResponseBytes: number;

  constructor(options: SessionClientOptions) {
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) throw new SessionError("fetch_unavailable", "A fetch implementation is required");
    const maxResponseBytes = options.maxResponseBytes ?? 100 * 1024;
    if (!Number.isInteger(maxResponseBytes) || maxResponseBytes <= 0) {
      throw new RangeError("maxResponseBytes must be a positive integer");
    }
    this.#reactor = options.reactor;
    this.#fetch = fetcher;
    this.#maxResponseBytes = maxResponseBytes;
  }

  /**
   * A new Session, signed out, with a new random `sid` (§5.2): no request is sent.
   *
   * `pairwiseUserId` is the User ID for the Company's `issuer` (§5.1); `agentId`, when the
   * User has several agents, says which one.
   */
  start(options: SessionStartOptions): Promise<PapSession> {
    return traced(
      this.#reactor,
      "pap.session.start",
      byIssuer(options.issuer),
      async () =>
        new PapSession({
          sid: newSessionId((length) => this.#random().bytes(length)),
          sub: options.pairwiseUserId,
          issuer: options.issuer,
          clientId: options.clientId,
          tenantId: options.tenantId,
          ...(options.agentId === undefined ? {} : { agentId: options.agentId }),
        }),
      sessionResult,
    );
  }

  /**
   * POST one grant to the token endpoint with a fresh client assertion (§4.1, §4.4).
   *
   * `form` gives the grant's own fields. No Session header goes to an OAuth endpoint (§5.2).
   * Throws `error` with the company's OAuth error code.
   */
  async tokenRequest(options: TokenRequestOptions): Promise<TokenResponse> {
    const Failure = options.error;
    const tokenEndpoint = httpsUrl(options.tokenEndpoint, "tokenEndpoint");
    const fields = await options.form();
    const body = new URLSearchParams({
      ...fields,
      ...(await this.clientAuthentication({ clientId: options.clientId, issuer: options.issuer })),
    });
    let response: Response;
    try {
      response = await this.#fetch(tokenEndpoint, {
        method: "POST",
        headers: { Accept: "application/json" },
        body,
        credentials: "omit",
        redirect: "manual",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (cause) {
      throw new Failure("request_failed", "Token request failed", { cause });
    }
    await refuseRedirect(response, Failure);
    const text = await readLimitedText(response, this.#maxResponseBytes);
    if (new TextEncoder().encode(text).byteLength > this.#maxResponseBytes) {
      throw new Failure("response_too_large", "Token response exceeds size limit", {
        statusCode: response.status,
      });
    }
    // A 429 has `Retry-After` and no body (§5.6).
    const payload = refusedWithoutBody(response, text) ? undefined : this.#decode(response, text, Failure);
    if (response.ok) {
      try {
        return parseTokenResponse(payload);
      } catch (cause) {
        const dpop = cause instanceof ProtocolValidationError && cause.code === "unsupported_token_type";
        throw new Failure(
          dpop ? "unsupported_token_type" : "invalid_token_response",
          dpop
            ? "The company issued a DPoP-bound token, which this SDK doesn't support yet"
            : "Token response is malformed",
          { statusCode: response.status, cause },
        );
      }
    }
    const details = refusalDetails(response, payload);
    throw new Failure(refusalCode(response, payload, "http_error"), "Company refused the token request", {
      statusCode: response.status,
      ...(Object.keys(details).length > 0 ? { details } : {}),
    });
  }

  /** `client_id` and a fresh client assertion, as form fields (§4.1). */
  async clientAuthentication(options: {
    readonly clientId: string;
    readonly issuer: string;
  }): Promise<Record<string, string>> {
    const signer = firstContribution(this.#reactor, Signers, "signer");
    const clientId = httpsUrl(options.clientId, "clientId");
    const claims = buildClientAssertionClaims({
      clientId,
      issuer: httpsUrl(options.issuer, "issuer"),
      now: firstContribution(this.#reactor, Clocks, "clock").now(),
      randomBytes: (length) => this.#random().bytes(length),
    });
    const assertion = await signer.sign({ ...claims }, { purpose: "client_assertion" });
    return {
      client_id: clientId,
      client_assertion_type: JWT_CLIENT_ASSERTION,
      client_assertion: assertion.reveal(),
    };
  }

  #random() {
    return firstContribution(this.#reactor, RandomSources, "random source");
  }

  #decode(response: Response, text: string, Failure: TokenErrorClass): unknown {
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    if (contentType !== "application/json") {
      throw new Failure("invalid_content_type", "Token endpoint must return JSON", {
        statusCode: response.status,
      });
    }
    try {
      return parseJsonStrict(text);
    } catch (cause) {
      throw new Failure("invalid_json", "Token endpoint returned invalid JSON", {
        statusCode: response.status,
        cause,
      });
    }
  }
}
