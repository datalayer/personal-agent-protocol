/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { PersonalAgentProtocolError, ProtocolValidationError, SessionError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { SecretValue } from "./secret.js";
import {
  Clocks,
  DpopProofProviders,
  PairwiseUserIdStores,
  RandomSources,
  Signers,
  firstContribution,
  type PairwiseUserIdStore,
} from "./reactor.js";
import { byIssuer, sessionResult, traced } from "./telemetry.js";
import { readLimitedText } from "./limits.js";
import { refusalDetails, refuseRedirect } from "./refusals.js";

export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const JWT_CLIENT_ASSERTION =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/** A client or Session assertion's `exp` is at most this long after its `iat` (§4.1, §4.2). */
export const ASSERTION_MAX_LIFETIME_SECONDS = 300;

export const TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
export const ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
/** A Session Key's name: its RFC 7638 SHA-256 JWK thumbprint (§4.3). */
export const SESSION_KEY = /^[A-Za-z0-9_-]{43}$/;

export interface SessionAssertionClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
  /** Which of the User's agents the Session is for (§4.2): User-ID rules, kept for life. */
  readonly agent_id?: string;
}

/** A token endpoint's answer, as on the wire (§4.2, §4.4): no Session named in it. */
export interface TokenResponse {
  readonly accessToken: SecretValue;
  readonly tokenType: "DPoP" | "Bearer";
  readonly expiresIn: number;
  readonly scope?: string;
  readonly refreshToken?: SecretValue;
  readonly refreshTokenExpiresIn?: number;
  readonly issuedTokenType?: string;
}

/**
 * A Session Token, with what the SDK knows of it beside the wire response.
 *
 * `sessionKey` is the Session Key's thumbprint, which names the Session (§4.3).
 * `signedIn` comes from the grant, never from the response (§4.2): the JWT bearer grant
 * always answers signed out, a sign-in or an Account Token signed in. `scopes` is what was
 * granted: a signed-in response that leaves `scope` out granted exactly the scopes
 * requested (RFC 6749 §5.1), a signed-out one has none.
 */
export interface SessionToken {
  readonly accessToken: SecretValue;
  readonly tokenType: "DPoP" | "Bearer";
  readonly expiresIn: number;
  readonly scopes: readonly string[];
  readonly sessionKey: string;
  readonly signedIn: boolean;
  readonly accountToken?: SecretValue;
  readonly accountTokenExpiresIn?: number;
}

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

function opaqueId(prefix: string, randomBytes: RandomBytes): string {
  const bytes = randomBytes(16);
  if (bytes.byteLength < 16) {
    throw new Error("Opaque PAP identifiers require at least 128 random bits");
  }
  return `${prefix}_${base64Url(bytes)}`;
}

export function generatePairwiseUserId(
  randomBytes: RandomBytes = defaultRandomBytes,
): string {
  return opaqueId("usr", randomBytes);
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

export interface SessionAssertionOptions {
  readonly clientId: string;
  readonly pairwiseUserId: string;
  /** The company's `auth.issuer`: the assertion's `aud`, one string, never an endpoint (§4.2). */
  readonly issuer: string;
  readonly now?: Date;
  readonly lifetimeSeconds?: number;
  readonly randomBytes?: RandomBytes;
  /** When the User has several agents, which one; left out otherwise (§4.2). */
  readonly agentId?: string;
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
  /** The company's `auth.issuer`, whichever endpoint the assertion goes to (§4.1, §9.4). */
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
 * Build unsigned PAP §4.2 claims; a key-custody provider signs them.
 *
 * `aud` is the company's `auth.issuer`, one string, never an endpoint (§4.2, §9.4); the
 * assertion lives at most five minutes.
 */
export function buildSessionAssertionClaims(
  options: SessionAssertionOptions,
): SessionAssertionClaims {
  const lifetime = options.lifetimeSeconds ?? 60;
  const iat = issuedAt(options.now, lifetime);
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(options.pairwiseUserId)) {
    throw new ProtocolValidationError(
      "invalid_user_id",
      "Pairwise user ID must use the URL-safe base64 alphabet",
    );
  }
  if (options.agentId !== undefined && !/^[A-Za-z0-9_-]{1,256}$/.test(options.agentId)) {
    throw new ProtocolValidationError(
      "invalid_agent_id",
      "Agent ID must use the URL-safe base64 alphabet",
    );
  }
  return {
    iss: httpsUrl(options.clientId, "clientId"),
    sub: options.pairwiseUserId,
    aud: httpsUrl(options.issuer, "issuer"),
    iat,
    exp: iat + lifetime,
    jti: opaqueId("jti", options.randomBytes ?? defaultRandomBytes),
    ...(options.agentId === undefined ? {} : { agent_id: options.agentId }),
  };
}

/**
 * Build unsigned `private_key_jwt` claims for any request to the company's OAuth server.
 *
 * `aud` is the company's `auth.issuer`, one string, whichever endpoint the assertion goes
 * to: token, revocation, or device authorization (§4.1, §9.4).
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
    jti: opaqueId("jti", options.randomBytes ?? defaultRandomBytes),
  };
}

/** An MCP server's `url` as a `resource` indicator: HTTPS, no fragment (RFC 8707). */
export function mcpResource(value: string): string {
  let parsed: URL | undefined;
  try {
    parsed = new URL(value);
  } catch {
    parsed = undefined;
  }
  if (
    parsed === undefined ||
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    parsed.hash ||
    value.includes("#")
  ) {
    throw new ProtocolValidationError(
      "invalid_url",
      "an MCP resource must be an HTTPS URL without a fragment",
    );
  }
  return value;
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

/** A token endpoint's JSON answer (§4.2): no Session named in it. */
export function parseTokenResponse(value: unknown): TokenResponse {
  const source = object(value, "token response");
  const tokenType = nonEmptyString(source.token_type, "token_type");
  if (tokenType !== "DPoP" && tokenType !== "Bearer") {
    throw new ProtocolValidationError("invalid_token_type", "Unsupported token_type");
  }
  const expiresIn = source.expires_in;
  if (!Number.isInteger(expiresIn) || (expiresIn as number) <= 0) {
    throw new ProtocolValidationError("invalid_expiry", "expires_in must be positive");
  }
  const optionalString = (name: string): string | undefined => {
    const item = source[name];
    if (item === undefined || item === null) return undefined;
    if (typeof item !== "string") {
      throw new ProtocolValidationError("invalid_type", `${name} must be a string`);
    }
    return item;
  };
  const scope = optionalString("scope");
  const refresh = source.refresh_token;
  const refreshExpiresIn = source.refresh_token_expires_in;
  if (
    refreshExpiresIn !== undefined &&
    refreshExpiresIn !== null &&
    (!Number.isInteger(refreshExpiresIn) || (refreshExpiresIn as number) <= 0)
  ) {
    throw new ProtocolValidationError("invalid_expiry", "refresh_token_expires_in must be positive");
  }
  const issuedTokenType = optionalString("issued_token_type");
  return {
    accessToken: new SecretValue(nonEmptyString(source.access_token, "access_token")),
    tokenType,
    expiresIn: expiresIn as number,
    ...(scope === undefined ? {} : { scope }),
    ...(refresh === undefined || refresh === null
      ? {}
      : { refreshToken: new SecretValue(nonEmptyString(refresh, "refresh_token")) }),
    ...(refreshExpiresIn === undefined || refreshExpiresIn === null
      ? {}
      : { refreshTokenExpiresIn: refreshExpiresIn as number }),
    ...(issuedTokenType === undefined ? {} : { issuedTokenType }),
  };
}

/**
 * A Session Token from a token response and what the grant says of it (§4.2).
 *
 * Signed in, a response without `scope` granted exactly `requestedScopes`, and one that
 * grants none is refused: approving none is a decline (§4.4). Signed out, no `scope`
 * means none.
 */
export function sessionTokenFromResponse(
  response: TokenResponse,
  options: {
    readonly sessionKey: string;
    readonly signedIn: boolean;
    readonly requestedScopes?: readonly string[];
  },
): SessionToken {
  if (!SESSION_KEY.test(options.sessionKey)) {
    throw new ProtocolValidationError("invalid_session_key", "A Session Key is a JWK thumbprint");
  }
  let scope: string;
  if (options.signedIn) {
    scope = response.scope ?? (options.requestedScopes ?? []).join(" ");
    if (!scope.trim()) {
      throw new ProtocolValidationError(
        "invalid_token_response",
        "A signed-in token response grants no scope",
      );
    }
  } else {
    scope = response.scope ?? "";
  }
  return {
    accessToken: response.accessToken,
    tokenType: response.tokenType,
    expiresIn: response.expiresIn,
    scopes: scope.split(" ").filter(Boolean),
    sessionKey: options.sessionKey,
    signedIn: options.signedIn,
    ...(response.refreshToken === undefined ? {} : { accountToken: response.refreshToken }),
    ...(response.refreshTokenExpiresIn === undefined
      ? {}
      : { accountTokenExpiresIn: response.refreshTokenExpiresIn }),
  };
}

export interface SessionRequestOptions {
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly issuer: string;
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  /** Which of the User's agents the Session is for, kept for the Session's life (§4.2). */
  readonly agentId?: string;
  /** A token for one service, such as an MCP server that supports DPoP (§4.3). */
  readonly resource?: string;
  readonly signal?: AbortSignal;
}

export interface SessionRenewOptions extends SessionRequestOptions {
  /** The Session Key's thumbprint, which names the Session (§4.3). */
  readonly sessionKey: string;
}

export interface McpTokenOptions {
  readonly clientId: string;
  readonly issuer: string;
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  readonly sessionKey: string;
  /** A current DPoP Session Token of the Session `sessionKey` names. */
  readonly subjectToken: SecretValue;
  /** The MCP server's `url` from poppy.json: the only place the token works. */
  readonly resource: string;
  /** Fewer scopes than the subject token has; left out, the same ones. */
  readonly scope?: string;
  readonly signal?: AbortSignal;
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

export interface TokenRequestOptions {
  readonly clientId: string;
  readonly issuer: string;
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  readonly sessionKey: string;
  /** The grant's own fields, made again for a `use_dpop_nonce` retry. */
  readonly form: () => Record<string, string> | Promise<Record<string, string>>;
  readonly error: TokenErrorClass;
  readonly signal?: AbortSignal;
}

export interface SessionClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

/** Start and renew signed-out PAP Sessions, each named by its own key (§4.2, §4.3). */
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
   * Start a new signed-out Session with a new Session Key (§4.2).
   *
   * `resource` asks for a token for one service, such as an MCP server that supports
   * DPoP (§4.3).
   */
  start(options: SessionRequestOptions): Promise<SessionToken> {
    return traced(
      this.#reactor,
      "pap.session.start",
      byIssuer(options.issuer),
      async () => {
        const sessionKey = await this.#prover().newSessionKey({
          tenantId: options.tenantId,
          issuer: options.issuer,
        });
        return this.#assert({ ...options, sessionKey });
      },
      sessionResult,
    );
  }

  /**
   * Renew a signed-out Session: fresh assertions, a proof from its own key (§4.2).
   *
   * `agentId` is the one the Session started with, or none. `invalid_grant` means the
   * Session has ended: its key is discarded, never used again, and the caller starts a
   * new Session.
   */
  renew(options: SessionRenewOptions): Promise<SessionToken> {
    return traced(
      this.#reactor,
      "pap.session.renew",
      byIssuer(options.issuer),
      () => this.#assert(options),
      sessionResult,
    );
  }

  /**
   * A Bearer Session Token for one MCP server without DPoP, by Token Exchange (§4.3).
   *
   * `subjectToken` is a current DPoP Session Token of the Session `sessionKey` names; the
   * answer is a Bearer token for the same Session, working only at the MCP server whose
   * `url` is `resource`, with the subject token's scopes or the fewer `scope` asks for.
   * For a server that supports DPoP, start or renew with `resource` instead: a DPoP
   * token, used with proofs.
   */
  async tokenForMcp(options: McpTokenOptions): Promise<SessionToken> {
    const form: Record<string, string> = {
      grant_type: TOKEN_EXCHANGE_GRANT,
      subject_token: options.subjectToken.reveal(),
      subject_token_type: ACCESS_TOKEN_TYPE,
      resource: mcpResource(options.resource),
      ...(options.scope === undefined ? {} : { scope: options.scope }),
    };
    const response = await this.tokenRequest({
      clientId: options.clientId,
      issuer: options.issuer,
      tokenEndpoint: options.tokenEndpoint,
      tenantId: options.tenantId,
      sessionKey: options.sessionKey,
      form: () => form,
      error: SessionError,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (response.tokenType !== "Bearer" || response.issuedTokenType !== ACCESS_TOKEN_TYPE) {
      throw new SessionError(
        "unexpected_token_type",
        "Token Exchange answered with another token type",
      );
    }
    return sessionTokenFromResponse(response, {
      sessionKey: options.sessionKey,
      signedIn: response.scope !== undefined,
    });
  }

  async #assert(options: SessionRenewOptions): Promise<SessionToken> {
    const signer = firstContribution(this.#reactor, Signers, "signer");
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const clientId = httpsUrl(options.clientId, "clientId");
    const issuer = httpsUrl(options.issuer, "issuer");
    const resource = options.resource === undefined ? undefined : mcpResource(options.resource);
    const form = async (): Promise<Record<string, string>> => {
      const claims = buildSessionAssertionClaims({
        clientId,
        pairwiseUserId: options.pairwiseUserId,
        issuer,
        now: firstContribution(this.#reactor, Clocks, "clock").now(),
        randomBytes: (length) => random.bytes(length),
        ...(options.agentId === undefined ? {} : { agentId: options.agentId }),
      });
      const assertion = await signer.sign({ ...claims }, { purpose: "session_assertion" });
      return {
        grant_type: JWT_BEARER_GRANT,
        assertion: assertion.reveal(),
        ...(resource === undefined ? {} : { resource }),
      };
    };
    let response: TokenResponse;
    try {
      response = await this.tokenRequest({
        clientId,
        issuer,
        tokenEndpoint: options.tokenEndpoint,
        tenantId: options.tenantId,
        sessionKey: options.sessionKey,
        form,
        error: SessionError,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (error) {
      if (error instanceof SessionError && error.code === "invalid_grant") {
        // The Session has ended or isn't this User's: never this key again (§4.2).
        await this.#prover().discardSessionKey({
          tenantId: options.tenantId,
          issuer,
          sessionKey: options.sessionKey,
        });
      }
      throw error;
    }
    if (response.tokenType !== "DPoP") {
      // Bearer Session Tokens come from Token Exchange alone (§4.3).
      throw new SessionError(
        "unexpected_token_type",
        "The Session request returned another token type",
      );
    }
    // The JWT bearer grant always answers signed out (§4.2).
    return sessionTokenFromResponse(response, { sessionKey: options.sessionKey, signedIn: false });
  }

  /**
   * POST one grant to the token endpoint with the Session Key's proof (§4.2–§4.8).
   *
   * `form` gives the grant's own fields, made again for a `use_dpop_nonce` retry so no
   * assertion is sent twice; the client assertion and a fresh proof signed with
   * `sessionKey`, the Session's name, go with every attempt. Throws `error` with the
   * company's OAuth error code.
   */
  async tokenRequest(options: TokenRequestOptions): Promise<TokenResponse> {
    const Failure = options.error;
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const signer = firstContribution(this.#reactor, Signers, "signer");
    const prover = this.#prover();
    const clientId = httpsUrl(options.clientId, "clientId");
    const tokenEndpoint = httpsUrl(options.tokenEndpoint, "tokenEndpoint");
    const issuer = httpsUrl(options.issuer, "issuer");
    let nonce: string | undefined;

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const fields = await options.form();
      const clientClaims = buildClientAssertionClaims({
        clientId,
        issuer,
        now: firstContribution(this.#reactor, Clocks, "clock").now(),
        randomBytes: (length) => random.bytes(length),
      });
      const clientAssertion = await signer.sign({ ...clientClaims }, {
        purpose: "client_assertion",
      });
      const proof = await prover.create({
        method: "POST",
        url: tokenEndpoint,
        tenantId: options.tenantId,
        issuer,
        sessionKey: options.sessionKey,
        ...(nonce === undefined ? {} : { nonce }),
      });
      const body = new URLSearchParams({
        ...fields,
        client_id: clientId,
        client_assertion_type: JWT_CLIENT_ASSERTION,
        client_assertion: clientAssertion.reveal(),
      });

      let response: Response;
      try {
        response = await this.#fetch(tokenEndpoint, {
          method: "POST",
          headers: { Accept: "application/json", DPoP: proof.reveal() },
          body,
          credentials: "omit",
          redirect: "manual",
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (cause) {
        throw new Failure("request_failed", "Token request failed", { cause });
      }
      await refuseRedirect(response, Failure);

      const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
      if (contentType !== "application/json") {
        throw new Failure("invalid_content_type", "Token endpoint must return JSON", {
          statusCode: response.status,
        });
      }
      const text = await readLimitedText(response, this.#maxResponseBytes);
      if (new TextEncoder().encode(text).byteLength > this.#maxResponseBytes) {
        throw new Failure("response_too_large", "Token response exceeds size limit", {
          statusCode: response.status,
        });
      }
      let payload: unknown;
      try {
        payload = parseJsonStrict(text);
      } catch (cause) {
        throw new Failure("invalid_json", "Token endpoint returned invalid JSON", {
          statusCode: response.status,
          cause,
        });
      }

      if (response.ok) {
        try {
          return parseTokenResponse(payload);
        } catch (cause) {
          throw new Failure("invalid_token_response", "Token response is malformed", {
            statusCode: response.status,
            cause,
          });
        }
      }

      const source = typeof payload === "object" && payload !== null ? payload : {};
      const remoteCode = "error" in source ? (source as { error?: unknown }).error : undefined;
      const code = typeof remoteCode === "string" ? remoteCode : "http_error";
      if (code === "use_dpop_nonce" && attempt === 0) {
        nonce = response.headers.get("dpop-nonce") ?? undefined;
        if (!nonce) {
          throw new Failure(
            "missing_dpop_nonce",
            "Company requested a DPoP nonce but did not send one",
            { statusCode: response.status },
          );
        }
        continue;
      }
      const details = refusalDetails(response, payload);
      throw new Failure(code, "Company refused the token request", {
        statusCode: response.status,
        ...(Object.keys(details).length > 0 ? { details } : {}),
      });
    }
    throw new Failure("use_dpop_nonce", "Company rejected the refreshed DPoP proof");
  }

  #prover() {
    return firstContribution(this.#reactor, DpopProofProviders, "DPoP proof provider");
  }
}
