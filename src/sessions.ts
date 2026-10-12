/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { ProtocolValidationError, SessionError } from "./errors.js";
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

export const JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
export const JWT_CLIENT_ASSERTION =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface SessionAssertionClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
}

export interface SessionToken {
  readonly accessToken: SecretValue;
  readonly tokenType: "DPoP" | "Bearer";
  readonly expiresIn: number;
  readonly scopes: readonly string[];
  readonly sessionId: string;
  readonly signedIn: boolean;
  readonly accountToken?: SecretValue;
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
  readonly tokenEndpoint: string;
  readonly now?: Date;
  readonly lifetimeSeconds?: number;
  readonly randomBytes?: RandomBytes;
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

export function buildSessionAssertionClaims(
  options: SessionAssertionOptions,
): SessionAssertionClaims {
  const lifetime = options.lifetimeSeconds ?? 60;
  if (!Number.isInteger(lifetime) || lifetime <= 0) {
    throw new ProtocolValidationError(
      "invalid_assertion_lifetime",
      "Assertion lifetime must be a positive integer",
    );
  }
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(options.pairwiseUserId)) {
    throw new ProtocolValidationError(
      "invalid_user_id",
      "Pairwise user ID must use the URL-safe base64 alphabet",
    );
  }
  const iat = Math.floor((options.now ?? new Date()).getTime() / 1000);
  return {
    iss: httpsUrl(options.clientId, "clientId"),
    sub: options.pairwiseUserId,
    aud: httpsUrl(options.tokenEndpoint, "tokenEndpoint"),
    iat,
    exp: iat + lifetime,
    jti: opaqueId("jti", options.randomBytes ?? defaultRandomBytes),
  };
}

export interface SessionGrantOptions {
  readonly assertion: string;
  readonly clientId: string;
  readonly clientAssertion: string;
  readonly sessionId?: string;
  /** An RFC 8707 resource indicator: an MCP server's `url`, for a Bearer token. */
  readonly resource?: string;
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

export class SessionGrant {
  readonly assertion: SecretValue;
  readonly clientId: string;
  readonly clientAssertion: SecretValue;
  readonly sessionId: string | undefined;
  readonly resource: string | undefined;

  constructor(options: SessionGrantOptions) {
    this.assertion = new SecretValue(options.assertion);
    this.clientId = httpsUrl(options.clientId, "clientId");
    this.clientAssertion = new SecretValue(options.clientAssertion);
    if (options.sessionId !== undefined && !/^[A-Za-z0-9_-]{1,256}$/.test(options.sessionId)) {
      throw new ProtocolValidationError("invalid_session_id", "Invalid PAP session ID");
    }
    this.sessionId = options.sessionId;
    this.resource = options.resource;
  }

  toForm(): URLSearchParams {
    const form = new URLSearchParams({
      grant_type: JWT_BEARER_GRANT,
      assertion: this.assertion.reveal(),
      client_id: this.clientId,
      client_assertion_type: JWT_CLIENT_ASSERTION,
      client_assertion: this.clientAssertion.reveal(),
    });
    if (this.sessionId !== undefined) {
      form.set("session_id", this.sessionId);
    }
    if (this.resource !== undefined) {
      form.set("resource", this.resource);
    }
    return form;
  }

  toJSON(): Record<string, unknown> {
    return {
      grant_type: JWT_BEARER_GRANT,
      assertion: this.assertion,
      client_id: this.clientId,
      client_assertion_type: JWT_CLIENT_ASSERTION,
      client_assertion: this.clientAssertion,
      ...(this.sessionId === undefined ? {} : { session_id: this.sessionId }),
      ...(this.resource === undefined ? {} : { resource: this.resource }),
    };
  }
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

export function parseSessionToken(value: unknown): SessionToken {
  const source = object(value, "session token response");
  const tokenType = nonEmptyString(source.token_type, "token_type");
  if (tokenType !== "DPoP" && tokenType !== "Bearer") {
    throw new ProtocolValidationError("invalid_token_type", "Unsupported token_type");
  }
  const expiresIn = source.expires_in;
  if (!Number.isInteger(expiresIn) || (expiresIn as number) <= 0) {
    throw new ProtocolValidationError("invalid_expiry", "expires_in must be positive");
  }
  const sessionId = nonEmptyString(source.session_id, "session_id");
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(sessionId)) {
    throw new ProtocolValidationError("invalid_session_id", "Invalid PAP session ID");
  }
  if (typeof source.signed_in !== "boolean") {
    throw new ProtocolValidationError("invalid_type", "signed_in must be boolean");
  }
  if (source.scope !== undefined && typeof source.scope !== "string") {
    throw new ProtocolValidationError("invalid_type", "scope must be a string");
  }
  const scope = (source.scope as string | undefined) ?? "";
  return {
    accessToken: new SecretValue(nonEmptyString(source.access_token, "access_token")),
    tokenType,
    expiresIn: expiresIn as number,
    scopes: scope.split(" ").filter(Boolean),
    sessionId,
    signedIn: source.signed_in,
    ...(source.refresh_token === undefined
      ? {}
      : {
          accountToken: new SecretValue(
            nonEmptyString(source.refresh_token, "refresh_token"),
          ),
        }),
  };
}

export interface SessionRequestOptions {
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly issuer: string;
  readonly tokenEndpoint: string;
  readonly tenantId: string;
  readonly signal?: AbortSignal;
}

export interface SessionRenewOptions extends SessionRequestOptions {
  readonly sessionId: string;
}

export interface McpBearerOptions extends SessionRenewOptions {
  /** The MCP server's `url` from poppy.json: the only place the token works. */
  readonly resource: string;
}

export interface SessionClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

/** Start and renew signed-out PAP sessions over an OAuth token endpoint. */
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

  start(options: SessionRequestOptions): Promise<SessionToken> {
    return traced(
      this.#reactor,
      "pap.session.start",
      byIssuer(options.issuer),
      () => this.#start(options),
      sessionResult,
    );
  }

  #start(options: SessionRequestOptions): Promise<SessionToken> {
    return this.#request(options);
  }

  renew(options: SessionRenewOptions): Promise<SessionToken> {
    return traced(
      this.#reactor,
      "pap.session.renew",
      byIssuer(options.issuer),
      () => this.#renew(options),
      sessionResult,
    );
  }

  #renew(options: SessionRenewOptions): Promise<SessionToken> {
    return this.#request(options, options.sessionId);
  }

  /**
   * A signed-out Bearer Session Token for one MCP server (§4.3).
   *
   * The renewal request of the Session, without a DPoP proof, with `resource` set to
   * the MCP server's `url` from poppy.json. The token works only there: hand it to
   * `McpClient` (or `McpBearerAuth`), never to an API.
   */
  async bearerForMcp(options: McpBearerOptions): Promise<SessionToken> {
    return this.#request(options, options.sessionId, mcpResource(options.resource));
  }

  async #request(
    options: SessionRequestOptions,
    sessionId?: string,
    bearerResource?: string,
  ): Promise<SessionToken> {
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
      const now = clock.now();
      const sessionClaims = buildSessionAssertionClaims({
        clientId: options.clientId,
        pairwiseUserId: options.pairwiseUserId,
        tokenEndpoint: options.tokenEndpoint,
        now,
        randomBytes: (length) => random.bytes(length),
      });
      const iat = Math.floor(now.getTime() / 1000);
      const clientId = httpsUrl(options.clientId, "clientId");
      const tokenEndpoint = httpsUrl(options.tokenEndpoint, "tokenEndpoint");
      const issuer = httpsUrl(options.issuer, "issuer");
      const clientClaims = {
        iss: clientId,
        sub: clientId,
        aud: tokenEndpoint,
        iat,
        exp: iat + 60,
        jti: opaqueId("jti", (length) => random.bytes(length)),
      };
      const assertion = await signer.sign({ ...sessionClaims }, {
        purpose: "session_assertion",
      });
      const clientAssertion = await signer.sign(clientClaims, {
        purpose: "client_assertion",
      });
      const headers: Record<string, string> = { Accept: "application/json" };
      if (bearerResource === undefined) {
        const proof = await dpop.create({
          method: "POST",
          url: tokenEndpoint,
          tenantId: options.tenantId,
          subject: options.pairwiseUserId,
          issuer,
          ...(nonce === undefined ? {} : { nonce }),
        });
        headers.DPoP = proof.reveal();
      }
      const grant = new SessionGrant({
        assertion: assertion.reveal(),
        clientId,
        clientAssertion: clientAssertion.reveal(),
        ...(sessionId === undefined ? {} : { sessionId }),
        ...(bearerResource === undefined ? {} : { resource: bearerResource }),
      });

      let response: Response;
      try {
        response = await this.#fetch(tokenEndpoint, {
          method: "POST",
          headers,
          body: grant.toForm(),
          credentials: "omit",
          redirect: "error",
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (cause) {
        throw new SessionError("request_failed", "Session token request failed", { cause });
      }

      const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
      if (contentType !== "application/json") {
        throw new SessionError(
          "invalid_content_type",
          "Session token endpoint must return JSON",
          { statusCode: response.status },
        );
      }
      const body = await readLimitedText(response, this.#maxResponseBytes);
      if (new TextEncoder().encode(body).byteLength > this.#maxResponseBytes) {
        throw new SessionError(
          "response_too_large",
          "Session token response exceeds size limit",
          { statusCode: response.status },
        );
      }
      let payload: unknown;
      try {
        payload = parseJsonStrict(body);
      } catch (cause) {
        throw new SessionError("invalid_json", "Session token endpoint returned invalid JSON", {
          statusCode: response.status,
          cause,
        });
      }

      if (response.ok) {
        let token: SessionToken;
        try {
          token = parseSessionToken(payload);
        } catch (cause) {
          throw new SessionError(
            "invalid_token_response",
            "Session token response is malformed",
            { statusCode: response.status, cause },
          );
        }
        const expected = bearerResource === undefined ? "DPoP" : "Bearer";
        if (
          token.tokenType !== expected ||
          (bearerResource !== undefined && token.sessionId !== sessionId)
        ) {
          throw new SessionError(
            "unexpected_token_type",
            `The Session request must return a ${expected} token for this Session`,
            { statusCode: response.status },
          );
        }
        return token;
      }

      const source = typeof payload === "object" && payload !== null ? payload : {};
      const remoteCode = "error" in source ? (source as { error?: unknown }).error : undefined;
      const code = typeof remoteCode === "string" ? remoteCode : "http_error";
      if (code === "use_dpop_nonce" && attempt === 0) {
        nonce = response.headers.get("dpop-nonce") ?? undefined;
        if (!nonce) {
          throw new SessionError(
            "missing_dpop_nonce",
            "Company requested a DPoP nonce but did not send one",
            { statusCode: response.status },
          );
        }
        continue;
      }
      const retryAfter = response.headers.get("retry-after");
      throw new SessionError(code, "Company refused the session token request", {
        statusCode: response.status,
        ...(retryAfter === null ? {} : { details: { retry_after: retryAfter } }),
      });
    }
    throw new SessionError("use_dpop_nonce", "Company rejected the refreshed DPoP proof");
  }
}
