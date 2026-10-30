/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Refresh tokens: access tokens, rotation, narrowing, tokens for one service, sign-out.
 *
 * A refresh token is what a sign-in returns (§4.4). It is used only at the company's
 * `token_endpoint` and `revocation_endpoint`, always behind an opaque reference in a Reactor
 * `TokenStore`, and never reaches a model, a conversation, a log, or a URL.
 *
 * - **Refresh** gets an access token: `grant_type=refresh_token` and a fresh client assertion.
 *   No Session is named: any of the User's Sessions uses the access token with its Session
 *   header (§4.4, §5.4).
 * - **Rotation** is serialized per reference through `pap.refreshTokenLock`: when the company
 *   returns a new `refresh_token`, it replaces the old one before the call returns.
 * - **Narrowing** asks for fewer scopes; a wider request is the company's `invalid_scope`,
 *   reported as `re_consent_required` so the host signs the user in again rather than retrying.
 * - **Tokens for one service** ask with `resource` (RFC 8707) for a service whose protected
 *   resource metadata names a resource other than the Company's domain, such as an MCP server
 *   (§4.5, §7). `ServiceTokens` reads that metadata before the first signed-in call to a
 *   service, and again when a service says it is stale.
 * - **`invalid_grant`** means the refresh token is no longer valid: the stored copy is deleted
 *   and the Sessions continue signed out (§5.5).
 * - **Sign-out** revokes every refresh token held for the account (RFC 7009, §4.6, §5.5); each
 *   local copy is deleted once the company has answered.
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError, ProtocolValidationError, type PersonalAgentProtocolError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { serviceResource, type DiscoveryOptions } from "./discovery.js";
import { readLimitedText } from "./limits.js";
import type { DiscoveredCompany } from "./models.js";
import { RefreshTokenLocks, TokenStores, firstContribution, type TokenStore } from "./reactor.js";
import { refusalCode, refusalDetails, refuseRedirect, refusedWithoutBody } from "./refusals.js";
import {
  SessionClient,
  accessTokenFromResponse,
  type AccessToken,
  type TokenResponse,
} from "./sessions.js";
import { byIssuer, signInResult, traced } from "./telemetry.js";

export const REFRESH_TOKEN_GRANT = "refresh_token";

const scopeToken = /^[\x21\x23-\x5b\x5d-\x7e]+$/;

function httpsUrl(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`, { cause });
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return value;
}

/** Where a refresh token is used, and for whom (all non-secret). */
export interface RefreshTokenContext {
  readonly tokenEndpoint: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly tenantId: string;
  readonly revocationEndpoint?: string;
}

export interface RefreshOptions {
  readonly context: RefreshTokenContext;
  /** Narrower scopes; omitted, the company grants what the token holds. */
  readonly scopes?: readonly string[];
  /** A token for one service (RFC 8707, §4.5), used only there. */
  readonly resource?: string | undefined;
  readonly signal?: AbortSignal;
}

/**
 * What a refresh did, without the refresh token itself.
 *
 * `token` is the access token on `signed_in`; `rotated` says the stored refresh token was
 * replaced; `missingScopes` are requested scopes the company left out. `signed_out`: no valid
 * refresh token is held any more (§5.5).
 */
export interface RefreshResult {
  readonly status: "signed_in" | "signed_out" | "re_consent_required";
  readonly token?: AccessToken;
  readonly rotated: boolean;
  readonly grantedScopes: readonly string[];
  readonly missingScopes: readonly string[];
}

/** A revocation the company acknowledged; the local copy is gone. */
export interface RevocationResult {
  readonly revoked: boolean;
  readonly deletedLocally: boolean;
}

/** Sign-out (§5.5): how many refresh tokens were revoked, and whether all were. */
export interface SignOutResult {
  readonly revoked: number;
  readonly signedOut: boolean;
}

export interface RefreshTokenClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

function outcome(status: RefreshResult["status"]): RefreshResult {
  return { status, rotated: false, grantedScopes: [], missingScopes: [] };
}

/** Use a stored refresh token without ever handing it to a caller. */
export class RefreshTokenClient {
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxResponseBytes: number;
  readonly #sessions: SessionClient;

  constructor(options: RefreshTokenClientOptions) {
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) throw new AuthorizationError("fetch_unavailable", "A fetch implementation is required");
    const limit = options.maxResponseBytes ?? 100 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#reactor = options.reactor;
    this.#fetch = fetcher;
    this.#maxResponseBytes = limit;
    this.#sessions = new SessionClient({
      reactor: options.reactor,
      fetch: fetcher,
      maxResponseBytes: limit,
    });
  }

  /**
   * An access token from the refresh token behind `reference` (§4.4).
   *
   * `scopes` narrows the request; omitted, the company grants what the token holds. `resource`
   * asks for a token for one service (RFC 8707, §4.5), used only there.
   */
  refresh(reference: string, options: RefreshOptions): Promise<RefreshResult> {
    return traced(
      this.#reactor,
      "pap.sign_in.refresh_token.refresh",
      byIssuer(options.context.issuer, "refresh_token"),
      () => this.#refresh(reference, options),
      signInResult,
    );
  }

  async #refresh(reference: string, options: RefreshOptions): Promise<RefreshResult> {
    const requested = options.scopes === undefined ? undefined : [...new Set(options.scopes)];
    if (requested && (requested.length === 0 || requested.some((scope) => !scopeToken.test(scope)))) {
      throw new AuthorizationError("invalid_scope", "At least one valid OAuth scope is required");
    }
    const resource = options.resource === undefined ? undefined : httpsUrl(options.resource, "resource");
    const context = options.context;
    const tokenEndpoint = httpsUrl(context.tokenEndpoint, "tokenEndpoint");
    const lock = firstContribution(this.#reactor, RefreshTokenLocks, "refresh token lock");
    const store = this.#store();
    return lock.hold(reference, async () => {
      const refreshToken = await store.get(reference);
      if (refreshToken === undefined) return outcome("signed_out");
      const form: Record<string, string> = {
        grant_type: REFRESH_TOKEN_GRANT,
        refresh_token: refreshToken.reveal(),
        ...(requested ? { scope: requested.join(" ") } : {}),
        ...(resource === undefined ? {} : { resource }),
      };
      let response: TokenResponse;
      try {
        response = await this.#sessions.tokenRequest({
          clientId: context.clientId,
          issuer: context.issuer,
          tokenEndpoint,
          form: () => form,
          error: AuthorizationError,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (error) {
        if (!(error instanceof AuthorizationError)) throw error;
        if (error.code === "invalid_scope") return outcome("re_consent_required");
        if (error.code !== "invalid_grant") throw error;
        // Expired, revoked, or the User disconnected the agent: the stored copy is useless
        // and must go; the Sessions continue signed out (§5.5).
        await store.delete(reference);
        return outcome("signed_out");
      }
      let token: AccessToken;
      try {
        token = accessTokenFromResponse(response, {
          requestedScopes: requested ?? [],
          ...(resource === undefined ? {} : { resource }),
        });
      } catch (cause) {
        if (!(cause instanceof ProtocolValidationError)) throw cause;
        throw new AuthorizationError("invalid_token_response", cause.message, { cause });
      }
      if (requested && token.scopes.some((scope) => !requested.includes(scope))) {
        throw new AuthorizationError(
          "scope_escalation",
          "Company returned a scope that was not requested",
        );
      }
      const rotated = response.refreshToken !== undefined;
      // The new token replaces the old before anyone can use either again (§4.4).
      if (response.refreshToken !== undefined) await store.put(reference, response.refreshToken);
      return {
        status: "signed_in",
        token,
        rotated,
        grantedScopes: token.scopes,
        missingScopes: (requested ?? []).filter((scope) => !token.scopes.includes(scope)),
      };
    });
  }

  /** An access token for one MCP server: `resource` is its `url` from poppy.json (§7). */
  tokenForMcp(
    reference: string,
    options: Omit<RefreshOptions, "resource"> & { readonly url: string },
  ): Promise<RefreshResult> {
    const { url, ...rest } = options;
    return this.refresh(reference, { ...rest, resource: url });
  }

  revoke(
    reference: string,
    options: { readonly context: RefreshTokenContext; readonly signal?: AbortSignal },
  ): Promise<RevocationResult> {
    return traced(
      this.#reactor,
      "pap.sign_in.refresh_token.revoke",
      byIssuer(options.context.issuer, "refresh_token"),
      () => this.#revoke(reference, options),
      signInResult,
    );
  }

  /** Revoke the refresh token at the company (RFC 7009, §4.6), then forget it. */
  async #revoke(
    reference: string,
    options: { readonly context: RefreshTokenContext; readonly signal?: AbortSignal },
  ): Promise<RevocationResult> {
    const context = options.context;
    if (context.revocationEndpoint === undefined) {
      throw new RangeError("Revocation needs the company's revocationEndpoint");
    }
    const endpoint = httpsUrl(context.revocationEndpoint, "revocationEndpoint");
    const lock = firstContribution(this.#reactor, RefreshTokenLocks, "refresh token lock");
    const store = this.#store();
    return lock.hold(reference, async () => {
      const refreshToken = await store.get(reference);
      if (refreshToken === undefined) return { revoked: false, deletedLocally: false };
      const client = await this.#sessions.clientAuthentication({
        clientId: context.clientId,
        issuer: context.issuer,
      });
      let response: Response;
      try {
        response = await this.#fetch(endpoint, {
          method: "POST",
          headers: { Accept: "application/json" },
          body: new URLSearchParams({
            token: refreshToken.reveal(),
            token_type_hint: REFRESH_TOKEN_GRANT,
            ...client,
          }),
          credentials: "omit",
          redirect: "manual",
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (cause) {
        throw new AuthorizationError("request_failed", "Revocation request failed", { cause });
      }
      await refuseRedirect(response, AuthorizationError);
      const payload = await this.#decode(response);
      if (!response.ok) {
        // Kept so the host can retry: a token it believes revoked must be.
        const details = refusalDetails(response, payload);
        throw new AuthorizationError(
          refusalCode(response, payload, "http_error"),
          "Company refused the revocation",
          {
            statusCode: response.status,
            ...(Object.keys(details).length > 0 ? { details } : {}),
          },
        );
      }
      await store.delete(reference);
      return { revoked: true, deletedLocally: true };
    });
  }

  /**
   * Sign out of an account: revoke every refresh token held for it (§4.6, §5.5).
   *
   * `references` are all the refresh tokens the agent holds for the account, from every
   * sign-in. The account is signed out once none is valid; the Sessions continue signed out,
   * sending the Session header alone.
   */
  async signOut(
    references: Iterable<string>,
    options: { readonly context: RefreshTokenContext; readonly signal?: AbortSignal },
  ): Promise<SignOutResult> {
    const unique = [...new Set(references)];
    let revoked = 0;
    for (const reference of unique) {
      if ((await this.revoke(reference, options)).revoked) revoked += 1;
    }
    const store = this.#store();
    const remaining = await Promise.all(unique.map((reference) => store.get(reference)));
    return { revoked, signedOut: remaining.every((token) => token === undefined) };
  }

  #store(): TokenStore {
    return firstContribution(this.#reactor, TokenStores, "token store");
  }

  async #decode(response: Response): Promise<unknown> {
    const body = await readLimitedText(response, this.#maxResponseBytes);
    if (new TextEncoder().encode(body).byteLength > this.#maxResponseBytes) {
      throw new AuthorizationError("response_too_large", "Revocation response exceeds size limit", {
        statusCode: response.status,
      });
    }
    if (!body || refusedWithoutBody(response, body)) return {};
    if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json") {
      if (response.ok) return {};
      throw new AuthorizationError("invalid_content_type", "Revocation endpoint must return JSON", {
        statusCode: response.status,
      });
    }
    try {
      return parseJsonStrict(body);
    } catch (cause) {
      throw new AuthorizationError("invalid_json", "Revocation endpoint returned invalid JSON", {
        statusCode: response.status,
        cause,
      });
    }
  }
}

/**
 * Whether a service refused a token not issued for it (§4.5).
 *
 * `invalid_token` with `resource_metadata` in its challenge: the agent's view of which
 * resource the service asks tokens for is stale; read it again.
 */
export function staleResourceMetadata(error: PersonalAgentProtocolError): boolean {
  return error.code === "invalid_token" && Boolean(error.details?.resource_metadata);
}

export interface ServiceTokensOptions {
  readonly refresh: RefreshTokenClient;
  readonly company: DiscoveredCompany;
  readonly reference: string;
  readonly context: RefreshTokenContext;
  readonly scopes?: readonly string[];
  /** How the service's protected resource metadata is read. */
  readonly discovery?: DiscoveryOptions;
}

/**
 * The access tokens of one account, one per service that asks for its own (§4.5).
 *
 * Before the first signed-in call to a service (an MCP server's `url`, the URL in an OpenAPI
 * description's `servers`, a conversation `endpoint`), `tokenFor` reads the service's protected
 * resource metadata: a `resource` other than `https://{organization.domain}` gets a token
 * requested for it, used only there; otherwise the default token serves. After a service
 * answers `invalid_token` with `resource_metadata`, `tokenFor(url, { fresh: true })` reads it
 * again.
 */
export class ServiceTokens {
  readonly #options: ServiceTokensOptions;
  readonly #tokens = new Map<string | undefined, AccessToken>();

  constructor(options: ServiceTokensOptions) {
    this.#options = options;
  }

  /** The `resource` to request for `serviceUrl`, or `undefined` for the default token. */
  resourceFor(serviceUrl: string, options: { readonly fresh?: boolean } = {}): Promise<string | undefined> {
    return serviceResource(this.#options.company, serviceUrl, {
      ...this.#options.discovery,
      ...options,
    });
  }

  /** The access token to call `serviceUrl` with, or `undefined` once signed out. */
  async tokenFor(
    serviceUrl: string,
    options: { readonly fresh?: boolean } = {},
  ): Promise<AccessToken | undefined> {
    const resource = await this.resourceFor(serviceUrl, options);
    if (options.fresh === true) this.#tokens.delete(resource);
    const known = this.#tokens.get(resource);
    if (known !== undefined) return known;
    const { refresh, reference, context, scopes } = this.#options;
    const result = await refresh.refresh(reference, {
      context,
      ...(scopes === undefined ? {} : { scopes }),
      resource,
    });
    if (result.status !== "signed_in" || result.token === undefined) {
      this.#tokens.clear();
      return undefined;
    }
    this.#tokens.set(resource, result.token);
    return result.token;
  }

  /** Drop every access token held: signed out, or a new sign-in replaces them. */
  forget(): void {
    this.#tokens.clear();
  }
}
