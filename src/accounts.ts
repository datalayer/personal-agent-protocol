/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError, ProtocolValidationError, SessionError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  AccountTokenLocks,
  Clocks,
  DpopProofProviders,
  RandomSources,
  Signers,
  TokenStores,
  firstContribution,
  type TokenStore,
} from "./reactor.js";
import { refusalDetails, refuseRedirect } from "./refusals.js";
import {
  JWT_CLIENT_ASSERTION,
  SessionClient,
  buildClientAssertionClaims,
  sessionTokenFromResponse,
  type SessionToken,
  type TokenResponse,
} from "./sessions.js";
import { byIssuer, signInResult, traced } from "./telemetry.js";
import { readLimitedText } from "./limits.js";

/**
 * PAP Account Tokens: refresh, rotation, narrowing, and revocation (§4.8, §4.9).
 *
 * The Account Token stays behind an opaque reference in the Reactor `TokenStore`; it is
 * sent only to the company's `token_endpoint` and `revocation_endpoint`. Uses of one
 * token are serialized through the `pap.accountTokenLock` contribution, so a rotated token
 * replaces the old one before anyone can use either again.
 *
 * - **Refresh** signs a Session in: `grant_type=refresh_token`, a fresh client assertion,
 *   and a fresh DPoP proof signed with the Session's key, which names it; a new key
 *   starts a new Session already signed in.
 * - **`invalid_grant`** means the Account Token or the Session ended; renewing the
 *   Session with its assertion tells which (`signed_out` or `session_ended`).
 */

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
  return parsed.toString();
}

export interface AccountTokenContext {
  readonly tokenEndpoint: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly revocationEndpoint?: string;
}

export interface AccountRefreshOptions {
  readonly context: AccountTokenContext;
  /**
   * The Session to sign in, by its Session Key; omitted, a new Session Key starts a new
   * Session already signed in (§4.8).
   */
  readonly sessionKey?: string;
  /** Narrower scopes; omitted, the company grants what the token holds. */
  readonly scopes?: readonly string[];
  /**
   * A token for one service, such as an MCP server that supports DPoP; one without DPoP
   * takes Token Exchange (`SessionClient.tokenForMcp`).
   */
  readonly resource?: string;
  readonly signal?: AbortSignal;
}

/**
 * What a refresh did, without the Account Token itself.
 *
 * `session_ended` means the Session the refresh named has ended while the Account Token
 * still works: start a new Session with it (§4.8). On `signed_out` after a refused
 * Account Token, `token` is the Session renewed signed out, when there was one.
 */
export interface AccountRefreshResult {
  readonly status: "signed_in" | "signed_out" | "session_ended" | "re_consent_required";
  readonly token?: SessionToken;
  readonly rotated: boolean;
  readonly grantedScopes: readonly string[];
  readonly missingScopes: readonly string[];
}

export interface AccountRevocationResult {
  readonly revoked: boolean;
  readonly deletedLocally: boolean;
}

export interface AccountTokenClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

function outcome(
  status: AccountRefreshResult["status"],
  token?: SessionToken,
): AccountRefreshResult {
  return {
    status,
    ...(token === undefined ? {} : { token }),
    rotated: false,
    grantedScopes: [],
    missingScopes: [],
  };
}

/** Use a stored Account Token without ever handing it to a caller. */
export class AccountTokenClient {
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxResponseBytes: number;
  readonly #sessions: SessionClient;

  constructor(options: AccountTokenClientOptions) {
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
   * A signed-in Session Token from the Account Token behind `reference` (§4.8).
   *
   * With `sessionKey`, for that Session, signing it in if it was signed out; without, a
   * new Session Key starts a new Session already signed in. `scopes` narrows the
   * request; omitted, the company grants what the token holds.
   */
  refresh(reference: string, options: AccountRefreshOptions): Promise<AccountRefreshResult> {
    return traced(
      this.#reactor,
      "pap.sign_in.account_token.refresh",
      byIssuer(options.context.issuer, "account_token"),
      () => this.#refresh(reference, options),
      signInResult,
    );
  }

  async #refresh(reference: string, options: AccountRefreshOptions): Promise<AccountRefreshResult> {
    const requested = options.scopes === undefined ? undefined : [...new Set(options.scopes)];
    if (requested && (requested.length === 0 || requested.some((scope) => !scopeToken.test(scope)))) {
      throw new AuthorizationError("invalid_scope", "At least one valid OAuth scope is required");
    }
    const resource = options.resource === undefined ? undefined : httpsUrl(options.resource, "resource");
    const context = options.context;
    const tokenEndpoint = httpsUrl(context.tokenEndpoint, "tokenEndpoint");
    const newSession = options.sessionKey === undefined;
    const key =
      options.sessionKey ??
      (await this.#prover().newSessionKey({ tenantId: context.tenantId, issuer: context.issuer }));
    const lock = firstContribution(this.#reactor, AccountTokenLocks, "Account Token lock");
    const store = firstContribution(this.#reactor, TokenStores, "token store");
    return lock.hold(reference, async () => {
      const accountToken = await store.get(reference);
      if (accountToken === undefined) return outcome("signed_out");
      const form: Record<string, string> = {
        grant_type: REFRESH_TOKEN_GRANT,
        refresh_token: accountToken.reveal(),
        ...(requested ? { scope: requested.join(" ") } : {}),
        ...(resource === undefined ? {} : { resource }),
      };
      let response: TokenResponse;
      try {
        response = await this.#sessions.tokenRequest({
          clientId: context.clientId,
          issuer: context.issuer,
          tokenEndpoint,
          tenantId: context.tenantId,
          sessionKey: key,
          form: () => form,
          error: AuthorizationError,
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (error) {
        if (!(error instanceof AuthorizationError)) throw error;
        if (error.code === "invalid_scope") return outcome("re_consent_required");
        if (error.code !== "invalid_grant") throw error;
        return this.#invalidGrant(reference, context, key, newSession, store);
      }
      if (response.tokenType !== "DPoP") {
        throw new AuthorizationError(
          "invalid_token_response",
          "An Account Token request answers with a DPoP Session Token",
        );
      }
      let token: SessionToken;
      try {
        token = sessionTokenFromResponse(response, {
          sessionKey: key,
          signedIn: true,
          requestedScopes: requested ?? [],
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
      const rotated = token.accountToken !== undefined;
      // The new token replaces the old before anyone can use either again.
      if (token.accountToken !== undefined) await store.put(reference, token.accountToken);
      const { accountToken: _rotated, ...publicToken } = token;
      return {
        status: "signed_in",
        token: publicToken,
        rotated,
        grantedScopes: publicToken.scopes,
        missingScopes: (requested ?? []).filter((scope) => !publicToken.scopes.includes(scope)),
      };
    });
  }

  /**
   * Tell an ended Account Token from an ended Session (§4.8).
   *
   * With a new key only the Account Token can be at fault. With an existing Session's
   * key, renewing that Session with its assertion tells them apart: refused there, the
   * Session has ended (its key is discarded); accepted, the Account Token is what ended,
   * and the Session carries on signed out.
   */
  async #invalidGrant(
    reference: string,
    context: AccountTokenContext,
    key: string,
    newSession: boolean,
    store: TokenStore,
  ): Promise<AccountRefreshResult> {
    if (!newSession) {
      let renewed: SessionToken;
      try {
        renewed = await this.#sessions.renew({
          clientId: context.clientId,
          pairwiseUserId: context.pairwiseUserId,
          issuer: context.issuer,
          tokenEndpoint: context.tokenEndpoint,
          tenantId: context.tenantId,
          sessionKey: key,
        });
      } catch (error) {
        if (error instanceof SessionError && error.code === "invalid_grant") {
          return outcome("session_ended");
        }
        throw error;
      }
      await store.delete(reference);
      return outcome("signed_out", renewed);
    }
    await this.#prover().discardSessionKey({
      tenantId: context.tenantId,
      issuer: context.issuer,
      sessionKey: key,
    });
    // Expired or revoked: the stored copy is useless and must go.
    await store.delete(reference);
    return outcome("signed_out");
  }

  #prover() {
    return firstContribution(this.#reactor, DpopProofProviders, "DPoP proof provider");
  }

  revoke(
    reference: string,
    options: { readonly context: AccountTokenContext; readonly signal?: AbortSignal },
  ): Promise<AccountRevocationResult> {
    return traced(
      this.#reactor,
      "pap.sign_in.account_token.revoke",
      byIssuer(options.context.issuer, "account_token"),
      () => this.#revoke(reference, options),
      signInResult,
    );
  }

  /** Revoke the Account Token (RFC 7009), then forget it: no proof goes with it (§4.3). */
  async #revoke(
    reference: string,
    options: { readonly context: AccountTokenContext; readonly signal?: AbortSignal },
  ): Promise<AccountRevocationResult> {
    if (options.context.revocationEndpoint === undefined) {
      throw new RangeError("Revocation needs the company's revocationEndpoint");
    }
    const context = options.context;
    const endpoint = httpsUrl(context.revocationEndpoint!, "revocationEndpoint");
    const lock = firstContribution(this.#reactor, AccountTokenLocks, "Account Token lock");
    const store = firstContribution(this.#reactor, TokenStores, "token store");
    return lock.hold(reference, async () => {
      const accountToken = await store.get(reference);
      if (accountToken === undefined) return { revoked: false, deletedLocally: false };
      const clock = firstContribution(this.#reactor, Clocks, "clock");
      const random = firstContribution(this.#reactor, RandomSources, "random source");
      const signer = firstContribution(this.#reactor, Signers, "signer");
      // `aud` is the issuer, whichever endpoint the assertion goes to (§4.1).
      const claims = buildClientAssertionClaims({
        clientId: context.clientId,
        issuer: context.issuer,
        now: clock.now(),
        randomBytes: (length) => random.bytes(length),
      });
      const assertion = await signer.sign({ ...claims }, { purpose: "client_assertion" });
      let response: Response;
      try {
        response = await this.#fetch(endpoint, {
          method: "POST",
          headers: { Accept: "application/json" },
          body: new URLSearchParams({
            token: accountToken.reveal(),
            token_type_hint: REFRESH_TOKEN_GRANT,
            client_id: context.clientId,
            client_assertion_type: JWT_CLIENT_ASSERTION,
            client_assertion: assertion.reveal(),
          }),
          credentials: "omit",
          redirect: "manual",
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (cause) {
        throw new AuthorizationError("request_failed", "Account Token request failed", { cause });
      }
      await refuseRedirect(response, AuthorizationError);
      const payload = await this.#decode(response);
      if (!response.ok) {
        // Kept so the host can retry: a token it believes revoked must be.
        const details = refusalDetails(response, payload);
        throw new AuthorizationError("revocation_failed", "Company refused the revocation", {
          statusCode: response.status,
          ...(Object.keys(details).length > 0 ? { details } : {}),
        });
      }
      await store.delete(reference);
      return { revoked: true, deletedLocally: true };
    });
  }

  async #decode(response: Response): Promise<unknown> {
    const body = await readLimitedText(response, this.#maxResponseBytes);
    if (new TextEncoder().encode(body).byteLength > this.#maxResponseBytes) {
      throw new AuthorizationError("response_too_large", "Account Token response exceeds size limit", {
        statusCode: response.status,
      });
    }
    if (!body) return {};
    if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json") {
      if (response.ok) return {};
      throw new AuthorizationError("invalid_content_type", "Account Token endpoint must return JSON", {
        statusCode: response.status,
      });
    }
    try {
      return parseJsonStrict(body);
    } catch (cause) {
      throw new AuthorizationError("invalid_json", "Account Token endpoint returned invalid JSON", {
        statusCode: response.status,
        cause,
      });
    }
  }
}
