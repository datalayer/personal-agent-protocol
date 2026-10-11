import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  AccountTokenLocks,
  Clocks,
  DpopProofProviders,
  RandomSources,
  Signers,
  TokenStores,
  firstContribution,
} from "./reactor.js";
import { JWT_CLIENT_ASSERTION, parseSessionToken, type SessionToken } from "./sessions.js";

/**
 * PAP Account Tokens: refresh, rotation, narrowing, and revocation (§4.8, §4.9).
 *
 * The Account Token stays behind an opaque reference in the Reactor
 * `TokenStore`; it is sent only to the company's `token_endpoint` and
 * `revocation_endpoint`. Uses of one token are serialized through the
 * `pap.accountTokenLock` contribution, so a rotated token replaces the old one
 * before anyone can use either again.
 */

export const REFRESH_TOKEN_GRANT = "refresh_token";

const opaque = /^[A-Za-z0-9_-]{1,256}$/;
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

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
  readonly sessionId: string;
  /** Narrower scopes; omitted, the company grants what the token holds. */
  readonly scopes?: readonly string[];
  /** An RFC 8707 resource indicator. */
  readonly resource?: string;
  readonly signal?: AbortSignal;
}

export interface AccountRefreshResult {
  readonly status: "signed_in" | "signed_out" | "re_consent_required";
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

/** Use a stored Account Token without ever handing it to a caller. */
export class AccountTokenClient {
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxResponseBytes: number;

  constructor(options: AccountTokenClientOptions) {
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) throw new AuthorizationError("fetch_unavailable", "A fetch implementation is required");
    const limit = options.maxResponseBytes ?? 100 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#reactor = options.reactor;
    this.#fetch = fetcher;
    this.#maxResponseBytes = limit;
  }

  async refresh(reference: string, options: AccountRefreshOptions): Promise<AccountRefreshResult> {
    if (!opaque.test(options.sessionId)) {
      throw new AuthorizationError("invalid_context", "sessionId must be an opaque identifier");
    }
    const requested = options.scopes === undefined ? undefined : [...new Set(options.scopes)];
    if (requested && (requested.length === 0 || requested.some((scope) => !scopeToken.test(scope)))) {
      throw new AuthorizationError("invalid_scope", "At least one valid OAuth scope is required");
    }
    const resource = options.resource === undefined ? undefined : httpsUrl(options.resource, "resource");
    const tokenEndpoint = httpsUrl(options.context.tokenEndpoint, "tokenEndpoint");
    const lock = firstContribution(this.#reactor, AccountTokenLocks, "Account Token lock");
    const store = firstContribution(this.#reactor, TokenStores, "token store");
    return lock.hold(reference, async () => {
      const accountToken = await store.get(reference);
      if (accountToken === undefined) {
        return { status: "signed_out", rotated: false, grantedScopes: [], missingScopes: [] };
      }
      const { response, payload } = await this.#post(
        tokenEndpoint,
        options.context,
        (assertion) => {
          const form = new URLSearchParams({
            grant_type: REFRESH_TOKEN_GRANT,
            refresh_token: accountToken.reveal(),
            session_id: options.sessionId,
            client_id: options.context.clientId,
            client_assertion_type: JWT_CLIENT_ASSERTION,
            client_assertion: assertion,
          });
          if (requested) form.set("scope", requested.join(" "));
          if (resource) form.set("resource", resource);
          return form;
        },
        true,
        options.signal,
      );
      if (!response.ok) {
        const error = remoteCode(payload);
        if (error === "invalid_grant") {
          await store.delete(reference);
          return { status: "signed_out", rotated: false, grantedScopes: [], missingScopes: [] };
        }
        if (error === "invalid_scope") {
          return { status: "re_consent_required", rotated: false, grantedScopes: [], missingScopes: [] };
        }
        throw new AuthorizationError(error ?? "http_error", "Company refused the Account Token", {
          statusCode: response.status,
        });
      }
      let token: SessionToken;
      try {
        token = parseSessionToken(payload);
      } catch (cause) {
        throw new AuthorizationError("invalid_token_response", "Account Token response is malformed", {
          statusCode: response.status,
          cause,
        });
      }
      if (token.tokenType !== "DPoP" || !token.signedIn || token.sessionId !== options.sessionId) {
        throw new AuthorizationError(
          "invalid_token_response",
          "A refresh must sign in the same proof-bound Session",
          { statusCode: response.status },
        );
      }
      if (requested && token.scopes.some((scope) => !requested.includes(scope))) {
        throw new AuthorizationError("scope_escalation", "Company returned an unrequested scope", {
          statusCode: response.status,
        });
      }
      const rotated = token.accountToken !== undefined;
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

  async revoke(
    reference: string,
    options: { readonly context: AccountTokenContext; readonly signal?: AbortSignal },
  ): Promise<AccountRevocationResult> {
    if (options.context.revocationEndpoint === undefined) {
      throw new RangeError("Revocation needs the company's revocationEndpoint");
    }
    const endpoint = httpsUrl(options.context.revocationEndpoint, "revocationEndpoint");
    const lock = firstContribution(this.#reactor, AccountTokenLocks, "Account Token lock");
    const store = firstContribution(this.#reactor, TokenStores, "token store");
    return lock.hold(reference, async () => {
      const accountToken = await store.get(reference);
      if (accountToken === undefined) return { revoked: false, deletedLocally: false };
      const { response } = await this.#post(
        endpoint,
        options.context,
        (assertion) =>
          new URLSearchParams({
            token: accountToken.reveal(),
            token_type_hint: REFRESH_TOKEN_GRANT,
            client_id: options.context.clientId,
            client_assertion_type: JWT_CLIENT_ASSERTION,
            client_assertion: assertion,
          }),
        false,
        options.signal,
      );
      if (!response.ok) {
        // Kept so the host can retry: a token it believes revoked must be.
        throw new AuthorizationError("revocation_failed", "Company refused the revocation", {
          statusCode: response.status,
        });
      }
      await store.delete(reference);
      return { revoked: true, deletedLocally: true };
    });
  }

  async #post(
    url: string,
    context: AccountTokenContext,
    form: (assertion: string) => URLSearchParams,
    dpop: boolean,
    signal?: AbortSignal,
  ): Promise<{ response: Response; payload: unknown }> {
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const signer = firstContribution(this.#reactor, Signers, "signer");
    let nonce: string | undefined;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const iat = Math.floor(clock.now().getTime() / 1000);
      const assertion = await signer.sign(
        {
          iss: context.clientId,
          sub: context.clientId,
          aud: url,
          iat,
          exp: iat + 60,
          jti: `jti_${base64Url(random.bytes(16))}`,
        },
        { purpose: "client_assertion" },
      );
      const headers: Record<string, string> = { Accept: "application/json" };
      if (dpop) {
        const provider = firstContribution(this.#reactor, DpopProofProviders, "DPoP proof provider");
        const proof = await provider.create({
          method: "POST",
          url,
          tenantId: context.tenantId,
          subject: context.pairwiseUserId,
          issuer: context.issuer,
          ...(nonce === undefined ? {} : { nonce }),
        });
        headers.DPoP = proof.reveal();
      }
      let response: Response;
      try {
        response = await this.#fetch(url, {
          method: "POST",
          headers,
          body: form(assertion.reveal()),
          credentials: "omit",
          redirect: "error",
          ...(signal === undefined ? {} : { signal }),
        });
      } catch (cause) {
        throw new AuthorizationError("request_failed", "Account Token request failed", { cause });
      }
      const payload = await this.#decode(response);
      if (dpop && attempt === 0 && remoteCode(payload) === "use_dpop_nonce") {
        nonce = response.headers.get("dpop-nonce") ?? undefined;
        if (!nonce) {
          throw new AuthorizationError("missing_dpop_nonce", "Company requested a DPoP nonce but sent none", {
            statusCode: response.status,
          });
        }
        continue;
      }
      return { response, payload };
    }
    throw new AuthorizationError("use_dpop_nonce", "Company rejected the refreshed DPoP proof");
  }

  async #decode(response: Response): Promise<unknown> {
    const body = await response.text();
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

function remoteCode(payload: unknown): string | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  const error = (payload as Record<string, unknown>).error;
  return typeof error === "string" ? error : undefined;
}
