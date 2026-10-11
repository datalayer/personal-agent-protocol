import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError, TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  AuthorizationStateStores,
  ProtectedInputs,
  RandomSources,
  TokenStores,
  firstContribution,
  type ProtectedInputRequest,
} from "./reactor.js";
import type { SecretValue } from "./secret.js";
import { parseSessionToken, type SessionToken } from "./sessions.js";
import { DpopFetchClient } from "./transport.js";

/**
 * PAP Mediated Sign-In: the user's credentials, relayed to one endpoint (§4.7).
 *
 * Fields come from the Reactor `pap.protectedInput` contribution (the host's
 * own trusted surface), go only to `auth.mediated.endpoint` on the company's
 * domain with no redirect followed, are sent once, and are dropped as soon as
 * the request is made. A `code_required` answer continues with the one-time
 * code alone, from the Session that started it.
 */

export interface MediatedField {
  readonly name: string;
  readonly label: string;
  readonly secret: boolean;
}

export interface MediatedSignInDescriptor {
  readonly endpoint: string;
  readonly fields: readonly MediatedField[];
}

export interface MediatedSignInResult {
  readonly status: "complete" | "code_required" | "failed" | "expired";
  readonly reference?: string;
  readonly sentTo?: string;
  readonly expiresAt?: Date;
  readonly token?: SessionToken;
  readonly accountTokenReference?: string;
  readonly grantedScopes: readonly string[];
  readonly missingScopes: readonly string[];
}

export interface MediatedSignInOptions {
  readonly mediated: MediatedSignInDescriptor;
  readonly organization: { readonly name: string; readonly domain: string };
  readonly issuer: string;
  readonly scopes: readonly string[];
  readonly token: SessionToken;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly signal?: AbortSignal;
}

export interface MediatedCodeOptions {
  readonly token: SessionToken;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly issuer: string;
  readonly signal?: AbortSignal;
}

export interface MediatedSignInClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

interface PendingCode {
  readonly kind: "pap.mediated-sign-in.v1";
  readonly endpoint: string;
  readonly signInId: string;
  readonly sessionId: string;
  readonly scopes: readonly string[];
  readonly companyName: string;
  readonly companyDomain: string;
  readonly sentTo?: string;
  readonly expiresAt: Date;
}

const identifier = /^[A-Za-z0-9_-]{1,256}$/;
const noResult = { grantedScopes: [], missingScopes: [] } as const;

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function isPending(value: unknown): value is PendingCode {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Partial<PendingCode>).kind === "pap.mediated-sign-in.v1"
  );
}

/** Relay a user's credentials to the company's mediated endpoint, once. */
export class MediatedSignInClient {
  readonly #reactor: ReactorPlatformView;
  readonly #transport: DpopFetchClient;
  readonly #maxResponseBytes: number;

  constructor(options: MediatedSignInClientOptions) {
    const limit = options.maxResponseBytes ?? 100 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#reactor = options.reactor;
    // Credentials go to one URL: a redirect is refused, never followed.
    this.#transport = new DpopFetchClient({
      reactor: options.reactor,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      maxRedirects: 0,
    });
    this.#maxResponseBytes = limit;
  }

  async signIn(options: MediatedSignInOptions): Promise<MediatedSignInResult> {
    const endpoint = endpointOnCompanyDomain(options.mediated.endpoint, options.organization.domain);
    const requested = [...new Set(options.scopes)];
    const credentials = await this.#collect(
      {
        purpose: "credentials",
        companyName: options.organization.name,
        companyDomain: options.organization.domain,
        fields: options.mediated.fields.map(({ name, label, secret }) => ({ name, label, secret })),
      },
      new Set(options.mediated.fields.map((field) => field.name)),
    );
    let body: string;
    try {
      body = JSON.stringify({
        scope: requested.join(" "),
        credentials: Object.fromEntries(
          Object.entries(credentials).map(([name, value]) => [name, value.reveal()]),
        ),
      });
    } finally {
      for (const name of Object.keys(credentials)) delete credentials[name];
    }
    const response = await this.#post(endpoint, body, options);
    return this.#result(response, {
      kind: "pap.mediated-sign-in.v1",
      endpoint,
      signInId: "",
      sessionId: options.token.sessionId,
      scopes: requested,
      companyName: options.organization.name,
      companyDomain: options.organization.domain,
      expiresAt: new Date(8.64e15),
    });
  }

  async submitCode(reference: string, options: MediatedCodeOptions): Promise<MediatedSignInResult> {
    const store = firstContribution(this.#reactor, AuthorizationStateStores, "authorization state store");
    const pending = await store.take(reference);
    if (!isPending(pending)) {
      throw new AuthorizationError(
        "invalid_or_expired_sign_in",
        "Mediated Sign-In is unknown, expired, or already complete",
      );
    }
    if (options.token.sessionId !== pending.sessionId) {
      await store.put(reference, pending, { expiresAt: pending.expiresAt });
      throw new AuthorizationError(
        "session_mismatch",
        "Only the Session that started this sign-in can finish it",
      );
    }
    const code = await this.#collect(
      {
        purpose: "one_time_code",
        companyName: pending.companyName,
        companyDomain: pending.companyDomain,
        fields: [{ name: "code", label: "Code", secret: true }],
        ...(pending.sentTo === undefined ? {} : { sentTo: pending.sentTo }),
      },
      new Set(["code"]),
    );
    let body: string;
    try {
      body = JSON.stringify({ code: (code.code as SecretValue).reveal() });
    } finally {
      delete code.code;
    }
    const response = await this.#post(`${pending.endpoint.replace(/\/$/, "")}/${pending.signInId}`, body, options);
    return this.#result(response, pending, reference);
  }

  async #result(response: Response, pending: PendingCode, reference?: string): Promise<MediatedSignInResult> {
    const payload = await this.#decode(response);
    if (!response.ok) {
      const retryAfter = response.headers.get("retry-after");
      throw new AuthorizationError(remoteCode(payload) ?? "http_error", "Company refused the Mediated Sign-In", {
        statusCode: response.status,
        ...(retryAfter ? { details: { retry_after: retryAfter } } : {}),
      });
    }
    const source = typeof payload === "object" && payload !== null ? (payload as Record<string, unknown>) : {};
    const status = source.status;
    if (status === "failed" || status === "expired") return { status, ...noResult };
    if (status === "code_required") return this.#codeRequired(source, pending, reference);
    if (status === "complete") return this.#complete(source, pending, response.status);
    throw new AuthorizationError("invalid_mediated_response", "Mediated Sign-In response has no known status", {
      statusCode: response.status,
    });
  }

  async #codeRequired(
    source: Record<string, unknown>,
    pending: PendingCode,
    reference?: string,
  ): Promise<MediatedSignInResult> {
    const signInId = source.sign_in_id;
    const expiresAt = typeof source.expires_at === "string" ? new Date(source.expires_at) : undefined;
    if (typeof signInId !== "string" || !identifier.test(signInId) || !expiresAt || Number.isNaN(+expiresAt)) {
      throw new AuthorizationError("invalid_mediated_response", "Mediated Sign-In code challenge is malformed");
    }
    if (pending.signInId && signInId !== pending.signInId) {
      throw new AuthorizationError("invalid_mediated_response", "Mediated Sign-In changed its sign-in ID");
    }
    const code = typeof source.code === "object" && source.code !== null ? (source.code as Record<string, unknown>) : {};
    const sentTo = typeof code.sent_to === "string" ? code.sent_to : undefined;
    const continued: PendingCode = {
      ...pending,
      signInId,
      expiresAt,
      ...(sentTo === undefined ? {} : { sentTo }),
    };
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const ref = reference ?? `mediated_${base64Url(random.bytes(16))}`;
    const store = firstContribution(this.#reactor, AuthorizationStateStores, "authorization state store");
    await store.put(ref, continued, { expiresAt });
    return {
      status: "code_required",
      reference: ref,
      expiresAt,
      ...(continued.sentTo === undefined ? {} : { sentTo: continued.sentTo }),
      ...noResult,
    };
  }

  async #complete(source: Record<string, unknown>, pending: PendingCode, status: number): Promise<MediatedSignInResult> {
    const { status: _status, ...fields } = source;
    let token: SessionToken;
    try {
      token = parseSessionToken(fields);
    } catch (cause) {
      throw new AuthorizationError("invalid_token_response", "Mediated Sign-In token response is malformed", {
        statusCode: status,
        cause,
      });
    }
    if (token.tokenType !== "DPoP" || !token.signedIn || token.sessionId !== pending.sessionId) {
      throw new AuthorizationError(
        "invalid_token_response",
        "Mediated Sign-In must sign in the same proof-bound Session",
        { statusCode: status },
      );
    }
    if (token.scopes.some((scope) => !pending.scopes.includes(scope))) {
      throw new AuthorizationError("scope_escalation", "Company returned an unrequested scope", { statusCode: status });
    }
    let accountTokenReference: string | undefined;
    if (token.accountToken !== undefined) {
      const random = firstContribution(this.#reactor, RandomSources, "random source");
      accountTokenReference = `account_${base64Url(random.bytes(16))}`;
      await firstContribution(this.#reactor, TokenStores, "token store").put(accountTokenReference, token.accountToken);
    }
    const { accountToken: _account, ...publicToken } = token;
    return {
      status: "complete",
      token: publicToken,
      ...(accountTokenReference === undefined ? {} : { accountTokenReference }),
      grantedScopes: publicToken.scopes,
      missingScopes: pending.scopes.filter((scope) => !publicToken.scopes.includes(scope)),
    };
  }

  async #collect(request: ProtectedInputRequest, expected: Set<string>): Promise<Record<string, SecretValue>> {
    const source = firstContribution(this.#reactor, ProtectedInputs, "protected input");
    const values = await source.collect(request);
    const names = Object.keys(values);
    if (
      names.length !== expected.size ||
      names.some((name) => !expected.has(name)) ||
      Object.values(values).some((value) => typeof value?.reveal !== "function" || !value.reveal())
    ) {
      for (const name of names) delete values[name];
      throw new AuthorizationError(
        "invalid_protected_input",
        "Protected input must answer exactly the declared fields, none empty",
      );
    }
    return values;
  }

  async #post(
    url: string,
    body: string,
    options: Pick<MediatedSignInOptions, "token" | "tenantId" | "pairwiseUserId" | "issuer" | "signal">,
  ): Promise<Response> {
    try {
      return await this.#transport.request("POST", url, {
        token: options.token,
        tenantId: options.tenantId,
        pairwiseUserId: options.pairwiseUserId,
        issuer: options.issuer,
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (cause) {
      const code = cause instanceof TransportError ? cause.code : "request_failed";
      throw new AuthorizationError(code, "Mediated Sign-In request failed", { cause });
    }
  }

  async #decode(response: Response): Promise<unknown> {
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > this.#maxResponseBytes) {
      throw new AuthorizationError("response_too_large", "Mediated Sign-In response exceeds size limit", {
        statusCode: response.status,
      });
    }
    if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json") {
      throw new AuthorizationError("invalid_content_type", "Mediated Sign-In endpoint must return JSON", {
        statusCode: response.status,
      });
    }
    try {
      return parseJsonStrict(body);
    } catch (cause) {
      throw new AuthorizationError("invalid_json", "Mediated Sign-In endpoint returned invalid JSON", {
        statusCode: response.status,
        cause,
      });
    }
  }
}

function endpointOnCompanyDomain(endpoint: string, domain: string): string {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch (cause) {
    throw new AuthorizationError("unsafe_mediated_endpoint", "Mediated endpoint is not a URL", { cause });
  }
  const host = url.hostname.toLowerCase();
  const company = domain.toLowerCase();
  if (url.protocol !== "https:" || (host !== company && !host.endsWith(`.${company}`))) {
    throw new AuthorizationError(
      "unsafe_mediated_endpoint",
      "Credentials are sent only to an endpoint on the company's own domain",
    );
  }
  return url.toString();
}

function remoteCode(payload: unknown): string | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  const error = (payload as Record<string, unknown>).error;
  return typeof error === "string" ? error : undefined;
}
