/**
 * A framework-neutral PAP company: discovery, Sessions, sign-in, conversations, operations.
 *
 * `CompanyService.handle` takes a neutral request and returns a neutral
 * response, so any web framework can serve it (`node.ts` serves it over
 * `node:http` and `node:https`). Every part a company would replace is a
 * Reactor contribution (`points.ts`): its store, accounts, agent, operation
 * executors, client policy and resolver, and replay cache. It is the port of
 * the Python `personal_agent_protocol.company.service` and answers the same
 * requests with the same responses.
 *
 * What it implements of draft 0.1 and Operations v1:
 *
 * - Discovery (`/.well-known/poppy.json`) and OAuth metadata
 *   (`/.well-known/oauth-authorization-server`), one issuer on the company's
 *   own domain.
 * - Sessions (§4.2): the JWT-bearer grant with a verified client assertion and
 *   Session assertion, DPoP-bound tokens, renewal by `session_id`.
 * - Direct Sign-In (§4.5): the company's consent page, the user's decision as
 *   `approveAuthorization` / `denyAuthorization`, PKCE, one-use codes.
 * - Device Sign-In (§4.6) with `authorization_pending` and `slow_down`, and the
 *   company's own approval page as `approveDevice` (the user's action).
 * - Mediated Sign-In (§4.7) with a one-time code, attempt limits, and uniform
 *   failures; credentials are checked by the account directory and dropped.
 * - Account Tokens (§4.8, §4.9): rotation on every refresh, narrower scopes
 *   only, `invalid_grant` for an expired, revoked, or rotated-away token, and
 *   revocation that signs out every Session signed in with it.
 * - Conversations (§7): idempotent messages, ordered cursor events, waited
 *   replies, SSE, handoff, Direct Conversations, `authorization` events, and
 *   closing; a conversation that is not yours is `conversation_not_found`.
 * - The OpenAPI API point (`/api/…`), its consequential calls answering `202`
 *   with an operation (Operations §4.1).
 * - Operations v1: proposals from the company agent or the API, read, confirm
 *   (latest revision, approval rules, scope, extension negotiation), at most
 *   once, and cancel.
 * - MCP (§4.3, §6), when a `pap.company.mcp` contribution is present: a
 *   Streamable HTTP endpoint at `/mcp` accepting only Bearer Session Tokens
 *   issued for its url (requested without DPoP, `resource` = that url), its
 *   protected resource metadata (RFC 9728), and tools that propose operations
 *   in `structuredContent` (Operations §4.2). Bearer tokens work nowhere else.
 * - Web browsing (§5), with `web: true`: the browser-session endpoint sets the
 *   company's own cookie for a Session from a verified browser assertion, and each
 *   operation's `url` shows it in that Session, where the user can confirm or cancel
 *   it: the same operation, performed at most once whichever channel confirms it.
 */

import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import type { ReactorPlatformView } from "@datalayer/reactor";
import { decodeJwt, decodeProtectedHeader, importJWK, type JWK } from "jose";

import { verifyBrowserAssertion, type VerifiedBrowserAssertion } from "../browser-server.js";
import { verifyDpopProof } from "../crypto.js";
import { ProofError, ProtocolValidationError, SessionError } from "../errors.js";
import { parseJsonStrict } from "../json.js";
import {
  parseMessage,
  parseOperation,
  type ClientMetadata,
  type JsonWebKeySet,
  type Message,
  type Operation,
  type OperationResult,
} from "../models.js";
import { OPERATIONS_VERSION } from "../operations.js";
import { PROTOCOL_PROFILE } from "../profile.js";
import { Clocks, RandomSources, firstContribution, optionalContribution } from "../reactor.js";
import { SecretValue } from "../secret.js";
import { JWT_BEARER_GRANT, JWT_CLIENT_ASSERTION } from "../sessions.js";
import {
  ClientPolicies,
  ClientResolvers,
  CompanyAccounts,
  CompanyAgents,
  CompanyApis,
  CompanyMcps,
  CompanyStores,
  OperationExecutors,
  OperationFailed,
  OperationOutcomeUnknown,
  ReplayCaches,
  type CompanyApi,
  type CompanyMcp,
  type Reply,
  type ReplayCache,
} from "./points.js";
import {
  RecordKinds,
  type AccountAgent,
  type AccountFamily,
  type AccountGrant,
  type CompanyStore,
  type IssuedCode,
  type IssuedSession,
  type JsonObject,
  type KnownClient,
  type MessageReceipt,
  type OperationProposal,
  type PendingAuthorization,
  type PendingDevice,
  type PendingMediated,
  type SessionPointer,
  type StoreWriteOptions,
  type StoredConversation,
  type StoredEvent,
  type StoredOperation,
  type StoredSession,
  type UserCode,
} from "./store.js";
import { verifyAssertion } from "./verify.js";

/** The `kid` a compact JWT's header names, if any (used only to look a key up). */
function keyId(compact: string): { readonly kid?: string } {
  try {
    const header: unknown = JSON.parse(
      Buffer.from(compact.split(".", 1)[0] ?? "", "base64url").toString("utf8"),
    );
    const kid = (header as { kid?: unknown } | null)?.kid;
    return typeof kid === "string" ? { kid } : {};
  } catch {
    return {};
  }
}

const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const REFRESH_TOKEN_GRANT = "refresh_token";
const PAGE = 50;

export type MediatedFieldSpec = readonly [name: string, label: string, secret: boolean];

export interface CompanyConfigOptions {
  readonly name: string;
  readonly domain: string;
  readonly scopes: readonly string[];
  readonly writeScopes?: readonly string[];
  readonly mediatedFields?: readonly MediatedFieldSpec[];
  readonly device?: boolean;
  readonly direct?: boolean;
  readonly operations?: boolean;
  readonly humansAvailable?: boolean;
  readonly sessionLifetimeSeconds?: number;
  readonly accountTokenLifetimeSeconds?: number;
  readonly operationLifetimeSeconds?: number;
  readonly deviceInterval?: number;
  readonly maxCodeAttempts?: number;
  readonly customScopes?: Readonly<Record<string, string>>;
  /** A hosted Device Sign-In page (`verification_uri`); `&code=<user_code>` completes it. */
  readonly devicePage?: string;
  /** A hosted consent page with `{request_id}`: `GET /oauth/authorize` answers 303 to it. */
  readonly consentPage?: string;
  /** Web browsing (§5): a browser-session endpoint and a page for each operation. */
  readonly web?: boolean;
}

function hostedPage(name: string, value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(value.replaceAll("{request_id}", "x"));
  } catch {
    throw new RangeError(`${name} must be an HTTPS URL without a fragment`);
  }
  if (parsed.protocol !== "https:" || !parsed.hostname || parsed.hash) {
    throw new RangeError(`${name} must be an HTTPS URL without a fragment`);
  }
  return value;
}

/** What the company publishes and allows. */
export class CompanyConfig {
  readonly name: string;
  readonly domain: string;
  readonly scopes: readonly string[];
  readonly writeScopes: readonly string[];
  readonly mediatedFields: readonly MediatedFieldSpec[];
  readonly device: boolean;
  readonly direct: boolean;
  readonly operations: boolean;
  readonly humansAvailable: boolean;
  readonly sessionLifetimeSeconds: number;
  readonly accountTokenLifetimeSeconds: number;
  readonly operationLifetimeSeconds: number;
  readonly deviceInterval: number;
  readonly maxCodeAttempts: number;
  readonly customScopes: Readonly<Record<string, string>>;
  readonly devicePage: string | undefined;
  readonly consentPage: string | undefined;
  readonly web: boolean;

  constructor(options: CompanyConfigOptions) {
    this.name = options.name;
    this.domain = options.domain;
    this.scopes = [...options.scopes];
    this.writeScopes = [...(options.writeScopes ?? [])];
    this.mediatedFields = [...(options.mediatedFields ?? [])];
    this.device = options.device ?? true;
    this.direct = options.direct ?? true;
    this.operations = options.operations ?? true;
    this.humansAvailable = options.humansAvailable ?? false;
    this.sessionLifetimeSeconds = options.sessionLifetimeSeconds ?? 60 * 60;
    this.accountTokenLifetimeSeconds = options.accountTokenLifetimeSeconds ?? 90 * 24 * 60 * 60;
    this.operationLifetimeSeconds = options.operationLifetimeSeconds ?? 15 * 60;
    this.deviceInterval = options.deviceInterval ?? 5;
    this.maxCodeAttempts = options.maxCodeAttempts ?? 3;
    this.customScopes = { ...(options.customScopes ?? {}) };
    this.devicePage = hostedPage("devicePage", options.devicePage);
    this.consentPage = hostedPage("consentPage", options.consentPage);
    this.web = options.web ?? false;
    if (this.consentPage !== undefined && !this.consentPage.includes("{request_id}")) {
      throw new RangeError("consentPage must contain {request_id}");
    }
    if (this.writeScopes.some((scope) => !this.scopes.includes(scope))) {
      throw new RangeError("writeScopes must be among scopes");
    }
    if (this.operations && !this.writeScopes.length) {
      // Confirming an operation needs a write scope: without one, any signed-in Session,
      // whatever it was granted, could confirm (Operations §3.3).
      throw new RangeError("operations need writeScopes: the scopes confirming one requires");
    }
  }

  get base(): string {
    return `https://${this.domain}`;
  }
  get tokenEndpoint(): string {
    return `${this.base}/oauth/token`;
  }
  get deviceEndpoint(): string {
    return `${this.base}/oauth/device`;
  }
  get authorizationEndpoint(): string {
    return `${this.base}/oauth/authorize`;
  }
  get apiDescription(): string {
    return `${this.base}/api/openapi.json`;
  }
  get revocationEndpoint(): string {
    return `${this.base}/oauth/revoke`;
  }
  get mediatedEndpoint(): string {
    return `${this.base}/poppy/sign-in`;
  }
  get conversationsEndpoint(): string {
    return `${this.base}/poppy/conversations`;
  }
  get operationsEndpoint(): string {
    return `${this.base}/poppy/operations`;
  }
  get mcpUrl(): string {
    return `${this.base}/mcp`;
  }
  get mcpResourceMetadata(): string {
    return `${this.base}/.well-known/oauth-protected-resource/mcp`;
  }
  get browserSessionEndpoint(): string {
    return `${this.base}/poppy/browser-session`;
  }
}

/** A request as any framework hands it over: full HTTPS URL, lower-case headers. */
export interface CompanyRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Uint8Array | string;
}

/**
 * A response: a JSON `body`, an HTML page (a string `body` with its own
 * `Content-Type`), or an SSE `stream`.
 */
export interface CompanyResponse {
  readonly status: number;
  readonly body?: unknown;
  readonly headers: Readonly<Record<string, string>>;
  readonly stream?: AsyncIterable<Uint8Array>;
}

class Refused extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly extra: Readonly<Record<string, unknown>> = {},
  ) {
    super(error);
  }
}

const NO_STORE = { "Cache-Control": "no-store" } as const;

const CHALLENGED = new Set([
  "invalid_token",
  "sign_in_required",
  "insufficient_scope",
  "invalid_dpop_proof",
]);

function jsonError(
  status: number,
  error: string,
  extra: Readonly<Record<string, unknown>> = {},
): CompanyResponse {
  const headers: Record<string, string> = { ...NO_STORE };
  if (CHALLENGED.has(error) && (status === 401 || status === 403)) {
    // Token errors are also in WWW-Authenticate (§6, RFC 9449).
    const scope = extra.scope;
    headers["WWW-Authenticate"] =
      `DPoP error="${error}"` + (typeof scope === "string" ? `, scope="${scope}"` : "");
  }
  return { status, body: { error, ...extra }, headers };
}

function rpcError(requestId: unknown, code: number, message: string): CompanyResponse {
  return {
    status: 200,
    body: { jsonrpc: "2.0", id: requestId ?? null, error: { code, message } },
    headers: {},
  };
}

function digest(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** The consent page's cookie: `__Host-`, so no other host or path can set it. */
export const CONSENT_COOKIE = "__Host-poppy_consent";
/** The website's cookie for the agent's Session (§5): `__Host-`, so no other host or path can set it. */
export const WEB_COOKIE = "__Host-poppy_session";

/** What the user decided on the company's own consent page, checked by `consentDecision`. */
export interface ConsentDecision {
  readonly requestId: string;
  readonly allow: boolean;
}

/** A form's CSRF token: only a page whose browser holds `secret` (a cookie) can know it. */
function bound(secret: string, purpose: string): string {
  return createHmac("sha256", secret).update(purpose).digest("base64url");
}

function cookie(request: CompanyRequest, name: string): string | undefined {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const at = part.indexOf("=");
    if (at > 0 && part.slice(0, at).trim() === name) {
      const value = part.slice(at + 1).trim();
      return value || undefined;
    }
  }
  return undefined;
}

/**
 * A POST a page of this site sent, never one another site's page made the browser send:
 * `Sec-Fetch-Site`, when sent, is `same-origin`, and `Origin`, when sent, the company's
 * own; the form's CSRF token is checked besides (Guides, consent pages).
 */
function fromThisSite(request: CompanyRequest, base: string): boolean {
  const site = request.headers["sec-fetch-site"];
  const origin = request.headers.origin;
  return (site === undefined || site === "same-origin") && (origin === undefined || origin === base);
}

function sameText(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

/** Python's `parse_qsl` into a dict: blank values dropped, the last value wins. */
function pairs(query: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of new URLSearchParams(query)) {
    if (value) result[name] = value;
  }
  return result;
}

function text(body: Uint8Array | string | undefined): string {
  if (body === undefined) return "";
  return typeof body === "string" ? body : new TextDecoder().decode(body);
}

function words(value: unknown): string[] {
  return String(value ?? "")
    .split(" ")
    .filter(Boolean);
}

/** RFC 3339 in UTC with `Z`, without a fraction when there is none (Python's `isoformat`). */
function isoZ(date: Date): string {
  return date.toISOString().replace(".000Z", "Z");
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** A request body that must be one JSON object: anything else is `invalid_request`. */
function jsonObject(body: Uint8Array | string | undefined): Record<string, unknown> {
  const value = parseJsonStrict(text(body));
  if (!isObject(value)) throw new Refused(400, "invalid_request");
  return value;
}

function sameOwner(a: readonly [string, string], b: readonly [string, string]): boolean {
  return a[0] === b[0] && a[1] === b[1];
}

/** The message as stored and digested: absent members dropped (Python's `exclude_none`). */
function plain(message: Message): Record<string, unknown> {
  return JSON.parse(JSON.stringify(message)) as Record<string, unknown>;
}

/** How often a compare-and-set is retried against concurrent writers before giving up. */
const CAS_ATTEMPTS = 32;

type TokenType = "DPoP" | "Bearer";
const EVERY_TOKEN_TYPE: readonly TokenType[] = ["DPoP", "Bearer"];
/** How long an expired device or Mediated sign-in is kept, to answer that it expired. */
const KEPT_EXPIRED_MS = 10 * 60 * 1000;

/** A record as the store keeps it. */
function json(record: object): JsonObject {
  return record as JsonObject;
}

function expiry(at: Date | string | undefined): StoreWriteOptions {
  return at === undefined ? {} : { expiresAt: new Date(at) };
}

/** One store key for several values (never ambiguous). */
function composite(...parts: readonly string[]): string {
  return digest(JSON.stringify(parts));
}

function withItem(items: readonly string[], item: string | undefined): readonly string[] {
  return item === undefined || items.includes(item) ? items : [...items, item];
}

/** JSON with every object's members sorted: equal values, equal text. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (isObject(value)) {
    const members = Object.keys(value)
      .sort()
      .filter((key) => value[key] !== undefined)
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`);
    return `{${members.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/** One company's PAP endpoints over Reactor contributions. */
export class CompanyService {
  readonly config: CompanyConfig;
  readonly reactor: ReactorPlatformView;

  constructor(options: { readonly config: CompanyConfig; readonly reactor: ReactorPlatformView }) {
    this.config = options.config;
    this.reactor = options.reactor;
  }

  // Contributions -------------------------------------------------------------------

  get store(): CompanyStore {
    return firstContribution(this.reactor, CompanyStores, "company store");
  }

  #now(): Date {
    return firstContribution(this.reactor, Clocks, "clock").now();
  }

  #id(prefix: string): string {
    const bytes = firstContribution(this.reactor, RandomSources, "random").bytes(16);
    if (bytes.byteLength < 16) {
      throw new Error("Opaque PAP identifiers require at least 128 random bits");
    }
    return `${prefix}_${base64Url(bytes)}`;
  }

  #replay(): ReplayCache {
    return firstContribution(this.reactor, ReplayCaches, "replay cache");
  }

  #later(seconds: number): Date {
    return new Date(this.#now().getTime() + seconds * 1000);
  }

  #passed(at: string): boolean {
    return this.#now().getTime() >= new Date(at).getTime();
  }

  async #read<T>(kind: string, key: string): Promise<T | undefined> {
    const entry = await this.store.get(kind, key);
    return entry === undefined ? undefined : (entry.value as unknown as T);
  }

  /**
   * Compare-and-set: `change` maps the current record to the next, retried on conflict.
   *
   * Returns `[before, after]`, or `undefined` when the record is absent; a change
   * returning the same object writes nothing. Its expiry is kept.
   */
  async #change<T extends object>(
    kind: string,
    key: string,
    change: (current: T) => T,
  ): Promise<readonly [T, T] | undefined> {
    for (let attempt = 0; attempt < CAS_ATTEMPTS; attempt += 1) {
      const entry = await this.store.get(kind, key);
      if (entry === undefined) return undefined;
      const before = entry.value as unknown as T;
      const after = change(before);
      if (after === before) return [before, after];
      if (await this.store.replace(kind, key, entry.version, json(after), expiry(entry.expiresAt))) {
        return [before, after];
      }
    }
    throw new Refused(503, "temporarily_unavailable");
  }

  // Routing -------------------------------------------------------------------------

  async handle(request: CompanyRequest): Promise<CompanyResponse> {
    const path = new URL(request.url).pathname;
    const method = request.method.toUpperCase();
    try {
      if (method === "GET" && path === "/.well-known/poppy.json") {
        return { status: 200, body: this.discoveryDocument(), headers: {} };
      }
      if (method === "GET" && path === "/.well-known/oauth-authorization-server") {
        return { status: 200, body: this.oauthMetadata(), headers: {} };
      }
      const mcp = this.#mcp();
      if (path === "/.well-known/oauth-protected-resource/mcp" && mcp !== undefined) {
        return { status: 200, body: this.protectedResourceMetadata(), headers: {} };
      }
      if (path === "/mcp" && mcp !== undefined) return await this.#mcpRoute(request, mcp);
      if (method === "POST" && path === "/poppy/browser-session" && this.config.web) {
        return await this.#browserSession(request);
      }
      if (path.startsWith("/operations/") && this.config.web && this.config.operations) {
        return await this.#operationPage(request, method, path.split("/")[2] ?? "");
      }
      if (method === "POST" && path === "/oauth/token") return await this.#token(request);
      if (method === "GET" && path === "/oauth/authorize" && this.config.direct) {
        return await this.#authorize(request);
      }
      const api = this.#api();
      if (method === "GET" && path === "/api/openapi.json" && api !== undefined) {
        return { status: 200, body: api.openapi(), headers: {} };
      }
      if (path.startsWith("/api/") && api !== undefined) {
        return await this.#apiCall(request, api, method, path);
      }
      if (method === "POST" && path === "/oauth/device" && this.config.device) {
        return await this.#device(request);
      }
      if (method === "POST" && path === "/oauth/revoke") return await this.#revoke(request);
      if (method === "POST" && path === "/poppy/sign-in" && this.config.mediatedFields.length) {
        return await this.#mediated(request);
      }
      if (method === "POST" && path.startsWith("/poppy/sign-in/")) {
        return await this.#mediatedCode(request, path.slice(path.lastIndexOf("/") + 1));
      }
      if (path === "/poppy/conversations" && method === "POST") {
        return await this.#startConversation(request);
      }
      if (path.startsWith("/poppy/conversations/")) {
        return await this.#conversationRoute(request, method, path);
      }
      if (path.startsWith("/poppy/operations/") && this.config.operations) {
        return await this.#operationRoute(request, method, path);
      }
    } catch (error) {
      if (error instanceof Refused) return jsonError(error.status, error.error, error.extra);
      if (error instanceof SessionError || error instanceof ProofError) {
        const status = error.statusCode ?? (error.code === "invalid_client" ? 401 : 400);
        return jsonError(status, error.code);
      }
      // A body that is not JSON, or not the shape the protocol defines: the caller's
      // mistake, never the company's (no 500).
      if (error instanceof ProtocolValidationError) return jsonError(400, "invalid_request");
      throw error;
    }
    return jsonError(404, "not_found");
  }

  // Discovery -----------------------------------------------------------------------

  discoveryDocument(): Record<string, unknown> {
    const config = this.config;
    const auth: Record<string, unknown> = { issuer: config.base };
    if (config.direct) auth.direct = { scopes: [...config.scopes] };
    if (config.device) auth.device = { scopes: [...config.scopes] };
    if (config.mediatedFields.length) {
      auth.mediated = {
        endpoint: config.mediatedEndpoint,
        fields: config.mediatedFields.map(([name, label, secret]) => ({ name, label, secret })),
        scopes: [...config.scopes],
      };
    }
    if (Object.keys(config.customScopes).length) auth.custom_scopes = { ...config.customScopes };
    const document: Record<string, unknown> = {
      protocol_version: PROTOCOL_PROFILE,
      organization: { name: config.name, domain: config.domain },
      auth,
      agent: { protocols: [{ type: "poppy", endpoint: config.conversationsEndpoint }] },
    };
    const apis: Record<string, string>[] = [];
    const api = this.#api();
    if (api !== undefined) {
      apis.push({ type: "openapi", url: config.apiDescription, description: api.description });
    }
    const mcp = this.#mcp();
    if (mcp !== undefined) {
      apis.push({ type: "mcp", url: config.mcpUrl, description: mcp.description });
    }
    if (apis.length) document.apis = apis;
    if (config.web) document.web = { browser_session_endpoint: config.browserSessionEndpoint };
    if (config.operations) {
      document.extensions = {
        operations: { version: OPERATIONS_VERSION, endpoint: config.operationsEndpoint },
      };
    }
    return document;
  }

  /** RFC 9728 metadata for the MCP server: its issuer is the company's (§6). */
  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.config.mcpUrl,
      authorization_servers: [this.config.base],
      scopes_supported: [...this.config.scopes],
      bearer_methods_supported: ["header"],
    };
  }

  oauthMetadata(): Record<string, unknown> {
    const config = this.config;
    const metadata: Record<string, unknown> = {
      issuer: config.base,
      token_endpoint: config.tokenEndpoint,
      revocation_endpoint: config.revocationEndpoint,
      poppy_domains: [config.domain],
      dpop_signing_alg_values_supported: ["ES256", "RS256"],
    };
    if (config.device) metadata.device_authorization_endpoint = config.deviceEndpoint;
    if (config.direct) {
      metadata.authorization_endpoint = config.authorizationEndpoint;
      metadata.code_challenge_methods_supported = ["S256"];
    }
    return metadata;
  }

  // OAuth ---------------------------------------------------------------------------

  /** Verify the client assertion, the agent's keys, and the company's policy. */
  async #client(form: Readonly<Record<string, string>>, audience: string): Promise<string> {
    const clientId = form.client_id ?? "";
    if (form.client_assertion_type !== JWT_CLIENT_ASSERTION || !clientId) {
      throw new Refused(401, "invalid_client");
    }
    if (!(await this.#allowed(clientId))) throw new Refused(401, "invalid_client");
    const resolver = firstContribution(this.reactor, ClientResolvers, "client resolver");
    let resolved: readonly [ClientMetadata, JsonWebKeySet];
    try {
      resolved = await resolver.resolve(clientId, keyId(form.client_assertion ?? ""));
    } catch {
      throw new Refused(401, "invalid_client");
    }
    const [metadata, keys] = resolved;
    await verifyAssertion(form.client_assertion ?? "", {
      keys,
      issuer: clientId,
      audience,
      subject: clientId,
      replayCache: this.#replay(),
      now: this.#now(),
    });
    const extensions = Object.keys(metadata.extensions ?? {}).sort();
    const known = await this.#read<KnownClient>(RecordKinds.client, clientId);
    if (known === undefined || canonical(known.extensions) !== canonical(extensions)) {
      await this.store.put(RecordKinds.client, clientId, json({ extensions } satisfies KnownClient));
    }
    return clientId;
  }

  /**
   * The company's policy on this agent, asked before anything is fetched for it: a
   * blocked `client_id` is never resolved (no metadata or keys fetched from its domain),
   * and a blocked agent's tokens stop working at once.
   */
  async #allowed(clientId: string): Promise<boolean> {
    return firstContribution(this.reactor, ClientPolicies, "policy").allows(clientId);
  }

  /** Whether the agent declared the Operations extension when it last authenticated. */
  async #supportsOperations(clientId: string): Promise<boolean> {
    const known = await this.#read<KnownClient>(RecordKinds.client, clientId);
    return known !== undefined && known.extensions.includes("operations");
  }

  async #dpop(request: CompanyRequest, accessToken?: string): Promise<string> {
    const status = accessToken === undefined ? 400 : 401;
    const proof = request.headers.dpop;
    if (!proof) throw new Refused(status, "invalid_dpop_proof");
    try {
      const verified = await verifyDpopProof(proof, {
        method: request.method,
        url: request.url,
        replayCache: this.#replay(),
        ...(accessToken === undefined ? {} : { accessToken: new SecretValue(accessToken) }),
        now: this.#now(),
      });
      return verified.keyThumbprint;
    } catch (error) {
      if (error instanceof ProofError) throw new Refused(status, error.code);
      throw error;
    }
  }

  async #token(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const grant = form.grant_type;
    const clientId = await this.#client(form, this.config.tokenEndpoint);
    if (request.headers.dpop === undefined && this.#mcp() !== undefined) {
      // A Bearer token, only for the MCP server's url and an existing Session (§4.3).
      if (form.resource !== this.config.mcpUrl) throw new Refused(400, "invalid_dpop_proof");
      if ((grant !== JWT_BEARER_GRANT && grant !== REFRESH_TOKEN_GRANT) || !form.session_id) {
        throw new Refused(400, "invalid_request");
      }
      if (grant === JWT_BEARER_GRANT) return this.#sessionGrant(form, clientId, "", "Bearer");
      return this.#refreshGrant(form, clientId, "", "Bearer");
    }
    const thumbprint = await this.#dpop(request);
    if (grant === JWT_BEARER_GRANT) return this.#sessionGrant(form, clientId, thumbprint, "DPoP");
    if (grant === REFRESH_TOKEN_GRANT) {
      return this.#refreshGrant(form, clientId, thumbprint, "DPoP");
    }
    if (grant === "authorization_code" && this.config.direct) {
      return this.#codeGrant(form, clientId, thumbprint);
    }
    if (grant === DEVICE_CODE_GRANT && this.config.device) {
      return this.#deviceGrant(form, clientId, thumbprint);
    }
    throw new Refused(400, "unsupported_grant_type");
  }

  async #sessionGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
    tokenType: TokenType,
  ): Promise<CompanyResponse> {
    const resolver = firstContribution(this.reactor, ClientResolvers, "client");
    const [, keys] = await resolver.resolve(clientId, keyId(form.assertion ?? ""));
    const claims = await verifyAssertion(form.assertion ?? "", {
      keys,
      issuer: clientId,
      audience: this.config.tokenEndpoint,
      replayCache: this.#replay(),
      now: this.#now(),
      error: "invalid_grant",
    });
    const pairwise = String(claims.sub);
    const sessionId = form.session_id;
    let session: IssuedSession;
    if (sessionId === undefined) {
      session = {
        sessionId: this.#id("ses"),
        clientId,
        pairwiseUserId: pairwise,
        keyThumbprint: thumbprint,
        expiresAt: this.#later(this.config.sessionLifetimeSeconds).toISOString(),
        scopes: [],
      };
    } else {
      const known = await this.#sessionById(sessionId);
      if (known === undefined || known.clientId !== clientId || known.pairwiseUserId !== pairwise) {
        throw new Refused(400, "invalid_session");
      }
      // Renewal with the assertion gives a signed-out token; a signed-in Session is
      // renewed with its Account Token instead (§4.2, §4.8).
      const {
        accountId: _account,
        accountToken: _token,
        resource: _resource,
        tokenType: _type,
        ...signedOut
      } = known;
      session = {
        ...signedOut,
        keyThumbprint: thumbprint,
        expiresAt: this.#later(this.config.sessionLifetimeSeconds).toISOString(),
        scopes: [],
        ...(form.resource === undefined ? {} : { resource: form.resource }),
        ...(tokenType === "Bearer" ? { tokenType } : {}),
      };
      return this.#issue(session, undefined, [tokenType]);
    }
    return this.#issue(session);
  }

  async #refreshGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
    tokenType: TokenType,
  ): Promise<CompanyResponse> {
    const presented = digest(form.refresh_token ?? "");
    const entry = await this.store.get(RecordKinds.accountToken, presented);
    const grant = entry?.value as unknown as AccountGrant | undefined;
    if (
      entry === undefined ||
      grant === undefined ||
      grant.revoked ||
      this.#passed(grant.expiresAt) ||
      grant.clientId !== clientId
    ) {
      throw new Refused(400, "invalid_grant");
    }
    const session = await this.#sessionById(form.session_id ?? "");
    if (
      session === undefined ||
      session.clientId !== clientId ||
      session.pairwiseUserId !== grant.pairwiseUserId
    ) {
      throw new Refused(400, "invalid_session");
    }
    if (session.accountId !== undefined && session.accountId !== grant.accountId) {
      // A Session signed in to one account never switches to another (§4.4).
      throw new Refused(400, "account_mismatch");
    }
    const requested = words(form.scope);
    if (requested.length && requested.some((scope) => !grant.scopes.includes(scope))) {
      throw new Refused(400, "invalid_scope");
    }
    // Rotation: exactly one refresh claims the presented token, which stops working the
    // moment it is claimed; a concurrent or later reuse is `invalid_grant`.
    const claimed = await this.store.replace(
      RecordKinds.accountToken,
      presented,
      entry.version,
      json({ ...grant, revoked: true } satisfies AccountGrant),
      expiry(entry.expiresAt),
    );
    if (!claimed) throw new Refused(400, "invalid_grant");
    const rotated = this.#id("acct");
    await this.store.put(
      RecordKinds.accountToken,
      digest(rotated),
      json({ ...grant, revoked: false } satisfies AccountGrant),
      expiry(grant.expiresAt),
    );
    if (!(await this.#joinFamily(grant.family, digest(rotated), session.sessionId))) {
      // The sign-in was revoked meanwhile: its new token is too.
      await this.#revokeGrants([digest(rotated)]);
      throw new Refused(400, "invalid_grant");
    }
    const resource = form.resource;
    const signedIn: IssuedSession = {
      ...session,
      keyThumbprint: thumbprint,
      accountId: grant.accountId,
      scopes: requested.length ? requested : grant.scopes,
      accountToken: digest(rotated),
      expiresAt: this.#later(this.config.sessionLifetimeSeconds).toISOString(),
    };
    // The resource is what this refresh asked for, never one an earlier refresh named.
    const { resource: _earlier, tokenType: _type, ...unbound } = signedIn;
    const typed: IssuedSession = tokenType === "Bearer" ? { ...unbound, tokenType } : unbound;
    const response = await this.#issue(
      resource === undefined ? typed : { ...typed, resource },
      rotated,
      [tokenType],
    );
    const family = await this.#read<AccountFamily>(RecordKinds.accountFamily, grant.family);
    if (family === undefined || family.revoked) {
      // Revoked while this token was issued: the Session continues signed out (§4.9).
      await this.#signOutSession(session.sessionId, [digest(rotated)]);
      throw new Refused(400, "invalid_grant");
    }
    return response;
  }

  async #device(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const clientId = await this.#client(form, this.config.deviceEndpoint);
    const scopes = words(form.scope);
    if (!scopes.length || scopes.some((scope) => !this.config.scopes.includes(scope))) {
      throw new Refused(400, "invalid_scope");
    }
    const deviceCode = this.#id("dev");
    const lifetime = 600;
    const expiresAt = this.#later(lifetime);
    const kept = expiry(new Date(expiresAt.getTime() + KEPT_EXPIRED_MS));
    let userCode: string;
    for (;;) {
      const raw = this.#id("u").slice(2, 10).toUpperCase().replaceAll("-", "X").replaceAll("_", "Y");
      userCode = `${raw.slice(0, 4)}-${raw.slice(4)}`;
      const pointer: UserCode = { device: digest(deviceCode) };
      if (await this.store.create(RecordKinds.userCode, userCode, json(pointer), kept)) break;
    }
    const pending: PendingDevice = {
      clientId,
      scopes,
      userCode,
      expiresAt: expiresAt.toISOString(),
      interval: this.config.deviceInterval,
      granted: [],
      denied: false,
    };
    await this.store.put(RecordKinds.device, digest(deviceCode), json(pending), kept);
    return {
      status: 200,
      body: {
        device_code: deviceCode,
        user_code: userCode,
        ...(this.config.devicePage === undefined
          ? {
              verification_uri: `${this.config.base}/device`,
              verification_uri_complete: `${this.config.base}/device?user_code=${userCode}`,
            }
          : {
              verification_uri: this.config.devicePage,
              verification_uri_complete: `${this.config.devicePage}${
                new URL(this.config.devicePage).search ? "&" : "?"
              }${new URLSearchParams({ code: userCode })}`,
            }),
        expires_in: lifetime,
        interval: this.config.deviceInterval,
      },
      headers: { ...NO_STORE },
    };
  }

  /**
   * The user signed in on the company's page and approved: what they granted.
   *
   * `scopes` may be fewer than requested (partial consent); omitted, all.
   * Approving twice, or an unknown code, rejects.
   */
  async approveDevice(
    userCode: string,
    options: { readonly accountId: string; readonly scopes?: readonly string[] },
  ): Promise<readonly string[]> {
    const pointer = await this.#read<UserCode>(RecordKinds.userCode, userCode);
    const changed =
      pointer === undefined
        ? undefined
        : await this.#change<PendingDevice>(RecordKinds.device, pointer.device, (pending) => {
            if (pending.userCode !== userCode || pending.accountId !== undefined) {
              throw new Error("unknown or already approved user code");
            }
            const granted = (options.scopes?.length ? options.scopes : pending.scopes).filter(
              (s) => pending.scopes.includes(s),
            );
            return { ...pending, accountId: options.accountId, granted };
          });
    if (changed === undefined) throw new Error("unknown or already approved user code");
    return changed[1].granted;
  }

  async denyDevice(userCode: string): Promise<void> {
    const pointer = await this.#read<UserCode>(RecordKinds.userCode, userCode);
    const changed =
      pointer === undefined
        ? undefined
        : await this.#change<PendingDevice>(RecordKinds.device, pointer.device, (pending) => ({
            ...pending,
            denied: true,
          }));
    if (changed === undefined) throw new Error("unknown user code");
  }

  async #deviceGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const key = digest(form.device_code ?? "");
    let polled = false;
    for (let attempt = 0; attempt < CAS_ATTEMPTS && !polled; attempt += 1) {
      const entry = await this.store.get(RecordKinds.device, key);
      const pending = entry?.value as unknown as PendingDevice | undefined;
      const now = this.#now();
      if (entry === undefined || pending === undefined || pending.clientId !== clientId) {
        throw new Refused(400, "invalid_grant");
      }
      if (this.#passed(pending.expiresAt)) {
        await this.#forgetDevice(key, pending);
        throw new Refused(400, "expired_token");
      }
      if (pending.denied) {
        await this.#forgetDevice(key, pending);
        throw new Refused(400, "access_denied");
      }
      let next: PendingDevice;
      let refusal: string;
      if (
        pending.lastPoll !== undefined &&
        now.getTime() - new Date(pending.lastPoll).getTime() < pending.interval * 1000
      ) {
        next = { ...pending, interval: pending.interval + 5, lastPoll: now.toISOString() };
        refusal = "slow_down";
      } else if (pending.accountId === undefined) {
        next = { ...pending, lastPoll: now.toISOString() };
        refusal = "authorization_pending";
      } else {
        polled = true;
        break;
      }
      if (
        await this.store.replace(
          RecordKinds.device,
          key,
          entry.version,
          json(next),
          expiry(entry.expiresAt),
        )
      ) {
        throw new Refused(400, refusal);
      }
    }
    if (!polled) throw new Refused(503, "temporarily_unavailable");
    const session = await this.#sessionById(form.session_id ?? "");
    if (session === undefined || session.clientId !== clientId) {
      throw new Refused(400, "invalid_session");
    }
    // Consumed once: of concurrent polls, only the one that takes it signs in.
    const approved = (await this.store.take(RecordKinds.device, key)) as unknown as
      | PendingDevice
      | undefined;
    if (approved === undefined || approved.accountId === undefined) {
      throw new Refused(400, "invalid_grant");
    }
    await this.store.delete(RecordKinds.userCode, approved.userCode);
    return this.#signIn(session, approved.accountId, approved.granted, thumbprint);
  }

  async #forgetDevice(key: string, pending: PendingDevice): Promise<void> {
    await this.store.delete(RecordKinds.device, key);
    await this.store.delete(RecordKinds.userCode, pending.userCode);
  }

  async #revoke(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const clientId = await this.#client(form, this.config.revocationEndpoint);
    const grant = await this.#read<AccountGrant>(RecordKinds.accountToken, digest(form.token ?? ""));
    if (grant !== undefined && grant.clientId === clientId) {
      // The token and every one rotated from the same sign-in: each Session signed
      // in with any of them continues signed out (§4.9).
      await this.#signOut([grant.family]);
    }
    return { status: 200, body: {}, headers: { ...NO_STORE } };
  }

  /**
   * The user disconnects an agent in account settings: its tokens go, Sessions sign out.
   *
   * Resolves to how many Account Tokens were revoked (upstream guides, account settings).
   */
  async disconnect(clientId: string, accountId: string): Promise<number> {
    const agent = await this.#read<AccountAgent>(
      RecordKinds.accountAgent,
      composite(clientId, accountId),
    );
    return agent === undefined ? 0 : this.#signOut(agent.families);
  }

  /** Revoke whole sign-ins: their tokens stop working, their Sessions sign out. */
  async #signOut(families: readonly string[]): Promise<number> {
    let revoked = 0;
    for (const familyId of families) {
      const changed = await this.#change<AccountFamily>(
        RecordKinds.accountFamily,
        familyId,
        (family) => (family.revoked ? family : { ...family, revoked: true }),
      );
      if (changed === undefined) continue;
      const family = changed[1];
      revoked += await this.#revokeGrants(family.tokens);
      for (const sessionId of family.sessions) {
        await this.#signOutSession(sessionId, family.tokens);
      }
    }
    return revoked;
  }

  async #revokeGrants(tokens: readonly string[]): Promise<number> {
    let revoked = 0;
    for (const token of tokens) {
      const changed = await this.#change<AccountGrant>(RecordKinds.accountToken, token, (grant) =>
        grant.revoked ? grant : { ...grant, revoked: true },
      );
      if (changed !== undefined && !changed[0].revoked) revoked += 1;
    }
    return revoked;
  }

  /** Each token of the Session signed in with one of `accountTokens` continues signed out. */
  async #signOutSession(sessionId: string, accountTokens: readonly string[]): Promise<void> {
    await this.#change<StoredSession>(RecordKinds.session, sessionId, (stored) => {
      let changed = false;
      const tokens: Record<string, IssuedSession> = {};
      for (const [key, token] of Object.entries(stored.tokens)) {
        if (token.accountToken !== undefined && accountTokens.includes(token.accountToken)) {
          const { accountId: _account, accountToken: _token, ...rest } = token;
          tokens[key] = { ...rest, scopes: [] };
          changed = true;
        } else {
          tokens[key] = token;
        }
      }
      return changed ? { ...stored, tokens } : stored;
    });
  }

  /** Add a token and a Session to a sign-in; `false` once it is revoked. */
  async #joinFamily(familyId: string, token: string, sessionId: string): Promise<boolean> {
    const changed = await this.#change<AccountFamily>(
      RecordKinds.accountFamily,
      familyId,
      (family) =>
        family.revoked
          ? family
          : {
              ...family,
              tokens: withItem(family.tokens, token),
              sessions: withItem(family.sessions, sessionId),
            },
    );
    return changed !== undefined && !changed[1].revoked;
  }

  /** Sign the Session in: `session` is its DPoP record, `thumbprint` the proven key. */
  async #signIn(
    session: IssuedSession,
    accountId: string,
    scopes: readonly string[],
    thumbprint: string,
  ): Promise<CompanyResponse> {
    if (session.accountId !== undefined && session.accountId !== accountId) {
      throw new Refused(400, "account_mismatch");
    }
    const accountToken = this.#id("acct");
    const family = digest(accountToken);
    const expiresAt = this.#later(this.config.accountTokenLifetimeSeconds);
    const grant: AccountGrant = {
      family,
      accountId,
      clientId: session.clientId,
      pairwiseUserId: session.pairwiseUserId,
      scopes,
      expiresAt: expiresAt.toISOString(),
      revoked: false,
    };
    await this.store.put(RecordKinds.accountToken, family, json(grant), expiry(expiresAt));
    const signIn: AccountFamily = {
      clientId: session.clientId,
      accountId,
      tokens: [family],
      sessions: [session.sessionId],
      revoked: false,
    };
    await this.store.put(RecordKinds.accountFamily, family, json(signIn), expiry(expiresAt));
    await this.#rememberFamily(session.clientId, accountId, family);
    // The signed-in token is the Session's own: DPoP, bound to the key that proved
    // possession, for no single resource. It replaces only the DPoP token; a Bearer token
    // for the MCP server is renewed with the Account Token (§4.3, §4.8).
    const signedIn: IssuedSession = {
      sessionId: session.sessionId,
      clientId: session.clientId,
      pairwiseUserId: session.pairwiseUserId,
      keyThumbprint: thumbprint,
      expiresAt: session.expiresAt,
      accountId,
      scopes,
      accountToken: family,
    };
    return this.#issue(signedIn, accountToken, ["DPoP"]);
  }

  async #rememberFamily(clientId: string, accountId: string, family: string): Promise<void> {
    const key = composite(clientId, accountId);
    for (let attempt = 0; attempt < CAS_ATTEMPTS; attempt += 1) {
      const first: AccountAgent = { families: [family] };
      if (await this.store.create(RecordKinds.accountAgent, key, json(first))) return;
      const changed = await this.#change<AccountAgent>(RecordKinds.accountAgent, key, (agent) => ({
        families: withItem(agent.families, family),
      }));
      if (changed !== undefined) return;
    }
    throw new Refused(503, "temporarily_unavailable");
  }

  /** Issue a token for the Session; it replaces the Session's tokens of `replacing` types. */
  async #issue(
    session: IssuedSession,
    refreshToken?: string,
    replacing: readonly TokenType[] = EVERY_TOKEN_TYPE,
  ): Promise<CompanyResponse> {
    const accessToken = this.#id("sat");
    const key = digest(accessToken);
    await this.#recordToken(session, key, replacing);
    const pointer: SessionPointer = { sessionId: session.sessionId };
    await this.store.put(RecordKinds.sessionToken, key, json(pointer), expiry(session.expiresAt));
    const body: Record<string, unknown> = {
      access_token: accessToken,
      token_type: session.tokenType ?? "DPoP",
      expires_in: Math.trunc((new Date(session.expiresAt).getTime() - this.#now().getTime()) / 1000),
      scope: session.scopes.join(" "),
      session_id: session.sessionId,
      signed_in: session.accountId !== undefined,
    };
    if (refreshToken !== undefined) body.refresh_token = refreshToken;
    return { status: 200, body, headers: { ...NO_STORE } };
  }

  /** One write: the new token joins the Session, the ones it replaces leave it. */
  async #recordToken(
    session: IssuedSession,
    key: string,
    replacing: readonly TokenType[],
  ): Promise<void> {
    for (let attempt = 0; attempt < CAS_ATTEMPTS; attempt += 1) {
      const entry = await this.store.get(RecordKinds.session, session.sessionId);
      const tokens: Record<string, IssuedSession> = {};
      if (entry !== undefined) {
        const current = entry.value as unknown as StoredSession;
        for (const [held, token] of Object.entries(current.tokens)) {
          if (!replacing.includes(token.tokenType ?? "DPoP")) tokens[held] = token;
        }
      }
      tokens[key] = session;
      const stored: StoredSession = {
        sessionId: session.sessionId,
        clientId: session.clientId,
        pairwiseUserId: session.pairwiseUserId,
        tokens,
        latest: key,
      };
      // A Session is forgotten once no Account Token could renew it any more.
      const latest = Math.max(...Object.values(tokens).map((token) => Date.parse(token.expiresAt)));
      const kept = expiry(new Date(latest + this.config.accountTokenLifetimeSeconds * 1000));
      if (entry === undefined) {
        if (await this.store.create(RecordKinds.session, session.sessionId, json(stored), kept)) {
          return;
        }
        continue;
      }
      if (
        await this.store.replace(RecordKinds.session, session.sessionId, entry.version, json(stored), kept)
      ) {
        return;
      }
    }
    throw new Refused(503, "temporarily_unavailable");
  }

  /**
   * The Session by its ID: its latest DPoP token's record, never a Bearer one. A Bearer
   * token stands for the Session only at the MCP server it was issued for (§4.3): a grant
   * naming the Session builds on its DPoP record.
   */
  async #sessionById(sessionId: string): Promise<IssuedSession | undefined> {
    const stored = await this.#read<StoredSession>(RecordKinds.session, sessionId);
    if (stored === undefined) return undefined;
    const latest = stored.tokens[stored.latest];
    if (latest !== undefined && latest.tokenType === undefined) return latest;
    let dpop: IssuedSession | undefined;
    for (const token of Object.values(stored.tokens)) {
      if (token.tokenType !== undefined) continue;
      if (dpop === undefined || Date.parse(token.expiresAt) > Date.parse(dpop.expiresAt)) dpop = token;
    }
    return dpop;
  }

  /** The state of the Session token `token`, while the Session still holds it. */
  async #tokenSession(token: string): Promise<IssuedSession | undefined> {
    const key = digest(token);
    const pointer = await this.#read<SessionPointer>(RecordKinds.sessionToken, key);
    if (pointer === undefined) return undefined;
    const stored = await this.#read<StoredSession>(RecordKinds.session, pointer.sessionId);
    return stored?.tokens[key];
  }

  // Direct Sign-In (§4.5) -------------------------------------------------------------

  /** The company's own sign-in and consent page for a personal agent's request. */
  async #authorize(request: CompanyRequest): Promise<CompanyResponse> {
    const query = pairs(new URL(request.url).search);
    const clientId = query.client_id ?? "";
    const redirectUri = query.redirect_uri ?? "";
    if (!clientId || !(await this.#allowed(clientId))) {
      return page(400, "This sign-in request is not valid.");
    }
    const resolver = firstContribution(this.reactor, ClientResolvers, "client");
    let metadata: ClientMetadata;
    try {
      [metadata] = await resolver.resolve(clientId);
    } catch {
      return page(400, "This agent could not be verified.");
    }
    // An unknown client or redirect is never redirected to: that would be an open redirector.
    if (!metadata.redirect_uris.includes(redirectUri)) {
      return page(400, "This sign-in request is not valid.");
    }
    const state = query.state ?? "";
    const scopes = words(query.scope);
    if (query.response_type !== "code") {
      return this.#redirect(redirectUri, { error: "unsupported_response_type", state });
    }
    if (query.code_challenge_method !== "S256" || !query.code_challenge) {
      return this.#redirect(redirectUri, { error: "invalid_request", state });
    }
    if (!scopes.length || scopes.some((scope) => !this.config.scopes.includes(scope))) {
      return this.#redirect(redirectUri, { error: "invalid_scope", state });
    }
    const requestId = this.#id("authz");
    const expiresAt = this.#later(10 * 60);
    // The company's own page binds the request to this browser: its consent cookie
    // (kept if it has one) and a form token only that cookie yields.
    const hosted = this.config.consentPage;
    const browser = cookie(request, CONSENT_COOKIE) ?? this.#id("consent");
    const pending: PendingAuthorization = {
      clientId,
      redirectUri,
      scopes,
      state,
      codeChallenge: query.code_challenge,
      expiresAt: expiresAt.toISOString(),
      clientName: metadata.client_name,
      ...(hosted === undefined ? { browserBinding: digest(browser) } : {}),
    };
    await this.store.put(RecordKinds.authorization, requestId, json(pending), expiry(expiresAt));
    if (hosted !== undefined) {
      // A hosted consent page reads the request back (`authorizationRequest`).
      return {
        status: 303,
        headers: {
          Location: hosted.replaceAll("{request_id}", encodeURIComponent(requestId)),
          ...NO_STORE,
        },
      };
    }
    const agent = escapeHtml(metadata.client_name);
    const agentDomain = escapeHtml(new URL(clientId).hostname);
    const described = scopes
      .map((scope) => `<li>${escapeHtml(this.config.customScopes[scope] ?? scope)}</li>`)
      .join("");
    return page(
      200,
      `<h1>${escapeHtml(this.config.name)}</h1>` +
        `<p><strong>${agent}</strong> (${agentDomain}) asks to:</p><ul>${described}</ul>` +
        `<form method="post" action="${this.config.authorizationEndpoint}" data-request-id="${requestId}">` +
        `<input type="hidden" name="request_id" value="${requestId}">` +
        `<input type="hidden" name="csrf" value="${bound(browser, `consent:${requestId}`)}">` +
        '<button name="decision" value="allow">Allow</button>' +
        '<button name="decision" value="deny">Deny</button></form>',
      `${CONSENT_COOKIE}=${browser}; Path=/; Secure; HttpOnly; SameSite=Strict`,
    );
  }

  /**
   * The decision the company's own consent form posted, once it is shown to be the user's.
   *
   * The company's web layer, which knows who is signed in, calls this on the form's POST
   * and then `approveAuthorization` or `denyAuthorization`. Rejects unless the POST comes
   * from this site (`Sec-Fetch-Site`, `Origin`), carries the consent cookie the request
   * was bound to when its page was shown, and the form token only that cookie yields:
   * another site's page cannot make the browser decide, and a form replayed from another
   * browser does not match (Guides, consent pages).
   */
  async consentDecision(request: CompanyRequest): Promise<ConsentDecision> {
    const refused = new Error("this decision did not come from the page that asked");
    if (request.method.toUpperCase() !== "POST" || !fromThisSite(request, this.config.base)) throw refused;
    const form = pairs(text(request.body));
    const requestId = form.request_id ?? "";
    const browser = cookie(request, CONSENT_COOKIE);
    const pending = requestId
      ? await this.#read<PendingAuthorization>(RecordKinds.authorization, requestId)
      : undefined;
    if (
      browser === undefined ||
      pending?.browserBinding === undefined ||
      !sameText(digest(browser), pending.browserBinding) ||
      !sameText(form.csrf ?? "", bound(browser, `consent:${requestId}`)) ||
      (form.decision !== "allow" && form.decision !== "deny")
    ) {
      throw refused;
    }
    return { requestId, allow: form.decision === "allow" };
  }

  /**
   * A pending Direct Sign-In request, for a consent page to show; not consumed.
   *
   * Who asks (`client_name`, the `client_id` domain), for what (each scope with its
   * `customScopes` words), until when; never `state`, PKCE, or the redirect. Rejects
   * for an unknown, used, or expired request.
   */
  async authorizationRequest(requestId: string): Promise<{
    readonly request_id: string;
    readonly client_name: string;
    readonly client_domain: string;
    readonly scopes: readonly { readonly scope: string; readonly description: string }[];
    readonly expires_at: string;
  }> {
    const pending = await this.#read<PendingAuthorization>(RecordKinds.authorization, requestId);
    if (pending === undefined || this.#passed(pending.expiresAt)) {
      throw new Error("unknown, used, or expired sign-in request");
    }
    return {
      request_id: requestId,
      client_name: pending.clientName ?? "",
      client_domain: new URL(pending.clientId).hostname,
      scopes: pending.scopes.map((scope) => ({ scope, description: this.config.customScopes[scope] ?? scope })),
      expires_at: isoZ(new Date(pending.expiresAt)),
    };
  }

  /**
   * The user, signed in on the company's page, allowed: where their browser goes next.
   *
   * `scopes` may be fewer than requested (partial consent); omitted, all.
   */
  async approveAuthorization(
    requestId: string,
    options: { readonly accountId: string; readonly scopes?: readonly string[] },
  ): Promise<string> {
    const pending = await this.#pendingAuthorization(requestId);
    const granted = (options.scopes?.length ? options.scopes : pending.scopes).filter((s) =>
      pending.scopes.includes(s),
    );
    const code = this.#id("code");
    const expiresAt = this.#later(60);
    const issued: IssuedCode = {
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      accountId: options.accountId,
      scopes: granted,
      expiresAt: expiresAt.toISOString(),
    };
    await this.store.put(RecordKinds.code, digest(code), json(issued), expiry(expiresAt));
    return this.#redirectUrl(pending.redirectUri, { code, state: pending.state });
  }

  /** The user refused: the agent learns only `access_denied`. */
  async denyAuthorization(requestId: string): Promise<string> {
    const pending = await this.#pendingAuthorization(requestId);
    return this.#redirectUrl(pending.redirectUri, {
      error: "access_denied",
      state: pending.state,
    });
  }

  /** The request, taken: of two decisions on it, only the first counts. */
  async #pendingAuthorization(requestId: string): Promise<PendingAuthorization> {
    const pending = (await this.store.take(RecordKinds.authorization, requestId)) as unknown as
      | PendingAuthorization
      | undefined;
    if (pending === undefined || this.#passed(pending.expiresAt)) {
      throw new Error("unknown, used, or expired sign-in request");
    }
    return pending;
  }

  async #codeGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const issued = (await this.store.take(RecordKinds.code, digest(form.code ?? ""))) as unknown as
      | IssuedCode
      | undefined;
    if (
      issued === undefined ||
      this.#passed(issued.expiresAt) ||
      issued.clientId !== clientId ||
      issued.redirectUri !== form.redirect_uri
    ) {
      throw new Refused(400, "invalid_grant");
    }
    const challenge = createHash("sha256")
      .update(form.code_verifier ?? "")
      .digest("base64url");
    const expected = Buffer.from(issued.codeChallenge);
    const actual = Buffer.from(challenge);
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      throw new Refused(400, "invalid_grant");
    }
    const session = await this.#sessionById(form.session_id ?? "");
    if (session === undefined || session.clientId !== clientId) {
      throw new Refused(400, "invalid_session");
    }
    return this.#signIn(session, issued.accountId, issued.scopes, thumbprint);
  }

  #redirectUrl(redirectUri: string, values: Readonly<Record<string, string>>): string {
    const url = new URL(redirectUri);
    url.hash = "";
    for (const [name, value] of Object.entries(values)) {
      if (value) url.searchParams.append(name, value);
    }
    url.searchParams.append("iss", this.config.base);
    return url.toString();
  }

  #redirect(redirectUri: string, values: Readonly<Record<string, string>>): CompanyResponse {
    return {
      status: 303,
      headers: { Location: this.#redirectUrl(redirectUri, values), ...NO_STORE },
    };
  }

  // OpenAPI API (§6, Operations §4.1) -----------------------------------------------------

  #api(): CompanyApi | undefined {
    return optionalContribution(this.reactor, CompanyApis, "API");
  }

  async #apiCall(
    request: CompanyRequest,
    api: CompanyApi,
    method: string,
    path: string,
  ): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const source = text(request.body);
    const body = source ? parseJsonStrict(source) : undefined;
    const result = await api.handle({
      method,
      path: path.slice("/api".length),
      query: pairs(new URL(request.url).search),
      body,
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      scopes: session.scopes,
      clientId: session.clientId,
    });
    if (result.operation === undefined) {
      return { status: result.status ?? 200, body: result.body, headers: {} };
    }
    if (session.accountId === undefined) throw new Refused(403, "sign_in_required");
    if (!(await this.#supportsOperations(session.clientId))) {
      throw new Refused(403, "extension_required", { extension: "operations" });
    }
    const operation = await this.#propose(session, { operation: result.operation });
    return { status: 202, body: { operation }, headers: {} };
  }

  // MCP (§4.3, §6, Operations §4.2) -------------------------------------------------------

  #mcp(): CompanyMcp | undefined {
    return optionalContribution(this.reactor, CompanyMcps, "MCP server");
  }

  #bearerRefusal(status: number, error: string, scope?: string): CompanyResponse {
    let challenge = `Bearer error="${error}", resource_metadata="${this.config.mcpResourceMetadata}"`;
    if (scope !== undefined) challenge += `, scope="${scope}"`;
    return {
      status,
      body: scope === undefined ? { error } : { error, scope },
      headers: { "WWW-Authenticate": challenge, ...NO_STORE },
    };
  }

  /** The Session of a Bearer token issued for this MCP server, else `undefined`. */
  async #bearerCaller(request: CompanyRequest): Promise<IssuedSession | undefined> {
    const authorization = request.headers.authorization ?? "";
    const space = authorization.indexOf(" ");
    const scheme = space < 0 ? authorization : authorization.slice(0, space);
    const token = space < 0 ? "" : authorization.slice(space + 1);
    if (scheme !== "Bearer" || !token) return undefined;
    const session = await this.#tokenSession(token);
    if (
      session === undefined ||
      this.#passed(session.expiresAt) ||
      session.tokenType !== "Bearer" ||
      session.resource !== this.config.mcpUrl ||
      !(await this.#allowed(session.clientId))
    ) {
      return undefined;
    }
    return session;
  }

  async #mcpRoute(request: CompanyRequest, mcp: CompanyMcp): Promise<CompanyResponse> {
    const session = await this.#bearerCaller(request);
    // A missing, expired, DPoP, or other-resource token: none is accepted here.
    if (session === undefined) return this.#bearerRefusal(401, "invalid_token");
    if (request.method.toUpperCase() !== "POST") {
      return { status: 405, body: { error: "method_not_allowed" }, headers: { Allow: "POST" } };
    }
    let message: unknown;
    try {
      message = parseJsonStrict(text(request.body));
    } catch {
      return rpcError(null, -32700, "Parse error");
    }
    if (!isObject(message) || message.jsonrpc !== "2.0") {
      return rpcError(null, -32600, "Invalid Request");
    }
    const requestId = message.id;
    if (requestId === undefined || requestId === null) {
      return { status: 202, headers: {} }; // a notification, such as notifications/initialized
    }
    const params = isObject(message.params) ? message.params : {};
    let result: unknown;
    if (message.method === "initialize") {
      result = {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: this.config.name, version: "1" },
      };
    } else if (message.method === "ping") {
      result = {};
    } else if (message.method === "tools/list") {
      result = { tools: mcp.tools() };
    } else if (message.method === "tools/call") {
      const outcome = await this.#mcpTool(session, mcp, params);
      if ("refused" in outcome) return outcome.refused;
      result = outcome.result;
    } else {
      return rpcError(requestId, -32601, "Method not found");
    }
    return { status: 200, body: { jsonrpc: "2.0", id: requestId, result }, headers: {} };
  }

  async #mcpTool(
    session: IssuedSession,
    mcp: CompanyMcp,
    params: Readonly<Record<string, unknown>>,
  ): Promise<{ readonly result: Record<string, unknown> } | { readonly refused: CompanyResponse }> {
    const name = params.name;
    const args = params.arguments ?? {};
    if (typeof name !== "string" || !isObject(args)) {
      return { refused: rpcError(null, -32602, "Invalid params") };
    }
    const answer = await mcp.call(name, args, {
      method: "TOOL",
      path: name,
      query: {},
      body: args,
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      scopes: session.scopes,
      clientId: session.clientId,
    });
    if (answer.refusal !== undefined) {
      const [status, error, scope] = answer.refusal;
      return { refused: this.#bearerRefusal(status, error, scope) };
    }
    if (answer.operation !== undefined) {
      if (session.accountId === undefined) {
        return { refused: this.#bearerRefusal(403, "sign_in_required") };
      }
      if (!(await this.#supportsOperations(session.clientId))) {
        return { refused: jsonError(403, "extension_required", { extension: "operations" }) };
      }
      const operation = await this.#propose(session, { operation: answer.operation });
      return {
        result: {
          content: [
            { type: "text", text: `Proposed: ${operation.summary} Not done until confirmed.` },
          ],
          structuredContent: { operation },
        },
      };
    }
    const result: Record<string, unknown> = {
      content: [{ type: "text", text: answer.text ?? JSON.stringify(answer.structured ?? {}) }],
    };
    if (answer.structured !== undefined) result.structuredContent = answer.structured;
    if (answer.isError) result.isError = true;
    return { result };
  }

  // Resource requests ---------------------------------------------------------------

  async #caller(request: CompanyRequest): Promise<[string, IssuedSession]> {
    const authorization = request.headers.authorization ?? "";
    const space = authorization.indexOf(" ");
    const scheme = space < 0 ? authorization : authorization.slice(0, space);
    const token = space < 0 ? "" : authorization.slice(space + 1);
    if (scheme !== "DPoP" || !token) throw new Refused(401, "invalid_token");
    const key = digest(token);
    const session = await this.#tokenSession(token);
    if (session === undefined || this.#passed(session.expiresAt) || session.tokenType === "Bearer") {
      // A Bearer token works only at the MCP server it was issued for (§4.3).
      throw new Refused(401, "invalid_token");
    }
    if (!(await this.#allowed(session.clientId))) throw new Refused(401, "invalid_token");
    const thumbprint = await this.#dpop(request, token);
    if (thumbprint !== session.keyThumbprint) throw new Refused(401, "invalid_dpop_proof");
    return [key, session];
  }

  async #mediated(request: CompanyRequest): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const source = text(request.body);
    const body = source ? parseJsonStrict(source) : {};
    const credentials = isObject(body) ? body.credentials : undefined;
    if (!isObject(credentials)) throw new Refused(400, "invalid_request");
    const scope = isObject(body) ? body.scope : undefined;
    const granted = typeof scope === "string" ? words(scope) : [];
    if (!granted.length || granted.some((item) => !this.config.scopes.includes(item))) {
      // Missing, unknown, or unavailable scopes are refused, never narrowed (§4.4).
      throw new Refused(400, "invalid_scope");
    }
    const accounts = firstContribution(this.reactor, CompanyAccounts, "accounts");
    const secrets: Record<string, SecretValue> = {};
    for (const [name, value] of Object.entries(credentials)) {
      // An empty value is no credential: the directory sees it missing, and refuses.
      if (value !== undefined && value !== null && String(value)) {
        secrets[name] = new SecretValue(String(value));
      }
      delete credentials[name];
    }
    const authenticated = await accounts.authenticate(secrets);
    for (const name of Object.keys(secrets)) delete secrets[name];
    if (authenticated === undefined) {
      return { status: 200, body: { status: "failed" }, headers: { ...NO_STORE } };
    }
    if (authenticated.codeReference === undefined) {
      return this.#signedInBody(session, authenticated.accountId, granted);
    }
    const signInId = this.#id("si");
    const expiresAt = this.#later(5 * 60);
    const pending: PendingMediated = {
      sessionId: session.sessionId,
      accountId: authenticated.accountId,
      scopes: granted,
      codeReference: authenticated.codeReference,
      expiresAt: expiresAt.toISOString(),
      attempts: 0,
    };
    await this.store.put(
      RecordKinds.mediated,
      signInId,
      json(pending),
      expiry(new Date(expiresAt.getTime() + KEPT_EXPIRED_MS)),
    );
    return {
      status: 200,
      body: {
        status: "code_required",
        sign_in_id: signInId,
        code: { sent_to: authenticated.sentTo ?? "your device" },
        expires_at: isoZ(expiresAt),
      },
      headers: { ...NO_STORE },
    };
  }

  async #mediatedCode(request: CompanyRequest, signInId: string): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const pending = await this.#read<PendingMediated>(RecordKinds.mediated, signInId);
    if (pending === undefined || pending.sessionId !== session.sessionId) {
      // Only the Session that started it can finish it; nothing else is said.
      throw new Refused(404, "not_found");
    }
    if (this.#passed(pending.expiresAt)) {
      await this.store.delete(RecordKinds.mediated, signInId);
      return { status: 200, body: { status: "expired" }, headers: { ...NO_STORE } };
    }
    const source = text(request.body);
    const body = source ? parseJsonStrict(source) : {};
    const code = isObject(body) ? body.code : undefined;
    const accounts = firstContribution(this.reactor, CompanyAccounts, "accounts");
    const failed = { status: 200, body: { status: "failed" }, headers: { ...NO_STORE } };
    if (
      typeof code !== "string" ||
      !code ||
      !(await accounts.checkCode(pending.codeReference, new SecretValue(code)))
    ) {
      // Every wrong code counts, however many replicas check them at once.
      const counted = await this.#change<PendingMediated>(
        RecordKinds.mediated,
        signInId,
        (current) => ({ ...current, attempts: current.attempts + 1 }),
      );
      if (counted === undefined || counted[1].attempts >= this.config.maxCodeAttempts) {
        await this.store.delete(RecordKinds.mediated, signInId);
        return failed;
      }
      return {
        status: 200,
        body: {
          status: "code_required",
          sign_in_id: signInId,
          code: {},
          expires_at: isoZ(new Date(pending.expiresAt)),
        },
        headers: { ...NO_STORE },
      };
    }
    // One use: of two right codes sent at once, only the one that takes it signs in.
    const completed = (await this.store.take(RecordKinds.mediated, signInId)) as unknown as
      | PendingMediated
      | undefined;
    if (completed === undefined) return failed;
    return this.#signedInBody(session, completed.accountId, completed.scopes);
  }

  async #signedInBody(
    session: IssuedSession,
    accountId: string,
    scopes: readonly string[],
  ): Promise<CompanyResponse> {
    const response = await this.#signIn(session, accountId, scopes, session.keyThumbprint);
    return {
      ...response,
      body: { status: "complete", ...(response.body as Record<string, unknown>) },
    };
  }

  // Conversations -------------------------------------------------------------------

  async #conversation(conversationId: string): Promise<StoredConversation> {
    const conversation = await this.#read<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
    );
    if (conversation === undefined) throw new Refused(404, "conversation_not_found");
    return conversation;
  }

  async #owned(conversationId: string, session: IssuedSession): Promise<StoredConversation> {
    const conversation = await this.#read<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
    );
    if (
      conversation === undefined ||
      !sameOwner(conversation.owner, [session.clientId, session.pairwiseUserId])
    ) {
      throw new Refused(404, "conversation_not_found");
    }
    if (conversation.accountId !== undefined && session.accountId !== conversation.accountId) {
      // Once it used the account, it belongs to that account (§7.2, §7.11).
      if (session.accountId === undefined) throw new Refused(403, "sign_in_required");
      throw new Refused(404, "conversation_not_found");
    }
    return conversation;
  }

  #event(payload: Readonly<Record<string, unknown>>): StoredEvent {
    const id = this.#id("evt");
    return { id, payload: { id, created_at: isoZ(this.#now()), ...payload } };
  }

  #state(status: string, responder: string): StoredEvent {
    return this.#event({ type: "state", status, responder });
  }

  /** A message or handoff goes only to an open conversation with no Direct one open. */
  #open(conversation: StoredConversation): void {
    if (conversation.status === "closed") throw new Refused(409, "conversation_closed");
    if (conversation.directChild !== undefined) {
      throw new Refused(409, "direct_conversation_open", {
        conversation_id: conversation.directChild,
      });
    }
  }

  async #startConversation(request: CompanyRequest): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const body = jsonObject(request.body);
    const message = parseMessage(body.message);
    const owner = [session.clientId, session.pairwiseUserId] as const;
    const replay = await this.#replayed(owner, message);
    if (replay !== undefined) {
      // A retried start answers only a caller that may read the conversation now.
      return this.#answer(request, await this.#owned(replay, session), 201);
    }
    const parentId = body.parent_conversation_id;
    let parent: StoredConversation | undefined;
    if (parentId !== undefined && parentId !== null) {
      parent = await this.#owned(String(parentId), session);
      if (parent.status === "closed") throw new Refused(409, "conversation_closed");
      if (parent.parentId !== undefined) throw new Refused(404, "conversation_not_found");
      this.#open(parent);
    }
    const conversationId = this.#id("cnv");
    const conversation: StoredConversation = {
      conversationId,
      owner,
      status: "idle",
      responder: "agent",
      ...(parent === undefined ? {} : { parentId: parent.conversationId }),
      events: [],
      forgotten: [],
    };
    const claimed = await this.#claim(owner, message, conversationId);
    if (claimed !== undefined) {
      return this.#answer(request, await this.#owned(claimed, session), 201);
    }
    await this.store.put(RecordKinds.conversation, conversationId, json(conversation));
    if (parent !== undefined) {
      await this.#openDirect(parent.conversationId, conversationId, owner, message);
    }
    return this.#answer(request, await this.#receive(conversationId, session, message), 201);
  }

  /** One write marks the parent's Direct Conversation; if it cannot, none was started. */
  async #openDirect(
    parentId: string,
    conversationId: string,
    owner: readonly [string, string],
    message: Message,
  ): Promise<void> {
    const opened = this.#event({ type: "direct_opened", conversation_id: conversationId });
    try {
      const changed = await this.#change<StoredConversation>(
        RecordKinds.conversation,
        parentId,
        (current) => {
          this.#open(current);
          return { ...current, directChild: conversationId, events: [...current.events, opened] };
        },
      );
      if (changed === undefined) throw new Refused(404, "conversation_not_found");
    } catch (error) {
      await this.store.delete(RecordKinds.conversation, conversationId);
      await this.store.delete(RecordKinds.messageId, this.#messageKey(owner, message.id));
      throw error;
    }
  }

  async #conversationRoute(
    request: CompanyRequest,
    method: string,
    path: string,
  ): Promise<CompanyResponse> {
    const parts = path.split("/");
    const conversationId = parts[3] ?? "";
    const action = parts[4] ?? "";
    const [, session] = await this.#caller(request);
    const conversation = await this.#owned(conversationId, session);
    if (method === "GET" && action === "events") {
      if ((request.headers.accept ?? "").includes("text/event-stream")) {
        return this.#stream(conversation, request.headers["last-event-id"]);
      }
      return this.#pageResponse(request, conversation, 200);
    }
    if (method !== "POST") throw new Refused(405, "method_not_allowed");
    if (action === "close") {
      await this.#close(conversationId);
      return this.#receipt(await this.#conversation(conversationId), 200);
    }
    this.#open(conversation);
    if (action === "handoff") {
      const changed = await this.#change<StoredConversation>(
        RecordKinds.conversation,
        conversationId,
        (current) => {
          this.#open(current);
          const responder = this.config.humansAvailable ? "human" : current.responder;
          return {
            ...current,
            status: "idle",
            responder,
            events: [
              ...current.events,
              this.#state("queued", current.responder),
              this.#state("idle", responder),
            ],
          };
        },
      );
      if (changed === undefined) throw new Refused(404, "conversation_not_found");
      return this.#receipt(changed[1], 202);
    }
    if (action === "messages") {
      const message = parseMessage(jsonObject(request.body).message);
      const owner = [session.clientId, session.pairwiseUserId] as const;
      const replay = await this.#replayed(owner, message);
      if (replay === undefined && (await this.#claim(owner, message, conversationId)) === undefined) {
        await this.#receive(conversationId, session, message);
      }
      return this.#answer(request, await this.#conversation(conversationId), 202);
    }
    throw new Refused(404, "not_found");
  }

  #messageKey(owner: readonly [string, string], messageId: string): string {
    return composite(owner[0], owner[1], messageId);
  }

  /** A retried message returns its conversation; a reused ID with new content conflicts. */
  async #replayed(owner: readonly [string, string], message: Message): Promise<string | undefined> {
    const known = await this.#read<MessageReceipt>(
      RecordKinds.messageId,
      this.#messageKey(owner, message.id),
    );
    if (known === undefined) return undefined;
    if (known.digest !== digest(JSON.stringify(plain(message)))) {
      throw new Refused(409, "message_id_conflict");
    }
    return known.conversationId;
  }

  /** Record the message ID, once: `undefined` when this call did, else the earlier conversation. */
  async #claim(
    owner: readonly [string, string],
    message: Message,
    conversationId: string,
  ): Promise<string | undefined> {
    const receipt: MessageReceipt = {
      conversationId,
      digest: digest(JSON.stringify(plain(message))),
    };
    for (let attempt = 0; attempt < CAS_ATTEMPTS; attempt += 1) {
      const key = this.#messageKey(owner, message.id);
      if (await this.store.create(RecordKinds.messageId, key, json(receipt))) return undefined;
      const replay = await this.#replayed(owner, message);
      if (replay !== undefined) return replay;
    }
    throw new Refused(503, "temporarily_unavailable");
  }

  async #receive(
    conversationId: string,
    session: IssuedSession,
    message: Message,
  ): Promise<StoredConversation> {
    const incoming = plain(message);
    const received = this.#event({ type: "message", message: { ...incoming, role: "user" } });
    let changed: readonly [StoredConversation, StoredConversation] | undefined;
    try {
      changed = await this.#change<StoredConversation>(
        RecordKinds.conversation,
        conversationId,
        (current) => {
          this.#open(current);
          const accountId = session.accountId ?? current.accountId;
          return {
            ...current,
            ...(accountId === undefined ? {} : { accountId }),
            events: [...current.events, received],
          };
        },
      );
      if (changed === undefined) throw new Refused(404, "conversation_not_found");
    } catch (error) {
      // Not received: the same message may be sent again.
      const owner = [session.clientId, session.pairwiseUserId] as const;
      await this.store.delete(RecordKinds.messageId, this.#messageKey(owner, message.id));
      throw error;
    }
    if (changed === undefined) throw new Refused(404, "conversation_not_found");
    const conversation = changed[1];
    if (conversation.responder === "human") return conversation;
    const agent = firstContribution(this.reactor, CompanyAgents, "company agent");
    const replies = await agent.respond({
      conversationId,
      ...(message.text === undefined ? {} : { text: message.text }),
      ...(message.data === undefined ? {} : { data: message.data }),
      sender: message.sender,
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      scopes: session.scopes,
      clientId: session.clientId,
      isDirect: conversation.parentId !== undefined,
    });
    const events: StoredEvent[] = [];
    for (const reply of replies) {
      const event = await this.#reply(session, reply);
      if (event !== undefined) events.push(event);
    }
    const answered = await this.#change<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
      (current) => ({
        ...current,
        status: current.status === "closed" ? "closed" : "idle",
        events: [...current.events, ...events],
      }),
    );
    return answered === undefined ? conversation : answered[1];
  }

  async #reply(session: IssuedSession, reply: Reply): Promise<StoredEvent | undefined> {
    if (reply.authorization !== undefined) {
      const [error, scope] = reply.authorization;
      return this.#event({ type: "authorization", error, scope });
    }
    if (reply.userRequested !== undefined) {
      return this.#event({ type: "user_requested", reason: reply.userRequested });
    }
    const message: Record<string, unknown> = {
      id: this.#id("msg"),
      sender: "agent",
      role: "company",
    };
    if (reply.text !== undefined) message.text = reply.text;
    if (reply.data !== undefined) message.data = reply.data;
    if (reply.operation !== undefined && session.accountId !== undefined) {
      if (await this.#supportsOperations(session.clientId)) {
        message.operation = await this.#propose(session, reply);
      }
    }
    return Object.keys(message).length > 3 ? this.#event({ type: "message", message }) : undefined;
  }

  async #close(conversationId: string): Promise<void> {
    const conversation = await this.#read<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
    );
    if (conversation === undefined || conversation.status === "closed") return;
    if (conversation.directChild !== undefined) await this.#close(conversation.directChild);
    const changed = await this.#change<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
      (current) =>
        current.status === "closed"
          ? current
          : {
              ...current,
              status: "closed",
              events: [...current.events, this.#state("closed", current.responder)],
            },
    );
    if (changed === undefined || changed[0].status === "closed") return;
    if (conversation.parentId !== undefined) {
      const closed = this.#event({ type: "direct_closed", conversation_id: conversationId });
      await this.#change<StoredConversation>(
        RecordKinds.conversation,
        conversation.parentId,
        (parent) => {
          const { directChild: _child, ...rest } = parent;
          return { ...rest, events: [...parent.events, closed] };
        },
      );
    }
  }

  #receipt(conversation: StoredConversation, status: number): CompanyResponse {
    return {
      status,
      body: {
        conversation_id: conversation.conversationId,
        status: conversation.status,
        responder: conversation.responder,
      },
      headers: {},
    };
  }

  #answer(
    request: CompanyRequest,
    conversation: StoredConversation,
    status: number,
  ): CompanyResponse {
    const query = pairs(new URL(request.url).search);
    if ("wait" in query || "cursor" in query) {
      return this.#pageResponse(request, conversation, status);
    }
    return this.#receipt(conversation, status);
  }

  #pageResponse(
    request: CompanyRequest,
    conversation: StoredConversation,
    status: number,
  ): CompanyResponse {
    const cursor = pairs(new URL(request.url).search).cursor;
    const events = this.#after(conversation, cursor);
    const pageEvents = events.slice(0, PAGE);
    const more = events.length > PAGE;
    const last = pageEvents.at(-1)?.id ?? cursor ?? startCursor(conversation);
    return {
      status,
      body: {
        conversation_id: conversation.conversationId,
        events: pageEvents.map((event) => event.payload),
        cursor: last,
        has_more: more,
        status: conversation.status,
        responder: conversation.responder,
      },
      headers: {},
    };
  }

  /** Retention: drop all but the last `keep` events; their cursors expire (§7.5). */
  async forgetEvents(conversationId: string, options: { readonly keep?: number } = {}): Promise<void> {
    const changed = await this.#change<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
      (conversation) => {
        const cut = Math.max(conversation.events.length - (options.keep ?? 0), 0);
        return {
          ...conversation,
          events: conversation.events.slice(cut),
          forgotten: [
            ...conversation.forgotten,
            ...conversation.events.slice(0, cut).map((event) => event.id),
          ],
        };
      },
    );
    if (changed === undefined) throw new Error("unknown conversation");
  }

  #after(conversation: StoredConversation, cursor: string | undefined): StoredEvent[] {
    if (cursor === undefined || cursor === startCursor(conversation)) {
      return [...conversation.events];
    }
    if (conversation.forgotten.includes(cursor)) throw new Refused(410, "cursor_expired");
    const index = conversation.events.findIndex((event) => event.id === cursor);
    if (index < 0) throw new Refused(400, "invalid_cursor");
    return conversation.events.slice(index + 1);
  }

  #stream(conversation: StoredConversation, lastEventId: string | undefined): CompanyResponse {
    const events = this.#after(conversation, lastEventId || undefined);
    const encoder = new TextEncoder();
    async function* frames(): AsyncGenerator<Uint8Array> {
      yield encoder.encode(": poppy\n\n");
      for (const event of events) {
        const message = event.payload.message;
        if (isObject(message) && message.role === "company" && message.text) {
          const full = String(message.text);
          const half = full.slice(0, Math.max(1, Math.floor(full.length / 2)));
          const delta = { message_id: message.id, text: half };
          yield encoder.encode(`event: text-delta\ndata: ${JSON.stringify(delta)}\n\n`);
        }
        yield encoder.encode(`id: ${event.id}\ndata: ${JSON.stringify(event.payload)}\n\n`);
      }
    }
    return {
      status: 200,
      headers: { "Content-Type": "text/event-stream", ...NO_STORE },
      stream: frames(),
    };
  }

  // Operations ----------------------------------------------------------------------

  /** A proposal as it goes on the wire: the same members, in the same order, as Python. */
  async #propose(session: IssuedSession, reply: Reply): Promise<Operation> {
    const proposal = reply.operation!;
    const owner = [session.clientId, session.pairwiseUserId] as const;
    const accountId = session.accountId!;
    // The same action through another channel is the same operation (Operations §4).
    const key = composite(
      owner[0],
      owner[1],
      accountId,
      proposal.action,
      proposal.summary,
      canonical(proposal.terms),
    );
    const known = await this.#read<OperationProposal>(RecordKinds.proposal, key);
    if (known !== undefined) {
      const current = await this.#currentOperation(known.operationId);
      if (
        current !== undefined &&
        sameOwner(current.owner, owner) &&
        current.accountId === accountId &&
        current.action === proposal.action &&
        current.operation.state === "proposed" &&
        current.operation.summary === proposal.summary &&
        sameJson(current.operation.terms, proposal.terms)
      ) {
        return current.operation;
      }
    }
    const operationId = this.#id("op");
    const expiresAt = isoZ(this.#later(this.config.operationLifetimeSeconds));
    const operation = {
      operation_id: operationId,
      revision: 1,
      state: "proposed",
      summary: proposal.summary,
      terms: { ...proposal.terms },
      expires_at: expiresAt,
      user_approval_required: proposal.userApprovalRequired ?? false,
      url: `${this.config.base}/operations/${operationId}`,
      confirmation: null,
      result: null,
    } as unknown as Operation;
    const stored: StoredOperation = {
      operation,
      action: proposal.action,
      owner,
      accountId,
      scopes: this.#operationScopes(proposal.scopes),
      performed: false,
    };
    await this.store.put(RecordKinds.operation, operationId, json(stored));
    const pointer: OperationProposal = { operationId };
    await this.store.put(RecordKinds.proposal, key, json(pointer), expiry(expiresAt));
    return operation;
  }

  /** The scopes confirming an operation requires: its own, else the write scopes. */
  #operationScopes(scopes: readonly string[] | undefined): readonly string[] {
    const required = scopes?.length ? [...scopes] : [...this.config.writeScopes];
    if (required.some((scope) => !this.config.scopes.includes(scope))) {
      throw new RangeError("an operation's scopes must be among the company's scopes");
    }
    return required;
  }

  /** An operation as the company keeps it: its record, action, owner, and account. */
  async operationRecord(operationId: string): Promise<StoredOperation> {
    const stored = await this.#currentOperation(operationId);
    if (stored === undefined) throw new Error("unknown operation");
    return stored;
  }

  /** The company changes a proposal's terms: a new revision, the old one unconfirmable. */
  async revise(
    operationId: string,
    changes: { readonly summary: string; readonly terms: Readonly<Record<string, unknown>> },
  ): Promise<Operation> {
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      operationId,
      (stored) => {
        if (stored.operation.state !== "proposed") {
          throw new Error("only a proposed operation can be revised");
        }
        return {
          ...stored,
          operation: {
            ...stored.operation,
            revision: stored.operation.revision + 1,
            summary: changes.summary,
            terms: { ...changes.terms },
            expires_at: isoZ(this.#later(this.config.operationLifetimeSeconds)),
          },
        };
      },
    );
    if (changed === undefined) throw new Error("unknown operation");
    return changed[1].operation;
  }

  /** The company found out how an operation left `in_progress` ended. */
  async settle(
    operationId: string,
    result: OperationResult,
    options: { readonly succeeded: boolean },
  ): Promise<Operation> {
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      operationId,
      (stored) => {
        if (stored.operation.state !== "in_progress") {
          throw new Error("only an operation in progress can be settled");
        }
        return {
          ...stored,
          performed: options.succeeded || stored.performed,
          operation: {
            ...stored.operation,
            state: options.succeeded ? "succeeded" : "failed",
            result: resultJson(result),
          } as unknown as Operation,
        };
      },
    );
    if (changed === undefined) throw new Error("unknown operation");
    return changed[1].operation;
  }

  async #operationRoute(
    request: CompanyRequest,
    method: string,
    path: string,
  ): Promise<CompanyResponse> {
    const parts = path.split("/");
    const operationId = parts[3] ?? "";
    const action = parts[4] ?? "";
    const [, session] = await this.#caller(request);
    if (!(await this.#supportsOperations(session.clientId))) {
      throw new Refused(403, "extension_required", { extension: "operations" });
    }
    const current = await this.#usable(operationId, session);
    if (method === "GET" && !action) return operationResponse(current);
    if (method === "POST" && action === "cancel") return this.#cancelOperation(operationId);
    if (method === "POST" && action === "confirm") {
      return this.#confirm(request, session, current);
    }
    throw new Refused(404, "not_found");
  }

  async #cancelOperation(operationId: string): Promise<CompanyResponse> {
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      operationId,
      (latest) => {
        const now = this.#expired(latest);
        // In progress, it stays so until the company knows whether it stopped (§7).
        if (now.operation.state !== "proposed") return now;
        return {
          ...now,
          operation: {
            ...now.operation,
            state: "cancelled",
            result: { summary: "Nothing was changed.", data: null },
          } as unknown as Operation,
        };
      },
    );
    if (changed === undefined) throw new Refused(404, "operation_not_found");
    return operationResponse(changed[1]);
  }

  /** The operation, if this Session may use it (Operations §3.2). */
  async #usable(operationId: string, session: IssuedSession): Promise<StoredOperation> {
    const stored = await this.#read<StoredOperation>(RecordKinds.operation, operationId);
    if (
      stored === undefined ||
      !sameOwner(stored.owner, [session.clientId, session.pairwiseUserId]) ||
      stored.accountId !== session.accountId
    ) {
      throw new Refused(404, "operation_not_found");
    }
    const current = await this.#currentOperation(operationId);
    if (current === undefined) throw new Refused(404, "operation_not_found");
    return current;
  }

  /** The operation now: a proposal past its expiry is recorded as expired. */
  async #currentOperation(operationId: string): Promise<StoredOperation | undefined> {
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      operationId,
      (stored) => this.#expired(stored),
    );
    return changed?.[1];
  }

  #expired(stored: StoredOperation): StoredOperation {
    const operation = stored.operation;
    if (
      operation.state === "proposed" &&
      operation.expires_at &&
      this.#passed(operation.expires_at)
    ) {
      return {
        ...stored,
        operation: {
          ...operation,
          state: "expired",
          result: { summary: "Nothing was changed; the proposal expired.", data: null },
        } as unknown as Operation,
      };
    }
    return stored;
  }

  async #confirm(
    request: CompanyRequest,
    session: IssuedSession,
    stored: StoredOperation,
  ): Promise<CompanyResponse> {
    const body = parseJsonStrict(text(request.body));
    const revision = isObject(body) ? body.revision : undefined;
    const approvedBy = isObject(body) ? body.approved_by : undefined;
    return this.#confirmOperation(session, stored, revision, approvedBy);
  }

  /** Confirm, whichever channel it comes through: at most once (Operations §4.4, §6). */
  async #confirmOperation(
    session: IssuedSession,
    stored: StoredOperation,
    revision: unknown,
    approvedBy: unknown,
  ): Promise<CompanyResponse> {
    const operation = stored.operation;
    // The scopes recorded with the operation when it was proposed, whichever channel
    // (API, MCP, conversation) proposed it and whichever confirms it.
    if (stored.scopes.some((scope) => !session.scopes.includes(scope))) {
      throw new Refused(403, "insufficient_scope", { scope: stored.scopes.join(" ") });
    }
    if (operation.state !== "proposed") {
      // At most once: a retried or late confirmation returns the record unchanged.
      return { status: 200, body: operation, headers: {} };
    }
    if (revision !== operation.revision) {
      throw new Refused(409, "terms_changed", { operation });
    }
    if (approvedBy !== "user" && approvedBy !== "standing_permission") {
      throw new Refused(400, "invalid_request");
    }
    if (approvedBy === "standing_permission" && operation.user_approval_required) {
      throw new Refused(403, "user_approval_required");
    }
    const confirmation = {
      revision: operation.revision,
      approved_by: approvedBy,
      confirmed_at: isoZ(this.#now()),
    };
    // The one compare-and-set from `proposed` to `in_progress`: only its winner performs.
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      operation.operation_id,
      (latest) => {
        const now = this.#expired(latest);
        if (now.operation.state !== "proposed") return now;
        if (now.operation.revision !== revision) {
          throw new Refused(409, "terms_changed", { operation: now.operation });
        }
        return {
          ...now,
          operation: {
            ...now.operation,
            state: "in_progress",
            confirmation,
            expires_at: null,
          } as unknown as Operation,
        };
      },
    );
    if (changed === undefined) throw new Refused(404, "operation_not_found");
    const [before, confirmed] = changed;
    if (before.operation.state !== "proposed" || confirmed.operation.state !== "in_progress") {
      return { status: 200, body: confirmed.operation, headers: {} };
    }
    return this.#perform(confirmed);
  }

  /**
   * Perform a just-confirmed operation with its action's executor: the action's
   * lowest-order executor performs it; two at that order are ambiguous.
   */
  async #perform(confirmed: StoredOperation): Promise<CompanyResponse> {
    const executors = this.reactor
      .getContributions(OperationExecutors)
      .filter((contribution) => contribution.value.action === confirmed.action);
    const executor = executors[0]?.value;
    if (executor === undefined || executors[1]?.order === executors[0]?.order) {
      // Nobody can perform it: it stays in progress rather than claim a failure.
      return operationResponse(confirmed);
    }
    let result: OperationResult;
    try {
      result = await executor.perform(parseOperation(confirmed.operation), confirmed.accountId);
    } catch (error) {
      if (error instanceof OperationFailed) {
        // Failed partway: the result says every change that was made (Operations §6).
        return this.#finish(confirmed, "failed", error.result);
      }
      if (error instanceof OperationOutcomeUnknown) {
        // Never `failed` while it may have taken effect: it stays in progress.
        return operationResponse(confirmed);
      }
      throw error;
    }
    return this.#finish(confirmed, "succeeded", result);
  }

  async #finish(
    confirmed: StoredOperation,
    state: "succeeded" | "failed",
    result: OperationResult,
  ): Promise<CompanyResponse> {
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      confirmed.operation.operation_id,
      (current) =>
        current.operation.state !== "in_progress"
          ? current
          : {
              ...current,
              performed: true,
              operation: {
                ...current.operation,
                state,
                result: resultJson(result),
              } as unknown as Operation,
            },
    );
    return operationResponse(changed === undefined ? confirmed : changed[1]);
  }

  // Web browsing (§5, Operations §4.4) -------------------------------------------------

  /** The Session as it is now: its latest unexpired DPoP token's record. */
  async #liveSession(sessionId: string): Promise<IssuedSession | undefined> {
    const stored = await this.#read<StoredSession>(RecordKinds.session, sessionId);
    let live: IssuedSession | undefined;
    for (const token of Object.values(stored?.tokens ?? {})) {
      if ((token.tokenType ?? "DPoP") !== "DPoP" || this.#passed(token.expiresAt)) continue;
      if (live === undefined || new Date(token.expiresAt) > new Date(live.expiresAt)) live = token;
    }
    return live;
  }

  /** Verify a browser assertion with one of the agent's published keys, else `undefined`. */
  async #browserAssertion(assertion: string): Promise<VerifiedBrowserAssertion | undefined> {
    let claims: Record<string, unknown>;
    let algorithm: string;
    let kid: unknown;
    try {
      claims = decodeJwt(assertion);
      const header = decodeProtectedHeader(assertion);
      algorithm = String(header.alg ?? "");
      kid = header.kid;
    } catch {
      return undefined;
    }
    if (typeof claims.iss !== "string") return undefined;
    const clientId = claims.iss;
    if (!(await this.#allowed(clientId))) return undefined;
    const resolver = firstContribution(this.reactor, ClientResolvers, "client");
    let keys: JsonWebKeySet;
    try {
      [, keys] = await resolver.resolve(clientId, keyId(assertion));
    } catch {
      return undefined;
    }
    for (const key of keys.keys) {
      if (kid !== undefined && key.kid !== kid) continue;
      if (key.alg !== undefined && key.alg !== algorithm) continue;
      try {
        return await verifyBrowserAssertion(assertion, {
          publicKey: await importJWK({ ...key } as JWK, algorithm),
          expectedEndpoint: this.config.browserSessionEndpoint,
          companyDomain: this.config.domain,
          expectedClientId: clientId,
          expectedPairwiseUserId: String(claims.sub ?? ""),
          expectedSessionId: String(claims.session_id ?? ""),
          replayCache: this.#replay(),
          now: this.#now(),
        });
      } catch {
        continue;
      }
    }
    return undefined;
  }

  /**
   * Join the agent's own browser to its Session: a verified, one-time browser assertion,
   * form-posted (never in a URL), answers `303` to its `return_to` with the company's
   * own cookie, which lives no longer than the Session (§5).
   */
  async #browserSession(request: CompanyRequest): Promise<CompanyResponse> {
    const refused = page(400, "This browser could not join the session.");
    const verified = await this.#browserAssertion(pairs(text(request.body)).assertion ?? "");
    if (verified === undefined) return refused;
    const session = await this.#liveSession(verified.sessionId);
    if (
      session === undefined ||
      !sameOwner([session.clientId, session.pairwiseUserId], [verified.clientId, verified.pairwiseUserId])
    ) {
      return refused;
    }
    const webCookie = this.#id("web");
    const pointer: SessionPointer = { sessionId: session.sessionId };
    await this.store.put(
      RecordKinds.browserCookie,
      digest(webCookie),
      json(pointer),
      expiry(new Date(new Date(session.expiresAt).getTime() + this.config.accountTokenLifetimeSeconds * 1000)),
    );
    return {
      status: 303,
      headers: {
        Location: verified.returnTo,
        // The company's own cookie: no Max-Age, and only as alive as its Session.
        "Set-Cookie": `${WEB_COOKIE}=${webCookie}; Path=/; Secure; HttpOnly; SameSite=Lax`,
        ...NO_STORE,
      },
    };
  }

  /** The Session a browser's cookie stands for, as it is now (§5). */
  async #webSession(webCookie: string | undefined): Promise<IssuedSession | undefined> {
    if (webCookie === undefined) return undefined;
    const pointer = await this.#read<SessionPointer>(RecordKinds.browserCookie, digest(webCookie));
    if (pointer === undefined) return undefined;
    const session = await this.#liveSession(pointer.sessionId);
    // The cookie does not outlive the Session.
    if (session === undefined) await this.store.delete(RecordKinds.browserCookie, digest(webCookie));
    return session;
  }

  /** An operation's page in the browser's Session, where the user confirms or cancels it. */
  async #operationPage(
    request: CompanyRequest,
    method: string,
    operationId: string,
  ): Promise<CompanyResponse> {
    const webCookie = cookie(request, WEB_COOKIE);
    const session = await this.#webSession(webCookie);
    if (webCookie === undefined || session === undefined) {
      return page(401, "Your agent's session has ended. Ask it to open this again.");
    }
    let stored: StoredOperation;
    try {
      stored = await this.#usable(operationId, session);
    } catch (error) {
      if (error instanceof Refused) return page(404, "There is nothing to show here.");
      throw error;
    }
    const pageUrl = `${this.config.base}/operations/${operationId}`;
    const csrf = bound(webCookie, `operation:${operationId}`);
    if (method === "POST") {
      const form = pairs(text(request.body));
      // This site's page, in the browser this cookie is in: never another site's page,
      // nor a form copied from another Session's page (Guides, consent pages).
      if (!fromThisSite(request, this.config.base) || !sameText(form.csrf ?? "", csrf)) {
        return page(403, "This request did not come from this site.");
      }
      try {
        if (form.action === "cancel") {
          await this.#cancelOperation(operationId);
        } else {
          const revision = /^\d+$/u.test(form.revision ?? "") ? Number(form.revision) : undefined;
          await this.#confirmOperation(session, stored, revision, form.approved_by ?? "user");
        }
      } catch (error) {
        if (error instanceof Refused) return page(error.status, `Not done: ${escapeHtml(error.error)}.`);
        throw error;
      }
      return { status: 303, headers: { Location: pageUrl, ...NO_STORE } };
    }
    if (method !== "GET") return page(405, "Not allowed.");
    const operation = stored.operation;
    let body =
      `<h1>${escapeHtml(this.config.name)}</h1>` +
      `<section data-operation-id="${escapeHtml(operation.operation_id)}" ` +
      `data-revision="${operation.revision}" data-state="${operation.state}">` +
      `<p>${escapeHtml(operation.summary)}</p><p>Status: ${operation.state}</p>`;
    if (operation.result) body += `<p>${escapeHtml(operation.result.summary)}</p>`;
    if (operation.state === "proposed") {
      body +=
        `<form method="post" action="${pageUrl}">` +
        `<input type="hidden" name="revision" value="${operation.revision}">` +
        '<input type="hidden" name="approved_by" value="user">' +
        `<input type="hidden" name="csrf" value="${csrf}">` +
        '<button name="action" value="confirm">Confirm</button>' +
        '<button name="action" value="cancel">Cancel</button></form>';
    }
    return page(200, `${body}</section>`);
  }
}

/** An operation's answer: `Retry-After` while it is in progress. */
function operationResponse(stored: StoredOperation): CompanyResponse {
  const headers: Record<string, string> =
    stored.operation.state === "in_progress" ? { "Retry-After": "5" } : {};
  return { status: 200, body: stored.operation, headers };
}

/** A result as Python serializes it: `data` is `null` when there is none. */
function resultJson(result: OperationResult): Record<string, unknown> {
  return { ...result, summary: result.summary, data: result.data ?? null };
}

/** Equal JSON values, whatever the member order (Python's `==` on dicts). */
function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  if (keys.length !== Object.keys(right).length) return false;
  return keys.every((key) => key in right && sameJson(left[key], right[key]));
}

function startCursor(conversation: StoredConversation): string {
  return `start_${conversation.conversationId}`;
}

/** A consent page: never framed, never cached (upstream guides, consent pages). */
function page(status: number, body: string, setCookie?: string): CompanyResponse {
  return {
    status,
    body: `<!doctype html><meta charset=utf-8><title>Sign in</title>${body}`,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'",
      ...NO_STORE,
      ...(setCookie === undefined ? {} : { "Set-Cookie": setCookie }),
    },
  };
}
