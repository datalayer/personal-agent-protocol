/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

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
 * What it implements of draft 0.3 and Operations v1:
 *
 * - Discovery (`/.well-known/poppy.json`) and OAuth metadata
 *   (`/.well-known/oauth-authorization-server`), one issuer on the company's
 *   own domain.
 * - Sessions (§4.2): the JWT-bearer grant with a verified client assertion and
 *   Session assertion, DPoP-bound tokens; each Session named by its key's thumbprint
 *   (the Session Key), renewed with a proof from it, its key refused once it ends.
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
 *   Once a conversation is handed to the company's people, one of them
 *   answers in it (`staffReply`), over the last event they read.
 * - The OpenAPI API point (`/api/…`), its consequential calls answering `202`
 *   with an operation (Operations §4.1).
 * - Operations v1: proposals from the company agent or the API, read, confirm
 *   (latest revision, approval rules, scope, extension negotiation), at most
 *   once, and cancel.
 * - MCP (§4.3, §6), when a `pap.company.mcp` contribution is present: a
 *   Streamable HTTP endpoint at `/mcp` accepting only Session Tokens issued for
 *   its url (`resource` = that url), its protected resource metadata (RFC 9728),
 *   and tools that propose operations in `structuredContent` (Operations §4.2).
 *   With `mcpDpop` (the default) the server supports DPoP: personal agents get
 *   DPoP tokens for it and send proofs; without it, they get Bearer tokens by Token
 *   Exchange, which work nowhere else.
 * - Feedback (§8), with `feedback` (the default): reports of tasks the protocol
 *   can't do, kept for the company's operator (`feedbackReports`).
 * - Web browsing (§5), with `web: true`: the browser-session endpoint gives a join form
 *   with a one-time code and sets the company's own cookie for the Session whose key
 *   signed a proof over that code, and each
 *   operation's `url` shows it in that Session, where the user can confirm or cancel
 *   it: the same operation, performed at most once whichever channel confirms it.
 * - Taking a company down: its owner reads what is under way (`openWork`), settles
 *   each open operation as cancelled (`cancelOpenOperations`) and ends every sign-in
 *   (`endSignIns`), before its records go.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import type { ReactorPlatformView } from "@datalayer/reactor";

import { IDEMPOTENCY_KEY, WRITE_METHODS } from "../apis.js";
import { verifyDpopProof } from "../crypto.js";
import { ProofError, ProtocolValidationError, SessionError } from "../errors.js";
import { parseJsonStrict } from "../json.js";
import {
  AUTHORIZATION_CODE_GRANT,
  parseAuthor,
  DEVICE_CODE_GRANT,
  REFRESH_TOKEN_GRANT,
  TOKEN_EXCHANGE_GRANT,
  parseMessage,
  parseOperation,
  redirectUriMatches,
  type ClientMetadata,
  type ConversationEvent,
  type JsonWebKeySet,
  type Message,
  type Operation,
  type OperationResult,
} from "../models.js";
import { OPERATIONS_VERSION } from "../operations.js";
import { PROTOCOL_PROFILE } from "../profile.js";
import { Clocks, RandomSources, firstContribution, optionalContribution } from "../reactor.js";
import { SecretValue } from "../secret.js";
import { ACCESS_TOKEN_TYPE, JWT_BEARER_GRANT, JWT_CLIENT_ASSERTION } from "../sessions.js";
import { emit, telemetrySink, type TelemetryInterface } from "../telemetry.js";
import {
  ClientPolicies,
  ClientResolvers,
  CompanyAccounts,
  CompanyAgents,
  CompanyApis,
  CompanyMcps,
  CompanyRateLimits,
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
  type IssuedNonce,
  type StoredFeedback,
  type AccountAgent,
  type AccountFamily,
  type AccountGrant,
  type CompanyStore,
  type IdempotencyRecord,
  type IssuedCode,
  type IssuedSession,
  type JoinCode,
  type JsonObject,
  type KnownClient,
  type MessageReceipt,
  type OperationProposal,
  type PendingAuthorization,
  type PendingDevice,
  type PendingMediated,
  type SessionPointer,
  type SignInAttempts,
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

const PAGE = 50;
const OPAQUE_ID = /^[A-Za-z0-9_-]{1,256}$/;
const THUMBPRINT = /^[A-Za-z0-9_-]{43}$/;
/** Ties a join code to the browser that loaded the join page (§5). */
export const JOIN_COOKIE = "__Host-poppy_join";
/** A join code lives at most this long (§5: no more than 60 seconds). */
const JOIN_LIFETIME_SECONDS = 60;
/** The DPoP algorithms the company accepts: ES256, which every company must (§3.2), and RS256. */
export const DPOP_ALGORITHMS: readonly string[] = ["ES256", "RS256"];
/** The longest `wait` the company holds a read for; a larger one is held this long (§7.5). */
export const MAX_WAIT_SECONDS = 30;

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
  /**
   * Failed Mediated Sign-In attempts (credentials or codes) a key may make before it is
   * locked out: an account identifier, an agent's user, a Session, an account's codes.
   */
  readonly maxSignInFailures?: number;
  /**
   * How long the first lockout lasts; each failure past the limit doubles it (at most a
   * day), and the count is forgotten once a key has failed nothing for this long.
   */
  readonly signInLockoutSeconds?: number;
  /**
   * What each scope allows, in words a user and a model understand, published as
   * `auth.scopes` (§3.1, §4.4): every scope in `scopes` needs one.
   */
  readonly scopeDescriptions: Readonly<Record<string, string>>;
  /**
   * `auth.scope_hints` (§4.4): per scope, its most consequential operation's `changes`
   * (none, reversible, irreversible) and whether it touches personal data.
   */
  readonly scopeHints?: Readonly<Record<string, readonly [changes: string, personalData: boolean]>>;
  /**
   * The tasks the company chose not to offer through the protocol, published at
   * `/poppy/excluded-tasks.json` (§8.1): each a `task` and an optional `alternative`.
   */
  readonly excludedTasks?: readonly Readonly<Record<string, unknown>>[];
  /**
   * Tasks a feedback report may name that can be done after all: the alternative (§8.2)
   * the company answers with, HTTP 200, keyed by task, compared ignoring case.
   */
  readonly feedbackAnswers?: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  /** A hosted Device Sign-In page (`verification_uri`); `&code=<user_code>` completes it. */
  readonly devicePage?: string;
  /** A hosted consent page with `{request_id}`: `GET /oauth/authorize` answers 303 to it. */
  readonly consentPage?: string;
  /** Web browsing (§5): a browser-session endpoint and a page for each operation. */
  readonly web?: boolean;
  /**
   * Other domains that are this company (§3): each publishes its discovery document, naming
   * itself as the organization's domain, and the issuer's metadata lists it in
   * `protected_resources`. Everything else stays on `domain`, the issuer's: an alias is never a
   * second identity, and answers nothing but its discovery document.
   */
  readonly aliases?: readonly string[];
  /**
   * The MCP server supports DPoP (§4.3; new MCP servers SHOULD): its protected resource
   * metadata lists `dpop_signing_alg_values_supported`, and personal agents get DPoP
   * tokens for it. Off, it is an MCP server that doesn't: they get Bearer tokens, by
   * Token Exchange alone.
   */
  readonly mcpDpop?: boolean;
  /** Accept feedback reports at `/poppy/feedback` and list it in poppy.json (§8). */
  readonly feedback?: boolean;
  /** Require DPoP proofs to carry a nonce the company issued (§4.3, RFC 9449 §8, §9). */
  readonly dpopNonce?: boolean;
  /** How long an issued DPoP nonce is accepted (default five minutes). */
  readonly dpopNonceLifetimeSeconds?: number;
  /** How long an ended Session's key is remembered and refused (§4.2; default 30 days). */
  readonly endedSessionMemorySeconds?: number;
  /**
   * How long an API write's `Idempotency-Key` is remembered in its Session, with the
   * original response a repeated key gets again (guides, *Retries*: a set time; default a day).
   */
  readonly idempotencyLifetimeSeconds?: number;
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
  readonly maxSignInFailures: number;
  readonly signInLockoutSeconds: number;
  readonly scopeDescriptions: Readonly<Record<string, string>>;
  readonly scopeHints: Readonly<Record<string, readonly [string, boolean]>>;
  readonly excludedTasks: readonly Readonly<Record<string, unknown>>[];
  readonly feedbackAnswers: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly devicePage: string | undefined;
  readonly consentPage: string | undefined;
  readonly web: boolean;
  readonly aliases: readonly string[];
  readonly mcpDpop: boolean;
  readonly feedback: boolean;
  readonly dpopNonce: boolean;
  readonly dpopNonceLifetimeSeconds: number;
  readonly endedSessionMemorySeconds: number;
  readonly idempotencyLifetimeSeconds: number;

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
    this.maxSignInFailures = options.maxSignInFailures ?? 5;
    this.signInLockoutSeconds = options.signInLockoutSeconds ?? 15 * 60;
    this.scopeDescriptions = { ...options.scopeDescriptions };
    this.scopeHints = { ...(options.scopeHints ?? {}) };
    this.excludedTasks = [...(options.excludedTasks ?? [])];
    this.feedbackAnswers = { ...(options.feedbackAnswers ?? {}) };
    this.devicePage = hostedPage("devicePage", options.devicePage);
    this.consentPage = hostedPage("consentPage", options.consentPage);
    this.web = options.web ?? false;
    this.aliases = [...(options.aliases ?? [])];
    this.mcpDpop = options.mcpDpop ?? true;
    this.feedback = options.feedback ?? true;
    this.dpopNonce = options.dpopNonce ?? false;
    this.dpopNonceLifetimeSeconds = options.dpopNonceLifetimeSeconds ?? 5 * 60;
    this.endedSessionMemorySeconds = options.endedSessionMemorySeconds ?? 30 * 24 * 60 * 60;
    this.idempotencyLifetimeSeconds = options.idempotencyLifetimeSeconds ?? 24 * 60 * 60;
    if (!(this.idempotencyLifetimeSeconds > 0)) {
      throw new RangeError("idempotencyLifetimeSeconds must be positive");
    }
    for (const alias of this.aliases) {
      if (!alias || alias !== alias.toLowerCase().replace(/\.$/, "") || alias.includes("/") || alias.includes(":")) {
        throw new RangeError("an alias is a DNS domain name, in small letters");
      }
    }
    if (this.aliases.includes(this.domain) || new Set(this.aliases).size !== this.aliases.length) {
      throw new RangeError("each alias is another domain, named once");
    }
    if (this.devicePage !== undefined) {
      const host = new URL(this.devicePage).hostname.toLowerCase();
      if (![this.domain, ...this.aliases].some((domain) => host === domain || host.endsWith(`.${domain}`))) {
        // A personal agent shows the link only on the issuer's host or the host of one of
        // its protected_resources, or a subdomain of either (§4.6).
        throw new RangeError("devicePage must be on the company's domain or a subdomain");
      }
    }
    if (this.consentPage !== undefined && !this.consentPage.includes("{request_id}")) {
      throw new RangeError("consentPage must contain {request_id}");
    }
    if (this.writeScopes.some((scope) => !this.scopes.includes(scope))) {
      throw new RangeError("writeScopes must be among scopes");
    }
    if (this.scopes.some((scope) => scope.startsWith("poppy:"))) {
      throw new RangeError("scope names starting with poppy: are reserved (§4.4)");
    }
    const described = Object.keys(this.scopeDescriptions);
    if (
      described.length !== new Set(this.scopes).size ||
      this.scopes.some((scope) => !this.scopeDescriptions[scope])
    ) {
      // Every scope in scopes_supported is described (§4.4).
      throw new RangeError("scopeDescriptions must describe every scope, and only those");
    }
    for (const [name, [changes]] of Object.entries(this.scopeHints)) {
      if (!this.scopes.includes(name) || !["none", "reversible", "irreversible"].includes(changes)) {
        throw new RangeError("scopeHints name a scope and its changes");
      }
    }
    if (!(Number.isInteger(this.maxSignInFailures) && this.maxSignInFailures >= 1 && this.signInLockoutSeconds > 0)) {
      throw new RangeError("sign-in attempts need a positive limit and lockout");
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
  get feedbackEndpoint(): string {
    return `${this.base}/poppy/feedback`;
  }
  get excludedTasksUrl(): string {
    return `${this.base}/poppy/excluded-tasks.json`;
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

/** One of the company's people answered over events they had not read: read again. */
export class StaleConversationError extends Error {
  constructor(
    readonly conversationId: string,
    readonly after: string,
  ) {
    super(`${conversationId} has events after ${after}: read it again`);
    this.name = "StaleConversationError";
  }
}

class Refused extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly extra: Readonly<Record<string, unknown>> = {},
    readonly headers: Readonly<Record<string, string>> = {},
  ) {
    super(error);
  }
}

/**
 * `insufficient_scope` (RFC 6750), naming the scopes the request needs (§4.4, §6).
 *
 * What a signed-out token gets for anything that needs the account: it has no scopes, so
 * the error fits, and the agent signs in or uses an Account Token.
 */
function insufficientScope(scopes: readonly string[]): Refused {
  return new Refused(403, "insufficient_scope", { scope: scopes.join(" ") });
}

/** The host's rate limit refused the request: `429` and when to ask again. */
class RateLimitedRefusal extends Refused {
  constructor(readonly retryAfter: number) {
    super(429, "rate_limited");
  }
}

const NO_STORE = { "Cache-Control": "no-store" } as const;

/** The device flow's progress: answered as errors by OAuth, never refusals (RFC 8628 §3.5). */
const PROGRESS = new Set(["authorization_pending", "slow_down"]);

/** The routes a request may be reported under: never a path's own words or an ID. */
const NAMED_ROUTES = new Set([
  "oauth_token",
  "oauth_authorize",
  "oauth_device",
  "oauth_revoke",
  "poppy_browser_session",
  "poppy_sign_in",
  "poppy_conversations",
  "poppy_operations",
  "poppy_feedback",
]);
const ROUTES: Readonly<Record<string, string>> = {
  operations: "operation_page",
  api: "api",
  mcp: "mcp",
  ".well-known": "discovery",
};

/** What a request came to, so far: for the telemetry reported when it ends. */
interface Exchange {
  readonly started: number;
  readonly route: string;
  clientId?: string;
  replayed: boolean;
}

const exchanges = new AsyncLocalStorage<Exchange>();

function routeOf(path: string): string {
  const parts = path.split("/").filter((part) => part !== "");
  const [first, second] = parts;
  if (first === undefined) return "unknown";
  if ((first === "oauth" || first === "poppy") && second !== undefined) {
    const route = `${first}_${second.replaceAll("-", "_")}`;
    return NAMED_ROUTES.has(route) ? route : "unknown";
  }
  return Object.hasOwn(ROUTES, first) ? (ROUTES[first] as string) : "unknown";
}

/** The company's replay cache, noting on the request when it refused a replay. */
class WatchedReplayCache implements ReplayCache {
  readonly #cache: ReplayCache;

  constructor(cache: ReplayCache) {
    this.#cache = cache;
  }

  async markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean> {
    const first = await this.#cache.markOnce(key, options);
    const exchange = exchanges.getStore();
    if (!first && exchange !== undefined) exchange.replayed = true;
    return first;
  }
}

const CHALLENGED = new Set([
  "invalid_token",
  "insufficient_scope",
  "invalid_dpop_proof",
  "use_dpop_nonce",
]);

/**
 * A JSON error; a token error at 401 or 403 also in `WWW-Authenticate` (§6).
 *
 * The token endpoint answers DPoP failures as OAuth errors with HTTP 400 and no
 * challenge; APIs and conversation endpoints answer them with HTTP 401 and the `DPoP`
 * challenge (§4.3). `use_dpop_nonce` carries `DPoP-Nonce` either way.
 */
function jsonError(
  status: number,
  error: string,
  extra: Readonly<Record<string, unknown>> = {},
  headers: Readonly<Record<string, string>> = {},
): CompanyResponse {
  const out: Record<string, string> = { ...NO_STORE, ...headers };
  if (CHALLENGED.has(error) && (status === 401 || status === 403)) {
    out["WWW-Authenticate"] = challenge("DPoP", error, extra);
  }
  return { status, body: { error, ...extra }, headers: out };
}

/** One `WWW-Authenticate` challenge with the error's `scope`, `extension`, or `resource_metadata`. */
function challenge(scheme: string, error: string, extra: Readonly<Record<string, unknown>>): string {
  let value = `${scheme} error="${error}"`;
  for (const name of ["scope", "extension", "resource_metadata"]) {
    const item = extra[name];
    if (typeof item === "string") value += `, ${name}="${item}"`;
  }
  return value;
}

const IDENTIFIER = /^[A-Za-z0-9_-]{1,256}$/u;

/** A request's query parameters, blank ones kept (Python's `parse_qsl(keep_blank_values=True)`). */
function queryOf(request: CompanyRequest): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of new URL(request.url).searchParams) result[name] = value;
  return result;
}

/**
 * The `wait` query parameter: a whole number of seconds, 0 or more (§7.5).
 *
 * Anything else is `invalid_request`; a larger value than the company holds a request
 * for is held for its cap (`MAX_WAIT_SECONDS`), never refused.
 */
function waitOf(request: CompanyRequest): number | undefined {
  const value = queryOf(request).wait;
  if (value === undefined) return undefined;
  if (!/^[0-9]+$/u.test(value)) throw new Refused(400, "invalid_request");
  return Math.min(Number(value), MAX_WAIT_SECONDS);
}

/** A message as the personal agent sent it; a `role` it set is ignored (§7.4). */
function incoming(value: unknown): Message {
  const message = parseMessage(value);
  if (message.role === undefined) return message;
  const { role: _role, ...rest } = message;
  return rest as Message;
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

/**
 * What a company has under way: what its owner settles and ends before taking it down.
 *
 * `operations` are those still `proposed` or `in_progress` (a proposal past its
 * expiry is not open); `signIns` are the agents and accounts, as `[clientId,
 * accountId]`, with a sign-in not ended — each one ended whole by
 * `CompanyService.disconnect`.
 */
export interface OpenWork {
  readonly operations: readonly Operation[];
  readonly signIns: readonly (readonly [clientId: string, accountId: string])[];
}

/** The states an operation is not final in (Operations §6). */
const OPEN_STATES: ReadonlySet<string> = new Set(["proposed", "in_progress"]);

function byCodePoint(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
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

/** Which of a Session's tokens one is: its own, or its token for the MCP server (§4.3). */
type TokenKind = "own" | "mcp";
/** How long an expired device or Mediated sign-in is kept, to answer that it expired. */
const KEPT_EXPIRED_MS = 10 * 60 * 1000;
/**
 * How long the first request with an `Idempotency-Key` holds it: a repeat in that time is
 * told to wait (503, `Retry-After`); a holder that never answered lets it go then.
 */
const IDEMPOTENCY_HELD_SECONDS = 60;

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
    return new WatchedReplayCache(firstContribution(this.reactor, ReplayCaches, "replay cache"));
  }

  // Telemetry -----------------------------------------------------------------------

  /** One `pap.telemetry` event of this request, when the host contributes a sink. */
  #report(
    name: string,
    outcome: "ok" | "error",
    attributes: Readonly<Record<string, unknown>>,
  ): void {
    const sink = telemetrySink(this.reactor);
    if (sink === undefined) return;
    // Outside a request (the host signing an account out, say): no route, no agent.
    const exchange = exchanges.getStore();
    emit(sink, name, outcome, exchange === undefined ? 0 : performance.now() - exchange.started, {
      "pap.company.issuer": this.config.base,
      "pap.company.domain": this.config.domain,
      "pap.company.route": exchange?.route,
      "pap.client.id": exchange?.clientId,
      ...attributes,
    });
  }

  /** A request answered with an error: the protocol's code, never the body's text. */
  #reportRefusal(response: CompanyResponse): void {
    const body: Readonly<Record<string, unknown>> = isObject(response.body) ? response.body : {};
    const code = typeof body.error === "string" ? body.error : "refused";
    // Progress, or a path the company does not serve.
    if (PROGRESS.has(code) || (response.status === 404 && code === "not_found")) return;
    this.#report("pap.company.refused", "error", {
      "pap.error": code,
      "pap.http.status": response.status,
      "pap.replayed": exchanges.getStore()?.replayed === true,
    });
  }

  /** A Session started or renewed; a token for one resource (the MCP server) moves it there. */
  #reportSession(session: IssuedSession, renewed: boolean, forResource: boolean): void {
    const signedIn = session.accountId !== undefined;
    if (forResource) {
      this.#reportSwitch("mcp", signedIn);
      return;
    }
    this.#report(renewed ? "pap.company.session.renew" : "pap.company.session.start", "ok", {
      "pap.session.signed_in": signedIn,
      "pap.scopes.granted": session.scopes.length,
    });
  }

  #reportSwitch(to: TelemetryInterface, signedIn: boolean): void {
    this.#report("pap.company.interface.switch", "ok", {
      "pap.interface": to,
      "pap.session.signed_in": signedIn,
    });
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

  /** Answer one request; what it came to is reported to `pap.telemetry`. */
  async handle(request: CompanyRequest): Promise<CompanyResponse> {
    const exchange: Exchange = {
      started: performance.now(),
      route: routeOf(new URL(request.url).pathname),
      replayed: false,
    };
    return exchanges.run(exchange, async () => {
      const response = await this.#dispatch(request);
      if (response.status >= 400) this.#reportRefusal(response);
      return response;
    });
  }

  async #dispatch(request: CompanyRequest): Promise<CompanyResponse> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();
    if (url.searchParams.has("access_token")) {
      // A token in a URL is logged, cached, and leaked in Referer: never accepted, even
      // beside a header that would be (§4.3, RFC 6750 §2.3).
      if (path === "/mcp" && this.#mcp() !== undefined) return this.#mcpRefusal(400, "invalid_request");
      return jsonError(400, "invalid_request");
    }
    try {
      const host = (request.headers.host ?? "").split(":", 1)[0]?.toLowerCase() ?? "";
      if (this.config.aliases.includes(host)) {
        // An alias publishes the company's discovery document, and nothing else (§3).
        if (method === "GET" && path === "/.well-known/poppy.json") {
          return { status: 200, body: this.discoveryDocument(host), headers: {} };
        }
        return jsonError(404, "not_found");
      }
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
      if (method === "GET" && path === "/poppy/browser-session" && this.config.web) {
        return await this.#joinPage();
      }
      if (method === "POST" && path === "/poppy/browser-session" && this.config.web) {
        return await this.#browserSession(request);
      }
      if (method === "GET" && path === "/poppy/excluded-tasks.json" && this.config.excludedTasks.length) {
        return { status: 200, body: { tasks: this.config.excludedTasks.map((task) => ({ ...task })) }, headers: {} };
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
      if (method === "POST" && path === "/poppy/feedback" && this.config.feedback) {
        return await this.#feedback(request);
      }
    } catch (error) {
      if (error instanceof RateLimitedRefusal) return rateLimited(error.retryAfter);
      if (error instanceof Refused) return jsonError(error.status, error.error, error.extra, error.headers);
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

  /**
   * The discovery document published at `domain`: the company's own, or one of its aliases,
   * which it names as the organization's domain; its endpoints stay on `base`.
   *
   * Every domain's document has the same `auth`, which describes the issuer (§3.2).
   */
  discoveryDocument(domain?: string): Record<string, unknown> {
    const config = this.config;
    if (domain !== undefined && domain !== config.domain && !config.aliases.includes(domain)) {
      throw new RangeError(`${domain} is not one of this company's domains`);
    }
    // Direct and Device Sign-In are the issuer's grants, not listed here (§3.2, §4.4).
    const auth: Record<string, unknown> = { issuer: config.base };
    if (config.mediatedFields.length) {
      auth.mediated = {
        endpoint: config.mediatedEndpoint,
        fields: config.mediatedFields.map(([name, label, secret]) => ({ name, label, secret })),
        scopes: [...config.scopes],
      };
    }
    auth.scopes = Object.fromEntries(config.scopes.map((scope) => [scope, config.scopeDescriptions[scope]]));
    if (Object.keys(config.scopeHints).length) {
      auth.scope_hints = Object.fromEntries(
        Object.entries(config.scopeHints).map(([scope, [changes, personal]]) => [
          scope,
          { changes, personal_data: personal },
        ]),
      );
    }
    const document: Record<string, unknown> = {
      protocol_version: PROTOCOL_PROFILE,
      organization: { name: config.name, domain: domain ?? config.domain },
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
    if (config.feedback) document.feedback = { endpoint: config.feedbackEndpoint };
    if (config.excludedTasks.length) document.excluded_tasks = { url: config.excludedTasksUrl };
    if (config.operations) {
      document.extensions = {
        operations: { version: OPERATIONS_VERSION, endpoint: config.operationsEndpoint },
      };
    }
    return document;
  }

  /** RFC 9728 metadata for the MCP server: its issuer is the company's (§6). */
  protectedResourceMetadata(): Record<string, unknown> {
    const metadata: Record<string, unknown> = {
      resource: this.config.mcpUrl,
      authorization_servers: [this.config.base],
      scopes_supported: [...this.config.scopes],
      bearer_methods_supported: ["header"],
    };
    if (this.config.mcpDpop) {
      // It supports DPoP (RFC 9728 §2), ES256 among its algorithms (§4.3).
      metadata.dpop_signing_alg_values_supported = [...DPOP_ALGORITHMS];
    }
    return metadata;
  }

  oauthMetadata(): Record<string, unknown> {
    const config = this.config;
    const grants: string[] = [JWT_BEARER_GRANT, REFRESH_TOKEN_GRANT];
    // `https://{domain}` for each domain whose poppy.json names the issuer, then the MCP
    // server: exact strings (§3.2, RFC 9728 §4).
    const resources = [config.domain, ...config.aliases].map((domain) => `https://${domain}`);
    const metadata: Record<string, unknown> = {
      issuer: config.base,
      token_endpoint: config.tokenEndpoint,
      revocation_endpoint: config.revocationEndpoint,
      grant_types_supported: grants,
      scopes_supported: [...config.scopes],
      protected_resources: resources,
      dpop_signing_alg_values_supported: [...DPOP_ALGORITHMS],
    };
    if (this.#mcp() !== undefined) {
      resources.push(config.mcpUrl);
      // Bearer tokens for an MCP server without DPoP come from Token Exchange alone (§4.3).
      if (!config.mcpDpop) grants.push(TOKEN_EXCHANGE_GRANT);
    }
    if (config.direct) {
      grants.push(AUTHORIZATION_CODE_GRANT);
      metadata.authorization_endpoint = config.authorizationEndpoint;
      metadata.code_challenge_methods_supported = ["S256"];
    }
    if (config.device) {
      grants.push(DEVICE_CODE_GRANT);
      metadata.device_authorization_endpoint = config.deviceEndpoint;
    }
    return metadata;
  }

  // OAuth ---------------------------------------------------------------------------

  /**
   * Verify the client assertion, the agent's keys, and the company's policy.
   *
   * The assertion's `aud` is the issuer, exactly, whichever endpoint it is sent to
   * (§4.1); its `jti` is refused again until it expires.
   */
  async #client(form: Readonly<Record<string, string>>): Promise<string> {
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
      audience: this.config.base,
      subject: clientId,
      replayCache: this.#replay(),
      now: this.#now(),
    });
    const extensions = Object.keys(metadata.extensions ?? {}).sort();
    const exchange = exchanges.getStore();
    if (exchange !== undefined) exchange.clientId = clientId;
    const known = await this.#read<KnownClient>(RecordKinds.client, clientId);
    if (known === undefined || canonical(known.extensions) !== canonical(extensions)) {
      await this.store.put(RecordKinds.client, clientId, json({ extensions } satisfies KnownClient));
      // Its identity verified for the first time, or with new metadata.
      this.#report("pap.company.identity.check", "ok", {});
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

  /**
   * Validate the request's DPoP proof as RFC 9449 §4.3 says; its key's thumbprint.
   *
   * One `DPoP` header holding one well-formed JWT, `typ` `dpop+jwt`, an accepted
   * asymmetric `alg`, a public `jwk` only, the signature, `htm` and `htu`, `iat` within
   * the window, a nonce the company issued when it requires them, and with a Session
   * Token, `ath`. A replayed `jti` is refused everywhere: at the token endpoint it must
   * be (§4.3). At the token endpoint a failure is an OAuth error, HTTP 400; elsewhere it
   * is HTTP 401 with the `DPoP` challenge.
   */
  async #dpop(request: CompanyRequest, accessToken?: string): Promise<string> {
    const status = accessToken === undefined ? 400 : 401;
    const proof = request.headers.dpop;
    if (!proof) throw new Refused(status, "invalid_dpop_proof");
    let verified: Awaited<ReturnType<typeof verifyDpopProof>>;
    try {
      verified = await verifyDpopProof(proof, {
        method: request.method,
        url: request.url,
        replayCache: this.#replay(),
        ...(accessToken === undefined ? {} : { accessToken: new SecretValue(accessToken) }),
        now: this.#now(),
      });
    } catch (error) {
      if (error instanceof ProofError) throw new Refused(status, error.code);
      throw error;
    }
    if (this.config.dpopNonce && !(await this.#nonceIssued(verified.nonce))) {
      throw new Refused(status, "use_dpop_nonce", {}, { "DPoP-Nonce": await this.#issueNonce() });
    }
    return verified.keyThumbprint;
  }

  async #issueNonce(): Promise<string> {
    const nonce = this.#id("nonce");
    await this.store.put(
      RecordKinds.dpopNonce,
      nonce,
      json({} satisfies IssuedNonce),
      expiry(this.#later(this.config.dpopNonceLifetimeSeconds)),
    );
    return nonce;
  }

  async #nonceIssued(nonce: string | undefined): Promise<boolean> {
    return nonce !== undefined && (await this.store.get(RecordKinds.dpopNonce, nonce)) !== undefined;
  }

  /**
   * The token endpoint: every grant carries a proof, whose key names the Session (§4.3).
   *
   * The JWT bearer grant starts a Session with a new key or renews the one a known key
   * names; the refresh grant signs in the key's Session, or starts one signed in with a
   * new key; the code and device grants sign in the Session their code is bound to;
   * Token Exchange turns a DPoP Session Token into a Bearer one for an MCP server without
   * DPoP, and nothing else issues a Bearer token.
   */
  async #token(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const grant = form.grant_type;
    const clientId = await this.#client(form);
    const thumbprint = await this.#dpop(request);
    if (grant === TOKEN_EXCHANGE_GRANT && this.#bearerMcpResource(form)) {
      return this.#exchangeGrant(form, clientId, thumbprint);
    }
    if (grant === TOKEN_EXCHANGE_GRANT || this.#bearerMcpResource(form)) {
      // Token Exchange only for an MCP server without DPoP, and such a server's tokens
      // only by Token Exchange (§4.3).
      throw new Refused(400, "invalid_target");
    }
    if (grant === JWT_BEARER_GRANT) return this.#sessionGrant(form, clientId, thumbprint);
    if (grant === REFRESH_TOKEN_GRANT) return this.#refreshGrant(form, clientId, thumbprint);
    if (grant === AUTHORIZATION_CODE_GRANT && this.config.direct) {
      return this.#codeGrant(form, clientId, thumbprint);
    }
    if (grant === DEVICE_CODE_GRANT && this.config.device) {
      return this.#deviceGrant(form, clientId, thumbprint);
    }
    throw new Refused(400, "unsupported_grant_type");
  }

  /** Whether `resource` names the MCP server that doesn't support DPoP (§4.3). */
  #bearerMcpResource(form: Readonly<Record<string, string>>): boolean {
    return this.#mcp() !== undefined && !this.config.mcpDpop && form.resource === this.config.mcpUrl;
  }

  /** The `resource` a token is issued for (RFC 8707): one this company serves. */
  #resource(form: Readonly<Record<string, string>>): string | undefined {
    const resource = form.resource;
    if (resource !== undefined && resource !== this.config.mcpUrl && resource !== this.config.base) {
      throw new Refused(400, "invalid_target");
    }
    return resource;
  }

  /** The scopes that read the account: the company's scopes that change nothing. */
  #accountScopes(): readonly string[] {
    const read = this.config.scopes.filter((scope) => !this.config.writeScopes.includes(scope));
    return read.length ? read : this.config.scopes;
  }

  /**
   * Which of a Session's tokens this is: its own, or its token for the MCP server.
   *
   * A Session has one of each at a time (§4.3); a new one replaces only its kind.
   */
  #kind(session: IssuedSession): TokenKind {
    return session.resource !== undefined && session.resource === this.config.mcpUrl ? "mcp" : "own";
  }

  /** Start a Session with a new key, or renew the signed-out one a known key names (§4.2). */
  async #sessionGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const resolver = firstContribution(this.reactor, ClientResolvers, "client");
    const [, keys] = await resolver.resolve(clientId, keyId(form.assertion ?? ""));
    const claims = await verifyAssertion(form.assertion ?? "", {
      keys,
      issuer: clientId,
      audience: this.config.base,
      replayCache: this.#replay(),
      now: this.#now(),
      error: "invalid_grant",
    });
    const pairwise = String(claims.sub);
    const agentId = claims.agent_id;
    if (agentId !== undefined && (typeof agentId !== "string" || !OPAQUE_ID.test(agentId))) {
      throw new Refused(400, "invalid_grant");
    }
    const resource = this.#resource(form);
    const known = await this.#sessionByKey(thumbprint);
    if (known === undefined) {
      const session: IssuedSession = {
        sessionKey: thumbprint,
        clientId,
        pairwiseUserId: pairwise,
        keyThumbprint: thumbprint,
        expiresAt: this.#later(this.config.sessionLifetimeSeconds).toISOString(),
        scopes: [],
        ...(resource === undefined ? {} : { resource }),
        ...(agentId === undefined ? {} : { agentId }),
      };
      const started = await this.#issue(session);
      this.#reportSession(session, false, resource !== undefined);
      return started;
    }
    if (known.clientId !== clientId || known.pairwiseUserId !== pairwise) {
      // The key names another agent's or user's Session (§4.2).
      throw new Refused(400, "invalid_grant");
    }
    if (known.agentId !== agentId) {
      // A Session keeps the Agent ID it started with, or none (§4.2).
      throw new Refused(400, "invalid_grant");
    }
    // Renewal with the assertion gives a signed-out token; a signed-in Session is renewed
    // with its Account Token instead (§4.2, §4.8).
    const {
      accountId: _account,
      accountToken: _token,
      resource: _resource,
      tokenType: _type,
      ...signedOut
    } = known;
    const session: IssuedSession = {
      ...signedOut,
      expiresAt: this.#later(this.config.sessionLifetimeSeconds).toISOString(),
      scopes: [],
      ...(resource === undefined ? {} : { resource }),
    };
    const renewed = await this.#issue(session, { replacing: [this.#kind(session)] });
    this.#reportSession(session, true, resource !== undefined);
    return renewed;
  }

  /** Sign in the key's Session with an Account Token, or start one signed in (§4.8). */
  async #refreshGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const resource = this.#resource(form);
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
    if (await this.#signInEnded(grant)) {
      throw new Refused(400, "invalid_grant");
    }
    let session = await this.#sessionByKey(thumbprint);
    if (session === undefined) {
      // A new key: a new Session, already signed in, with no Agent ID (§4.2, §4.8).
      session = {
        sessionKey: thumbprint,
        clientId,
        pairwiseUserId: grant.pairwiseUserId,
        keyThumbprint: thumbprint,
        expiresAt: this.#later(this.config.sessionLifetimeSeconds).toISOString(),
        scopes: [],
      };
    } else if (session.clientId !== clientId || session.pairwiseUserId !== grant.pairwiseUserId) {
      throw new Refused(400, "invalid_grant");
    } else {
      await this.#checkAccount(session.sessionKey, grant.accountId);
    }
    const requested = words(form.scope);
    if (requested.length && requested.some((scope) => !grant.scopes.includes(scope))) {
      throw new Refused(400, "invalid_scope");
    }
    if (!this.#offers(requested.length ? requested : grant.scopes)) {
      // A scope the company no longer offers (a rollback, a narrower version): asked
      // within what it offers now, the same Account Token still serves.
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
    if (!(await this.#joinFamily(grant.family, digest(rotated), session.sessionKey))) {
      // The sign-in was revoked meanwhile: its new token is too.
      await this.#revokeGrants([digest(rotated)]);
      throw new Refused(400, "invalid_grant");
    }
    // The resource is what this refresh asked for, never one an earlier refresh named.
    const { resource: _earlier, tokenType: _type, ...unbound } = session;
    const signedIn: IssuedSession = {
      ...unbound,
      accountId: grant.accountId,
      scopes: requested.length ? requested : grant.scopes,
      accountToken: digest(rotated),
      expiresAt: this.#later(this.config.sessionLifetimeSeconds).toISOString(),
      ...(resource === undefined ? {} : { resource }),
    };
    const response = await this.#issue(signedIn, {
      refreshToken: rotated,
      replacing: [this.#kind(signedIn)],
      // A refresh naming no scope gets them in the response: the agent can't know.
      requested,
      accountTokenExpiresAt: grant.expiresAt,
    });
    const family = await this.#read<AccountFamily>(RecordKinds.accountFamily, grant.family);
    if (family === undefined || family.revoked) {
      // Revoked while this token was issued: the Session continues signed out (§4.9).
      await this.#signOutSession(session.sessionKey, [digest(rotated)]);
      throw new Refused(400, "invalid_grant");
    }
    this.#reportSession(signedIn, true, resource !== undefined);
    return response;
  }

  /**
   * A Bearer Session Token for the MCP server without DPoP, by Token Exchange (§4.3).
   *
   * The subject token is a current DPoP Session Token of the same agent, bound to the
   * proof's key; the answer belongs to the same Session, with its scopes or the fewer
   * `scope` asks for, and works only at that server.
   */
  async #exchangeGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    if (form.subject_token_type !== ACCESS_TOKEN_TYPE) throw new Refused(400, "invalid_request");
    const subject = await this.#tokenSession(form.subject_token ?? "");
    if (
      subject === undefined ||
      subject.tokenType === "Bearer" ||
      subject.clientId !== clientId ||
      subject.keyThumbprint !== thumbprint ||
      this.#passed(subject.expiresAt) ||
      this.#kind(subject) !== "own"
    ) {
      throw new Refused(400, "invalid_grant");
    }
    const requested = words(form.scope);
    if (requested.some((scope) => !subject.scopes.includes(scope))) {
      throw new Refused(400, "invalid_scope");
    }
    const lifetime = this.#later(this.config.sessionLifetimeSeconds).getTime();
    const bearer: IssuedSession = {
      ...subject,
      tokenType: "Bearer",
      keyThumbprint: "",
      resource: this.config.mcpUrl,
      scopes: requested.length ? requested : subject.scopes,
      expiresAt: new Date(Math.min(Date.parse(subject.expiresAt), lifetime)).toISOString(),
    };
    const response = await this.#issue(bearer, {
      replacing: [this.#kind(bearer)],
      requested,
      exchanged: true,
    });
    this.#reportSession(bearer, false, true);
    return response;
  }

  async #device(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const clientId = await this.#client(form);
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
      if (pending.sessionKey !== undefined && pending.sessionKey !== thumbprint) {
        // Bound to the key of its first poll: any other key is refused (§4.6).
        throw new Refused(400, "invalid_grant");
      }
      const bound: PendingDevice =
        pending.sessionKey === undefined ? { ...pending, sessionKey: thumbprint } : pending;
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
        next = { ...bound, interval: pending.interval + 5, lastPoll: now.toISOString() };
        refusal = "slow_down";
      } else if (pending.accountId === undefined) {
        next = { ...bound, lastPoll: now.toISOString() };
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
    // Approved: the Session the bound key names is signed in (§4.6).
    const session = await this.#sessionByKey(thumbprint);
    if (session === undefined || session.clientId !== clientId) {
      throw new Refused(400, "invalid_grant");
    }
    // Consumed once: of concurrent polls, only the one that takes it signs in.
    const approved = (await this.store.take(RecordKinds.device, key)) as unknown as
      | PendingDevice
      | undefined;
    if (approved === undefined || approved.accountId === undefined) {
      throw new Refused(400, "invalid_grant");
    }
    await this.store.delete(RecordKinds.userCode, approved.userCode);
    return this.#signIn(session, approved.accountId, approved.granted, thumbprint, approved.scopes);
  }

  async #forgetDevice(key: string, pending: PendingDevice): Promise<void> {
    await this.store.delete(RecordKinds.device, key);
    await this.store.delete(RecordKinds.userCode, pending.userCode);
  }

  async #revoke(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const clientId = await this.#client(form);
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
      if (!changed[0].revoked) {
        // A whole sign-in ended: by its agent, a password reset, or its host.
        this.#report("pap.company.sign_out", "ok", { "pap.session.signed_in": false });
      }
      revoked += await this.#revokeGrants(family.tokens);
      for (const sessionKey of family.sessions) {
        await this.#signOutSession(sessionKey, family.tokens);
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
  async #signOutSession(sessionKey: string, accountTokens: readonly string[]): Promise<void> {
    await this.#change<StoredSession>(RecordKinds.session, sessionKey, (stored) => {
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
  async #joinFamily(familyId: string, token: string, sessionKey: string): Promise<boolean> {
    const changed = await this.#change<AccountFamily>(
      RecordKinds.accountFamily,
      familyId,
      (family) =>
        family.revoked
          ? family
          : {
              ...family,
              tokens: withItem(family.tokens, token),
              sessions: withItem(family.sessions, sessionKey),
            },
    );
    return changed !== undefined && !changed[1].revoked;
  }

  /**
   * Sign the Session in: `session` is its DPoP record, `thumbprint` the proven key.
   *
   * `scopes` are the ones the user approved of those `requested`; the response leaves
   * `scope` out when they are the same (§4.4, RFC 6749 §5.1).
   */
  async #signIn(
    session: IssuedSession,
    accountId: string,
    scopes: readonly string[],
    thumbprint: string,
    requested: readonly string[],
  ): Promise<CompanyResponse> {
    if (!scopes.length) {
      // A sign-in grants at least one scope: approving none is a decline (§4.4).
      throw new Refused(400, "access_denied");
    }
    // Checked before anything is issued: a mismatch issues no tokens (§4.4).
    await this.#checkAccount(session.sessionKey, accountId);
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
      signedInAt: this.#now().toISOString(),
    };
    await this.store.put(RecordKinds.accountToken, family, json(grant), expiry(expiresAt));
    const signIn: AccountFamily = {
      clientId: session.clientId,
      accountId,
      tokens: [family],
      sessions: [session.sessionKey],
      revoked: false,
    };
    await this.store.put(RecordKinds.accountFamily, family, json(signIn), expiry(expiresAt));
    await this.#rememberFamily(session.clientId, accountId, family);
    // The signed-in token is the Session's own: DPoP, bound to the key that proved
    // possession, for no single resource. It replaces only that token; a token for the
    // MCP server is renewed with the Account Token (§4.3, §4.8).
    const signedIn: IssuedSession = {
      sessionKey: session.sessionKey,
      clientId: session.clientId,
      pairwiseUserId: session.pairwiseUserId,
      keyThumbprint: thumbprint,
      expiresAt: session.expiresAt,
      accountId,
      scopes,
      accountToken: family,
      ...(session.agentId === undefined ? {} : { agentId: session.agentId }),
    };
    return this.#issue(signedIn, {
      refreshToken: accountToken,
      replacing: [this.#kind(signedIn)],
      requested,
      accountTokenExpiresAt: expiresAt.toISOString(),
    });
  }

  /**
   * A Session that was ever signed in to another account is `account_mismatch` (§4.4).
   *
   * Even signed out since (§4.9): the code exchange, the device poll, Mediated Sign-In,
   * and an Account Token all refuse, and issue nothing.
   */
  async #checkAccount(sessionKey: string, accountId: string): Promise<void> {
    const stored = await this.#read<StoredSession>(RecordKinds.session, sessionKey);
    if (stored?.accountId !== undefined && stored.accountId !== accountId) {
      throw new Refused(400, "account_mismatch");
    }
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

  /**
   * Issue a token for the Session; it replaces the Session's tokens of `replacing` kinds.
   *
   * The response names no Session: its key does (§4.3). `scope` follows RFC 6749: left
   * out of a signed-out token's response, and of a signed-in one granting exactly the
   * scopes `requested` (§4.2, §4.4).
   */
  async #issue(
    session: IssuedSession,
    options: {
      readonly refreshToken?: string;
      readonly replacing?: readonly TokenKind[];
      readonly requested?: readonly string[];
      readonly accountTokenExpiresAt?: string;
      readonly exchanged?: boolean;
    } = {},
  ): Promise<CompanyResponse> {
    const accessToken = this.#id("sat");
    const key = digest(accessToken);
    await this.#recordToken(session, key, options.replacing ?? []);
    const pointer: SessionPointer = { sessionKey: session.sessionKey };
    await this.store.put(RecordKinds.sessionToken, key, json(pointer), expiry(session.expiresAt));
    const body: Record<string, unknown> = {
      access_token: accessToken,
      token_type: session.tokenType ?? "DPoP",
      expires_in: Math.trunc((new Date(session.expiresAt).getTime() - this.#now().getTime()) / 1000),
    };
    const requested = new Set(options.requested ?? []);
    const granted = new Set(session.scopes);
    if (granted.size && (granted.size !== requested.size || [...granted].some((scope) => !requested.has(scope)))) {
      body.scope = session.scopes.join(" ");
    }
    if (options.exchanged) body.issued_token_type = ACCESS_TOKEN_TYPE;
    if (options.refreshToken !== undefined) {
      body.refresh_token = options.refreshToken;
      if (options.accountTokenExpiresAt !== undefined) {
        // So the agent tells an expired Account Token from a revoked one (guides).
        body.refresh_token_expires_in = Math.trunc(
          (Date.parse(options.accountTokenExpiresAt) - this.#now().getTime()) / 1000,
        );
      }
    }
    return { status: 200, body, headers: { ...NO_STORE } };
  }

  /**
   * One write: the new token joins the Session, the ones it replaces leave it.
   *
   * `replacing` names token kinds (`#kind`): the Session's own token, or its token for one
   * resource. A signed-in token records the account the Session is tied to from then on,
   * signed out or not (§4.4).
   */
  async #recordToken(
    session: IssuedSession,
    key: string,
    replacing: readonly TokenKind[],
  ): Promise<void> {
    for (let attempt = 0; attempt < CAS_ATTEMPTS; attempt += 1) {
      const entry = await this.store.get(RecordKinds.session, session.sessionKey);
      const tokens: Record<string, IssuedSession> = {};
      let accountId = session.accountId;
      if (entry !== undefined) {
        const current = entry.value as unknown as StoredSession;
        if (
          session.accountId !== undefined &&
          current.accountId !== undefined &&
          current.accountId !== session.accountId
        ) {
          throw new Refused(400, "account_mismatch");
        }
        accountId = current.accountId ?? session.accountId;
        for (const [held, token] of Object.entries(current.tokens)) {
          if (!replacing.includes(this.#kind(token))) tokens[held] = token;
        }
      }
      tokens[key] = session;
      // A Session ends once no Account Token could renew it any more; its record is kept
      // past its end, so its key is refused rather than reused (§4.2).
      const latest = Math.max(...Object.values(tokens).map((token) => Date.parse(token.expiresAt)));
      const endsAt = new Date(latest + this.config.accountTokenLifetimeSeconds * 1000);
      const stored: StoredSession = {
        sessionKey: session.sessionKey,
        clientId: session.clientId,
        pairwiseUserId: session.pairwiseUserId,
        tokens,
        latest: key,
        ...(accountId === undefined ? {} : { accountId }),
        endsAt: endsAt.toISOString(),
      };
      const kept = expiry(new Date(endsAt.getTime() + this.config.endedSessionMemorySeconds * 1000));
      if (entry === undefined) {
        if (await this.store.create(RecordKinds.session, session.sessionKey, json(stored), kept)) {
          return;
        }
        continue;
      }
      if (
        await this.store.replace(RecordKinds.session, session.sessionKey, entry.version, json(stored), kept)
      ) {
        return;
      }
    }
    throw new Refused(503, "temporarily_unavailable");
  }

  /**
   * The Session a key's thumbprint names, or `undefined` for a key never seen (§4.3).
   *
   * A key whose Session has ended is refused, `invalid_grant`, rather than starting a new
   * Session the agent would not know of (§4.2).
   */
  async #sessionByKey(sessionKey: string): Promise<IssuedSession | undefined> {
    const stored = await this.#read<StoredSession>(RecordKinds.session, sessionKey);
    if (stored?.endsAt !== undefined && this.#passed(stored.endsAt)) {
      throw new Refused(400, "invalid_grant");
    }
    return this.#sessionRecord(sessionKey);
  }

  /**
   * The Session by its key: its own latest token's record, else its token for MCP.
   *
   * A token for the MCP server stands for the Session only there (§4.3): a grant naming
   * the Session builds on the record of its own token, and on the MCP one only when the
   * Session was started for the MCP server alone. Every grant replaces what a record says
   * of the token (its key, type, resource, account, and lifetime); only the Session's
   * identity is read.
   */
  async #sessionRecord(sessionKey: string): Promise<IssuedSession | undefined> {
    const stored = await this.#read<StoredSession>(RecordKinds.session, sessionKey);
    if (stored === undefined) return undefined;
    const latest = stored.tokens[stored.latest];
    if (latest !== undefined && this.#kind(latest) === "own") return latest;
    let own: IssuedSession | undefined;
    let any: IssuedSession | undefined;
    for (const token of Object.values(stored.tokens)) {
      if (any === undefined || Date.parse(token.expiresAt) > Date.parse(any.expiresAt)) any = token;
      if (this.#kind(token) !== "own") continue;
      if (own === undefined || Date.parse(token.expiresAt) > Date.parse(own.expiresAt)) own = token;
    }
    if (own !== undefined) return own;
    if (any === undefined) return undefined;
    const { accountId: _account, accountToken: _token, resource: _resource, ...base } = any;
    return { ...base, scopes: [] };
  }

  /** The state of the Session token `token`, while the Session still holds it. */
  async #tokenSession(token: string): Promise<IssuedSession | undefined> {
    const key = digest(token);
    const pointer = await this.#read<SessionPointer>(RecordKinds.sessionToken, key);
    if (pointer === undefined) return undefined;
    const stored = await this.#read<StoredSession>(RecordKinds.session, pointer.sessionKey);
    const session = stored?.tokens[key];
    if (session !== undefined && (await this.#signedInBeforeItsEnd(session))) return undefined;
    return session;
  }

  /** Whether this signed-in token's sign-in ended since (`signedOutBefore`); ends it if so. */
  async #signedInBeforeItsEnd(session: IssuedSession): Promise<boolean> {
    if (session.accountId === undefined || session.accountToken === undefined) return false;
    const grant = await this.#read<AccountGrant>(RecordKinds.accountToken, session.accountToken);
    if (grant === undefined) {
      // Its Account Token is gone (expired, deleted): nothing to hold it to.
      return (await this.#signedOutBefore(session.accountId)) !== undefined;
    }
    return this.#signInEnded(grant);
  }

  async #signedOutBefore(accountId: string): Promise<Date | undefined> {
    const accounts = optionalContribution(this.reactor, CompanyAccounts, "accounts");
    return accounts?.signedOutBefore === undefined ? undefined : accounts.signedOutBefore(accountId);
  }

  /**
   * Whether the account's sign-ins ended after this one: then it ends, whole — a password
   * reset, an account locked: its Account Tokens revoked, the Sessions signed in with them
   * continuing signed out (`#signOut`).
   */
  async #signInEnded(grant: AccountGrant): Promise<boolean> {
    const before = await this.#signedOutBefore(grant.accountId);
    if (before === undefined) return false;
    if (grant.signedInAt !== undefined && new Date(grant.signedInAt) >= before) return false;
    await this.#signOut([grant.family]);
    return true;
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
    // Exactly, but a loopback redirect URI matches with any port (§4.5, RFC 8252 §7.3).
    if (!metadata.redirect_uris.some((entry) => redirectUriMatches(entry, redirectUri))) {
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
    if (!THUMBPRINT.test(query.dpop_jkt ?? "")) {
      // The code is bound to the Session Key: without one it could sign in no Session
      // (§4.5, RFC 9449 §10).
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
      dpopJkt: query.dpop_jkt as string,
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
      .map((scope) => `<li>${escapeHtml(this.config.scopeDescriptions[scope] ?? scope)}</li>`)
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
   * `scopeDescriptions` words), until when; never `state`, PKCE, or the redirect. Rejects
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
      scopes: pending.scopes.map((scope) => ({ scope, description: this.config.scopeDescriptions[scope] ?? scope })),
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
      dpopJkt: pending.dpopJkt,
      requested: pending.scopes,
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
      issued.redirectUri !== form.redirect_uri ||
      issued.dpopJkt !== thumbprint
    ) {
      // Expired, reused, or redeemed with another key than the one it is bound to.
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
    const session = await this.#sessionByKey(thumbprint);
    if (session === undefined || session.clientId !== clientId) {
      throw new Refused(400, "invalid_grant");
    }
    return this.#signIn(session, issued.accountId, issued.scopes, thumbprint, issued.requested);
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
    const key = request.headers["idempotency-key"];
    if (key === undefined || !WRITE_METHODS.has(method)) {
      return await this.#apiAnswer(request, api, method, path, session, body);
    }
    // A write with an Idempotency-Key (guides, *Retries*): remembered per Session for
    // `idempotencyLifetimeSeconds`, a repeat answered with the original response.
    if (!IDEMPOTENCY_KEY.test(key)) throw new Refused(400, "invalid_request");
    const record = composite(session.sessionKey, key);
    const requestDigest = composite(method, path, new URL(request.url).search, canonical(body ?? null));
    const earlier = await this.#holdIdempotencyKey(record, requestDigest);
    if (earlier !== undefined) return earlier;
    let response: CompanyResponse;
    try {
      response = await this.#apiAnswer(request, api, method, path, session, body);
    } catch (error) {
      await this.store.delete(RecordKinds.idempotency, record);
      throw error;
    }
    if (response.status >= 200 && response.status < 300) {
      const answered: IdempotencyRecord = {
        digest: requestDigest,
        status: response.status,
        ...(response.body === undefined ? {} : { body: response.body }),
      };
      await this.store.put(
        RecordKinds.idempotency,
        record,
        json(answered),
        expiry(this.#later(this.config.idempotencyLifetimeSeconds)),
      );
    } else {
      // A refusal is not remembered: the retry, once signed in or granted, is new.
      await this.store.delete(RecordKinds.idempotency, record);
    }
    return response;
  }

  /**
   * Hold the key for this request: `undefined` when held, else the answer to a repeat.
   *
   * A repeat with another request is `409 idempotency_key_conflict`; a repeat while the
   * first is under way waits (`503`, `Retry-After`).
   */
  async #holdIdempotencyKey(record: string, requestDigest: string): Promise<CompanyResponse | undefined> {
    const held: IdempotencyRecord = { digest: requestDigest };
    for (let attempt = 0; attempt < CAS_ATTEMPTS; attempt += 1) {
      if (
        await this.store.create(
          RecordKinds.idempotency,
          record,
          json(held),
          expiry(this.#later(IDEMPOTENCY_HELD_SECONDS)),
        )
      ) {
        return undefined;
      }
      const known = await this.#read<IdempotencyRecord>(RecordKinds.idempotency, record);
      if (known === undefined) continue;
      if (known.digest !== requestDigest) throw new Refused(409, "idempotency_key_conflict");
      if (known.status === undefined) {
        throw new Refused(503, "temporarily_unavailable", {}, { "Retry-After": "1" });
      }
      return { status: known.status, body: known.body, headers: {} };
    }
    throw new Refused(503, "temporarily_unavailable");
  }

  async #apiAnswer(
    request: CompanyRequest,
    api: CompanyApi,
    method: string,
    path: string,
    session: IssuedSession,
    body: unknown,
  ): Promise<CompanyResponse> {
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
    if (session.accountId === undefined) throw insufficientScope(this.config.writeScopes);
    if (!(await this.#supportsOperations(session.clientId))) {
      // At an API, in the WWW-Authenticate challenge with its `extension` (§3.3, §6).
      throw new Refused(
        403,
        "extension_required",
        { extension: "operations" },
        { "WWW-Authenticate": 'DPoP error="extension_required", extension="operations"' },
      );
    }
    const operation = await this.#propose(session, { operation: result.operation });
    return { status: 202, body: { operation }, headers: {} };
  }

  // MCP (§4.3, §6, Operations §4.2) -------------------------------------------------------

  #mcp(): CompanyMcp | undefined {
    return optionalContribution(this.reactor, CompanyMcps, "MCP server");
  }

  /**
   * A token refusal at the MCP server: one challenge per scheme it accepts (§6).
   *
   * `Bearer`, and `DPoP` when it supports DPoP, each with `resource_metadata` (RFC 9728
   * §5.1) and the error's `scope`.
   */
  #mcpRefusal(
    status: number,
    error: string,
    scope?: string,
    headers: Readonly<Record<string, string>> = {},
  ): CompanyResponse {
    const extra: Record<string, unknown> = { resource_metadata: this.config.mcpResourceMetadata };
    if (scope !== undefined) extra.scope = scope;
    const schemes = this.config.mcpDpop ? ["Bearer", "DPoP"] : ["Bearer"];
    return {
      status,
      body: scope === undefined ? { error } : { error, scope },
      headers: {
        "WWW-Authenticate": schemes.map((scheme) => challenge(scheme, error, extra)).join(", "),
        ...NO_STORE,
        ...headers,
      },
    };
  }

  /**
   * The Session of a token issued for this MCP server, else its refusal (§4.3, §6).
   *
   * A Bearer token issued for its url (from a personal agent when it doesn't support
   * DPoP, or from an MCP client that doesn't implement the protocol), or, when it
   * supports DPoP, a DPoP token issued for its url with a valid proof. A DPoP token sent
   * with the `Bearer` scheme is refused (RFC 9449 §7.1).
   */
  async #mcpCaller(request: CompanyRequest): Promise<IssuedSession | CompanyResponse> {
    const authorization = request.headers.authorization ?? "";
    const space = authorization.indexOf(" ");
    const scheme = space < 0 ? authorization : authorization.slice(0, space);
    const token = space < 0 ? "" : authorization.slice(space + 1);
    const accepted = this.config.mcpDpop ? ["Bearer", "DPoP"] : ["Bearer"];
    if (!accepted.includes(scheme) || !token) return this.#mcpRefusal(401, "invalid_token");
    const session = await this.#tokenSession(token);
    if (
      session === undefined ||
      this.#passed(session.expiresAt) ||
      (session.tokenType ?? "DPoP") !== scheme ||
      session.resource !== this.config.mcpUrl ||
      !this.#offers(session.scopes) ||
      !(await this.#allowed(session.clientId))
    ) {
      return this.#mcpRefusal(401, "invalid_token");
    }
    if (scheme === "DPoP") {
      let thumbprint: string;
      try {
        thumbprint = await this.#dpop(request, token);
      } catch (error) {
        if (error instanceof Refused) return this.#mcpRefusal(401, error.error, undefined, error.headers);
        throw error;
      }
      if (thumbprint !== session.keyThumbprint) return this.#mcpRefusal(401, "invalid_dpop_proof");
    }
    return session;
  }

  /**
   * Whether this company offers every one of these scopes now. A Session holding
   * a scope it no longer offers (rolled back to a version without it, or
   * narrowed) is refused as `invalid_token`, so the personal agent starts a new
   * one within what is offered; an Account Token refreshed for such a scope is
   * `invalid_scope`, and serves again when asked within what is offered.
   */
  #offers(scopes: readonly string[]): boolean {
    return scopes.every((scope) => this.config.scopes.includes(scope));
  }

  async #mcpRoute(request: CompanyRequest, mcp: CompanyMcp): Promise<CompanyResponse> {
    const session = await this.#mcpCaller(request);
    // A missing, expired, or other-resource token, or a token in the wrong scheme.
    if (!("sessionKey" in session)) return session;
    const wait = await this.#admitted(session);
    if (wait !== undefined) return rateLimited(wait);
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
      return { refused: this.#mcpRefusal(status, error, scope) };
    }
    if (answer.operation !== undefined) {
      if (session.accountId === undefined) {
        return {
          refused: this.#mcpRefusal(403, "insufficient_scope", this.config.writeScopes.join(" ")),
        };
      }
      if (!(await this.#supportsOperations(session.clientId))) {
        // A tool can't be refused with `extension_required`, which refuses the personal
        // agent entirely: an ordinary tool error (Operations §2, §6).
        return {
          result: {
            content: [
              {
                type: "text",
                text: "This tool needs the Operations extension, which your agent doesn't list.",
              },
            ],
            isError: true,
          },
        };
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
    if (
      session === undefined ||
      this.#passed(session.expiresAt) ||
      session.tokenType === "Bearer" ||
      this.#kind(session) === "mcp"
    ) {
      // A token for the MCP server, Bearer or DPoP, works only there (§4.3).
      throw new Refused(401, "invalid_token");
    }
    if (!this.#offers(session.scopes)) {
      // The company no longer offers a scope this Session holds (a rollback, a narrower
      // version): the Session ends here, and a new one is the way back.
      throw new Refused(401, "invalid_token");
    }
    if (!(await this.#allowed(session.clientId))) throw new Refused(401, "invalid_token");
    const thumbprint = await this.#dpop(request, token);
    if (thumbprint !== session.keyThumbprint) throw new Refused(401, "invalid_dpop_proof");
    const wait = await this.#admitted(session);
    if (wait !== undefined) throw new RateLimitedRefusal(wait);
    return [key, session];
  }

  /** The host's rate limit on this agent and its signed-in account: seconds to wait, or undefined. */
  async #admitted(session: IssuedSession): Promise<number | undefined> {
    const limit = optionalContribution(this.reactor, CompanyRateLimits, "rate limit");
    if (limit === undefined) return undefined;
    const wait = await limit.admit(session.clientId, session.accountId);
    return wait === undefined ? undefined : Math.max(1, Math.trunc(wait));
  }

  // Mediated Sign-In attempt limits (§4.7: a company MUST rate-limit attempts) -----------

  /**
   * What a credential attempt counts against: the account, the agent's user, the Session.
   * The account is named by the declared fields that are not secret (an email, a
   * username), normalized; its password is never part of a key.
   */
  #attemptKeys(session: IssuedSession, credentials: Readonly<Record<string, unknown>>): string[] {
    const keys = [
      composite("user", session.clientId, session.pairwiseUserId),
      composite("session", session.sessionKey),
    ];
    const named = this.config.mediatedFields
      .filter(([, , secret]) => !secret)
      .map(([name]) => String(credentials[name] ?? "").trim().toLowerCase());
    if (named.some(Boolean)) keys.unshift(composite("account", ...named));
    return keys;
  }

  #codeKey(accountId: string): string {
    return composite("code", accountId);
  }

  /** Seconds until every key may try again, or `undefined` when none is locked out. */
  async #lockedFor(keys: readonly string[]): Promise<number | undefined> {
    const now = this.#now().getTime();
    let wait: number | undefined;
    for (const key of keys) {
      const attempts = await this.#read<SignInAttempts>(RecordKinds.signInAttempts, key);
      if (attempts?.lockedUntil === undefined) continue;
      const left = Date.parse(attempts.lockedUntil) - now;
      if (left > 0) wait = Math.max(wait ?? 0, left);
    }
    return wait === undefined ? undefined : Math.max(1, Math.ceil(wait / 1000));
  }

  /** Count one failure against each key; at the limit, lock it out, doubling each time. */
  async #attemptFailed(keys: readonly string[]): Promise<void> {
    const config = this.config;
    for (const key of keys) {
      let written = false;
      for (let attempt = 0; attempt < CAS_ATTEMPTS && !written; attempt += 1) {
        const now = this.#now().getTime();
        const entry = await this.store.get(RecordKinds.signInAttempts, key);
        const before: SignInAttempts = (entry?.value as unknown as SignInAttempts | undefined) ?? {
          failures: 0,
        };
        const failures = before.failures + 1;
        let lockedUntil = before.lockedUntil;
        if (failures >= config.maxSignInFailures) {
          const over = Math.min(failures - config.maxSignInFailures, 7);
          const seconds = Math.min(config.signInLockoutSeconds * 2 ** over, 24 * 60 * 60);
          lockedUntil = new Date(now + seconds * 1000).toISOString();
        }
        const after: SignInAttempts = lockedUntil === undefined ? { failures } : { failures, lockedUntil };
        // Forgotten once the key has failed nothing for a lockout's length.
        const until = Math.max(now, lockedUntil === undefined ? now : Date.parse(lockedUntil));
        const kept = { expiresAt: new Date(until + config.signInLockoutSeconds * 1000) };
        written =
          entry === undefined
            ? await this.store.create(RecordKinds.signInAttempts, key, json(after), kept)
            : await this.store.replace(RecordKinds.signInAttempts, key, entry.version, json(after), kept);
      }
      if (!written) throw new Refused(503, "temporarily_unavailable");
    }
  }

  async #attemptsCleared(keys: readonly string[]): Promise<void> {
    for (const key of keys) await this.store.delete(RecordKinds.signInAttempts, key);
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
    const keys = this.#attemptKeys(session, credentials);
    const locked = await this.#lockedFor(keys);
    if (locked !== undefined) {
      // Locked out: the credentials are not even checked (§4.2, `rate_limited`).
      for (const name of Object.keys(credentials)) delete credentials[name];
      return rateLimited(locked);
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
    const authenticated = await accounts.authenticate(secrets, {
      clientId: session.clientId,
      sessionKey: session.sessionKey,
    });
    for (const name of Object.keys(secrets)) delete secrets[name];
    if (authenticated === undefined) {
      await this.#attemptFailed(keys);
      return { status: 200, body: { status: "failed" }, headers: { ...NO_STORE } };
    }
    // Tied to another account, even signed out since: refused before any code is sent.
    await this.#checkAccount(session.sessionKey, authenticated.accountId);
    if (authenticated.codeReference === undefined) {
      await this.#attemptsCleared(keys);
      return this.#signedInBody(session, authenticated.accountId, granted);
    }
    const codeLocked = await this.#lockedFor([this.#codeKey(authenticated.accountId)]);
    // Too many wrong codes for this account: no new code until the lockout ends.
    if (codeLocked !== undefined) return rateLimited(codeLocked);
    const signInId = this.#id("si");
    const expiresAt = this.#later(5 * 60);
    const pending: PendingMediated = {
      sessionKey: session.sessionKey,
      accountId: authenticated.accountId,
      scopes: granted,
      codeReference: authenticated.codeReference,
      expiresAt: expiresAt.toISOString(),
      attemptKeys: keys,
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
    if (pending === undefined || pending.sessionKey !== session.sessionKey) {
      // Unknown, or another Session's: the same error for both (§4.7).
      throw new Refused(404, "sign_in_not_found");
    }
    if ((pending.status ?? "code_required") !== "code_required") {
      // Once failed or expired, it stays so: the same status again, HTTP 200 (§4.7).
      return { status: 200, body: { status: pending.status }, headers: { ...NO_STORE } };
    }
    if (this.#passed(pending.expiresAt)) return this.#mediatedEnded(signInId, "expired");
    const codeKey = this.#codeKey(pending.accountId);
    if ((await this.#lockedFor([codeKey])) !== undefined) {
      // The account's code budget is spent, whichever sign-in spent it.
      return this.#mediatedEnded(signInId, "failed");
    }
    const source = text(request.body);
    const body = source ? parseJsonStrict(source) : {};
    const code = isObject(body) ? body.code : undefined;
    const accounts = firstContribution(this.reactor, CompanyAccounts, "accounts");
    if (
      typeof code !== "string" ||
      !code ||
      !(await accounts.checkCode(pending.codeReference, new SecretValue(code)))
    ) {
      // Every wrong code counts, however many replicas check them at once: against this
      // sign-in, and against the account across every sign-in started for it.
      await this.#attemptFailed([codeKey]);
      const counted = await this.#change<PendingMediated>(
        RecordKinds.mediated,
        signInId,
        (current) => ({ ...current, attempts: current.attempts + 1 }),
      );
      if (
        counted === undefined ||
        counted[1].attempts >= this.config.maxCodeAttempts ||
        (await this.#lockedFor([codeKey])) !== undefined
      ) {
        return this.#mediatedEnded(signInId, "failed");
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
    if (completed === undefined || (completed.status ?? "code_required") !== "code_required") {
      return { status: 200, body: { status: "failed" }, headers: { ...NO_STORE } };
    }
    await this.#attemptsCleared([...completed.attemptKeys, codeKey]);
    return this.#signedInBody(session, completed.accountId, completed.scopes);
  }

  /** The sign-in ends as `status`, kept so a later code gets the same answer (§4.7). */
  async #mediatedEnded(signInId: string, status: "failed" | "expired"): Promise<CompanyResponse> {
    const changed = await this.#change<PendingMediated>(RecordKinds.mediated, signInId, (current) =>
      (current.status ?? "code_required") !== "code_required" ? current : { ...current, status },
    );
    const ended = changed === undefined ? status : (changed[1].status ?? status);
    return { status: 200, body: { status: ended }, headers: { ...NO_STORE } };
  }

  async #signedInBody(
    session: IssuedSession,
    accountId: string,
    scopes: readonly string[],
  ): Promise<CompanyResponse> {
    // Every requested scope is granted here, so `scope` is left out, as at the token
    // endpoint (§4.4, §4.7).
    const response = await this.#signIn(session, accountId, scopes, session.keyThumbprint, scopes);
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
      if (session.accountId === undefined) throw insufficientScope(this.#accountScopes());
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
    waitOf(request);
    const body = jsonObject(request.body);
    const message = incoming(body.message);
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
    if (!IDENTIFIER.test(conversationId)) {
      // An ID with characters not allowed is malformed, not unknown (§7.2, §7.13).
      throw new Refused(400, "invalid_request");
    }
    waitOf(request);
    const conversation = await this.#owned(conversationId, session);
    if (method === "GET" && action === "events") {
      if ((request.headers.accept ?? "").includes("text/event-stream")) {
        // Last-Event-ID wins over `cursor`: an SSE client adds it to the URL the stream
        // was first opened with (§7.6).
        const cursor = request.headers["last-event-id"] || queryOf(request).cursor;
        return this.#stream(conversation, cursor);
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
          if (current.status === "queued" || current.responder === "human") {
            // Already asked for, or with a person: 202, nothing changes (§7.9).
            return current;
          }
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
      const message = incoming(jsonObject(request.body).message);
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
          const account = accountId === undefined ? {} : { accountId };
          if (current.responder === "human") {
            return { ...current, ...account, events: [...current.events, received] };
          }
          // The agent works on it: every change of status adds a state event (§7).
          return {
            ...current,
            ...account,
            status: "working",
            events: [...current.events, received, this.#state("working", current.responder)],
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
      author: message.author.type,
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      scopes: session.scopes,
      clientId: session.clientId,
      isDirect: conversation.parentId !== undefined,
      supportsOperations: await this.#supportsOperations(session.clientId),
    });
    const events: StoredEvent[] = [];
    for (const reply of replies) {
      const event = await this.#reply(session, reply);
      if (event !== undefined) events.push(event);
    }
    const answered = await this.#change<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
      (current) =>
        current.status === "closed"
          ? { ...current, events: [...current.events, ...events] }
          : {
              ...current,
              status: "idle",
              events: [...current.events, ...events, this.#state("idle", current.responder)],
            },
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
      author: { type: "agent", ...(reply.persona ?? {}) },
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
    const query = queryOf(request);
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
    const cursor = queryOf(request).cursor || undefined;
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

  // Feedback (§8) -------------------------------------------------------------------

  /**
   * Accept a report with a Session Token, signed in or out, no scope needed.
   *
   * Any `kind` is accepted, so later versions can add kinds; `task` (at most 200
   * characters) and `description` (at most 2,000) are required. The text is kept as data
   * for the operator, never acted on.
   */
  async #feedback(request: CompanyRequest): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const body = jsonObject(request.body);
    const { kind, task, description } = body;
    if (
      typeof kind !== "string" ||
      !kind ||
      typeof task !== "string" ||
      !(task.length > 0 && task.length <= 200) ||
      typeof description !== "string" ||
      !(description.length > 0 && description.length <= 2000)
    ) {
      throw new Refused(400, "invalid_request");
    }
    const report: StoredFeedback = {
      reportId: this.#id("fb"),
      kind,
      task,
      description,
      clientId: session.clientId,
      pairwiseUserId: session.pairwiseUserId,
      receivedAt: this.#now().toISOString(),
    };
    await this.store.put(RecordKinds.feedback, report.reportId, json(report));
    const answers = new Map(
      Object.entries(this.config.feedbackAnswers).map(([key, value]) => [key.toLowerCase(), value]),
    );
    const alternative = answers.get(task.toLowerCase());
    if (alternative !== undefined) {
      // The task can be done after all: here is how (§8.3).
      return { status: 200, body: { ...alternative }, headers: { ...NO_STORE } };
    }
    return { status: 202, headers: { ...NO_STORE } };
  }

  /**
   * The feedback reports personal agents sent, oldest first, for the operator (§8).
   *
   * A report can be wrong or written to mislead: its text is data, never an instruction,
   * including when a model reads it.
   */
  async feedbackReports(): Promise<readonly StoredFeedback[]> {
    const reports = (await this.store.records(RecordKinds.feedback)).map(
      (record) => record.value as unknown as StoredFeedback,
    );
    return reports.sort(
      (a, b) => Date.parse(a.receivedAt) - Date.parse(b.receivedAt) || byCodePoint(a.reportId, b.reportId),
    );
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

  // One of the company's people ---------------------------------------------------

  /** A conversation as the company keeps it: its status, responder, and events. */
  async conversationRecord(conversationId: string): Promise<StoredConversation> {
    const conversation = await this.#read<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
    );
    if (conversation === undefined) throw new Error("unknown conversation");
    return conversation;
  }

  /**
   * One of the company's people answers in a conversation handed to them (§7.9).
   *
   * `after` is the ID of the last event they read: compare-and-set, so an
   * answer written over anything they have not read is refused
   * (`StaleConversationError`) and they read the conversation again. Their
   * message is the company's (`role: company`) and written by a person
   * (`author.type: human`, with the person's `id`, display `name`, and `image` when given,
   * §7.4); a conversation not handed to people, closed, or with a
   * Direct Conversation open takes none. The event written is returned: its
   * ID is their next `after`.
   */
  async staffReply(
    conversationId: string,
    reply: {
      readonly after: string;
      readonly text?: string;
      readonly data?: Readonly<Record<string, unknown>>;
      readonly authorId?: string;
      readonly authorName?: string;
      readonly authorImage?: string;
    },
  ): Promise<ConversationEvent> {
    if (reply.text === undefined && reply.data === undefined) {
      throw new Error("a reply says something: text, data, or both");
    }
    const author = parseAuthor({
      type: "human",
      ...(reply.authorId === undefined ? {} : { id: reply.authorId }),
      ...(reply.authorName === undefined ? {} : { name: reply.authorName }),
      ...(reply.authorImage === undefined ? {} : { image: reply.authorImage }),
    });
    const message: Record<string, unknown> = {
      id: this.#id("msg"),
      author: { ...author },
      role: "company",
    };
    if (reply.text !== undefined) message.text = reply.text;
    if (reply.data !== undefined) message.data = { ...reply.data };
    const event = this.#event({ type: "message", message });
    const changed = await this.#change<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
      (current) => {
        if (current.status === "closed") throw new Error("the conversation is closed");
        if (current.responder !== "human") {
          throw new Error("the conversation is not handed to the company's people");
        }
        if (current.directChild !== undefined) {
          throw new Error("a Direct Conversation is open under this conversation");
        }
        if (current.events.at(-1)?.id !== reply.after) {
          throw new StaleConversationError(conversationId, reply.after);
        }
        return { ...current, events: [...current.events, event] };
      },
    );
    if (changed === undefined) throw new Error("unknown conversation");
    return event.payload as unknown as ConversationEvent;
  }

  // Taking the company down -------------------------------------------------------

  /** What is under way: open operations and sign-ins not ended, read from the store. */
  async openWork(): Promise<OpenWork> {
    const operations: Operation[] = [];
    for (const record of await this.store.records(RecordKinds.operation)) {
      const stored = this.#expired(record.value as unknown as StoredOperation);
      if (OPEN_STATES.has(stored.operation.state)) operations.push(stored.operation);
    }
    const signIns = new Map<string, readonly [string, string]>();
    for (const record of await this.store.records(RecordKinds.accountFamily)) {
      const family = record.value as unknown as AccountFamily;
      if (!family.revoked) {
        signIns.set(JSON.stringify([family.clientId, family.accountId]), [
          family.clientId,
          family.accountId,
        ]);
      }
    }
    operations.sort((a, b) => byCodePoint(a.operation_id, b.operation_id));
    const keys = [...signIns.keys()].sort(byCodePoint);
    return { operations, signIns: keys.map((key) => signIns.get(key) as readonly [string, string]) };
  }

  /**
   * Settle every open operation as `cancelled`, because of `reason` (a sentence).
   *
   * For a company being taken down: nothing will perform or settle them after, and a
   * personal agent would otherwise read one as in progress for ever. A proposal was
   * never performed: *Nothing was changed.* One in progress may have changed something
   * before it stopped, which its result says (Operations §6). A proposal past its
   * expiry is recorded as expired. Resolves to how many were cancelled.
   */
  async cancelOpenOperations(reason: string): Promise<number> {
    const why = reason.trim();
    if (!why) throw new Error("say why the operations are cancelled");
    const stopped = {
      summary:
        "It was stopped before it finished, and nothing more will be done: " +
        `whatever it changed until then stands. ${why}`,
      data: null,
    };
    const untouched = { summary: `Nothing was changed. ${why}`, data: null };
    let cancelled = 0;
    for (const record of await this.store.records(RecordKinds.operation)) {
      const operationId = (record.value as unknown as StoredOperation).operation.operation_id;
      const changed = await this.#change<StoredOperation>(
        RecordKinds.operation,
        operationId,
        (latest) => {
          const now = this.#expired(latest);
          const state = now.operation.state;
          if (!OPEN_STATES.has(state)) return now;
          return {
            ...now,
            operation: {
              ...now.operation,
              state: "cancelled",
              result: state === "in_progress" ? stopped : untouched,
            } as unknown as Operation,
          };
        },
      );
      if (
        changed !== undefined &&
        changed[0].operation.state !== "cancelled" &&
        changed[1].operation.state === "cancelled"
      ) {
        cancelled += 1;
      }
    }
    return cancelled;
  }

  /**
   * End every sign-in, as each agent's disconnect does: tokens revoked, Sessions signed out.
   *
   * Resolves to how many agents' sign-ins to an account were ended.
   */
  async endSignIns(): Promise<number> {
    const work = await this.openWork();
    for (const [clientId, accountId] of work.signIns) await this.disconnect(clientId, accountId);
    return work.signIns.length;
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

  /**
   * The operation, if this Session may use it now (Operations §3.2).
   *
   * One proposed signed in belongs to the account: any Session of the same personal
   * agent and user may use it while signed in to that account, checked at each request.
   * Signed out, that Session gets `insufficient_scope` (Operations 3.2); anyone else
   * `operation_not_found`.
   */
  async #usable(operationId: string, session: IssuedSession): Promise<StoredOperation> {
    const stored = await this.#read<StoredOperation>(RecordKinds.operation, operationId);
    if (stored === undefined || !sameOwner(stored.owner, [session.clientId, session.pairwiseUserId])) {
      throw new Refused(404, "operation_not_found");
    }
    if (stored.accountId !== session.accountId) {
      if (session.accountId === undefined) throw insufficientScope(this.config.writeScopes);
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
        // `expires_at` is the proposal's (Operations §3: required while proposed): once
        // confirmed it is absent, never `null`, which no member of an operation may be.
        const { expires_at: _proposalExpiry, ...rest } = now.operation;
        return {
          ...now,
          operation: { ...rest, state: "in_progress", confirmation } as unknown as Operation,
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
  async #liveSession(sessionKey: string): Promise<IssuedSession | undefined> {
    const stored = await this.#read<StoredSession>(RecordKinds.session, sessionKey);
    let live: IssuedSession | undefined;
    for (const token of Object.values(stored?.tokens ?? {})) {
      if ((token.tokenType ?? "DPoP") !== "DPoP" || this.#passed(token.expiresAt)) continue;
      if (live === undefined || new Date(token.expiresAt) > new Date(live.expiresAt)) live = token;
    }
    if (live !== undefined && (await this.#signedInBeforeItsEnd(live))) return undefined;
    return live;
  }

  /**
   * Step 1 of joining a browser (§5): a form with a one-time code, tied to this browser.
   *
   * Loading it starts, ends or changes no Session and no other cookie. The page is never
   * cached, framed, or kept by the page that opened it.
   */
  async #joinPage(): Promise<CompanyResponse> {
    const code = this.#id("bc");
    const browser = this.#id("join");
    await this.store.put(
      RecordKinds.joinCode,
      digest(code),
      json({ browser: digest(browser) } satisfies JoinCode),
      expiry(this.#later(JOIN_LIFETIME_SECONDS)),
    );
    return {
      status: 200,
      body:
        "<!doctype html><meta charset=utf-8><title>Connecting</title>" +
        '<form method="post" action="/poppy/browser-session">' +
        `<input type="hidden" name="code" value="${escapeHtml(code)}">` +
        '<input type="text" name="proof"></form>',
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        ...NO_STORE,
        "Content-Security-Policy": "frame-ancestors 'none'",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Set-Cookie": `${JOIN_COOKIE}=${browser}; Path=/; Max-Age=60; Secure; HttpOnly; SameSite=Strict`,
      },
    };
  }

  /**
   * Step 3 (§5): the cookie, the code, and a proof over it from an active Session's key.
   *
   * A code is used by the first request that sends it, whatever the result. A key the
   * company doesn't know is an error here, never a new Session. Answers `303` with the
   * company's own cookie, which lives no longer than the Session.
   */
  async #browserSession(request: CompanyRequest): Promise<CompanyResponse> {
    const refused = page(
      400,
      "This browser could not join the session.",
      `${JOIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`,
    );
    const form = pairs(text(request.body));
    const code = form.code ?? "";
    const proof = form.proof ?? "";
    const browser = cookie(request, JOIN_COOKIE);
    const taken = code
      ? ((await this.store.take(RecordKinds.joinCode, digest(code))) as unknown as JoinCode | undefined)
      : undefined;
    if (taken === undefined || browser === undefined) return refused;
    const expected = Buffer.from(taken.browser);
    const actual = Buffer.from(digest(browser));
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) return refused;
    let thumbprint: string;
    try {
      const verified = await verifyDpopProof(proof, {
        method: "POST",
        url: this.config.browserSessionEndpoint,
        replayCache: this.#replay(),
        nonce: code,
        now: this.#now(),
      });
      thumbprint = verified.keyThumbprint;
    } catch (error) {
      if (error instanceof ProofError) return refused;
      throw error;
    }
    const session = await this.#liveSession(thumbprint);
    if (session === undefined || !(await this.#allowed(session.clientId))) return refused;
    const webCookie = this.#id("web");
    const pointer: SessionPointer = { sessionKey: session.sessionKey };
    await this.store.put(
      RecordKinds.browserCookie,
      digest(webCookie),
      json(pointer),
      expiry(new Date(new Date(session.expiresAt).getTime() + this.config.accountTokenLifetimeSeconds * 1000)),
    );
    const exchange = exchanges.getStore();
    if (exchange !== undefined) exchange.clientId = session.clientId;
    this.#reportSwitch("web", session.accountId !== undefined);
    return {
      status: 303,
      headers: {
        Location: `${this.config.base}/`,
        // The company's own cookie, `__Host-`: no Max-Age, only as alive as its Session
        // (§5). The join cookie is cleared; several cookies are one per line.
        "Set-Cookie":
          `${WEB_COOKIE}=${webCookie}; Path=/; Secure; HttpOnly; SameSite=Strict\n` +
          `${JOIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`,
        ...NO_STORE,
      },
    };
  }

  /** The Session a browser's cookie stands for, as it is now (§5). */
  async #webSession(webCookie: string | undefined): Promise<IssuedSession | undefined> {
    if (webCookie === undefined) return undefined;
    const pointer = await this.#read<SessionPointer>(RecordKinds.browserCookie, digest(webCookie));
    if (pointer === undefined) return undefined;
    const session = await this.#liveSession(pointer.sessionKey);
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

/** Too many failed sign-in attempts: `429` with how long to wait (§4.2, `rate_limited`). */
function rateLimited(retryAfter: number): CompanyResponse {
  return {
    status: 429,
    body: { error: "rate_limited" },
    headers: { "Retry-After": String(retryAfter), ...NO_STORE },
  };
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
