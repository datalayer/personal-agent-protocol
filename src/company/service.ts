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
 * What it implements of draft 0.3 (upstream 3e9bada) and Operations v2:
 *
 * - Discovery (`/.well-known/poppy.json`), the domain's protected resource
 *   metadata naming the issuer (`/.well-known/oauth-protected-resource`), and
 *   OAuth metadata (`/.well-known/oauth-authorization-server`), one issuer on the
 *   company's own domain.
 * - Sessions (§5): the Session header on every request, verified in the spec's
 *   order (delegation, delegated key, claims, access token), Sessions kept by
 *   `client_id` and `sid`, ended ones remembered; any failure is
 *   `invalid_session` (HTTP 400). Its own access token without the header is refused.
 * - OAuth (§4): Bearer access tokens and refresh tokens; Direct Sign-In, Device
 *   Sign-In with `authorization_pending` and `slow_down`, refresh with rotation,
 *   narrower scopes and `resource` (RFC 8707: `invalid_target` for one it doesn't
 *   serve), and revocation (RFC 7009) whose sign-in ends whole.
 * - The Mediated Sign-In extension v1, an extension grant at the token endpoint, with a
 *   one-time code, attempt limits, and uniform failures; credentials are checked by the
 *   account directory and dropped.
 * - Conversations (§8): idempotent messages, ordered cursor events, waited
 *   replies, SSE, handoff, Direct Conversations, `authorization` events, and
 *   closing; a conversation that is not yours is `conversation_not_found`.
 *   Once a conversation is handed to the company's people, one of them
 *   answers in it (`staffReply`), over the last event they read.
 * - Operations v2, at no endpoint of their own: a request for an action that needs
 *   approval is refused with the operation (`403 approval_required`, an MCP error
 *   result, a company message), and the same request with the approval
 *   (`Poppy-Approval`, `_meta`, a message's `approval`) is checked in the extension's
 *   order and performed at most once; a repeat gets the original response, a request
 *   while it is performed `503` and `Retry-After`, and a failed check a new revision.
 * - MCP (§7), when a `pap.company.mcp` contribution is present: a Streamable HTTP
 *   endpoint at `/mcp` accepting the Session header and access tokens issued for
 *   its url (`resource` = that url), its protected resource metadata (RFC 9728),
 *   and tools that return operations in `structuredContent` (Operations 4).
 *   A token issued for another resource is `invalid_token` with `resource_metadata`.
 * - Feedback (§9.3), with `feedback` (the default): reports of tasks the
 *   protocol can't do, kept for the company's operator (`feedbackReports`).
 * - Web browsing (§6), with `web: true`: the browser-session page with a one-time
 *   code, `{endpoint}/authorize` for the personal agent, and the company's own
 *   cookie for the Session.
 * - Rate limits (§5.6): HTTP 429 and `Retry-After`, no body.
 * - Taking a company down: its owner reads what is under way (`openWork`),
 *   settles each open operation (`settleOpenOperations`) and ends every
 *   sign-in (`endSignIns`), before its records go.
 */

import { AsyncLocalStorage } from "node:async_hooks";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

import type { ReactorPlatformView } from "@datalayer/reactor";

import { IDEMPOTENCY_KEY, WRITE_METHODS } from "../apis.js";
import { ProofError, ProtocolValidationError, SessionError } from "../errors.js";
import { parseJsonStrict } from "../json.js";
import { MEDIATED_EXTENSION, MEDIATED_GRANT, MEDIATED_VERSION } from "../mediated.js";
import {
  AUTHORIZATION_CODE_GRANT,
  parseAuthor,
  DEVICE_CODE_GRANT,
  MEDIATED_RESERVED_FIELDS,
  REFRESH_TOKEN_GRANT,
  parseMessage,
  redirectUriMatches,
  type Approval,
  type ClientMetadata,
  type ConversationEvent,
  type JsonWebKeySet,
  type Message,
  type Operation,
} from "../models.js";
import {
  APPROVAL_HEADER,
  OPERATIONS_EXTENSION,
  OPERATIONS_VERSION,
  approvalFromMeta,
  parseApprovalHeader,
} from "../operations.js";
import { PROTOCOL_PROFILE } from "../profile.js";
import { Clocks, RandomSources, firstContribution, optionalContribution } from "../reactor.js";
import { SecretValue } from "../secret.js";
import { JWT_CLIENT_ASSERTION } from "../sessions.js";
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
  SignInRefused,
  type ActionResult,
  type Authenticated,
  type CompanyApi,
  type CompanyMcp,
  type ProposedOperation,
  type Reply,
  type ReplayCache,
} from "./points.js";
import {
  RecordKinds,
  latestRevision,
  revisionOperation,
  type StoredFeedback,
  type AccountAgent,
  type AccountFamily,
  type AccountGrant,
  type CompanyStore,
  type IdempotencyRecord,
  type IssuedAccessToken,
  type IssuedCode,
  type JoinCode,
  type JsonObject,
  type KnownClient,
  type MessageReceipt,
  type OperationOutcome,
  type OperationProposal,
  type OperationRevision,
  type PendingAuthorization,
  type PendingDevice,
  type PendingMediated,
  type SignInAttempts,
  type StoreWriteOptions,
  type StoredConversation,
  type StoredEvent,
  type StoredOperation,
  type StoredSession,
  type UserCode,
  type WebSession,
} from "./store.js";
import {
  DelegationCache,
  unverifiedSessionIssuer,
  verifyAssertion,
  verifySessionJwt,
  type ResolveClient,
  type VerifiedSessionJwt,
} from "./verify.js";

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
/** Ties a join code to the browser that loaded the join page (§6). */
export const JOIN_COOKIE = "__Host-poppy_join";
/** A join code lives at most this long (§6: no more than 60 seconds). */
const JOIN_LIFETIME_SECONDS = 60;
/** The header that carries the Session JWT (§5.2), as a neutral request names it. */
const SESSION_HEADER = "poppy-session";
/** The key prefix of a `client_id`'s Mediated Sign-In attempts: it has its own limit. */
const CLIENT_ATTEMPTS = "client:";
/** How long a Mediated Sign-In's one-time code can be sent, in seconds. */
const MEDIATED_CODE_LIFETIME_SECONDS = 5 * 60;
/** The error a Mediated Sign-In that ended answers with, for good. */
const MEDIATED_ENDED = { failed: "invalid_grant", expired: "expired_token" } as const;
/** How long a request for an operation being performed waits before trying again. */
const PERFORMING_RETRY_AFTER = "5";
/** The longest `wait` the company holds a read for; a larger one is held this long (§7.5). */
export const MAX_WAIT_SECONDS = 30;

export type MediatedFieldSpec = readonly [name: string, label: string, secret: boolean];

export interface CompanyConfigOptions {
  readonly name: string;
  readonly domain: string;
  readonly scopes: readonly string[];
  readonly writeScopes?: readonly string[];
  /** Mediated Sign-In's `fields`. None, it isn't offered. */
  readonly mediatedFields?: readonly MediatedFieldSpec[];
  /** The scopes Mediated Sign-In can grant, its `scopes`: none named, all of `scopes`. */
  readonly mediatedScopes?: readonly string[];
  readonly device?: boolean;
  readonly direct?: boolean;
  readonly operations?: boolean;
  readonly humansAvailable?: boolean;
  /** How long a Session lasts (§5.5: the Company decides; default a day); then it has ended. */
  readonly sessionLifetimeSeconds?: number;
  /** How long an access token works (§4.5; guides: an hour). */
  readonly accessTokenLifetimeSeconds?: number;
  /** How long a sign-in's refresh tokens work (§4.4; default 90 days). */
  readonly refreshTokenLifetimeSeconds?: number;
  readonly operationLifetimeSeconds?: number;
  readonly deviceInterval?: number;
  readonly maxCodeAttempts?: number;
  /**
   * Failed Mediated Sign-In attempts (credentials or codes) a key may make before it is
   * locked out: an account identifier, an account's codes.
   */
  readonly maxSignInFailures?: number;
  /** The same for all of a `client_id`'s attempts, which many users' sign-ins share. */
  readonly maxClientSignInFailures?: number;
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
  /** Web browsing (§6): a browser-session endpoint. */
  readonly web?: boolean;
  /**
   * Other domains that are this company (§3): each publishes its discovery document, naming
   * itself as the organization's domain, and the issuer's metadata lists it in
   * `protected_resources`. Everything else stays on `domain`, the issuer's: an alias is never a
   * second identity, and answers nothing but its discovery document.
   */
  readonly aliases?: readonly string[];
  /** Accept feedback reports at `/poppy/feedback` and list it in poppy.json (§9.3). */
  readonly feedback?: boolean;
  /** How long an ended Session's `sid` is remembered and refused (§5.5; default 30 days). */
  readonly endedSessionMemorySeconds?: number;
  /** The acceptance window of a Session JWT's `iat` (§5.3: such as one minute). */
  readonly sessionJwtWindowSeconds?: number;
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
  readonly mediatedScopes: readonly string[];
  readonly device: boolean;
  readonly direct: boolean;
  readonly operations: boolean;
  readonly humansAvailable: boolean;
  readonly sessionLifetimeSeconds: number;
  readonly accessTokenLifetimeSeconds: number;
  readonly refreshTokenLifetimeSeconds: number;
  readonly operationLifetimeSeconds: number;
  readonly deviceInterval: number;
  readonly maxCodeAttempts: number;
  readonly maxSignInFailures: number;
  readonly maxClientSignInFailures: number;
  readonly signInLockoutSeconds: number;
  readonly scopeDescriptions: Readonly<Record<string, string>>;
  readonly scopeHints: Readonly<Record<string, readonly [string, boolean]>>;
  readonly excludedTasks: readonly Readonly<Record<string, unknown>>[];
  readonly feedbackAnswers: Readonly<Record<string, Readonly<Record<string, unknown>>>>;
  readonly devicePage: string | undefined;
  readonly consentPage: string | undefined;
  readonly web: boolean;
  readonly aliases: readonly string[];
  readonly feedback: boolean;
  readonly endedSessionMemorySeconds: number;
  readonly sessionJwtWindowSeconds: number;
  readonly idempotencyLifetimeSeconds: number;

  constructor(options: CompanyConfigOptions) {
    this.name = options.name;
    this.domain = options.domain;
    this.scopes = [...options.scopes];
    this.writeScopes = [...(options.writeScopes ?? [])];
    this.mediatedFields = [...(options.mediatedFields ?? [])];
    this.mediatedScopes = [...(options.mediatedScopes ?? [])];
    this.device = options.device ?? true;
    this.direct = options.direct ?? true;
    this.operations = options.operations ?? true;
    this.humansAvailable = options.humansAvailable ?? false;
    this.sessionLifetimeSeconds = options.sessionLifetimeSeconds ?? 24 * 60 * 60;
    this.accessTokenLifetimeSeconds = options.accessTokenLifetimeSeconds ?? 60 * 60;
    this.refreshTokenLifetimeSeconds = options.refreshTokenLifetimeSeconds ?? 90 * 24 * 60 * 60;
    this.operationLifetimeSeconds = options.operationLifetimeSeconds ?? 15 * 60;
    this.deviceInterval = options.deviceInterval ?? 5;
    this.maxCodeAttempts = options.maxCodeAttempts ?? 3;
    this.maxSignInFailures = options.maxSignInFailures ?? 5;
    this.maxClientSignInFailures = options.maxClientSignInFailures ?? 100;
    this.signInLockoutSeconds = options.signInLockoutSeconds ?? 15 * 60;
    this.scopeDescriptions = { ...options.scopeDescriptions };
    this.scopeHints = { ...(options.scopeHints ?? {}) };
    this.excludedTasks = [...(options.excludedTasks ?? [])];
    this.feedbackAnswers = { ...(options.feedbackAnswers ?? {}) };
    this.devicePage = hostedPage("devicePage", options.devicePage);
    this.consentPage = hostedPage("consentPage", options.consentPage);
    this.web = options.web ?? false;
    this.aliases = [...(options.aliases ?? [])];
    this.feedback = options.feedback ?? true;
    this.endedSessionMemorySeconds = options.endedSessionMemorySeconds ?? 30 * 24 * 60 * 60;
    this.sessionJwtWindowSeconds = options.sessionJwtWindowSeconds ?? 60;
    this.idempotencyLifetimeSeconds = options.idempotencyLifetimeSeconds ?? 24 * 60 * 60;
    for (const [name, lifetime] of Object.entries({
      idempotencyLifetimeSeconds: this.idempotencyLifetimeSeconds,
      sessionLifetimeSeconds: this.sessionLifetimeSeconds,
      accessTokenLifetimeSeconds: this.accessTokenLifetimeSeconds,
      refreshTokenLifetimeSeconds: this.refreshTokenLifetimeSeconds,
      sessionJwtWindowSeconds: this.sessionJwtWindowSeconds,
    })) {
      if (!(lifetime > 0)) throw new RangeError(`${name} must be positive`);
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
    if (
      !(
        Number.isInteger(this.maxSignInFailures) &&
        this.maxSignInFailures >= 1 &&
        Number.isInteger(this.maxClientSignInFailures) &&
        this.maxClientSignInFailures >= 1 &&
        this.signInLockoutSeconds > 0
      )
    ) {
      throw new RangeError("sign-in attempts need a positive limit and lockout");
    }
    if (this.mediatedFields.some(([name]) => MEDIATED_RESERVED_FIELDS.has(name))) {
      // A field would overwrite the grant's own parameters (Mediated Sign-In 2).
      throw new RangeError("a Mediated Sign-In field can't use a reserved parameter name");
    }
    if (this.mediatedScopes.some((scope) => !this.scopes.includes(scope))) {
      throw new RangeError("mediatedScopes must be among scopes");
    }
    if (this.operations && !this.writeScopes.length) {
      // Approving an operation needs a write scope: without one, any signed-in Session,
      // whatever it was granted, could approve.
      throw new RangeError("operations need writeScopes: the scopes approving one requires");
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
  /** The extension's `scopes`: what Mediated Sign-In can grant. */
  get mediatedGrantScopes(): readonly string[] {
    return this.mediatedScopes.length ? this.mediatedScopes : this.scopes;
  }
  get conversationsEndpoint(): string {
    return `${this.base}/poppy/conversations`;
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

/**
 * Who a verified request is from (§5.3): its Session, and its account when signed in.
 *
 * `sessionKey` names the Session in the store (`clientId` and `sid`). `accountId`, `scopes`,
 * `family` and `resource` are the access token's, for this request only: a Session is
 * signed in on each request that carries one (§5.4).
 */
export interface CallerSession {
  readonly sessionKey: string;
  readonly clientId: string;
  readonly sid: string;
  readonly pairwiseUserId: string;
  readonly agentId?: string;
  readonly accountId?: string;
  readonly scopes: readonly string[];
  readonly family?: string;
  readonly resource?: string;
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
 * A 401 challenge with no error code: the request needs the account and has no access
 * token; its `scope` names the scopes needed (§7, RFC 6750 §3.1).
 */
const SIGNED_OUT = "";

/**
 * The refusal of a request that needs `scopes` of the account (§5.4, §7).
 *
 * Signed out (no access token): a 401 challenge with `scope` and no error code. Signed in
 * without them: `insufficient_scope` (HTTP 403), naming them.
 */
function needsAccount(accountId: string | undefined, scopes: readonly string[]): Refused {
  if (accountId === undefined) return new Refused(401, SIGNED_OUT, { scope: scopes.join(" ") });
  return new Refused(403, "insufficient_scope", { scope: scopes.join(" ") });
}

/** The host's rate limit refused the request: `429` and when to ask again (§5.6). */
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
  "poppy_conversations",
  "poppy_feedback",
]);
const ROUTES: Readonly<Record<string, string>> = {
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

const CHALLENGED = new Set(["invalid_token", "insufficient_scope", SIGNED_OUT]);

/**
 * A JSON error; a token error at 401 or 403 in `WWW-Authenticate` too (§7).
 *
 * A signed-out request for the account gets the challenge alone: no error code, no body.
 * `invalid_session` is a JSON body, HTTP 400 (§5.3).
 */
function jsonError(
  status: number,
  error: string,
  extra: Readonly<Record<string, unknown>> = {},
  headers: Readonly<Record<string, string>> = {},
): CompanyResponse {
  const out: Record<string, string> = { ...NO_STORE, ...headers };
  if (CHALLENGED.has(error) && (status === 401 || status === 403)) {
    out["WWW-Authenticate"] = challenge("Bearer", error, extra);
  }
  if (error === SIGNED_OUT) return { status, headers: out };
  return { status, body: { error, ...extra }, headers: out };
}

/** One `WWW-Authenticate` challenge with the error's `scope`, `extension`, metadata URL. */
function challenge(scheme: string, error: string, extra: Readonly<Record<string, unknown>>): string {
  const parts = error ? [`error="${error}"`] : [];
  for (const name of ["scope", "extension", "resource_metadata"]) {
    const item = extra[name];
    if (typeof item === "string") parts.push(`${name}="${item}"`);
  }
  return parts.length ? `${scheme} ${parts.join(", ")}` : scheme;
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
/** The website's cookie for the agent's Session (§6): `__Host-`, so no other host or path can set it. */
export const WEB_COOKIE = "__Host-poppy_session";

/** What the user decided on the company's own consent page, checked by `consentDecision`. */
export interface ConsentDecision {
  readonly requestId: string;
  readonly allow: boolean;
}

/**
 * What a company has under way: what its owner settles and ends before taking it down.
 *
 * `operations` are those that can still be approved, or are being performed (one whose
 * revisions have all expired is not open); `signIns` are the agents and accounts, as
 * `[clientId, accountId]`, with a sign-in not ended — each one ended whole by
 * `CompanyService.disconnect`.
 */
export interface OpenWork {
  readonly operations: readonly Operation[];
  readonly signIns: readonly (readonly [clientId: string, accountId: string])[];
}

/** What a request asks for: the action, its terms now, and the request's fingerprint. */
interface Asked {
  readonly action: string;
  /** The `OperationProposal` key: requests with the same one are the same operation. */
  readonly key: string;
  readonly summary: string;
  readonly terms: Readonly<Record<string, unknown>> | undefined;
  readonly scopes: readonly string[];
  /** The request's fingerprint, and what the action said for it. */
  readonly request: string;
  readonly digest: string;
}

/**
 * What an operation's request comes to, whichever interface it came through.
 *
 * `operation`: ask for approval of this revision. `outcome`: it was performed, the response
 * as it would have been without operations. Neither: it is being performed.
 */
interface Decision {
  readonly operation?: Operation | undefined;
  readonly outcome?: OperationOutcome | undefined;
}

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

/** A digest of what a request asks, or of what an action said: canonical JSON. */
function fingerprint(...parts: readonly unknown[]): string {
  return digest(canonical(parts));
}

/** One company's PAP endpoints over Reactor contributions. */
export class CompanyService {
  readonly config: CompanyConfig;
  readonly reactor: ReactorPlatformView;
  /** Verified delegations, until each expires (§5.2: a resource MAY cache them). */
  readonly delegations = new DelegationCache();

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

  /** A Session started here; or a request moved one to the MCP server or the website. */
  #reportSession(signedIn: boolean, to?: TelemetryInterface): void {
    if (to !== undefined) {
      this.#report("pap.company.interface.switch", "ok", {
        "pap.interface": to,
        "pap.session.signed_in": signedIn,
      });
      return;
    }
    this.#report("pap.company.session.start", "ok", { "pap.session.signed_in": signedIn });
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
      // beside a header that would be (§5.6, RFC 6750 §2.3).
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
        if (method === "GET" && path === "/.well-known/oauth-protected-resource") {
          return { status: 200, body: this.domainResourceMetadata(host), headers: {} };
        }
        return jsonError(404, "not_found");
      }
      if (method === "GET" && path === "/.well-known/poppy.json") {
        return { status: 200, body: this.discoveryDocument(), headers: {} };
      }
      if (method === "GET" && path === "/.well-known/oauth-protected-resource") {
        return { status: 200, body: this.domainResourceMetadata(), headers: {} };
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
      if (method === "POST" && path === "/poppy/browser-session/authorize" && this.config.web) {
        return await this.#authorizeJoin(request);
      }
      if (method === "GET" && path === "/poppy/excluded-tasks.json" && this.config.excludedTasks.length) {
        return { status: 200, body: { tasks: this.config.excludedTasks.map((task) => ({ ...task })) }, headers: {} };
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
      if (path === "/poppy/conversations" && method === "POST") {
        return await this.#startConversation(request);
      }
      if (path.startsWith("/poppy/conversations/")) {
        return await this.#conversationRoute(request, method, path);
      }
      if (method === "POST" && path === "/poppy/feedback" && this.config.feedback) {
        return await this.#feedback(request);
      }
    } catch (error) {
      if (error instanceof RateLimitedRefusal) return rateLimited(error.retryAfter);
      if (error instanceof Refused) return jsonError(error.status, error.error, error.extra, error.headers);
      if (error instanceof SessionError || error instanceof ProofError) {
        // A JSON body, HTTP 400, whichever check failed (§5.3).
        if (error.code === "invalid_session") return jsonError(400, "invalid_session");
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
    const extensions: Record<string, unknown> = {};
    if (config.operations) extensions[OPERATIONS_EXTENSION] = { version: OPERATIONS_VERSION };
    if (config.mediatedFields.length) {
      extensions[MEDIATED_EXTENSION] = {
        version: MEDIATED_VERSION,
        fields: config.mediatedFields.map(([name, label, secret]) => ({ name, label, secret })),
        scopes: [...config.mediatedGrantScopes],
      };
    }
    if (Object.keys(extensions).length) document.extensions = extensions;
    return document;
  }

  /**
   * RFC 9728 metadata for the MCP server: its `url`, and the company's issuer (§7).
   *
   * Its `resource` is the server's own: it accepts only access tokens issued for it (§4.5).
   */
  protectedResourceMetadata(): Record<string, unknown> {
    return {
      resource: this.config.mcpUrl,
      authorization_servers: [this.config.base],
      scopes_supported: [...this.config.scopes],
      bearer_methods_supported: ["header"],
    };
  }

  /**
   * RFC 9728 metadata of `https://{domain}`, naming the issuer (§3.2).
   *
   * Published by the company's own domain and each alias: `resource` is exactly
   * `https://{domain}` and its one authorization server is the company's issuer.
   */
  domainResourceMetadata(domain?: string): Record<string, unknown> {
    const config = this.config;
    if (domain !== undefined && domain !== config.domain && !config.aliases.includes(domain)) {
      throw new RangeError(`${domain} is not one of this company's domains`);
    }
    return {
      resource: `https://${domain ?? config.domain}`,
      authorization_servers: [config.base],
      scopes_supported: [...config.scopes],
      bearer_methods_supported: ["header"],
    };
  }

  oauthMetadata(): Record<string, unknown> {
    const config = this.config;
    const grants: string[] = [REFRESH_TOKEN_GRANT];
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
    };
    if (this.#mcp() !== undefined) resources.push(config.mcpUrl);
    if (config.direct) {
      grants.push(AUTHORIZATION_CODE_GRANT);
      metadata.authorization_endpoint = config.authorizationEndpoint;
      metadata.code_challenge_methods_supported = ["S256"];
    }
    if (config.device) {
      grants.push(DEVICE_CODE_GRANT);
      metadata.device_authorization_endpoint = config.deviceEndpoint;
    }
    if (config.mediatedFields.length) grants.push(MEDIATED_GRANT);
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
    const exchange = exchanges.getStore();
    if (exchange !== undefined) exchange.clientId = clientId;
    await this.#rememberClient(clientId, metadata);
    return clientId;
  }

  /** What a personal agent declares, kept whichever request verified it first. */
  async #rememberClient(clientId: string, metadata: ClientMetadata): Promise<void> {
    const extensions = Object.fromEntries(
      Object.entries(metadata.extensions ?? {}).map(([name, item]) => [name, item.version]),
    );
    const known = await this.#read<KnownClient>(RecordKinds.client, clientId);
    if (known === undefined || canonical(known.extensions) !== canonical(extensions)) {
      await this.store.put(RecordKinds.client, clientId, json({ extensions } satisfies KnownClient));
      // Its identity verified for the first time, or with new metadata.
      this.#report("pap.company.identity.check", "ok", {});
    }
  }

  /**
   * The company's policy on this agent, asked before anything is fetched for it: a
   * blocked `client_id` is never resolved (no metadata or keys fetched from its domain),
   * and a blocked agent's tokens stop working at once.
   */
  async #allowed(clientId: string): Promise<boolean> {
    return firstContribution(this.reactor, ClientPolicies, "policy").allows(clientId);
  }

  /** Whether the agent listed this version of Operations when it last authenticated. */
  async #supportsOperations(clientId: string): Promise<boolean> {
    const known = await this.#read<KnownClient>(RecordKinds.client, clientId);
    return known !== undefined && known.extensions[OPERATIONS_EXTENSION] === OPERATIONS_VERSION;
  }

  /**
   * The token endpoint (§4): every grant carries a client assertion, and nothing else.
   *
   * The refresh grant issues an access token, for a `resource` this company serves when one
   * is named (RFC 8707); the code and device grants sign in. No Session is named: any of the
   * User's Sessions uses the access token (§5.4).
   */
  async #token(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const grant = form.grant_type;
    const clientId = await this.#client(form);
    if (grant === REFRESH_TOKEN_GRANT) return this.#refreshGrant(form, clientId);
    if (grant === AUTHORIZATION_CODE_GRANT && this.config.direct) return this.#codeGrant(form, clientId);
    if (grant === DEVICE_CODE_GRANT && this.config.device) return this.#deviceGrant(form, clientId);
    if (grant === MEDIATED_GRANT && this.config.mediatedFields.length) {
      // The request itself uses the extension: no client metadata entry is asked for, and
      // `extension_required` can't refuse it (§3.3).
      return this.#mediatedGrant(form, clientId);
    }
    throw new Refused(400, "unsupported_grant_type");
  }

  /**
   * The `resource` a token is issued for (RFC 8707, §4.5): one this company serves.
   *
   * `https://{domain}` (or an alias's) is the default token's, `undefined`; the MCP server's
   * `url` gets a token for it alone; anything else is `invalid_target`.
   */
  #resource(form: Readonly<Record<string, string>>): string | undefined {
    const resource = form.resource;
    if (resource === undefined) return undefined;
    if ([this.config.domain, ...this.config.aliases].some((domain) => resource === `https://${domain}`)) {
      return undefined;
    }
    if (this.#mcp() !== undefined && resource === this.config.mcpUrl) return resource;
    throw new Refused(400, "invalid_target");
  }

  /** The scopes that read the account: the company's scopes that change nothing. */
  #accountScopes(): readonly string[] {
    const read = this.config.scopes.filter((scope) => !this.config.writeScopes.includes(scope));
    return read.length ? read : this.config.scopes;
  }

  /**
   * An access token from a refresh token, which is rotated (§4.4).
   *
   * Narrower scopes only; `resource` for one service. Exactly one refresh claims the
   * presented token, which stops working the moment it is claimed.
   */
  async #refreshGrant(form: Readonly<Record<string, string>>, clientId: string): Promise<CompanyResponse> {
    const resource = this.#resource(form);
    const presented = digest(form.refresh_token ?? "");
    const entry = await this.store.get(RecordKinds.refreshToken, presented);
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
    if (await this.#signInEnded(grant)) throw new Refused(400, "invalid_grant");
    const requested = words(form.scope);
    if (requested.length && requested.some((scope) => !grant.scopes.includes(scope))) {
      throw new Refused(400, "invalid_scope");
    }
    if (!this.#offers(requested.length ? requested : grant.scopes)) {
      // A scope the company no longer offers (a rollback, a narrower version): asked
      // within what it offers now, the same refresh token still serves.
      throw new Refused(400, "invalid_scope");
    }
    const claimed = await this.store.replace(
      RecordKinds.refreshToken,
      presented,
      entry.version,
      json({ ...grant, revoked: true } satisfies AccountGrant),
      expiry(entry.expiresAt),
    );
    if (!claimed) throw new Refused(400, "invalid_grant");
    const rotated = this.#id("rt");
    await this.store.put(
      RecordKinds.refreshToken,
      digest(rotated),
      json({ ...grant, revoked: false } satisfies AccountGrant),
      expiry(grant.expiresAt),
    );
    if (!(await this.#joinFamily(grant.family, { refreshToken: digest(rotated) }))) {
      // The sign-in was revoked meanwhile: its new token is too.
      await this.#revokeGrants([digest(rotated)]);
      throw new Refused(400, "invalid_grant");
    }
    const response = await this.#issue({
      clientId,
      accountId: grant.accountId,
      scopes: requested.length ? requested : grant.scopes,
      family: grant.family,
      ...(resource === undefined ? {} : { resource }),
      refreshToken: rotated,
      // A refresh naming no scope gets them in the response: the agent can't know.
      requested,
    });
    const family = await this.#read<AccountFamily>(RecordKinds.accountFamily, grant.family);
    if (family === undefined || family.revoked) {
      // Revoked while this token was issued: it ends with its sign-in (§5.5).
      await this.#signOut([grant.family]);
      throw new Refused(400, "invalid_grant");
    }
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

  async #deviceGrant(form: Readonly<Record<string, string>>, clientId: string): Promise<CompanyResponse> {
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
    // Consumed once: of concurrent polls, only the one that takes it signs in.
    const approved = (await this.store.take(RecordKinds.device, key)) as unknown as
      | PendingDevice
      | undefined;
    if (approved === undefined || approved.accountId === undefined) {
      throw new Refused(400, "invalid_grant");
    }
    await this.store.delete(RecordKinds.userCode, approved.userCode);
    return this.#signIn(clientId, approved.accountId, approved.granted, approved.scopes);
  }

  async #forgetDevice(key: string, pending: PendingDevice): Promise<void> {
    await this.store.delete(RecordKinds.device, key);
    await this.store.delete(RecordKinds.userCode, pending.userCode);
  }

  async #revoke(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const clientId = await this.#client(form);
    const grant = await this.#read<AccountGrant>(RecordKinds.refreshToken, digest(form.token ?? ""));
    if (grant !== undefined && grant.clientId === clientId) {
      // The token and every one rotated from the same sign-in, and the access tokens
      // they gave (RFC 7009 §2.1): the Sessions continue signed out (§5.5).
      await this.#signOut([grant.family]);
    }
    return { status: 200, body: {}, headers: { ...NO_STORE } };
  }

  /**
   * The user disconnects an agent in account settings: its tokens go (§5.5).
   *
   * Resolves to how many refresh tokens were revoked (upstream guides, account settings).
   */
  async disconnect(clientId: string, accountId: string): Promise<number> {
    const agent = await this.#read<AccountAgent>(
      RecordKinds.accountAgent,
      composite(clientId, accountId),
    );
    return agent === undefined ? 0 : this.#signOut(agent.families);
  }

  /**
   * Revoke whole sign-ins: their refresh and access tokens stop working.
   *
   * Resolves to how many refresh tokens this revoked (the others already were).
   */
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
      for (const token of family.accessTokens) await this.store.delete(RecordKinds.accessToken, token);
    }
    return revoked;
  }

  async #revokeGrants(tokens: readonly string[]): Promise<number> {
    let revoked = 0;
    for (const token of tokens) {
      const changed = await this.#change<AccountGrant>(RecordKinds.refreshToken, token, (grant) =>
        grant.revoked ? grant : { ...grant, revoked: true },
      );
      if (changed !== undefined && !changed[0].revoked) revoked += 1;
    }
    return revoked;
  }

  /** Add a refresh or an access token to a sign-in; `false` once it is revoked. */
  async #joinFamily(
    familyId: string,
    added: { readonly refreshToken?: string; readonly accessToken?: string },
  ): Promise<boolean> {
    const changed = await this.#change<AccountFamily>(
      RecordKinds.accountFamily,
      familyId,
      (family) =>
        family.revoked
          ? family
          : {
              ...family,
              tokens: withItem(family.tokens, added.refreshToken),
              accessTokens: withItem(family.accessTokens, added.accessToken),
            },
    );
    return changed !== undefined && !changed[1].revoked;
  }

  /**
   * A sign-in: a new refresh token, and an access token (§4.7).
   *
   * `scopes` are the ones the user approved of those `requested`; the response leaves
   * `scope` out when they are the same (RFC 6749 §5.1). Plain OAuth: no Session is named or
   * signed in here (§5.4).
   */
  async #signIn(
    clientId: string,
    accountId: string,
    scopes: readonly string[],
    requested: readonly string[],
  ): Promise<CompanyResponse> {
    if (!scopes.length) {
      // A sign-in grants at least one scope: approving none is a decline (§4.7).
      throw new Refused(400, "access_denied");
    }
    const refreshToken = this.#id("rt");
    const family = digest(refreshToken);
    const expiresAt = this.#later(this.config.refreshTokenLifetimeSeconds);
    const grant: AccountGrant = {
      accountId,
      clientId,
      scopes,
      expiresAt: expiresAt.toISOString(),
      revoked: false,
      family,
      signedInAt: this.#now().toISOString(),
    };
    await this.store.put(RecordKinds.refreshToken, family, json(grant), expiry(expiresAt));
    const signIn: AccountFamily = {
      clientId,
      accountId,
      tokens: [family],
      accessTokens: [],
      revoked: false,
    };
    await this.store.put(RecordKinds.accountFamily, family, json(signIn), expiry(expiresAt));
    await this.#rememberFamily(clientId, accountId, family);
    return this.#issue({ clientId, accountId, scopes, family, refreshToken, requested });
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
   * A token response (§4.7): a Bearer access token, and the refresh token if any.
   *
   * `scope` follows RFC 6749: left out when it grants exactly the scopes requested.
   */
  async #issue(options: {
    readonly clientId: string;
    readonly accountId: string;
    readonly scopes: readonly string[];
    readonly family: string;
    readonly resource?: string;
    readonly refreshToken?: string;
    readonly requested: readonly string[];
  }): Promise<CompanyResponse> {
    const { clientId, accountId, scopes, family, resource, refreshToken, requested } = options;
    const accessToken = this.#id("at");
    const key = digest(accessToken);
    const expiresAt = this.#later(this.config.accessTokenLifetimeSeconds);
    const issued: IssuedAccessToken = {
      clientId,
      accountId,
      scopes,
      expiresAt: expiresAt.toISOString(),
      family,
      ...(resource === undefined ? {} : { resource }),
    };
    await this.store.put(RecordKinds.accessToken, key, json(issued), expiry(expiresAt));
    if (!(await this.#joinFamily(family, { accessToken: key }))) {
      await this.store.delete(RecordKinds.accessToken, key);
      throw new Refused(400, "invalid_grant");
    }
    const body: Record<string, unknown> = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: Math.trunc(this.config.accessTokenLifetimeSeconds),
    };
    const asked = new Set(requested);
    const granted = new Set(scopes);
    if (granted.size !== asked.size || [...granted].some((scope) => !asked.has(scope))) {
      body.scope = scopes.join(" ");
    }
    if (refreshToken !== undefined) body.refresh_token = refreshToken;
    return { status: 200, body, headers: { ...NO_STORE } };
  }

  /** The access token's record while it works: issued here, unexpired, sign-in not ended. */
  async #accessToken(token: string): Promise<IssuedAccessToken | undefined> {
    const issued = await this.#read<IssuedAccessToken>(RecordKinds.accessToken, digest(token));
    if (issued === undefined || this.#passed(issued.expiresAt)) return undefined;
    const grant = await this.#read<AccountGrant>(RecordKinds.refreshToken, issued.family);
    if (grant === undefined) {
      // Its sign-in's records are gone (expired, deleted): nothing to hold it to.
      if ((await this.#signedOutBefore(issued.accountId)) !== undefined) return undefined;
    } else if (await this.#signInEnded(grant)) {
      return undefined;
    }
    return issued;
  }

  async #signedOutBefore(accountId: string): Promise<Date | undefined> {
    const accounts = optionalContribution(this.reactor, CompanyAccounts, "accounts");
    return accounts?.signedOutBefore === undefined ? undefined : accounts.signedOutBefore(accountId);
  }

  /**
   * Whether the account's sign-ins ended after this one: then it ends, whole — a password
   * reset, an account locked: its refresh tokens are revoked and its access tokens stop
   * working (`#signOut`).
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

  async #codeGrant(form: Readonly<Record<string, string>>, clientId: string): Promise<CompanyResponse> {
    const issued = (await this.store.take(RecordKinds.code, digest(form.code ?? ""))) as unknown as
      | IssuedCode
      | undefined;
    if (
      issued === undefined ||
      this.#passed(issued.expiresAt) ||
      issued.clientId !== clientId ||
      issued.redirectUri !== form.redirect_uri
    ) {
      // Expired, reused, another agent's, or for another redirect (§4.2).
      throw new Refused(400, "invalid_grant");
    }
    const verifier = createHash("sha256")
      .update(form.code_verifier ?? "")
      .digest("base64url");
    if (!sameText(verifier, issued.codeChallenge)) throw new Refused(400, "invalid_grant");
    return this.#signIn(clientId, issued.accountId, issued.scopes, issued.requested);
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

  // OpenAPI API (§6, Operations 4, 6) -----------------------------------------------------

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
    session: CallerSession,
    body: unknown,
  ): Promise<CompanyResponse> {
    const negotiated = await this.#supportsOperations(session.clientId);
    const approval = negotiated
      ? parseApprovalHeader(request.headers[APPROVAL_HEADER.toLowerCase()])
      : undefined;
    const target = await this.#approvalTarget(session, approval);
    const settled = target === undefined ? undefined : settledDecision(target);
    if (settled !== undefined) return apiDecision(settled);
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
      const answer = isObject(result.body) ? result.body : {};
      if (result.status === 403 && answer.error === "insufficient_scope") {
        // In the challenge, and signed out with no error code (§7).
        throw needsAccount(session.accountId, String(answer.scope ?? "").split(" "));
      }
      return { status: result.status ?? 200, body: result.body, headers: {} };
    }
    if (!negotiated) {
      // At an API, in the WWW-Authenticate challenge with its `extension` (§3.3, §7).
      throw new Refused(
        403,
        "extension_required",
        { extension: OPERATIONS_EXTENSION },
        { "WWW-Authenticate": `Bearer error="extension_required", extension="${OPERATIONS_EXTENSION}"` },
      );
    }
    const requested = fingerprint("api", method, path, new URL(request.url).search, body ?? null);
    const asked = this.#asked(session, result.operation, requested);
    return apiDecision(await this.#decide(session, asked, approval, target));
  }

  // MCP (§4.5, §7, Operations 4, 6) -------------------------------------------------------

  #mcp(): CompanyMcp | undefined {
    return optionalContribution(this.reactor, CompanyMcps, "MCP server");
  }

  /**
   * A token refusal at the MCP server: the `Bearer` challenge with `resource_metadata`.
   *
   * RFC 9728 §5.1: so a client with stale metadata learns where to read it (§4.5, §7). A
   * signed-out call for the account gets the challenge with `scope` and no error code.
   */
  #mcpRefusal(
    status: number,
    error: string,
    scope?: string,
    headers: Readonly<Record<string, string>> = {},
  ): CompanyResponse {
    const extra: Record<string, unknown> = { resource_metadata: this.config.mcpResourceMetadata };
    if (scope !== undefined) extra.scope = scope;
    return {
      status,
      ...(error ? { body: scope === undefined ? { error } : { error, scope } } : {}),
      headers: {
        "WWW-Authenticate": challenge("Bearer", error, extra),
        ...NO_STORE,
        ...headers,
      },
    };
  }

  /**
   * The caller at the MCP server: the Session header, and a token issued for it (§7).
   *
   * The reference MCP server accepts the Session header, so signed-out calls carry it
   * alone; a token issued for another resource is `invalid_token` with `resource_metadata`.
   */
  async #mcpCaller(request: CompanyRequest): Promise<CallerSession | CompanyResponse> {
    let session: CallerSession;
    try {
      [, session] = await this.#caller(request, this.config.mcpUrl);
    } catch (error) {
      if (error instanceof Refused && !(error instanceof RateLimitedRefusal)) {
        return this.#mcpRefusal(error.status, error.error, undefined, error.headers);
      }
      throw error;
    }
    if (session.accountId !== undefined) this.#reportSession(true, "mcp");
    return session;
  }

  /**
   * Whether this company offers every one of these scopes now. An access token holding a
   * scope it no longer offers (rolled back to a version without it, or narrowed) is
   * refused as `invalid_token`, so the personal agent gets a new one within what is
   * offered; a refresh token refreshed for such a scope is `invalid_scope`, and serves
   * again when asked within what is offered.
   */
  #offers(scopes: readonly string[]): boolean {
    return scopes.every((scope) => this.config.scopes.includes(scope));
  }

  async #mcpRoute(request: CompanyRequest, mcp: CompanyMcp): Promise<CompanyResponse> {
    const session = await this.#mcpCaller(request);
    // An expired or other-resource token.
    if (!("sessionKey" in session)) return session;
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
    session: CallerSession,
    mcp: CompanyMcp,
    params: Readonly<Record<string, unknown>>,
  ): Promise<{ readonly result: Record<string, unknown> } | { readonly refused: CompanyResponse }> {
    const name = params.name;
    const args = params.arguments ?? {};
    if (typeof name !== "string" || !isObject(args)) {
      return { refused: rpcError(null, -32602, "Invalid params") };
    }
    const negotiated = await this.#supportsOperations(session.clientId);
    const approval = negotiated ? approvalFromMeta(params._meta) : undefined;
    let target: StoredOperation | undefined;
    try {
      target = await this.#approvalTarget(session, approval);
    } catch (error) {
      if (error instanceof Refused) {
        return { refused: this.#mcpRefusal(error.status, error.error, String(error.extra.scope)) };
      }
      throw error;
    }
    const settled = target === undefined ? undefined : settledDecision(target);
    if (settled !== undefined) return mcpDecision(settled);
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
      if (error === "insufficient_scope" && session.accountId === undefined) {
        // Signed out: the challenge with `scope`, no error code (§7).
        return { refused: this.#mcpRefusal(401, SIGNED_OUT, scope) };
      }
      return { refused: this.#mcpRefusal(status, error, scope) };
    }
    if (answer.operation !== undefined) {
      if (!negotiated) {
        // A tool can't be refused with `extension_required`, which refuses the personal
        // agent entirely: an ordinary tool error (Operations 2).
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
      const asked = this.#asked(session, answer.operation, fingerprint("mcp", name, args));
      return mcpDecision(await this.#decide(session, asked, approval, target));
    }
    const result: Record<string, unknown> = {
      content: [{ type: "text", text: answer.text ?? JSON.stringify(answer.structured ?? {}) }],
    };
    if (answer.structured !== undefined) result.structuredContent = answer.structured;
    if (answer.isError) result.isError = true;
    return { result };
  }

  // Resource requests ---------------------------------------------------------------

  /**
   * Verify the request's Session header, and its access token if any (§5.3, §7).
   *
   * `resource` is the service the request is for: `undefined` for the company's own
   * endpoints, which take the default token, or the MCP server's `url`. Resolves to the
   * access token's digest (or `""`) and the caller's Session.
   */
  async #caller(request: CompanyRequest, resource?: string): Promise<[string, CallerSession]> {
    const authorization = request.headers.authorization ?? "";
    const space = authorization.indexOf(" ");
    const scheme = space < 0 ? authorization : authorization.slice(0, space);
    const token = space < 0 ? "" : authorization.slice(space + 1);
    const presented = scheme.toLowerCase() === "bearer" && token ? token : undefined;
    if (authorization && presented === undefined) throw new Refused(401, "invalid_token");
    const header = request.headers[SESSION_HEADER];
    if (!header) {
      // A copied access token is useless without the agent's key (§5.3); and every
      // request names its Session (§5.2).
      throw new SessionError("invalid_session", "No Session header", { statusCode: 400 });
    }
    const clientId = unverifiedSessionIssuer(header);
    if (!(await this.#allowed(clientId))) {
      // A refused personal agent: `invalid_session` at a resource (§4.1).
      throw new SessionError("invalid_session", "Refused agent", { statusCode: 400 });
    }
    const resolver = firstContribution(this.reactor, ClientResolvers, "client resolver");
    const resolve: ResolveClient = async (agent, kid) => {
      const resolved = await resolver.resolve(agent, kid === undefined ? {} : { kid });
      // A request can be the agent's first: a Session needs no OAuth endpoint (§4).
      await this.#rememberClient(agent, resolved[0]);
      return resolved;
    };
    const verified = await verifySessionJwt(header, {
      issuer: this.config.base,
      method: request.method,
      url: request.url,
      resolve,
      replayCache: this.#replay(),
      now: this.#now(),
      ...(presented === undefined ? {} : { accessToken: presented }),
      delegations: this.delegations,
      windowSeconds: this.config.sessionJwtWindowSeconds,
    });
    const exchange = exchanges.getStore();
    if (exchange !== undefined) exchange.clientId = verified.clientId;
    let issued: IssuedAccessToken | undefined;
    if (presented !== undefined) {
      issued = await this.#accessToken(presented);
      if (issued !== undefined && issued.clientId !== verified.clientId) {
        // Issued to another agent than the Session JWT's (§5.3).
        throw new SessionError("invalid_session", "Token of another agent", { statusCode: 400 });
      }
      if (issued === undefined || !this.#offers(issued.scopes)) throw new Refused(401, "invalid_token");
      if (issued.resource !== resource) {
        // Not issued for this service: where to read which one it is (§4.5, §7).
        throw new Refused(401, "invalid_token", {
          resource_metadata: this.#resourceMetadataUrl(resource),
        });
      }
    }
    const sessionKey = await this.#session(verified);
    const session: CallerSession = {
      sessionKey,
      clientId: verified.clientId,
      sid: verified.sid,
      pairwiseUserId: verified.sub,
      ...(verified.agentId === undefined ? {} : { agentId: verified.agentId }),
      ...(issued === undefined ? {} : { accountId: issued.accountId, family: issued.family }),
      scopes: issued === undefined ? [] : issued.scopes,
      ...(resource === undefined ? {} : { resource }),
    };
    const wait = await this.#admitted(session);
    if (wait !== undefined) throw new RateLimitedRefusal(wait);
    return [presented === undefined ? "" : digest(presented), session];
  }

  /** The protected resource metadata URL of the service a request was for (RFC 9728). */
  #resourceMetadataUrl(resource: string | undefined): string {
    if (resource === this.config.mcpUrl) return this.config.mcpResourceMetadata;
    return `${this.config.base}/.well-known/oauth-protected-resource`;
  }

  /**
   * The Session by `client_id` and `sid`: started when unknown, checked when known (§5.3).
   *
   * A known Session keeps its User ID and Agent ID; one that has ended, and is still
   * remembered, is `invalid_session` (§5.5).
   */
  async #session(verified: VerifiedSessionJwt): Promise<string> {
    const key = composite(verified.clientId, verified.sid);
    for (let attempt = 0; attempt < CAS_ATTEMPTS; attempt += 1) {
      const known = await this.#read<StoredSession>(RecordKinds.session, key);
      if (known === undefined) {
        const endsAt = this.#later(this.config.sessionLifetimeSeconds);
        const started: StoredSession = {
          clientId: verified.clientId,
          sid: verified.sid,
          pairwiseUserId: verified.sub,
          ...(verified.agentId === undefined ? {} : { agentId: verified.agentId }),
          endsAt: endsAt.toISOString(),
          ended: false,
        };
        const remembered = new Date(endsAt.getTime() + this.config.endedSessionMemorySeconds * 1000);
        if (await this.store.create(RecordKinds.session, key, json(started), expiry(remembered))) {
          this.#reportSession(false);
          return key;
        }
        continue;
      }
      if (known.ended || this.#passed(known.endsAt)) {
        throw new SessionError("invalid_session", "The Session has ended", { statusCode: 400 });
      }
      if (known.pairwiseUserId !== verified.sub || known.agentId !== verified.agentId) {
        // A Session keeps its User ID and Agent ID, or none, for its life (§5.2).
        throw new SessionError("invalid_session", "Another User's Session", { statusCode: 400 });
      }
      return key;
    }
    throw new Refused(503, "temporarily_unavailable");
  }

  /**
   * The company ends a Session: requests naming its `sid` get `invalid_session` (§5.5).
   *
   * Remembered for `endedSessionMemorySeconds`. Resolves to whether a Session was ended.
   */
  async endSession(clientId: string, sid: string): Promise<boolean> {
    const changed = await this.#change<StoredSession>(
      RecordKinds.session,
      composite(clientId, sid),
      (stored) => (stored.ended ? stored : { ...stored, ended: true }),
    );
    return changed !== undefined && !changed[0].ended;
  }

  /** The host's rate limit on this agent and its signed-in account: seconds to wait, or undefined. */
  async #admitted(session: CallerSession): Promise<number | undefined> {
    const limit = optionalContribution(this.reactor, CompanyRateLimits, "rate limit");
    if (limit === undefined) return undefined;
    const wait = await limit.admit(session.clientId, session.accountId);
    return wait === undefined ? undefined : Math.max(1, Math.trunc(wait));
  }

  // Mediated Sign-In attempt limits (a company MUST rate-limit attempts) -----------------

  /**
   * What a credential attempt counts against: the account, and the `client_id`. The account
   * is named by the declared fields that are not secret (an email, a username), normalized;
   * its password is never part of a key.
   */
  #attemptKeys(clientId: string, credentials: Readonly<Record<string, unknown>>): string[] {
    const keys = [`${CLIENT_ATTEMPTS}${composite(clientId)}`];
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
        const limit = key.startsWith(CLIENT_ATTEMPTS)
          ? config.maxClientSignInFailures
          : config.maxSignInFailures;
        if (failures >= limit) {
          const over = Math.min(failures - limit, 7);
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

  /** The grant's first request: credentials and `scope` (Mediated Sign-In 3). */
  async #mediatedGrant(form: Readonly<Record<string, string>>, clientId: string): Promise<CompanyResponse> {
    if (Object.hasOwn(form, "sign_in_id") || Object.hasOwn(form, "one_time_code")) return this.#mediatedCode(form, clientId);
    const config = this.config;
    const granted = words(form.scope);
    if (!granted.length || granted.some((scope) => !config.mediatedGrantScopes.includes(scope))) {
      // Missing, unknown, or unavailable scopes are refused, never narrowed.
      throw new Refused(400, "invalid_scope");
    }
    const credentials: Record<string, string> = {};
    for (const [name] of config.mediatedFields) {
      const value = form[name];
      if (value === undefined) throw new Refused(400, "invalid_request");
      credentials[name] = value;
    }
    const keys = this.#attemptKeys(clientId, credentials);
    const locked = await this.#lockedFor(keys);
    if (locked !== undefined) {
      // Locked out: the credentials are not even checked.
      for (const name of Object.keys(credentials)) delete credentials[name];
      throw new RateLimitedRefusal(locked);
    }
    const accounts = firstContribution(this.reactor, CompanyAccounts, "accounts");
    const secrets: Record<string, SecretValue> = {};
    for (const [name, value] of Object.entries(credentials)) {
      secrets[name] = new SecretValue(value);
      delete credentials[name];
    }
    let authenticated: Authenticated | undefined;
    try {
      authenticated = await accounts.authenticate(secrets, { clientId });
    } catch (error) {
      if (error instanceof SignInRefused) throw new Refused(400, "access_denied");
      throw error;
    } finally {
      for (const name of Object.keys(secrets)) delete secrets[name];
    }
    if (authenticated === undefined) {
      await this.#attemptFailed(keys);
      // The same answer for an unknown account and a wrong password.
      throw new Refused(400, "invalid_grant");
    }
    const { accountId, codeReference, sentTo } = authenticated;
    if (codeReference === undefined) {
      await this.#attemptsCleared(keys);
      return this.#signIn(clientId, accountId, granted, granted);
    }
    const codeLocked = await this.#lockedFor([this.#codeKey(accountId)]);
    // Too many wrong codes for this account: no new code until the lockout ends.
    if (codeLocked !== undefined) throw new RateLimitedRefusal(codeLocked);
    const signInId = this.#id("sgn");
    const expiresAt = this.#later(MEDIATED_CODE_LIFETIME_SECONDS);
    const pending: PendingMediated = {
      clientId,
      accountId,
      scopes: granted,
      codeReference,
      expiresAt: expiresAt.toISOString(),
      sentTo: sentTo ?? "your device",
      attemptKeys: keys,
      attempts: 0,
      status: "code_required",
    };
    await this.store.put(
      RecordKinds.mediated,
      signInId,
      json(pending),
      expiry(new Date(expiresAt.getTime() + KEPT_EXPIRED_MS)),
    );
    return this.#codeRequired(signInId, pending);
  }

  /** A code is on its way: send it with `sign_in_id` (Mediated Sign-In 4). */
  #codeRequired(signInId: string, pending: PendingMediated): CompanyResponse {
    const left = Math.ceil((Date.parse(pending.expiresAt) - this.#now().getTime()) / 1000);
    return jsonError(400, "code_required", {
      sign_in_id: signInId,
      sent_to: pending.sentTo,
      expires_in: Math.max(1, left),
    });
  }

  /** The grant's continuation: `sign_in_id` and the code, nothing else (Mediated 4). */
  async #mediatedCode(form: Readonly<Record<string, string>>, clientId: string): Promise<CompanyResponse> {
    const signInId = form.sign_in_id;
    const code = form.one_time_code;
    if (
      signInId === undefined ||
      code === undefined ||
      Object.hasOwn(form, "scope") ||
      this.config.mediatedFields.some(([name]) => Object.hasOwn(form, name))
    ) {
      throw new Refused(400, "invalid_request");
    }
    const pending = await this.#read<PendingMediated>(RecordKinds.mediated, signInId);
    if (pending === undefined || pending.clientId !== clientId) {
      // Unknown, or another client's: the same error for both.
      throw new Refused(400, "invalid_grant");
    }
    if (pending.status !== "code_required") {
      // Once failed or expired, it stays so: the same error again.
      throw new Refused(400, MEDIATED_ENDED[pending.status]);
    }
    if (this.#passed(pending.expiresAt)) return this.#mediatedEnded(signInId, "expired");
    const codeKey = this.#codeKey(pending.accountId);
    if ((await this.#lockedFor([codeKey])) !== undefined) {
      // The account's code budget is spent, whichever sign-in spent it.
      return this.#mediatedEnded(signInId, "failed");
    }
    const accounts = firstContribution(this.reactor, CompanyAccounts, "accounts");
    if (!(await accounts.checkCode(pending.codeReference, new SecretValue(code)))) {
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
      return this.#codeRequired(signInId, pending);
    }
    // One use: of two right codes sent at once, only the one that takes it signs in.
    const completed = (await this.store.take(RecordKinds.mediated, signInId)) as unknown as
      | PendingMediated
      | undefined;
    if (completed === undefined || completed.status !== "code_required") {
      throw new Refused(400, "invalid_grant");
    }
    await this.#attemptsCleared([...completed.attemptKeys, codeKey]);
    return this.#signIn(clientId, completed.accountId, completed.scopes, completed.scopes);
  }

  /** The sign-in ends as `status`, kept so a later code gets the same error. */
  async #mediatedEnded(signInId: string, status: "failed" | "expired"): Promise<never> {
    const changed = await this.#change<PendingMediated>(RecordKinds.mediated, signInId, (current) =>
      current.status !== "code_required" ? current : { ...current, status },
    );
    const ended = changed === undefined ? status : changed[1].status;
    throw new Refused(400, MEDIATED_ENDED[ended === "code_required" ? status : ended]);
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

  async #owned(conversationId: string, session: CallerSession): Promise<StoredConversation> {
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
      if (session.accountId === undefined) throw needsAccount(undefined, this.#accountScopes());
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
    session: CallerSession,
    message: Message,
  ): Promise<StoredConversation> {
    const incoming = plain(message);
    const received = this.#event({ type: "message", message: { ...incoming, role: "user" } });
    const negotiated = await this.#supportsOperations(session.clientId);
    let target: StoredOperation | undefined;
    let changed: readonly [StoredConversation, StoredConversation] | undefined;
    try {
      target = negotiated ? await this.#approvalTarget(session, message.approval) : undefined;
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
    const events: StoredEvent[] = [];
    if (target !== undefined) {
      // Only `approval` approves: its message's text is no question for the agent.
      const event = await this.#conversationApproval(conversationId, session, target, message);
      if (event !== undefined) events.push(event);
    } else if (conversation.responder === "human") {
      return conversation;
    } else if (message.text !== undefined || message.data !== undefined || message.approval === undefined) {
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
        supportsOperations: negotiated,
      });
      for (const reply of replies) {
        const event = await this.#reply(conversationId, session, reply);
        if (event !== undefined) events.push(event);
      }
    }
    const answered = await this.#change<StoredConversation>(
      RecordKinds.conversation,
      conversationId,
      (current) =>
        current.status !== "working"
          ? { ...current, events: [...current.events, ...events] }
          : {
              ...current,
              status: "idle",
              events: [...current.events, ...events, this.#state("idle", current.responder)],
            },
    );
    return answered === undefined ? conversation : answered[1];
  }

  /**
   * A message's approval: the action performed, and how it went, in a later message.
   *
   * A new message with the approval of an operation already performed, or being performed,
   * adds nothing (Operations 7).
   */
  async #conversationApproval(
    conversationId: string,
    session: CallerSession,
    target: StoredOperation,
    message: Message,
  ): Promise<StoredEvent | undefined> {
    if (settledDecision(target) !== undefined) return undefined;
    const approval = message.approval as Approval;
    const latest = latestRevision(target);
    const named = target.revisions.find((item) => item.revision === approval.revision) ?? latest;
    const asked: Asked = {
      action: target.action,
      key: target.key,
      summary: latest.summary,
      terms: latest.terms,
      scopes: target.scopes,
      request: fingerprint("conversation", conversationId),
      digest: named.asked,
    };
    const decision = await this.#decide(session, asked, approval, target);
    const reply: Record<string, unknown> = {
      id: this.#id("msg"),
      author: { type: "agent" },
      role: "company",
    };
    if (decision.operation !== undefined) {
      reply.text = "That approval doesn't cover these terms. Here they are to approve.";
      reply.operation = decision.operation;
    } else if (decision.outcome === undefined) {
      reply.text = "This is still being done. I'll say how it went here.";
    } else {
      reply.text = decision.outcome.summary;
      if (decision.outcome.data !== undefined) reply.data = decision.outcome.data;
    }
    return this.#event({ type: "message", message: reply });
  }

  async #reply(
    conversationId: string,
    session: CallerSession,
    reply: Reply,
  ): Promise<StoredEvent | undefined> {
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
    if (reply.operation !== undefined && (await this.#supportsOperations(session.clientId))) {
      const request = fingerprint("conversation", conversationId);
      const asked = this.#asked(session, reply.operation, request);
      const decision = await this.#decide(session, asked, undefined, undefined);
      message.operation = decision.operation;
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

  // Feedback (§9.3) -----------------------------------------------------------------

  /**
   * Accept a report with the Session header, signed in or out, no scope needed.
   *
   * `task` (at most 200 characters) and `description` (at most 2,000) are required; other
   * members are ignored. The text is kept as data for the operator, never acted on.
   */
  async #feedback(request: CompanyRequest): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const body = jsonObject(request.body);
    const { task, description } = body;
    if (
      typeof task !== "string" ||
      !(task.length > 0 && task.length <= 200) ||
      typeof description !== "string" ||
      !(description.length > 0 && description.length <= 2000)
    ) {
      throw new Refused(400, "invalid_request");
    }
    const report: StoredFeedback = {
      reportId: this.#id("fb"),
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
   * The feedback reports personal agents sent, oldest first, for the operator (§9.3).
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

  // Operations (the extension's sections 3, 6 and 7) -----------------------------------

  /** What a request asks for: one action of one account, or of one signed-out Session. */
  #asked(session: CallerSession, proposal: ProposedOperation, request: string): Asked {
    const scopes = proposal.scopes?.length ? [...proposal.scopes] : [...this.config.writeScopes];
    if (scopes.some((scope) => !this.config.scopes.includes(scope))) {
      throw new RangeError("an operation's scopes must be among the company's scopes");
    }
    return {
      action: proposal.action,
      key: composite(
        session.clientId,
        session.pairwiseUserId,
        session.accountId ?? session.sessionKey,
        proposal.action,
        proposal.subject ?? "",
      ),
      summary: proposal.summary,
      terms: proposal.terms,
      scopes,
      request,
      digest: fingerprint(proposal.summary, proposal.terms ?? null),
    };
  }

  /**
   * Check 1: the operation, if this Session can approve it (Operations 3, 6).
   *
   * One returned signed out can be approved only in that Session. One returned signed in
   * belongs to the account: any Session of the same personal agent and user, signed in to
   * it. A signed-out Session of theirs gets a challenge for the account, and one without its
   * scopes `insufficient_scope`. Anyone else's request is handled as if it had no approval:
   * `undefined`.
   */
  async #approvalTarget(
    session: CallerSession,
    approval: Approval | undefined,
  ): Promise<StoredOperation | undefined> {
    if (approval === undefined) return undefined;
    const stored = await this.#read<StoredOperation>(RecordKinds.operation, approval.operation_id);
    if (stored === undefined || !sameOwner(stored.owner, [session.clientId, session.pairwiseUserId])) {
      return undefined;
    }
    if (stored.accountId === undefined) {
      return stored.sessionKey === session.sessionKey ? stored : undefined;
    }
    if (session.accountId === undefined) throw needsAccount(undefined, stored.scopes);
    if (session.accountId !== stored.accountId) return undefined;
    if (stored.scopes.some((scope) => !session.scopes.includes(scope))) {
      throw needsAccount(session.accountId, stored.scopes);
    }
    return stored;
  }

  /** Check 3: a revision the company returned, unexpired, for exactly this request. */
  #approves(stored: StoredOperation, revision: OperationRevision | undefined, asked: Asked): boolean {
    return (
      revision !== undefined &&
      stored.status === "open" &&
      !revision.withdrawn &&
      this.#now().getTime() <= Date.parse(revision.expiresAt) &&
      revision.request === asked.request &&
      revision.asked === asked.digest
    );
  }

  /** Checks 1 and 2 passed for `target`, if any: check 3, then perform or ask. */
  async #decide(
    session: CallerSession,
    asked: Asked,
    approval: Approval | undefined,
    target: StoredOperation | undefined,
  ): Promise<Decision> {
    if (target !== undefined && approval !== undefined) {
      const revision = target.revisions.find((item) => item.revision === approval.revision);
      if (this.#approves(target, revision, asked)) {
        return this.#perform(target, revision as OperationRevision);
      }
    }
    let current = target?.key === asked.key ? target : undefined;
    if (current === undefined || current.status !== "open") {
      current = await this.#openOperation(asked.key);
    }
    return { operation: await this.#revisionFor(session, current, asked, approval?.revision) };
  }

  async #openOperation(key: string): Promise<StoredOperation | undefined> {
    const known = await this.#read<OperationProposal>(RecordKinds.proposal, key);
    if (known === undefined) return undefined;
    const stored = await this.#read<StoredOperation>(RecordKinds.operation, known.operationId);
    return stored?.status === "open" ? stored : undefined;
  }

  /**
   * The revision to approve for what the request asks: never the one an approval named.
   *
   * The latest one, while it still is what this request asks. Otherwise a new one of the
   * same operation, with the same terms when the company changed them since the action said
   * them (`revise`), or a new operation for a new action.
   */
  async #revisionFor(
    session: CallerSession,
    current: StoredOperation | undefined,
    asked: Asked,
    named: string | undefined,
  ): Promise<Operation> {
    const expiresAt = this.#later(this.config.operationLifetimeSeconds).toISOString();
    let summary = asked.summary;
    let terms = asked.terms;
    if (current !== undefined) {
      const latest = latestRevision(current);
      if (this.#approves(current, latest, asked) && latest.revision !== named) {
        return revisionOperation(current, latest);
      }
      if (latest.request === asked.request && latest.asked === asked.digest) {
        summary = latest.summary;
        terms = latest.terms;
      }
    }
    const fresh: OperationRevision = {
      revision: this.#id("rev"),
      summary,
      ...(terms === undefined ? {} : { terms }),
      expiresAt,
      request: asked.request,
      asked: asked.digest,
      withdrawn: false,
    };
    if (current !== undefined) {
      const changed = await this.#change<StoredOperation>(
        RecordKinds.operation,
        current.operationId,
        (stored) =>
          stored.status !== "open" ? stored : { ...stored, revisions: [...stored.revisions, fresh] },
      );
      if (changed !== undefined && changed[1].status === "open") {
        return revisionOperation(changed[1], fresh);
      }
    }
    const signedIn = session.accountId !== undefined;
    const stored: StoredOperation = {
      operationId: this.#id("op"),
      action: asked.action,
      owner: [session.clientId, session.pairwiseUserId],
      key: asked.key,
      revisions: [fresh],
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      ...(signedIn ? {} : { sessionKey: session.sessionKey }),
      scopes: signedIn ? asked.scopes : [],
      status: "open",
    };
    await this.store.put(RecordKinds.operation, stored.operationId, json(stored));
    const pointer: OperationProposal = { operationId: stored.operationId };
    await this.store.put(RecordKinds.proposal, asked.key, json(pointer));
    return revisionOperation(stored);
  }

  /** The one compare-and-set from `open` to `performing`: only its winner performs. */
  async #perform(target: StoredOperation, revision: OperationRevision): Promise<Decision> {
    const approvedAt = this.#now().toISOString();
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      target.operationId,
      (current) =>
        current.status !== "open"
          ? current
          : { ...current, status: "performing", approved: revision.revision, approvedAt },
    );
    if (changed === undefined) return {};
    const [before, claimed] = changed;
    if (before.status !== "open") return settledDecision(claimed) ?? {};
    const executors = this.reactor
      .getContributions(OperationExecutors)
      .filter((contribution) => contribution.value.action === claimed.action);
    const executor = executors[0]?.value;
    if (executor === undefined || executors[1]?.order === executors[0]?.order) {
      // Nobody can perform it: being performed, rather than claim a failure.
      return {};
    }
    let result: ActionResult;
    try {
      result = await executor.perform(revisionOperation(claimed, revision), claimed.accountId);
    } catch (error) {
      if (error instanceof OperationFailed) {
        // Failed partway: the result says every change that was made.
        return this.#finish(claimed, error.result, false);
      }
      // Never reported as failed while it may have taken effect (Operations 7).
      if (error instanceof OperationOutcomeUnknown) return {};
      throw error;
    }
    return this.#finish(claimed, result, true);
  }

  async #finish(claimed: StoredOperation, result: ActionResult, succeeded: boolean): Promise<Decision> {
    const outcome = outcomeOf(result, succeeded);
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      claimed.operationId,
      (current) =>
        current.status !== "performing" ? current : { ...current, status: "performed", outcome },
    );
    return { outcome: changed === undefined ? outcome : changed[1].outcome };
  }

  /** An operation as the company keeps it: each revision, action, owner, and outcome. */
  async operationRecord(operationId: string): Promise<StoredOperation> {
    const stored = await this.#read<StoredOperation>(RecordKinds.operation, operationId);
    if (stored === undefined) throw new Error("unknown operation");
    return stored;
  }

  /** The company changes an operation's terms: a new revision, earlier ones withdrawn. */
  async revise(
    operationId: string,
    changes: { readonly summary: string; readonly terms: Readonly<Record<string, unknown>> },
  ): Promise<Operation> {
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      operationId,
      (stored) => {
        if (stored.status !== "open") {
          throw new Error("only an operation not yet approved can be revised");
        }
        return {
          ...stored,
          revisions: [
            ...stored.revisions.map((item) => ({ ...item, withdrawn: true })),
            {
              ...latestRevision(stored),
              revision: this.#id("rev"),
              summary: changes.summary,
              terms: changes.terms,
              expiresAt: this.#later(this.config.operationLifetimeSeconds).toISOString(),
            },
          ],
        };
      },
    );
    if (changed === undefined) throw new Error("unknown operation");
    return revisionOperation(changed[1]);
  }

  /** The company found out how an operation being performed ended. */
  async settle(
    operationId: string,
    result: ActionResult,
    options: { readonly succeeded: boolean },
  ): Promise<StoredOperation> {
    const changed = await this.#change<StoredOperation>(
      RecordKinds.operation,
      operationId,
      (stored) => {
        if (stored.status !== "performing") {
          throw new Error("only an operation being performed can be settled");
        }
        return { ...stored, status: "performed", outcome: outcomeOf(result, options.succeeded) };
      },
    );
    if (changed === undefined) throw new Error("unknown operation");
    return changed[1];
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

  #isOpen(stored: StoredOperation): boolean {
    if (stored.status === "performing") return true;
    return (
      stored.status === "open" &&
      stored.revisions.some(
        (item) => !item.withdrawn && this.#now().getTime() <= Date.parse(item.expiresAt),
      )
    );
  }

  /** What is under way: open operations and sign-ins not ended, read from the store. */
  async openWork(): Promise<OpenWork> {
    const operations: Operation[] = [];
    for (const record of await this.store.records(RecordKinds.operation)) {
      const stored = record.value as unknown as StoredOperation;
      if (this.#isOpen(stored)) operations.push(revisionOperation(stored));
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
   * Settle every open operation, because of `reason` (a sentence).
   *
   * For a company being taken down: nothing will perform or settle them after, and a
   * personal agent retrying an approval would otherwise wait for ever. One not yet approved
   * is withdrawn, never to be performed. One being performed may have changed something
   * before it stopped: a retry is told so, as a failure whose summary says it. Resolves to
   * how many were settled.
   */
  async settleOpenOperations(reason: string): Promise<number> {
    const why = reason.trim();
    if (!why) throw new Error("say why the operations are settled");
    const stopped: OperationOutcome = {
      summary:
        "It was stopped before it finished, and nothing more will be done: " +
        `whatever it changed until then stands. ${why}`,
      succeeded: false,
    };
    let settled = 0;
    for (const record of await this.store.records(RecordKinds.operation)) {
      const { operationId } = record.value as unknown as StoredOperation;
      const changed = await this.#change<StoredOperation>(
        RecordKinds.operation,
        operationId,
        (latest) => {
          if (!this.#isOpen(latest)) return latest;
          if (latest.status === "performing") {
            return { ...latest, status: "performed", outcome: stopped };
          }
          return { ...latest, status: "withdrawn" };
        },
      );
      if (changed !== undefined && this.#isOpen(changed[0])) settled += 1;
    }
    return settled;
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

  // Web browsing (§6) -----------------------------------------------------------------

  /**
   * Step 1 of joining a browser (§6): a form with a one-time code, tied to this browser.
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
        "<button>Continue</button></form>",
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
   * Step 2 (§6): the personal agent authorizes a code for its Session, and account.
   *
   * The Session header is checked as at any resource, which starts the Session if its `sid`
   * is new; a code that isn't one issued, unexpired, and not authorized before is
   * `invalid_request`. HTTP 204.
   */
  async #authorizeJoin(request: CompanyRequest): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const code = jsonObject(request.body).code;
    if (typeof code !== "string" || !code) throw new Refused(400, "invalid_request");
    const stored = await this.#read<StoredSession>(
      RecordKinds.session,
      session.sessionKey,
    );
    if (stored === undefined) throw new Refused(400, "invalid_request");
    const authorized: WebSession = {
      clientId: session.clientId,
      sid: session.sid,
      pairwiseUserId: session.pairwiseUserId,
      ...(session.agentId === undefined ? {} : { agentId: session.agentId }),
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      scopes: session.scopes,
      ...(session.family === undefined ? {} : { family: session.family }),
      expiresAt: stored.endsAt,
    };
    const changed = await this.#change<JoinCode>(RecordKinds.joinCode, digest(code), (current) => {
      if (current.authorized !== undefined) throw new Refused(400, "invalid_request");
      return { ...current, authorized };
    });
    if (changed === undefined) throw new Refused(400, "invalid_request");
    return { status: 204, headers: { ...NO_STORE } };
  }

  /**
   * Step 3 (§6): the browser submits the code with step 1's cookie: the Session's cookie.
   *
   * A code is used by the first request that submits it, whatever the result; one not
   * authorized in step 2 sets no cookie.
   */
  async #browserSession(request: CompanyRequest): Promise<CompanyResponse> {
    const refused = page(
      400,
      "This browser could not join the session.",
      `${JOIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`,
    );
    const code = pairs(text(request.body)).code ?? "";
    const browser = cookie(request, JOIN_COOKIE);
    const issued = code
      ? ((await this.store.take(RecordKinds.joinCode, digest(code))) as unknown as JoinCode | undefined)
      : undefined;
    if (
      issued?.authorized === undefined ||
      browser === undefined ||
      !sameText(issued.browser, digest(browser))
    ) {
      return refused;
    }
    const joined = issued.authorized;
    if (!(await this.#allowed(joined.clientId)) || this.#passed(joined.expiresAt)) return refused;
    const webCookie = this.#id("web");
    await this.store.put(
      RecordKinds.browserCookie,
      digest(webCookie),
      json(joined),
      expiry(joined.expiresAt),
    );
    const exchange = exchanges.getStore();
    if (exchange !== undefined) exchange.clientId = joined.clientId;
    this.#reportSession(joined.accountId !== undefined, "web");
    return {
      status: 303,
      headers: {
        Location: `${this.config.base}/`,
        // The company's own cookie, `__Host-`: no Max-Age, only as alive as its Session
        // (§6). The join cookie is cleared; several cookies are one per line.
        "Set-Cookie":
          `${WEB_COOKIE}=${webCookie}; Path=/; Secure; HttpOnly; SameSite=Strict\n` +
          `${JOIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict`,
        ...NO_STORE,
      },
    };
  }

  /**
   * The Session a browser's cookie stands for, as it is now, for the company's pages (§6).
   *
   * Signed out once its sign-in has ended (§5.5); gone once its Session has.
   */
  async webSession(webCookie: string | undefined): Promise<CallerSession | undefined> {
    if (webCookie === undefined) return undefined;
    const joined = await this.#read<WebSession>(RecordKinds.browserCookie, digest(webCookie));
    if (joined === undefined) return undefined;
    const key = composite(joined.clientId, joined.sid);
    const stored = await this.#read<StoredSession>(RecordKinds.session, key);
    if (stored === undefined || stored.ended || this.#passed(stored.endsAt)) {
      // The cookie does not outlive the Session.
      await this.store.delete(RecordKinds.browserCookie, digest(webCookie));
      return undefined;
    }
    let signedIn = joined.accountId !== undefined;
    if (joined.family !== undefined) {
      const family = await this.#read<AccountFamily>(RecordKinds.accountFamily, joined.family);
      const grant = await this.#read<AccountGrant>(RecordKinds.refreshToken, joined.family);
      if (family === undefined || family.revoked || (grant !== undefined && (await this.#signInEnded(grant)))) {
        // The User signed out or disconnected the agent: no account any more.
        signedIn = false;
      }
    }
    return {
      sessionKey: key,
      clientId: joined.clientId,
      sid: joined.sid,
      pairwiseUserId: joined.pairwiseUserId,
      ...(joined.agentId === undefined ? {} : { agentId: joined.agentId }),
      ...(signedIn && joined.accountId !== undefined ? { accountId: joined.accountId } : {}),
      scopes: signedIn ? joined.scopes : [],
      ...(signedIn && joined.family !== undefined ? { family: joined.family } : {}),
    };
  }
}

/** HTTP 429 and `Retry-After`, and no body (§5.6). */
function rateLimited(retryAfter: number): CompanyResponse {
  return { status: 429, headers: { "Retry-After": String(retryAfter), ...NO_STORE } };
}

/** An outcome as the company keeps it: the summary, its data, and how it ended. */
function outcomeOf(result: ActionResult, succeeded: boolean): OperationOutcome {
  return {
    summary: result.summary,
    ...(result.data === undefined ? {} : { data: result.data }),
    succeeded,
  };
}

/** Check 2: what an operation performed, or being performed, answers (Operations 7). */
function settledDecision(stored: StoredOperation): Decision | undefined {
  if (stored.status === "performed") return { outcome: stored.outcome };
  if (stored.status === "performing") return {};
  return undefined;
}

/** The API's answer: the operation, what it came to, or `503` while it is performed. */
function apiDecision(decision: Decision): CompanyResponse {
  if (decision.operation !== undefined) {
    return jsonError(403, "approval_required", { operation: decision.operation });
  }
  const outcome = decision.outcome;
  if (outcome === undefined) {
    return jsonError(503, "temporarily_unavailable", {}, { "Retry-After": PERFORMING_RETRY_AFTER });
  }
  const body = { summary: outcome.summary, ...(outcome.data === undefined ? {} : { data: outcome.data }) };
  if (outcome.succeeded) return { status: 200, body, headers: {} };
  // It didn't finish: an API error, saying every change that was made.
  return { status: 422, body: { error: "action_failed", ...body }, headers: {} };
}

/** The tool's result: the operation, what it came to, or `503` while it is performed. */
function mcpDecision(
  decision: Decision,
): { readonly result: Record<string, unknown> } | { readonly refused: CompanyResponse } {
  const { operation, outcome } = decision;
  if (operation !== undefined) {
    return {
      result: {
        isError: true,
        content: [{ type: "text", text: `Not done yet. This needs the user's approval: ${operation.summary}` }],
        structuredContent: { operation },
      },
    };
  }
  if (outcome === undefined) {
    return {
      refused: jsonError(503, "temporarily_unavailable", {}, { "Retry-After": PERFORMING_RETRY_AFTER }),
    };
  }
  const result: Record<string, unknown> = { content: [{ type: "text", text: outcome.summary }] };
  if (outcome.data !== undefined) result.structuredContent = outcome.data;
  if (!outcome.succeeded) result.isError = true;
  return { result };
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
