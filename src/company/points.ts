/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The company side's Reactor contribution points, and their in-memory defaults.
 *
 * A company assembles its PAP service from contributions, each replaceable
 * without touching the service (the same ids as the Python SDK):
 *
 * - `pap.company.store` keeps Sessions, tokens, sign-ins, conversations, and
 *   operations as versioned JSON records (`store.ts`; in memory by default, a
 *   database in production).
 * - `pap.company.accounts` checks a user's credentials and second factor for
 *   Mediated Sign-In.
 * - `pap.company.agent` answers conversation messages: the company agent.
 * - `pap.company.operationExecutor` performs an approved operation, by action.
 * - `pap.company.clientPolicy` allows or blocks personal agents by `client_id`.
 * - `pap.company.clientResolver` fetches a personal agent's client metadata
 *   and JWKS (over HTTPS through `AgentIdentityClient` by default).
 * - `pap.company.replayCache` remembers assertion and proof IDs once: by default in
 *   the contributed store (`StoreReplayCache`), so every replica sharing a durable
 *   store shares the cache.
 * - `pap.company.api` answers the company's OpenAPI API (`/api/…`), its
 *   consequential calls needing the user's approval (`403 approval_required`,
 *   Operations 4).
 * - `pap.company.mcp` answers the company's MCP server (`/mcp`), its tools
 *   returning operations in `structuredContent` (§7, Operations 4).
 * - `pap.company.rateLimit` says how often the company answers one personal
 *   agent and one signed-in account: once a request's Session is verified, a
 *   refusal is HTTP 429 with `Retry-After`, and no body. None by default.
 */

import { createHash } from "node:crypto";

import { defineContributionPoint } from "@datalayer/reactor";

import type { ClientMetadata, JsonWebKeySet, Operation } from "../models.js";
import type { SecretValue } from "../secret.js";
import { RecordKinds, type CompanyStore } from "./store.js";

export * from "./store.js";

/** Mediated Sign-In's first step: the account, and a code to ask for when needed. */
export interface Authenticated {
  readonly accountId: string;
  readonly codeReference?: string;
  readonly sentTo?: string;
}

/** Who a Mediated Sign-In attempt comes from: the agent, by its `client_id`. */
export interface SignInContext {
  readonly clientId: string;
}

/** The Company refuses this sign-in, whatever the credentials: `access_denied`. */
export class SignInRefused extends Error {
  constructor(message = "the sign-in is refused") {
    super(message);
    this.name = "SignInRefused";
  }
}

/**
 * The company's own accounts: credentials and second factors.
 *
 * The service limits Mediated Sign-In attempts itself (by account identifier, by
 * `client_id`, and wrong codes by account), but a directory MUST also throttle its own
 * checks: it is the one place that sees every path to an account, and `context` says which
 * agent each attempt comes from. `authenticate` throws `SignInRefused` to refuse a sign-in
 * outright.
 */
export interface AccountDirectory {
  authenticate(
    credentials: Readonly<Record<string, SecretValue>>,
    context: SignInContext,
  ): Promise<Authenticated | undefined>;
  checkCode(codeReference: string, code: SecretValue): Promise<boolean>;
  /**
   * Since when the account's earlier sign-ins are over, or `undefined` when nothing ended
   * them: a password reset, an account locked or recovered. Every sign-in to the account
   * from before that moment ends — its tokens refused and revoked, the Sessions that used
   * them continuing signed out — while a sign-in after it works. Asked on every signed-in
   * request, so a directory answers from a cache it keeps short. Python's `AccountSignOuts`.
   */
  signedOutBefore?(accountId: string): Promise<Date | undefined>;
}

/** One message the company agent answers, and who it is answering. */
export interface Turn {
  readonly conversationId: string;
  readonly text?: string;
  readonly data?: Readonly<Record<string, unknown>>;
  /** Who wrote the message: the personal agent or its user (`author.type`, §7.4, §7.8). */
  readonly author: "agent" | "human";
  readonly accountId?: string;
  readonly scopes: readonly string[];
  readonly clientId: string;
  readonly isDirect: boolean;
  /**
   * Whether the personal agent negotiated Operations: without it, an operation is never
   * sent, so the agent's words must not promise one.
   */
  readonly supportsOperations: boolean;
}

/**
 * What an action needs the user's approval of; the service gives it its IDs and expiry.
 *
 * `action` says which executor performs it, and with `subject`, what it is done to in the
 * company's records, such as the order: requests for the same action and subject are one
 * operation, whose terms can change (Operations 3). `summary` and `terms` are what it would
 * do now: anything that affects the action is in them. `scopes` are what a Session must
 * hold to approve it, recorded with it; none named, the company's `writeScopes`.
 */
export interface ProposedOperation {
  readonly action: string;
  readonly summary: string;
  readonly terms?: Readonly<Record<string, unknown>>;
  readonly subject?: string;
  readonly scopes?: readonly string[];
}

/**
 * What the company agent says back.
 *
 * `authorization` asks the personal agent to sign in or widen scopes (§7.11)
 * instead of answering; `operation` asks for the user's approval with the
 * reply (Operations 4).
 */
export interface Reply {
  readonly text?: string;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly operation?: ProposedOperation;
  readonly authorization?: readonly ["insufficient_scope", string];
  readonly userRequested?: string;
  /** The AI persona writing, when the company names one: `id`, `name`, `image` (§7.4). */
  readonly persona?: Readonly<{ id?: string; name?: string; image?: string }>;
}

/** Answer one turn of a conversation. */
export interface CompanyAgent {
  respond(turn: Turn): Promise<readonly Reply[]>;
}

/** What an action came to: the response a request with the approval gets, every time. */
export interface ActionResult {
  readonly summary: string;
  readonly data?: Readonly<Record<string, unknown>>;
}

/** The action was not completed; `result.summary` says every change that was made. */
export class OperationFailed extends Error {
  readonly result: ActionResult;

  constructor(result: ActionResult) {
    super(result.summary);
    this.name = "OperationFailed";
    this.result = result;
  }
}

/** A downstream system did not answer: retries get `503` until `settle` (Operations 7). */
export class OperationOutcomeUnknown extends Error {
  constructor(message = "the outcome is not known") {
    super(message);
    this.name = "OperationOutcomeUnknown";
  }
}

/**
 * Perform one approved operation; `operation_id` is its idempotency key.
 *
 * `operation` is the revision the user approved, and `accountId` the account it belongs
 * to, `undefined` for one returned signed out. Return the result of a completed action;
 * throw `OperationFailed` with the changes made when it failed partway, or
 * `OperationOutcomeUnknown` while it is not known whether it took effect (never reported
 * as failed).
 */
export interface OperationExecutor {
  readonly action: string;
  perform(operation: Operation, accountId: string | undefined): Promise<ActionResult>;
}

/** Allow or block a personal agent by its `client_id`. */
export interface ClientPolicy {
  allows(clientId: string): Promise<boolean>;
}

/** The default policy: any agent with valid identity is welcome. */
export class AllowEveryAgent implements ClientPolicy {
  async allows(_clientId: string): Promise<boolean> {
    return true;
  }
}

/**
 * Resolve a `client_id` to its verified metadata and keys. `kid` is the key an
 * assertion names: a resolver that caches keys fetches them again when the
 * cached set lacks it (rate-limited; Guides, rotating keys).
 */
export interface ClientResolver {
  resolve(
    clientId: string,
    options?: { readonly kid?: string },
  ): Promise<readonly [ClientMetadata, JsonWebKeySet]>;
}

/** Remember an assertion or Session JWT ID once. */
export interface ReplayCache {
  markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean>;
}

const FIRST_SWEEP = 1024;
/** A mark is kept a second past its expiry, so an identifier is refused until then, inclusive. */
const INCLUSIVE_MS = 1000;

/**
 * The default replay cache: one atomic `create` in the company's store per identifier.
 *
 * The identifier is kept (as its SHA-256) until a second after its `expiresAt`, so it is
 * refused until its expiry, inclusive. The store is looked up at each call, the
 * contributed `pap.company.store`: a durable store shared by every replica implies a
 * replay cache shared by every replica, so a proof captured at one replica is refused at
 * another, and after a restart. With the memory store it is one process, as that store is.
 */
export class StoreReplayCache implements ReplayCache {
  readonly #store: () => CompanyStore;

  constructor(store: () => CompanyStore) {
    this.#store = store;
  }

  async markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean> {
    const digest = createHash("sha256").update(key).digest("hex");
    return this.#store().create(RecordKinds.replay, digest, {}, {
      expiresAt: new Date(options.expiresAt.getTime() + INCLUSIVE_MS),
    });
  }
}

/**
 * A replay cache in one process, entries dropped after expiry (not the default): for a
 * verifier used on its own (`verifyAssertion`, `verifySessionJwt`); a company's default
 * is `StoreReplayCache` over its store.
 *
 * An identifier is refused until its `expiresAt` by `clock` (the assertion or proof it
 * names is refused as expired after that). Expired entries are swept whenever the cache
 * has doubled since the last sweep, so it holds about twice the identifiers still alive,
 * never every one ever seen.
 */
export class MemoryReplayCache implements ReplayCache {
  #seen = new Map<string, number>();
  #sweepAt = FIRST_SWEEP;
  clock: { now(): Date };

  constructor(options: { readonly clock?: { now(): Date } } = {}) {
    this.clock = options.clock ?? { now: () => new Date() };
  }

  get size(): number {
    return this.#seen.size;
  }

  async markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean> {
    const now = this.clock.now().getTime();
    const seen = this.#seen.get(key);
    // Seen until its expiry, inclusive: a proof accepted at its last instant
    // is not accepted again at that same instant.
    if (seen !== undefined && now <= seen) return false;
    this.#seen.set(key, options.expiresAt.getTime());
    if (this.#seen.size >= this.#sweepAt) {
      this.#seen = new Map([...this.#seen].filter(([, until]) => now < until));
      this.#sweepAt = Math.max(FIRST_SWEEP, 2 * this.#seen.size);
    }
    return true;
  }
}


/** One verified call to the company's API: who, with what authority. */
export interface ApiCall {
  readonly method: string;
  readonly path: string;
  readonly query: Readonly<Record<string, string>>;
  readonly body: unknown;
  readonly accountId?: string;
  readonly scopes: readonly string[];
  readonly clientId: string;
  /** The request came with an approval (Operations 6): a company tells a retry from a first ask. */
  readonly carriesApproval?: boolean;
}

/** The API's answer: a JSON body, or an operation (`403 approval_required`). */
export interface ApiResult {
  readonly status?: number;
  readonly body?: unknown;
  readonly operation?: ProposedOperation;
}

export const ApiResults = {
  insufficientScope(scope: string): ApiResult {
    return { status: 403, body: { error: "insufficient_scope", scope } };
  },
  notFound(): ApiResult {
    return { status: 404, body: { error: "not_found" } };
  },
} as const;

/** The company's OpenAPI API: its description, and each call. */
export interface CompanyApi {
  readonly description: string;
  openapi(): Readonly<Record<string, unknown>>;
  handle(call: ApiCall): Promise<ApiResult>;
}

/**
 * An MCP tool's answer: text and structured content, or an operation to approve.
 *
 * `refusal` is `[status, error, scope]` for a token error the server returns
 * over HTTP with a Bearer challenge (`insufficient_scope`, naming the scopes needed).
 */
export interface ToolResult {
  readonly text?: string;
  readonly structured?: Readonly<Record<string, unknown>>;
  readonly operation?: ProposedOperation;
  readonly isError?: boolean;
  readonly refusal?: readonly [status: number, error: string, scope: string | undefined];
}

export const ToolResults = {
  insufficientScope(scope: string): ToolResult {
    return { refusal: [403, "insufficient_scope", scope] };
  },
} as const;

/** The company's MCP server: its tools, and each call (with the caller's authority). */
export interface CompanyMcp {
  readonly description: string;
  tools(): readonly Readonly<Record<string, unknown>>[];
  call(name: string, args: Readonly<Record<string, unknown>>, call: ApiCall): Promise<ToolResult>;
}

export const CompanyStores = defineContributionPoint<CompanyStore>("pap.company.store");
export const CompanyAccounts = defineContributionPoint<AccountDirectory>("pap.company.accounts");
export const CompanyAgents = defineContributionPoint<CompanyAgent>("pap.company.agent");
export const OperationExecutors = defineContributionPoint<OperationExecutor>(
  "pap.company.operationExecutor",
);
export const ClientPolicies = defineContributionPoint<ClientPolicy>("pap.company.clientPolicy");
export const ClientResolvers = defineContributionPoint<ClientResolver>(
  "pap.company.clientResolver",
);
export const ReplayCaches = defineContributionPoint<ReplayCache>("pap.company.replayCache");
export const CompanyApis = defineContributionPoint<CompanyApi>("pap.company.api");
export const CompanyMcps = defineContributionPoint<CompanyMcp>("pap.company.mcp");

/**
 * How often the company answers one personal agent, and one signed-in account.
 * Asked once a request's Session is verified, before anything is done for it:
 * `undefined` lets it through; a number of seconds refuses it as HTTP 429 with
 * `Retry-After` saying when to ask again, and no body. The host keeps the counts,
 * shared by every replica answering for the company. None contributed: no limit
 * beyond the protocol's own.
 */
export interface RateLimit {
  admit(clientId: string, accountId: string | undefined): Promise<number | undefined>;
}

export const CompanyRateLimits = defineContributionPoint<RateLimit>("pap.company.rateLimit");
