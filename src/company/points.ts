/**
 * The company side's Reactor contribution points, and their in-memory defaults.
 *
 * A company assembles its PAP service from contributions, each replaceable
 * without touching the service (the same ids as the Python SDK):
 *
 * - `pap.company.store` keeps Sessions, Account Tokens, sign-ins,
 *   conversations, and operations as versioned JSON records (`store.ts`; in
 *   memory by default, a database in production).
 * - `pap.company.accounts` checks a user's credentials and second factor for
 *   Mediated Sign-In.
 * - `pap.company.agent` answers conversation messages: the company agent.
 * - `pap.company.operationExecutor` performs a confirmed operation, by action.
 * - `pap.company.clientPolicy` allows or blocks personal agents by `client_id`.
 * - `pap.company.clientResolver` fetches a personal agent's client metadata
 *   and JWKS (over HTTPS through `AgentIdentityClient` by default).
 * - `pap.company.replayCache` remembers assertion and proof IDs once.
 * - `pap.company.api` answers the company's OpenAPI API (`/api/…`), its
 *   consequential calls proposing operations (`202`, Operations §4.1).
 * - `pap.company.mcp` answers the company's MCP server (`/mcp`), its tools
 *   proposing operations in `structuredContent` (§6, Operations §4.2).
 */

import { defineContributionPoint } from "@datalayer/reactor";

import type {
  ClientMetadata,
  JsonWebKeySet,
  Operation,
  OperationResult,
} from "../models.js";
import type { SecretValue } from "../secret.js";
import type { CompanyStore } from "./store.js";

export * from "./store.js";

/** Mediated Sign-In's first step: the account, and a code to ask for when needed. */
export interface Authenticated {
  readonly accountId: string;
  readonly codeReference?: string;
  readonly sentTo?: string;
}

/** The company's own accounts: credentials and second factors. */
export interface AccountDirectory {
  authenticate(credentials: Readonly<Record<string, SecretValue>>): Promise<Authenticated | undefined>;
  checkCode(codeReference: string, code: SecretValue): Promise<boolean>;
}

/** One message the company agent answers, and who it is answering. */
export interface Turn {
  readonly conversationId: string;
  readonly text?: string;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly sender: "agent" | "human";
  readonly accountId?: string;
  readonly scopes: readonly string[];
  readonly clientId: string;
  readonly isDirect: boolean;
}

/** An operation the agent proposes; the service gives it an ID and expiry. */
export interface ProposedOperation {
  readonly action: string;
  readonly summary: string;
  readonly terms: Readonly<Record<string, unknown>>;
  readonly userApprovalRequired?: boolean;
}

/**
 * What the company agent says back.
 *
 * `authorization` asks the personal agent to sign in or widen scopes (§7.11)
 * instead of answering; `operation` proposes an operation with the reply
 * (Operations §4.3).
 */
export interface Reply {
  readonly text?: string;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly operation?: ProposedOperation;
  readonly authorization?: readonly ["sign_in_required" | "insufficient_scope", string];
  readonly userRequested?: string;
}

/** Answer one turn of a conversation. */
export interface CompanyAgent {
  respond(turn: Turn): Promise<readonly Reply[]>;
}

/** The action was not completed; `result.summary` says every change that was made. */
export class OperationFailed extends Error {
  readonly result: OperationResult;

  constructor(result: OperationResult) {
    super(result.summary);
    this.name = "OperationFailed";
    this.result = result;
  }
}

/** A downstream system did not answer: the operation stays `in_progress` (Operations §6). */
export class OperationOutcomeUnknown extends Error {
  constructor(message = "the outcome is not known") {
    super(message);
    this.name = "OperationOutcomeUnknown";
  }
}

/**
 * Perform one confirmed operation; `operation_id` is its idempotency key.
 *
 * Return the result of a completed action; throw `OperationFailed` with the
 * changes made when it failed partway, or `OperationOutcomeUnknown` while it
 * is not known whether it took effect (never reported as failed).
 */
export interface OperationExecutor {
  readonly action: string;
  perform(operation: Operation, accountId: string): Promise<OperationResult>;
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

/** Remember an assertion or proof ID once (the `DpopReplayCache` shape). */
export interface ReplayCache {
  markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean>;
}

/**
 * The default replay cache: one process, every ID kept.
 *
 * It keeps each expiry but never prunes on the wall clock: a company's clock
 * is a contribution, and an ID dropped early could be replayed.
 */
const FIRST_SWEEP = 1024;

/**
 * The default replay cache: one process, entries dropped after expiry.
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
}

/** The API's answer: a JSON body, or an operation to propose (`202`). */
export interface ApiResult {
  readonly status?: number;
  readonly body?: unknown;
  readonly operation?: ProposedOperation;
}

export const ApiResults = {
  signInRequired(scope: string): ApiResult {
    return { status: 403, body: { error: "sign_in_required", scope } };
  },
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
 * An MCP tool's answer: text and structured content, or an operation to propose.
 *
 * `refusal` is `[status, error, scope]` for a token error the server returns
 * over HTTP with a Bearer challenge (`sign_in_required`, `insufficient_scope`).
 */
export interface ToolResult {
  readonly text?: string;
  readonly structured?: Readonly<Record<string, unknown>>;
  readonly operation?: ProposedOperation;
  readonly isError?: boolean;
  readonly refusal?: readonly [status: number, error: string, scope: string | undefined];
}

export const ToolResults = {
  signInRequired(scope: string): ToolResult {
    return { refusal: [403, "sign_in_required", scope] };
  },
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
