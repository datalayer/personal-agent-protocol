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
export class MemoryReplayCache implements ReplayCache {
  readonly #seen = new Map<string, Date>();

  async markOnce(key: string, options: { readonly expiresAt: Date }): Promise<boolean> {
    if (this.#seen.has(key)) return false;
    this.#seen.set(key, options.expiresAt);
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
