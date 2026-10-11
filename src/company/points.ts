/**
 * The company side's Reactor contribution points, and their in-memory defaults.
 *
 * A company assembles its PAP service from contributions, each replaceable
 * without touching the service (the same ids as the Python SDK):
 *
 * - `pap.company.store` keeps Sessions, Account Tokens, sign-ins,
 *   conversations, and operations (in memory by default; a database in
 *   production).
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

/** A Session the company issued; its token is bound to a DPoP key. */
export interface IssuedSession {
  readonly sessionId: string;
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly keyThumbprint: string;
  readonly expiresAt: Date;
  readonly accountId?: string;
  readonly scopes: readonly string[];
  /** The digest of the Account Token this Session is signed in with. */
  readonly accountToken?: string;
  readonly resource?: string;
}

/** What an Account Token is: one account, one agent, one user, some scopes. */
export interface AccountGrant {
  /** The sign-in it comes from: every token rotated from it shares it (§4.9). */
  readonly family: string;
  readonly accountId: string;
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
  revoked: boolean;
}

export interface PendingDevice {
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly userCode: string;
  readonly expiresAt: Date;
  interval: number;
  lastPoll?: Date;
  accountId?: string;
  granted: readonly string[];
  denied: boolean;
}

/** A Direct Sign-In request waiting on the user's decision on the company's page. */
export interface PendingAuthorization {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly state: string;
  readonly codeChallenge: string;
  readonly expiresAt: Date;
  /** The agent's `client_name`, for a hosted consent page (`authorizationRequest`). */
  readonly clientName?: string;
}

/** A one-use authorization code, at most a minute old. */
export interface IssuedCode {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  readonly accountId: string;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
}

export interface PendingMediated {
  readonly sessionId: string;
  readonly accountId: string;
  readonly scopes: readonly string[];
  readonly codeReference: string;
  readonly expiresAt: Date;
  attempts: number;
}

export interface StoredEvent {
  readonly id: string;
  readonly payload: Readonly<Record<string, unknown>>;
}

export type StoredConversationStatus = "working" | "idle" | "queued" | "closed";

export interface StoredConversation {
  readonly conversationId: string;
  /** `[client_id, pairwise user ID]`: only that pair sees the conversation. */
  readonly owner: readonly [string, string];
  status: StoredConversationStatus;
  responder: "agent" | "human";
  readonly parentId?: string;
  directChild?: string;
  /** The account the conversation used; from then on it belongs to that account. */
  accountId?: string;
  readonly events: StoredEvent[];
  /** Event IDs the company no longer keeps: a cursor naming one is `cursor_expired`. */
  readonly forgotten: Set<string>;
}

export interface StoredOperation {
  operation: Operation;
  readonly action: string;
  readonly owner: readonly [string, string];
  readonly accountId: string;
  performed: boolean;
}

/** Everything a company remembers, by kind and key. */
export interface CompanyStore {
  /** Sessions by the digest of their access token. */
  readonly sessions: Map<string, IssuedSession>;
  /** Account Tokens by digest. */
  readonly accountTokens: Map<string, AccountGrant>;
  /** Pending device sign-ins by the digest of their device code. */
  readonly devices: Map<string, PendingDevice>;
  readonly authorizations: Map<string, PendingAuthorization>;
  /** Authorization codes by digest. */
  readonly codes: Map<string, IssuedCode>;
  readonly mediated: Map<string, PendingMediated>;
  readonly conversations: Map<string, StoredConversation>;
  readonly operations: Map<string, StoredOperation>;
  /** `conversation_id:digest` by `client_id`, pairwise user ID and message ID. */
  readonly messageIds: Map<string, string>;
}

/** The default store: one process, nothing persisted. */
export class MemoryCompanyStore implements CompanyStore {
  readonly sessions = new Map<string, IssuedSession>();
  readonly accountTokens = new Map<string, AccountGrant>();
  readonly devices = new Map<string, PendingDevice>();
  readonly authorizations = new Map<string, PendingAuthorization>();
  readonly codes = new Map<string, IssuedCode>();
  readonly mediated = new Map<string, PendingMediated>();
  readonly conversations = new Map<string, StoredConversation>();
  readonly operations = new Map<string, StoredOperation>();
  readonly messageIds = new Map<string, string>();
}

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
