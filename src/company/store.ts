/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * What a company remembers: an async keyed store of JSON records, and the records.
 *
 * A `CompanyStore` (the `pap.company.store` contribution) keeps JSON objects
 * by kind and key, each with a version and an optional expiry. The service
 * never changes a record in place: every change is an explicit write, and
 * every transition that must not race between replicas goes through `create`
 * (only if absent), `take` (read and delete at once), or `replace`
 * (compare-and-set on the version read). An expired record reads as absent.
 *
 * Any backend (a database, a key-value service) implements the seven methods;
 * `checkStore` (`./testing.js`) checks one. `MemoryCompanyStore` is the
 * default: one process, nothing persisted. The port of the Python
 * `personal_agent_protocol.company.store`.
 */

import type { Operation } from "../models.js";
import type { Clock } from "../reactor.js";

/** A record as stored: a JSON object (strings, numbers, booleans, null, arrays, objects). */
export type JsonObject = { readonly [key: string]: unknown };

/** A record read from the store: its value, its version, and when it expires. */
export interface StoredRecord {
  readonly value: JsonObject;
  readonly version: string;
  readonly expiresAt?: Date;
}

/** When a written record expires; absent, never. */
export interface StoreWriteOptions {
  readonly expiresAt?: Date;
}

/**
 * Everything a company remembers, as JSON records by kind and key.
 *
 * - `get` reads a record, or `undefined` when absent or expired.
 * - `put` writes it unconditionally (a new version).
 * - `create` writes it only if absent (or expired): `true` when written.
 * - `replace` writes it only if its version is still `version`: `true` when written.
 * - `take` reads and deletes it at once: exactly one caller gets it.
 * - `delete` removes it, if present.
 * - `records` reads every live record of one kind, in no particular order: what a
 *   company's owner settles and ends before taking it down (`CompanyService.openWork`).
 *   Only values come back, never keys — a backend may keep keys as digests it cannot
 *   reverse — so the records read this way name what they are (an operation its ID, a
 *   sign-in its agent and account).
 *
 * Values are JSON objects; a backend stores copies, never the caller's object.
 */
export interface CompanyStore {
  get(kind: string, key: string): Promise<StoredRecord | undefined>;
  put(kind: string, key: string, value: JsonObject, options?: StoreWriteOptions): Promise<void>;
  create(kind: string, key: string, value: JsonObject, options?: StoreWriteOptions): Promise<boolean>;
  replace(
    kind: string,
    key: string,
    version: string,
    value: JsonObject,
    options?: StoreWriteOptions,
  ): Promise<boolean>;
  take(kind: string, key: string): Promise<JsonObject | undefined>;
  delete(kind: string, key: string): Promise<void>;
  records(kind: string): Promise<StoredRecord[]>;
}

interface Entry {
  readonly text: string;
  readonly version: string;
  readonly expiresAt: Date | undefined;
}

/** The memory store sweeps expired records once it holds this many, then whenever it doubles. */
const FIRST_SWEEP = 1024;

/**
 * The default store: one process, nothing persisted, versions and expiry real.
 *
 * `clock` judges expiry; `buildCompany` binds the company's own clock. Expired records
 * are swept whenever the store has doubled since the last sweep, so it holds about twice
 * the records still alive, never every one ever written (replay IDs, sign-in attempts,
 * pointers).
 */
export class MemoryCompanyStore implements CompanyStore {
  readonly #entries = new Map<string, Entry>();
  #version = 0;
  #sweepAt = FIRST_SWEEP;
  clock: Clock;

  /** How many records it holds, expired ones not yet swept included. */
  get size(): number {
    return this.#entries.size;
  }

  constructor(options: { readonly clock?: Clock } = {}) {
    this.clock = options.clock ?? { now: () => new Date() };
  }

  #slot(kind: string, key: string): string {
    return JSON.stringify([kind, key]);
  }

  #live(kind: string, key: string): Entry | undefined {
    const slot = this.#slot(kind, key);
    const entry = this.#entries.get(slot);
    if (entry === undefined) return undefined;
    const expiresAt = entry.expiresAt;
    if (expiresAt !== undefined && this.clock.now().getTime() >= expiresAt.getTime()) {
      this.#entries.delete(slot);
      return undefined;
    }
    return entry;
  }

  #write(kind: string, key: string, value: JsonObject, options: StoreWriteOptions): void {
    this.#version += 1;
    this.#entries.set(this.#slot(kind, key), {
      text: JSON.stringify(value),
      version: String(this.#version),
      expiresAt: options.expiresAt === undefined ? undefined : new Date(options.expiresAt.getTime()),
    });
    if (this.#entries.size >= this.#sweepAt) {
      const now = this.clock.now().getTime();
      for (const [slot, entry] of this.#entries) {
        if (entry.expiresAt !== undefined && now >= entry.expiresAt.getTime()) this.#entries.delete(slot);
      }
      this.#sweepAt = Math.max(FIRST_SWEEP, 2 * this.#entries.size);
    }
  }

  async get(kind: string, key: string): Promise<StoredRecord | undefined> {
    const entry = this.#live(kind, key);
    if (entry === undefined) return undefined;
    const value = JSON.parse(entry.text) as JsonObject;
    return entry.expiresAt === undefined
      ? { value, version: entry.version }
      : { value, version: entry.version, expiresAt: new Date(entry.expiresAt.getTime()) };
  }

  async put(kind: string, key: string, value: JsonObject, options: StoreWriteOptions = {}): Promise<void> {
    this.#write(kind, key, value, options);
  }

  async create(
    kind: string,
    key: string,
    value: JsonObject,
    options: StoreWriteOptions = {},
  ): Promise<boolean> {
    if (this.#live(kind, key) !== undefined) return false;
    this.#write(kind, key, value, options);
    return true;
  }

  async replace(
    kind: string,
    key: string,
    version: string,
    value: JsonObject,
    options: StoreWriteOptions = {},
  ): Promise<boolean> {
    const entry = this.#live(kind, key);
    if (entry === undefined || entry.version !== version) return false;
    this.#write(kind, key, value, options);
    return true;
  }

  async take(kind: string, key: string): Promise<JsonObject | undefined> {
    const entry = this.#live(kind, key);
    if (entry === undefined) return undefined;
    this.#entries.delete(this.#slot(kind, key));
    return JSON.parse(entry.text) as JsonObject;
  }

  async delete(kind: string, key: string): Promise<void> {
    this.#entries.delete(this.#slot(kind, key));
  }

  async records(kind: string): Promise<StoredRecord[]> {
    const found: StoredRecord[] = [];
    for (const key of this.keys(kind)) {
      const record = await this.get(kind, key);
      if (record !== undefined) found.push(record);
    }
    return found;
  }

  /** The live keys of one kind, oldest first: for tests and inspection, not the service. */
  keys(kind: string): string[] {
    const keys: string[] = [];
    for (const slot of [...this.#entries.keys()]) {
      const [entryKind, key] = JSON.parse(slot) as [string, string];
      if (entryKind === kind && this.#live(entryKind, key) !== undefined) keys.push(key);
    }
    return keys;
  }
}

// The kinds of record a company keeps (the same as the Python SDK's).
export const RecordKinds = {
  session: "session",
  sessionToken: "session_token",
  accountToken: "account_token",
  accountFamily: "account_family",
  accountAgent: "account_agent",
  client: "client",
  device: "device",
  userCode: "user_code",
  authorization: "authorization",
  code: "code",
  mediated: "mediated",
  conversation: "conversation",
  messageId: "message_id",
  operation: "operation",
  proposal: "proposal",
  browserCookie: "browser_cookie",
  /** A browser-session join code (§5), by digest: the browser it was given to. */
  joinCode: "join_code",
  /** An assertion, proof, or browser-assertion ID seen once (the default replay cache). */
  replay: "replay",
  /** Failed sign-in attempts by one key, and until when it is locked out (§4.7). */
  signInAttempts: "sign_in_attempts",
  /** A feedback report a personal agent sent (§8), kept for the company's operator. */
  feedback: "feedback",
  /** A DPoP nonce the company issued, until it stops accepting it (§4.3). */
  dpopNonce: "dpop_nonce",
  /** An API write's `Idempotency-Key` in one Session, and its original response (guides, *Retries*). */
  idempotency: "idempotency",
} as const;

export type RecordKind = (typeof RecordKinds)[keyof typeof RecordKinds];

// Records: JSON-ready objects; times are RFC 3339 strings. ---------------------------

/** One token of a Session, as issued; the token is bound to a DPoP key. */
export interface IssuedSession {
  /** The Session Key's thumbprint, which names the Session (§4.3). */
  readonly sessionKey: string;
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly keyThumbprint: string;
  readonly expiresAt: string;
  readonly accountId?: string;
  readonly scopes: readonly string[];
  /** The digest of the Account Token this Session is signed in with. */
  readonly accountToken?: string;
  readonly resource?: string;
  /** `Bearer` for a token issued to the MCP server (§4.3); a DPoP token otherwise. */
  readonly tokenType?: "Bearer";
  /** The Agent ID the Session started with, kept for its life (§4.2). */
  readonly agentId?: string;
}

/**
 * A Session by its key's thumbprint: each live token's state by digest, the latest.
 *
 * `accountId` is the account the Session was ever signed in to: kept after it signs out,
 * so it is never signed in to another (§4.4, §4.8). `endsAt` is when the Session ends;
 * its record is kept a while after, so its key is refused (`invalid_grant`) rather than
 * starting a new Session (§4.2).
 */
export interface StoredSession {
  readonly sessionKey: string;
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly tokens: Readonly<Record<string, IssuedSession>>;
  readonly latest: string;
  readonly accountId?: string;
  readonly endsAt?: string;
}

/** What an Account Token is: one account, one agent, one user, some scopes. */
export interface AccountGrant {
  /** The sign-in it comes from: every token rotated from it shares it (§4.9). */
  readonly family: string;
  readonly accountId: string;
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly scopes: readonly string[];
  readonly expiresAt: string;
  readonly revoked: boolean;
  /**
   * When that sign-in happened, carried by every token rotated from it: a sign-in from
   * before the account's sign-ins all ended (a password reset) ends. Unknown is taken for
   * before any such moment.
   */
  readonly signedInAt?: string;
}

/** One sign-in: every Account Token rotated from it, and the Sessions signed in with them. */
export interface AccountFamily {
  readonly clientId: string;
  readonly accountId: string;
  readonly tokens: readonly string[];
  readonly sessions: readonly string[];
  /** Revoked (§4.9) or disconnected: no token joins it any more. */
  readonly revoked: boolean;
}

/** The sign-ins of one agent to one account, for disconnecting it. */
export interface AccountAgent {
  readonly families: readonly string[];
}

/**
 * What a verified personal agent declared: the extensions it supports. One record per
 * `clientId` that authenticated, kept without expiry. Only an agent with valid metadata
 * and keys at its own domain adds one, but an operator of many domains can add many: a
 * company bounds that with its `pap.company.clientPolicy` (or a store that ages them out).
 */
export interface KnownClient {
  readonly extensions: readonly string[];
}

export interface PendingDevice {
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly userCode: string;
  readonly expiresAt: string;
  readonly interval: number;
  readonly lastPoll?: string;
  readonly accountId?: string;
  readonly granted: readonly string[];
  readonly denied: boolean;
  /** The Session Key of the first poll: the device code is bound to it (§4.6). */
  readonly sessionKey?: string;
}

/** The device sign-in a user code stands for (by device-code digest). */
export interface UserCode {
  readonly device: string;
}

/** A Direct Sign-In request waiting on the user's decision on the company's page. */
export interface PendingAuthorization {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly state: string;
  readonly codeChallenge: string;
  /** The Session Key the code will be bound to (§4.5, RFC 9449 §10). */
  readonly dpopJkt: string;
  readonly expiresAt: string;
  /** The agent's `client_name`, for a hosted consent page (`authorizationRequest`). */
  readonly clientName?: string;
  /**
   * The digest of the consent cookie of the browser the company's own page was shown
   * to; absent when a hosted consent page answers (it protects its own form).
   */
  readonly browserBinding?: string;
}

/** A one-use authorization code, at most a minute old. */
export interface IssuedCode {
  readonly clientId: string;
  readonly redirectUri: string;
  readonly codeChallenge: string;
  /** The Session Key the code is bound to: only a proof with it redeems the code. */
  readonly dpopJkt: string;
  /** The scopes the request asked for: the response leaves `scope` out when all granted. */
  readonly requested: readonly string[];
  readonly accountId: string;
  readonly scopes: readonly string[];
  readonly expiresAt: string;
}

export interface PendingMediated {
  readonly sessionKey: string;
  readonly accountId: string;
  readonly scopes: readonly string[];
  readonly codeReference: string;
  readonly expiresAt: string;
  /** The `signInAttempts` keys the credentials counted against, cleared on success. */
  readonly attemptKeys: readonly string[];
  readonly attempts: number;
  /**
   * `code_required` (absent) while a code is awaited; once `failed` or `expired` it stays
   * so, and a code sent to it gets the same status again (§4.7).
   */
  readonly status?: "code_required" | "failed" | "expired";
}

/** An identifier seen once: the record is its presence, until its expiry. */
export type ReplayMark = Record<string, never>;

/** A DPoP nonce the company issued: accepted in a proof until the record expires. */
export type IssuedNonce = Record<string, never>;

/**
 * An API write's `Idempotency-Key` in one Session: the request's digest, and its answer.
 *
 * `status` is absent while the first request with the key is under way; then the status
 * and JSON body it answered, returned again for a repeated key. The digest covers the
 * method, path, query and body, never the credentials.
 */
export interface IdempotencyRecord {
  readonly digest: string;
  readonly status?: number;
  readonly body?: unknown;
}

/**
 * A feedback report as the company received it (§8): data, never instructions.
 *
 * `kind` is whatever the personal agent sent (an unknown kind is accepted); `clientId`
 * and `pairwiseUserId` are the Session's, which sent it.
 */
export interface StoredFeedback {
  readonly reportId: string;
  readonly kind: string;
  readonly task: string;
  readonly description: string;
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly receivedAt: string;
}

/**
 * Failed sign-in attempts by one key (an account, a user, a Session, a code).
 * `lockedUntil` is set once `failures` reach the company's limit: until then every
 * attempt by the key is refused (`429`, `Retry-After`).
 */
export interface SignInAttempts {
  readonly failures: number;
  readonly lockedUntil?: string;
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
  readonly status: StoredConversationStatus;
  readonly responder: "agent" | "human";
  readonly parentId?: string;
  readonly directChild?: string;
  /** The account the conversation used; from then on it belongs to that account. */
  readonly accountId?: string;
  readonly events: readonly StoredEvent[];
  /** Event IDs the company no longer keeps: a cursor naming one is `cursor_expired`. */
  readonly forgotten: readonly string[];
}

/** A message ID seen from one agent and user: its conversation and content digest. */
export interface MessageReceipt {
  readonly conversationId: string;
  readonly digest: string;
}

export interface StoredOperation {
  /** The operation as it goes on the wire. */
  readonly operation: Operation;
  readonly action: string;
  readonly owner: readonly [string, string];
  readonly accountId: string;
  /** The scopes a Session must hold to confirm it, recorded when it was proposed. */
  readonly scopes: readonly string[];
  readonly performed: boolean;
}

/** The operation an identical proposal returns (Operations §4: one action, one operation). */
export interface OperationProposal {
  readonly operationId: string;
}

/** The Session a token stands for. */
export interface SessionPointer {
  readonly sessionKey: string;
}

/** A browser-session join code (§5): the digest of the cookie that ties it to a browser. */
export interface JoinCode {
  readonly browser: string;
}
