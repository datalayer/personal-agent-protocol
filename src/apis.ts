/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What a discovery document advertises, and calls to a company's OpenAPI API, as in
// Python's personal_agent_protocol.apis: the API types this SDK speaks, the `poppy`
// conversation endpoint, the OpenAPI description, and `ApiClient`, which calls the API in a
// Session (§7, Operations 4, 6). Unknown API and protocol types are skipped, never an error
// (§3.3, §7).
//
// A read answers its JSON body. An action that needs the user's approval answers
// `403 approval_required` with an operation: refused, nothing done. The same request again
// with the user's approval (`approval`, the `Poppy-Approval` header) performs it. The same
// operation object arrives through a conversation or an MCP tool, so one approval flow serves
// every interface (`OperationsClient`).
//
// Every write (POST, PUT, PATCH, DELETE) carries an `Idempotency-Key` (guides, *Retries*):
// a random UUID (version 4), or the caller's own key when it retries the same request.
// The key used comes back on the response and on the `ApiError`, so a retry can send it
// again; the company answers a repeated key with its original response.
import { PersonalAgentProtocolError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  parseOperation,
  type ApiDescriptor,
  type Approval,
  type DiscoveryDocument,
  type Operation,
} from "./models.js";
import { ACTION_FAILED, APPROVAL_HEADER, approvalHeader } from "./operations.js";
import type { AccessToken, PapSession } from "./sessions.js";
import type { SessionFetchClient } from "./transport.js";
import { readLimited } from "./limits.js";
import { refusalCode, refusalDetails } from "./refusals.js";

/** The API types this SDK speaks. */
export const KNOWN_API_TYPES: ReadonlySet<string> = new Set(["openapi", "mcp"]);

/** The advertised APIs of a type this SDK speaks, in the company's order. */
export function knownApis(document: DiscoveryDocument): readonly ApiDescriptor[] {
  return (document.apis ?? []).filter((api) => KNOWN_API_TYPES.has(api.type));
}

/** The `poppy` conversation endpoint, skipping protocol types this SDK does not speak. */
export function conversationEndpoint(document: DiscoveryDocument): string | undefined {
  return document.agent?.protocols.find((protocol) => protocol.type === "poppy")?.endpoint;
}

/** The company's OpenAPI description, when it advertises one. */
export function openapiUrl(document: DiscoveryDocument): string | undefined {
  return (document.apis ?? []).find((api) => api.type === "openapi")?.url;
}

/** The methods that change something: each carries an `Idempotency-Key` (guides, *Retries*). */
export const WRITE_METHODS: ReadonlySet<string> = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/** What a company accepts as an `Idempotency-Key`: 1 to 255 visible ASCII characters. */
export const IDEMPOTENCY_KEY = /^[\x21-\x7e]{1,255}$/u;

/** A fresh key for a write: a random UUID (version 4). */
export function newIdempotencyKey(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * The company refused an API call; `code` is its error, never its body.
 *
 * `idempotencyKey` is the key a write was sent with, to send again on a retry.
 */
export class ApiError extends PersonalAgentProtocolError {
  idempotencyKey: string | undefined;
  /**
   * What the company said of an action that failed (`action_failed`): its `summary` of every
   * change made and its `data`, content from the company (§10.1) for the host to show.
   * `toString()` never carries it.
   */
  readonly body: Readonly<Record<string, unknown>> | undefined;

  constructor(
    code: string,
    message: string,
    options: {
      statusCode?: number;
      details?: Readonly<Record<string, unknown>>;
      cause?: unknown;
      idempotencyKey?: string;
      body?: Readonly<Record<string, unknown>>;
    } = {},
  ) {
    super(code, message, options);
    this.body = options.body;
    this.name = "ApiError";
    this.idempotencyKey = options.idempotencyKey;
  }
}

/** An API answer: the body, or the operation to approve (`403 approval_required`). */
export interface ApiResponse {
  readonly status: number;
  readonly body?: unknown;
  readonly operation?: Operation;
  /** The `Idempotency-Key` a write was sent with; absent for a read. */
  readonly idempotencyKey?: string;
}

export interface ApiCallOptions {
  readonly session: PapSession;
  /** Signed in with it, signed out without. */
  readonly token?: AccessToken | undefined;
  /** A JSON body, sent as `application/json`. */
  readonly body?: unknown;
  /**
   * A write's `Idempotency-Key`: the key of an earlier attempt, to retry the same request.
   * Absent, a write gets a new random one; a read takes none.
   */
  readonly idempotencyKey?: string;
  /**
   * The user's approval: the same request as the one that returned the operation. Its
   * `Idempotency-Key` doesn't carry over (Operations 6).
   */
  readonly approval?: Approval;
  readonly signal?: AbortSignal;
}

export interface ApiClientOptions {
  readonly transport: SessionFetchClient;
  readonly maxResponseBytes?: number;
}

function member(payload: unknown, name: string): unknown {
  return typeof payload === "object" && payload !== null && !Array.isArray(payload)
    ? (payload as Record<string, unknown>)[name]
    : undefined;
}

/** Read and change through a company's API, the credentials host-owned. */
export class ApiClient {
  readonly #transport: SessionFetchClient;
  readonly #maxResponseBytes: number;

  constructor(options: ApiClientOptions) {
    const limit = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#transport = options.transport;
    this.#maxResponseBytes = limit;
  }

  /**
   * One call; `insufficient_scope` carries the scopes the request needs (§6).
   *
   * A write sends `options.idempotencyKey`, or a new random one; pass the key of an
   * earlier attempt to retry the same request. A read takes none.
   */
  async call(name: string, url: string, options: ApiCallOptions): Promise<ApiResponse> {
    const method = name.toUpperCase();
    const headers: Record<string, string> = { Accept: "application/json" };
    let key: string | undefined;
    if (WRITE_METHODS.has(method)) {
      key = options.idempotencyKey ?? newIdempotencyKey();
      if (!IDEMPOTENCY_KEY.test(key)) {
        throw new RangeError("an Idempotency-Key is 1 to 255 visible ASCII characters");
      }
      headers["Idempotency-Key"] = key;
    } else if (options.idempotencyKey !== undefined) {
      throw new RangeError("only a write (POST, PUT, PATCH, DELETE) takes an Idempotency-Key");
    }
    if (options.approval !== undefined) headers[APPROVAL_HEADER] = approvalHeader(options.approval);
    let body: string | undefined;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    const response = await this.#transport.request(method, url, {
      session: options.session,
      token: options.token,
      headers,
      ...(body === undefined ? {} : { body }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    try {
      return await this.#answer(response, key);
    } catch (error) {
      if (error instanceof ApiError) error.idempotencyKey = key;
      throw error;
    }
  }

  async #answer(response: Response, key: string | undefined): Promise<ApiResponse> {
    const sent = key === undefined ? {} : { idempotencyKey: key };
    const payload = await this.#payload(response);
    if (response.status === 403 && member(payload, "error") === "approval_required") {
      try {
        return { status: 403, operation: parseOperation(member(payload, "operation")), ...sent };
      } catch (cause) {
        throw new ApiError("invalid_operation", "approval_required carries no valid operation", {
          statusCode: 403,
          cause,
        });
      }
    }
    if (response.ok) return { status: response.status, body: payload, ...sent };
    // `scope`, `extension`, and on a 429 `retry_after`: never retried here (§4.3).
    const details = refusalDetails(response, payload);
    // In the JSON body, or a token error in WWW-Authenticate (§3.3, §7).
    const code = refusalCode(response, payload, "api_request_failed");
    throw new ApiError(code, "the company refused the API call", {
      statusCode: response.status,
      ...(Object.keys(details).length ? { details } : {}),
      ...(code === ACTION_FAILED && typeof payload === "object" && payload !== null ? { body: payload as Readonly<Record<string, unknown>> } : {}),
    });
  }

  async #payload(response: Response): Promise<unknown> {
    const bytes = await readLimited(response, this.#maxResponseBytes);
    if (bytes.byteLength > this.#maxResponseBytes) {
      throw new ApiError("response_too_large", "API response exceeded limit");
    }
    if (!bytes.byteLength) return undefined;
    try {
      return parseJsonStrict(new TextDecoder().decode(bytes));
    } catch (cause) {
      throw new ApiError("invalid_json", "API response was not JSON", { cause });
    }
  }
}
