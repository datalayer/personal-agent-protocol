/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What a discovery document advertises, and calls to a company's OpenAPI API, as in
// Python's personal_agent_protocol.apis: the API types this SDK speaks, the `poppy`
// conversation endpoint, the OpenAPI description, and `ApiClient`, which calls the API
// with the Session's DPoP token (§6, Operations §4.1). Unknown API and protocol types
// are skipped, never an error (§3.3, §6).
//
// A read answers its JSON body. A consequential call answers `202` with an operation:
// proposed, not performed, until it is confirmed at the operations endpoint
// (`OperationsClient`). The same operation object arrives through a conversation and
// through MCP, so one approval flow serves every channel.
import { PersonalAgentProtocolError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { parseOperation, type ApiDescriptor, type DiscoveryDocument, type Operation } from "./models.js";
import type { SessionToken } from "./sessions.js";
import type { DpopFetchClient } from "./transport.js";
import { readLimited } from "./limits.js";

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

/** The company refused an API call; `code` is its error, never its body. */
export class ApiError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; details?: Readonly<Record<string, unknown>>; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "ApiError";
  }
}

/** A successful API answer: the body, or the operation it proposes (`202`). */
export interface ApiResponse {
  readonly status: number;
  readonly body?: unknown;
  readonly operation?: Operation;
}

export interface ApiCallOptions {
  readonly token: SessionToken;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly issuer: string;
  /** A JSON body, sent as `application/json`. */
  readonly body?: unknown;
  readonly signal?: AbortSignal;
}

export interface ApiClientOptions {
  readonly transport: DpopFetchClient;
  readonly maxResponseBytes?: number;
}

const CHALLENGE = /(\w+)="([^"]*)"/g;

/** `error` and `scope` from a `DPoP`/`Bearer` WWW-Authenticate challenge. */
function challenge(header: string): { error?: string; scope?: string } {
  const values: Record<string, string> = {};
  for (const [, name, value] of header.matchAll(CHALLENGE)) values[name as string] = value as string;
  return {
    ...(values.error === undefined ? {} : { error: values.error }),
    ...(values.scope === undefined ? {} : { scope: values.scope }),
  };
}

function member(payload: unknown, name: string): unknown {
  return typeof payload === "object" && payload !== null && !Array.isArray(payload)
    ? (payload as Record<string, unknown>)[name]
    : undefined;
}

/** Read and change through a company's API, the credentials host-owned. */
export class ApiClient {
  readonly #transport: DpopFetchClient;
  readonly #maxResponseBytes: number;

  constructor(options: ApiClientOptions) {
    const limit = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#transport = options.transport;
    this.#maxResponseBytes = limit;
  }

  /** One call; `sign_in_required` and `insufficient_scope` carry the scope asked for. */
  async call(method: string, url: string, options: ApiCallOptions): Promise<ApiResponse> {
    const headers: Record<string, string> = { Accept: "application/json" };
    let body: string | undefined;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    const response = await this.#transport.request(method, url, {
      token: options.token,
      tenantId: options.tenantId,
      pairwiseUserId: options.pairwiseUserId,
      issuer: options.issuer,
      headers,
      ...(body === undefined ? {} : { body }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const payload = await this.#payload(response);
    if (response.status === 202) {
      try {
        return { status: 202, operation: parseOperation(member(payload, "operation")) };
      } catch (cause) {
        throw new ApiError("invalid_operation", "202 answer carries no valid operation", {
          statusCode: 202,
          cause,
        });
      }
    }
    if (response.ok) return { status: response.status, body: payload };
    let error = member(payload, "error");
    let scope = member(payload, "scope");
    if (typeof error !== "string") {
      // Token errors may come only in WWW-Authenticate (§6).
      ({ error, scope } = challenge(response.headers.get("www-authenticate") ?? ""));
    }
    const details: Record<string, unknown> = typeof scope === "string" ? { scope } : {};
    const retryAfter = response.headers.get("retry-after");
    if (response.status === 429 && retryAfter) {
      // Never retried here: the caller waits at least this long (§4.3).
      details.retry_after = retryAfter;
    }
    throw new ApiError(typeof error === "string" ? error : "api_request_failed", "the company refused the API call", {
      statusCode: response.status,
      ...(Object.keys(details).length ? { details } : {}),
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
