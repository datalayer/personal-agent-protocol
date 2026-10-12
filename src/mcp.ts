/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * A company's MCP server with a resource-bound Bearer Session Token (§4.3, §6), as in
 * Python's `personal_agent_protocol.mcp`.
 *
 * MCP authorization uses Bearer tokens, so for MCP the personal agent asks for a
 * Session Token without a DPoP proof and with `resource` set to the MCP server's
 * `url` from poppy.json (`SessionClient.bearerForMcp`, or
 * `AccountTokenClient.bearerForMcp` signed in). Anyone holding a Bearer token can use
 * it, so this module sends it only to that exact URL:
 *
 * - `McpBearerAuth` is a `fetch` that adds the token to requests for the MCP server's
 *   URL and refuses every other request, before it is sent. Hand its `fetch` to any MCP
 *   client that takes one (for example the MCP SDK's Streamable HTTP transport).
 * - `McpClient` is a minimal Streamable HTTP client (initialize, tools/list,
 *   tools/call) over that auth, with no MCP SDK dependency.
 * - `McpToolResult.operation` is the operation a consequential tool proposes in
 *   `structuredContent.operation` (Operations §4.2): the same `Operation` as an API's
 *   `202` or a conversation message, confirmed at the operations endpoint.
 */
import { PersonalAgentProtocolError, TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import type { ApiDescriptor, DiscoveryDocument, Operation } from "./models.js";
import { operationFrom } from "./operations.js";
import type { SessionToken } from "./sessions.js";
import { readLimited, readLimitedText } from "./limits.js";

export const MCP_PROTOCOL_VERSION = "2025-06-18";

/** The MCP server refused a request; `code` is its token or JSON-RPC error. */
export class McpError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; details?: Readonly<Record<string, unknown>>; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "McpError";
  }
}

/** The company's MCP server, when it lists one. */
export function mcpApi(document: DiscoveryDocument): ApiDescriptor | undefined {
  return (document.apis ?? []).find((api) => api.type === "mcp");
}

function target(url: string | URL): string | undefined {
  let parsed: URL;
  try {
    parsed = new URL(String(url));
  } catch {
    return undefined;
  }
  const port = parsed.port || (parsed.protocol === "https:" ? "443" : parsed.protocol === "http:" ? "80" : "");
  return JSON.stringify([parsed.protocol, parsed.hostname.toLowerCase(), port, parsed.pathname || "/"]);
}

function requestUrl(input: string | URL | Request): string {
  return input instanceof Request ? input.url : String(input);
}

/** Send a Bearer Session Token to one MCP server's URL, and nowhere else. */
export class McpBearerAuth {
  readonly resource: string;
  readonly #token: SessionToken;
  readonly #fetch: typeof globalThis.fetch;

  constructor(token: SessionToken, resource: string, options: { readonly fetch?: typeof globalThis.fetch } = {}) {
    if (token.tokenType !== "Bearer") {
      throw new TransportError("unexpected_token_type", "MCP uses a Bearer token issued for its url");
    }
    let protocol: string | undefined;
    try {
      protocol = new URL(resource).protocol;
    } catch {
      protocol = undefined;
    }
    if (protocol !== "https:") throw new TransportError("invalid_url", "an MCP server's url must use HTTPS");
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) throw new TransportError("fetch_unavailable", "A fetch implementation is required");
    this.#token = token;
    this.resource = resource;
    this.#fetch = fetcher;
  }

  /**
   * `fetch` with the Bearer token, for the MCP server's URL only.
   *
   * Any other URL (another path, host, port or scheme) is refused before a request is
   * made: a copied Bearer token works for anyone, so it never leaves its MCP server.
   * Redirects are never followed with it.
   */
  readonly fetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = requestUrl(input);
    if (target(url) === undefined || target(url) !== target(this.resource)) {
      throw new TransportError(
        "bearer_not_for_this_url",
        "A Bearer Session Token is sent only to the MCP server it was issued for",
      );
    }
    const headers = new Headers(input instanceof Request ? input.headers : undefined);
    for (const [name, value] of new Headers(init.headers)) headers.set(name, value);
    headers.set("Authorization", `Bearer ${this.#token.accessToken.reveal()}`);
    return this.#fetch(url, {
      ...init,
      method: init.method ?? (input instanceof Request ? input.method : "GET"),
      headers,
      credentials: "omit",
      redirect: "manual",
    });
  };
}

/** A tool's answer; `operation` is set when it proposed one (Operations §4.2). */
export interface McpToolResult {
  readonly content: readonly Readonly<Record<string, unknown>>[];
  readonly structuredContent?: Readonly<Record<string, unknown>>;
  readonly isError: boolean;
  readonly operation?: Operation;
  /** The text items of `content`, one per line. */
  readonly text: string;
}

export interface McpClientOptions {
  readonly token: SessionToken;
  /** The MCP server's `url` from poppy.json (`mcpApi(document).url`). */
  readonly url: string;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Initialize, list, and call tools on one MCP server with a resource-bound Bearer token. */
export class McpClient {
  readonly url: string;
  readonly auth: McpBearerAuth;
  readonly #maxResponseBytes: number;
  #nextId = 0;
  #sessionId: string | undefined;
  #initialized = false;

  constructor(options: McpClientOptions) {
    const limit = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.url = options.url;
    this.auth = new McpBearerAuth(options.token, options.url, {
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
    });
    this.#maxResponseBytes = limit;
  }

  async initialize(options: { readonly signal?: AbortSignal } = {}): Promise<Record<string, unknown>> {
    const result = await this.#call(
      "initialize",
      {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo: { name: "personal-agent-protocol", version: "1" },
      },
      options.signal,
    );
    this.#initialized = true;
    await this.#post({ jsonrpc: "2.0", method: "notifications/initialized" }, options.signal);
    return result;
  }

  async listTools(options: { readonly signal?: AbortSignal } = {}): Promise<readonly Record<string, unknown>[]> {
    await this.#ensureInitialized(options.signal);
    const tools = (await this.#call("tools/list", {}, options.signal)).tools;
    if (!Array.isArray(tools)) throw new McpError("invalid_response", "tools/list did not return tools");
    return tools as Record<string, unknown>[];
  }

  async callTool(
    name: string,
    args: Readonly<Record<string, unknown>> = {},
    options: { readonly signal?: AbortSignal } = {},
  ): Promise<McpToolResult> {
    await this.#ensureInitialized(options.signal);
    const result = await this.#call("tools/call", { name, arguments: args }, options.signal);
    const structured = result.structuredContent;
    let operation: Operation | undefined;
    if (isObject(structured) && "operation" in structured) {
      try {
        operation = operationFrom(result);
      } catch (cause) {
        throw new McpError("invalid_operation", "the tool proposed a malformed operation", { cause });
      }
    }
    const content = Array.isArray(result.content) ? (result.content as Record<string, unknown>[]) : [];
    return {
      content,
      ...(isObject(structured) ? { structuredContent: structured } : {}),
      isError: result.isError === true,
      ...(operation === undefined ? {} : { operation }),
      text: content
        .filter((item) => isObject(item) && item.type === "text")
        .map((item) => String(item.text ?? ""))
        .join("\n"),
    };
  }

  async #ensureInitialized(signal: AbortSignal | undefined): Promise<void> {
    if (!this.#initialized) await this.initialize(signal === undefined ? {} : { signal });
  }

  async #call(
    method: string,
    params: Readonly<Record<string, unknown>>,
    signal: AbortSignal | undefined,
  ): Promise<Record<string, unknown>> {
    this.#nextId += 1;
    const message = await this.#post({ jsonrpc: "2.0", id: this.#nextId, method, params }, signal);
    if (!isObject(message)) throw new McpError("invalid_response", "MCP answered no JSON-RPC message");
    const error = message.error;
    if (isObject(error)) throw new McpError("jsonrpc_error", `MCP error ${String(error.code)}`);
    const result = message.result;
    if (!isObject(result)) throw new McpError("invalid_response", "MCP answered no result");
    return result;
  }

  async #post(message: Readonly<Record<string, unknown>>, signal: AbortSignal | undefined): Promise<unknown> {
    const headers: Record<string, string> = {
      Accept: "application/json, text/event-stream",
      "Content-Type": "application/json",
    };
    if (this.#initialized) headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION;
    if (this.#sessionId !== undefined) headers["Mcp-Session-Id"] = this.#sessionId;
    let response: Response;
    try {
      response = await this.auth.fetch(this.url, {
        method: "POST",
        headers,
        body: JSON.stringify(message),
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      if (cause instanceof TransportError) throw cause;
      throw new TransportError("request_failed", "MCP request failed", { cause });
    }
    const sessionId = response.headers.get("mcp-session-id");
    if (sessionId) this.#sessionId = sessionId;
    if (response.status === 401 || response.status === 403) throw await refusal(response);
    if (response.status === 202 || !("id" in message)) {
      await response.body?.cancel().catch(() => undefined);
      return undefined;
    }
    if (response.status !== 200) {
      await response.body?.cancel().catch(() => undefined);
      throw new McpError("http_error", "MCP request failed", { statusCode: response.status });
    }
    const bytes = await readLimited(response, this.#maxResponseBytes);
    if (bytes.byteLength > this.#maxResponseBytes) {
      throw new McpError("response_too_large", "MCP response exceeded limit");
    }
    const body = new TextDecoder().decode(bytes);
    const kind = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    try {
      if (kind === "text/event-stream") {
        for (const data of sseData(body)) {
          const parsed = parseJsonStrict(data);
          if (isObject(parsed) && parsed.id === message.id) return parsed;
        }
        throw new McpError("invalid_response", "the MCP stream ended without an answer");
      }
      return parseJsonStrict(body);
    } catch (cause) {
      if (cause instanceof McpError) throw cause;
      throw new McpError("invalid_json", "MCP answered invalid JSON", { cause });
    }
  }
}

/** A token refusal, from the Bearer challenge (RFC 6750) or the body. */
async function refusal(response: Response): Promise<McpError> {
  const values: Record<string, string> = {};
  const challenge = (response.headers.get("www-authenticate") ?? "").replace(/^Bearer/u, "");
  for (const part of challenge.split(",")) {
    const at = part.indexOf("=");
    const name = (at < 0 ? part : part.slice(0, at)).trim();
    if (name) values[name] = (at < 0 ? "" : part.slice(at + 1)).trim().replace(/^"|"$/gu, "");
  }
  let payload: unknown;
  try {
    payload = parseJsonStrict(await readLimitedText(response, 64 * 1024));
  } catch {
    payload = undefined;
  }
  let code = values.error;
  if (code === undefined) {
    const error = isObject(payload) ? payload.error : undefined;
    code = typeof error === "string" ? error : "unauthorized";
  }
  const details: Record<string, unknown> = {};
  if (values.scope !== undefined) details.scope = values.scope;
  if (isObject(payload) && typeof payload.extension === "string") details.extension = payload.extension;
  return new McpError(code, "the MCP server refused the token", {
    statusCode: response.status,
    ...(Object.keys(details).length ? { details } : {}),
  });
}

function* sseData(text: string): Generator<string> {
  let data: string[] = [];
  for (const line of [...text.split(/\r\n|\r|\n/u), ""]) {
    if (!line) {
      if (data.length) yield data.join("\n");
      data = [];
    } else if (line.startsWith("data:")) {
      data.push(line.slice(5).replace(/^ /u, ""));
    }
  }
}
