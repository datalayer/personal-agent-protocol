/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * A company's MCP server, with an access token issued for its url (§4.5, §7), as in Python's
 * `personal_agent_protocol.mcp`.
 *
 * The server's protected resource metadata (RFC 9728) has its `url` from poppy.json as
 * `resource` and the Company's issuer among its `authorization_servers`;
 * `fetchMcpServerMetadata` reads and checks it. Signed in, the personal agent asks for an
 * access token with `resource` set to that `url` (`RefreshTokenClient.tokenForMcp`, a refresh
 * with `resource`) and uses it there only. Every request carries the Session header; signed
 * out, the Session header alone, which a server that accepts it may allow.
 *
 * `McpSessionAuth` is a `fetch` that refuses any other URL before a request is sent; hand one
 * to any MCP client that takes a `fetch`. `McpClient` is a minimal Streamable HTTP client
 * (initialize, tools/list, tools/call) over it, with no MCP SDK dependency.
 * `McpToolResult.operation` is the operation a tool returns for the user's approval, in
 * `structuredContent.operation` of an error result, and `callTool(..., { approval })` calls it
 * again with the approval (Operations 4, 6).
 */
import type { ReactorPlatformView } from "@datalayer/reactor";

import { PersonalAgentProtocolError, ProtocolValidationError, TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  parseProtectedResourceMetadata,
  protectedResourceMetadataUrl,
  type ApiDescriptor,
  type Approval,
  type DiscoveryDocument,
  type Operation,
  type ProtectedResourceMetadata,
} from "./models.js";
import { APPROVAL_META_KEY, operationFrom } from "./operations.js";
import { challengeParameters, dpopNonceAsked, refuseRedirect } from "./refusals.js";
import { DPOP_NONCE_HEADER, type AccessToken, type PapSession } from "./sessions.js";
import { parseRetryAfter, readLimited, readLimitedText } from "./limits.js";
import { invalidSession, sessionHeaders } from "./transport.js";

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

/** An MCP server's protected resource metadata (RFC 9728, §7). */
export type McpServerMetadata = ProtectedResourceMetadata;

/**
 * The MCP server's protected resource metadata, checked against poppy.json (§7).
 *
 * Its `resource` is the server's `url`, and its `authorization_servers` include the
 * company's issuer; anything else is `McpError` (`invalid_resource_metadata`).
 * No redirect is followed.
 */
export async function fetchMcpServerMetadata(
  url: string,
  options: {
    readonly issuer: string;
    readonly fetch?: typeof globalThis.fetch;
    readonly maxResponseBytes?: number;
    readonly signal?: AbortSignal;
  },
): Promise<McpServerMetadata> {
  const fetcher = options.fetch ?? globalThis.fetch;
  if (!fetcher) throw new TransportError("fetch_unavailable", "A fetch implementation is required");
  const limit = options.maxResponseBytes ?? 64 * 1024;
  let response: Response;
  try {
    response = await fetcher(protectedResourceMetadataUrl(url), {
      headers: { Accept: "application/json" },
      credentials: "omit",
      redirect: "manual",
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } catch (cause) {
    throw new McpError("request_failed", "MCP resource metadata request failed", { cause });
  }
  await refuseRedirect(response, McpError);
  const bytes = await readLimited(response, limit);
  if (response.status !== 200 || bytes.byteLength > limit) {
    throw new McpError("invalid_resource_metadata", "MCP resource metadata is unavailable", {
      statusCode: response.status,
    });
  }
  let metadata: McpServerMetadata;
  try {
    metadata = parseProtectedResourceMetadata(parseJsonStrict(new TextDecoder().decode(bytes)));
  } catch (cause) {
    throw new McpError("invalid_resource_metadata", "MCP resource metadata is malformed", { cause });
  }
  if (metadata.resource !== url || !metadata.authorization_servers.includes(options.issuer)) {
    throw new McpError(
      "invalid_resource_metadata",
      "MCP resource metadata names another resource or authorization server",
    );
  }
  return metadata;
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

/**
 * The Session header, and signed in a token, to one MCP server's URL only (§7).
 *
 * The token was issued for that server's `url` and works nowhere else; the Session JWT is
 * signed for each request by the host's `pap.sessionSigner`, and with a `DPoP` token a proof by
 * `pap.dpopProver`. A `use_dpop_nonce` challenge is retried once, and the server's latest
 * nonce kept for its later requests (§4.5). Any other URL (another path,
 * host, port or scheme) is refused before a request is made, and redirects are never followed.
 */
export class McpSessionAuth {
  readonly url: string;
  readonly session: PapSession;
  /** The latest `DPoP-Nonce` the server gave a request with a `DPoP` token (§4.5). */
  dpopNonce: string | undefined;
  readonly #token: AccessToken | undefined;
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;

  constructor(
    url: string,
    options: {
      readonly session: PapSession;
      readonly token?: AccessToken | undefined;
      readonly reactor: ReactorPlatformView;
      readonly fetch?: typeof globalThis.fetch;
    },
  ) {
    let protocol: string | undefined;
    try {
      protocol = new URL(url).protocol;
    } catch {
      protocol = undefined;
    }
    if (protocol !== "https:") throw new TransportError("invalid_url", "an MCP server's url must use HTTPS");
    if (options.token !== undefined && options.token.resource !== url) {
      throw new TransportError("token_not_for_this_url", "An MCP server takes a token issued for its url");
    }
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) throw new TransportError("fetch_unavailable", "A fetch implementation is required");
    this.url = url;
    this.session = options.session;
    this.#token = options.token;
    this.#reactor = options.reactor;
    this.#fetch = fetcher;
  }

  /** `fetch` with the Session header and any token, for the MCP server's URL only. */
  readonly fetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = requestUrl(input);
    if (target(url) === undefined || target(url) !== target(this.url)) {
      // A token for an MCP server never leaves it (§7).
      throw new TransportError(
        "token_not_for_this_url",
        "A token for an MCP server is sent only to that server",
      );
    }
    const method = (init.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const send = async (): Promise<Response> => {
      const signed = await sessionHeaders(this.#reactor, method, url, {
        session: this.session,
        token: this.#token,
        dpopNonce: this.dpopNonce,
      });
      const headers = new Headers(input instanceof Request ? input.headers : undefined);
      for (const [name, value] of new Headers(init.headers)) headers.set(name, value);
      for (const [name, value] of Object.entries(signed)) headers.set(name, value);
      return this.#fetch(url, { ...init, method, headers, credentials: "omit", redirect: "manual" });
    };
    const response = await send();
    if (this.#token?.tokenType !== "DPoP") return response;
    this.#keepNonce(response);
    if (dpopNonceAsked(response) === undefined) return response;
    await response.body?.cancel().catch(() => undefined);
    const retried = await send();
    this.#keepNonce(retried);
    return retried;
  };

  #keepNonce(response: Response): void {
    this.dpopNonce = response.headers.get(DPOP_NONCE_HEADER) ?? this.dpopNonce;
  }
}

/** A tool's answer; `operation` is set when it needs the user's approval (Operations 4). */
export interface McpToolResult {
  readonly content: readonly Readonly<Record<string, unknown>>[];
  readonly structuredContent?: Readonly<Record<string, unknown>>;
  readonly isError: boolean;
  readonly operation?: Operation;
  /** The text items of `content`, one per line. */
  readonly text: string;
}

export interface McpClientOptions {
  /** The MCP server's `url` from poppy.json (`mcpApi(document).url`). */
  readonly url: string;
  readonly session: PapSession;
  /** The host's reactor, whose `pap.sessionSigner` signs each request. */
  readonly reactor: ReactorPlatformView;
  /** An access token issued for `url`; signed out without. */
  readonly token?: AccessToken | undefined;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Initialize, list, and call tools on one MCP server, in a Session (§7).
 *
 * Signed in with `token`, an access token issued for `url`; signed out without.
 */
export class McpClient {
  readonly url: string;
  readonly session: PapSession;
  readonly auth: McpSessionAuth;
  readonly #maxResponseBytes: number;
  #nextId = 0;
  #sessionId: string | undefined;
  #initialized = false;

  constructor(options: McpClientOptions) {
    const limit = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.url = options.url;
    this.session = options.session;
    this.auth = new McpSessionAuth(options.url, {
      session: options.session,
      token: options.token,
      reactor: options.reactor,
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
    options: { readonly signal?: AbortSignal; readonly approval?: Approval } = {},
  ): Promise<McpToolResult> {
    await this.#ensureInitialized(options.signal);
    const { approval } = options;
    const result = await this.#call(
      "tools/call",
      {
        name,
        arguments: args,
        ...(approval === undefined
          ? {}
          : {
              _meta: {
                [APPROVAL_META_KEY]: {
                  operation_id: approval.operation_id,
                  revision: approval.revision,
                },
              },
            }),
      },
      options.signal,
    );
    const structured = result.structuredContent;
    let operation: Operation | undefined;
    if (isObject(structured) && "operation" in structured) {
      try {
        operation = operationFrom(result);
      } catch (cause) {
        throw new McpError("invalid_operation", "the tool returned a malformed operation", { cause });
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
    for (let restarted = false; ; restarted = true) {
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
      await refuseRedirect(response, McpError);
      if (!(await invalidSession(response))) break;
      await response.body?.cancel().catch(() => undefined);
      if (restarted) {
        throw new McpError("invalid_session", "MCP refused the Session", { statusCode: response.status });
      }
      // The Session failed a check or has ended: a new one, once (§5.5, §7).
      this.session.restart();
    }
    const sessionId = response.headers.get("mcp-session-id");
    if (sessionId) this.#sessionId = sessionId;
    if (response.status === 401 || response.status === 403) throw await refusal(response);
    if (response.status === 202 || !("id" in message)) {
      await response.body?.cancel().catch(() => undefined);
      return undefined;
    }
    if (response.status === 429) {
      await response.body?.cancel().catch(() => undefined);
      throw rateLimited(response);
    }
    if (response.status === 503) {
      // Being performed, or not known yet: send it again (Operations 7).
      await response.body?.cancel().catch(() => undefined);
      const retryAfter = response.headers.get("retry-after");
      throw new McpError("temporarily_unavailable", "the MCP server can't answer yet", {
        statusCode: 503,
        ...(retryAfter ? { details: { retry_after: retryAfter } } : {}),
      });
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

/**
 * A `429`: `rate_limited`, its `Retry-After` kept as the other clients keep it (§5.6).
 *
 * Never retried here: the caller waits at least this long. The message says when,
 * in seconds, for the model reading the error.
 */
function rateLimited(response: Response): McpError {
  const retryAfter = response.headers.get("retry-after");
  const seconds = parseRetryAfter(retryAfter, new Date());
  return new McpError(
    "rate_limited",
    `the MCP server is rate limited${seconds === undefined ? "" : `, retry after ${Math.ceil(seconds)} s`}`,
    {
      statusCode: response.status,
      ...(retryAfter ? { details: { retry_after: retryAfter } } : {}),
    },
  );
}

/**
 * A token refusal, from the `WWW-Authenticate` challenge (§7) or the body.
 *
 * A challenge with no error code (signed out) is `insufficient_scope` (§7); its
 * `resource_metadata` is kept, so a stale view of the server is read again.
 */
async function refusal(response: Response): Promise<McpError> {
  const values = challengeParameters(response.headers.get("www-authenticate"));
  let payload: unknown;
  try {
    payload = parseJsonStrict(await readLimitedText(response, 64 * 1024));
  } catch {
    payload = undefined;
  }
  let code = values.error;
  if (code === undefined && response.status === 401 && values.scope !== undefined) {
    code = "insufficient_scope";
  }
  if (code === undefined) {
    const error = isObject(payload) ? payload.error : undefined;
    code = typeof error === "string" ? error : "unauthorized";
  }
  const details: Record<string, unknown> = {};
  if (values.scope !== undefined) details.scope = values.scope;
  if (values.resource_metadata !== undefined) details.resource_metadata = values.resource_metadata;
  const extension = isObject(payload) && typeof payload.extension === "string" ? payload.extension : values.extension;
  // The server refuses the personal agent entirely, never one tool (§7).
  if (extension) details.extension = extension;
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
