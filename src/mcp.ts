/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * A company's MCP server, with a Session Token issued for its url (§4.3, §6), as in
 * Python's `personal_agent_protocol.mcp`.
 *
 * An MCP server supports DPoP when its protected resource metadata (RFC 9728) lists
 * `dpop_signing_alg_values_supported`; `fetchMcpServerMetadata` reads it
 * (`McpServerMetadata.supportsDpop`). The personal agent then asks for a Session Token
 * with `resource` set to the server's `url` from poppy.json (`SessionClient.tokenForMcp`,
 * or `AccountTokenClient.tokenForMcp` signed in), with a DPoP proof for a DPoP server
 * and without one otherwise, and uses the scheme `token_type` names:
 *
 * - `McpDpopAuth` sends a DPoP token with a fresh proof on each request, and retries
 *   once with the server's nonce on `use_dpop_nonce`.
 * - `McpBearerAuth` sends a Bearer token. Anyone holding one can use it, so it goes
 *   only to that exact URL.
 *
 * Both are `fetch`es that refuse any other URL before a request is sent; hand one to
 * any MCP client that takes a `fetch` (for example the MCP SDK's Streamable HTTP
 * transport). `McpClient` is a minimal Streamable HTTP client (initialize, tools/list,
 * tools/call) over them, with no MCP SDK dependency. `McpToolResult.operation` is the
 * operation a consequential tool proposes in `structuredContent.operation` (Operations
 * §4.2): the same `Operation` as an API's `202` or a conversation message, confirmed at
 * the operations endpoint.
 */
import type { ReactorPlatformView } from "@datalayer/reactor";

import { PersonalAgentProtocolError, ProtocolValidationError, TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { DPOP_REQUIRED_ALGORITHM, type ApiDescriptor, type DiscoveryDocument, type Operation } from "./models.js";
import { operationFrom } from "./operations.js";
import { DpopProofProviders, firstContribution } from "./reactor.js";
import { challengeParameters, refuseRedirect } from "./refusals.js";
import type { SessionToken } from "./sessions.js";
import { parseRetryAfter, readLimited, readLimitedText } from "./limits.js";

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

/** Whose Session a request is for: the tenant and the company a DPoP proof is signed for. */
export interface McpWho {
  readonly tenantId: string;
  readonly issuer: string;
}

/**
 * An MCP server's protected resource metadata (RFC 9728, §6).
 *
 * `dpop_signing_alg_values_supported`, when listed, says the server supports DPoP, and
 * then includes ES256 (§4.3): `supportsDpop`.
 */
export interface McpServerMetadata {
  readonly resource: string;
  readonly authorization_servers: readonly string[];
  readonly scopes_supported: readonly string[];
  readonly bearer_methods_supported: readonly string[];
  readonly dpop_signing_alg_values_supported?: readonly string[];
  /** Whether the server takes DPoP Session Tokens with proofs (§4.3). */
  readonly supportsDpop: boolean;
}

function httpsOnly(value: unknown, label: string): string {
  let parsed: URL | undefined;
  try {
    parsed = typeof value === "string" ? new URL(value) : undefined;
  } catch {
    parsed = undefined;
  }
  if (parsed === undefined || parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new ProtocolValidationError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return value as string;
}

function strings(value: unknown, label: string): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new ProtocolValidationError("invalid_type", `${label} must be a list of strings`);
  }
  return value as string[];
}

/** Protected resource metadata, validated; `invalid_resource_metadata` otherwise. */
export function parseMcpServerMetadata(value: unknown): McpServerMetadata {
  if (!isObject(value)) throw new ProtocolValidationError("invalid_type", "resource metadata must be an object");
  const servers = strings(value.authorization_servers, "authorization_servers").map((item) =>
    httpsOnly(item, "authorization server"),
  );
  if (servers.length === 0) {
    throw new ProtocolValidationError("invalid_type", "authorization_servers must not be empty");
  }
  const listed = value.dpop_signing_alg_values_supported;
  let algorithms: readonly string[] | undefined;
  if (listed !== undefined && listed !== null) {
    algorithms = strings(listed, "dpop_signing_alg_values_supported");
    if (!algorithms.includes(DPOP_REQUIRED_ALGORITHM)) {
      throw new ProtocolValidationError("invalid_type", "an MCP server that supports DPoP lists ES256");
    }
  }
  return {
    resource: httpsOnly(value.resource, "resource"),
    authorization_servers: servers,
    scopes_supported: strings(value.scopes_supported, "scopes_supported"),
    bearer_methods_supported: strings(value.bearer_methods_supported, "bearer_methods_supported"),
    ...(algorithms === undefined ? {} : { dpop_signing_alg_values_supported: algorithms }),
    supportsDpop: algorithms !== undefined,
  };
}

/** Where an MCP server's RFC 9728 metadata is: the well-known path before its own. */
export function protectedResourceMetadataUrl(url: string): string {
  const parsed = new URL(url);
  const path = parsed.pathname.replace(/\/$/, "");
  return `${parsed.protocol}//${parsed.host}/.well-known/oauth-protected-resource${path}`;
}

/**
 * The MCP server's protected resource metadata, checked against poppy.json (§6).
 *
 * Its `resource` is the server's `url`, and its `authorization_servers` include the
 * company's `auth.issuer`; anything else is `McpError` (`invalid_resource_metadata`).
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
    metadata = parseMcpServerMetadata(parseJsonStrict(new TextDecoder().decode(bytes)));
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

/**
 * Send a DPoP Session Token with a fresh proof to one MCP server's URL (§4.3).
 *
 * The proof is signed by the host's `pap.dpopProofProvider` for the user and company in
 * `who`. A `use_dpop_nonce` refusal is retried once, with a new proof carrying the
 * server's `DPoP-Nonce`. Any other URL is refused before a request is made.
 */
export class McpDpopAuth {
  readonly resource: string;
  readonly #token: SessionToken;
  readonly #reactor: ReactorPlatformView;
  readonly #who: McpWho;
  readonly #fetch: typeof globalThis.fetch;

  constructor(
    token: SessionToken,
    resource: string,
    options: { readonly reactor: ReactorPlatformView; readonly who: McpWho; readonly fetch?: typeof globalThis.fetch },
  ) {
    if (token.tokenType !== "DPoP") {
      throw new TransportError("unexpected_token_type", "A DPoP MCP server takes a DPoP token issued for its url");
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
    this.#reactor = options.reactor;
    this.#who = options.who;
    this.#fetch = fetcher;
  }

  /** `fetch` with the DPoP token and a fresh proof, for the MCP server's URL only. */
  readonly fetch = async (input: string | URL | Request, init: RequestInit = {}): Promise<Response> => {
    const url = requestUrl(input);
    if (target(url) === undefined || target(url) !== target(this.resource)) {
      throw new TransportError(
        "token_not_for_this_url",
        "A Session Token for an MCP server is sent only to that server",
      );
    }
    const method = (init.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
    const provider = firstContribution(this.#reactor, DpopProofProviders, "DPoP proof provider");
    let nonce: string | undefined;
    for (let attempt = 0; ; attempt += 1) {
      const proof = await provider.create({
        method,
        url,
        tenantId: this.#who.tenantId,
        sessionKey: this.#token.sessionKey,
        issuer: this.#who.issuer,
        accessToken: this.#token.accessToken,
        ...(nonce === undefined ? {} : { nonce }),
      });
      const headers = new Headers(input instanceof Request ? input.headers : undefined);
      for (const [name, value] of new Headers(init.headers)) headers.set(name, value);
      headers.set("Authorization", `DPoP ${this.#token.accessToken.reveal()}`);
      headers.set("DPoP", proof.reveal());
      const response = await this.#fetch(url, { ...init, method, headers, credentials: "omit", redirect: "manual" });
      const challenge = challengeParameters(response.headers.get("www-authenticate"));
      if (response.status !== 401 || challenge.error !== "use_dpop_nonce") return response;
      const next = response.headers.get("dpop-nonce");
      if (attempt > 0 || !next) return response;
      await response.body?.cancel().catch(() => undefined);
      nonce = next;
    }
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
  /** For a DPoP token: the host's reactor, whose `pap.dpopProofProvider` signs the proofs. */
  readonly reactor?: ReactorPlatformView;
  /** For a DPoP token: whose Session it is. */
  readonly who?: McpWho;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Initialize, list, and call tools on one MCP server with a token issued for its url.
 *
 * A DPoP token (from a server that supports DPoP) is sent with proofs and needs the
 * host's `reactor` and `who` the Session is for; a Bearer token needs neither.
 */
export class McpClient {
  readonly url: string;
  readonly auth: McpBearerAuth | McpDpopAuth;
  readonly #maxResponseBytes: number;
  #nextId = 0;
  #sessionId: string | undefined;
  #initialized = false;

  constructor(options: McpClientOptions) {
    const limit = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.url = options.url;
    const fetch = options.fetch === undefined ? {} : { fetch: options.fetch };
    if (options.token.tokenType === "DPoP") {
      if (options.reactor === undefined || options.who === undefined) {
        throw new TransportError("dpop_unavailable", "A DPoP token for MCP needs the host's reactor and who");
      }
      this.auth = new McpDpopAuth(options.token, options.url, { reactor: options.reactor, who: options.who, ...fetch });
    } else {
      this.auth = new McpBearerAuth(options.token, options.url, fetch);
    }
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
    await refuseRedirect(response, McpError);
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
 * A `429`: `rate_limited`, its `Retry-After` kept as the other clients keep it (§4.3).
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

/** A token refusal, from the `Bearer` or `DPoP` challenges (§6) or the body. */
async function refusal(response: Response): Promise<McpError> {
  const values = challengeParameters(response.headers.get("www-authenticate"));
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
  const extension = isObject(payload) && typeof payload.extension === "string" ? payload.extension : values.extension;
  // The server refuses the personal agent entirely, never one tool (§6).
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
