/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Serve a `CompanyService` with `node:http` or `node:https` (no web framework needed).
 *
 * ```ts
 * import { createServer } from "node:https";
 * createServer({ key, cert }, companyRequestListener(service)).listen(443);
 * ```
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import type { CompanyService } from "./service.js";

export type RequestListener = (request: IncomingMessage, response: ServerResponse) => void;

export interface CompanyRequestListenerOptions {
  /** The largest request body accepted; larger is `413`. Defaults to 1 MiB. */
  readonly maxBodyBytes?: number;
  /** Told about a request the service could not answer (`500`); never about secrets. */
  readonly onError?: (error: unknown) => void;
}

class TooLarge extends Error {}
class RepeatedHeader extends Error {}

/**
 * Headers a request carries at most once: a second is refused (`400`). One credential
 * per request: a repeated one is never merged or picked from (RFC 6750 §2). A repeated
 * `DPoP` header is joined, so its proof fails as `invalid_dpop_proof` (§4.3).
 */
const SINGLE_HEADERS = ["authorization"] as const;

async function readBody(request: IncomingMessage, limit: number): Promise<Uint8Array> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as string);
    size += buffer.byteLength;
    if (size > limit) throw new TooLarge();
    chunks.push(buffer);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

function lowerCaseHeaders(request: IncomingMessage): Record<string, string> {
  // One credential per request: a repeated one is never merged or picked from (RFC 6750
  // §2). `headers` keeps one `authorization` and joins `dpop`, whose joined proofs are no
  // compact JWT (§4.3); `headersDistinct` keeps every value.
  for (const name of SINGLE_HEADERS) {
    if ((request.headersDistinct[name]?.length ?? 0) > 1) throw new RepeatedHeader();
  }
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined) continue;
    headers[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
  }
  return headers;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
  });
  response.end(payload);
}

/**
 * A request listener answering at the company's own HTTPS origin.
 *
 * The request URL is rebuilt on `service.config.base`, the origin the company
 * publishes, so DPoP `htu` checks compare against what the personal agent
 * signed whatever proxy or TLS terminator is in front.
 */
export function companyRequestListener(
  service: CompanyService,
  options: CompanyRequestListenerOptions = {},
): RequestListener {
  const limit = options.maxBodyBytes ?? 1024 * 1024;
  return (request, response) => {
    void (async () => {
      try {
        const body = await readBody(request, limit);
        const answer = await service.handle({
          method: request.method ?? "GET",
          url: `${service.config.base}${request.url ?? "/"}`,
          headers: lowerCaseHeaders(request),
          body,
        });
        if (answer.stream !== undefined) {
          response.writeHead(answer.status, { ...answer.headers });
          for await (const chunk of answer.stream) response.write(chunk);
          response.end();
          return;
        }
        let payload: string;
        let headers: Record<string, string>;
        if (typeof answer.body === "string") {
          // A page (the consent page): its own Content-Type is in its headers.
          payload = answer.body;
          headers = { ...answer.headers };
        } else {
          payload = answer.body === undefined ? "" : JSON.stringify(answer.body);
          headers = { "Content-Type": "application/json", ...answer.headers };
        }
        response.writeHead(answer.status, {
          ...headers,
          "Content-Length": String(Buffer.byteLength(payload)),
        });
        response.end(payload);
      } catch (error) {
        if (error instanceof TooLarge) {
          sendJson(response, 413, { error: "request_too_large" });
          return;
        }
        if (error instanceof RepeatedHeader) {
          sendJson(response, 400, { error: "invalid_request" });
          return;
        }
        options.onError?.(error);
        if (response.headersSent) response.destroy();
        else sendJson(response, 500, { error: "server_error" });
      }
    })();
  };
}

/** A site serving fixed JSON documents by path: a personal agent's identity documents. */
export function jsonSite(documents: Readonly<Record<string, unknown>>): RequestListener {
  return (request, response) => {
    const path = new URL(request.url ?? "/", "https://site.invalid").pathname;
    const document = documents[path];
    if (document === undefined) sendJson(response, 404, { error: "not_found" });
    else sendJson(response, 200, document);
  };
}

/** One server answering for several domains, each by its `Host`; anything else is `421`. */
export function byHost(sites: Readonly<Record<string, RequestListener>>): RequestListener {
  return (request, response) => {
    const host = (request.headers.host ?? "").split(":", 1)[0]?.toLowerCase() ?? "";
    const site = sites[host];
    if (site === undefined) {
      response.writeHead(421).end();
      return;
    }
    site(request, response);
  };
}
