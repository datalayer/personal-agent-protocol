/**
 * A `fetch` for untrusted PAP URLs on Node: it resolves the host, refuses any address that
 * is not global unicast, and dials only the address it vetted (SSRF, DNS rebinding).
 *
 * Node-only: exported from `@datalayer/personal-agent-protocol/server`, and the default of
 * the Node company (`buildCompany`). The portable entry never imports it.
 */

import type { LookupAddress } from "node:dns";
import { lookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP, type LookupFunction } from "node:net";
import { Readable } from "node:stream";

import { isGlobalAddress, literalAddress } from "./addresses.js";
import { DiscoveryError } from "./errors.js";

/** Every address a host name resolves to (A and AAAA). */
export type NodeAddressResolver = (hostname: string) => Promise<readonly string[]>;

export async function resolveAddresses(hostname: string): Promise<readonly string[]> {
  try {
    const records = await lookup(hostname, { all: true, verbatim: true });
    return [...new Set(records.map((record) => record.address))];
  } catch (cause) {
    throw new DiscoveryError("dns_failed", "Could not resolve metadata host", { cause });
  }
}

export interface ResolvingFetchOptions {
  /** How host names are resolved; `dns.lookup` with every address by default. */
  readonly resolver?: NodeAddressResolver;
  /** Allow private addresses: only for a deployment whose agents are all on its network. */
  readonly allowPrivateNetworks?: boolean;
  /** Extra TLS trust (a test CA); the system's roots otherwise. */
  readonly ca?: string | Buffer | readonly (string | Buffer)[];
  /** At most this many redirects when a caller asks fetch to follow them. */
  readonly maxRedirects?: number;
}

/** Resolve and vet `url`'s host: the one address to dial, or a refusal. */
export async function vetHost(
  url: URL,
  options: Pick<ResolvingFetchOptions, "resolver" | "allowPrivateNetworks"> = {},
): Promise<{ readonly address: string; readonly family: 4 | 6 }> {
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new DiscoveryError("unsafe_url", "Discovery and metadata URLs must use HTTPS without user information");
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const literal = literalAddress(hostname);
  const addresses = literal !== undefined ? [literal] : await (options.resolver ?? resolveAddresses)(hostname);
  if (addresses.length === 0) throw new DiscoveryError("dns_failed", "Metadata host has no addresses");
  // Every address, not only the one dialled: a name answering one private address is refused.
  if (!options.allowPrivateNetworks && addresses.some((address) => !isGlobalAddress(address))) {
    throw new DiscoveryError("unsafe_address", "Metadata host resolves to a non-public address");
  }
  const address = addresses[0]!;
  const family = isIP(address);
  if (family !== 4 && family !== 6) throw new DiscoveryError("dns_failed", "Metadata host resolved to no address");
  return { address, family };
}

function pinnedLookup(address: string, family: 4 | 6): LookupFunction {
  // The socket asks to resolve the URL's host: it gets the vetted address, never DNS again.
  return ((_hostname: string, options: { all?: boolean } | number, callback: unknown) => {
    const done = (typeof options === "function" ? options : callback) as (
      error: NodeJS.ErrnoException | null,
      address: string | LookupAddress[],
      family?: number,
    ) => void;
    if (typeof options === "object" && options?.all) done(null, [{ address, family }]);
    else done(null, address, family);
  }) as unknown as LookupFunction;
}

function headerRecord(headers: HeadersInit | undefined): Record<string, string> {
  const result: Record<string, string> = {};
  if (headers === undefined) return result;
  for (const [name, value] of new Headers(headers)) result[name.toLowerCase()] = value;
  return result;
}

function bodyBytes(body: BodyInit | null | undefined): Uint8Array | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof URLSearchParams) return new TextEncoder().encode(body.toString());
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  throw new TypeError("The resolving fetch sends a string, form, or byte body only");
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);

/**
 * A `fetch` that resolves, vets, and pins: `dns.lookup` every address of the host, refuse
 * the URL if any is not global unicast (loopback, private, link-local and metadata,
 * CGNAT, ULA, an IPv4 address inside IPv6), then dial the vetted address over
 * `node:https` with the URL's own name for SNI, certificate checks, and `Host`.
 * A name that rebinds after the check is never resolved again. Redirects are returned
 * (`manual`), refused (`error`), or followed and vetted again (`follow`).
 */
export function createResolvingFetch(options: ResolvingFetchOptions = {}): typeof globalThis.fetch {
  const maxRedirects = options.maxRedirects ?? 5;
  const once = async (url: URL, init: RequestInit): Promise<Response> => {
    const { address, family } = await vetHost(url, options);
    const signal = init.signal ?? undefined;
    signal?.throwIfAborted();
    const body = bodyBytes(init.body);
    return new Promise<Response>((resolve, reject) => {
      const request = httpsRequest(
        {
          host: url.hostname.replace(/^\[|\]$/g, ""),
          port: url.port || 443,
          path: `${url.pathname}${url.search}`,
          method: init.method ?? "GET",
          headers: { ...headerRecord(init.headers), host: url.host },
          lookup: pinnedLookup(address, family),
          agent: false,
          ...(literalAddress(url.hostname) === undefined ? { servername: url.hostname } : {}),
          ...(options.ca === undefined ? {} : { ca: options.ca as string | Buffer | (string | Buffer)[] }),
        },
        (response) => {
          const headers = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (value === undefined) continue;
            for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
          }
          const status = response.statusCode ?? 0;
          const empty = [204, 205, 304].includes(status) || (init.method ?? "GET").toUpperCase() === "HEAD";
          if (empty) response.resume();
          resolve(
            new Response(empty ? null : (Readable.toWeb(response) as unknown as ReadableStream<Uint8Array>), {
              status,
              ...(response.statusMessage ? { statusText: response.statusMessage } : {}),
              headers,
            }),
          );
        },
      );
      request.on("error", reject);
      signal?.addEventListener("abort", () => request.destroy(signal.reason as Error), { once: true });
      if (body !== undefined) request.write(body);
      request.end();
    });
  };
  return (async (input: string | URL | Request, init: RequestInit = {}) => {
    if (input instanceof Request) throw new TypeError("The resolving fetch takes a URL, not a Request");
    let url = new URL(String(input));
    let current = init;
    for (let redirects = 0; ; redirects += 1) {
      const response = await once(url, current);
      if (!REDIRECTS.has(response.status) || (init.redirect ?? "follow") === "manual") return response;
      await response.body?.cancel().catch(() => undefined);
      if (init.redirect === "error") throw new TypeError("fetch failed: redirect mode is error");
      const location = response.headers.get("location");
      if (location === null || redirects >= maxRedirects) throw new TypeError("fetch failed: redirect");
      url = new URL(location, url);
      // Each hop is resolved and vetted again; a 303 (or a 301/302 POST) continues as GET.
      if (response.status === 303 || ((response.status === 301 || response.status === 302) && (current.method ?? "GET").toUpperCase() === "POST")) {
        const { body: _body, ...rest } = current;
        current = { ...rest, method: "GET" };
      }
    }
  }) as typeof globalThis.fetch;
}
