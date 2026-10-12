/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { MetadataCache } from "./caching.js";
import { DiscoveryError, ProtocolValidationError } from "./errors.js";
import { readBoundedBody, withinDeadline, type CacheBounds } from "./limits.js";
import { parseJsonStrict } from "./json.js";
import {
  parseDiscoveryDocument,
  parseOAuthServerMetadata,
  type DiscoveredCompany,
} from "./models.js";
import {
  DiscoveryTransports,
  UrlSafetyPolicies,
  buildPapReactor,
  firstContribution,
  type DiscoveryTransport,
  type UrlSafetyPolicy,
} from "./reactor.js";
import { traced } from "./telemetry.js";
import type { ReactorPlatformView } from "@datalayer/reactor";

export interface DiscoveryOptions {
  readonly reactor?: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly assertSafeUrl?: (url: URL) => void | Promise<void>;
  readonly maxRedirects?: number;
  readonly maxResponseBytes?: number;
  /** Total time for each metadata fetch, however slowly the server sends (default 5000). */
  readonly timeoutMs?: number;
  /** Cache-Control bounds for discovery and OAuth metadata (default: a minute to a day). */
  readonly cacheBounds?: CacheBounds;
  readonly signal?: AbortSignal;
}

function normalizeDomain(domain: string): string {
  const value = domain.replace(/\.$/, "").toLowerCase();
  if (!value || value.includes("://") || value.includes("/")) {
    throw new DiscoveryError("invalid_domain", "Discovery requires a DNS domain name");
  }
  return value;
}

function metadataUrl(issuer: string): URL {
  const parsed = new URL(issuer);
  const path = parsed.pathname.replace(/\/$/, "");
  parsed.pathname = `/.well-known/oauth-authorization-server${path}`;
  parsed.search = "";
  parsed.hash = "";
  return parsed;
}

interface Fetched {
  readonly value: unknown;
  readonly finalUrl: URL;
}

interface ReadOptions {
  readonly transport: DiscoveryTransport;
  readonly urlPolicy: UrlSafetyPolicy;
  readonly maxRedirects: number;
  readonly maxResponseBytes: number;
  readonly timeoutMs: number;
  readonly cache: MetadataCache;
  readonly signal: AbortSignal | undefined;
}

/** The document at `url`, from `pap.cache` while its `Cache-Control` allows (§3, §3.2). */
async function readJson(initialUrl: URL, options: ReadOptions): Promise<Fetched> {
  const key = `pap.metadata:${initialUrl.toString()}`;
  const cached = await options.cache.get(key);
  if (cached !== undefined) return { value: cached.value, finalUrl: new URL(cached.finalUrl) };
  const fetched = await fetchJson(initialUrl, options);
  await options.cache.put(key, fetched.value, fetched.finalUrl.toString(), fetched.headers);
  return fetched;
}

async function fetchJson(
  initialUrl: URL,
  options: ReadOptions,
): Promise<Fetched & { readonly headers: Headers }> {
  const { transport, urlPolicy, maxRedirects, maxResponseBytes, timeoutMs, signal } = options;
  let current = initialUrl;
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    await urlPolicy.assertSafe(current);
    const startedAt = Date.now();
    let response: Response;
    try {
      response = await withinDeadline(
        (aborted) =>
          transport.fetch(current, {
            headers: { Accept: "application/json" },
            redirect: "manual",
            credentials: "omit",
            signal: aborted,
          }),
        { timeoutMs, startedAt, ...(signal === undefined ? {} : { signal }) },
      );
    } catch (cause) {
      if (cause instanceof DiscoveryError) throw cause;
      throw new DiscoveryError("request_failed", "Discovery request failed", { cause });
    }

    if (response.status >= 300 && response.status < 400) {
      // A redirect's body is never read: cancelled, so its connection is released.
      await response.body?.cancel().catch(() => undefined);
      if (redirects === maxRedirects) {
        throw new DiscoveryError("too_many_redirects", "Discovery exceeded redirect limit");
      }
      const location = response.headers.get("location");
      if (!location) {
        throw new DiscoveryError("invalid_redirect", "Discovery redirect has no location");
      }
      current = new URL(location, current);
      continue;
    }
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new DiscoveryError(
        "http_error",
        "Discovery endpoint returned an unsuccessful status",
        { statusCode: response.status },
      );
    }
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
    if (contentType !== "application/json" && contentType !== "application/poppy+json") {
      throw new DiscoveryError("invalid_content_type", "Discovery response must be JSON");
    }
    const body = await readBoundedBody(response, {
      maxBytes: maxResponseBytes,
      timeoutMs,
      startedAt,
      tooLarge: () =>
        new DiscoveryError("response_too_large", "Discovery response exceeds size limit"),
    });
    try {
      return { value: parseJsonStrict(body), finalUrl: current, headers: response.headers };
    } catch (cause) {
      if (cause instanceof ProtocolValidationError) throw cause;
      throw new ProtocolValidationError("invalid_json", "Response is not valid JSON", {
        cause,
      });
    }
  }
  throw new DiscoveryError("too_many_redirects", "Discovery exceeded redirect limit");
}

export function discoverCompany(
  domain: string,
  options: DiscoveryOptions = {},
): Promise<DiscoveredCompany> {
  return traced(
    options.reactor,
    "pap.discovery.discover",
    { "pap.company.domain": domain.replace(/\.$/, "").toLowerCase() },
    () => discover(domain, options),
    (company) => ({ "pap.company.issuer": company.oauthMetadata?.issuer }),
  );
}

async function discover(domain: string, options: DiscoveryOptions): Promise<DiscoveredCompany> {
  const requestedDomain = normalizeDomain(domain);
  const reactor = options.reactor ?? buildPapReactor(options);
  const transport = firstContribution<DiscoveryTransport>(
    reactor,
    DiscoveryTransports,
    "discovery transport",
  );
  const urlPolicy = firstContribution<UrlSafetyPolicy>(
    reactor,
    UrlSafetyPolicies,
    "URL safety policy",
  );
  const timeoutMs = options.timeoutMs ?? 5000;
  if (!(timeoutMs > 0)) throw new RangeError("timeoutMs must be positive");
  const read: ReadOptions = {
    transport,
    urlPolicy,
    maxRedirects: options.maxRedirects ?? 3,
    maxResponseBytes: options.maxResponseBytes ?? 100 * 1024,
    timeoutMs,
    cache: new MetadataCache(reactor, options.cacheBounds),
    signal: options.signal,
  };
  const discovery = await readJson(
    new URL(`https://${requestedDomain}/.well-known/poppy.json`),
    read,
  );
  const document = parseDiscoveryDocument(discovery.value);
  if (
    document.organization.domain.replace(/^www\./, "") !==
    requestedDomain.replace(/^www\./, "")
  ) {
    throw new DiscoveryError(
      "organization_domain_mismatch",
      "Discovery organization domain does not match the requested domain",
    );
  }
  if (!document.auth) {
    return { discoveryUrl: discovery.finalUrl.toString(), document };
  }

  const metadataResponse = await readJson(metadataUrl(document.auth.issuer), read);
  const oauthMetadata = parseOAuthServerMetadata(metadataResponse.value);
  if (oauthMetadata.issuer !== document.auth.issuer) {
    throw new DiscoveryError("issuer_mismatch", "OAuth metadata issuer does not match auth.issuer");
  }
  if (!oauthMetadata.poppy_domains.includes(document.organization.domain)) {
    throw new DiscoveryError(
      "domain_not_authorized",
      "OAuth metadata does not authorize the discovered company domain",
    );
  }
  return {
    discoveryUrl: discovery.finalUrl.toString(),
    document,
    oauthMetadata,
  };
}
