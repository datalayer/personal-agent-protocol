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
  SUPPORTED_PROTOCOL_VERSIONS,
  companyIssuer,
  companyResource,
  listsResource,
  needsIssuer,
  parseDiscoveryDocument,
  parseExcludedTasks,
  parseOAuthServerMetadata,
  parseProtectedResourceMetadata,
  protectedResourceMetadataUrl,
  type DiscoveredCompany,
  type DiscoveryDocument,
  type ExcludedTasks,
  type ProtectedResourceMetadata,
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

/**
 * The issuer's RFC 8414 §3.1 metadata URL: the well-known path between host and path.
 *
 * `https://auth.provider.example/shop-a` has its metadata at
 * `https://auth.provider.example/.well-known/oauth-authorization-server/shop-a` (§3.2).
 */
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

function readOptions(options: DiscoveryOptions): { reactor: ReactorPlatformView; read: ReadOptions } {
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
  return { reactor, read };
}

async function discover(domain: string, options: DiscoveryOptions): Promise<DiscoveredCompany> {
  const requestedDomain = normalizeDomain(domain);
  const { read } = readOptions(options);
  const discovery = await readJson(
    new URL(`https://${requestedDomain}/.well-known/poppy.json`),
    read,
  );
  // A redirect may change host, but only a document at the well-known path itself, with
  // no query, speaks for a domain: not an upload elsewhere on it (§3, §9.3).
  if (discovery.finalUrl.pathname !== "/.well-known/poppy.json" || discovery.finalUrl.search) {
    throw new DiscoveryError(
      "invalid_discovery_location",
      "Discovery redirects must end at /.well-known/poppy.json with no query",
    );
  }
  const raw = discovery.value;
  const version =
    typeof raw === "object" && raw !== null && !Array.isArray(raw)
      ? (raw as Record<string, unknown>).protocol_version
      : undefined;
  if (typeof version === "string" && !SUPPORTED_PROTOCOL_VERSIONS.has(version)) {
    // Before 1.0 each version can break the last: only a supported major.minor (§3.1).
    throw new DiscoveryError(
      "unsupported_protocol_version",
      "poppy.json follows a protocol version this personal agent does not support",
    );
  }
  const document = parseDiscoveryDocument(raw);
  // The document speaks for the host that served it, after redirects, compared
  // ignoring case and nothing else (§3, §3.1).
  const servedBy = discovery.finalUrl.hostname.toLowerCase().replace(/\.$/, "");
  if (document.organization.domain !== servedBy) {
    throw new DiscoveryError(
      "organization_domain_mismatch",
      "Discovery organization domain is not the host that served the document",
    );
  }
  const resourceMetadata = await domainResourceMetadata(document, read);
  if (resourceMetadata === undefined) {
    return { discoveryUrl: discovery.finalUrl.toString(), document };
  }

  const issuer = issuerNamed(document, resourceMetadata);
  const metadataResponse = await readJson(metadataUrl(issuer), read);
  let oauthMetadata;
  try {
    oauthMetadata = parseOAuthServerMetadata(metadataResponse.value);
  } catch (cause) {
    throw new ProtocolValidationError(
      "invalid_oauth_metadata",
      "OAuth server metadata failed validation",
      { cause },
    );
  }
  // Character for character: no case folding, no trailing-slash trimming (§3.2).
  if (oauthMetadata.issuer !== issuer) {
    throw new DiscoveryError("issuer_mismatch", "OAuth metadata issuer is not the issuer found");
  }
  // `https://{domain}` exactly, the host ignoring case (§3.2, RFC 9728 §3.3).
  if (!listsResource(oauthMetadata, document.organization.domain)) {
    throw new DiscoveryError(
      "domain_not_authorized",
      "OAuth metadata does not authorize the discovered company domain",
    );
  }
  return {
    discoveryUrl: discovery.finalUrl.toString(),
    document,
    resourceMetadata,
    oauthMetadata,
  };
}

/**
 * The domain's protected resource metadata, which names its issuer (§3.2).
 *
 * Its `resource` is exactly `https://{organization.domain}`. A domain without it has no
 * issuer: refused when the document lists anything that needs one, else a website to
 * browse only.
 */
async function domainResourceMetadata(
  document: DiscoveryDocument,
  read: ReadOptions,
): Promise<ProtectedResourceMetadata | undefined> {
  const resource = `https://${document.organization.domain}`;
  let fetched: Fetched;
  try {
    fetched = await readJson(new URL(protectedResourceMetadataUrl(resource)), read);
  } catch (cause) {
    if (cause instanceof DiscoveryError && cause.code === "http_error" && cause.statusCode === 404) {
      if (needsIssuer(document)) {
        throw new DiscoveryError(
          "issuer_not_found",
          "The domain publishes no protected resource metadata naming its issuer",
          { cause },
        );
      }
      return undefined;
    }
    throw cause;
  }
  const metadata = parseResourceMetadata(fetched.value);
  if (metadata.resource !== resource) {
    throw new DiscoveryError(
      "resource_mismatch",
      "The domain's protected resource metadata names another resource",
    );
  }
  return metadata;
}

function parseResourceMetadata(value: unknown): ProtectedResourceMetadata {
  try {
    return parseProtectedResourceMetadata(value);
  } catch (cause) {
    throw new ProtocolValidationError(
      "invalid_resource_metadata",
      "Protected resource metadata failed validation",
      { cause },
    );
  }
}

/**
 * The issuer the domain names (§3.1, §3.2).
 *
 * One authorization server is the issuer, and `auth.issuer`, if present, names it; with
 * several, `auth.issuer` is required and must be one of them.
 */
function issuerNamed(document: DiscoveryDocument, metadata: ProtectedResourceMetadata): string {
  const servers = metadata.authorization_servers;
  const named = document.auth?.issuer;
  if (servers.length === 1) {
    const only = servers[0] as string;
    if (named !== undefined && named !== only) {
      throw new DiscoveryError("issuer_mismatch", "auth.issuer is not the domain's authorization server");
    }
    return only;
  }
  if (named === undefined) {
    throw new DiscoveryError(
      "issuer_not_named",
      "The domain lists several authorization servers and auth.issuer names none",
    );
  }
  if (!servers.includes(named)) {
    throw new DiscoveryError(
      "issuer_mismatch",
      "auth.issuer is not one of the domain's authorization servers",
    );
  }
  return named;
}

/**
 * The protected resource metadata of the service at `url` (RFC 9728 §3.1), if any.
 *
 * `undefined` when the service publishes none (404). Cached as its headers allow; `fresh`
 * reads it again, after a service said the agent's view is stale (§4.5).
 */
export async function resourceMetadata(
  url: string,
  options: DiscoveryOptions & { readonly fresh?: boolean } = {},
): Promise<ProtectedResourceMetadata | undefined> {
  const { read } = readOptions(options);
  const metadataAddress = protectedResourceMetadataUrl(url);
  if (options.fresh === true) await read.cache.delete(`pap.metadata:${metadataAddress}`);
  try {
    return parseResourceMetadata((await readJson(new URL(metadataAddress), read)).value);
  } catch (cause) {
    if (cause instanceof DiscoveryError && cause.code === "http_error" && cause.statusCode === 404) {
      return undefined;
    }
    throw cause;
  }
}

/**
 * The `resource` to request a token for before calling `url`, or `undefined` (§4.5).
 *
 * A service whose protected resource metadata names a `resource` other than
 * `https://{organization.domain}` accepts only tokens issued for it, and its
 * `authorization_servers` include the Company's issuer. Without metadata, or with the
 * domain's own, the default token works there.
 */
export async function serviceResource(
  company: DiscoveredCompany,
  url: string,
  options: DiscoveryOptions & { readonly fresh?: boolean } = {},
): Promise<string | undefined> {
  const metadata = await resourceMetadata(url, options);
  if (metadata === undefined || metadata.resource === companyResource(company)) return undefined;
  const issuer = companyIssuer(company);
  if (issuer === undefined || !metadata.authorization_servers.includes(issuer)) {
    throw new DiscoveryError(
      "invalid_resource_metadata",
      "The service's protected resource metadata names another authorization server",
    );
  }
  return metadata.resource;
}

/**
 * The tasks the company chose not to offer through the protocol (§8.1).
 *
 * A public document: a GET with no token, cached as its headers allow. `undefined` when
 * the company lists none. Read it before starting on a task there; whether a user's task
 * is one of them is the agent's judgment.
 */
export async function excludedTasks(
  company: DiscoveredCompany,
  options: DiscoveryOptions = {},
): Promise<ExcludedTasks | undefined> {
  const descriptor = company.document.excluded_tasks;
  if (descriptor === undefined) return undefined;
  const { read } = readOptions(options);
  const fetched = await readJson(new URL(descriptor.url), read);
  try {
    return parseExcludedTasks(fetched.value);
  } catch (cause) {
    throw new ProtocolValidationError(
      "invalid_excluded_tasks",
      "The excluded tasks document failed validation",
      { cause },
    );
  }
}
