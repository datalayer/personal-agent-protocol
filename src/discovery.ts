/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { MetadataCache } from "./caching.js";
import { DiscoveryError, ProtocolValidationError } from "./errors.js";
import { readBoundedBytes, withinDeadline, type CacheBounds } from "./limits.js";
import { parseJsonStrict } from "./json.js";
import {
  chooseProtocolVersion,
  chosenVersion,
  implementedProtocolVersions,
  companyIssuer,
  companyResource,
  listsResource,
  needsIssuer,
  parseDiscoveryDocument,
  parseOAuthServerMetadata,
  parseProtectedResourceMetadata,
  protectedResourceMetadataUrl,
  type DiscoveredCompany,
  type DiscoveryDocument,
  type SkillEntry,
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
  /** The most a skill's artifact may weigh (`fetchSkill`, §9.4; default 4 MiB). */
  readonly maxSkillBytes?: number;
  /** Total time for each metadata fetch, however slowly the server sends (default 5000). */
  readonly timeoutMs?: number;
  /** Cache-Control bounds for discovery and OAuth metadata (default: a minute to a day). */
  readonly cacheBounds?: CacheBounds;
  readonly signal?: AbortSignal;
  /**
   * Read `poppy.json` again, not a cached copy (§3.4): after `version_unsupported`, when the
   * Personal Agent chooses a version again.
   */
  readonly fresh?: boolean;
  /**
   * The protocol versions this Personal Agent implements (§3.4): `SUPPORTED_PROTOCOL_VERSIONS`,
   * the published version, by default. Name `DRAFT_PROTOCOL_VERSION` among them to use
   * Companies that serve the 1.0 draft, such as `["0.4", "1.0"]`; the newest compatible version
   * a Company serves is chosen.
   */
  readonly protocolVersions?: Iterable<string>;
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
  readonly maxSkillBytes: number;
  readonly timeoutMs: number;
  readonly cache: MetadataCache;
  readonly signal: AbortSignal | undefined;
}

/** The document at `url`, from `pap.cache` while its `Cache-Control` allows (§3, §3.2). */
async function readJson(
  initialUrl: URL,
  options: ReadOptions,
  followRedirects = true,
): Promise<Fetched> {
  const key = `pap.metadata:${initialUrl.toString()}`;
  const cached = await options.cache.get(key);
  if (cached !== undefined) return { value: cached.value, finalUrl: new URL(cached.finalUrl) };
  const fetched = await fetchJson(initialUrl, options, followRedirects);
  await options.cache.put(key, fetched.value, fetched.finalUrl.toString(), fetched.headers);
  return fetched;
}

async function fetchJson(
  initialUrl: URL,
  options: ReadOptions,
  followRedirects = true,
): Promise<Fetched & { readonly headers: Headers }> {
  const { bytes, finalUrl, headers } = await fetchBytes(initialUrl, options, {
    accept: "application/json",
    maxBytes: options.maxResponseBytes,
    followRedirects,
  });
  const contentType = headers.get("content-type")?.split(";", 1)[0]?.trim();
  if (contentType !== "application/json" && contentType !== "application/poppy+json") {
    throw new DiscoveryError("invalid_content_type", "Discovery response must be JSON");
  }
  try {
    const body = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return { value: parseJsonStrict(body), finalUrl, headers };
  } catch (cause) {
    if (cause instanceof ProtocolValidationError) throw cause;
    throw new ProtocolValidationError("invalid_json", "Response is not valid JSON", {
      cause,
    });
  }
}

/**
 * A public document at `url`, redirects followed within the address rules (§3), or refused
 * when `followRedirects` is off (a version's document, §3.4).
 */
async function fetchBytes(
  initialUrl: URL,
  options: ReadOptions,
  bounds: { readonly accept: string; readonly maxBytes: number; readonly followRedirects?: boolean },
): Promise<{ readonly bytes: Uint8Array; readonly finalUrl: URL; readonly headers: Headers }> {
  const { transport, urlPolicy, maxRedirects, timeoutMs, signal } = options;
  let current = initialUrl;
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    await urlPolicy.assertSafe(current);
    const startedAt = Date.now();
    let response: Response;
    try {
      response = await withinDeadline(
        (aborted) =>
          transport.fetch(current, {
            headers: { Accept: bounds.accept },
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
      if (bounds.followRedirects === false) {
        throw new DiscoveryError("version_document_redirect", "A version's document is served where it is listed");
      }
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
    const bytes = await readBoundedBytes(response, {
      maxBytes: bounds.maxBytes,
      timeoutMs,
      startedAt,
      tooLarge: () =>
        new DiscoveryError("response_too_large", "Discovery response exceeds size limit"),
    });
    return { bytes, finalUrl: current, headers: response.headers };
  }
  throw new Error("redirect loop exited unexpectedly");
}

/**
 * The artifact of one of a Company's skills, its `digest` verified (§9.4).
 *
 * `skill` is one of `SessionTasks.skills`, from the Session's tasks response: its `url` is
 * resolved against `tasks.endpoint` and HTTPS, and it is fetched
 * as other public metadata is, through the URL safety policy, redirects included, with no
 * credential and no Session header, at most `maxSkillBytes`. The bytes are the artifact as
 * published: the `SKILL.md` of a `skill-md` entry, or an archive, whose extraction, with the
 * proposal's archive safety checks, is the host's. A digest that differs is
 * `skill_digest_mismatch`. A skill is Company content (§10.1): its scripts run only when the
 * host's configuration allows.
 */
export async function fetchSkill(skill: SkillEntry, options: DiscoveryOptions = {}): Promise<Uint8Array> {
  const { read } = readOptions(options);
  const { bytes } = await fetchBytes(new URL(skill.url), read, {
    accept: "*/*",
    maxBytes: read.maxSkillBytes,
  });
  // A copy backed by its own ArrayBuffer: the digest input is a BufferSource, never a view
  // of a shared buffer.
  const content = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  content.set(bytes);
  const hashed = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", content));
  const digest = `sha256:${Array.from(hashed, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  if (digest !== skill.digest) {
    throw new DiscoveryError("skill_digest_mismatch", "The skill's content is not what its digest names");
  }
  return bytes;
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
    maxSkillBytes: options.maxSkillBytes ?? 4 * 1024 * 1024,
    timeoutMs,
    cache: new MetadataCache(reactor, options.cacheBounds),
    signal: options.signal,
  };
  return { reactor, read };
}

/**
 * The Company at `domain`, at the newest protocol version compatible with this SDK.
 *
 * `poppy.json` is the document of the version the Company prefers; when another of its
 * `supported_versions` is the one chosen, that version's document is fetched and used instead
 * (§3.4). `fresh` reads `poppy.json` again, not a cached copy.
 */
async function discover(domain: string, options: DiscoveryOptions): Promise<DiscoveredCompany> {
  const requestedDomain = normalizeDomain(domain);
  const { read } = readOptions(options);
  const poppyUrl = new URL(`https://${requestedDomain}/.well-known/poppy.json`);
  if (options.fresh) await read.cache.delete(`pap.metadata:${poppyUrl.toString()}`);
  const discovery = await readJson(poppyUrl, read);
  // A redirect may change host, but only a document at the well-known path itself, with
  // no query, speaks for a domain: not an upload elsewhere on it (§3, §9.3).
  if (discovery.finalUrl.pathname !== "/.well-known/poppy.json" || discovery.finalUrl.search) {
    throw new DiscoveryError(
      "invalid_discovery_location",
      "Discovery redirects must end at /.well-known/poppy.json with no query",
    );
  }
  const raw = discovery.value;
  const implemented = implementedProtocolVersions(options.protocolVersions);
  if (typeof raw === "object" && raw !== null && !Array.isArray(raw) && chosenOf(raw as Record<string, unknown>, implemented) === undefined) {
    // Neither its own version nor one it links to is compatible with one this SDK
    // implements: none of the documents is used (§3.1, §3.4).
    throw new DiscoveryError(
      "unsupported_protocol_version",
      "poppy.json follows no protocol version this personal agent supports",
    );
  }
  let document = parseDiscoveryDocument(raw, implemented);
  // The document speaks for the host that served it, after redirects, compared
  // ignoring case and nothing else (§3, §3.1).
  const servedBy = discovery.finalUrl.hostname.toLowerCase().replace(/\.$/, "");
  if (document.organization.domain !== servedBy) {
    throw new DiscoveryError(
      "organization_domain_mismatch",
      "Discovery organization domain is not the host that served the document",
    );
  }
  const chosen = chosenVersion(document, implemented);
  if (chosen !== undefined && chosen !== document.protocol_version) {
    document = await versionDocument(document, chosen, discovery.finalUrl, read, implemented);
  }
  const resourceMetadata = await domainResourceMetadata(document, read);
  if (resourceMetadata === undefined || resourceMetadata.authorization_servers.length === 0) {
    // The only way to no issuer: 404, or metadata that lists none (§3.2).
    if (needsIssuer(document)) {
      throw new DiscoveryError("issuer_not_found", "The company offers sign-in and its domain names no issuer");
    }
    return {
      discoveryUrl: discovery.finalUrl.toString(),
      document,
      ...(resourceMetadata === undefined ? {} : { resourceMetadata }),
    };
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

function chosenOf(raw: Record<string, unknown>, implemented: ReadonlySet<string>): string | undefined {
  const version = raw.protocol_version;
  if (typeof version !== "string") return undefined;
  const supported = raw.supported_versions;
  const others =
    typeof supported === "object" && supported !== null && !Array.isArray(supported)
      ? Object.keys(supported)
      : [];
  return chooseProtocolVersion(version, others, implemented);
}

/**
 * The document of `version`, one of the preferred document's `supported_versions` (§3.4): an
 * HTTPS URL on the host that served `poppy.json`, fetched without following a redirect, with
 * `version` as its `protocol_version`, no `supported_versions`, the same `organization.domain`
 * and the same issuer.
 */
async function versionDocument(
  preferred: DiscoveryDocument,
  version: string,
  poppyUrl: URL,
  read: ReadOptions,
  implemented: ReadonlySet<string>,
): Promise<DiscoveryDocument> {
  const url = preferred.supported_versions[version] as string;
  const host = new URL(url).hostname.toLowerCase().replace(/\.$/, "");
  if (host !== poppyUrl.hostname.toLowerCase().replace(/\.$/, "")) {
    throw new DiscoveryError("version_document_host", "A version's document is on the host that served poppy.json, never another");
  }
  const fetched = await readJson(new URL(url), read, false);
  if (fetched.finalUrl.toString() !== new URL(url).toString()) {
    throw new DiscoveryError("version_document_redirect", "A version's document is served where it is listed");
  }
  const mismatch = () =>
    new DiscoveryError(
      "version_document_mismatch",
      "A version's document has the version it is listed under, no supported_versions, and the Company's domain and issuer",
    );
  const raw = fetched.value;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw mismatch();
  if ((raw as Record<string, unknown>).protocol_version !== version) throw mismatch();
  let document: DiscoveryDocument;
  try {
    document = parseDiscoveryDocument(raw, implemented);
  } catch (cause) {
    throw new ProtocolValidationError("invalid_discovery_document", "A version's document failed protocol validation", { cause });
  }
  if (
    Object.keys(document.supported_versions).length ||
    document.organization.domain !== preferred.organization.domain ||
    document.auth?.issuer !== preferred.auth?.issuer
  ) {
    throw mismatch();
  }
  return document;
}

/**
 * The domain's protected resource metadata, which names its issuer (§3.2).
 *
 * Its `resource` is exactly `https://{organization.domain}`. `undefined` for a 404, which says
 * the Company has no issuer; any other failure is thrown, and never read so.
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
 * `undefined` when the service publishes none (404), and when its `resource` isn't `url`, the
 * URL the metadata URL was derived from: such metadata is treated as absent (RFC 9728 §3.3,
 * §4.5). Cached as its headers allow; `fresh` reads it again, after a service said the agent's
 * view is stale (§4.5).
 */
export async function resourceMetadata(
  url: string,
  options: DiscoveryOptions & { readonly fresh?: boolean } = {},
): Promise<ProtectedResourceMetadata | undefined> {
  const { read } = readOptions(options);
  const metadataAddress = protectedResourceMetadataUrl(url);
  if (options.fresh === true) await read.cache.delete(`pap.metadata:${metadataAddress}`);
  try {
    const metadata = parseResourceMetadata((await readJson(new URL(metadataAddress), read)).value);
    return metadata.resource === url ? metadata : undefined;
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
  return (await serviceMetadata(company, url, options))?.resource;
}

/** The metadata of a service that accepts only tokens issued for it, or `undefined` (§4.5). */
export async function serviceMetadata(
  company: DiscoveredCompany,
  url: string,
  options: DiscoveryOptions & { readonly fresh?: boolean } = {},
): Promise<ProtectedResourceMetadata | undefined> {
  const metadata = await resourceMetadata(url, options);
  if (metadata === undefined || metadata.resource === companyResource(company)) return undefined;
  const issuer = companyIssuer(company);
  if (issuer === undefined || !metadata.authorization_servers.includes(issuer)) {
    throw new DiscoveryError(
      "invalid_resource_metadata",
      "The service's protected resource metadata names another authorization server",
    );
  }
  return metadata;
}
