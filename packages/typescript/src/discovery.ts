import { DiscoveryError, ProtocolValidationError } from "./errors.js";
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
import type { ReactorPlatformView } from "@datalayer/reactor";

export interface DiscoveryOptions {
  readonly reactor?: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly assertSafeUrl?: (url: URL) => void | Promise<void>;
  readonly maxRedirects?: number;
  readonly maxResponseBytes?: number;
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

async function readJson(
  initialUrl: URL,
  transport: DiscoveryTransport,
  urlPolicy: UrlSafetyPolicy,
  maxRedirects: number,
  maxResponseBytes: number,
): Promise<{ value: unknown; finalUrl: URL }> {
  let current = initialUrl;
  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    await urlPolicy.assertSafe(current);
    let response: Response;
    try {
      response = await transport.fetch(current, {
        headers: { Accept: "application/json" },
        redirect: "manual",
        credentials: "omit",
      });
    } catch (cause) {
      throw new DiscoveryError("request_failed", "Discovery request failed", { cause });
    }

    if (response.status >= 300 && response.status < 400) {
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
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > maxResponseBytes) {
      throw new DiscoveryError("response_too_large", "Discovery response exceeds size limit");
    }
    try {
      return { value: parseJsonStrict(body), finalUrl: current };
    } catch (cause) {
      if (cause instanceof ProtocolValidationError) throw cause;
      throw new ProtocolValidationError("invalid_json", "Response is not valid JSON", {
        cause,
      });
    }
  }
  throw new DiscoveryError("too_many_redirects", "Discovery exceeded redirect limit");
}

export async function discoverCompany(
  domain: string,
  options: DiscoveryOptions = {},
): Promise<DiscoveredCompany> {
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
  const maxRedirects = options.maxRedirects ?? 3;
  const maxBytes = options.maxResponseBytes ?? 100 * 1024;
  const discovery = await readJson(
    new URL(`https://${requestedDomain}/.well-known/poppy.json`),
    transport,
    urlPolicy,
    maxRedirects,
    maxBytes,
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

  const metadataResponse = await readJson(
    metadataUrl(document.auth.issuer),
    transport,
    urlPolicy,
    maxRedirects,
    maxBytes,
  );
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
