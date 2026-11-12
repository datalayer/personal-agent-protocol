/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Website pages fetched without a browser: the Session header, always signed out (§5.2), as in
 * Python's `personal_agent_protocol.pages`.
 *
 * A personal agent that fetches a page of a company's website with its own HTTP client, such
 * as a help article, sends the Session header with it (SHOULD), so the company can tell which
 * personal agent and Session the request is from:
 *
 * ```ts
 * const page = await new PageClient({ transport }).fetch("https://shop.example/help/returns", {
 *   session,
 *   company: company.document,
 * });
 * if (page.invalidSession) { ... } // a mistake in this agent's header: the page is still there
 * ```
 *
 * What this client guarantees:
 *
 * - **Only the company's own host.** The header goes with an HTTPS URL whose host is exactly
 *   `organization.domain`, the host that served `poppy.json`: never to another host on the
 *   company's domain, a subdomain, or anyone else.
 * - **Pages, not documents.** Discovery and description documents and OAuth endpoints never
 *   carry the header, on that host either (§5.2): a `/.well-known/` URL, a description URL
 *   `poppy.json` lists in `apis`, and, when the company is given as discovered, its issuer's
 *   endpoints are fetched without it.
 * - **Never an access token.** The Session JWT has no `ath` and the request is signed out,
 *   even when a browser joined to the Session is signed in. `fetch` takes no token.
 * - **A new JWT per redirect, or none.** A redirect is followed by hand: the next URL gets a
 *   Session JWT signed for it while its host is still `organization.domain`, and is fetched
 *   without the header otherwise. Every hop is HTTPS and passes the host's URL safety policy.
 * - **`invalid_session` is reported.** A page that verifies the header answers a failed check
 *   with `invalid_session` (§5.3). `fetch` says so (`invalidSession`) and, with
 *   `againWithoutHeader`, fetches the page once more without the header. It never leaves the
 *   header out on its own to look like a person.
 *
 * A headless browser is a browser: it joins the Session (`BrowserSessionClient`) and sends no
 * header. `web.disabled` asks agents not to use a browser on the website; it does not cover
 * these fetches (§6).
 */
import { TransportError } from "./errors.js";
import { readLimited } from "./limits.js";
import type { DiscoveredCompany, DiscoveryDocument } from "./models.js";
import { UrlSafetyPolicies, optionalContribution } from "./reactor.js";
import { REDIRECT_STATUSES } from "./refusals.js";
import type { PapSession } from "./sessions.js";
import { sessionError, sessionHeaders, type SessionFetchClient } from "./transport.js";

/**
 * A website page as the agent's own HTTP client got it. Content from the company (§10.1): data
 * for the agent, never instructions.
 */
export interface FetchedPage {
  /** The URL that answered, after any redirects. */
  readonly url: string;
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly content: Uint8Array;
  /** Whether the request that got this response carried the Session header. */
  readonly sessionHeaderSent: boolean;
  /**
   * Whether the company answered the header with `invalid_session`: a mistake in this agent's
   * header, as at any endpoint (§5.3).
   */
  readonly invalidSession: boolean;
}

/**
 * Whether a page fetch carries the Session header (§5.2): an HTTPS URL whose host is exactly
 * `organization.domain`, compared ignoring case, on the default port.
 */
export function pageCarriesSession(url: string, domain: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  return (
    parsed.protocol === "https:" &&
    parsed.hostname.toLowerCase() === domain.toLowerCase().replace(/\.+$/, "") &&
    parsed.port === "" &&
    !parsed.username &&
    !parsed.password
  );
}

/** A URL's origin and path: what names a document, whatever its query. */
function documentKey(url: string): string | undefined {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname}`;
  } catch {
    return undefined;
  }
}

/**
 * The URLs of a company that are documents or OAuth endpoints, not website pages (§5.2): they
 * never carry the Session header. `/.well-known/` paths are recognized apart, by their path.
 */
function documentUrls(company: DiscoveredCompany | DiscoveryDocument): ReadonlySet<string> {
  const discovered = "document" in company && "discoveryUrl" in company ? (company as DiscoveredCompany) : undefined;
  const document = discovered?.document ?? (company as DiscoveryDocument);
  const metadata = discovered?.oauthMetadata;
  const urls: (string | undefined)[] = [
    discovered?.discoveryUrl,
    ...document.apis.map((api) => api.url),
    ...Object.values(document.supported_versions),
    metadata?.token_endpoint,
    metadata?.revocation_endpoint,
    metadata?.authorization_endpoint,
    metadata?.device_authorization_endpoint,
    metadata?.pushed_authorization_request_endpoint,
  ];
  const keys = new Set<string>();
  for (const url of urls) {
    const key = typeof url === "string" ? documentKey(url) : undefined;
    if (key !== undefined) keys.add(key);
  }
  return keys;
}

export interface PageClientOptions {
  readonly transport: SessionFetchClient;
  readonly maxRedirects?: number;
  readonly maxResponseBytes?: number;
}

export interface PageFetchOptions {
  readonly session: PapSession;
  /** The Session's company: its `organization.domain` decides which URLs carry the header. */
  readonly company: DiscoveredCompany | DiscoveryDocument;
  /** After `invalid_session`, fetch the page once more without the header. */
  readonly againWithoutHeader?: boolean;
  readonly signal?: AbortSignal;
}

/** Where the header goes for one company: its domain, less its documents and OAuth endpoints. */
interface Destination {
  readonly domain: string;
  readonly documents: ReadonlySet<string>;
}

function isDocument(url: string, documents: ReadonlySet<string>): boolean {
  const key = documentKey(url);
  return key === undefined || new URL(url).pathname.startsWith("/.well-known/") || documents.has(key);
}

/** Fetch a company's website pages without a browser, in a Session, signed out. */
export class PageClient {
  readonly #transport: SessionFetchClient;
  readonly #maxRedirects: number;
  readonly #maxResponseBytes: number;

  constructor(options: PageClientOptions) {
    const maxRedirects = options.maxRedirects ?? 5;
    const maxResponseBytes = options.maxResponseBytes ?? 2 * 1024 * 1024;
    if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || !Number.isInteger(maxResponseBytes) || maxResponseBytes <= 0) {
      throw new RangeError("maxRedirects and maxResponseBytes must be positive");
    }
    this.#transport = options.transport;
    this.#maxRedirects = maxRedirects;
    this.#maxResponseBytes = maxResponseBytes;
  }

  /**
   * `GET url`, with the Session header wherever §5.2 says it goes.
   *
   * `company` is the Session's company: its `organization.domain` decides which URLs carry the
   * header. A URL elsewhere is fetched too, without it: that is an ordinary fetch of a public
   * page.
   */
  async fetch(url: string, options: PageFetchOptions): Promise<FetchedPage> {
    const company = options.company;
    const document = "document" in company && "discoveryUrl" in company ? (company as DiscoveredCompany).document : (company as DiscoveryDocument);
    const where: Destination = { domain: document.organization.domain, documents: documentUrls(company) };
    const page = await this.#follow(url, options, where, true);
    if (page.invalidSession && options.againWithoutHeader === true) {
      const again = await this.#follow(url, options, where, false);
      return { ...again, sessionHeaderSent: false, invalidSession: true };
    }
    return page;
  }

  async #follow(url: string, options: PageFetchOptions, where: Destination, withHeader: boolean): Promise<FetchedPage> {
    let current = url;
    for (let hop = 0; hop <= this.#maxRedirects; hop += 1) {
      await this.#assertSafe(current);
      const carries = withHeader && pageCarriesSession(current, where.domain) && !isDocument(current, where.documents);
      const headers: Record<string, string> = { Accept: "text/html, text/plain;q=0.9, */*;q=0.5" };
      if (carries) {
        // A new Session JWT for this URL, no access token: no `ath`, signed out.
        Object.assign(headers, await sessionHeaders(this.#transport.reactor, "GET", current, { session: options.session }));
      }
      let response: Response;
      try {
        const send = this.#transport.fetch;
        response = await send(current, {
          method: "GET",
          headers,
          credentials: "omit",
          redirect: "manual",
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (cause) {
        throw new TransportError("request_failed", "The page could not be fetched", { cause });
      }
      if (REDIRECT_STATUSES.has(response.status)) {
        await response.body?.cancel().catch(() => undefined);
        const location = response.headers.get("location");
        if (!location) throw new TransportError("invalid_redirect", "A redirect names no location");
        try {
          current = new URL(location, current).toString();
        } catch (cause) {
          throw new TransportError("invalid_redirect", "A redirect names no usable location", { cause });
        }
        continue;
      }
      const invalidSession = carries && (await sessionError(response)) === "invalid_session";
      let content: Uint8Array;
      try {
        content = await readLimited(response, this.#maxResponseBytes);
      } catch (cause) {
        throw new TransportError("request_failed", "The page could not be fetched", { cause });
      }
      if (content.byteLength > this.#maxResponseBytes) {
        throw new TransportError("response_too_large", "The page exceeds the size limit");
      }
      return {
        url: current,
        statusCode: response.status,
        headers: Object.fromEntries(response.headers),
        content,
        sessionHeaderSent: carries,
        invalidSession,
      };
    }
    throw new TransportError("too_many_redirects", "The page redirected too many times");
  }

  async #assertSafe(url: string): Promise<void> {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch (cause) {
      throw new TransportError("invalid_url", "A page is fetched from an HTTPS URL", { cause });
    }
    if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
      throw new TransportError("invalid_url", "A page is fetched from an HTTPS URL");
    }
    await optionalContribution(this.#transport.reactor, UrlSafetyPolicies, "URL policy")?.assertSafe(parsed);
  }
}
