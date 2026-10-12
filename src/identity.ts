import type { ReactorPlatformView } from "@datalayer/reactor";

import { MetadataCache } from "./caching.js";
import { DiscoveryError, IdentityError, ProtocolValidationError } from "./errors.js";
import { readBoundedBody, withinDeadline, type CacheBounds } from "./limits.js";
import { parseJsonStrict } from "./json.js";
import {
  parseClientMetadata,
  parseJsonWebKeySet,
  type ClientMetadata,
  type JsonWebKeySet,
} from "./models.js";
import {
  DiscoveryTransports,
  UrlSafetyPolicies,
  buildPapReactor,
  firstContribution,
  type DiscoveryTransport,
  type PapCoreOptions,
  type UrlSafetyPolicy,
} from "./reactor.js";

export interface AgentIdentityClientOptions extends PapCoreOptions {
  readonly reactor?: ReactorPlatformView;
  readonly maxJwksRedirects?: number;
  readonly maxResponseBytes?: number;
  /** Total time for each fetch, however slowly the server sends (default 5000). */
  readonly timeoutMs?: number;
  /** Cache-Control bounds for client metadata and JWKS (default: a minute to a day). */
  readonly cacheBounds?: CacheBounds;
  /** At most one JWKS refetch per `jwks_uri` this often, for unknown `kid`s (default 60). */
  readonly jwksRefetchIntervalSeconds?: number;
}

export interface IdentityRequestOptions {
  readonly signal?: AbortSignal;
}

export interface JwksRequestOptions extends IdentityRequestOptions {
  /** The key an assertion names: fetch the set again when the cached one lacks it. */
  readonly kid?: string;
}

/** Safely retrieve and bind a personal agent's public identity documents. */
export class AgentIdentityClient {
  readonly #reactor: ReactorPlatformView;
  readonly #maxJwksRedirects: number;
  readonly #maxResponseBytes: number;
  readonly #timeoutMs: number;
  readonly #cache: MetadataCache;
  readonly #refetchIntervalMs: number;
  readonly #refetched = new Map<string, number>();

  constructor(options: AgentIdentityClientOptions = {}) {
    const maxRedirects = options.maxJwksRedirects ?? 3;
    const maxBytes = options.maxResponseBytes ?? 100 * 1024;
    if (!Number.isInteger(maxRedirects) || maxRedirects < 0) {
      throw new RangeError("maxJwksRedirects must be a non-negative integer");
    }
    if (!Number.isInteger(maxBytes) || maxBytes <= 0) {
      throw new RangeError("maxResponseBytes must be a positive integer");
    }
    this.#reactor = options.reactor ?? buildPapReactor(options);
    this.#maxJwksRedirects = maxRedirects;
    this.#maxResponseBytes = maxBytes;
    this.#timeoutMs = options.timeoutMs ?? 5000;
    if (!(this.#timeoutMs > 0)) throw new RangeError("timeoutMs must be positive");
    this.#cache = new MetadataCache(this.#reactor, options.cacheBounds);
    this.#refetchIntervalMs = (options.jwksRefetchIntervalSeconds ?? 60) * 1000;
  }

  async fetchMetadata(
    clientId: string,
    options: IdentityRequestOptions = {},
  ): Promise<ClientMetadata> {
    const requested = this.#clientIdUrl(clientId);
    const value = await this.#cachedJson(
      `pap.client-metadata:${requested.toString()}`,
      requested,
      0,
      undefined,
      options.signal,
    );
    let metadata: ClientMetadata;
    try {
      metadata = parseClientMetadata(value);
    } catch (cause) {
      throw new ProtocolValidationError(
        "invalid_client_metadata",
        "Client metadata failed protocol validation",
        { cause },
      );
    }
    if (metadata.client_id !== requested.toString()) {
      throw new IdentityError(
        "client_id_mismatch",
        "Client metadata client_id does not match the URL that was fetched",
      );
    }
    return metadata;
  }

  /**
   * Fetch a verified client's bounded, public-only signing key set.
   *
   * The set is cached by its `Cache-Control`. When `kid` names a key the cached
   * set lacks — the agent published its next key beside the current one — the
   * set is fetched again, at most once per `jwksRefetchIntervalSeconds` for each
   * `jwks_uri`, so a stream of unknown `kid`s cannot trigger a fetch each time.
   */
  async fetchJwks(
    clientId: string,
    options: JwksRequestOptions = {},
  ): Promise<JsonWebKeySet> {
    const metadata = await this.fetchMetadata(clientId, options);
    const key = `pap.jwks:${metadata.jwks_uri}`;
    const keys = parseKeys(await this.#jwks(metadata, key, options.signal));
    if (options.kid === undefined || keys.keys.some((item) => item.kid === options.kid)) {
      return keys;
    }
    const now = this.#cache.now().getTime();
    const last = this.#refetched.get(metadata.jwks_uri);
    if (last !== undefined && now - last < this.#refetchIntervalMs) return keys;
    this.#refetched.set(metadata.jwks_uri, now);
    await this.#cache.delete(key);
    return parseKeys(await this.#jwks(metadata, key, options.signal));
  }

  #jwks(metadata: ClientMetadata, key: string, signal: AbortSignal | undefined): Promise<unknown> {
    return this.#cachedJson(
      key,
      new URL(metadata.jwks_uri),
      this.#maxJwksRedirects,
      new URL(metadata.client_id).hostname,
      signal,
    );
  }

  async #cachedJson(
    key: string,
    url: URL,
    maxRedirects: number,
    requiredHost: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<unknown> {
    const cached = await this.#cache.get(key);
    if (cached !== undefined) return cached.value;
    const fetched = await this.#readJson(url, maxRedirects, requiredHost, signal);
    await this.#cache.put(key, fetched.value, fetched.finalUrl, fetched.headers);
    return fetched.value;
  }

  #clientIdUrl(clientId: string): URL {
    let requested: URL;
    try {
      requested = new URL(clientId);
    } catch (cause) {
      throw new IdentityError(
        "invalid_client_id",
        "client_id must be a valid HTTPS URL",
        { cause },
      );
    }
    if (requested.hash) {
      throw new IdentityError("invalid_client_id", "client_id must not contain a fragment");
    }
    return requested;
  }

  async #readJson(
    initialUrl: URL,
    maxRedirects: number,
    requiredHost: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<{ readonly value: unknown; readonly finalUrl: string; readonly headers: Headers }> {
    const transport = firstContribution(
      this.#reactor,
      DiscoveryTransports,
      "metadata transport",
    );
    const policy = firstContribution(
      this.#reactor,
      UrlSafetyPolicies,
      "URL safety policy",
    );
    let current = initialUrl;

    for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
      if (requiredHost !== undefined && current.hostname !== requiredHost) {
        throw new IdentityError("jwks_domain_mismatch", "JWKS redirect changed agent domain");
      }
      await policy.assertSafe(current);
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
          { timeoutMs: this.#timeoutMs, startedAt, ...(signal === undefined ? {} : { signal }) },
        );
      } catch (cause) {
        if (cause instanceof DiscoveryError) throw cause;
        throw new IdentityError("request_failed", "Agent identity request failed", { cause });
      }
      if (response.status >= 300 && response.status < 400) {
        // A redirect's body is never read: cancelled, so its connection is released.
        await response.body?.cancel().catch(() => undefined);
        if (redirects === maxRedirects) {
          const code = maxRedirects === 0 ? "metadata_redirect" : "too_many_redirects";
          throw new IdentityError(code, "Agent identity endpoint exceeded redirect policy");
        }
        const location = response.headers.get("location");
        if (!location) {
          throw new IdentityError(
            "invalid_redirect",
            "Agent identity redirect has no location",
          );
        }
        current = new URL(location, current);
        continue;
      }
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        throw new IdentityError(
          "http_error",
          "Agent identity endpoint returned an unsuccessful status",
          { statusCode: response.status },
        );
      }
      const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
      if (contentType !== "application/json" && contentType !== "application/jwk-set+json") {
        throw new IdentityError("invalid_content_type", "Agent identity response must be JSON");
      }
      const body = await readBoundedBody(response, {
        maxBytes: this.#maxResponseBytes,
        timeoutMs: this.#timeoutMs,
        startedAt,
        tooLarge: () =>
          new IdentityError("response_too_large", "Agent identity response exceeds size limit"),
      });
      return { value: parseJsonStrict(body), finalUrl: current.toString(), headers: response.headers };
    }
    throw new IdentityError("too_many_redirects", "Agent identity endpoint exceeded redirect policy");
  }
}

function parseKeys(value: unknown): JsonWebKeySet {
  try {
    return parseJsonWebKeySet(value);
  } catch (cause) {
    throw new ProtocolValidationError(
      "invalid_jwks",
      "Personal-agent JWKS failed protocol validation",
      { cause },
    );
  }
}
