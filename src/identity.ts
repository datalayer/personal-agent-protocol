import type { ReactorPlatformView } from "@datalayer/reactor";

import { IdentityError, ProtocolValidationError } from "./errors.js";
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
}

export interface IdentityRequestOptions {
  readonly signal?: AbortSignal;
}

/** Safely retrieve and bind a personal agent's public identity documents. */
export class AgentIdentityClient {
  readonly #reactor: ReactorPlatformView;
  readonly #maxJwksRedirects: number;
  readonly #maxResponseBytes: number;

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
  }

  async fetchMetadata(
    clientId: string,
    options: IdentityRequestOptions = {},
  ): Promise<ClientMetadata> {
    const requested = this.#clientIdUrl(clientId);
    const value = await this.#readJson(requested, 0, undefined, options.signal);
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

  async fetchJwks(
    clientId: string,
    options: IdentityRequestOptions = {},
  ): Promise<JsonWebKeySet> {
    const metadata = await this.fetchMetadata(clientId, options);
    const jwksUrl = new URL(metadata.jwks_uri);
    const value = await this.#readJson(
      jwksUrl,
      this.#maxJwksRedirects,
      new URL(metadata.client_id).hostname,
      options.signal,
    );
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
  ): Promise<unknown> {
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
      let response: Response;
      try {
        response = await transport.fetch(current, {
          headers: { Accept: "application/json" },
          redirect: "manual",
          credentials: "omit",
          ...(signal === undefined ? {} : { signal }),
        });
      } catch (cause) {
        throw new IdentityError("request_failed", "Agent identity request failed", { cause });
      }
      if (response.status >= 300 && response.status < 400) {
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
      const body = await response.text();
      if (new TextEncoder().encode(body).byteLength > this.#maxResponseBytes) {
        throw new IdentityError(
          "response_too_large",
          "Agent identity response exceeds size limit",
        );
      }
      return parseJsonStrict(body);
    }
    throw new IdentityError("too_many_redirects", "Agent identity endpoint exceeded redirect policy");
  }
}
