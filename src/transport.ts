import type { ReactorPlatformView } from "@datalayer/reactor";

import { TransportError } from "./errors.js";
import { DpopProofProviders, firstContribution } from "./reactor.js";
import type { SessionToken } from "./sessions.js";

const redirects = new Set([301, 302, 303, 307, 308]);

function httpsUrl(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new TransportError("invalid_url", "PAP resource URL must use HTTPS", {
      cause,
    });
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new TransportError("invalid_url", "PAP resource URL must use HTTPS");
  }
  return url;
}

export interface DpopFetchClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxRedirects?: number;
}

export interface DpopFetchRequestOptions {
  readonly token: SessionToken;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly issuer: string;
  readonly headers?: Readonly<Record<string, string>>;
  /** Replayable request body. Streaming bodies are intentionally unsupported. */
  readonly body?: string;
  readonly signal?: AbortSignal;
}

/** Send proof-bound PAP requests with fresh proofs and safe redirect handling. */
export class DpopFetchClient {
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxRedirects: number;

  constructor(options: DpopFetchClientOptions) {
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher)
      throw new TransportError(
        "fetch_unavailable",
        "A fetch implementation is required",
      );
    const maxRedirects = options.maxRedirects ?? 3;
    if (!Number.isInteger(maxRedirects) || maxRedirects < 0) {
      throw new RangeError("maxRedirects must not be negative");
    }
    this.#reactor = options.reactor;
    this.#fetch = fetcher;
    this.#maxRedirects = maxRedirects;
  }

  async request(
    method: string,
    url: string,
    options: DpopFetchRequestOptions,
  ): Promise<Response> {
    if (options.token.tokenType !== "DPoP") {
      throw new TransportError(
        "unexpected_token_type",
        "PAP resource requests require a DPoP token",
      );
    }
    const supplied = { ...(options.headers ?? {}) };
    if (
      Object.keys(supplied).some((name) =>
        ["authorization", "dpop"].includes(name.toLowerCase()),
      )
    ) {
      throw new TransportError(
        "protected_header",
        "Authorization and DPoP headers are host-owned",
      );
    }
    const dpop = firstContribution(
      this.#reactor,
      DpopProofProviders,
      "DPoP proof provider",
    );
    let currentUrl = httpsUrl(url);
    let currentMethod = method.toUpperCase();
    let currentBody = options.body;
    let redirectCount = 0;
    let nonce: string | undefined;
    let nonceRetried = false;
    while (true) {
      const proof = await dpop.create({
        method: currentMethod,
        url: currentUrl.toString(),
        tenantId: options.tenantId,
        subject: options.pairwiseUserId,
        issuer: options.issuer,
        accessToken: options.token.accessToken,
        ...(nonce === undefined ? {} : { nonce }),
      });
      let response: Response;
      try {
        response = await this.#fetch(currentUrl, {
          method: currentMethod,
          headers: {
            ...supplied,
            Authorization: `DPoP ${options.token.accessToken.reveal()}`,
            DPoP: proof.reveal(),
          },
          ...(currentBody === undefined ? {} : { body: currentBody }),
          credentials: "omit",
          redirect: "manual",
          ...(options.signal === undefined ? {} : { signal: options.signal }),
        });
      } catch (cause) {
        throw new TransportError(
          "request_failed",
          "PAP resource request failed",
          { cause },
        );
      }
      const challenge =
        response.headers.get("www-authenticate")?.toLowerCase() ?? "";
      const requestedNonce = response.headers.get("dpop-nonce") ?? undefined;
      if (challenge.includes("use_dpop_nonce") && !nonceRetried) {
        if (!requestedNonce) {
          throw new TransportError(
            "missing_dpop_nonce",
            "DPoP nonce challenge omitted its nonce",
          );
        }
        nonce = requestedNonce;
        nonceRetried = true;
        continue;
      }
      if (!redirects.has(response.status)) return response;
      if (redirectCount >= this.#maxRedirects) {
        throw new TransportError(
          "too_many_redirects",
          "PAP resource request exceeded redirect limit",
        );
      }
      const location = response.headers.get("location");
      if (!location)
        throw new TransportError(
          "invalid_redirect",
          "PAP resource redirect has no location",
        );
      const target = httpsUrl(new URL(location, currentUrl).toString());
      if (target.origin !== currentUrl.origin) {
        throw new TransportError(
          "cross_origin_redirect",
          "PAP credentials are never forwarded to another origin",
        );
      }
      redirectCount += 1;
      currentUrl = target;
      nonce = undefined;
      nonceRetried = false;
      if (response.status === 303) {
        currentMethod = "GET";
        currentBody = undefined;
      }
    }
  }
}
