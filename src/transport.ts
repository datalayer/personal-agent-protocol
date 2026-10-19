/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { TransportError } from "./errors.js";
import { budgetKey, parseRetryAfter, RetryPolicy } from "./limits.js";
import {
  Clocks,
  DpopProofProviders,
  RandomSources,
  RateLimitBudgets,
  RetryPolicies,
  firstContribution,
  optionalContribution,
} from "./reactor.js";
import { refuseRedirect } from "./refusals.js";
import type { SessionToken } from "./sessions.js";

/** Refusals that ask the caller to come back later (Guides, retries and rate limits). */
const later = new Set([429, 503]);
/** Methods retried on their own: they change nothing at the company. */
const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);

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

/** Send proof-bound PAP requests with fresh proofs; a redirect is refused, never followed (§3). */
export class DpopFetchClient {
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: DpopFetchClientOptions) {
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher)
      throw new TransportError(
        "fetch_unavailable",
        "A fetch implementation is required",
      );
    this.#reactor = options.reactor;
    this.#fetch = fetcher;
  }

  /**
   * Send a DPoP request within the company's shared budget, retrying when told to.
   *
   * Every attempt draws on `pap.rateLimitBudget` for the company's origin. A
   * 429 or 503 shares its `Retry-After` with every task through the budget; a
   * safe method (GET, HEAD, OPTIONS) is then retried by `pap.retryPolicy` —
   * never sooner than `Retry-After`, with exponential backoff and jitter
   * otherwise — each time with a fresh DPoP proof. A write, or a pause longer
   * than the policy allows, returns the refusal to the caller.
   */
  async request(
    method: string,
    url: string,
    options: DpopFetchRequestOptions,
  ): Promise<Response> {
    const policy =
      optionalContribution(this.#reactor, RetryPolicies, "retry policy") ??
      new RetryPolicy({ maxAttempts: 1 });
    const budget = optionalContribution(this.#reactor, RateLimitBudgets, "rate-limit budget");
    const key = budgetKey(httpsUrl(url));
    let attempts = 0;
    while (true) {
      await budget?.acquire(key);
      const response = await this.#requestOnce(method, url, options);
      attempts += 1;
      if (!later.has(response.status)) return response;
      const retryAfter = parseRetryAfter(response.headers.get("retry-after"), this.#now());
      const delay = safeMethods.has(method.toUpperCase())
        ? policy.delay(attempts, retryAfter, this.#jitter())
        : undefined;
      const pause = delay ?? retryAfter;
      if (budget !== undefined && pause !== undefined) await budget.defer(key, pause);
      if (delay === undefined) return response;
      // Drop the refused body before trying again.
      await response.body?.cancel().catch(() => undefined);
      if (budget === undefined) await new Promise((resolve) => setTimeout(resolve, delay * 1000));
    }
  }

  #now(): Date {
    return (optionalContribution(this.#reactor, Clocks, "clock") ?? { now: () => new Date() }).now();
  }

  #jitter(): number {
    const source = optionalContribution(this.#reactor, RandomSources, "random source");
    if (source === undefined) return 0.5;
    const bytes = source.bytes(4);
    if (bytes.byteLength < 4) return 0.5;
    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0) / 2 ** 32;
  }

  async #requestOnce(
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
    const currentUrl = httpsUrl(url);
    const currentMethod = method.toUpperCase();
    const currentBody = options.body;
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
      // A redirect would carry the token and a proof to another URL: refused (§3).
      await refuseRedirect(response);
      return response;
    }
  }
}
