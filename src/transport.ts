/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The Session header on every request to a Company's APIs and endpoints (§5.2, §5.6).
 *
 * Each request carries a fresh Session JWT (`Poppy-Session`) from the host's
 * `pap.sessionSigner`, and, signed in, the account's access token in `Authorization`, with the
 * scheme its `tokenType` names. A `DPoP` token goes with a fresh proof from `pap.dpopProver` on
 * every request and retry, and a `use_dpop_nonce` challenge is retried once; the latest nonce
 * is kept per origin for later requests (§4.5). An `invalid_session` answer starts a new
 * Session once, and the request is sent again in it; a second one is returned to the caller,
 * who stops (§5.5, §7).
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { budgetKey, parseRetryAfter, RetryPolicy } from "./limits.js";
import {
  Clocks,
  DpopProvers,
  RandomSources,
  RateLimitBudgets,
  RetryPolicies,
  SessionSigners,
  firstContribution,
  optionalContribution,
} from "./reactor.js";
import { dpopNonceAsked, refuseRedirect } from "./refusals.js";
import { DPOP_HEADER, DPOP_NONCE_HEADER, type AccessToken, type PapSession } from "./sessions.js";

/** The header that carries the Session JWT (§5.2). */
export const SESSION_HEADER = "Poppy-Session";
/** Refusals that ask the caller to come back later (Guides, retries and rate limits). */
const later = new Set([429, 503]);
/** Methods retried on their own: they change nothing at the company. */
const safeMethods = new Set(["GET", "HEAD", "OPTIONS"]);
/** Headers the host owns: a caller never sets them. */
const hostOwned = new Set(["authorization", "dpop", "poppy-session"]);

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

/** Whether the company answered `invalid_session` (§5.3): HTTP 400 and its JSON body. */
export async function invalidSession(response: Response): Promise<boolean> {
  if (response.status !== 400) return false;
  try {
    const payload = parseJsonStrict(await response.clone().text());
    return (
      typeof payload === "object" &&
      payload !== null &&
      (payload as Record<string, unknown>).error === "invalid_session"
    );
  } catch {
    return false;
  }
}

/**
 * The headers of one request: every credential, fresh (§4.5, §5.2).
 *
 * `Poppy-Session` always; with an access token, `Authorization`; with a `DPoP` token, a `DPoP`
 * proof too, whose `ath` covers the same token as the Session JWT's. `dpopNonce` is the
 * server's latest for this origin.
 */
export async function sessionHeaders(
  reactor: ReactorPlatformView,
  method: string,
  url: string,
  options: {
    readonly session: PapSession;
    readonly token?: AccessToken | undefined;
    readonly dpopNonce?: string | undefined;
  },
): Promise<Record<string, string>> {
  const { session, token, dpopNonce } = options;
  const signer = firstContribution(reactor, SessionSigners, "session signer");
  const jwt = await signer.sign({
    method: method.toUpperCase(),
    url,
    tenantId: session.tenantId,
    issuer: session.issuer,
    clientId: session.clientId,
    sid: session.sid,
    sub: session.sub,
    ...(session.agentId === undefined ? {} : { agentId: session.agentId }),
    ...(token === undefined ? {} : { accessToken: token.accessToken }),
  });
  const headers: Record<string, string> = { [SESSION_HEADER]: jwt.reveal() };
  if (token === undefined) return headers;
  headers.Authorization = `${token.tokenType} ${token.accessToken.reveal()}`;
  if (token.tokenType === "DPoP") {
    const proof = await firstContribution(reactor, DpopProvers, "DPoP prover").prove({
      method: method.toUpperCase(),
      url,
      tenantId: session.tenantId,
      issuer: session.issuer,
      accessToken: token.accessToken,
      ...(dpopNonce === undefined ? {} : { nonce: dpopNonce }),
    });
    headers[DPOP_HEADER] = proof.reveal();
  }
  return headers;
}

export interface SessionFetchClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
}

export interface SessionFetchRequestOptions {
  readonly session: PapSession;
  /** Signed in with it, signed out without. */
  readonly token?: AccessToken | undefined;
  readonly headers?: Readonly<Record<string, string>>;
  /** Replayable request body. Streaming bodies are intentionally unsupported. */
  readonly body?: string;
  readonly signal?: AbortSignal;
}

/** Send requests with the Session header; a redirect is refused, never followed (§3). */
export class SessionFetchClient {
  /** The latest `DPoP-Nonce` each origin gave a request with a `DPoP` token (§4.5). */
  readonly dpopNonces = new Map<string, string>();
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: SessionFetchClientOptions) {
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
   * Send a request in `session`, within the company's shared budget.
   *
   * Signed in with `token`, signed out without. Every attempt draws on `pap.rateLimitBudget`
   * for the company's origin and carries a fresh Session JWT. A 429 or 503 shares its
   * `Retry-After` with every task through the budget; a safe method (GET, HEAD, OPTIONS) is
   * then retried by `pap.retryPolicy` — never sooner than `Retry-After`, with exponential
   * backoff and jitter otherwise. A write, or a pause longer than the policy allows, returns
   * the refusal to the caller. `invalid_session` starts a new Session once
   * (`session.restart()`) and sends the request again in it, and a `use_dpop_nonce` challenge
   * sends it again once with the nonce.
   */
  async request(
    method: string,
    url: string,
    options: SessionFetchRequestOptions,
  ): Promise<Response> {
    const policy =
      optionalContribution(this.#reactor, RetryPolicies, "retry policy") ??
      new RetryPolicy({ maxAttempts: 1 });
    const budget = optionalContribution(this.#reactor, RateLimitBudgets, "rate-limit budget");
    const key = budgetKey(httpsUrl(url));
    let attempts = 0;
    let restarted = false;
    let nonceRetried = false;
    while (true) {
      await budget?.acquire(key);
      const response = await this.#requestOnce(method, url, options);
      attempts += 1;
      if (!restarted && (await invalidSession(response))) {
        // The Session failed a check or has ended: a new one, once (§5.5, §7).
        restarted = true;
        await response.body?.cancel().catch(() => undefined);
        options.session.restart((length) => this.#randomBytes(length));
        continue;
      }
      if (!nonceRetried && options.token?.tokenType === "DPoP" && dpopNonceAsked(response) !== undefined) {
        nonceRetried = true;
        await response.body?.cancel().catch(() => undefined);
        continue;
      }
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

  #randomBytes(length: number): Uint8Array {
    return firstContribution(this.#reactor, RandomSources, "random").bytes(length);
  }

  #jitter(): number {
    const source = optionalContribution(this.#reactor, RandomSources, "random source");
    if (source === undefined) return 0.5;
    const bytes = source.bytes(4);
    if (bytes.byteLength < 4) return 0.5;
    return new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0) / 2 ** 32;
  }

  /** One request with a fresh Session JWT; no redirect followed. */
  async #requestOnce(
    method: string,
    url: string,
    options: SessionFetchRequestOptions,
  ): Promise<Response> {
    const supplied = { ...(options.headers ?? {}) };
    if (Object.keys(supplied).some((name) => hostOwned.has(name.toLowerCase()))) {
      throw new TransportError(
        "protected_header",
        "Authorization, DPoP and Poppy-Session headers are host-owned",
      );
    }
    const target = httpsUrl(url);
    const origin = budgetKey(target);
    const dpopNonce = options.token === undefined ? undefined : this.dpopNonces.get(origin);
    const signed = await sessionHeaders(this.#reactor, method, target.toString(), { ...options, dpopNonce });
    let response: Response;
    try {
      response = await this.#fetch(target, {
        method: method.toUpperCase(),
        headers: { ...supplied, ...signed },
        ...(options.body === undefined ? {} : { body: options.body }),
        credentials: "omit",
        redirect: "manual",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (cause) {
      throw new TransportError("request_failed", "PAP resource request failed", { cause });
    }
    // A redirect would carry the token and a Session JWT to another URL: refused (§3).
    await refuseRedirect(response);
    const given = response.headers.get(DPOP_NONCE_HEADER);
    if (given && options.token?.tokenType === "DPoP") this.dpopNonces.set(origin, given);
    return response;
  }
}
