// Guide-level limits shared by both roles: bounded metadata caching, retries,
// and shared rate-limit budgets (PAP Guides). Portable: no Node APIs.

import { DiscoveryError, TransportError } from "./errors.js";

/** How long metadata may be cached, whatever its `Cache-Control` says. */
export interface CacheBounds {
  readonly minSeconds: number;
  readonly maxSeconds: number;
  readonly defaultSeconds: number;
}

/** At least a minute, at most a day (the Guides' example bounds). */
export const DEFAULT_CACHE_BOUNDS: CacheBounds = Object.freeze({
  minSeconds: 60,
  maxSeconds: 86_400,
  defaultSeconds: 60,
});

export function checkCacheBounds(bounds: CacheBounds): CacheBounds {
  if (!(bounds.minSeconds > 0 && bounds.minSeconds <= bounds.maxSeconds)) {
    throw new RangeError("cache bounds need 0 < minSeconds <= maxSeconds");
  }
  if (bounds.defaultSeconds < bounds.minSeconds || bounds.defaultSeconds > bounds.maxSeconds) {
    throw new RangeError("defaultSeconds must lie within the cache bounds");
  }
  return bounds;
}

/** Seconds to keep a response by its `Cache-Control`, or `undefined` when it must not be cached. */
export function cacheLifetime(
  cacheControl: string | null | undefined,
  bounds: CacheBounds = DEFAULT_CACHE_BOUNDS,
): number | undefined {
  if (cacheControl === null || cacheControl === undefined) return bounds.defaultSeconds;
  let maxAge: number | undefined;
  for (const directive of cacheControl.split(",")) {
    const [rawName, ...rest] = directive.trim().split("=");
    const name = (rawName ?? "").trim().toLowerCase();
    if (name === "no-store" || name === "no-cache") return undefined;
    if (name === "max-age") {
      const argument = rest.join("=").trim().replace(/^"|"$/g, "");
      if (!/^\d+$/.test(argument)) return undefined;
      maxAge = Number(argument);
    }
  }
  if (maxAge === undefined) return bounds.defaultSeconds;
  if (maxAge <= 0) return undefined;
  return Math.min(Math.max(maxAge, bounds.minSeconds), bounds.maxSeconds);
}

/** One cached metadata document: the parsed JSON, where it came from, until when. */
export interface CachedMetadata {
  readonly kind: "pap.cachedMetadata";
  readonly value: unknown;
  readonly finalUrl: string;
  readonly expiresAt: Date;
}

export function isCachedMetadata(value: unknown): value is CachedMetadata {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { kind?: unknown }).kind === "pap.cachedMetadata" &&
    (value as { expiresAt?: unknown }).expiresAt instanceof Date
  );
}

/** Default `pap.cache`: a bounded, least-recently-used map in one process. */
export class InMemoryProtocolCache {
  readonly #entries = new Map<string, unknown>();
  readonly #maxEntries: number;

  constructor(maxEntries = 1024) {
    if (!Number.isInteger(maxEntries) || maxEntries <= 0) {
      throw new RangeError("maxEntries must be a positive integer");
    }
    this.#maxEntries = maxEntries;
  }

  async put(key: string, value: unknown, _options: { readonly expiresAt: Date }): Promise<void> {
    this.#entries.delete(key);
    this.#entries.set(key, value);
    while (this.#entries.size > this.#maxEntries) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
  }

  async get(key: string): Promise<unknown | undefined> {
    if (!this.#entries.has(key)) return undefined;
    const value = this.#entries.get(key);
    this.#entries.delete(key);
    this.#entries.set(key, value);
    return value;
  }

  async delete(key: string): Promise<void> {
    this.#entries.delete(key);
  }
}

/**
 * When to retry a refused request (Guides, retries).
 *
 * After `attempts` tries, `delay` is how long to wait before the next one, or
 * `undefined` to stop and report: a `Retry-After` is always honoured (never
 * retried sooner), but one longer than `maxRetryAfter` is reported instead of
 * waited for; otherwise the delay backs off exponentially from `baseDelay`,
 * with jitter, capped at `maxDelay`. At most `maxAttempts` tries in all.
 */
export class RetryPolicy {
  readonly maxAttempts: number;
  readonly baseDelay: number;
  readonly maxDelay: number;
  readonly maxRetryAfter: number;

  constructor(
    options: {
      readonly maxAttempts?: number;
      readonly baseDelay?: number;
      readonly maxDelay?: number;
      readonly maxRetryAfter?: number;
    } = {},
  ) {
    this.maxAttempts = options.maxAttempts ?? 3;
    this.baseDelay = options.baseDelay ?? 0.5;
    this.maxDelay = options.maxDelay ?? 30;
    this.maxRetryAfter = options.maxRetryAfter ?? 10;
    if (!Number.isInteger(this.maxAttempts) || this.maxAttempts < 1) {
      throw new RangeError("maxAttempts must be at least 1");
    }
    if (!(this.baseDelay > 0 && this.baseDelay <= this.maxDelay)) {
      throw new RangeError("retry delays need 0 < baseDelay <= maxDelay");
    }
    if (this.maxRetryAfter < 0) throw new RangeError("maxRetryAfter must not be negative");
  }

  /** Seconds to wait after `attempts` tries; `jitter` is uniform in [0, 1). */
  delay(attempts: number, retryAfter: number | undefined, jitter: number): number | undefined {
    if (attempts >= this.maxAttempts) return undefined;
    const backoff = Math.min(this.maxDelay, this.baseDelay * 2 ** (attempts - 1));
    if (retryAfter === undefined) return backoff / 2 + (jitter * backoff) / 2;
    if (retryAfter > this.maxRetryAfter) return undefined;
    return retryAfter + jitter * Math.min(backoff, this.baseDelay);
  }
}

/** `Retry-After` in seconds (delta-seconds or an HTTP date), or `undefined`. */
export function parseRetryAfter(value: string | null | undefined, now: Date): number | undefined {
  if (value === null || value === undefined) return undefined;
  const text = value.trim();
  if (/^\d+$/.test(text)) return Number(text);
  if (!/[a-z]/i.test(text)) return undefined;
  const when = Date.parse(text);
  if (Number.isNaN(when)) return undefined;
  return Math.max(0, (when - now.getTime()) / 1000);
}

/**
 * A company's request budget, shared by every task and user of the host.
 *
 * `acquire` waits for the company's budget (or rejects with `rate_limited`
 * when the wait would be too long); `defer` records that the company asked for
 * a pause (`Retry-After`), so every task waits, not only the refused one.
 */
export interface RateLimitBudget {
  acquire(key: string): Promise<void>;
  defer(key: string, seconds: number): Promise<void>;
}

interface Bucket {
  /** When the next request may go if the burst is spent (GCRA's theoretical arrival time). */
  due: number;
  blockedUntil: number;
}

/**
 * Default `pap.rateLimitBudget`: per-company budgets in one process.
 * No rate limit unless `rate` is set: only the companies' own pauses are shared.
 *
 * Each caller reserves its turn when it asks — the turn counts every caller ahead of it
 * and the company's pause (`defer`) — and sleeps until then, so concurrent callers never
 * exceed the rate, and a turn further than `maxWait` seconds away is refused at once with
 * `rate_limited` and `retry_after`, however many callers are queued (the generic cell
 * rate algorithm).
 */
export class SharedRateLimitBudget implements RateLimitBudget {
  readonly rate: number | undefined;
  readonly burst: number;
  readonly maxWait: number;
  readonly #sleep: (seconds: number) => Promise<void>;
  readonly #monotonic: () => number;
  readonly #buckets = new Map<string, Bucket>();

  constructor(
    options: {
      readonly rate?: number;
      readonly burst?: number;
      readonly maxWait?: number;
      readonly sleep?: (seconds: number) => Promise<void>;
      readonly monotonic?: () => number;
    } = {},
  ) {
    if (options.rate !== undefined && !(options.rate > 0)) {
      throw new RangeError("rate must be positive");
    }
    this.rate = options.rate;
    this.burst = options.burst ?? 1;
    if (!Number.isInteger(this.burst) || this.burst < 1) throw new RangeError("burst must be at least 1");
    this.maxWait = options.maxWait ?? 10;
    // Rounded up to whole milliseconds (timers truncate): never sooner than the turn.
    this.#sleep = options.sleep ?? ((seconds) => new Promise((resolve) => setTimeout(resolve, Math.ceil(seconds * 1000))));
    this.#monotonic = options.monotonic ?? (() => performance.now() / 1000);
  }

  #bucket(key: string, now: number): Bucket {
    let bucket = this.#buckets.get(key);
    if (bucket === undefined) {
      bucket = { due: now, blockedUntil: 0 };
      this.#buckets.set(key, bucket);
    }
    return bucket;
  }

  async acquire(key: string): Promise<void> {
    // Reserved without awaiting anything: callers take their turns in arrival order.
    const now = this.#monotonic();
    const bucket = this.#bucket(key, now);
    let turn = Math.max(now, bucket.blockedUntil);
    const due = Math.max(bucket.due, turn);
    const interval = this.rate === undefined ? 0 : 1 / this.rate;
    if (this.rate !== undefined) turn = Math.max(turn, due - (this.burst - 1) * interval);
    const wait = turn - now;
    if (wait > this.maxWait) {
      throw new TransportError("rate_limited", "The company's shared request budget is exhausted", {
        details: { retry_after: String(Math.ceil(wait)) },
      });
    }
    if (this.rate !== undefined) bucket.due = due + interval;
    // A timer may fire early (Node's loop clock lags a busy iteration): sleep the rest.
    for (let left = wait; left > 0; left = turn - this.#monotonic()) await this.#sleep(left);
  }

  async defer(key: string, seconds: number): Promise<void> {
    const now = this.#monotonic();
    const bucket = this.#bucket(key, now);
    bucket.blockedUntil = Math.max(bucket.blockedUntil, now + Math.max(0, seconds));
  }
}

/** The shared rate-limit budget a request draws on: its company's origin. */
export function budgetKey(url: URL | string): string {
  const parsed = new URL(url);
  const port = parsed.port || (parsed.protocol === "https:" ? "443" : "80");
  return `${parsed.protocol}//${parsed.hostname.toLowerCase()}:${port}`;
}

/**
 * Read a metadata body: at most `maxBytes`, and within `timeoutMs` in all, however
 * slowly the server sends (each read races the deadline).
 */
export async function readBoundedBody(
  response: Response,
  options: {
    readonly maxBytes: number;
    readonly timeoutMs: number;
    readonly startedAt: number;
    readonly tooLarge: () => Error;
  },
): Promise<string> {
  const declared = response.headers.get("content-length");
  if (declared !== null && /^\d+$/.test(declared) && Number(declared) > options.maxBytes) {
    throw options.tooLarge();
  }
  const reader = response.body?.getReader();
  if (reader === undefined) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const remaining = Math.max(0, options.timeoutMs - (Date.now() - options.startedAt));
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new DiscoveryError("metadata_timeout", "Metadata fetch exceeded its time limit")),
      remaining,
    );
  });
  try {
    while (true) {
      const { done, value } = await Promise.race([reader.read(), deadline]);
      if (done) break;
      total += value.byteLength;
      if (total > options.maxBytes) throw options.tooLarge();
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(body);
}

/** Race `promise` against the time left of a `timeoutMs` budget started at `startedAt`. */
export async function withinDeadline<T>(
  promise: Promise<T>,
  options: { readonly timeoutMs: number; readonly startedAt: number },
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const remaining = Math.max(0, options.timeoutMs - (Date.now() - options.startedAt));
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new DiscoveryError("metadata_timeout", "Metadata fetch exceeded its time limit")),
          remaining,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
