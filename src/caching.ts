// Bounded caching of public PAP metadata (PAP §3, §3.2; Guides, fetching metadata).
//
// Discovery documents, OAuth metadata, client metadata, and JWKS are cached by
// their `Cache-Control` within the host's bounds (a minute to a day by default);
// `no-store` and `no-cache` are never cached. Entries go to the `pap.cache`
// contribution with an absolute expiry the reader checks against `pap.clock`.
import type { ReactorPlatformView } from "@datalayer/reactor";

import {
  DEFAULT_CACHE_BOUNDS,
  cacheLifetime,
  checkCacheBounds,
  isCachedMetadata,
  type CacheBounds,
  type CachedMetadata,
} from "./limits.js";
import { Caches, Clocks, optionalContribution } from "./reactor.js";

export class MetadataCache {
  readonly #reactor: ReactorPlatformView;
  readonly bounds: CacheBounds;

  constructor(reactor: ReactorPlatformView, bounds: CacheBounds = DEFAULT_CACHE_BOUNDS) {
    this.#reactor = reactor;
    this.bounds = checkCacheBounds(bounds);
  }

  now(): Date {
    return (optionalContribution(this.#reactor, Clocks, "clock") ?? { now: () => new Date() }).now();
  }

  async get(key: string): Promise<CachedMetadata | undefined> {
    const cache = optionalContribution(this.#reactor, Caches, "cache");
    if (cache === undefined) return undefined;
    const entry = await cache.get(key);
    if (!isCachedMetadata(entry)) return undefined;
    if (entry.expiresAt.getTime() <= this.now().getTime()) {
      await cache.delete(key);
      return undefined;
    }
    return entry;
  }

  async put(key: string, value: unknown, finalUrl: string, headers: Headers): Promise<void> {
    const cache = optionalContribution(this.#reactor, Caches, "cache");
    if (cache === undefined) return;
    const lifetime = cacheLifetime(headers.get("cache-control"), this.bounds);
    if (lifetime === undefined) {
      await cache.delete(key);
      return;
    }
    const expiresAt = new Date(this.now().getTime() + lifetime * 1000);
    const entry: CachedMetadata = { kind: "pap.cachedMetadata", value, finalUrl, expiresAt };
    await cache.put(key, entry, { expiresAt });
  }

  async delete(key: string): Promise<void> {
    await optionalContribution(this.#reactor, Caches, "cache")?.delete(key);
  }
}
