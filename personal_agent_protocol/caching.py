# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Bounded caching of public PAP metadata (PAP §3, §3.2; Guides, fetching metadata).

Discovery documents, OAuth metadata, client metadata, and JWKS are cached
according to their `Cache-Control`, within bounds the host sets: at least
`min_seconds` (a minute by default) and at most `max_seconds` (a day).
`no-store` and `no-cache` (or `max-age=0`) are never cached. A response without
`Cache-Control` is kept for `default_seconds`.

Entries go to the `pap.cache` contribution (`ProtocolCache`) as
`CachedMetadata`, whose `expires_at` the reader checks against the Reactor
clock, so any cache implementation (in-memory, Redis, ...) works unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import cast

from reactor import PluginPlatform  # type: ignore[import-untyped]

from .reactor import (
    CACHES,
    CLOCKS,
    Clock,
    InMemoryProtocolCache,
    ProtocolCache,
    SystemClock,
    optional_contribution,
)


@dataclass(frozen=True)
class CacheBounds:
    """How long metadata may be cached, whatever its `Cache-Control` says."""

    min_seconds: float = 60.0
    max_seconds: float = 86_400.0
    default_seconds: float = 60.0

    def __post_init__(self) -> None:
        if not 0 < self.min_seconds <= self.max_seconds:
            raise ValueError("cache bounds need 0 < min_seconds <= max_seconds")
        if not self.min_seconds <= self.default_seconds <= self.max_seconds:
            raise ValueError("default_seconds must lie within the cache bounds")


def cache_lifetime(headers: Mapping[str, str], bounds: CacheBounds) -> float | None:
    """Seconds to keep a response, or `None` when it must not be cached."""

    value = next((v for k, v in headers.items() if k.lower() == "cache-control"), None)
    if value is None:
        return bounds.default_seconds
    max_age: float | None = None
    for directive in value.split(","):
        name, _, argument = directive.strip().partition("=")
        name = name.strip().lower()
        if name in {"no-store", "no-cache"}:
            return None
        if name == "max-age":
            try:
                max_age = float(int(argument.strip().strip('"')))
            except ValueError:
                return None  # a malformed max-age is not a promise to cache
    if max_age is None:
        return bounds.default_seconds
    if max_age <= 0:
        return None
    return min(max(max_age, bounds.min_seconds), bounds.max_seconds)


@dataclass(frozen=True)
class CachedMetadata:
    """One cached metadata document: the parsed JSON, where it came from, until when."""

    value: object
    final_url: str
    expires_at: datetime


class MetadataCache:
    """Read and write cached metadata through a Reactor's `pap.cache` and clock."""

    def __init__(self, reactor: PluginPlatform, bounds: CacheBounds | None = None) -> None:
        self.reactor = reactor
        self.bounds = bounds or CacheBounds()

    def _cache(self) -> ProtocolCache | None:
        return cast(ProtocolCache | None, optional_contribution(self.reactor, CACHES, "cache"))

    def now(self) -> datetime:
        clock = cast(Clock | None, optional_contribution(self.reactor, CLOCKS, "clock"))
        return (clock or SystemClock()).now()

    async def get(self, key: str) -> CachedMetadata | None:
        cache = self._cache()
        if cache is None:
            return None
        entry = await cache.get(key)
        if not isinstance(entry, CachedMetadata):
            return None
        if entry.expires_at <= self.now():
            await cache.delete(key)
            return None
        return entry

    async def put(
        self, key: str, value: object, *, final_url: str, headers: Mapping[str, str]
    ) -> None:
        cache = self._cache()
        if cache is None:
            return
        lifetime = cache_lifetime(headers, self.bounds)
        if lifetime is None:
            await cache.delete(key)
            return
        expires_at = self.now() + timedelta(seconds=lifetime)
        await cache.put(
            key,
            CachedMetadata(value=value, final_url=final_url, expires_at=expires_at),
            expires_at=expires_at,
        )

    async def delete(self, key: str) -> None:
        cache = self._cache()
        if cache is not None:
            await cache.delete(key)


__all__ = [
    "CacheBounds",
    "CachedMetadata",
    "InMemoryProtocolCache",
    "MetadataCache",
    "cache_lifetime",
]
