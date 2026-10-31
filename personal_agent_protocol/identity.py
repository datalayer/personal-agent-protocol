# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe retrieval of personal-agent client metadata and public keys."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .caching import CacheBounds, MetadataCache
from .crypto import jwk_thumbprint
from .errors import (
    DiscoveryError,
    IdentityError,
    PersonalAgentProtocolError,
    ProtocolValidationError,
)
from .json import loads_strict
from .models import ClientMetadata, JsonWebKeySet
from .operator_signatures import OPERATOR_DIRECTORY_MEDIA_TYPE
from .reactor import (
    DISCOVERY_TRANSPORTS,
    URL_SAFETY_POLICIES,
    AddressResolver,
    ApprovedUrl,
    DiscoveryTransport,
    MetadataFetch,
    UrlSafetyPolicy,
    build_pap_reactor,
    first_contribution,
    resolve_addresses,
)

#: The most entries a per-URL table keeps (refetch times, unfetchable client IDs).
_REMEMBERED = 1024
#: What a metadata document, a JWK Set or an operator's directory is served as.
_JSON_TYPES = frozenset(
    {"application/json", "application/jwk-set+json", OPERATOR_DIRECTORY_MEDIA_TYPE}
)
#: A directory with more keys is refused (Web Bot Auth §6.7).
MAX_OPERATOR_KEYS = 32


def _remember(table: dict[str, Any], key: str, value: Any, stale: datetime) -> None:
    """Set `table[key]`, keeping the table bounded: stale entries go first, then the oldest.

    An entry is stale once it no longer matters (a refetch older than the
    interval, a failure past its expiry): an attacker naming endless URLs
    cannot grow the table past `_REMEMBERED`.
    """

    table.pop(key, None)
    if len(table) >= _REMEMBERED:
        for name in [name for name, entry in table.items() if _when(entry) <= stale]:
            del table[name]
        while len(table) >= _REMEMBERED:
            del table[next(iter(table))]
    table[key] = value


def _when(entry: Any) -> datetime:
    return entry[0] if isinstance(entry, tuple) else entry


def _operator_keys(document: object) -> list[dict[str, Any]]:
    """The usable keys of a directory: public Ed25519, the rest ignored."""

    keys = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(keys, list) or len(keys) > MAX_OPERATOR_KEYS:
        raise ProtocolValidationError(
            "invalid_operator_directory", "An operator directory is a bounded JWK Set"
        )
    return [
        item
        for item in keys
        if isinstance(item, dict)
        and item.get("kty") == "OKP"
        and item.get("crv") == "Ed25519"
        and isinstance(item.get("x"), str)
        and "d" not in item
    ]


class AgentIdentityClient:
    """Fetch and verify a personal agent's public identity documents."""

    def __init__(
        self,
        *,
        reactor: PluginPlatform | None = None,
        http_client: httpx.AsyncClient | None = None,
        address_resolver: AddressResolver = resolve_addresses,
        allow_private_networks: bool = False,
        max_jwks_redirects: int = 3,
        max_response_bytes: int = 100 * 1024,
        timeout: float = 5.0,
        cache_bounds: CacheBounds | None = None,
        jwks_refetch_interval: float = 60.0,
        unfetchable_for: float = 30.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if reactor is None:
            reactor, owned_http = build_pap_reactor(
                http_client=http_client,
                address_resolver=address_resolver,
                allow_private_networks=allow_private_networks,
            )
        else:
            owned_http = None
        self.reactor = reactor
        self._owned_http = owned_http
        self._max_jwks_redirects = max_jwks_redirects
        self._max_bytes = max_response_bytes
        self._timeout = timeout
        self._cache = MetadataCache(reactor, cache_bounds)
        self._refetch_interval = timedelta(seconds=jwks_refetch_interval)
        self._refetched: dict[str, datetime] = {}
        #: A `client_id` whose metadata could not be fetched, and its error, for a while:
        #: a stream of assertions naming it does not fetch it each time.
        self._unfetchable_for = timedelta(seconds=unfetchable_for)
        self._unfetchable: dict[str, tuple[datetime, PersonalAgentProtocolError]] = {}

    async def __aenter__(self) -> AgentIdentityClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owned_http is not None:
            await self._owned_http.aclose()

    async def fetch_metadata(self, client_id: str) -> ClientMetadata:
        """Fetch client metadata without redirects and bind it to ``client_id``."""

        requested = self._fetchable_url(client_id)
        now = self._cache.now()
        remembered = self._unfetchable.get(requested)
        if remembered is not None and now < remembered[0]:
            raise type(remembered[1])(remembered[1].code, "Client metadata could not be fetched")
        try:
            data = await self._cached_json(
                f"pap.client-metadata:{requested}", requested, max_redirects=0, required_host=None
            )
        except (DiscoveryError, IdentityError) as error:
            _remember(self._unfetchable, requested, (now + self._unfetchable_for, error), now)
            raise
        try:
            metadata = ClientMetadata.model_validate(data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_client_metadata", "Client metadata failed protocol validation"
            ) from exc
        if metadata.client_id != requested:
            raise IdentityError(
                "client_id_mismatch",
                "Client metadata client_id does not match the URL that was fetched",
            )
        return metadata

    async def fetch_jwks(self, client_id: str, *, kid: str | None = None) -> JsonWebKeySet:
        """Fetch a verified client's bounded, public-only signing key set.

        The set is cached by its `Cache-Control`. When `kid` names a key the
        cached set lacks — the agent rotated its keys, publishing the new one
        beside the old — the set is fetched again, at most once per
        `jwks_refetch_interval` for each `jwks_uri`, so a stream of assertions
        with unknown `kid`s cannot trigger a fetch each time (Guides, rotating keys).
        """

        metadata = await self.fetch_metadata(client_id)
        key = f"pap.jwks:{metadata.jwks_uri}"
        keys = self._key_set(await self._jwks(metadata, key))
        if kid is None or any(item.kid == kid for item in keys.keys):
            return keys
        now = self._cache.now()
        last = self._refetched.get(metadata.jwks_uri)
        if last is not None and now - last < self._refetch_interval:
            return keys
        _remember(self._refetched, metadata.jwks_uri, now, now - self._refetch_interval)
        await self._cache.delete(key)
        return self._key_set(await self._jwks(metadata, key))

    async def fetch_operator_keys(self, url: str, *, keyid: str) -> list[dict[str, Any]]:
        """The Ed25519 keys published at a `Signature-Agent` URL (§5.3, Web Bot Auth §5.5).

        Never a redirect, and only a bounded JWK Set of public keys, as any URL a
        request names is fetched through `pap.urlSafetyPolicy`. A `keyid` the cached set
        lacks fetches it again, at most once per `jwks_refetch_interval`; a fetch that
        fails then keeps the cached set, as an outage says nothing of the keys. A URL
        that can't be read isn't fetched again for `unfetchable_for`.
        """

        requested = self._fetchable_url(url)
        key = f"pap.operator-keys:{requested}"
        now = self._cache.now()
        remembered = self._unfetchable.get(requested)
        if remembered is not None and now < remembered[0]:
            raise type(remembered[1])(remembered[1].code, "A directory could not be fetched")
        try:
            document = await self._cached_json(key, requested, max_redirects=0, required_host=None)
        except (DiscoveryError, IdentityError) as error:
            _remember(self._unfetchable, requested, (now + self._unfetchable_for, error), now)
            raise
        keys = _operator_keys(document)
        if any(jwk_thumbprint(item) == keyid for item in keys):
            return keys
        last = self._refetched.get(requested)
        if last is not None and now - last < self._refetch_interval:
            return keys
        _remember(self._refetched, requested, now, now - self._refetch_interval)
        value, final_url, headers = await self._get_json(
            requested, max_redirects=0, required_host=None
        )
        keys = _operator_keys(value)
        await self._cache.put(key, value, final_url=final_url, headers=headers)
        return keys

    async def _jwks(self, metadata: ClientMetadata, key: str) -> object:
        return await self._cached_json(
            key,
            metadata.jwks_uri,
            max_redirects=self._max_jwks_redirects,
            required_host=urlsplit(metadata.client_id).hostname,
        )

    @staticmethod
    def _key_set(data: object) -> JsonWebKeySet:
        try:
            return JsonWebKeySet.model_validate(data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_jwks", "Personal-agent JWKS failed protocol validation"
            ) from exc

    async def _cached_json(
        self, key: str, url: str, *, max_redirects: int, required_host: str | None
    ) -> object:
        cached = await self._cache.get(key)
        if cached is not None:
            return cached.value
        value, final_url, headers = await self._get_json(
            url, max_redirects=max_redirects, required_host=required_host
        )
        await self._cache.put(key, value, final_url=final_url, headers=headers)
        return value

    @staticmethod
    def _fetchable_url(value: str) -> str:
        try:
            if urlsplit(value).fragment:
                raise IdentityError("invalid_client_id", "client_id must not contain a fragment")
            return str(httpx.URL(value))
        except (TypeError, ValueError, httpx.InvalidURL) as exc:
            raise IdentityError("invalid_client_id", "client_id must be a valid HTTPS URL") from exc

    async def _get_json(  # noqa: C901 - explicit trust-boundary branches
        self,
        url: str,
        *,
        max_redirects: int,
        required_host: str | None,
    ) -> tuple[object, str, dict[str, str]]:
        transport = first_contribution(self.reactor, DISCOVERY_TRANSPORTS, "metadata transport")
        policy = first_contribution(self.reactor, URL_SAFETY_POLICIES, "URL safety policy")
        if not isinstance(transport, DiscoveryTransport):
            raise TypeError("PAP metadata transport contribution has an invalid contract")
        if not isinstance(policy, UrlSafetyPolicy):
            raise TypeError("PAP URL safety policy contribution has an invalid contract")

        current = url
        for redirect_count in range(max_redirects + 1):
            if required_host is not None and urlsplit(current).hostname != required_host:
                raise IdentityError("jwks_domain_mismatch", "JWKS redirect changed agent domain")
            approved = await policy.assert_safe(current)
            if not isinstance(approved, ApprovedUrl) or approved.url != current:
                raise TypeError("PAP URL safety policy must return the ApprovedUrl it checked")
            response = await transport.get(
                current,
                fetch=MetadataFetch(
                    approved=approved, max_bytes=self._max_bytes, timeout=self._timeout
                ),
            )
            if response.is_redirect:
                if redirect_count == max_redirects:
                    code = "metadata_redirect" if max_redirects == 0 else "too_many_redirects"
                    raise IdentityError(code, "Agent identity endpoint exceeded redirect policy")
                location = response.headers.get("location")
                if not location:
                    raise IdentityError(
                        "invalid_redirect", "Agent identity redirect has no location"
                    )
                current = urljoin(response.url, location)
                continue
            if response.status_code != 200:
                raise IdentityError(
                    "http_error",
                    "Agent identity endpoint returned an unsuccessful status",
                    status_code=response.status_code,
                )
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
            if content_type not in _JSON_TYPES:
                raise IdentityError("invalid_content_type", "Agent identity response must be JSON")
            if len(response.content) > self._max_bytes:
                raise IdentityError(
                    "response_too_large", "Agent identity response exceeds size limit"
                )
            return loads_strict(response.content), response.url, response.headers

        raise AssertionError("redirect loop exited unexpectedly")
