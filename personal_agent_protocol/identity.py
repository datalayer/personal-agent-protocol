# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe retrieval of personal-agent client metadata and public keys."""

from __future__ import annotations

from datetime import datetime, timedelta
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .caching import CacheBounds, MetadataCache
from .errors import IdentityError, ProtocolValidationError
from .json import loads_strict
from .models import ClientMetadata, JsonWebKeySet
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
        data = await self._cached_json(
            f"pap.client-metadata:{requested}", requested, max_redirects=0, required_host=None
        )
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
        self._refetched[metadata.jwks_uri] = now
        await self._cache.delete(key)
        return self._key_set(await self._jwks(metadata, key))

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
        parsed = urlsplit(value)
        if parsed.fragment:
            raise IdentityError("invalid_client_id", "client_id must not contain a fragment")
        try:
            return str(httpx.URL(value))
        except (TypeError, ValueError) as exc:
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
            if content_type not in {"application/json", "application/jwk-set+json"}:
                raise IdentityError("invalid_content_type", "Agent identity response must be JSON")
            if len(response.content) > self._max_bytes:
                raise IdentityError(
                    "response_too_large", "Agent identity response exceeds size limit"
                )
            return loads_strict(response.content), response.url, response.headers

        raise AssertionError("redirect loop exited unexpectedly")
