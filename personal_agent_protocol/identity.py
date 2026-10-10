# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe retrieval of personal-agent client metadata and public keys."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import IdentityError, ProtocolValidationError
from .json import loads_strict
from .models import ClientMetadata, JsonWebKeySet
from .reactor import (
    DISCOVERY_TRANSPORTS,
    URL_SAFETY_POLICIES,
    AddressResolver,
    DiscoveryTransport,
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
    ) -> None:
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
        data = await self._get_json(requested, max_redirects=0, required_host=None)
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

    async def fetch_jwks(self, client_id: str) -> JsonWebKeySet:
        """Fetch a verified client's bounded, public-only signing key set."""

        metadata = await self.fetch_metadata(client_id)
        host = urlsplit(metadata.client_id).hostname
        data = await self._get_json(
            metadata.jwks_uri,
            max_redirects=self._max_jwks_redirects,
            required_host=host,
        )
        try:
            return JsonWebKeySet.model_validate(data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_jwks", "Personal-agent JWKS failed protocol validation"
            ) from exc

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
    ) -> object:
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
            await policy.assert_safe(current)
            response = await transport.get(current)
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
            return loads_strict(response.content)

        raise AssertionError("redirect loop exited unexpectedly")
