# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe discovery for Personal Agent Protocol companies."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from pydantic import ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import DiscoveryError, ProtocolValidationError
from .json import loads_strict
from .models import DiscoveredCompany, DiscoveryDocument, OAuthServerMetadata
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


def _metadata_url(issuer: str) -> str:
    parsed = urlsplit(issuer)
    path = parsed.path.rstrip("/")
    metadata_path = "/.well-known/oauth-authorization-server" + path
    return urlunsplit((parsed.scheme, parsed.netloc, metadata_path, "", ""))


class DiscoveryClient:
    """Discover and authenticate a company's PAP declaration."""

    def __init__(
        self,
        *,
        reactor: PluginPlatform | None = None,
        http_client: httpx.AsyncClient | None = None,
        address_resolver: AddressResolver = resolve_addresses,
        allow_private_networks: bool = False,
        max_redirects: int = 3,
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
        self._max_redirects = max_redirects
        self._max_bytes = max_response_bytes

    async def __aenter__(self) -> DiscoveryClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owned_http is not None:
            await self._owned_http.aclose()

    async def discover(self, domain: str) -> DiscoveredCompany:
        requested_domain = self._normalize_domain(domain)
        discovery_url = f"https://{requested_domain}/.well-known/poppy.json"
        document_data, final_url = await self._get_json(discovery_url)
        try:
            document = DiscoveryDocument.model_validate(document_data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_discovery_document", "poppy.json failed protocol validation"
            ) from exc

        expected = requested_domain.removeprefix("www.")
        actual = document.organization.domain.removeprefix("www.")
        if actual != expected:
            raise DiscoveryError(
                "organization_domain_mismatch",
                "Discovery organization domain does not match the requested domain",
            )

        metadata: OAuthServerMetadata | None = None
        if document.auth:
            metadata_data, _ = await self._get_json(_metadata_url(document.auth.issuer))
            try:
                metadata = OAuthServerMetadata.model_validate(metadata_data)
            except ValidationError as exc:
                raise ProtocolValidationError(
                    "invalid_oauth_metadata", "OAuth server metadata failed validation"
                ) from exc
            if metadata.issuer != document.auth.issuer:
                raise DiscoveryError(
                    "issuer_mismatch", "OAuth metadata issuer does not match auth.issuer"
                )
            if document.organization.domain not in metadata.poppy_domains:
                raise DiscoveryError(
                    "domain_not_authorized",
                    "OAuth metadata does not authorize the discovered company domain",
                )

        return DiscoveredCompany(
            discovery_url=str(final_url),
            document=document,
            oauth_metadata=metadata,
        )

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        value = domain.rstrip(".").lower()
        if "://" in value or "/" in value or not value:
            raise DiscoveryError("invalid_domain", "Discovery requires a DNS domain name")
        return value

    async def _get_json(self, url: str) -> tuple[object, httpx.URL]:
        transport = first_contribution(self.reactor, DISCOVERY_TRANSPORTS, "discovery transport")
        policy = first_contribution(self.reactor, URL_SAFETY_POLICIES, "URL safety policy")
        if not isinstance(transport, DiscoveryTransport):
            raise TypeError("PAP discovery transport contribution has an invalid contract")
        if not isinstance(policy, UrlSafetyPolicy):
            raise TypeError("PAP URL safety policy contribution has an invalid contract")
        current = url
        for redirect_count in range(self._max_redirects + 1):
            await policy.assert_safe(current)
            response = await transport.get(current)

            if response.is_redirect:
                if redirect_count == self._max_redirects:
                    raise DiscoveryError("too_many_redirects", "Discovery exceeded redirect limit")
                location = response.headers.get("location")
                if not location:
                    raise DiscoveryError("invalid_redirect", "Discovery redirect has no location")
                current = urljoin(response.url, location)
                continue

            if response.status_code != 200:
                raise DiscoveryError(
                    "http_error",
                    "Discovery endpoint returned an unsuccessful status",
                    status_code=response.status_code,
                )
            content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
            if content_type not in {"application/json", "application/poppy+json"}:
                raise DiscoveryError("invalid_content_type", "Discovery response must be JSON")
            if len(response.content) > self._max_bytes:
                raise DiscoveryError("response_too_large", "Discovery response exceeds size limit")
            return loads_strict(response.content), httpx.URL(response.url)

        raise AssertionError("redirect loop exited unexpectedly")
