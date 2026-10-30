# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe discovery for Personal Agent Protocol companies."""

from __future__ import annotations

from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from pydantic import ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .caching import CacheBounds, MetadataCache
from .errors import DiscoveryError, ProtocolValidationError
from .json import loads_strict
from .models import (
    SUPPORTED_PROTOCOL_VERSIONS,
    DiscoveredCompany,
    DiscoveryDocument,
    ExcludedTasks,
    OAuthServerMetadata,
    ProtectedResourceMetadata,
    protected_resource_metadata_url,
)
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
from .telemetry import by_domain, company_result, traced


def _metadata_url(issuer: str) -> str:
    """The issuer's RFC 8414 §3.1 metadata URL: the well-known path between host and path.

    `https://auth.provider.example/shop-a` has its metadata at
    `https://auth.provider.example/.well-known/oauth-authorization-server/shop-a` (§3.2).
    """

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
        timeout: float = 5.0,
        cache_bounds: CacheBounds | None = None,
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
        self._max_redirects = max_redirects
        self._max_bytes = max_response_bytes
        self._timeout = timeout
        self._cache = MetadataCache(reactor, cache_bounds)

    async def __aenter__(self) -> DiscoveryClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._owned_http is not None:
            await self._owned_http.aclose()

    @traced("pap.discovery.discover", before=by_domain, after=company_result)
    async def discover(self, domain: str) -> DiscoveredCompany:
        requested_domain = self._normalize_domain(domain)
        discovery_url = f"https://{requested_domain}/.well-known/poppy.json"
        document_data, final_url = await self._get_json(discovery_url)
        # A redirect may change host, but only a document at the well-known path itself,
        # with no query, speaks for a domain: not an upload elsewhere on it (§3, §9.3).
        if final_url.path != "/.well-known/poppy.json" or final_url.query:
            raise DiscoveryError(
                "invalid_discovery_location",
                "Discovery redirects must end at /.well-known/poppy.json with no query",
            )
        version = document_data.get("protocol_version") if isinstance(document_data, dict) else None
        if isinstance(version, str) and version not in SUPPORTED_PROTOCOL_VERSIONS:
            # Before 1.0 each version can break the last: only a supported major.minor (§3.1).
            raise DiscoveryError(
                "unsupported_protocol_version",
                "poppy.json follows a protocol version this personal agent does not support",
            )
        try:
            document = DiscoveryDocument.model_validate(document_data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_discovery_document", "poppy.json failed protocol validation"
            ) from exc

        # The document speaks for the host that served it, after redirects, compared
        # ignoring case and nothing else (§3, §3.1).
        served_by = (final_url.host or "").lower().rstrip(".")
        if document.organization.domain != served_by:
            raise DiscoveryError(
                "organization_domain_mismatch",
                "Discovery organization domain is not the host that served the document",
            )

        resource_metadata = await self._domain_resource_metadata(document)
        metadata: OAuthServerMetadata | None = None
        if resource_metadata is None or not resource_metadata.authorization_servers:
            # The only way to no issuer: 404, or metadata that lists none (§3.2).
            if document.needs_issuer:
                raise DiscoveryError(
                    "issuer_not_found",
                    "The company offers sign-in and its domain names no issuer",
                )
        else:
            issuer = self._issuer(document, resource_metadata)
            metadata_data, _ = await self._get_json(_metadata_url(issuer))
            try:
                metadata = OAuthServerMetadata.model_validate(metadata_data)
            except ValidationError as exc:
                raise ProtocolValidationError(
                    "invalid_oauth_metadata", "OAuth server metadata failed validation"
                ) from exc
            # Character for character: no case folding, no trailing-slash trimming (§3.2).
            if metadata.issuer != issuer:
                raise DiscoveryError(
                    "issuer_mismatch", "OAuth metadata issuer is not the issuer found"
                )
            # `https://{domain}` exactly, the host ignoring case (§3.2, RFC 9728 §3.3).
            if not metadata.lists_resource(document.organization.domain):
                raise DiscoveryError(
                    "domain_not_authorized",
                    "OAuth metadata does not authorize the discovered company domain",
                )

        return DiscoveredCompany(
            discovery_url=str(final_url),
            document=document,
            oauth_metadata=metadata,
            resource_metadata=resource_metadata,
        )

    async def _domain_resource_metadata(
        self, document: DiscoveryDocument
    ) -> ProtectedResourceMetadata | None:
        """The domain's protected resource metadata, which names its issuer (§3.2).

        Its `resource` is exactly `https://{organization.domain}`. `None` for a 404, which
        says the Company has no issuer; any other failure is raised, and never read so.
        """

        resource = f"https://{document.organization.domain}"
        try:
            data, _ = await self._get_json(protected_resource_metadata_url(resource))
        except DiscoveryError as exc:
            if exc.code == "http_error" and exc.status_code == 404:
                return None
            raise
        try:
            metadata = ProtectedResourceMetadata.model_validate(data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_resource_metadata", "Protected resource metadata failed validation"
            ) from exc
        if metadata.resource != resource:
            raise DiscoveryError(
                "resource_mismatch",
                "The domain's protected resource metadata names another resource",
            )
        return metadata

    @staticmethod
    def _issuer(document: DiscoveryDocument, metadata: ProtectedResourceMetadata) -> str:
        """The issuer the domain names (§3.1, §3.2).

        One authorization server is the issuer, and `auth.issuer`, if present, names
        it; with several, `auth.issuer` is required and must be one of them.
        """

        servers = metadata.authorization_servers
        named = document.auth.issuer if document.auth is not None else None
        if len(servers) == 1:
            if named is not None and named != servers[0]:
                raise DiscoveryError(
                    "issuer_mismatch", "auth.issuer is not the domain's authorization server"
                )
            return servers[0]
        if named is None:
            raise DiscoveryError(
                "issuer_not_named",
                "The domain lists several authorization servers and auth.issuer names none",
            )
        if named not in servers:
            raise DiscoveryError(
                "issuer_mismatch", "auth.issuer is not one of the domain's authorization servers"
            )
        return named

    async def resource_metadata(
        self, url: str, *, fresh: bool = False
    ) -> ProtectedResourceMetadata | None:
        """The protected resource metadata of the service at `url` (RFC 9728 §3.1), if any.

        `None` when the service publishes none (404). Cached as its headers allow;
        `fresh` reads it again, after a service said the agent's view is stale (§4.5).
        """

        metadata_url = protected_resource_metadata_url(url)
        if fresh:
            await self._cache.delete(f"pap.metadata:{metadata_url}")
        try:
            data, _ = await self._get_json(metadata_url)
        except DiscoveryError as exc:
            if exc.code == "http_error" and exc.status_code == 404:
                return None
            raise
        try:
            return ProtectedResourceMetadata.model_validate(data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_resource_metadata", "Protected resource metadata failed validation"
            ) from exc

    async def service_resource(
        self, company: DiscoveredCompany, url: str, *, fresh: bool = False
    ) -> str | None:
        """The `resource` to request a token for before calling `url`, or `None` (§4.5).

        A service whose protected resource metadata names a `resource` other than
        `https://{organization.domain}` accepts only tokens issued for it, and its
        `authorization_servers` include the Company's issuer. Without metadata, or
        with the domain's own, the default token works there.
        """

        metadata = await self.service_metadata(company, url, fresh=fresh)
        return None if metadata is None else metadata.resource

    async def service_metadata(
        self, company: DiscoveredCompany, url: str, *, fresh: bool = False
    ) -> ProtectedResourceMetadata | None:
        """The metadata of a service that accepts only tokens issued for it, or `None` (§4.5)."""

        metadata = await self.resource_metadata(url, fresh=fresh)
        if metadata is None or metadata.resource == company.resource:
            return None
        if company.issuer is None or company.issuer not in metadata.authorization_servers:
            raise DiscoveryError(
                "invalid_resource_metadata",
                "The service's protected resource metadata names another authorization server",
            )
        return metadata

    async def excluded_tasks(self, company: DiscoveredCompany) -> ExcludedTasks | None:
        """The tasks the company chose not to offer through the protocol (§8.1).

        A public document: a GET with no token, cached as its headers allow. `None`
        when the company lists none. Read it before starting on a task there; whether
        a user's task is one of them is the agent's judgment.
        """

        descriptor = company.document.excluded_tasks
        if descriptor is None:
            return None
        data, _ = await self._get_json(descriptor.url)
        try:
            return ExcludedTasks.model_validate(data)
        except ValidationError as exc:
            raise ProtocolValidationError(
                "invalid_excluded_tasks", "The excluded tasks document failed validation"
            ) from exc

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        value = domain.rstrip(".").lower()
        if "://" in value or "/" in value or not value:
            raise DiscoveryError("invalid_domain", "Discovery requires a DNS domain name")
        return value

    async def _get_json(self, url: str) -> tuple[object, httpx.URL]:
        """The document at `url`, from `pap.cache` while its `Cache-Control` allows (§3, §3.2)."""

        key = f"pap.metadata:{url}"
        cached = await self._cache.get(key)
        if cached is not None:
            return cached.value, httpx.URL(cached.final_url)
        value, final_url, headers = await self._fetch_json(url)
        await self._cache.put(key, value, final_url=str(final_url), headers=headers)
        return value, final_url

    async def _fetch_json(  # noqa: C901 - explicit trust-boundary branches
        self, url: str
    ) -> tuple[object, httpx.URL, dict[str, str]]:
        transport = first_contribution(self.reactor, DISCOVERY_TRANSPORTS, "discovery transport")
        policy = first_contribution(self.reactor, URL_SAFETY_POLICIES, "URL safety policy")
        if not isinstance(transport, DiscoveryTransport):
            raise TypeError("PAP discovery transport contribution has an invalid contract")
        if not isinstance(policy, UrlSafetyPolicy):
            raise TypeError("PAP URL safety policy contribution has an invalid contract")
        current = url
        for redirect_count in range(self._max_redirects + 1):
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
            return loads_strict(response.content), httpx.URL(response.url), response.headers

        raise AssertionError("redirect loop exited unexpectedly")
