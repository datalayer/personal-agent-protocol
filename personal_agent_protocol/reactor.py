# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Reactor contribution points and the default PAP infrastructure plugin."""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import secrets
import socket
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpcore
import httpx
from pydantic import SecretStr
from reactor import (  # type: ignore[import-untyped]
    PluginManifest,
    PluginPlatform,
    define_contribution_point,
    hookimpl,
)

from .errors import DiscoveryError

AddressResolver = Callable[[str], Awaitable[list[str]]]


@dataclass(frozen=True)
class DiscoveryResponse:
    """Transport-neutral response used by safe PAP discovery."""

    url: str
    status_code: int
    headers: dict[str, str]
    content: bytes

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400


@dataclass(frozen=True)
class ApprovedUrl:
    """A URL the safety policy approved, and the addresses it approved for its host.

    The transport connects only to these addresses: it never resolves the host
    again, so DNS cannot rebind it between the check and the connection.
    """

    url: str
    host: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class MetadataFetch:
    """The bounds of one public metadata fetch: size, total time, approved addresses."""

    approved: ApprovedUrl
    max_bytes: int
    timeout: float


@dataclass(frozen=True)
class ProtocolProfile:
    """Version-specific PAP behavior selected through Reactor."""

    version: str


@runtime_checkable
class Clock(Protocol):
    """Supply timezone-aware wall-clock time to expiring protocol state."""

    def now(self) -> datetime: ...


@runtime_checkable
class RandomSource(Protocol):
    """Supply cryptographically secure random bytes."""

    def bytes(self, length: int) -> bytes: ...


@runtime_checkable
class Signer(Protocol):
    """Sign a compact assertion without exposing private key material."""

    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr: ...


@dataclass(frozen=True)
class KeyReference:
    """Opaque reference to a protected signing or proof-of-possession key."""

    id: str
    algorithm: str


@runtime_checkable
class KeyStore(Protocol):
    """Resolve protected keys by tenant and protocol purpose."""

    async def get_or_create(
        self, *, tenant_id: str, subject: str, purpose: str
    ) -> KeyReference: ...


@runtime_checkable
class TokenStore(Protocol):
    """Keep credentials behind opaque references and explicit deletion."""

    async def put(self, reference: str, token: SecretStr) -> None: ...

    async def get(self, reference: str) -> SecretStr | None: ...

    async def delete(self, reference: str) -> None: ...


@runtime_checkable
class PairwiseUserIdStore(Protocol):
    """Persist stable random identities by tenant, local user, and issuer."""

    async def get_or_create(
        self,
        *,
        tenant_id: str,
        local_user_id: str,
        company_issuer: str,
    ) -> str: ...


@runtime_checkable
class AuthorizationStateStore(Protocol):
    """Persist and atomically consume short-lived authorization state."""

    async def put(self, reference: str, value: object, *, expires_at: datetime) -> None: ...

    async def take(self, reference: str) -> object | None: ...


@runtime_checkable
class ProtocolCache(Protocol):
    """Bound cached public protocol data by an absolute expiry."""

    async def put(self, key: str, value: object, *, expires_at: datetime) -> None: ...

    async def get(self, key: str) -> object | None: ...

    async def delete(self, key: str) -> None: ...


@runtime_checkable
class BrowserHandoff(Protocol):
    """Hand a human-only authorization URL to a trusted browser surface."""

    async def open(self, authorization_url: SecretStr) -> None: ...


@runtime_checkable
class BrowserFormPost(Protocol):
    """Submit protected fields as a controlled top-level browser navigation."""

    async def post(self, endpoint: str, fields: dict[str, SecretStr]) -> None: ...


@dataclass(frozen=True)
class DpopProofRequest:
    """Inputs for one fresh proof-of-possession JWT."""

    method: str
    url: str
    tenant_id: str
    subject: str
    issuer: str
    access_token: SecretStr | None = None
    nonce: str | None = None


@runtime_checkable
class DpopProofProvider(Protocol):
    """Create a fresh DPoP proof while keeping its private key protected."""

    async def create(self, request: DpopProofRequest) -> SecretStr: ...


@runtime_checkable
class AccountTokenLock(Protocol):
    """Serialize every use of one Account Token (PAP §4.8 rotation).

    A rotated Account Token invalidates the one it replaces, so two refreshes
    racing on the same reference would leave one of them holding a revoked
    credential. A multi-process host contributes a distributed lock here.
    """

    def hold(self, reference: str) -> AbstractAsyncContextManager[None]: ...


class InProcessAccountTokenLock:
    """Default Account Token lock for a single process."""

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def hold(self, reference: str) -> AsyncIterator[None]:
        lock = self._locks.setdefault(reference, asyncio.Lock())
        async with lock:
            yield


@dataclass(frozen=True)
class ProtectedInputField:
    """One field a human types into the host's own trusted surface."""

    name: str
    label: str
    secret: bool


@dataclass(frozen=True)
class ProtectedInputRequest:
    """What the host must ask the user for, and for which company.

    `purpose` is `credentials` (Mediated Sign-In's declared fields) or
    `one_time_code` (its `code_required` continuation, `sent_to` saying where
    the company sent it). The answers never pass through a model.
    """

    purpose: Literal["credentials", "one_time_code"]
    company_name: str
    company_domain: str
    fields: tuple[ProtectedInputField, ...]
    sent_to: str | None = None


@runtime_checkable
class ProtectedInput(Protocol):
    """Collect protected values from the user outside model context (PAP §4.7)."""

    async def collect(self, request: ProtectedInputRequest) -> dict[str, SecretStr]: ...


class SystemClock:
    """Default UTC wall clock."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class SystemRandomSource:
    """Default operating-system cryptographic randomness."""

    def bytes(self, length: int) -> bytes:
        if length <= 0:
            raise ValueError("random byte length must be positive")
        return secrets.token_bytes(length)


@runtime_checkable
class DiscoveryTransport(Protocol):
    """Fetch public metadata without credentials, within `fetch`'s bounds.

    The transport connects only to `fetch.approved.addresses`, stops reading
    past `fetch.max_bytes` (`response_too_large`), and gives up after
    `fetch.timeout` seconds in all (`metadata_timeout`), however slowly the
    server sends.
    """

    async def get(self, url: str, *, fetch: MetadataFetch) -> DiscoveryResponse: ...


@runtime_checkable
class UrlSafetyPolicy(Protocol):
    """Resolve and approve a metadata URL before the transport connects to it."""

    async def assert_safe(self, url: str) -> ApprovedUrl: ...


DISCOVERY_TRANSPORTS = define_contribution_point("pap.discoveryTransport")
URL_SAFETY_POLICIES = define_contribution_point("pap.urlSafetyPolicy")
PROTOCOL_PROFILES = define_contribution_point("pap.protocolProfile")
EXTENSION_HANDLERS = define_contribution_point("pap.extensionHandler")
CLOCKS = define_contribution_point("pap.clock")
RANDOM_SOURCES = define_contribution_point("pap.randomSource")
SIGNERS = define_contribution_point("pap.signer")
KEY_STORES = define_contribution_point("pap.keyStore")
TOKEN_STORES = define_contribution_point("pap.tokenStore")
PAIRWISE_USER_ID_STORES = define_contribution_point("pap.pairwiseUserIdStore")
AUTHORIZATION_STATE_STORES = define_contribution_point("pap.authorizationStateStore")
CACHES = define_contribution_point("pap.cache")
BROWSER_HANDOFFS = define_contribution_point("pap.browserHandoff")
BROWSER_FORM_POSTS = define_contribution_point("pap.browserFormPost")
DPOP_PROOF_PROVIDERS = define_contribution_point("pap.dpopProofProvider")
ACCOUNT_TOKEN_LOCKS = define_contribution_point("pap.accountTokenLock")
PROTECTED_INPUTS = define_contribution_point("pap.protectedInput")


async def resolve_addresses(host: str) -> list[str]:
    """Resolve a host off the event loop."""

    def resolve() -> list[str]:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return sorted({str(record[4][0]) for record in records})

    try:
        return await asyncio.to_thread(resolve)
    except socket.gaierror as exc:
        raise DiscoveryError("dns_failed", "Could not resolve discovery host") from exc


# Connection pinning ------------------------------------------------------------------

#: The addresses approved for each host, while a metadata fetch is in flight.
_PINNED: contextvars.ContextVar[Mapping[str, tuple[str, ...]] | None] = contextvars.ContextVar(
    "pap_pinned_addresses", default=None
)


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Dial the address the URL safety policy approved, never the host name again.

    While `HttpxDiscoveryTransport` fetches metadata, a connection to the
    fetched host goes to one of the approved addresses, in order; TLS still
    names the host (SNI and certificate verification are unchanged). Any other
    connection passes through to the wrapped backend.
    """

    def __init__(self, inner: httpcore.AsyncNetworkBackend) -> None:
        self.inner = inner

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        pins = _PINNED.get()
        if pins is None or host.lower() not in pins:
            return await self.inner.connect_tcp(
                host,
                port,
                timeout=timeout,
                local_address=local_address,
                socket_options=socket_options,
            )
        failure: Exception | None = None
        for address in pins[host.lower()]:
            try:
                return await self.inner.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout, OSError) as exc:
                failure = exc
        raise httpcore.ConnectError("no approved address accepted the connection") from failure

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if _PINNED.get() is not None:
            raise httpcore.ConnectError("metadata is never fetched over a unix socket")
        return await self.inner.connect_unix_socket(
            path, timeout=timeout, socket_options=socket_options
        )

    async def sleep(self, seconds: float) -> None:
        await self.inner.sleep(seconds)


def pin_connections(client: httpx.AsyncClient) -> httpx.AsyncClient:
    """Make `client`'s socket transports dial approved addresses during metadata fetches.

    Every `httpx.AsyncHTTPTransport` of the client (its default and its mounts)
    gets a `PinnedNetworkBackend`; transports without sockets (mock, ASGI) are
    left as they are. Idempotent.
    """

    transports = [client._transport, *client._mounts.values()]
    for transport in transports:
        pool = getattr(transport, "_pool", None)
        backend = getattr(pool, "_network_backend", None)
        if pool is None or backend is None or isinstance(backend, PinnedNetworkBackend):
            continue
        pool._network_backend = PinnedNetworkBackend(backend)
    return client


@asynccontextmanager
async def pinned(approved: ApprovedUrl) -> AsyncIterator[None]:
    """Pin connections to `approved.host` to its approved addresses within the block."""

    if not approved.addresses:
        raise DiscoveryError("dns_failed", "Discovery host has no approved address")
    token = _PINNED.set({approved.host.lower(): approved.addresses})
    try:
        yield
    finally:
        _PINNED.reset(token)


class HttpxDiscoveryTransport:
    """Default credential-free transport contributed by the PAP core plugin.

    It sends no cookie or credential, connects only to the approved addresses,
    reads at most `max_bytes`, and abandons a fetch after `timeout` seconds in
    all, so a slow server cannot hold it open by trickling bytes.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = pin_connections(client)

    async def get(self, url: str, *, fetch: MetadataFetch) -> DiscoveryResponse:
        if urlsplit(url).hostname != fetch.approved.host:
            raise DiscoveryError("unsafe_url", "The fetched URL is not the approved one")
        try:
            return await asyncio.wait_for(self._get(url, fetch), fetch.timeout)
        except asyncio.TimeoutError as exc:
            raise DiscoveryError(
                "metadata_timeout", "Metadata fetch exceeded its time limit"
            ) from exc

    async def _get(self, url: str, fetch: MetadataFetch) -> DiscoveryResponse:
        request = self.client.build_request("GET", url, headers={"Accept": "application/json"})
        # Never the host client's cookies, nor any credential header (Guides, fetching).
        for name in ("cookie", "authorization", "dpop"):
            if name in request.headers:
                del request.headers[name]
        try:
            async with pinned(fetch.approved):
                response = await self.client.send(request, stream=True, follow_redirects=False)
                try:
                    declared = response.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > fetch.max_bytes:
                        raise DiscoveryError(
                            "response_too_large", "Discovery response exceeds size limit"
                        )
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > fetch.max_bytes:
                            raise DiscoveryError(
                                "response_too_large", "Discovery response exceeds size limit"
                            )
                finally:
                    await response.aclose()
        except httpx.HTTPError as exc:
            raise DiscoveryError("request_failed", "Discovery request failed") from exc
        return DiscoveryResponse(
            url=str(response.url),
            status_code=response.status_code,
            headers={key.lower(): value for key, value in response.headers.items()},
            content=bytes(body),
        )


class PublicUrlSafetyPolicy:
    """Default SSRF boundary for discovery and authorization metadata."""

    def __init__(
        self,
        resolver: AddressResolver = resolve_addresses,
        *,
        allow_private_networks: bool = False,
    ) -> None:
        self._resolver = resolver
        self._allow_private = allow_private_networks

    async def assert_safe(self, url: str) -> ApprovedUrl:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise DiscoveryError("unsafe_url", "Discovery and metadata URLs must use HTTPS")
        addresses = await self._resolver(parsed.hostname)
        if not addresses:
            raise DiscoveryError("dns_failed", "Discovery host has no addresses")
        try:
            parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
        except ValueError as exc:
            raise DiscoveryError("dns_failed", "Discovery host resolved to no address") from exc
        if not self._allow_private and any(not address.is_global for address in parsed_addresses):
            raise DiscoveryError(
                "unsafe_address", "Discovery host resolves to a non-public address"
            )
        # The transport dials exactly these: the host is never resolved again.
        return ApprovedUrl(
            url=url,
            host=parsed.hostname,
            addresses=tuple(str(address) for address in parsed_addresses),
        )


class PapCorePlugin:
    """Contribute PAP's secure defaults through Reactor."""

    def __init__(self, transport: DiscoveryTransport, url_policy: UrlSafetyPolicy) -> None:
        self._transport = transport
        self._url_policy = url_policy

    @hookimpl
    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(DISCOVERY_TRANSPORTS, self._transport, contribution_id="httpx", order=100)
        contribute(URL_SAFETY_POLICIES, self._url_policy, contribution_id="public", order=100)
        contribute(
            PROTOCOL_PROFILES,
            ProtocolProfile(version="0.1"),
            contribution_id="0.1",
            order=100,
        )
        contribute(CLOCKS, SystemClock(), contribution_id="system", order=100)
        contribute(
            RANDOM_SOURCES,
            SystemRandomSource(),
            contribution_id="system",
            order=100,
        )
        contribute(
            ACCOUNT_TOKEN_LOCKS,
            InProcessAccountTokenLock(),
            contribution_id="in-process",
            order=100,
        )


def build_pap_reactor(
    *,
    http_client: httpx.AsyncClient | None = None,
    address_resolver: AddressResolver = resolve_addresses,
    allow_private_networks: bool = False,
    plugins: Iterable[tuple[PluginManifest, object]] = (),
) -> tuple[PluginPlatform, httpx.AsyncClient | None]:
    """Build a PAP Reactor host with plugins and return any HTTP client it owns.

    Plugins use Reactor's native ``(PluginManifest, implementation)`` input so
    applications can assemble all required PAP contributions before handing
    the platform to a client. The PAP core is registered first; lower-order
    plugin contributions can deliberately replace its portable defaults.
    """

    owned_http = http_client is None
    client = pin_connections(
        http_client or httpx.AsyncClient(timeout=5.0, follow_redirects=False)
    )
    platform = PluginPlatform(extension_group="personal_agent_protocol.plugins")
    platform.register_plugin(
        PluginManifest(
            name="personal-agent-protocol.core",
            version="0.4.0",
            contribution_points=[
                DISCOVERY_TRANSPORTS.id,
                URL_SAFETY_POLICIES.id,
                PROTOCOL_PROFILES.id,
                EXTENSION_HANDLERS.id,
                CLOCKS.id,
                RANDOM_SOURCES.id,
                SIGNERS.id,
                KEY_STORES.id,
                TOKEN_STORES.id,
                PAIRWISE_USER_ID_STORES.id,
                AUTHORIZATION_STATE_STORES.id,
                CACHES.id,
                BROWSER_HANDOFFS.id,
                BROWSER_FORM_POSTS.id,
                DPOP_PROOF_PROVIDERS.id,
                ACCOUNT_TOKEN_LOCKS.id,
                PROTECTED_INPUTS.id,
            ],
        ),
        PapCorePlugin(
            HttpxDiscoveryTransport(client),
            PublicUrlSafetyPolicy(
                address_resolver,
                allow_private_networks=allow_private_networks,
            ),
        ),
    )
    for manifest, implementation in plugins:
        platform.register_plugin(manifest, implementation)
    return platform, client if owned_http else None


def first_contribution(platform: PluginPlatform, point: object, label: str) -> object:
    """Resolve the highest-priority active provider for a PAP point."""

    contributions = platform.get_contributions(point)
    if not contributions:
        raise RuntimeError(f"PAP Reactor has no active {label} contribution")
    if len(contributions) > 1 and contributions[0].order == contributions[1].order:
        raise RuntimeError(f"PAP Reactor has ambiguous {label} contributions")
    return contributions[0].value
