# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Reactor contribution points and the default PAP infrastructure plugin."""

from __future__ import annotations

import asyncio
import contextvars
import ipaddress
import math
import secrets
import socket
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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

from .errors import DiscoveryError, TransportError

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

    The host shows `company_name` and `company_domain` whenever it asks
    (§4.7), and a credential store the user chose picks stored credentials by
    `issuer`, the company's `auth.issuer`: never by the field labels or the
    endpoint, which the company writes and can name anything.
    """

    purpose: Literal["credentials", "one_time_code"]
    company_name: str
    company_domain: str
    issuer: str
    fields: tuple[ProtectedInputField, ...]
    sent_to: str | None = None


@runtime_checkable
class ProtectedInput(Protocol):
    """Collect protected values from the user outside model context (PAP §4.7)."""

    async def collect(self, request: ProtectedInputRequest) -> dict[str, SecretStr]: ...


@dataclass(frozen=True)
class ApprovalRequest:
    """A live-session action that changes or ends what the user holds, to approve first.

    `summary` says what it does in plain words; `arguments` are the action's own
    (Session and operation IDs, never a credential). Nothing has been done yet.
    """

    action_id: str
    action_name: str
    summary: str
    arguments: Mapping[str, str]
    tenant_id: str


@runtime_checkable
class ApprovalSurface(Protocol):
    """The host's own approval surface: the user, not a model, answers.

    Only `True` approves. Without a contribution, a destructive live-session
    action is refused (`approval_required`); it stays available from `pap`.
    """

    async def approve(self, request: ApprovalRequest) -> bool: ...


@runtime_checkable
class TelemetrySink(Protocol):
    """Receive each finished protocol stage (`telemetry.TelemetryEvent`), redacted already."""

    def record(self, event: Any) -> None: ...


class InMemoryProtocolCache:
    """Default `pap.cache`: a bounded, least-recently-used map in one process."""

    def __init__(self, max_entries: int = 1024) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.max_entries = max_entries
        self._entries: OrderedDict[str, tuple[object, datetime]] = OrderedDict()

    async def put(self, key: str, value: object, *, expires_at: datetime) -> None:
        self._entries[key] = (value, expires_at)
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    async def get(self, key: str) -> object | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        self._entries.move_to_end(key)
        return entry[0]

    async def delete(self, key: str) -> None:
        self._entries.pop(key, None)


@dataclass(frozen=True)
class RetryPolicy:
    """When to retry a refused request (Guides, retries).

    After `attempts` tries, `delay` is how long to wait before the next one,
    or `None` to stop and report: a `Retry-After` is always honoured (never
    retried sooner), but one longer than `max_retry_after` is reported to the
    caller instead of waited for; otherwise the delay backs off exponentially
    from `base_delay`, with jitter, capped at `max_delay`. At most
    `max_attempts` tries in all.
    """

    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    max_retry_after: float = 10.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if not 0 < self.base_delay <= self.max_delay:
            raise ValueError("retry delays need 0 < base_delay <= max_delay")
        if self.max_retry_after < 0:
            raise ValueError("max_retry_after must not be negative")

    def delay(self, attempts: int, retry_after: float | None, jitter: float) -> float | None:
        """Seconds to wait after `attempts` tries; `jitter` is uniform in [0, 1)."""

        if attempts >= self.max_attempts:
            return None
        backoff = min(self.max_delay, self.base_delay * 2 ** (attempts - 1))
        if retry_after is None:
            # "Equal jitter": at least half the backoff, so a retry is never immediate.
            return backoff / 2 + jitter * backoff / 2
        if retry_after > self.max_retry_after:
            return None
        # Never sooner than Retry-After; jitter spreads clients told the same time.
        return retry_after + jitter * min(backoff, self.base_delay)


def parse_retry_after(value: str | None, now: datetime) -> float | None:
    """`Retry-After` in seconds (delta-seconds or an HTTP date), or `None`."""

    if value is None:
        return None
    text = value.strip()
    if text.isdigit():
        return float(int(text))
    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - now).total_seconds())


@runtime_checkable
class RateLimitBudget(Protocol):
    """A company's request budget, shared by every task and user of the host.

    `acquire` waits for the company's budget (or raises `rate_limited` when the
    wait would be too long); `defer` records that the company asked for a pause
    (`Retry-After`), so every task waits, not only the one that was refused. A
    multi-process host contributes a distributed budget.
    """

    async def acquire(self, key: str) -> None: ...

    async def defer(self, key: str, seconds: float) -> None: ...


@dataclass
class _Bucket:
    #: When the next request may go if the burst is spent (GCRA's theoretical arrival time).
    due: float
    blocked_until: float = 0.0


class SharedRateLimitBudget:
    """Default `pap.rateLimitBudget`: per-company budgets in one process.

    `rate` requests per second with bursts of `burst` (no rate limit when
    `rate` is `None`: only the companies' own pauses are shared). Each caller
    reserves its turn when it asks — the turn counts every caller ahead of it
    and the company's pause (`defer`) — and sleeps until then, so concurrent
    callers never exceed the rate, and a turn further than `max_wait` seconds
    away is refused at once with `rate_limited` and `retry_after`, however
    many callers are queued (the generic cell rate algorithm).
    """

    def __init__(
        self,
        *,
        rate: float | None = None,
        burst: int = 1,
        max_wait: float = 10.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate is not None and rate <= 0:
            raise ValueError("rate must be positive")
        if burst < 1:
            raise ValueError("burst must be at least 1")
        self.rate = rate
        self.burst = burst
        self.max_wait = max_wait
        self._sleep = sleep
        self._monotonic = monotonic
        self._buckets: dict[str, _Bucket] = {}

    def _bucket(self, key: str, now: float) -> _Bucket:
        return self._buckets.setdefault(key, _Bucket(due=now))

    async def acquire(self, key: str) -> None:
        # Reserved without awaiting anything: callers take their turns in arrival order.
        now = self._monotonic()
        bucket = self._bucket(key, now)
        turn = max(now, bucket.blocked_until)
        due = max(bucket.due, turn)
        interval = 0.0 if self.rate is None else 1.0 / self.rate
        if self.rate is not None:
            turn = max(turn, due - (self.burst - 1) * interval)
        wait = turn - now
        if wait > self.max_wait:
            raise TransportError(
                "rate_limited",
                "The company's shared request budget is exhausted",
                details={"retry_after": str(math.ceil(wait))},
            )
        if self.rate is not None:
            bucket.due = due + interval
        left = wait
        while left > 0:  # a timer may fire a little early: sleep the rest
            await self._sleep(left)
            left = turn - self._monotonic()

    async def defer(self, key: str, seconds: float) -> None:
        now = self._monotonic()
        bucket = self._bucket(key, now)
        bucket.blocked_until = max(bucket.blocked_until, now + max(0.0, seconds))


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
CLOCKS = define_contribution_point("pap.clock")
RANDOM_SOURCES = define_contribution_point("pap.randomSource")
SIGNERS = define_contribution_point("pap.signer")
TOKEN_STORES = define_contribution_point("pap.tokenStore")
PAIRWISE_USER_ID_STORES = define_contribution_point("pap.pairwiseUserIdStore")
AUTHORIZATION_STATE_STORES = define_contribution_point("pap.authorizationStateStore")
CACHES = define_contribution_point("pap.cache")
BROWSER_HANDOFFS = define_contribution_point("pap.browserHandoff")
BROWSER_FORM_POSTS = define_contribution_point("pap.browserFormPost")
DPOP_PROOF_PROVIDERS = define_contribution_point("pap.dpopProofProvider")
ACCOUNT_TOKEN_LOCKS = define_contribution_point("pap.accountTokenLock")
PROTECTED_INPUTS = define_contribution_point("pap.protectedInput")
RETRY_POLICIES = define_contribution_point("pap.retryPolicy")
RATE_LIMIT_BUDGETS = define_contribution_point("pap.rateLimitBudget")
#: `operations.StandingPermissionStore`: the user's standing permissions (Operations).
STANDING_PERMISSION_STORES = define_contribution_point("pap.standingPermissionStore")
#: `TelemetrySink`: where traces and analytics events go; none, and nothing is emitted.
TELEMETRY_SINKS = define_contribution_point("pap.telemetry")
#: `ApprovalSurface`: a host's approval for destructive live-session actions (Python hosts).
APPROVAL_SURFACES = define_contribution_point("pap.approvalSurface")


#: Prefixes that carry an IPv4 address in their last 32 bits: NAT64 (RFC 6052),
#: IPv4-mapped, and the deprecated IPv4-compatible form.
_EMBEDDING_V4 = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("::ffff:0:0/96"),
    ipaddress.IPv6Network("::/96"),
)
#: Local-use NAT64 (RFC 8215): it translates to whatever its operator chose, never global.
_LOCAL_NAT64 = ipaddress.IPv6Network("64:ff9b:1::/48")
#: 6to4 (RFC 3056) carries an IPv4 address in bits 16..48.
_SIX_TO_FOUR = ipaddress.IPv6Network("2002::/16")


def is_global_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Whether an address is globally reachable, an IPv4 address inside IPv6 included.

    `ipaddress`'s `is_global` judges `64:ff9b::7f00:1` (NAT64 for 127.0.0.1) and
    `::a9fe:a9fe` (IPv4-compatible 169.254.169.254) global: the IPv4 address
    they carry is unwrapped and judged instead, so a resolver answering one of
    them never reaches loopback, link-local metadata, or a private network.
    """

    if isinstance(address, ipaddress.IPv6Address):
        if address in _LOCAL_NAT64:
            return False
        if any(address in prefix for prefix in _EMBEDDING_V4):
            embedded = ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
            return embedded.is_global and not embedded.is_multicast
        if address in _SIX_TO_FOUR:
            embedded = ipaddress.IPv4Address((int(address) >> 80) & 0xFFFFFFFF)
            return embedded.is_global and not embedded.is_multicast
    return address.is_global and not address.is_multicast


#: Headers that described the body as the server sent it, not as it is read back.
_FRAMING = frozenset({"content-encoding", "content-length", "transfer-encoding"})


async def send_bounded(
    http: httpx.AsyncClient,
    request: httpx.Request,
    *,
    max_bytes: int,
    auth: httpx.Auth | None = None,
) -> httpx.Response:
    """Send `request` (no redirect followed) and read at most `max_bytes + 1` of the body.

    The response is read back with that much: a caller's `len(content) >
    max_bytes` check refuses a larger body without the rest ever being read
    into memory, however much the server sends.
    """

    response = await http.send(
        request,
        stream=True,
        follow_redirects=False,
        **({} if auth is None else {"auth": auth}),
    )
    body = bytearray()
    try:
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > max_bytes:
                break
    finally:
        await response.aclose()
    headers = [(k, v) for k, v in response.headers.multi_items() if k.lower() not in _FRAMING]
    return httpx.Response(
        response.status_code,
        headers=headers,
        content=bytes(body[: max_bytes + 1]),
        request=request,
    )


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

    for transport in [client._transport, *client._mounts.values()]:
        _pin_transport(transport)
    return client


def _pin_transport(transport: object) -> None:
    pool = getattr(transport, "_pool", None)
    backend = getattr(pool, "_network_backend", None)
    if pool is None or backend is None or isinstance(backend, PinnedNetworkBackend):
        return
    pool._network_backend = PinnedNetworkBackend(backend)


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


class ResolvingTransport(httpx.AsyncBaseTransport):
    """Every request to an untrusted host resolved, vetted, and pinned.

    Python's `createResolvingFetch`, for everything a personal agent sends a
    company once its metadata is read: Sessions and sign-ins, conversations,
    API calls, Operations, the company's MCP server. Before each request —
    each hop of a redirect the caller follows included — the URL safety
    policy resolves the host and refuses the request unless it is HTTPS and
    every address is public (`DiscoveryError`: `unsafe_url`, `unsafe_address`,
    `dns_failed`); nothing is sent, and nothing is tried elsewhere. The
    connection then dials only the approved addresses, TLS still naming the
    host, so a name that rebinds after the check reaches no private address.

    With `max_response_bytes`, no response body is read past it
    (`TransportError`: `response_too_large`), for callers that read whole
    bodies themselves; the SDK's own clients bound theirs already.
    """

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport | None = None,
        *,
        resolver: AddressResolver = resolve_addresses,
        allow_private_networks: bool = False,
        max_response_bytes: int | None = None,
    ) -> None:
        if max_response_bytes is not None and max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self._inner = inner if inner is not None else httpx.AsyncHTTPTransport()
        _pin_transport(self._inner)
        self._policy = PublicUrlSafetyPolicy(
            resolver, allow_private_networks=allow_private_networks
        )
        self._max = max_response_bytes

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        approved = await self._policy.assert_safe(str(request.url))
        async with pinned(approved):
            response = await self._inner.handle_async_request(request)
        if self._max is None:
            return response
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max:
            await response.aclose()
            raise TransportError(
                "response_too_large", "The company's response exceeds the size limit"
            )
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=_BoundedStream(response.stream, self._max),
            extensions=response.extensions,
            request=request,
        )

    async def aclose(self) -> None:
        await self._inner.aclose()


class _BoundedStream(httpx.AsyncByteStream):
    """A response body that stops being read past `limit` bytes."""

    def __init__(self, inner: httpx.SyncByteStream | httpx.AsyncByteStream, limit: int) -> None:
        self._inner = inner
        self._limit = limit

    async def __aiter__(self) -> AsyncIterator[bytes]:
        if not isinstance(self._inner, httpx.AsyncByteStream):
            raise TransportError("request_failed", "A company's response is read asynchronously")
        read = 0
        async for chunk in self._inner:
            read += len(chunk)
            if read > self._limit:
                raise TransportError(
                    "response_too_large", "The company's response exceeds the size limit"
                )
            yield chunk

    async def aclose(self) -> None:
        if isinstance(self._inner, httpx.AsyncByteStream):
            await self._inner.aclose()


def create_resolving_client(
    *,
    resolver: AddressResolver = resolve_addresses,
    allow_private_networks: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
    timeout: float = 10.0,
    max_response_bytes: int | None = None,
) -> httpx.AsyncClient:
    """An `httpx` client whose every request goes through a `ResolvingTransport`.

    Redirects are never followed by the client (the SDK follows those it
    allows, each hop vetted again), and no proxy from the environment is
    used: a proxy would dial the host itself, unpinned. `transport` replaces
    the socket transport underneath (a test network, a custom TLS context).
    """

    return httpx.AsyncClient(
        transport=ResolvingTransport(
            transport,
            resolver=resolver,
            allow_private_networks=allow_private_networks,
            max_response_bytes=max_response_bytes,
        ),
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    )


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
        # Any user information, even empty (`https://:@host/`), is refused.
        if parsed.scheme != "https" or not parsed.hostname or "@" in parsed.netloc:
            raise DiscoveryError("unsafe_url", "Discovery and metadata URLs must use HTTPS")
        addresses = await self._resolver(parsed.hostname)
        if not addresses:
            raise DiscoveryError("dns_failed", "Discovery host has no addresses")
        try:
            parsed_addresses = [ipaddress.ip_address(address) for address in addresses]
        except ValueError as exc:
            raise DiscoveryError("dns_failed", "Discovery host resolved to no address") from exc
        if not self._allow_private and any(
            not is_global_address(address) for address in parsed_addresses
        ):
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
        contribute(CACHES, InMemoryProtocolCache(), contribution_id="memory", order=100)
        contribute(RETRY_POLICIES, RetryPolicy(), contribution_id="default", order=100)
        contribute(
            RATE_LIMIT_BUDGETS, SharedRateLimitBudget(), contribution_id="in-process", order=100
        )

    @hookimpl
    def provide_display_types(self, registry: object) -> None:
        # Asked only by a reactor with `reactor.ui` (1.1), so the import waits
        # until then: the SDK itself runs on an older one.
        from .ui import PapConfirm, PapOutcome, PapReplies, PapSignIn

        registry.register(PapSignIn)  # type: ignore[attr-defined]
        registry.register(PapConfirm)  # type: ignore[attr-defined]
        registry.register(PapOutcome)  # type: ignore[attr-defined]
        registry.register(PapReplies)  # type: ignore[attr-defined]


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
    client = pin_connections(http_client or httpx.AsyncClient(timeout=5.0, follow_redirects=False))
    platform = PluginPlatform(extension_group="personal_agent_protocol.plugins")
    platform.register_plugin(
        PluginManifest(
            name="personal-agent-protocol.core",
            version="0.25.0",
            contribution_points=[
                DISCOVERY_TRANSPORTS.id,
                URL_SAFETY_POLICIES.id,
                CLOCKS.id,
                RANDOM_SOURCES.id,
                SIGNERS.id,
                TOKEN_STORES.id,
                PAIRWISE_USER_ID_STORES.id,
                AUTHORIZATION_STATE_STORES.id,
                CACHES.id,
                BROWSER_HANDOFFS.id,
                BROWSER_FORM_POSTS.id,
                DPOP_PROOF_PROVIDERS.id,
                ACCOUNT_TOKEN_LOCKS.id,
                PROTECTED_INPUTS.id,
                RETRY_POLICIES.id,
                RATE_LIMIT_BUDGETS.id,
                STANDING_PERMISSION_STORES.id,
                TELEMETRY_SINKS.id,
                APPROVAL_SURFACES.id,
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


def optional_contribution(platform: PluginPlatform, point: object, label: str) -> object | None:
    """The highest-priority provider for an optional PAP point, `None` when there is none.

    An optional point may have no provider (the feature is off), but never two at the
    same winning priority: that fails closed exactly as `first_contribution` does.
    """

    if not platform.get_contributions(point):
        return None
    return first_contribution(platform, point, label)
