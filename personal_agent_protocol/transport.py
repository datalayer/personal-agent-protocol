# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""The Session header on every request to a Company's APIs and endpoints (§5.2, §5.6).

Each request carries a fresh Session JWT (`Poppy-Session`) from the host's
`pap.sessionSigner`, and, signed in, the account's access token in
`Authorization: Bearer`. An `invalid_session` answer starts a new Session once,
and the request is sent again in it; a second one is returned to the caller,
who stops (§5.5, §7).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
from typing import cast
from urllib.parse import urlsplit

import httpx
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import TransportError
from .json import loads_strict
from .reactor import (
    CLOCKS,
    RANDOM_SOURCES,
    RATE_LIMIT_BUDGETS,
    RETRY_POLICIES,
    SESSION_SIGNERS,
    Clock,
    RandomSource,
    RateLimitBudget,
    RetryPolicy,
    SessionJwtRequest,
    SessionSigner,
    SystemClock,
    first_contribution,
    optional_contribution,
    parse_retry_after,
    send_bounded,
)
from .refusals import refuse_redirect
from .sessions import AccessToken, PapSession

#: The header that carries the Session JWT (§5.2).
SESSION_HEADER = "Poppy-Session"
#: Refusals that ask the caller to come back later (Guides, retries and rate limits).
_LATER = frozenset({429, 503})
#: Methods retried on their own: they change nothing at the company.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: Headers the host owns: a caller never sets them.
_HOST_OWNED = frozenset({"authorization", "dpop", "poppy-session"})


def _https_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise TransportError("invalid_url", "PAP resource URL must use HTTPS")
    return value


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    return parsed.scheme, (parsed.hostname or "").lower(), parsed.port or 443


def budget_key(url: str) -> str:
    """The shared rate-limit budget a request draws on: its company's origin."""

    scheme, host, port = _origin(url)
    return f"{scheme}://{host}:{port}"


def invalid_session(response: httpx.Response) -> bool:
    """Whether the company answered `invalid_session` (§5.3): HTTP 400 and its JSON body."""

    if response.status_code != 400:
        return False
    try:
        payload = loads_strict(response.content)
    except Exception:
        return False
    return isinstance(payload, dict) and payload.get("error") == "invalid_session"


async def session_headers(
    reactor: PluginPlatform,
    method: str,
    url: str,
    *,
    session: PapSession,
    token: AccessToken | None,
) -> dict[str, str]:
    """`Poppy-Session` for this request, and with an access token, `Authorization` (§5.2)."""

    signer = cast(SessionSigner, first_contribution(reactor, SESSION_SIGNERS, "session signer"))
    jwt = await signer.sign(
        SessionJwtRequest(
            method=method.upper(),
            url=url,
            tenant_id=session.tenant_id,
            issuer=session.issuer,
            client_id=session.client_id,
            sid=session.sid,
            sub=session.sub,
            agent_id=session.agent_id,
            access_token=None if token is None else token.access_token,
        )
    )
    headers = {SESSION_HEADER: jwt.get_secret_value()}
    if token is not None:
        headers["Authorization"] = f"Bearer {token.access_token.get_secret_value()}"
    return headers


class SessionHttpClient:
    """Send requests with the Session header; a redirect is refused, never followed (§3)."""

    def __init__(
        self,
        *,
        reactor: PluginPlatform,
        http_client: httpx.AsyncClient,
        max_response_bytes: int = 1024 * 1024,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.reactor = reactor
        self.http = http_client
        #: No more than this (and one byte) of a response is read; the client checks the rest.
        self.max_response_bytes = max_response_bytes

    async def request(
        self,
        method: str,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """Send a request in `session`, within the company's shared budget.

        Signed in with `token`, signed out without. Every attempt draws on
        `pap.rateLimitBudget` for the company's origin and carries a fresh Session
        JWT. A 429 or 503 shares its `Retry-After` with every task through the
        budget; a safe method (GET, HEAD, OPTIONS) is then retried by
        `pap.retryPolicy` — never sooner than `Retry-After`, with exponential
        backoff and jitter otherwise. A write, or a pause longer than the policy
        allows, returns the refusal to the caller. `invalid_session` starts a new
        Session once (`session.restart()`) and sends the request again in it.
        """

        policy = optional_contribution(self.reactor, RETRY_POLICIES, "retry policy")
        budget = optional_contribution(self.reactor, RATE_LIMIT_BUDGETS, "rate-limit budget")
        retry = policy if isinstance(policy, RetryPolicy) else RetryPolicy(max_attempts=1)
        key = budget_key(url)
        attempts = 0
        restarted = False
        while True:
            if isinstance(budget, RateLimitBudget):
                await budget.acquire(key)
            response = await self._request_once(
                method, url, session=session, token=token, headers=headers, content=content
            )
            attempts += 1
            if invalid_session(response) and not restarted:
                # The Session failed a check or has ended: a new one, once (§5.5, §7).
                restarted = True
                session.restart(self._random_bytes)
                continue
            if response.status_code not in _LATER:
                return response
            retry_after = parse_retry_after(response.headers.get("retry-after"), self._now())
            delay = (
                retry.delay(attempts, retry_after, self._jitter())
                if method.upper() in _SAFE_METHODS
                else None
            )
            pause = delay if delay is not None else retry_after
            if isinstance(budget, RateLimitBudget) and pause is not None:
                await budget.defer(key, pause)
            if delay is None:
                return response
            if not isinstance(budget, RateLimitBudget):
                await asyncio.sleep(delay)

    def _now(self) -> datetime:
        clock = optional_contribution(self.reactor, CLOCKS, "clock")
        return (clock if isinstance(clock, Clock) else SystemClock()).now()

    def _random_bytes(self, length: int) -> bytes:
        source = cast(RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random"))
        return source.bytes(length)

    def _jitter(self) -> float:
        source = optional_contribution(self.reactor, RANDOM_SOURCES, "random source")
        if not isinstance(source, RandomSource):
            return 0.5
        return int.from_bytes(source.bytes(4), "big") / 2**32

    def _headers(self, supplied: Mapping[str, str] | None) -> dict[str, str]:
        values = dict(supplied or {})
        if any(name.lower() in _HOST_OWNED for name in values):
            raise TransportError(
                "protected_header", "Authorization and Poppy-Session headers are host-owned"
            )
        return values

    async def _request_once(
        self,
        method: str,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """One request with a fresh Session JWT; no redirect followed."""

        target = _https_url(url)
        supplied = self._headers(headers)
        signed = await session_headers(self.reactor, method, target, session=session, token=token)
        try:
            response = await send_bounded(
                self.http,
                self.http.build_request(
                    method.upper(), target, content=content, headers={**supplied, **signed}
                ),
                max_bytes=self.max_response_bytes,
            )
        except httpx.HTTPError as exc:
            raise TransportError("request_failed", "PAP resource request failed") from exc
        # A redirect would carry the token and a Session JWT to another URL: refused (§3).
        refuse_redirect(response)
        return response

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> AsyncIterator[httpx.Response]:
        """Open a streamed response (SSE) in `session`; no redirect followed.

        `invalid_session` starts a new Session once, as `request` does.
        """

        target = _https_url(url)
        supplied = self._headers(headers)
        for attempt in range(2):
            signed = await session_headers(
                self.reactor, method, target, session=session, token=token
            )
            request = self.http.build_request(
                method.upper(), target, headers={**supplied, **signed}
            )
            try:
                response = await self.http.send(request, stream=True, follow_redirects=False)
            except httpx.HTTPError as exc:
                raise TransportError("request_failed", "PAP stream request failed") from exc
            try:
                if response.status_code == 400 and attempt == 0:
                    await response.aread()
                    if invalid_session(response):
                        session.restart(self._random_bytes)
                        continue
                refuse_redirect(response)
                yield response
                return
            finally:
                await response.aclose()
