# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""Proof-bound HTTP transport for PAP APIs and conversations."""

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
from .reactor import (
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    RANDOM_SOURCES,
    RATE_LIMIT_BUDGETS,
    RETRY_POLICIES,
    Clock,
    DpopProofProvider,
    DpopProofRequest,
    RandomSource,
    RateLimitBudget,
    RetryPolicy,
    SystemClock,
    first_contribution,
    optional_contribution,
    parse_retry_after,
    send_bounded,
)
from .refusals import refuse_redirect
from .sessions import SessionToken

#: Refusals that ask the caller to come back later (Guides, retries and rate limits).
_LATER = frozenset({429, 503})
#: Methods retried on their own: they change nothing at the company.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


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


class DpopHttpClient:
    """Send replay-safe DPoP requests; a redirect is refused, never followed (§3)."""

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
        token: SessionToken,
        tenant_id: str,
        issuer: str,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """Send a DPoP request within the company's shared budget, retrying when told to.

        Every attempt draws on `pap.rateLimitBudget` for the company's origin.
        A 429 or 503 shares its `Retry-After` with every task through the
        budget; a safe method (GET, HEAD, OPTIONS) is then retried by
        `pap.retryPolicy` — never sooner than `Retry-After`, with exponential
        backoff and jitter otherwise — each time with a fresh DPoP proof. A
        write, or a pause longer than the policy allows, returns the refusal
        to the caller.
        """

        policy = optional_contribution(self.reactor, RETRY_POLICIES, "retry policy")
        budget = optional_contribution(self.reactor, RATE_LIMIT_BUDGETS, "rate-limit budget")
        retry = policy if isinstance(policy, RetryPolicy) else RetryPolicy(max_attempts=1)
        key = budget_key(url)
        attempts = 0
        while True:
            if isinstance(budget, RateLimitBudget):
                await budget.acquire(key)
            response = await self._request_once(
                method,
                url,
                token=token,
                tenant_id=tenant_id,
                issuer=issuer,
                headers=headers,
                content=content,
            )
            attempts += 1
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

    def _jitter(self) -> float:
        source = optional_contribution(self.reactor, RANDOM_SOURCES, "random source")
        if not isinstance(source, RandomSource):
            return 0.5
        return int.from_bytes(source.bytes(4), "big") / 2**32

    async def _request_once(
        self,
        method: str,
        url: str,
        *,
        token: SessionToken,
        tenant_id: str,
        issuer: str,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """One DPoP request: one retry with the company's nonce, no redirect followed."""

        if token.token_type != "DPoP":  # noqa: S105 - OAuth token type
            raise TransportError(
                "unexpected_token_type", "PAP resource requests require a DPoP token"
            )
        current_url = _https_url(url)
        current_method = method.upper()
        supplied = dict(headers or {})
        if any(name.lower() in {"authorization", "dpop"} for name in supplied):
            raise TransportError(
                "protected_header", "Authorization and DPoP headers are host-owned"
            )
        dpop = cast(
            DpopProofProvider,
            first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
        )
        nonce: str | None = None
        nonce_retried = False
        while True:
            proof = await dpop.create(
                DpopProofRequest(
                    method=current_method,
                    url=current_url,
                    tenant_id=tenant_id,
                    issuer=issuer,
                    session_key=token.session_key,
                    access_token=token.access_token,
                    nonce=nonce,
                )
            )
            try:
                response = await send_bounded(
                    self.http,
                    self.http.build_request(
                        current_method,
                        current_url,
                        content=content,
                        headers={
                            **supplied,
                            "Authorization": f"DPoP {token.access_token.get_secret_value()}",
                            "DPoP": proof.get_secret_value(),
                        },
                    ),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise TransportError("request_failed", "PAP resource request failed") from exc

            challenge = response.headers.get("www-authenticate", "").lower()
            requested_nonce = response.headers.get("dpop-nonce")
            if "use_dpop_nonce" in challenge and not nonce_retried:
                if not requested_nonce:
                    raise TransportError(
                        "missing_dpop_nonce", "DPoP nonce challenge omitted its nonce"
                    )
                nonce = requested_nonce
                nonce_retried = True
                continue

            # A redirect would carry the token and a proof to another URL: refused (§3).
            refuse_redirect(response)
            return response

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        token: SessionToken,
        tenant_id: str,
        issuer: str,
        headers: Mapping[str, str] | None = None,
    ) -> AsyncIterator[httpx.Response]:
        """Open a streamed DPoP response (SSE): one nonce retry, no redirect followed."""

        if token.token_type != "DPoP":  # noqa: S105 - OAuth token type
            raise TransportError(
                "unexpected_token_type", "PAP resource requests require a DPoP token"
            )
        target = _https_url(url)
        supplied = dict(headers or {})
        if any(name.lower() in {"authorization", "dpop"} for name in supplied):
            raise TransportError(
                "protected_header", "Authorization and DPoP headers are host-owned"
            )
        dpop = cast(
            DpopProofProvider,
            first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
        )
        nonce: str | None = None
        for attempt in range(2):
            proof = await dpop.create(
                DpopProofRequest(
                    method=method.upper(),
                    url=target,
                    tenant_id=tenant_id,
                    issuer=issuer,
                    session_key=token.session_key,
                    access_token=token.access_token,
                    nonce=nonce,
                )
            )
            request = self.http.build_request(
                method.upper(),
                target,
                headers={
                    **supplied,
                    "Authorization": f"DPoP {token.access_token.get_secret_value()}",
                    "DPoP": proof.get_secret_value(),
                },
            )
            try:
                response = await self.http.send(request, stream=True, follow_redirects=False)
            except httpx.HTTPError as exc:
                raise TransportError("request_failed", "PAP stream request failed") from exc
            try:
                challenge = response.headers.get("www-authenticate", "").lower()
                if "use_dpop_nonce" in challenge and attempt == 0:
                    nonce = response.headers.get("dpop-nonce")
                    if not nonce:
                        raise TransportError(
                            "missing_dpop_nonce", "DPoP nonce challenge omitted its nonce"
                        )
                    continue
                refuse_redirect(response)
                yield response
                return
            finally:
                await response.aclose()
        raise TransportError("use_dpop_nonce", "Company rejected the refreshed DPoP proof")
