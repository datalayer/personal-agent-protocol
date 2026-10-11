# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""Proof-bound HTTP transport for PAP APIs and conversations."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import cast
from urllib.parse import urljoin, urlsplit

import httpx
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import TransportError
from .reactor import DPOP_PROOF_PROVIDERS, DpopProofProvider, DpopProofRequest, first_contribution
from .sessions import SessionToken

_REDIRECTS = frozenset({301, 302, 303, 307, 308})


def _https_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise TransportError("invalid_url", "PAP resource URL must use HTTPS")
    return value


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    return parsed.scheme, (parsed.hostname or "").lower(), parsed.port or 443


class DpopHttpClient:
    """Send replay-safe DPoP requests without forwarding credentials across origins."""

    def __init__(
        self,
        *,
        reactor: PluginPlatform,
        http_client: httpx.AsyncClient,
        max_redirects: int = 3,
    ) -> None:
        if max_redirects < 0:
            raise ValueError("max_redirects must not be negative")
        self.reactor = reactor
        self.http = http_client
        self.max_redirects = max_redirects

    async def request(  # noqa: C901 - security state machine is clearer in one loop
        self,
        method: str,
        url: str,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """Send a DPoP request, retry one nonce, and follow same-origin redirects."""

        if token.token_type != "DPoP":  # noqa: S105 - OAuth token type
            raise TransportError(
                "unexpected_token_type", "PAP resource requests require a DPoP token"
            )
        current_url = _https_url(url)
        current_method = method.upper()
        current_content = content
        supplied = dict(headers or {})
        if any(name.lower() in {"authorization", "dpop"} for name in supplied):
            raise TransportError(
                "protected_header", "Authorization and DPoP headers are host-owned"
            )
        dpop = cast(
            DpopProofProvider,
            first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
        )
        redirects = 0
        nonce: str | None = None
        nonce_retried = False
        while True:
            proof = await dpop.create(
                DpopProofRequest(
                    method=current_method,
                    url=current_url,
                    tenant_id=tenant_id,
                    subject=pairwise_user_id,
                    issuer=issuer,
                    access_token=token.access_token,
                    nonce=nonce,
                )
            )
            try:
                response = await self.http.request(
                    current_method,
                    current_url,
                    content=current_content,
                    headers={
                        **supplied,
                        "Authorization": f"DPoP {token.access_token.get_secret_value()}",
                        "DPoP": proof.get_secret_value(),
                    },
                    follow_redirects=False,
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

            if response.status_code not in _REDIRECTS:
                return response
            if redirects >= self.max_redirects:
                raise TransportError(
                    "too_many_redirects", "PAP resource request exceeded redirect limit"
                )
            location = response.headers.get("location")
            if not location:
                raise TransportError("invalid_redirect", "PAP resource redirect has no location")
            target = _https_url(urljoin(current_url, location))
            if _origin(target) != _origin(current_url):
                raise TransportError(
                    "cross_origin_redirect",
                    "PAP credentials are never forwarded to another origin",
                )
            redirects += 1
            current_url = target
            nonce = None
            nonce_retried = False
            if response.status_code == 303:
                current_method = "GET"
                current_content = None

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
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
                    subject=pairwise_user_id,
                    issuer=issuer,
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
                if response.status_code in _REDIRECTS:
                    raise TransportError(
                        "stream_redirect", "A PAP stream is never followed through a redirect"
                    )
                yield response
                return
            finally:
                await response.aclose()
        raise TransportError("use_dpop_nonce", "Company rejected the refreshed DPoP proof")
