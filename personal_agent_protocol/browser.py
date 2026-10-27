# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""Joining the personal agent's own browser to a PAP Session (§5, §9.6).

The browser loads `web.browser_session_endpoint` with a GET and gets a form
holding a one-time `code`, tied to that browser by a `SameSite=Strict` cookie.
The personal agent signs a DPoP proof with the Session Key, the code as its
`nonce`, and the browser submits code and proof; the company answers with the
Session's cookie. The code is read from the agent's own browser only, by host
code the model cannot read (§9.2): never from a message or another page.
"""

from __future__ import annotations

from datetime import datetime
from typing import cast
from urllib.parse import urlsplit

from pydantic import SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import BrowserSessionError
from .models import ProtocolModel
from .reactor import (
    BROWSER_JOINS,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    BrowserJoin,
    Clock,
    DpopProofProvider,
    DpopProofRequest,
    first_contribution,
)

#: A join code carries at least 128 random bits (§5): 22 base64url characters or more.
_MIN_CODE_LENGTH = 22


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BrowserSessionError("invalid_url", f"{label} must be an HTTPS URL")
    return value


class BrowserSessionStart(ProtocolModel):
    """Safe status once the browser has submitted the join form."""

    endpoint: str
    joined_at: datetime


class BrowserSessionClient:
    """Join the agent's own browser to a Session with a proof over a one-time code."""

    def __init__(self, *, reactor: PluginPlatform) -> None:
        self.reactor = reactor

    async def join(
        self,
        *,
        browser_session_endpoint: str,
        tenant_id: str,
        issuer: str,
        session_key: str,
    ) -> BrowserSessionStart:
        """Load the join form, sign its code with the Session Key, submit it (§5).

        `session_key` is the Session the browser joins, signed in or out. The proof's
        `htm` is POST, its `htu` the endpoint, its `nonce` the code; it has no `ath`.
        """

        endpoint = _https_url(browser_session_endpoint, "browser_session_endpoint")
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        browser = cast(BrowserJoin, first_contribution(self.reactor, BROWSER_JOINS, "browser join"))
        prover = cast(
            DpopProofProvider,
            first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
        )
        code = await browser.load_join_form(endpoint)
        if len(code.get_secret_value()) < _MIN_CODE_LENGTH:
            raise BrowserSessionError(
                "invalid_join_code", "The join page's code is too short to be one-time"
            )
        proof = await prover.create(
            DpopProofRequest(
                method="POST",
                url=endpoint,
                tenant_id=tenant_id,
                issuer=issuer,
                session_key=session_key,
                nonce=code.get_secret_value(),
            )
        )
        await browser.submit_join_form(proof)
        return BrowserSessionStart(endpoint=endpoint, joined_at=clock.now())


def join_proof_nonce(code: SecretStr | str) -> str:
    """The `nonce` a join proof carries: the code itself (§5, RFC 9449 §8)."""

    return code.get_secret_value() if isinstance(code, SecretStr) else code
