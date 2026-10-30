# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""Joining the personal agent's own browser to a PAP Session (§6, §10.6).

1. The browser loads `web.browser_session_endpoint` with a GET and gets a form
   holding a one-time `code`, tied to that browser by a `SameSite=Strict` cookie.
2. The personal agent authorizes the code in a request of its own:
   `POST {browser_session_endpoint}/authorize` with `{"code": ...}`, the Session
   header of the Session the browser joins and, signed in, its access token. The
   company answers `204`.
3. The browser submits the form, the code alone; the company answers with the
   Session's cookie. The access token never passes through the browser.

The code is read from the agent's own browser only, by host code the model
cannot read (§10.2): never from a message or another page. Only a browser the
personal agent controls joins, never the User's own (§6).

A join with a token signs the browser in, in place of any login it had; one without
leaves the login the browser has, and ends the sign-in of an earlier join (§6).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import cast
from urllib.parse import urlsplit

from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import BrowserSessionError, TransportError
from .models import ProtocolModel
from .reactor import BROWSER_JOINS, CLOCKS, BrowserJoin, Clock, first_contribution
from .sessions import AccessToken, PapSession
from .transport import SessionHttpClient

#: A join code carries at least 128 random bits (§6): 22 base64url characters or more.
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
    """Join the agent's own browser to a Session: load, authorize, submit (§6)."""

    def __init__(self, *, reactor: PluginPlatform, transport: SessionHttpClient) -> None:
        self.reactor = reactor
        self.transport = transport

    async def join(
        self,
        *,
        browser_session_endpoint: str,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> BrowserSessionStart:
        """Join the agent's browser to `session`, signed in with `token` or signed out (§6).

        The code is authorized at `{endpoint}/authorize` with the Session header and
        the access token; a code the company refuses there (`invalid_request`) is a
        `BrowserSessionError`, and the agent starts again at step 1.
        """

        endpoint = _https_url(browser_session_endpoint, "browser_session_endpoint")
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        browser = cast(BrowserJoin, first_contribution(self.reactor, BROWSER_JOINS, "browser join"))
        code = await browser.load_join_form(endpoint)
        if len(code.get_secret_value()) < _MIN_CODE_LENGTH:
            raise BrowserSessionError(
                "invalid_join_code", "The join page's code is too short to be one-time"
            )
        try:
            response = await self.transport.request(
                "POST",
                f"{endpoint.rstrip('/')}/authorize",
                session=session,
                token=token,
                headers={"Content-Type": "application/json"},
                content=json.dumps({"code": code.get_secret_value()}).encode(),
            )
        except TransportError as exc:
            raise BrowserSessionError(exc.code, "Authorizing the join code failed") from exc
        if response.status_code != 204:
            raise BrowserSessionError(
                "join_not_authorized",
                "The company refused to authorize the join code",
                status_code=response.status_code,
            )
        await browser.submit_join_form()
        return BrowserSessionStart(endpoint=endpoint, joined_at=clock.now())
