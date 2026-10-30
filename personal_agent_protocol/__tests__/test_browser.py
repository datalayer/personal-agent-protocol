# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timezone

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    BROWSER_JOINS,
    CLOCKS,
    SESSION_SIGNERS,
    AccessToken,
    BrowserSessionClient,
    BrowserSessionError,
    DelegatedSessionSigner,
    InMemoryDelegatedKeys,
    JoseSigner,
    PapSession,
    SessionHttpClient,
    build_pap_reactor,
)
from personal_agent_protocol.crypto import token_hash

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
ENDPOINT = "https://shop.example/poppy/browser-session"
AUTHORIZE = f"{ENDPOINT}/authorize"
ISSUER = "https://shop.example"
CODE = "bc_Vn3qT8xLw2Rk9mZ4yHc1Ad"
SESSION = PapSession(
    sid="S" * 22,
    sub="usr_pairwise",
    issuer=ISSUER,
    client_id="https://agent.example/agent.json",
    tenant_id="t",
)


class Clock:
    def now(self) -> datetime:
        return NOW


class Browser:
    """The agent's own browser: the page it loaded holds the code; it submits the form."""

    def __init__(self, code: str = CODE) -> None:
        self.code = code
        self.loaded: list[str] = []
        self.submitted = 0

    async def load_join_form(self, endpoint: str) -> SecretStr:
        self.loaded.append(endpoint)
        return SecretStr(self.code)

    async def submit_join_form(self) -> None:
        self.submitted += 1


class Plugin:
    def __init__(self, browser: Browser) -> None:
        self.browser = browser
        self.session_signer = DelegatedSessionSigner(
            InMemoryDelegatedKeys(),
            signer=JoseSigner(ec.generate_private_key(ec.SECP256R1()), key_id="agent-key"),
            now=lambda: NOW,
        )

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(BROWSER_JOINS, self.browser, contribution_id="browser")
        contribute(SESSION_SIGNERS, self.session_signer, contribution_id="delegated-keys")
        contribute(CLOCKS, Clock(), contribution_id="fixed", order=0)


def authorized(_: httpx.Request) -> httpx.Response:
    return httpx.Response(204)


async def joined(
    browser: Browser,
    *,
    company: Callable[[httpx.Request], httpx.Response] = authorized,
    token: AccessToken | None = None,
) -> list[httpx.Request]:
    sent: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return company(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(recording)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="browser-test", version="1"), Plugin(browser))
        try:
            await BrowserSessionClient(
                reactor=reactor,
                transport=SessionHttpClient(reactor=reactor, http_client=http),
            ).join(browser_session_endpoint=ENDPOINT, session=SESSION, token=token)
        finally:
            reactor.stop()
    return sent


@pytest.mark.asyncio
async def test_the_agent_authorizes_the_pages_code_and_the_browser_submits_the_form() -> None:
    browser = Browser()
    sent = await joined(browser)

    assert browser.loaded == [ENDPOINT] and browser.submitted == 1
    assert [(request.method, str(request.url)) for request in sent] == [("POST", AUTHORIZE)]
    assert json.loads(sent[0].content) == {"code": CODE}
    payload = jwt.decode(sent[0].headers["poppy-session"], options={"verify_signature": False})
    # Signed out: the Session header alone, with no `ath` (§6).
    assert (payload["htm"], payload["htu"], payload["sid"]) == ("POST", AUTHORIZE, SESSION.sid)
    assert "ath" not in payload and "authorization" not in sent[0].headers


@pytest.mark.asyncio
async def test_signed_in_the_access_token_goes_with_the_agents_own_request() -> None:
    token = AccessToken(access_token=SecretStr("access-secret"), scope="orders:read")
    browser = Browser()
    sent = await joined(browser, token=token)

    assert sent[0].headers["authorization"] == "Bearer access-secret"
    payload = jwt.decode(sent[0].headers["poppy-session"], options={"verify_signature": False})
    assert payload["ath"] == token_hash(token.access_token)
    assert browser.submitted == 1


@pytest.mark.asyncio
async def test_a_code_the_company_refuses_is_never_submitted() -> None:
    browser = Browser()
    with pytest.raises(BrowserSessionError) as refused:
        await joined(
            browser,
            company=lambda _: httpx.Response(400, json={"error": "invalid_request"}),
        )
    assert (refused.value.code, refused.value.status_code) == ("join_not_authorized", 400)
    assert browser.submitted == 0


@pytest.mark.asyncio
async def test_a_code_too_short_to_be_one_time_is_never_signed() -> None:
    browser = Browser(code="short")
    sent: list[httpx.Request] = []

    def company(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(204)

    with pytest.raises(BrowserSessionError) as refused:
        await joined(browser, company=company)
    assert refused.value.code == "invalid_join_code"
    assert sent == [] and browser.submitted == 0
