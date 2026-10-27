# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

from datetime import datetime, timezone

import jwt
import pytest
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    BROWSER_JOINS,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    BrowserSessionClient,
    BrowserSessionError,
    InMemorySessionKeys,
    JoseDpopProofProvider,
    build_pap_reactor,
    verify_dpop_proof,
)

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)
ENDPOINT = "https://shop.example/poppy/browser-session"
ISSUER = "https://shop.example"
CODE = "bc_Vn3qT8xLw2Rk9mZ4yHc1Ad"


class Clock:
    def now(self) -> datetime:
        return NOW


class Browser:
    """The agent's own browser: the page it loaded holds the code; it submits the proof."""

    def __init__(self, code: str = CODE) -> None:
        self.code = code
        self.loaded: list[str] = []
        self.submitted: list[SecretStr] = []

    async def load_join_form(self, endpoint: str) -> SecretStr:
        self.loaded.append(endpoint)
        return SecretStr(self.code)

    async def submit_join_form(self, proof: SecretStr) -> None:
        self.submitted.append(proof)


class ReplayCache:
    def __init__(self) -> None:
        self.keys: set[str] = set()

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        if key in self.keys:
            return False
        self.keys.add(key)
        return True


class Plugin:
    def __init__(self, browser: Browser, provider: JoseDpopProofProvider) -> None:
        self.browser = browser
        self.provider = provider

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(BROWSER_JOINS, self.browser, contribution_id="browser")
        contribute(DPOP_PROOF_PROVIDERS, self.provider, contribution_id="keys")
        contribute(CLOCKS, Clock(), contribution_id="fixed", order=0)


async def joined(browser: Browser) -> tuple[str, Browser]:
    provider = JoseDpopProofProvider(InMemorySessionKeys(), now=lambda: NOW)
    reactor, owned_http = build_pap_reactor()
    reactor.register_plugin(
        PluginManifest(name="browser-test", version="1"), Plugin(browser, provider)
    )
    session_key = await provider.new_session_key(tenant_id="t", issuer=ISSUER)
    try:
        await BrowserSessionClient(reactor=reactor).join(
            browser_session_endpoint=ENDPOINT, tenant_id="t", issuer=ISSUER, session_key=session_key
        )
    finally:
        reactor.stop()
        assert owned_http is not None
        await owned_http.aclose()
    return session_key, browser


@pytest.mark.asyncio
async def test_signs_the_pages_code_with_the_session_key_and_submits_it() -> None:
    session_key, browser = await joined(Browser())
    assert browser.loaded == [ENDPOINT] and len(browser.submitted) == 1
    proof = browser.submitted[0]
    payload = jwt.decode(proof.get_secret_value(), options={"verify_signature": False})
    # POST to the endpoint, the code as its nonce, no `ath`: no Session Token (§5).
    assert (payload["htm"], payload["htu"], payload["nonce"]) == ("POST", ENDPOINT, CODE)
    assert "ath" not in payload
    verified = await verify_dpop_proof(
        proof, method="POST", url=ENDPOINT, replay_cache=ReplayCache(), nonce=CODE, now=NOW
    )
    # Signed with the Session's own key, which names it (§4.3).
    assert verified.key_thumbprint == session_key


@pytest.mark.asyncio
async def test_a_proof_over_another_code_is_refused() -> None:
    _, browser = await joined(Browser())
    with pytest.raises(Exception, match="nonce"):
        await verify_dpop_proof(
            browser.submitted[0],
            method="POST",
            url=ENDPOINT,
            replay_cache=ReplayCache(),
            nonce="bc_someone_elses_code_000000",
            now=NOW,
        )


@pytest.mark.asyncio
async def test_a_code_too_short_to_be_one_time_is_never_signed() -> None:
    with pytest.raises(BrowserSessionError) as refused:
        await joined(Browser(code="short"))
    assert refused.value.code == "invalid_join_code"
