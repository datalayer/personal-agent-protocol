# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    BROWSER_ASSERTION_TYPE,
    BROWSER_FORM_POSTS,
    SIGNERS,
    BrowserSessionClient,
    BrowserSessionError,
    JoseSigner,
    build_browser_assertion_claims,
    build_pap_reactor,
    verify_browser_assertion,
)

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


class Clock:
    def now(self) -> datetime:
        return NOW


class Browser:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, SecretStr]]] = []

    async def post(self, endpoint: str, fields: dict[str, SecretStr]) -> None:
        self.posts.append((endpoint, fields))


class ReplayCache:
    def __init__(self) -> None:
        self.keys: set[str] = set()

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        assert expires_at > NOW
        if key in self.keys:
            return False
        self.keys.add(key)
        return True


class BrowserPlugin:
    def __init__(self, signer: JoseSigner, browser: Browser) -> None:
        self.signer = signer
        self.browser = browser

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(SIGNERS, self.signer, contribution_id="signer")
        contribute(BROWSER_FORM_POSTS, self.browser, contribution_id="browser")


def options() -> dict[str, str]:
    return {
        "client_id": "https://agent.example/agent.json",
        "pairwise_user_id": "usr_example",
        "browser_session_endpoint": "https://shop.example/poppy/browser-session",
        "session_id": "ses_example",
        "return_to": "https://orders.shop.example/current",
        "company_domain": "shop.example",
    }


def test_builds_short_lived_company_bound_claims() -> None:
    claims = build_browser_assertion_claims(
        **options(), now=NOW, random_bytes=lambda length: bytes(range(length))
    )
    assert claims.exp - claims.iat == 60
    assert claims.jti == "jti_AAECAwQFBgcICQoLDA0ODw"
    with pytest.raises(ValueError, match="company domain"):
        build_browser_assertion_claims(
            **{**options(), "return_to": "https://attacker.example/steal"}, now=NOW
        )
    with pytest.raises(ValueError, match="between 1 and 60"):
        build_browser_assertion_claims(**options(), now=NOW, lifetime_seconds=61)


@pytest.mark.asyncio
async def test_posts_and_verifies_browser_assertion_once() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    browser = Browser()
    reactor, owned_http = build_pap_reactor()
    reactor.register_plugin(
        PluginManifest(name="browser-test", version="1"),
        BrowserPlugin(JoseSigner(private_key, key_id="agent-key"), browser),
    )
    # Replace the system clock at a higher priority for deterministic claims.
    from personal_agent_protocol import CLOCKS

    class ClockPlugin:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(CLOCKS, Clock(), contribution_id="fixed", order=0)  # type: ignore[attr-defined]

    reactor.register_plugin(PluginManifest(name="clock-test", version="1"), ClockPlugin())
    started = await BrowserSessionClient(reactor=reactor).join(**options())
    reactor.stop()
    assert owned_http is not None
    await owned_http.aclose()

    assert started.return_to == options()["return_to"]
    assert len(browser.posts) == 1
    endpoint, fields = browser.posts[0]
    assertion = fields["assertion"]
    assert endpoint == options()["browser_session_endpoint"]
    assert jwt.get_unverified_header(assertion.get_secret_value())["typ"] == BROWSER_ASSERTION_TYPE
    assert "assertion=" not in endpoint

    cache = ReplayCache()
    verified = await verify_browser_assertion(
        assertion,
        public_key=private_key.public_key(),
        expected_endpoint=options()["browser_session_endpoint"],
        company_domain=options()["company_domain"],
        expected_client_id=options()["client_id"],
        expected_pairwise_user_id=options()["pairwise_user_id"],
        expected_session_id=options()["session_id"],
        replay_cache=cache,
        now=NOW,
    )
    assert verified.session_id == "ses_example"
    with pytest.raises(BrowserSessionError, match="already been used"):
        await verify_browser_assertion(
            assertion,
            public_key=private_key.public_key(),
            expected_endpoint=options()["browser_session_endpoint"],
            company_domain=options()["company_domain"],
            expected_client_id=options()["client_id"],
            expected_pairwise_user_id=options()["pairwise_user_id"],
            expected_session_id=options()["session_id"],
            replay_cache=cache,
            now=NOW,
        )


@pytest.mark.asyncio
async def test_rejects_wrong_type_owner_and_expiry() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    claims = build_browser_assertion_claims(**options(), now=NOW)
    ordinary = await JoseSigner(private_key).sign(claims.model_dump(), purpose="session_assertion")
    with pytest.raises(BrowserSessionError, match="type is invalid"):
        await verify_browser_assertion(
            ordinary,
            public_key=private_key.public_key(),
            expected_endpoint=options()["browser_session_endpoint"],
            company_domain=options()["company_domain"],
            expected_client_id=options()["client_id"],
            expected_pairwise_user_id=options()["pairwise_user_id"],
            expected_session_id=options()["session_id"],
            replay_cache=ReplayCache(),
            now=NOW,
        )
