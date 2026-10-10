# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import asyncio
from datetime import datetime, timezone
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    AUTHORIZATION_STATE_STORES,
    BROWSER_HANDOFFS,
    DPOP_PROOF_PROVIDERS,
    SIGNERS,
    AuthorizationCodeGrant,
    AuthorizationError,
    DirectSignInClient,
    DirectSignInRequest,
    DpopProofRequest,
    build_direct_sign_in_request,
    validate_direct_sign_in_callback,
)
from personal_agent_protocol.reactor import build_pap_reactor


def fixed_random(length: int) -> bytes:
    return bytes(range(length))


def request() -> DirectSignInRequest:
    return build_direct_sign_in_request(
        authorization_endpoint="https://auth.example.com/oauth/authorize",
        issuer="https://auth.example.com",
        client_id="https://agent.example/agent.json",
        redirect_uri="https://agent.example/oauth/callback",
        scopes=("poppy:read", "poppy:write"),
        random_bytes=fixed_random,
    )


def callback_url(**overrides: str) -> str:
    sign_in = request()
    values = {
        "code": "one-time-code",
        "state": sign_in.state.get_secret_value(),
        "iss": sign_in.issuer,
        **overrides,
    }
    return urlunsplit(("https", "agent.example", "/oauth/callback", urlencode(values), ""))


def test_builds_direct_sign_in_url_with_s256_pkce() -> None:
    sign_in = request()
    values = parse_qs(urlsplit(sign_in.authorization_url.get_secret_value()).query)

    assert values["response_type"] == ["code"]
    assert values["scope"] == ["poppy:read poppy:write"]
    assert values["code_challenge_method"] == ["S256"]
    assert len(sign_in.code_verifier.get_secret_value()) == 43
    assert sign_in.state.get_secret_value() not in repr(sign_in)


def test_validates_callback_and_redacts_code_exchange() -> None:
    sign_in = request()
    callback = validate_direct_sign_in_callback(sign_in, callback_url())
    grant = AuthorizationCodeGrant(
        code=callback.code,
        redirect_uri=sign_in.redirect_uri,
        code_verifier=sign_in.code_verifier,
        session_id="ses_2Lm0",
        client_id=sign_in.client_id,
        client_assertion=SecretStr("signed-client-assertion"),
    )

    assert grant.as_form()["code"] == "one-time-code"
    assert "one-time-code" not in repr(grant)
    assert "signed-client-assertion" not in grant.model_dump_json()


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"state": "attacker-state"}, "state_mismatch"),
        ({"iss": "https://attacker.example"}, "issuer_mismatch"),
        ({"code": ""}, "invalid_callback"),
        ({"error": "access_denied", "code": ""}, "authorization_denied"),
    ],
)
def test_rejects_invalid_callbacks(override: dict[str, str], code: str) -> None:
    with pytest.raises(AuthorizationError) as caught:
        validate_direct_sign_in_callback(request(), callback_url(**override))

    assert caught.value.code == code


def test_rejects_weak_entropy() -> None:
    with pytest.raises(AuthorizationError, match="weak_entropy"):
        build_direct_sign_in_request(
            authorization_endpoint="https://auth.example.com/oauth/authorize",
            issuer="https://auth.example.com",
            client_id="https://agent.example/agent.json",
            redirect_uri="https://agent.example/oauth/callback",
            scopes=("poppy:read",),
            random_bytes=lambda _: b"short",
        )


def test_rejects_duplicate_callback_security_parameters() -> None:
    sign_in = request()
    callback = callback_url() + "&state=second-state"

    with pytest.raises(AuthorizationError) as caught:
        validate_direct_sign_in_callback(sign_in, callback)

    assert caught.value.code == "invalid_callback"


def test_rejects_callback_at_another_redirect_location() -> None:
    with pytest.raises(AuthorizationError) as caught:
        validate_direct_sign_in_callback(
            request(), callback_url().replace("/oauth/callback", "/other/callback")
        )

    assert caught.value.code == "redirect_mismatch"


class MemoryAuthorizationStateStore:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    async def put(self, reference: str, value: object, *, expires_at: datetime) -> None:
        assert expires_at.tzinfo is not None
        self.values[reference] = value

    async def take(self, reference: str) -> object | None:
        return self.values.pop(reference, None)


class Browser:
    def __init__(self) -> None:
        self.urls: list[SecretStr] = []

    async def open(self, authorization_url: SecretStr) -> None:
        self.urls.append(authorization_url)


class Signer:
    def __init__(self) -> None:
        self.calls = 0

    async def sign(self, _: dict[str, object], *, purpose: str) -> SecretStr:
        assert purpose == "client_assertion"
        self.calls += 1
        return SecretStr(f"client-assertion-{self.calls}")


class Dpop:
    def __init__(self) -> None:
        self.requests: list[DpopProofRequest] = []

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr(f"dpop-{len(self.requests)}")


class DirectSignInPlugin:
    def __init__(self) -> None:
        self.state = MemoryAuthorizationStateStore()
        self.browser = Browser()
        self.signer = Signer()
        self.dpop = Dpop()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(AUTHORIZATION_STATE_STORES, self.state, contribution_id="memory")
        contribute(BROWSER_HANDOFFS, self.browser, contribution_id="browser")
        contribute(SIGNERS, self.signer, contribution_id="signer")
        contribute(DPOP_PROOF_PROVIDERS, self.dpop, contribution_id="dpop")


def callback_from_browser(browser: Browser, **overrides: str) -> str:
    authorization_url = browser.urls[-1].get_secret_value()
    state = dict(parse_qsl(urlsplit(authorization_url).query))["state"]
    values = {
        "code": "one-time-code",
        "state": state,
        "iss": "https://auth.example.com",
        **overrides,
    }
    return urlunsplit(("https", "agent.example", "/oauth/callback", urlencode(values), ""))


async def begin_direct_sign_in(
    client: DirectSignInClient,
    plugin: DirectSignInPlugin,
) -> str:
    started = await client.begin(
        authorization_endpoint="https://auth.example.com/oauth/authorize",
        token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
        issuer="https://auth.example.com",
        client_id="https://agent.example/agent.json",
        redirect_uri="https://agent.example/oauth/callback",
        scopes=("poppy:read", "poppy:write"),
        tenant_id="application-one",
        pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
        session_id="ses_existing",
    )
    assert started.expires_at > datetime.now(timezone.utc)
    assert started.requested_scopes == ("poppy:read", "poppy:write")
    assert len(plugin.browser.urls) == 1
    return callback_from_browser(plugin.browser)


def test_orchestrates_one_use_direct_sign_in_with_nonce_and_partial_scopes() -> None:
    async def scenario() -> None:
        forms: list[dict[str, str]] = []
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            forms.append(dict(parse_qsl(request.content.decode())))
            assert request.headers["dpop"] == f"dpop-{calls}"
            if calls == 1:
                return httpx.Response(
                    400,
                    json={"error": "use_dpop_nonce"},
                    headers={"DPoP-Nonce": "company-nonce"},
                )
            return httpx.Response(
                200,
                json={
                    "access_token": "signed-in-session-token",
                    "token_type": "DPoP",
                    "expires_in": 300,
                    "scope": "poppy:read",
                    "session_id": "ses_existing",
                    "signed_in": True,
                    "refresh_token": "account-token",
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            reactor, owned = build_pap_reactor(http_client=http)
            assert owned is None
            plugin = DirectSignInPlugin()
            reactor.register_plugin(
                PluginManifest(name="pap-test-direct", version="1"),
                plugin,
            )
            client = DirectSignInClient(reactor=reactor, http_client=http)
            callback = await begin_direct_sign_in(client, plugin)
            result = await client.complete(callback)
            with pytest.raises(AuthorizationError) as reused:
                await client.complete(callback)
            reactor.stop()

        assert reused.value.code == "invalid_or_expired_state"
        assert result.token.access_token.get_secret_value() == "signed-in-session-token"
        assert result.granted_scopes == ("poppy:read",)
        assert result.missing_scopes == ("poppy:write",)
        assert [item.nonce for item in plugin.dpop.requests] == [None, "company-nonce"]
        assert forms[0]["session_id"] == forms[1]["session_id"] == "ses_existing"
        assert forms[0]["code_verifier"] == forms[1]["code_verifier"]
        assert forms[0]["client_assertion"] != forms[1]["client_assertion"]

    asyncio.run(scenario())


def test_direct_sign_in_denial_consumes_state_without_exposing_remote_text() -> None:
    async def scenario() -> None:
        async with httpx.AsyncClient() as http:
            reactor, owned = build_pap_reactor(http_client=http)
            assert owned is None
            plugin = DirectSignInPlugin()
            reactor.register_plugin(
                PluginManifest(name="pap-test-direct-denial", version="1"),
                plugin,
            )
            client = DirectSignInClient(reactor=reactor, http_client=http)
            await begin_direct_sign_in(client, plugin)
            denied = callback_from_browser(
                plugin.browser,
                error="access_denied",
                error_description="private company detail",
                code="",
            )
            with pytest.raises(AuthorizationError) as caught:
                await client.complete(denied)
            with pytest.raises(AuthorizationError) as reused:
                await client.complete(denied)
            reactor.stop()

        assert caught.value.code == "authorization_denied"
        assert "private company detail" not in str(caught.value)
        assert reused.value.code == "invalid_or_expired_state"

    asyncio.run(scenario())
