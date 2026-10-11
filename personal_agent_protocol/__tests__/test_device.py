# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    AUTHORIZATION_STATE_STORES,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    SIGNERS,
    TOKEN_STORES,
    AuthorizationError,
    DeviceSignInClient,
    DpopProofRequest,
)
from personal_agent_protocol.reactor import build_pap_reactor


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 10, 10, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class MemoryState:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    async def put(self, reference: str, value: object, *, expires_at: datetime) -> None:
        assert expires_at.tzinfo is not None
        self.values[reference] = value

    async def take(self, reference: str) -> object | None:
        return self.values.pop(reference, None)


class MemoryTokens:
    def __init__(self) -> None:
        self.values: dict[str, SecretStr] = {}

    async def put(self, reference: str, token: SecretStr) -> None:
        self.values[reference] = token

    async def get(self, reference: str) -> SecretStr | None:
        return self.values.get(reference)

    async def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


class Signer:
    async def sign(self, _: dict[str, object], *, purpose: str) -> SecretStr:
        assert purpose == "client_assertion"
        return SecretStr("signed-client-assertion")


class Dpop:
    def __init__(self) -> None:
        self.requests: list[DpopProofRequest] = []

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr("proof")


class DevicePlugin:
    def __init__(self) -> None:
        self.clock = MutableClock()
        self.state = MemoryState()
        self.tokens = MemoryTokens()
        self.dpop = Dpop()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(CLOCKS, self.clock, contribution_id="mutable")
        contribute(AUTHORIZATION_STATE_STORES, self.state, contribution_id="memory")
        contribute(TOKEN_STORES, self.tokens, contribution_id="memory")
        contribute(SIGNERS, Signer(), contribution_id="signer")
        contribute(DPOP_PROOF_PROVIDERS, self.dpop, contribution_id="dpop")


def test_device_sign_in_paces_polling_and_protects_tokens() -> None:
    async def scenario() -> None:
        calls = 0
        forms: list[dict[str, str]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            form = dict(parse_qsl(request.content.decode()))
            forms.append(form)
            if calls == 1:
                assert "DPoP" not in request.headers
                return httpx.Response(
                    200,
                    json={
                        "device_code": "private-device-code",
                        "user_code": "WDJB-MJHT",
                        "verification_uri": "https://company.example/device",
                        "verification_uri_complete": "https://company.example/device?user_code=WDJB-MJHT",
                        "expires_in": 600,
                        "interval": 5,
                    },
                )
            assert request.headers["DPoP"] == "proof"
            if calls == 2:
                return httpx.Response(400, json={"error": "authorization_pending"})
            if calls == 3:
                return httpx.Response(400, json={"error": "slow_down"})
            return httpx.Response(
                200,
                json={
                    "access_token": "signed-in-session-token",
                    "token_type": "DPoP",
                    "expires_in": 300,
                    "scope": "poppy:read",
                    "session_id": "ses_existing",
                    "signed_in": True,
                    "refresh_token": "private-account-token",
                },
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            reactor, _ = build_pap_reactor(http_client=http)
            plugin = DevicePlugin()
            reactor.register_plugin(PluginManifest(name="pap-test-device", version="1"), plugin)
            client = DeviceSignInClient(reactor=reactor, http_client=http)
            started = await client.begin(
                device_authorization_endpoint="https://auth.example.com/oauth/device",
                token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
                issuer="https://auth.example.com",
                client_id="https://agent.example/agent.json",
                scopes=("poppy:read", "poppy:write"),
                tenant_id="application-one",
                pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
                session_id="ses_existing",
            )
            assert started.user_code == "WDJB-MJHT"
            assert "private-device-code" not in started.model_dump_json()
            assert calls == 1

            early = await client.poll(started.reference)
            assert early.status == "pending"
            assert calls == 1
            plugin.clock.advance(5)
            pending = await client.poll(started.reference)
            assert pending.retry_at == plugin.clock.now() + timedelta(seconds=5)
            plugin.clock.advance(5)
            slowed = await client.poll(started.reference)
            assert slowed.retry_at == plugin.clock.now() + timedelta(seconds=10)
            plugin.clock.advance(10)
            complete = await client.poll(started.reference)
            reactor.stop()

        assert complete.status == "complete"
        assert complete.granted_scopes == ("poppy:read",)
        assert complete.missing_scopes == ("poppy:write",)
        assert complete.token is not None and complete.token.refresh_token is None
        assert complete.account_token_reference is not None
        stored = plugin.tokens.values[complete.account_token_reference]
        assert stored.get_secret_value() == "private-account-token"
        assert forms[0]["scope"] == "poppy:read poppy:write"
        assert all(form.get("device_code") == "private-device-code" for form in forms[1:])
        assert len(plugin.dpop.requests) == 3

    asyncio.run(scenario())


def test_device_sign_in_denial_is_terminal() -> None:
    async def scenario() -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/device"):
                return httpx.Response(
                    200,
                    json={
                        "device_code": "private-device-code",
                        "user_code": "ABCD-EFGH",
                        "verification_uri": "https://company.example/device",
                        "expires_in": 60,
                        "interval": 1,
                    },
                )
            return httpx.Response(
                400,
                json={"error": "access_denied", "error_description": "private detail"},
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            reactor, _ = build_pap_reactor(http_client=http)
            plugin = DevicePlugin()
            reactor.register_plugin(
                PluginManifest(name="pap-test-device-denial", version="1"), plugin
            )
            client = DeviceSignInClient(reactor=reactor, http_client=http)
            started = await client.begin(
                device_authorization_endpoint="https://auth.example.com/oauth/device",
                token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
                issuer="https://auth.example.com",
                client_id="https://agent.example/agent.json",
                scopes=("poppy:read",),
                tenant_id="application-one",
                pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
                session_id="ses_existing",
            )
            plugin.clock.advance(1)
            with pytest.raises(AuthorizationError) as caught:
                await client.poll(started.reference)
            with pytest.raises(AuthorizationError) as reused:
                await client.poll(started.reference)
            reactor.stop()

        assert caught.value.code == "access_denied"
        assert "private detail" not in str(caught.value)
        assert reused.value.code == "invalid_or_expired_device_session"

    asyncio.run(scenario())
