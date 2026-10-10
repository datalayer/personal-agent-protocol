# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    JWT_BEARER_GRANT,
    JWT_CLIENT_ASSERTION,
    SIGNERS,
    DpopProofRequest,
    SessionClient,
    SessionError,
    SessionGrant,
    SessionToken,
    build_session_assertion_claims,
    generate_pairwise_user_id,
)
from personal_agent_protocol.reactor import build_pap_reactor

FIXTURES = Path(__file__).parents[1] / "protocol" / "fixtures"


def fixed_random(length: int) -> bytes:
    return bytes(range(length))


def test_generates_random_pairwise_identifier_without_personal_data() -> None:
    identifier = generate_pairwise_user_id(fixed_random)

    assert identifier == "usr_AAECAwQFBgcICQoLDA0ODw"


def test_builds_short_lived_session_assertion_claims() -> None:
    claims = build_session_assertion_claims(
        client_id="https://agent.example/agent.json",
        pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
        token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
        now=datetime(2026, 10, 10, tzinfo=timezone.utc),
        random_bytes=fixed_random,
    )

    assert claims.iss == "https://agent.example/agent.json"
    assert claims.aud == "https://auth.example.com/oauth/token"
    assert claims.exp - claims.iat == 60
    assert claims.jti == "jti_AAECAwQFBgcICQoLDA0ODw"


def test_session_grant_redacts_assertions_until_form_serialization() -> None:
    grant = SessionGrant(
        assertion=SecretStr("session-assertion"),
        client_id="https://agent.example/agent.json",
        client_assertion=SecretStr("client-assertion"),
        session_id="ses_2Lm0",
    )

    assert "session-assertion" not in repr(grant)
    assert grant.as_form() == {
        "grant_type": JWT_BEARER_GRANT,
        "assertion": "session-assertion",
        "client_id": "https://agent.example/agent.json",
        "client_assertion_type": JWT_CLIENT_ASSERTION,
        "client_assertion": "client-assertion",
        "session_id": "ses_2Lm0",
    }


def test_parses_session_token_as_opaque_secret() -> None:
    payload = json.loads((FIXTURES / "session-token-valid.json").read_text())
    token = SessionToken.model_validate(payload)

    assert token.access_token.get_secret_value() == "opaque-session-token"
    assert token.scopes == ("poppy:read", "poppy:write")
    assert "opaque-session-token" not in repr(token)
    assert "opaque-session-token" not in token.model_dump_json()


class FakeSigner:
    def __init__(self) -> None:
        self.purposes: list[str] = []

    async def sign(self, _: dict[str, object], *, purpose: str) -> SecretStr:
        self.purposes.append(purpose)
        return SecretStr(f"signed-{purpose}-{len(self.purposes)}")


class FakeDpopProvider:
    def __init__(self) -> None:
        self.requests: list[DpopProofRequest] = []

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr(f"proof-{len(self.requests)}")


class SecurityPlugin:
    def __init__(self, signer: FakeSigner, dpop: FakeDpopProvider) -> None:
        self.signer = signer
        self.dpop = dpop

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(SIGNERS, self.signer, contribution_id="test-signer")
        contribute(DPOP_PROOF_PROVIDERS, self.dpop, contribution_id="test-dpop")


def session_reactor(
    http: httpx.AsyncClient,
) -> tuple[PluginPlatform, FakeSigner, FakeDpopProvider]:
    signer = FakeSigner()
    dpop = FakeDpopProvider()
    reactor, owned = build_pap_reactor(http_client=http)
    assert owned is None
    reactor.register_plugin(
        PluginManifest(name="pap-test-security", version="1"),
        SecurityPlugin(signer, dpop),
    )
    return reactor, signer, dpop


def token_response() -> dict[str, object]:
    return json.loads((FIXTURES / "session-token-valid.json").read_text())


@pytest.mark.asyncio
async def test_starts_and_renews_session_over_http() -> None:
    forms: list[dict[str, list[str]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.headers["dpop"].startswith("proof-")
        forms.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json=token_response())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, signer, dpop = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        started = await client.start(
            client_id="https://agent.example/agent.json",
            pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
            issuer="https://auth.example.com",
            token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
            tenant_id="tenant-one",
        )
        renewed = await client.renew(
            client_id="https://agent.example/agent.json",
            pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
            issuer="https://auth.example.com",
            token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
            tenant_id="tenant-one",
            session_id=started.session_id,
        )
        reactor.stop()

    assert started.session_id == renewed.session_id == "ses_2Lm0"
    assert "session_id" not in forms[0]
    assert forms[1]["session_id"] == ["ses_2Lm0"]
    assert forms[0]["grant_type"] == [JWT_BEARER_GRANT]
    assert signer.purposes == [
        "session_assertion",
        "client_assertion",
        "session_assertion",
        "client_assertion",
    ]
    assert all(request.tenant_id == "tenant-one" for request in dpop.requests)


@pytest.mark.asyncio
async def test_retries_once_with_a_fresh_dpop_nonce_and_assertions() -> None:
    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                400,
                json={"error": "use_dpop_nonce"},
                headers={"DPoP-Nonce": "company-nonce"},
            )
        return httpx.Response(200, json=token_response())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, signer, dpop = session_reactor(http)
        token = await SessionClient(reactor=reactor, http_client=http).start(
            client_id="https://agent.example/agent.json",
            pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
            issuer="https://auth.example.com",
            token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
            tenant_id="tenant-one",
        )
        reactor.stop()

    assert token.session_id == "ses_2Lm0"
    assert [request.nonce for request in dpop.requests] == [None, "company-nonce"]
    assert len(signer.purposes) == 4


@pytest.mark.asyncio
async def test_session_error_never_includes_remote_error_description() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": "invalid_client", "error_description": "secret-token"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, _, _ = session_reactor(http)
        with pytest.raises(SessionError) as caught:
            await SessionClient(reactor=reactor, http_client=http).start(
                client_id="https://agent.example/agent.json",
                pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
                issuer="https://auth.example.com",
                token_endpoint="https://auth.example.com/oauth/token",  # noqa: S106
                tenant_id="tenant-one",
            )
        reactor.stop()

    assert caught.value.code == "invalid_client"
    assert caught.value.status_code == 401
    assert "secret-token" not in str(caught.value)
