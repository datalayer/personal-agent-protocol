# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Sessions, client assertions, and plain OAuth token responses (§4, §5)."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from personal_agent_protocol import (
    SESSION_SIGNERS,
    SIGNERS,
    AccessToken,
    PapSession,
    SessionClient,
    SessionError,
    SessionHttpClient,
    SessionJwtRequest,
    TokenResponse,
    build_client_assertion_claims,
    generate_pairwise_user_id,
)
from personal_agent_protocol.errors import ProtocolValidationError
from personal_agent_protocol.reactor import build_pap_reactor
from personal_agent_protocol.sessions import (
    JWT_CLIENT_ASSERTION,
    ClientAssertionClaims,
    new_session_id,
)

CLIENT_ID = "https://agent.example/agent.json"
ISSUER = "https://auth.example.com"
TOKEN_ENDPOINT = "https://auth.example.com/oauth/token"
PAIRWISE = "usr_AAECAwQFBgcICQoLDA0ODw"
WHO = {
    "client_id": CLIENT_ID,
    "pairwise_user_id": PAIRWISE,
    "issuer": ISSUER,
    "tenant_id": "tenant-one",
}


def fixed_random(length: int) -> bytes:
    return bytes(range(length))


def test_generates_random_pairwise_identifier_without_personal_data() -> None:
    identifier = generate_pairwise_user_id(fixed_random)

    assert identifier == "usr_AAECAwQFBgcICQoLDA0ODw"


def test_a_client_assertion_names_the_issuer_and_lives_at_most_five_minutes() -> None:
    now = datetime(2026, 10, 10, tzinfo=timezone.utc)
    claims = build_client_assertion_claims(
        client_id=CLIENT_ID,
        issuer="https://auth.provider.example/shop-a",
        now=now,
        random_bytes=fixed_random,
    )
    assert (claims.iss, claims.sub) == (CLIENT_ID, CLIENT_ID)
    assert claims.aud == "https://auth.provider.example/shop-a"
    assert claims.exp - claims.iat == 60
    assert claims.jti == "AAECAwQFBgcICQoLDA0ODw"
    longest = build_client_assertion_claims(
        client_id=CLIENT_ID, issuer=ISSUER, now=now, lifetime_seconds=300
    )
    assert longest.exp - longest.iat == 300
    with pytest.raises(ValueError, match="300"):
        build_client_assertion_claims(
            client_id=CLIENT_ID, issuer=ISSUER, now=now, lifetime_seconds=301
        )
    with pytest.raises(ValueError, match="five minutes"):
        ClientAssertionClaims(
            iss=CLIENT_ID,
            sub=CLIENT_ID,
            aud=ISSUER,
            iat=1000,
            exp=1301,
            jti="jti_AAECAwQFBgcICQoLDA0ODw",
        )


def test_parses_an_access_token_as_opaque_secret() -> None:
    response = TokenResponse.model_validate(
        {
            "access_token": "opaque-access-token",
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": "orders:read orders:write",
        }
    )
    token = AccessToken.from_response(response)

    # `token_type` is compared ignoring case (RFC 6749 §5.1).
    assert token.token_type == "Bearer"
    assert token.access_token.get_secret_value() == "opaque-access-token"
    assert token.scopes == ("orders:read", "orders:write")
    assert token.resource is None
    assert "opaque-access-token" not in repr(token)
    assert "opaque-access-token" not in token.model_dump_json()


def test_a_signed_in_response_without_scope_granted_exactly_what_was_asked() -> None:
    response = TokenResponse.model_validate(
        {"access_token": "t", "token_type": "Bearer", "expires_in": 60, "refresh_token": "r"}
    )
    token = AccessToken.from_response(response, requested_scopes=("orders:read",))
    assert token.scopes == ("orders:read",)
    # A sign-in grants at least one scope (§4.7).
    with pytest.raises(ProtocolValidationError):
        AccessToken.from_response(response)


def test_an_access_token_remembers_the_service_it_was_issued_for() -> None:
    response = TokenResponse.model_validate(
        {"access_token": "t", "token_type": "Bearer", "scope": "orders:read"}
    )
    mcp = "https://mcp.example.com/mcp"
    assert AccessToken.from_response(response, resource=mcp).resource == mcp


@pytest.mark.parametrize("token_type", ["DPoP", "dpop", "mac"])
def test_a_token_response_is_bearer(token_type: str) -> None:
    with pytest.raises(ValueError):
        TokenResponse.model_validate({"access_token": "t", "token_type": token_type})


class FakeSigner:
    def __init__(self) -> None:
        self.purposes: list[str] = []
        self.claims: list[dict[str, object]] = []

    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        self.purposes.append(purpose)
        self.claims.append(claims)
        return SecretStr(f"signed-{purpose}-{len(self.purposes)}")


class FakeSessionSigner:
    def __init__(self) -> None:
        self.requests: list[SessionJwtRequest] = []

    async def sign(self, request: SessionJwtRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr(f"session-jwt-{len(self.requests)}")


class SecurityPlugin:
    def __init__(self, signer: FakeSigner, session_signer: FakeSessionSigner) -> None:
        self.signer = signer
        self.session_signer = session_signer

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(SIGNERS, self.signer, contribution_id="test-signer")
        contribute(SESSION_SIGNERS, self.session_signer, contribution_id="test-session-signer")


def session_reactor(
    http: httpx.AsyncClient,
) -> tuple[PluginPlatform, FakeSigner, FakeSessionSigner]:
    signer = FakeSigner()
    session_signer = FakeSessionSigner()
    reactor, owned = build_pap_reactor(http_client=http)
    assert owned is None
    reactor.register_plugin(
        PluginManifest(name="pap-test-security", version="1"),
        SecurityPlugin(signer, session_signer),
    )
    return reactor, signer, session_signer


def token_response() -> dict[str, object]:
    return {"access_token": "opaque-access-token", "token_type": "Bearer", "expires_in": 3600}


async def refresh(client: SessionClient) -> TokenResponse:
    """One grant at the token endpoint, as a sign-in or a refresh sends it."""

    return await client.token_request(
        client_id=CLIENT_ID,
        issuer=ISSUER,
        token_endpoint=TOKEN_ENDPOINT,
        form=lambda: {"grant_type": "refresh_token", "refresh_token": "refresh-secret"},
        error=SessionError,
    )


@pytest.mark.asyncio
async def test_a_session_starts_with_no_request_and_a_new_random_sid() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(500)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, signer, session_signer = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        first = await client.start(**WHO)
        second = await client.start(**WHO)
        reactor.stop()

    # Local: nothing is asked of the company, and nothing is signed yet (§5.2).
    assert sent == [] and signer.purposes == [] and session_signer.requests == []
    assert first.sid != second.sid and len(first.sid) >= 22
    assert (first.sub, first.issuer, first.client_id) == (PAIRWISE, ISSUER, CLIENT_ID)
    assert first.tenant_id == "tenant-one" and first.agent_id is None
    assert first.handle == f"ses_{first.sid}"
    assert PapSession.from_json(first.to_json()) == first


def test_a_session_id_is_at_least_128_random_bits() -> None:
    assert new_session_id(fixed_random) == "AAECAwQFBgcICQoLDA0ODw"
    with pytest.raises(ValueError, match="128 random bits"):
        new_session_id(lambda _: b"short")
    with pytest.raises(ValueError, match="Session ID"):
        PapSession(
            sid="short", sub=PAIRWISE, issuer=ISSUER, client_id=CLIENT_ID, tenant_id="tenant-one"
        )


@pytest.mark.asyncio
async def test_a_new_session_replaces_an_ended_one_for_the_same_user() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as http:
        reactor, _, _ = session_reactor(http)
        session = await SessionClient(reactor=reactor, http_client=http).start(
            **WHO, agent_id="agt_shopping"
        )
        reactor.stop()
    ended = session.sid
    session.restart(fixed_random)
    # The Session has ended: its `sid` is never used again (§5.5).
    assert session.sid == "AAECAwQFBgcICQoLDA0ODw" != ended
    assert (session.sub, session.agent_id) == (PAIRWISE, "agt_shopping")


@pytest.mark.asyncio
async def test_the_token_endpoint_gets_a_client_assertion_and_no_session() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json=token_response())

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, _, session_signer = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        response = await refresh(client)
        await refresh(client)
        reactor.stop()

    assert response.access_token.get_secret_value() == "opaque-access-token"
    forms = [parse_qs(request.content.decode()) for request in sent]
    assert forms[0]["grant_type"] == ["refresh_token"]
    assert forms[0]["client_id"] == [CLIENT_ID]
    assert forms[0]["client_assertion_type"] == [JWT_CLIENT_ASSERTION]
    # A fresh assertion for each request; no Session header at an OAuth endpoint (§5.2).
    assert [form["client_assertion"] for form in forms] == [
        ["signed-client_assertion-1"],
        ["signed-client_assertion-2"],
    ]
    assert session_signer.requests == []
    assert all("poppy-session" not in request.headers for request in sent)
    assert all("dpop" not in request.headers for request in sent)


@pytest.mark.asyncio
async def test_a_dpop_token_type_is_refused_at_the_token_endpoint() -> None:
    answer = {"access_token": "key-bound-secret", "token_type": "DPoP", "expires_in": 60}
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=answer))
    ) as http:
        reactor, _, _ = session_reactor(http)
        with pytest.raises(SessionError) as refused:
            await refresh(SessionClient(reactor=reactor, http_client=http))
        reactor.stop()
    assert refused.value.code == "unsupported_token_type"
    assert refused.value.status_code == 200
    assert "key-bound-secret" not in str(refused.value)


@pytest.mark.asyncio
async def test_a_malformed_token_response_is_not_a_token_type_refusal() -> None:
    answer = {"access_token": "t", "token_type": "mac"}
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=answer))
    ) as http:
        reactor, _, _ = session_reactor(http)
        with pytest.raises(SessionError) as refused:
            await refresh(SessionClient(reactor=reactor, http_client=http))
        reactor.stop()
    assert refused.value.code == "invalid_token_response"


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
            await refresh(SessionClient(reactor=reactor, http_client=http))
        reactor.stop()

    assert caught.value.code == "invalid_client"
    assert caught.value.status_code == 401
    assert "secret-token" not in str(caught.value)


@pytest.mark.asyncio
async def test_a_client_assertion_names_the_issuer_and_lives_one_minute() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=token_response()))
    ) as http:
        reactor, signer, _ = session_reactor(http)
        await refresh(SessionClient(reactor=reactor, http_client=http))
        reactor.stop()
    # aud is the company's issuer, one string, never its token endpoint (§4.1).
    assert [claims["aud"] for claims in signer.claims] == [ISSUER]
    assert all(claims["exp"] - claims["iat"] == 60 for claims in signer.claims)  # type: ignore[operator]


@pytest.mark.asyncio
async def test_a_redirect_at_the_token_endpoint_gets_nothing() -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(307, headers={"Location": "https://elsewhere.example/token"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, _, _ = session_reactor(http)
        with pytest.raises(SessionError) as refused:
            await refresh(SessionClient(reactor=reactor, http_client=http))
        reactor.stop()
    # Nothing is sent to the new URL: no assertion, no refresh token (§3).
    assert refused.value.code == "redirect_refused" and refused.value.status_code == 307
    assert [str(request.url) for request in sent] == [TOKEN_ENDPOINT]


@pytest.mark.asyncio
async def test_extension_required_and_rate_limited_at_the_token_endpoint_are_read() -> None:
    answers = [
        httpx.Response(403, json={"error": "extension_required", "extension": "operations"}),
        # A 429 has `Retry-After` and no body (§5.6).
        httpx.Response(429, headers={"Retry-After": "7"}),
    ]

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: answers.pop(0))) as http:
        reactor, _, _ = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        with pytest.raises(SessionError) as required:
            await refresh(client)
        with pytest.raises(SessionError) as limited:
            await refresh(client)
        reactor.stop()
    assert (required.value.code, required.value.status_code) == ("extension_required", 403)
    assert required.value.details == {"extension": "operations"}
    assert (limited.value.code, limited.value.details) == ("rate_limited", {"retry_after": "7"})


@pytest.mark.asyncio
async def test_an_agent_id_rides_in_the_session() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, _, session_signer = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        transport = SessionHttpClient(reactor=reactor, http_client=http)
        for agent_id in ("agt_shopping", None):
            session = await client.start(**WHO, agent_id=agent_id)
            await transport.request("GET", "https://shop.example/api/orders", session=session)
        reactor.stop()
    # An agent with one agent leaves it out (§5.2).
    assert [request.agent_id for request in session_signer.requests] == ["agt_shopping", None]
    assert [request.sub for request in session_signer.requests] == [PAIRWISE, PAIRWISE]
    assert [request.headers["poppy-session"] for request in seen] == [
        "session-jwt-1",
        "session-jwt-2",
    ]
