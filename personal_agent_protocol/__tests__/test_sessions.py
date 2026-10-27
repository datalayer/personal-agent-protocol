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
    SessionToken,
    TokenResponse,
    build_client_assertion_claims,
    build_session_assertion_claims,
    generate_pairwise_user_id,
)
from personal_agent_protocol.errors import ProtocolValidationError
from personal_agent_protocol.reactor import build_pap_reactor
from personal_agent_protocol.sessions import ClientAssertionClaims

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"
#: A Session Key's thumbprint: 43 base64url characters (RFC 7638, SHA-256).
KEY = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def fixed_random(length: int) -> bytes:
    return bytes(range(length))


def test_generates_random_pairwise_identifier_without_personal_data() -> None:
    identifier = generate_pairwise_user_id(fixed_random)

    assert identifier == "usr_AAECAwQFBgcICQoLDA0ODw"


def test_builds_short_lived_session_assertion_claims() -> None:
    claims = build_session_assertion_claims(
        client_id="https://agent.example/agent.json",
        pairwise_user_id="usr_AAECAwQFBgcICQoLDA0ODw",
        issuer="https://auth.example.com",
        now=datetime(2026, 10, 10, tzinfo=timezone.utc),
        random_bytes=fixed_random,
    )

    assert claims.iss == "https://agent.example/agent.json"
    # The company's auth.issuer, one string, never its token endpoint (§4.2, §9.4).
    assert claims.aud == "https://auth.example.com"
    assert claims.exp - claims.iat == 60
    assert claims.jti == "jti_AAECAwQFBgcICQoLDA0ODw"


def test_a_client_assertion_names_the_issuer_and_lives_at_most_five_minutes() -> None:
    now = datetime(2026, 10, 10, tzinfo=timezone.utc)
    claims = build_client_assertion_claims(
        client_id="https://agent.example/agent.json",
        issuer="https://auth.provider.example/shop-a",
        now=now,
        random_bytes=fixed_random,
    )
    assert (claims.iss, claims.sub) == ("https://agent.example/agent.json",) * 2
    assert claims.aud == "https://auth.provider.example/shop-a"
    assert claims.exp - claims.iat == 60
    longest = build_client_assertion_claims(
        client_id="https://agent.example/agent.json",
        issuer="https://auth.example.com",
        now=now,
        lifetime_seconds=300,
    )
    assert longest.exp - longest.iat == 300
    for build in (build_client_assertion_claims, build_session_assertion_claims):
        extra = {"pairwise_user_id": "usr_x"} if build is build_session_assertion_claims else {}
        with pytest.raises(ValueError, match="300"):
            build(  # type: ignore[operator]
                client_id="https://agent.example/agent.json",
                issuer="https://auth.example.com",
                now=now,
                lifetime_seconds=301,
                **extra,
            )
    with pytest.raises(ValueError, match="five minutes"):
        ClientAssertionClaims(
            iss="https://agent.example/agent.json",
            sub="https://agent.example/agent.json",
            aud="https://auth.example.com",
            iat=1000,
            exp=1301,
            jti="jti_AAECAwQFBgcICQoLDA0ODw",
        )


def test_parses_session_token_as_opaque_secret() -> None:
    payload = json.loads((FIXTURES / "session-token-valid.json").read_text())
    response = TokenResponse.model_validate(payload)
    token = SessionToken.from_response(response, session_key=KEY, signed_in=False)

    assert token.access_token.get_secret_value() == "opaque-session-token"
    # Signed out: no `scope` in the response, and none granted (§4.2).
    assert token.scopes == () and not token.signed_in
    assert "opaque-session-token" not in repr(token)
    assert "opaque-session-token" not in token.model_dump_json()


def test_a_signed_in_response_without_scope_granted_exactly_what_was_asked() -> None:
    response = TokenResponse.model_validate(
        {"access_token": "t", "token_type": "DPoP", "expires_in": 60, "refresh_token": "r"}
    )
    token = SessionToken.from_response(
        response, session_key=KEY, signed_in=True, requested_scopes=("orders:read",)
    )
    assert token.scopes == ("orders:read",)
    # A sign-in grants at least one scope (§4.4).
    with pytest.raises(ProtocolValidationError):
        SessionToken.from_response(response, session_key=KEY, signed_in=True)


class FakeSigner:
    def __init__(self) -> None:
        self.purposes: list[str] = []
        self.claims: list[dict[str, object]] = []

    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        self.purposes.append(purpose)
        self.claims.append(claims)
        return SecretStr(f"signed-{purpose}-{len(self.purposes)}")


class FakeDpopProvider:
    def __init__(self) -> None:
        self.requests: list[DpopProofRequest] = []
        self.made: list[str] = []
        self.discarded: list[str] = []

    async def new_session_key(self, *, tenant_id: str, issuer: str) -> str:
        self.made.append(f"{'k' * 42}{len(self.made)}")
        return self.made[-1]

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr(f"proof-{len(self.requests)}")

    async def discard_session_key(self, *, tenant_id: str, issuer: str, session_key: str) -> None:
        self.discarded.append(session_key)


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
            session_key=started.session_key,
        )
        reactor.stop()

    # A new key starts the Session; the renewal is signed with the same key, which names
    # the Session: nothing else does (§4.3).
    assert started.session_key == renewed.session_key == dpop.made[0]
    assert [request.session_key for request in dpop.requests] == [dpop.made[0]] * 2
    assert all("session_id" not in form and "session_key" not in form for form in forms)
    assert forms[0]["grant_type"] == [JWT_BEARER_GRANT]
    assert not started.signed_in and started.scopes == ()
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

    assert token.session_key == dpop.made[0]
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


WHO = {
    "client_id": "https://agent.example/agent.json",
    "pairwise_user_id": "usr_AAECAwQFBgcICQoLDA0ODw",
    "issuer": "https://auth.example.com",
    "token_endpoint": "https://auth.example.com/oauth/token",
    "tenant_id": "tenant-one",
}


@pytest.mark.asyncio
async def test_both_assertions_name_the_issuer_and_live_one_minute() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=token_response()))
    ) as http:
        reactor, signer, _ = session_reactor(http)
        await SessionClient(reactor=reactor, http_client=http).start(**WHO)
        reactor.stop()
    # aud is the company's auth.issuer, one string, never its token endpoint (§4.1, §4.2).
    assert [claims["aud"] for claims in signer.claims] == ["https://auth.example.com"] * 2
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
            await SessionClient(reactor=reactor, http_client=http).start(**WHO)
        reactor.stop()
    # Nothing is sent to the new URL: no assertion, no proof (§3).
    assert refused.value.code == "redirect_refused" and refused.value.status_code == 307
    assert [str(request.url) for request in sent] == ["https://auth.example.com/oauth/token"]


@pytest.mark.asyncio
async def test_extension_required_and_rate_limited_at_the_token_endpoint_are_read() -> None:
    answers = [
        httpx.Response(403, json={"error": "extension_required", "extension": "operations"}),
        httpx.Response(429, json={"error": "rate_limited"}, headers={"Retry-After": "7"}),
    ]

    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: answers.pop(0))) as http:
        reactor, _, _ = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        with pytest.raises(SessionError) as required:
            await client.start(**WHO)
        with pytest.raises(SessionError) as limited:
            await client.start(**WHO)
        reactor.stop()
    assert (required.value.code, required.value.status_code) == ("extension_required", 403)
    assert required.value.details == {"extension": "operations"}
    assert (limited.value.code, limited.value.details) == ("rate_limited", {"retry_after": "7"})


@pytest.mark.asyncio
async def test_invalid_grant_on_a_renewal_discards_the_key_for_good() -> None:
    answers = [
        httpx.Response(200, json=token_response()),
        httpx.Response(400, json={"error": "invalid_grant"}),
    ]
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: answers.pop(0))) as http:
        reactor, _, dpop = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        started = await client.start(**WHO)
        with pytest.raises(SessionError) as ended:
            await client.renew(**WHO, session_key=started.session_key)
        reactor.stop()
    # The Session has ended: its key is never used again (§4.2).
    assert ended.value.code == "invalid_grant"
    assert dpop.discarded == [started.session_key]


@pytest.mark.asyncio
async def test_an_agent_id_rides_in_the_session_assertion() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=token_response()))
    ) as http:
        reactor, signer, _ = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        await client.start(**WHO, agent_id="agt_shopping")
        await client.start(**WHO)
        reactor.stop()
    sessions = [
        claims
        for claims, purpose in zip(signer.claims, signer.purposes)
        if purpose == "session_assertion"
    ]
    assert sessions[0]["agent_id"] == "agt_shopping"
    assert "agent_id" not in sessions[1]  # an agent with one agent leaves it out (§4.2)


@pytest.mark.asyncio
async def test_a_bearer_token_for_an_mcp_server_comes_from_token_exchange() -> None:
    forms: list[dict[str, list[str]]] = []
    proofs: list[bool] = []
    answers = [
        {**token_response()},
        {
            "access_token": "bearer",
            "token_type": "Bearer",
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "expires_in": 60,
        },
        {"access_token": "dpop", "token_type": "DPoP", "expires_in": 60},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        forms.append(parse_qs(request.content.decode()))
        proofs.append("dpop" in request.headers)
        return httpx.Response(200, json=answers.pop(0))

    mcp = "https://mcp.example.com/mcp"
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        reactor, _, _ = session_reactor(http)
        client = SessionClient(reactor=reactor, http_client=http)
        session = await client.start(**WHO)
        exchange = {key: value for key, value in WHO.items() if key != "pairwise_user_id"}
        bearer = await client.token_for_mcp(
            **exchange,
            session_key=session.session_key,
            subject_token=session.access_token,
            resource=mcp,
        )
        with pytest.raises(SessionError) as wrong:
            # Token Exchange answers with a Bearer token, or it is refused (§4.3).
            await client.token_for_mcp(
                **exchange,
                session_key=session.session_key,
                subject_token=session.access_token,
                resource=mcp,
            )
        reactor.stop()
    assert bearer.token_type == "Bearer" and bearer.session_key == session.session_key
    assert wrong.value.code == "unexpected_token_type"
    # Every token request carries a proof, Token Exchange included (§4.3).
    assert proofs == [True, True, True]
    assert forms[1]["grant_type"] == ["urn:ietf:params:oauth:grant-type:token-exchange"]
    assert forms[1]["subject_token"] == ["opaque-session-token"]
    assert forms[1]["subject_token_type"] == ["urn:ietf:params:oauth:token-type:access_token"]
    assert forms[1]["resource"] == [mcp]
