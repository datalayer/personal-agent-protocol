# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    SESSION_SIGNERS,
    AccessToken,
    PapSession,
    SessionHttpClient,
    SessionJwtRequest,
    TransportError,
    build_pap_reactor,
)

ORDERS = "https://api.example/orders"
INVALID_SESSION = {"error": "invalid_session"}


class Jwts:
    def __init__(self) -> None:
        self.requests: list[SessionJwtRequest] = []

    async def sign(self, request: SessionJwtRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr(f"jwt-{len(self.requests)}")


class Plugin:
    def __init__(self, jwts: Jwts) -> None:
        self.jwts = jwts

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            SESSION_SIGNERS, self.jwts, contribution_id="session-signer"
        )


def session() -> PapSession:
    return PapSession(
        sid="S" * 22,
        sub="usr_pairwise",
        issuer="https://auth.example",
        client_id="https://agent.example/agent.json",
        tenant_id="tenant",
    )


def token() -> AccessToken:
    return AccessToken(access_token=SecretStr("access-secret"), expires_in=300, scope="orders:read")


@pytest.mark.asyncio
async def test_invalid_session_restarts_once_with_a_fresh_jwt_and_a_redirect_gets_nothing() -> None:
    calls = 0

    def company(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["authorization"] == "Bearer access-secret"
        assert request.headers["poppy-session"] == f"jwt-{calls}"
        assert "dpop" not in request.headers
        if calls == 1:
            return httpx.Response(400, json=INVALID_SESSION)
        if calls == 2:
            return httpx.Response(200, json={"ok": True})
        # Even on the company's own origin, a redirect is never followed with the token,
        # a Session JWT, or the body (§3): the caller sees `redirect_refused`.
        return httpx.Response(307, headers={"Location": "/orders/current"})

    jwts = Jwts()
    pap_session = session()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(jwts))
        client = SessionHttpClient(reactor=reactor, http_client=http)
        response = await client.request("GET", ORDERS, session=pap_session, token=token())
        with pytest.raises(TransportError) as refused:
            await client.request("GET", ORDERS, session=pap_session, token=token())
        reactor.stop()

    assert response.status_code == 200
    assert refused.value.code == "redirect_refused" and refused.value.status_code == 307
    assert calls == 3
    # A new `sid` for the same User, from the moment the first was refused (§5.5, §7).
    sids = [request.sid for request in jwts.requests]
    assert sids[0] == "S" * 22 and sids[1] == sids[2] == pap_session.sid != sids[0]
    assert {request.sub for request in jwts.requests} == {"usr_pairwise"}
    assert [request.url for request in jwts.requests] == [ORDERS] * 3
    assert all(
        request.access_token is not None
        and request.access_token.get_secret_value() == "access-secret"
        for request in jwts.requests
    )


@pytest.mark.asyncio
async def test_a_second_invalid_session_goes_back_to_the_caller() -> None:
    calls = 0

    def company(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400, json=INVALID_SESSION)

    jwts = Jwts()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(jwts))
        client = SessionHttpClient(reactor=reactor, http_client=http)
        response = await client.request("POST", ORDERS, session=session(), content=b"{}")
        reactor.stop()

    # The Personal Agent stops sending the request (§7).
    assert response.status_code == 400 and calls == 2


@pytest.mark.asyncio
async def test_another_400_is_not_invalid_session() -> None:
    calls = 0

    def company(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(400, json={"error": "invalid_request"})

    pap_session = session()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(Jwts()))
        client = SessionHttpClient(reactor=reactor, http_client=http)
        response = await client.request("GET", ORDERS, session=pap_session)
        reactor.stop()

    assert response.status_code == 400 and calls == 1
    assert pap_session.sid == "S" * 22


@pytest.mark.asyncio
async def test_a_stream_restarts_once_on_invalid_session() -> None:
    sent: list[httpx.Request] = []

    def company(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        if len(sent) == 1:
            return httpx.Response(400, json=INVALID_SESSION)
        return httpx.Response(200, text="data: ok\n\n")

    jwts = Jwts()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(jwts))
        client = SessionHttpClient(reactor=reactor, http_client=http)
        async with client.stream("GET", ORDERS, session=session(), token=token()) as response:
            assert response.status_code == 200
        reactor.stop()

    assert [request.headers["poppy-session"] for request in sent] == ["jwt-1", "jwt-2"]
    assert jwts.requests[0].sid != jwts.requests[1].sid


@pytest.mark.asyncio
async def test_signed_out_requests_carry_the_session_header_alone() -> None:
    sent: list[httpx.Request] = []

    def company(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={})

    jwts = Jwts()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(jwts))
        client = SessionHttpClient(reactor=reactor, http_client=http)
        await client.request("GET", ORDERS, session=session())
        reactor.stop()

    assert sent[0].headers["poppy-session"] == "jwt-1"
    assert "authorization" not in sent[0].headers
    assert jwts.requests[0].access_token is None


@pytest.mark.asyncio
async def test_refuses_cross_origin_redirect_and_protected_headers() -> None:
    calls = 0

    def company(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(307, headers={"Location": "https://attacker.example/collect"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(Jwts()))
        client = SessionHttpClient(reactor=reactor, http_client=http)
        with pytest.raises(TransportError, match="redirect_refused"):
            await client.request("GET", ORDERS, session=session(), token=token())
        for name, value in (
            ("Authorization", "Bearer attacker-controlled"),
            ("Poppy-Session", "attacker-controlled"),
        ):
            with pytest.raises(TransportError, match="host-owned"):
                await client.request(
                    "GET", ORDERS, session=session(), token=token(), headers={name: value}
                )
        reactor.stop()
    assert calls == 1
