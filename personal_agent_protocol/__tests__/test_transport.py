# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    DpopHttpClient,
    DpopProofRequest,
    SessionToken,
    TransportError,
    build_pap_reactor,
)


class Proofs:
    def __init__(self) -> None:
        self.requests: list[DpopProofRequest] = []

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr(f"proof-{len(self.requests)}")


class Plugin:
    def __init__(self, proofs: Proofs) -> None:
        self.proofs = proofs

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            DPOP_PROOF_PROVIDERS, self.proofs, contribution_id="proofs"
        )


def token() -> SessionToken:
    return SessionToken(
        access_token=SecretStr("session-secret"),
        token_type="DPoP",  # noqa: S106 - OAuth token type, not a password
        expires_in=300,
        session_key="K" * 43,
        signed_in=True,
        scope="orders:read",
    )


@pytest.mark.asyncio
async def test_nonce_retry_uses_a_fresh_proof_and_a_redirect_gets_nothing() -> None:
    calls = 0

    def company(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["authorization"] == "DPoP session-secret"
        assert request.headers["dpop"] == f"proof-{calls}"
        if calls == 1:
            return httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
                    "DPoP-Nonce": "company-nonce",
                },
            )
        if calls == 2:
            return httpx.Response(200, json={"ok": True})
        # Even on the company's own origin, a redirect is never followed with the token,
        # a proof, or the body (§3): the caller sees `redirect_refused`.
        return httpx.Response(307, headers={"Location": "/orders/current"})

    proofs = Proofs()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(proofs))
        client = DpopHttpClient(reactor=reactor, http_client=http)
        response = await client.request(
            "GET",
            "https://api.example/orders",
            token=token(),
            tenant_id="tenant",
            issuer="https://auth.example",
        )
        with pytest.raises(TransportError) as refused:
            await client.request(
                "GET",
                "https://api.example/orders",
                token=token(),
                tenant_id="tenant",
                issuer="https://auth.example",
            )
        reactor.stop()

    assert response.status_code == 200
    assert refused.value.code == "redirect_refused" and refused.value.status_code == 307
    assert [request.nonce for request in proofs.requests] == [None, "company-nonce", None]
    assert [request.url for request in proofs.requests] == ["https://api.example/orders"] * 3
    assert calls == 3
    assert all(
        request.access_token is not None
        and request.access_token.get_secret_value() == "session-secret"
        for request in proofs.requests
    )


@pytest.mark.asyncio
async def test_refuses_cross_origin_redirect_and_protected_headers() -> None:
    calls = 0

    def company(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(307, headers={"Location": "https://attacker.example/collect"})

    proofs = Proofs()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="transport-test", version="1"), Plugin(proofs))
        client = DpopHttpClient(reactor=reactor, http_client=http)
        with pytest.raises(TransportError, match="redirect_refused"):
            await client.request(
                "GET",
                "https://api.example/orders",
                token=token(),
                tenant_id="tenant",
                issuer="https://auth.example",
            )
        with pytest.raises(TransportError, match="host-owned"):
            await client.request(
                "GET",
                "https://api.example/orders",
                token=token(),
                tenant_id="tenant",
                issuer="https://auth.example",
                headers={"Authorization": "Bearer attacker-controlled"},
            )
        reactor.stop()
    assert calls == 1
