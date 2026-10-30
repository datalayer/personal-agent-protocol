# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""DPoP (§4.5, RFC 9449): the personal agent's proofs, token requests and resources."""

from __future__ import annotations

import hashlib
import json
from base64 import urlsafe_b64encode
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from personal_agent_protocol import (
    CLOCKS,
    DEVICE_CODE_GRANT,
    DPOP_PROVERS,
    PROTECTED_INPUTS,
    SESSION_SIGNERS,
    SIGNERS,
    AccessToken,
    AuthorizationError,
    DpopProofRequest,
    InMemoryDpopKeys,
    JoseDpopProver,
    MediatedSignInClient,
    PapSession,
    SessionClient,
    SessionError,
    SessionHttpClient,
    SessionJwtRequest,
    TokenResponse,
    TransportError,
    build_pap_reactor,
)
from personal_agent_protocol.cli_host import FileDpopKeys, FileKeyStore
from personal_agent_protocol.company import CompanyConfig, MemoryReplayCache
from personal_agent_protocol.company.verify import verify_dpop_proof
from personal_agent_protocol.conformance import ConformanceContext, SignedIn
from personal_agent_protocol.crypto import jwk_thumbprint, new_dpop_key, token_hash
from personal_agent_protocol.demo.conformance import MANZANITA_SCENARIO, ManzanitaConformance
from personal_agent_protocol.demo.kit import ScriptedInput
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE, CONFIG
from personal_agent_protocol.errors import ProofError
from personal_agent_protocol.mcp import McpSessionAuth
from personal_agent_protocol.reactor import first_contribution

ISSUER = "https://shop.example"
NOW = datetime(2026, 10, 30, 12, tzinfo=timezone.utc)


def _proof_request(**changes: object) -> DpopProofRequest:
    values: dict[str, object] = {
        "method": "post",
        "url": "https://shop.example/api/orders?page=2#top",
        "tenant_id": "tenant",
        "issuer": ISSUER,
    }
    return DpopProofRequest(**{**values, **changes})  # type: ignore[arg-type]


def _read(proof: SecretStr) -> tuple[dict[str, object], dict[str, object]]:
    compact = proof.get_secret_value()
    header = jwt.get_unverified_header(compact)
    key = jwt.PyJWK.from_dict(header["jwk"], algorithm="ES256").key  # type: ignore[arg-type]
    return header, jwt.decode(compact, key, algorithms=["ES256"], options={"verify_iat": False})


@pytest.mark.asyncio
async def test_a_proof_has_the_header_and_claims_of_rfc_9449() -> None:
    prover = JoseDpopProver(InMemoryDpopKeys(), now=lambda: NOW)
    header, claims = _read(await prover.prove(_proof_request()))
    assert header["typ"] == "dpop+jwt" and header["alg"] == "ES256"
    assert set(header["jwk"]) == {"kty", "crv", "x", "y"}  # type: ignore[arg-type]
    assert set(claims) == {"jti", "htm", "htu", "iat"}
    assert claims["htm"] == "POST"
    assert claims["htu"] == "https://shop.example/api/orders"
    assert claims["iat"] == int(NOW.timestamp())
    assert len(str(claims["jti"])) >= 22


@pytest.mark.asyncio
async def test_ath_goes_with_an_access_token_and_nonce_when_given() -> None:
    prover = JoseDpopProver(InMemoryDpopKeys(), now=lambda: NOW)
    token = SecretStr("access-secret")
    _, claims = _read(await prover.prove(_proof_request(access_token=token, nonce="n-1")))
    digest = hashlib.sha256(b"access-secret").digest()
    assert claims["ath"] == urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert claims["nonce"] == "n-1"


@pytest.mark.asyncio
async def test_one_key_per_company_for_a_tenant_and_a_new_jti_for_each_proof() -> None:
    keys = InMemoryDpopKeys()
    prover = JoseDpopProver(keys, now=lambda: NOW)

    async def key_of(**changes: object) -> tuple[str, object]:
        header, claims = _read(await prover.prove(_proof_request(**changes)))
        return jwk_thumbprint(header["jwk"]), claims["jti"]  # type: ignore[arg-type]

    first, jti = await key_of()
    same, other_jti = await key_of()
    assert first == same and jti != other_jti
    assert first != (await key_of(tenant_id="other"))[0]
    assert first != (await key_of(issuer="https://other.example"))[0]
    assert len(keys) == 3
    await keys.forget(tenant_id="tenant", issuer=ISSUER)
    assert first != (await key_of())[0]


@pytest.mark.asyncio
async def test_a_proof_needs_128_random_bits_and_a_timezone() -> None:
    weak = JoseDpopProver(InMemoryDpopKeys(), now=lambda: NOW, random_bytes=lambda _: b"short")
    with pytest.raises(ProofError) as short:
        await weak.prove(_proof_request())
    assert short.value.code == "weak_randomness"
    naive = JoseDpopProver(InMemoryDpopKeys(), now=lambda: NOW.replace(tzinfo=None))
    with pytest.raises(ProofError) as clock:
        await naive.prove(_proof_request())
    assert clock.value.code == "invalid_clock"


@pytest.mark.asyncio
async def test_the_default_prover_reads_the_hosts_clock_when_it_signs() -> None:
    class Stopped:
        def now(self) -> datetime:
            return NOW

    class Host:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(CLOCKS, Stopped(), contribution_id="host", order=10)  # type: ignore[attr-defined]

    platform, owned = build_pap_reactor(
        http_client=httpx.AsyncClient(),
        plugins=[(PluginManifest(name="host", version="1"), Host())],
    )
    try:
        prover = first_contribution(platform, DPOP_PROVERS, "DPoP prover")
        assert isinstance(prover, JoseDpopProver)
        _, claims = _read(await prover.prove(_proof_request()))
    finally:
        platform.stop()
    assert claims["iat"] == int(NOW.timestamp()) and owned is None


@pytest.mark.asyncio
async def test_the_cli_keeps_its_dpop_keys_in_the_key_file(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    keys = FileDpopKeys(FileKeyStore(path))
    first = await keys.key_for(tenant_id="t", issuer=ISSUER)
    again = await FileDpopKeys(FileKeyStore(path)).key_for(tenant_id="t", issuer=ISSUER)
    assert first.thumbprint == again.thumbprint
    assert isinstance(again.private_key, ec.EllipticCurvePrivateKey)
    assert "d" not in first.public_jwk
    assert path.stat().st_mode & 0o077 == 0
    assert json.loads(path.read_text())["dpop"].keys() == {f"t|{ISSUER}"}
    await keys.forget(tenant_id="t", issuer=ISSUER)
    assert (await keys.key_for(tenant_id="t", issuer=ISSUER)).thumbprint != first.thumbprint


# Token requests ---------------------------------------------------------------------


class _Signer:
    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        return SecretStr(f"assertion-{claims['jti']}")


class _Host:
    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(SIGNERS, _Signer(), contribution_id="agent")  # type: ignore[attr-defined]


def _sessions(http: httpx.AsyncClient) -> tuple[SessionClient, PluginPlatform]:
    platform, _ = build_pap_reactor(
        http_client=http, plugins=[(PluginManifest(name="host", version="1"), _Host())]
    )
    return SessionClient(reactor=platform, http_client=http), platform


TOKEN_ENDPOINT = f"{ISSUER}/oauth/token"
ISSUED = {"access_token": "at", "token_type": "DPoP", "expires_in": 60}


async def _token_request(
    answers: Callable[[httpx.Request], httpx.Response], algs: list[str] | None
) -> tuple[TokenResponse, list[httpx.Request]]:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return answers(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client, platform = _sessions(http)
        try:
            response = await client.token_request(
                client_id="https://agent.example/agent.json",
                issuer=ISSUER,
                token_endpoint=TOKEN_ENDPOINT,
                form=lambda: {"grant_type": "refresh_token", "refresh_token": "rt"},
                error=SessionError,
                tenant_id="tenant",
                dpop_signing_algs=algs,
            )
        finally:
            platform.stop()
    return response, sent


@pytest.mark.asyncio
@pytest.mark.parametrize("algs", [["ES256"], ["RS256", "ES256"]])
async def test_a_token_request_proves_when_the_issuer_lists_es256(algs: list[str]) -> None:
    response, sent = await _token_request(lambda _: httpx.Response(200, json=ISSUED), algs)
    assert response.token_type == "DPoP"
    _, claims = _read(SecretStr(sent[0].headers["dpop"]))
    assert claims["htm"] == "POST" and claims["htu"] == TOKEN_ENDPOINT
    assert "ath" not in claims and "nonce" not in claims


@pytest.mark.asyncio
@pytest.mark.parametrize("algs", [None, [], ["RS256"], ["es256"]])
async def test_a_token_request_sends_no_proof_to_a_company_that_does_not_list_es256(
    algs: list[str] | None,
) -> None:
    answer = {**ISSUED, "token_type": "Bearer"}
    _, sent = await _token_request(lambda _: httpx.Response(200, json=answer), algs)
    assert "dpop" not in sent[0].headers


@pytest.mark.asyncio
async def test_bearer_after_a_proof_is_the_companys_choice() -> None:
    answer = {**ISSUED, "token_type": "Bearer"}
    response, sent = await _token_request(lambda _: httpx.Response(200, json=answer), ["ES256"])
    assert response.token_type == "Bearer" and "dpop" in sent[0].headers


@pytest.mark.asyncio
async def test_dpop_with_no_proof_sent_is_refused() -> None:
    with pytest.raises(SessionError) as refused:
        await _token_request(lambda _: httpx.Response(200, json=ISSUED), ["RS256"])
    assert refused.value.code == "unsupported_token_type"
    assert "at" not in str(refused.value).split()


@pytest.mark.asyncio
async def test_use_dpop_nonce_is_retried_once_with_a_fresh_proof_and_assertion() -> None:
    def answers(request: httpx.Request) -> httpx.Response:
        if "nonce" in _read(SecretStr(request.headers["dpop"]))[1]:
            return httpx.Response(200, json=ISSUED)
        body = {"error": "use_dpop_nonce"}
        return httpx.Response(400, json=body, headers={"DPoP-Nonce": "n-1"})

    response, sent = await _token_request(answers, ["ES256"])
    assert response.token_type == "DPoP" and len(sent) == 2
    first, second = (_read(SecretStr(item.headers["dpop"]))[1] for item in sent)
    assert first["jti"] != second["jti"] and second["nonce"] == "n-1"
    assertions = [parse_qs(item.content.decode())["client_assertion"] for item in sent]
    assert assertions[0] != assertions[1]


@pytest.mark.asyncio
async def test_a_second_use_dpop_nonce_is_refused_and_not_retried_again() -> None:
    def answers(_: httpx.Request) -> httpx.Response:
        body = {"error": "use_dpop_nonce"}
        return httpx.Response(400, json=body, headers={"DPoP-Nonce": "n-again"})

    sent: list[httpx.Request] = []

    def counted(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return answers(request)

    with pytest.raises(SessionError) as refused:
        await _token_request(counted, ["ES256"])
    assert refused.value.code == "use_dpop_nonce" and len(sent) == 2


@pytest.mark.asyncio
async def test_use_dpop_nonce_with_no_proof_sent_is_not_retried() -> None:
    sent: list[httpx.Request] = []

    def answers(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        body = {"error": "use_dpop_nonce"}
        return httpx.Response(400, json=body, headers={"DPoP-Nonce": "n-1"})

    with pytest.raises(SessionError) as refused:
        await _token_request(answers, None)
    assert refused.value.code == "use_dpop_nonce" and len(sent) == 1


# Resources --------------------------------------------------------------------------

ORDERS = "https://shop.example/api/orders"
BOUND = AccessToken(access_token=SecretStr("bound-token"), token_type="DPoP", scope="orders:read")  # noqa: S106
PLAIN = AccessToken(access_token=SecretStr("plain-token"), scope="orders:read")


def _session() -> PapSession:
    return PapSession(
        sid="S" * 22,
        sub="usr_pairwise",
        issuer=ISSUER,
        client_id="https://agent.example/agent.json",
        tenant_id="tenant",
    )


class _Jwts:
    def __init__(self) -> None:
        self.requests: list[SessionJwtRequest] = []

    async def sign(self, request: SessionJwtRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr(f"jwt-{len(self.requests)}")


class _ResourceHost:
    def __init__(self, jwts: _Jwts) -> None:
        self.jwts = jwts

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            SESSION_SIGNERS, self.jwts, contribution_id="session-signer"
        )


def _world(
    answers: Callable[[httpx.Request], httpx.Response],
) -> tuple[SessionHttpClient, list[httpx.Request], _Jwts, httpx.AsyncClient, PluginPlatform]:
    sent: list[httpx.Request] = []
    jwts = _Jwts()

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return answers(request)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    platform, _ = build_pap_reactor(
        http_client=http,
        plugins=[(PluginManifest(name="host", version="1"), _ResourceHost(jwts))],
    )
    return SessionHttpClient(reactor=platform, http_client=http), sent, jwts, http, platform


def _challenge_nonce(request: httpx.Request) -> httpx.Response:
    if _read(SecretStr(request.headers["dpop"]))[1].get("nonce") == "n-1":
        return httpx.Response(200, json={}, headers={"DPoP-Nonce": "n-2"})
    return httpx.Response(
        401,
        json={"error": "use_dpop_nonce"},
        headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "n-1"},
    )


@pytest.mark.asyncio
async def test_a_dpop_token_goes_with_a_proof_and_the_session_header() -> None:
    client, sent, jwts, http, platform = _world(lambda _: httpx.Response(200, json={}))
    await client.request("GET", f"{ORDERS}?page=2", session=_session(), token=BOUND)
    platform.stop()
    await http.aclose()
    request = sent[0]
    assert request.headers["authorization"] == "DPoP bound-token"
    assert request.headers["poppy-session"] == "jwt-1"
    _, claims = _read(SecretStr(request.headers["dpop"]))
    assert claims["htu"] == ORDERS and claims["htm"] == "GET"
    assert claims["ath"] == token_hash(BOUND.access_token)
    assert jwts.requests[0].access_token == BOUND.access_token


@pytest.mark.asyncio
async def test_a_bearer_token_and_a_signed_out_request_carry_no_proof() -> None:
    client, sent, _, http, platform = _world(lambda _: httpx.Response(200, json={}))
    await client.request("GET", ORDERS, session=_session(), token=PLAIN)
    await client.request("GET", ORDERS, session=_session())
    platform.stop()
    await http.aclose()
    assert sent[0].headers["authorization"] == "Bearer plain-token"
    assert all("dpop" not in request.headers for request in sent)


@pytest.mark.asyncio
async def test_a_resource_nonce_is_retried_once_and_the_latest_kept_for_the_origin() -> None:
    client, sent, jwts, http, platform = _world(_challenge_nonce)
    answered = await client.request("GET", ORDERS, session=_session(), token=BOUND)
    assert answered.status_code == 200 and len(sent) == 2
    first, second = (_read(SecretStr(item.headers["dpop"]))[1] for item in sent)
    assert first["jti"] != second["jti"] and "nonce" not in first and second["nonce"] == "n-1"
    # A fresh Session JWT too.
    assert [item.headers["poppy-session"] for item in sent] == ["jwt-1", "jwt-2"]
    assert len(jwts.requests) == 2
    # The latest nonce, from the success, goes with the next request to the origin.
    assert client.dpop_nonces == {"https://shop.example:443": "n-2"}
    client.dpop_nonces["https://shop.example:443"] = "n-1"
    await client.request("GET", f"{ORDERS}/1", session=_session(), token=BOUND)
    assert len(sent) == 3
    assert _read(SecretStr(sent[2].headers["dpop"]))[1]["nonce"] == "n-1"
    platform.stop()
    await http.aclose()


@pytest.mark.asyncio
async def test_a_second_nonce_challenge_is_returned_to_the_caller() -> None:
    def always(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": "use_dpop_nonce"},
            headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "n-3"},
        )

    client, sent, _, http, platform = _world(always)
    answered = await client.request("GET", ORDERS, session=_session(), token=BOUND)
    platform.stop()
    await http.aclose()
    assert answered.status_code == 401 and len(sent) == 2


@pytest.mark.asyncio
async def test_a_bearer_token_ignores_a_nonce_challenge() -> None:
    client, sent, _, http, platform = _world(_challenge_nonce_for_bearer)
    answered = await client.request("GET", ORDERS, session=_session(), token=PLAIN)
    platform.stop()
    await http.aclose()
    assert answered.status_code == 401 and len(sent) == 1 and client.dpop_nonces == {}


def _challenge_nonce_for_bearer(_: httpx.Request) -> httpx.Response:
    return httpx.Response(
        401,
        headers={"WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "n-1"},
    )


@pytest.mark.asyncio
async def test_a_stream_retries_a_nonce_with_a_fresh_proof() -> None:
    client, sent, _, http, platform = _world(_challenge_nonce)
    async with client.stream("GET", ORDERS, session=_session(), token=BOUND) as response:
        assert response.status_code == 200
    platform.stop()
    await http.aclose()
    assert len(sent) == 2
    assert sent[0].headers["dpop"] != sent[1].headers["dpop"]
    assert client.dpop_nonces == {"https://shop.example:443": "n-2"}


@pytest.mark.asyncio
async def test_a_restarted_session_sends_a_fresh_proof_and_a_redirect_is_refused() -> None:
    answers = iter(
        [
            httpx.Response(400, json={"error": "invalid_session"}),
            httpx.Response(302, headers={"Location": "https://elsewhere.example/"}),
        ]
    )
    client, sent, _, http, platform = _world(lambda _: next(answers))
    with pytest.raises(TransportError) as refused:
        await client.request("GET", ORDERS, session=_session(), token=BOUND)
    platform.stop()
    await http.aclose()
    assert refused.value.code == "redirect_refused" and len(sent) == 2
    assert sent[0].headers["dpop"] != sent[1].headers["dpop"]


@pytest.mark.asyncio
async def test_the_dpop_header_stays_the_hosts() -> None:
    client, sent, _, http, platform = _world(lambda _: httpx.Response(200, json={}))
    with pytest.raises(TransportError) as refused:
        await client.request(
            "GET", ORDERS, session=_session(), token=BOUND, headers={"DPoP": "forged"}
        )
    platform.stop()
    await http.aclose()
    assert refused.value.code == "protected_header" and sent == []


@pytest.mark.asyncio
async def test_mcp_sends_a_proof_and_retries_a_nonce_once() -> None:
    url = "https://shop.example/mcp"
    token = BOUND.model_copy(update={"resource": url})
    client, sent, _, http, platform = _world(_challenge_nonce)
    auth = McpSessionAuth(url, session=_session(), token=token, reactor=platform)
    await http.send(http.build_request("POST", url, content=b"{}"), auth=auth)
    assert len(sent) == 2
    assert sent[1].headers["authorization"] == "DPoP bound-token"
    assert _read(SecretStr(sent[1].headers["dpop"]))[1]["nonce"] == "n-1"
    assert auth.dpop_nonce == "n-2"
    platform.stop()
    await http.aclose()
    assert client.dpop_nonces == {}


# The reference company --------------------------------------------------------------


def _config(**changes: object) -> CompanyConfig:
    return replace(CONFIG, **changes)  # type: ignore[arg-type]


def _binding(monkeypatch: pytest.MonkeyPatch, **changes: object) -> ManzanitaConformance:
    monkeypatch.setattr("personal_agent_protocol.demo.conformance.world_config", lambda _: changes)
    return ManzanitaConformance("a-test-world")


async def _signed_in(ctx: ConformanceContext) -> SignedIn:
    user = ctx.new_user()
    return await ctx.sign_in(user, await ctx.session(user))


def test_nonces_need_binding_and_binding_is_one_of_three() -> None:
    with pytest.raises(ValueError, match="dpop_nonces need"):
        _config(dpop_nonces=True)
    with pytest.raises(ValueError, match="dpop_binding is"):
        _config(dpop_binding="sometimes")


@pytest.mark.asyncio
async def test_by_default_nothing_is_listed_and_a_proof_changes_nothing() -> None:
    world = ManzanitaConformance()
    ctx = world.context()
    assert (await ctx.metadata()).dpop_signing_alg_values_supported is None
    signed = await _signed_in(ctx)
    assert signed.token.token_type == "Bearer"
    url = ctx.url(MANZANITA_SCENARIO.read_path)
    headers = await ctx.auth(signed.session, "GET", url, signed.token)
    assert headers["Authorization"].startswith("Bearer ") and "DPoP" not in headers
    assert (await ctx.send("GET", url, headers=headers)).status_code == 200
    headers = await ctx.auth(signed.session, "GET", url, signed.token)
    headers["Authorization"] = headers["Authorization"].replace("Bearer", "DPoP")
    refused = await ctx.send("GET", url, headers=headers)
    assert refused.status_code == 401
    assert refused.headers["www-authenticate"] == 'Bearer error="invalid_token"'


@pytest.mark.asyncio
async def test_optional_binds_with_a_proof_and_issues_bearer_without(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _binding(monkeypatch, dpop_binding="optional")
    ctx = world.context()
    assert (await ctx.metadata()).dpop_signing_alg_values_supported == ["ES256"]
    bound = await _signed_in(ctx)
    assert bound.token.token_type == "DPoP"
    # No proof, because the host read nothing from the metadata: a Bearer token.
    context = replace(await ctx.account_context("anyone"), dpop_signing_algs=None)
    plain = await ctx.agent.accounts.refresh(bound.reference, context=context)
    token = plain.token
    assert token is not None and token.token_type == "Bearer"
    url = ctx.url(MANZANITA_SCENARIO.read_path)
    used = await ctx.agent.transport.request("GET", url, session=bound.session, token=token)
    assert used.status_code == 200
    # An unbound token sent as DPoP: every scheme the resource takes is challenged.
    headers = await ctx.auth(bound.session, "GET", url, token)
    headers["Authorization"] = headers["Authorization"].replace("Bearer", "DPoP")
    refused = await ctx.send("GET", url, headers=headers)
    assert refused.status_code == 401
    assert refused.headers["www-authenticate"] == (
        'Bearer error="invalid_token", DPoP error="invalid_token"'
    )


@pytest.mark.asyncio
async def test_required_challenges_dpop_alone_signed_out_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _binding(monkeypatch, dpop_binding="required")
    ctx = world.context()
    session = await ctx.session(ctx.new_user())
    url = ctx.url(MANZANITA_SCENARIO.read_path)
    refused = await ctx.send("GET", url, headers=await ctx.auth(session, "GET", url))
    assert refused.status_code == 401
    assert refused.headers["www-authenticate"].startswith("DPoP scope=")


@pytest.mark.asyncio
async def test_a_refused_proof_spends_no_device_code(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _binding(monkeypatch, dpop_binding="required")
    ctx = world.context()
    metadata = await ctx.metadata()
    device = ctx.agent.device
    started = await device.begin(
        device_authorization_endpoint=str(metadata.device_authorization_endpoint),
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=ctx.agent.identity.client_id,
        scopes=MANZANITA_SCENARIO.scopes,
        tenant_id=ctx.tenant_id,
        organization=(await ctx.company()).document.organization,
        protected_resources=metadata.protected_resources,
    )
    await ctx.driver.approve_device(started.user_code, account=ctx.driver.accounts[0])
    await ctx.driver.wait(started.poll_interval)
    # The host forgot the metadata, so no proof went.
    with pytest.raises(AuthorizationError) as refused:
        await device.poll(started.reference)
    assert refused.value.code == "invalid_dpop_proof"
    # A proof with a bad signature, at the token endpoint directly: the code stays good.
    pending = await ctx.agent.vault.take(started.reference)
    device_code = pending.device_code.get_secret_value()
    form = {
        "grant_type": DEVICE_CODE_GRANT,
        "device_code": device_code,
        **(await ctx.client_form()),
    }
    good = jwt.encode(
        {"jti": "j" * 22, "htm": "POST", "htu": metadata.token_endpoint, "iat": 0},
        (key := new_dpop_key()).private_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": key.public_jwk},
    )
    stale = await ctx.token_request(form, dpop=good)
    assert stale.status_code == 400 and stale.json()["error"] == "invalid_dpop_proof"
    form = {**form, **(await ctx.client_form())}
    prover = first_contribution(ctx.agent.reactor, DPOP_PROVERS, "DPoP prover")
    proof = await cast(JoseDpopProver, prover).prove(
        DpopProofRequest(
            method="POST",
            url=metadata.token_endpoint,
            tenant_id=ctx.tenant_id,
            issuer=metadata.issuer,
        )
    )
    await ctx.driver.wait(started.poll_interval)
    issued = await ctx.token_request(form, dpop=proof.get_secret_value())
    assert issued.status_code == 200 and issued.json()["token_type"] == "DPoP"


@pytest.mark.asyncio
async def test_a_mediated_sign_in_binds_its_token(monkeypatch: pytest.MonkeyPatch) -> None:
    world = _binding(monkeypatch, dpop_binding="required", dpop_nonces=True)
    ctx = world.context()
    company = await ctx.company()
    typed = first_contribution(ctx.agent.reactor, PROTECTED_INPUTS, "protected input")
    cast(ScriptedInput, typed).answers.extend([dict(ADA), {"code": ADA_CODE}])
    client = MediatedSignInClient(reactor=ctx.agent.reactor, http_client=ctx.http)
    started = await client.sign_in(
        company=company,
        client_id=ctx.agent.identity.client_id,
        scopes=("orders:read",),
        tenant_id=ctx.tenant_id,
    )
    assert started.status == "code_required" and started.reference is not None
    done = await client.submit_code(started.reference)
    assert done.token is not None
    assert done.token.token_type == "DPoP"


@pytest.mark.asyncio
async def test_a_repeated_dpop_header_is_refused_at_the_asgi_door(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _binding(monkeypatch, dpop_binding="required")
    ctx = world.context()
    signed = await _signed_in(ctx)
    url = ctx.url(MANZANITA_SCENARIO.read_path)
    headers = await ctx.auth(signed.session, "GET", url, signed.token)
    proof = headers.pop("DPoP")
    twice = [*headers.items(), ("DPoP", proof), ("DPoP", proof)]
    request = httpx.Request("GET", url, headers=twice)
    answer = await ctx.http.send(request)
    assert answer.status_code == 401 and answer.json()["error"] == "invalid_dpop_proof"


@pytest.mark.asyncio
async def test_a_private_key_or_another_curve_in_a_proof_is_refused() -> None:
    now = NOW
    private = new_dpop_key()
    leaky = {**private.public_jwk, "d": "AAAA"}
    other = ec.generate_private_key(ec.SECP384R1())
    other_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(other.public_key()))
    claims = {"jti": "j" * 22, "htm": "GET", "htu": ORDERS, "iat": int(now.timestamp())}
    cases = [
        jwt.encode(
            claims,
            private.private_key,
            algorithm="ES256",
            headers={"typ": "dpop+jwt", "jwk": leaky},
        ),
        jwt.encode(claims, other, algorithm="ES384", headers={"typ": "dpop+jwt", "jwk": other_jwk}),
        jwt.encode(claims, "s" * 32, algorithm="HS256", headers={"typ": "dpop+jwt"}),
    ]
    for proof in cases:
        with pytest.raises(ProofError) as refused:
            await verify_dpop_proof(
                proof,
                method="GET",
                url=ORDERS,
                replay_cache=MemoryReplayCache(),
                now=now,
                window=timedelta(seconds=60),
            )
        assert refused.value.code == "invalid_dpop_proof"
