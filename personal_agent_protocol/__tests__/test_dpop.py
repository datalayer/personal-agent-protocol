# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""DPoP (§4.5, RFC 9449): the personal agent's proofs, token requests and resources."""

from __future__ import annotations

import hashlib
import json
from base64 import urlsafe_b64encode
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from personal_agent_protocol import (
    CLOCKS,
    DPOP_PROVERS,
    SIGNERS,
    DpopProofRequest,
    InMemoryDpopKeys,
    JoseDpopProver,
    SessionClient,
    SessionError,
    TokenResponse,
    build_pap_reactor,
)
from personal_agent_protocol.cli_host import FileDpopKeys, FileKeyStore
from personal_agent_protocol.crypto import jwk_thumbprint
from personal_agent_protocol.errors import ProofError
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
