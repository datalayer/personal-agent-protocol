# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""DPoP (§4.5, RFC 9449): the personal agent's proofs, token requests and resources."""

from __future__ import annotations

import hashlib
import json
from base64 import urlsafe_b64encode
from datetime import datetime, timezone
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr

from personal_agent_protocol import (
    DPOP_PROVERS,
    DpopProofRequest,
    InMemoryDpopKeys,
    JoseDpopProver,
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
    from reactor import PluginManifest

    from personal_agent_protocol import CLOCKS

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
