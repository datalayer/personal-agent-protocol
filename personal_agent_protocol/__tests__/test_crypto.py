# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

from datetime import datetime, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import SecretStr

from personal_agent_protocol import (
    DpopKeyMaterial,
    DpopProofRequest,
    JoseDpopProofProvider,
    JoseSigner,
    ProofError,
    verify_dpop_proof,
)

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


class ReplayCache:
    def __init__(self) -> None:
        self.keys: set[str] = set()

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        assert expires_at > NOW
        if key in self.keys:
            return False
        self.keys.add(key)
        return True


@pytest.mark.parametrize("algorithm", ["ES256", "RS256"])
@pytest.mark.asyncio
async def test_signs_and_verifies_only_asymmetric_pap_assertions(algorithm: str) -> None:
    private_key: ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey
    if algorithm == "ES256":
        private_key = ec.generate_private_key(ec.SECP256R1())
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = JoseSigner(private_key, algorithm=algorithm, key_id="agent-key")  # type: ignore[arg-type]

    compact = (await signer.sign({"sub": "user"}, purpose="test")).get_secret_value()

    assert jwt.get_unverified_header(compact) == {
        "alg": algorithm,
        "kid": "agent-key",
        "typ": "JWT",
    }
    assert jwt.decode(compact, private_key.public_key(), algorithms=[algorithm]) == {"sub": "user"}


def test_rejects_symmetric_and_none_algorithms() -> None:
    with pytest.raises(ValueError, match="ES256 or RS256"):
        JoseSigner(b"secret", algorithm="HS256")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ES256 or RS256"):
        JoseSigner(None, algorithm="none")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_creates_and_verifies_bound_dpop_proof_once() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)

    async def resolve(_: DpopProofRequest) -> DpopKeyMaterial:
        return DpopKeyMaterial(private_key, public_jwk)

    provider = JoseDpopProofProvider(
        resolve,
        now=lambda: NOW,
        random_bytes=lambda length: bytes(range(length)),
    )
    access_token = SecretStr("opaque-token")
    proof = await provider.create(
        DpopProofRequest(
            method="post",
            url="https://api.example/orders?tracking=secret#fragment",
            tenant_id="tenant-one",
            subject="usr_one",
            issuer="https://auth.example",
            access_token=access_token,
            nonce="company-nonce",
        )
    )
    cache = ReplayCache()

    verified = await verify_dpop_proof(
        proof,
        method="POST",
        url="https://api.example/orders?different=query",
        access_token=access_token,
        nonce="company-nonce",
        replay_cache=cache,
        now=NOW,
    )

    assert verified.jti == "AAECAwQFBgcICQoLDA0ODw"
    assert verified.public_jwk == public_jwk
    assert verified.key_thumbprint
    with pytest.raises(ProofError, match="already been used"):
        await verify_dpop_proof(
            proof,
            method="POST",
            url="https://api.example/orders",
            access_token=access_token,
            nonce="company-nonce",
            replay_cache=cache,
            now=NOW,
        )


@pytest.mark.asyncio
async def test_rejects_dpop_request_or_token_mismatch() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)

    async def resolve(_: DpopProofRequest) -> DpopKeyMaterial:
        return DpopKeyMaterial(private_key, public_jwk)

    proof = await JoseDpopProofProvider(resolve, now=lambda: NOW).create(
        DpopProofRequest(
            method="GET",
            url="https://api.example/orders",
            tenant_id="tenant-one",
            subject="usr_one",
            issuer="https://auth.example",
            access_token=SecretStr("right-token"),
        )
    )

    with pytest.raises(ProofError, match="does not match"):
        await verify_dpop_proof(
            proof,
            method="DELETE",
            url="https://api.example/orders",
            access_token=SecretStr("right-token"),
            replay_cache=ReplayCache(),
            now=NOW,
        )
    with pytest.raises(ProofError, match="hash is invalid"):
        await verify_dpop_proof(
            proof,
            method="GET",
            url="https://api.example/orders",
            access_token=SecretStr("wrong-token"),
            replay_cache=ReplayCache(),
            now=NOW,
        )


def test_rejects_private_dpop_jwk_in_protected_header() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_jwk = jwt.algorithms.ECAlgorithm.to_jwk(private_key, as_dict=True)

    with pytest.raises(ValueError, match="private key material"):
        DpopKeyMaterial(private_key, private_jwk)
