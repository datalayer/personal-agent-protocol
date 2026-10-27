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


class FixedKey:
    """One Session Key, already made: a custody holding exactly it."""

    def __init__(self, material: DpopKeyMaterial) -> None:
        from personal_agent_protocol import jwk_thumbprint

        self.material = material
        self.thumbprint = jwk_thumbprint(material.public_jwk)

    async def generate(self, *, tenant_id: str, issuer: str) -> DpopKeyMaterial:
        return self.material

    async def get(self, *, tenant_id: str, issuer: str, thumbprint: str) -> DpopKeyMaterial | None:
        return self.material if thumbprint == self.thumbprint else None

    async def discard(self, *, tenant_id: str, issuer: str, thumbprint: str) -> None:
        return None


@pytest.mark.asyncio
async def test_creates_and_verifies_bound_dpop_proof_once() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)

    keys = FixedKey(DpopKeyMaterial(private_key, public_jwk))
    provider = JoseDpopProofProvider(
        keys,
        now=lambda: NOW,
        random_bytes=lambda length: bytes(range(length)),
    )
    access_token = SecretStr("opaque-token")
    proof = await provider.create(
        DpopProofRequest(
            method="post",
            url="https://api.example/orders?tracking=secret#fragment",
            tenant_id="tenant-one",
            issuer="https://auth.example",
            session_key=keys.thumbprint,
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

    keys = FixedKey(DpopKeyMaterial(private_key, public_jwk))
    proof = await JoseDpopProofProvider(keys, now=lambda: NOW).create(
        DpopProofRequest(
            method="GET",
            url="https://api.example/orders",
            tenant_id="tenant-one",
            issuer="https://auth.example",
            session_key=keys.thumbprint,
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


@pytest.mark.asyncio
async def test_each_session_has_a_key_of_its_own_until_it_is_discarded() -> None:
    """A new key pair for each Session, named by its thumbprint (§4.3); a discarded key is
    never used again (§4.2)."""

    from personal_agent_protocol import InMemorySessionKeys, jwk_thumbprint
    from personal_agent_protocol.reactor import DpopProofRequest

    keys = InMemorySessionKeys()
    provider = JoseDpopProofProvider(keys, now=lambda: NOW)
    shop = "https://auth.provider.example/shop-a"
    first = await provider.new_session_key(tenant_id="tenant", issuer=shop)
    second = await provider.new_session_key(tenant_id="tenant", issuer=shop)
    assert first != second and len(first) == 43
    material = await keys.get(tenant_id="tenant", issuer=shop, thumbprint=first)
    assert material is not None and jwk_thumbprint(material.public_jwk) == first
    request = DpopProofRequest(
        method="POST",
        url="https://auth.provider.example/oauth/token",
        tenant_id="tenant",
        issuer=shop,
        session_key=first,
    )
    header = jwt.get_unverified_header((await provider.create(request)).get_secret_value())
    assert jwk_thumbprint(header["jwk"]) == first
    # Another issuer, or another tenant, is another key's name space.
    assert (
        await keys.get(tenant_id="tenant", issuer="https://other.example", thumbprint=first) is None
    )
    await provider.discard_session_key(tenant_id="tenant", issuer=shop, session_key=first)
    with pytest.raises(ProofError, match="Session Key"):
        await provider.create(request)
