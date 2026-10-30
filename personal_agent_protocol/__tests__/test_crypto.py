# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""`JoseSigner` and JWK thumbprints (§4.1, §5.2)."""

from __future__ import annotations

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from personal_agent_protocol import JoseSigner, ProofError, jwk_thumbprint
from personal_agent_protocol.crypto import public_jwk

#: The worked example of RFC 7638 §3.1.
RFC7638_JWK = {
    "kty": "RSA",
    "n": (
        "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_B"
        "JECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F"
        "DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4"
        "vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
    ),
    "e": "AQAB",
    "alg": "RS256",
    "kid": "2011-04-29",
}
RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def _key(algorithm: str) -> ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey:
    if algorithm == "ES256":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.mark.parametrize("algorithm", ["ES256", "PS384"])
@pytest.mark.asyncio
async def test_signs_and_verifies_only_asymmetric_pap_assertions(algorithm: str) -> None:
    private_key = _key(algorithm)
    signer = JoseSigner(private_key, algorithm=algorithm, key_id="agent-key")  # type: ignore[arg-type]

    compact = (await signer.sign({"sub": "user"}, purpose="client_assertion")).get_secret_value()

    assert jwt.get_unverified_header(compact) == {
        "alg": algorithm,
        "kid": "agent-key",
        "typ": "JWT",
    }
    assert jwt.decode(compact, private_key.public_key(), algorithms=[algorithm]) == {"sub": "user"}


@pytest.mark.parametrize("algorithm", ["ES256", "PS384"])
@pytest.mark.asyncio
async def test_each_purpose_signs_with_its_own_type(algorithm: str) -> None:
    signer = JoseSigner(_key(algorithm), algorithm=algorithm)  # type: ignore[arg-type]

    delegation = (await signer.sign({"iss": "agent"}, purpose="delegation")).get_secret_value()

    assert jwt.get_unverified_header(delegation)["typ"] == "pap-delegation+jwt"
    with pytest.raises(ProofError) as refused:
        await signer.sign({"sub": "user"}, purpose="session_assertion")
    assert refused.value.code == "unknown_purpose"


def test_rejects_symmetric_and_none_algorithms() -> None:
    with pytest.raises(ValueError, match="ES256 and PS384"):
        JoseSigner(b"secret", algorithm="HS256")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ES256 and PS384"):
        JoseSigner(None, algorithm="none")  # type: ignore[arg-type]
    # RS256 is not among the algorithms a key in `jwks_uri` signs with (§4.1).
    with pytest.raises(ValueError, match="ES256 and PS384"):
        JoseSigner(_key("PS384"), algorithm="RS256")  # type: ignore[arg-type]


def test_a_thumbprint_is_rfc_7638() -> None:
    assert jwk_thumbprint(RFC7638_JWK) == RFC7638_THUMBPRINT
    # Only the required members count, whatever else the JWK carries and in any order.
    required = {"e": RFC7638_JWK["e"], "kty": "RSA", "n": RFC7638_JWK["n"]}
    assert jwk_thumbprint(required) == RFC7638_THUMBPRINT


def test_an_ec_thumbprint_names_one_public_key() -> None:
    first = jwt.algorithms.ECAlgorithm.to_jwk(
        ec.generate_private_key(ec.SECP256R1()).public_key(), as_dict=True
    )
    second = jwt.algorithms.ECAlgorithm.to_jwk(
        ec.generate_private_key(ec.SECP256R1()).public_key(), as_dict=True
    )
    assert len(jwk_thumbprint(first)) == 43
    assert jwk_thumbprint(first) == jwk_thumbprint({**first, "kid": "ignored"})
    assert jwk_thumbprint(first) != jwk_thumbprint(second)


def test_rejects_private_material_in_a_public_jwk() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_jwk = jwt.algorithms.ECAlgorithm.to_jwk(private_key, as_dict=True)

    with pytest.raises(ValueError, match="private key material"):
        public_jwk(private_jwk)
