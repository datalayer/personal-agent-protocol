# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Blind signing of client assertions and delegations (§10.7, RFC 9474).

`BlindJoseSigner` is a `pap.signer` that runs on the User's device: it writes the
JWT, draws nothing the key holder could guess, blinds the signing input with
RSABSSA-SHA384-PSS-Deterministic, and sends only the blinded message to a
`BlindSigningKey`, the holder of a key in `jwks_uri`. It unblinds the answer into
an ordinary `PS384` signature, which any company verifies like another.

The variant adds no prefix to the message, so the signature verifies as a JWT's;
it is safe only because the message holds a value the signer can't guess: the
`jti`, which the device draws (`build_client_assertion_claims`, `delegation_claims`).
One signer signs both client assertions and delegations: a key that signs blindly
signs whatever a device sends it, so its signature never means the agent's own
systems approved what it signed (§10.7).
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
from collections.abc import Callable
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from pydantic import SecretStr

from .crypto import SIGNER_TYPES
from .errors import ProofError

#: RSABSSA-SHA384-PSS-Deterministic (RFC 9474 §5): SHA-384, MGF1 with SHA-384, a 48-byte
#: salt, and the identity preparation function. "Deterministic" names the message
#: preparation: the salt is random, so `PS384` verifies the signature.
_HASH_LENGTH = 48
_SALT_LENGTH = 48
#: Smaller moduli are refused (RFC 9474 §7; 3072 bits is suggested).
MIN_MODULUS_BITS = 2048
#: A `jti` carries at least 128 random bits: 22 base64url characters (§5.2, §10.7).
_MIN_JTI_LENGTH = 22


@runtime_checkable
class BlindSigningKey(Protocol):
    """The holder of a key in `jwks_uri`: it signs a blinded message, never seeing the JWT."""

    async def blind_sign(self, blinded: bytes) -> bytes: ...


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _mgf1(seed: bytes, length: int) -> bytes:
    output = b""
    counter = 0
    while len(output) < length:
        output += hashlib.sha384(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return output[:length]


def emsa_pss_encode(message: bytes, modulus_bits: int, salt: bytes) -> bytes:
    """EMSA-PSS-ENCODE (RFC 8017 §9.1.1) with SHA-384, MGF1-SHA-384, and `salt`."""

    em_bits = modulus_bits - 1
    em_length = math.ceil(em_bits / 8)
    if em_length < _HASH_LENGTH + len(salt) + 2:
        raise ProofError("signing_failed", "The modulus is too short for PS384")
    message_hash = hashlib.sha384(message).digest()
    digest = hashlib.sha384(b"\0" * 8 + message_hash + salt).digest()
    data_block = b"\0" * (em_length - len(salt) - _HASH_LENGTH - 2) + b"\x01" + salt
    mask = _mgf1(digest, len(data_block))
    masked = bytearray(block ^ byte for block, byte in zip(data_block, mask, strict=True))
    masked[0] &= 0xFF >> (8 * em_length - em_bits)
    return bytes(masked) + digest + b"\xbc"


class RsaBlindSigningKey:
    """A reference `BlindSigningKey`: an RSA key of 2048 bits or more (3072 suggested).

    BlindSign (RFC 9474 §4.3): it raises the blinded message to its private exponent
    and checks the result. Whoever holds it sees integers, never a claim. A real one
    sits in the agent's KMS, and limits how many signatures each User can get (§10.7).
    """

    def __init__(self, private_key: RSAPrivateKey) -> None:
        if private_key.key_size < MIN_MODULUS_BITS:
            raise ValueError("a blind signing key has 2048 bits or more")
        self._private_key = private_key

    @property
    def public_key(self) -> RSAPublicKey:
        return self._private_key.public_key()

    async def blind_sign(self, blinded: bytes) -> bytes:
        numbers = self._private_key.private_numbers()
        n, e = numbers.public_numbers.n, numbers.public_numbers.e
        message = int.from_bytes(blinded, "big")
        if len(blinded) != math.ceil(n.bit_length() / 8) or message >= n:
            raise ProofError("signing_failed", "The blinded message is out of range")
        signature = pow(message, numbers.d, n)
        if pow(signature, e, n) != message:
            raise ProofError("signing_failed", "The blind signature did not verify")
        return signature.to_bytes(len(blinded), "big")


class BlindJoseSigner:
    """`pap.signer` on the User's device: PS384 signatures a key signs blindly (§10.7).

    `public_key` is the public half of the `jwks_uri` key named `key_id`; `key` holds
    the private half. It signs client assertions and delegations alike, both
    blindly, each with a `jti` the device drew.
    """

    def __init__(
        self,
        key: BlindSigningKey,
        *,
        public_key: RSAPublicKey,
        key_id: str,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if public_key.key_size < MIN_MODULUS_BITS:
            raise ValueError("a blind signing key has 2048 bits or more")
        self.key = key
        self.public_key = public_key
        self.key_id = key_id
        self.random_bytes = random_bytes

    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        """A compact `PS384` JWT, its signing input never shown to the key holder."""

        if purpose not in SIGNER_TYPES:
            raise ProofError("unknown_purpose", f"Nothing is signed for {purpose}")
        jti = claims.get("jti")
        if not isinstance(jti, str) or len(jti) < _MIN_JTI_LENGTH:
            # The value the signer can't guess: the variant is unsafe without it (§10.7).
            raise ProofError("weak_randomness", "A blindly signed JWT needs a device-drawn jti")
        header = {"alg": "PS384", "typ": SIGNER_TYPES[purpose], "kid": self.key_id}
        signing_input = ".".join(
            _base64url(json.dumps(part, separators=(",", ":")).encode())
            for part in (header, claims)
        )
        message = signing_input.encode()
        signature = await self._blind_signature(message)
        return SecretStr(f"{signing_input}.{_base64url(signature)}")

    async def _blind_signature(self, message: bytes) -> bytes:
        numbers = self.public_key.public_numbers()
        n, e = numbers.n, numbers.e
        modulus_length = math.ceil(n.bit_length() / 8)
        salt = self.random_bytes(_SALT_LENGTH)
        if len(salt) < _SALT_LENGTH:
            raise ProofError("weak_randomness", "PS384 needs a 48-byte salt")
        encoded = int.from_bytes(emsa_pss_encode(message, n.bit_length(), salt), "big")
        if math.gcd(encoded, n) != 1:
            raise ProofError("signing_failed", "The encoded message is not invertible")
        blind = self._blinding_factor(n)
        blinded = (encoded * pow(blind, e, n)) % n
        answer = await self.key.blind_sign(blinded.to_bytes(modulus_length, "big"))
        signature = (int.from_bytes(answer, "big") * pow(blind, -1, n)) % n
        final = signature.to_bytes(modulus_length, "big")
        try:
            # Finalize verifies (RFC 9474 §4.4): a bad answer never leaves the device.
            self.public_key.verify(
                final,
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=_SALT_LENGTH),
                hashes.SHA384(),
            )
        except InvalidSignature as exc:
            raise ProofError("signing_failed", "The blind signature did not verify") from exc
        return final

    def _blinding_factor(self, n: int) -> int:
        """A uniform `r` in [1, n) with an inverse (RFC 9474 §4.2)."""

        length = math.ceil(n.bit_length() / 8)
        while True:
            candidate = int.from_bytes(self.random_bytes(length), "big")
            if 1 <= candidate < n and math.gcd(candidate, n) == 1:
                return candidate


__all__ = [
    "MIN_MODULUS_BITS",
    "BlindJoseSigner",
    "BlindSigningKey",
    "RsaBlindSigningKey",
    "emsa_pss_encode",
]
