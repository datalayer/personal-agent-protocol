# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Asymmetric JOSE signing and DPoP proof primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol, TypeAlias
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pydantic import SecretStr

from .errors import ProofError
from .reactor import DpopProofRequest

JoseAlgorithm = Literal["ES256", "RS256"]
SigningKey: TypeAlias = EllipticCurvePrivateKey | RSAPrivateKey | jwt.PyJWK | str | bytes

_ALLOWED_ALGORITHMS = frozenset({"ES256", "RS256"})
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


def _algorithm(value: str) -> JoseAlgorithm:
    if value not in _ALLOWED_ALGORITHMS:
        raise ValueError("PAP JOSE algorithms must be ES256 or RS256")
    return value  # type: ignore[return-value]


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _normalized_htu(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ProofError("invalid_htu", "DPoP target must be an HTTPS URL")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def _public_jwk(value: dict[str, Any], algorithm: JoseAlgorithm) -> dict[str, Any]:
    if _PRIVATE_JWK_MEMBERS.intersection(value):
        raise ValueError("DPoP public JWK must not contain private key material")
    expected = "EC" if algorithm == "ES256" else "RSA"
    if value.get("kty") != expected:
        raise ValueError(f"{algorithm} requires a {expected} public JWK")
    required = {"kty", "crv", "x", "y"} if expected == "EC" else {"kty", "n", "e"}
    if expected == "EC" and value.get("crv") != "P-256":
        raise ValueError("ES256 requires a P-256 public JWK")
    if any(not isinstance(value.get(member), str) or not value[member] for member in required):
        raise ValueError("DPoP public JWK is incomplete")
    return {key: item for key, item in value.items() if key not in _PRIVATE_JWK_MEMBERS}


@dataclass(frozen=True)
class DpopKeyMaterial:
    """Private signing handle and separately exportable public JWK."""

    private_key: SigningKey
    public_jwk: dict[str, Any]
    algorithm: JoseAlgorithm = "ES256"

    def __post_init__(self) -> None:
        algorithm = _algorithm(self.algorithm)
        object.__setattr__(self, "public_jwk", _public_jwk(self.public_jwk, algorithm))


class DpopReplayCache(Protocol):
    """Atomically remember a proof ID until its acceptance window ends."""

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        """Return true only when ``key`` had not already been stored."""


class JoseSigner:
    """Sign PAP assertions with an injected asymmetric private key or handle."""

    def __init__(
        self,
        private_key: SigningKey,
        *,
        algorithm: JoseAlgorithm = "ES256",
        key_id: str | None = None,
    ) -> None:
        self.private_key = private_key
        self.algorithm = _algorithm(algorithm)
        self.key_id = key_id

    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        """Return a compact JWT without exposing the supplied private key."""

        headers: dict[str, str] = {"typ": "JWT"}
        if self.key_id:
            headers["kid"] = self.key_id
        try:
            encoded = jwt.encode(
                claims,
                self.private_key,
                algorithm=self.algorithm,
                headers=headers,
            )
        except (TypeError, ValueError, jwt.PyJWTError) as exc:
            raise ProofError("signing_failed", f"Could not sign {purpose}") from exc
        return SecretStr(encoded)


class SessionKeyCustody(Protocol):
    """Where Session Keys live: made one per Session, found by thumbprint, then forgotten.

    A host keeps them in its KMS or HSM; `InMemorySessionKeys` is for one process.
    """

    async def generate(self, *, tenant_id: str, issuer: str) -> DpopKeyMaterial: ...

    async def get(
        self, *, tenant_id: str, issuer: str, thumbprint: str
    ) -> DpopKeyMaterial | None: ...

    async def discard(self, *, tenant_id: str, issuer: str, thumbprint: str) -> None: ...


class InMemorySessionKeys:
    """Session Keys in this process's memory: a new P-256 key for each Session (§4.3)."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str, str], DpopKeyMaterial] = {}

    async def generate(self, *, tenant_id: str, issuer: str) -> DpopKeyMaterial:
        private = ec.generate_private_key(ec.SECP256R1())
        public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
        material = DpopKeyMaterial(private_key=private, public_jwk=public)
        self._keys[(tenant_id, issuer, jwk_thumbprint(material.public_jwk))] = material
        return material

    async def get(self, *, tenant_id: str, issuer: str, thumbprint: str) -> DpopKeyMaterial | None:
        return self._keys.get((tenant_id, issuer, thumbprint))

    async def discard(self, *, tenant_id: str, issuer: str, thumbprint: str) -> None:
        self._keys.pop((tenant_id, issuer, thumbprint), None)


class JoseDpopProofProvider:
    """Create fresh RFC 9449 proofs, each with the key of its own Session (§4.3)."""

    def __init__(
        self,
        keys: SessionKeyCustody,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        self.keys = keys
        self.now = now
        self.random_bytes = random_bytes

    async def new_session_key(self, *, tenant_id: str, issuer: str) -> str:
        material = await self.keys.generate(tenant_id=tenant_id, issuer=issuer)
        return jwk_thumbprint(material.public_jwk)

    async def discard_session_key(self, *, tenant_id: str, issuer: str, session_key: str) -> None:
        await self.keys.discard(tenant_id=tenant_id, issuer=issuer, thumbprint=session_key)

    async def create(self, request: DpopProofRequest) -> SecretStr:
        material = await self.keys.get(
            tenant_id=request.tenant_id, issuer=request.issuer, thumbprint=request.session_key
        )
        if material is None:
            # A key this provider never made, or one it discarded: never a stand-in (§4.2).
            raise ProofError("unknown_session_key", "No Session Key with that thumbprint")
        algorithm = _algorithm(material.algorithm)
        issued_at = self.now()
        if issued_at.tzinfo is None:
            raise ProofError("invalid_clock", "DPoP clock must be timezone-aware")
        entropy = self.random_bytes(16)
        if len(entropy) < 16:
            raise ProofError("weak_randomness", "DPoP proof IDs require 128 random bits")
        claims: dict[str, object] = {
            "jti": _base64url(entropy),
            "htm": request.method.upper(),
            "htu": _normalized_htu(request.url),
            "iat": int(issued_at.timestamp()),
        }
        if request.access_token is not None:
            token = request.access_token.get_secret_value().encode()
            claims["ath"] = _base64url(hashlib.sha256(token).digest())
        if request.nonce is not None:
            claims["nonce"] = request.nonce
        try:
            encoded = jwt.encode(
                claims,
                material.private_key,
                algorithm=algorithm,
                headers={
                    "typ": "dpop+jwt",
                    "alg": algorithm,
                    "jwk": material.public_jwk,
                },
            )
        except (TypeError, ValueError, jwt.PyJWTError) as exc:
            raise ProofError("signing_failed", "Could not sign DPoP proof") from exc
        return SecretStr(encoded)


@dataclass(frozen=True)
class VerifiedDpopProof:
    """Safe identity of a verified, newly accepted DPoP proof."""

    jti: str
    issued_at: datetime
    public_jwk: dict[str, Any]
    key_thumbprint: str
    #: The `nonce` the proof carried, for a company that requires ones it issued (§4.3).
    nonce: str | None = None


def jwk_thumbprint(jwk_value: dict[str, Any]) -> str:
    """A public JWK's RFC 7638 SHA-256 thumbprint: a Session Key's name (§4.3)."""

    return _thumbprint(jwk_value)


def _thumbprint(jwk_value: dict[str, Any]) -> str:
    if jwk_value["kty"] == "EC":
        members = {name: jwk_value[name] for name in ("crv", "kty", "x", "y")}
    else:
        members = {name: jwk_value[name] for name in ("e", "kty", "n")}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return _base64url(hashlib.sha256(canonical).digest())


async def verify_dpop_proof(  # noqa: C901 - every bound claim is checked in sequence
    proof: SecretStr | str,
    *,
    method: str,
    url: str,
    replay_cache: DpopReplayCache,
    access_token: SecretStr | None = None,
    nonce: str | None = None,
    now: datetime | None = None,
    acceptance_window_seconds: int = 60,
) -> VerifiedDpopProof:
    """Verify signature, binding, freshness, nonce, token hash, and replay state."""

    if acceptance_window_seconds <= 0:
        raise ValueError("acceptance_window_seconds must be positive")
    compact = proof.get_secret_value() if isinstance(proof, SecretStr) else proof
    if compact.count(".") != 2 or any(char in compact for char in ", \t"):
        # One `DPoP` header holding one compact JWT: two headers joined are refused (§4.3).
        raise ProofError("invalid_dpop_proof", "DPoP header is not one compact JWT")
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("verification time must be timezone-aware")
    try:
        header = jwt.get_unverified_header(compact)
        algorithm = _algorithm(str(header.get("alg", "")))
        if header.get("typ") != "dpop+jwt" or not isinstance(header.get("jwk"), dict):
            raise ProofError("invalid_dpop_proof", "DPoP protected header is invalid")
        public_jwk = _public_jwk(header["jwk"], algorithm)
        key = jwt.PyJWK.from_dict(public_jwk, algorithm=algorithm).key
        claims = jwt.decode(
            compact,
            key,
            algorithms=[algorithm],
            options={
                "require": ["jti", "htm", "htu", "iat"],
                "verify_aud": False,
                "verify_iat": False,
            },
        )
    except ProofError:
        raise
    except (KeyError, TypeError, ValueError, jwt.PyJWTError) as exc:
        raise ProofError("invalid_dpop_proof", "DPoP signature or claims are invalid") from exc

    jti = claims.get("jti")
    issued = claims.get("iat")
    # At least 16 characters (96+ bits): a short `jti` is guessable, so a replay key collides.
    if not isinstance(jti, str) or not 16 <= len(jti) <= 256 or not isinstance(issued, int):
        raise ProofError("invalid_dpop_proof", "DPoP proof identity is invalid")
    issued_at = datetime.fromtimestamp(issued, timezone.utc)
    window = timedelta(seconds=acceptance_window_seconds)
    if issued_at < current - window or issued_at > current + window:
        raise ProofError("invalid_dpop_proof", "DPoP proof is outside the acceptance window")
    if claims.get("htm") != method.upper() or claims.get("htu") != _normalized_htu(url):
        raise ProofError("invalid_dpop_proof", "DPoP proof does not match the request")
    if nonce is not None and claims.get("nonce") != nonce:
        raise ProofError("use_dpop_nonce", "DPoP proof nonce is missing or invalid")
    if access_token is not None:
        expected = _base64url(hashlib.sha256(access_token.get_secret_value().encode()).digest())
        actual = claims.get("ath")
        if not isinstance(actual, str) or not hmac.compare_digest(actual, expected):
            raise ProofError("invalid_dpop_proof", "DPoP access-token hash is invalid")
    elif "ath" in claims:
        raise ProofError("invalid_dpop_proof", "Token-endpoint DPoP proof must not contain ath")

    thumbprint = _thumbprint(public_jwk)
    replay_key = f"{thumbprint}:{jti}"
    # Remembered for as long as the proof would be accepted: until `iat` leaves the window.
    if not await replay_cache.mark_once(replay_key, expires_at=issued_at + window):
        raise ProofError("invalid_dpop_proof", "DPoP proof has already been used")
    carried = claims.get("nonce")
    return VerifiedDpopProof(
        jti, issued_at, public_jwk, thumbprint, carried if isinstance(carried, str) else None
    )
