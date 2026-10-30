# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""JOSE signing, delegated keys, and the Session JWT (§4.1, §5.2).

- `JoseSigner` is the `pap.signer` default: a key from the agent's `jwks_uri`
  signs client assertions (`purpose="client_assertion"`, `typ: JWT`) and
  delegations (`purpose="delegation"`, `typ: pap-delegation+jwt`), with
  `ES256` or `PS384`.
- `DelegatedSessionSigner` is the `pap.sessionSigner` default: one delegated
  P-256 key per User ID (tenant, issuer, `sub`), vouched for by a delegation
  the `pap.signer` key signs, and a fresh Session JWT for each request. Keys
  live in a `DelegatedKeyCustody`; `InMemoryDelegatedKeys` is for one process.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol, TypeAlias, cast
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from pydantic import SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import ProofError
from .reactor import SIGNERS, SessionJwtRequest, Signer, first_contribution

JoseAlgorithm = Literal["ES256", "PS384"]
SigningKey: TypeAlias = EllipticCurvePrivateKey | RSAPrivateKey | jwt.PyJWK | str | bytes

#: The algorithms a key in `jwks_uri` signs client assertions and delegations with (§4.1, §5.2).
JOSE_ALGORITHMS: tuple[JoseAlgorithm, ...] = ("ES256", "PS384")
#: A Session JWT's `typ` and `alg` (§5.2).
SESSION_JWT_TYPE = "poppy-session+jwt"
SESSION_JWT_ALGORITHM = "ES256"
#: A delegation's `typ` (§5.2).
DELEGATION_TYPE = "pap-delegation+jwt"
#: A delegation expires at most this long after it is issued (§5.2).
DELEGATION_MAX_LIFETIME = timedelta(hours=24)
#: The `typ` each `pap.signer` purpose signs with.
SIGNER_TYPES = {"client_assertion": "JWT", "delegation": DELEGATION_TYPE}

_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
#: A Session ID: the characters of a Conversation ID, at least 128 random bits (§5.2, §8.2).
SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{22,256}$")


def _algorithm(value: str) -> JoseAlgorithm:
    for algorithm in JOSE_ALGORITHMS:
        if value == algorithm:
            return algorithm
    raise ValueError("PAP JOSE algorithms are ES256 and PS384")


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def token_hash(access_token: SecretStr | str) -> str:
    """`ath`: the access token's SHA-256, base64url-encoded (§5.2, as RFC 9449 §4.2)."""

    value = access_token.get_secret_value() if isinstance(access_token, SecretStr) else access_token
    return _base64url(hashlib.sha256(value.encode()).digest())


def normalized_htu(value: str) -> str:
    """`htu`: the request's URL without its query or fragment (§5.2)."""

    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ProofError("invalid_htu", "A Session JWT's target must be an HTTPS URL")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


def public_jwk(value: dict[str, Any]) -> dict[str, Any]:
    """A public JWK with no private member: refused otherwise (§5.2)."""

    if _PRIVATE_JWK_MEMBERS.intersection(value):
        raise ValueError("a public JWK must not contain private key material")
    return dict(value)


def jwk_thumbprint(jwk_value: dict[str, Any]) -> str:
    """A public JWK's RFC 7638 SHA-256 thumbprint: a Session JWT's `kid` (§5.2)."""

    if jwk_value["kty"] == "EC":
        members = {name: jwk_value[name] for name in ("crv", "kty", "x", "y")}
    else:
        members = {name: jwk_value[name] for name in ("e", "kty", "n")}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return _base64url(hashlib.sha256(canonical).digest())


class JoseSigner:
    """Sign client assertions and delegations with a key from the agent's `jwks_uri`.

    `purpose` sets the header's `typ`: `client_assertion` signs a `JWT`, and
    `delegation` a `pap-delegation+jwt` (§4.1, §5.2). `ES256` or `PS384`.
    """

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

        if purpose not in SIGNER_TYPES:
            raise ProofError("unknown_purpose", f"Nothing is signed for {purpose}")
        headers: dict[str, str] = {"typ": SIGNER_TYPES[purpose]}
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


class ContributedSigner:
    """The `pap.signer` contribution, asked each time it signs: whichever the host contributes."""

    def __init__(self, reactor: PluginPlatform) -> None:
        self.reactor = reactor

    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        return await signer.sign(claims, purpose=purpose)


@dataclass(frozen=True)
class DelegatedKey:
    """One delegated key, its delegation, and when the delegation expires (§5.2).

    `thumbprint` is the public key's RFC 7638 thumbprint, the `kid` of every
    Session JWT it signs; `delegation` is the compact JWT carried in `pap_dlg`.
    """

    private_key: EllipticCurvePrivateKey
    public_jwk: dict[str, Any]
    thumbprint: str
    delegation: SecretStr
    client_id: str
    issued_at: datetime
    expires_at: datetime


class DelegatedKeyCustody(Protocol):
    """Where delegated keys live: one current key per User ID, replaced when it rotates.

    The key of `(tenant_id, issuer, sub)` signs that User ID's Session JWTs only
    (§5.2). A host keeps them on the User's device or in its KMS;
    `InMemoryDelegatedKeys` is for one process.
    """

    async def current(self, *, tenant_id: str, issuer: str, sub: str) -> DelegatedKey | None: ...

    async def replace(
        self, *, tenant_id: str, issuer: str, sub: str, key: DelegatedKey
    ) -> None: ...

    async def forget(self, *, tenant_id: str, issuer: str, sub: str) -> None: ...


class InMemoryDelegatedKeys:
    """Delegated keys in this process's memory, one per User ID."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str, str], DelegatedKey] = {}

    async def current(self, *, tenant_id: str, issuer: str, sub: str) -> DelegatedKey | None:
        return self._keys.get((tenant_id, issuer, sub))

    async def replace(self, *, tenant_id: str, issuer: str, sub: str, key: DelegatedKey) -> None:
        self._keys[(tenant_id, issuer, sub)] = key

    async def forget(self, *, tenant_id: str, issuer: str, sub: str) -> None:
        self._keys.pop((tenant_id, issuer, sub), None)

    def __len__(self) -> int:
        return len(self._keys)


def delegation_claims(
    *,
    client_id: str,
    public: dict[str, Any],
    issued_at: datetime,
    lifetime: timedelta,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> dict[str, object]:
    """A delegation's claims (§5.2): `iss`, `cnf.jwk`, `iat`, `exp`, `jti`, nothing else.

    Nothing about the User or the Company: no User ID, Agent ID, or issuer.
    """

    if not timedelta(0) < lifetime <= DELEGATION_MAX_LIFETIME:
        raise ValueError("a delegation lives more than 0 seconds and at most 24 hours")
    entropy = random_bytes(16)
    if len(entropy) < 16:
        raise ProofError("weak_randomness", "A delegation ID needs 128 random bits")
    iat = int(issued_at.timestamp())
    return {
        "iss": client_id,
        "cnf": {"jwk": public_jwk(public)},
        "iat": iat,
        "exp": iat + int(lifetime.total_seconds()),
        "jti": _base64url(entropy),
    }


def session_jwt_claims(
    request: SessionJwtRequest,
    *,
    issued_at: datetime,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
) -> dict[str, object]:
    """A Session JWT's claims for one request (§5.2).

    Every claim but `agent_id`, and `ath` only when the request carries an access
    token.
    """

    if not SESSION_ID.fullmatch(request.sid):
        raise ProofError("invalid_session_id", "A Session ID is 22 to 256 URL-safe characters")
    if not request.sub:
        raise ProofError("invalid_user_id", "A Session JWT names its User ID")
    entropy = random_bytes(16)
    if len(entropy) < 16:
        raise ProofError("weak_randomness", "A Session JWT's jti needs 128 random bits")
    claims: dict[str, object] = {
        "iss": request.client_id,
        "aud": request.issuer,
        "sid": request.sid,
        "sub": request.sub,
        "htm": request.method.upper(),
        "htu": normalized_htu(request.url),
        "iat": int(issued_at.timestamp()),
        "jti": _base64url(entropy),
    }
    if request.agent_id is not None:
        claims["agent_id"] = request.agent_id
    if request.access_token is not None:
        claims["ath"] = token_hash(request.access_token)
    return claims


class DelegatedSessionSigner:
    """`pap.sessionSigner`: a delegated key per User ID signs each request's Session JWT (§5.2).

    The key of a User ID is made on first use, with a delegation the `signer` (the
    `pap.signer` key from `jwks_uri`) signs for `delegation_lifetime`, and replaced
    by a new key and delegation `rotate_before` its expiry: a JWT is never signed
    after its delegation's `exp`. A key is never shared by two User IDs, so its
    thumbprint and its delegation's `jti` name one User at one Company.
    """

    def __init__(
        self,
        custody: DelegatedKeyCustody,
        *,
        signer: Signer,
        delegation_lifetime: timedelta = timedelta(hours=1),
        rotate_before: timedelta = timedelta(minutes=5),
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    ) -> None:
        if not timedelta(0) < delegation_lifetime <= DELEGATION_MAX_LIFETIME:
            raise ValueError("delegation_lifetime is more than 0 and at most 24 hours")
        if not timedelta(0) <= rotate_before < delegation_lifetime:
            raise ValueError("rotate_before is shorter than delegation_lifetime")
        self.custody = custody
        self.signer = signer
        self.delegation_lifetime = delegation_lifetime
        self.rotate_before = rotate_before
        self.now = now
        self.random_bytes = random_bytes

    async def sign(self, request: SessionJwtRequest) -> SecretStr:
        issued_at = self.now()
        if issued_at.tzinfo is None:
            raise ProofError("invalid_clock", "The Session JWT clock must be timezone-aware")
        key = await self.key_for(request, now=issued_at)
        claims = session_jwt_claims(request, issued_at=issued_at, random_bytes=self.random_bytes)
        try:
            encoded = jwt.encode(
                claims,
                key.private_key,
                algorithm=SESSION_JWT_ALGORITHM,
                headers={
                    "typ": SESSION_JWT_TYPE,
                    "kid": key.thumbprint,
                    "pap_dlg": key.delegation.get_secret_value(),
                },
            )
        except (TypeError, ValueError, jwt.PyJWTError) as exc:
            raise ProofError("signing_failed", "Could not sign the Session JWT") from exc
        return SecretStr(encoded)

    async def key_for(self, request: SessionJwtRequest, *, now: datetime) -> DelegatedKey:
        """The User ID's current delegated key, or a new one when it is due to rotate."""

        who = {"tenant_id": request.tenant_id, "issuer": request.issuer, "sub": request.sub}
        key = await self.custody.current(**who)
        if (
            key is not None
            and key.client_id == request.client_id
            and now < key.expires_at - self.rotate_before
        ):
            return key
        key = await self._new_key(request.client_id, now)
        await self.custody.replace(**who, key=key)
        return key

    async def _new_key(self, client_id: str, now: datetime) -> DelegatedKey:
        private = ec.generate_private_key(ec.SECP256R1())
        public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
        claims = delegation_claims(
            client_id=client_id,
            public=public,
            issued_at=now,
            lifetime=self.delegation_lifetime,
            random_bytes=self.random_bytes,
        )
        delegation = await self.signer.sign(claims, purpose="delegation")
        issued, expires = cast(int, claims["iat"]), cast(int, claims["exp"])
        return DelegatedKey(
            private_key=private,
            public_jwk=public,
            thumbprint=jwk_thumbprint(public),
            delegation=delegation,
            client_id=client_id,
            issued_at=datetime.fromtimestamp(issued, timezone.utc),
            expires_at=datetime.fromtimestamp(expires, timezone.utc),
        )


__all__ = [
    "DELEGATION_MAX_LIFETIME",
    "DELEGATION_TYPE",
    "JOSE_ALGORITHMS",
    "SESSION_JWT_ALGORITHM",
    "SESSION_JWT_TYPE",
    "ContributedSigner",
    "DelegatedKey",
    "DelegatedKeyCustody",
    "DelegatedSessionSigner",
    "InMemoryDelegatedKeys",
    "JoseSigner",
    "delegation_claims",
    "jwk_thumbprint",
    "normalized_htu",
    "public_jwk",
    "session_jwt_claims",
    "token_hash",
]
