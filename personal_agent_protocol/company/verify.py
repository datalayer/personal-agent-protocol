# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Verify a personal agent's client assertions, Session JWTs and DPoP proofs (§4.1, §4.5, §5.3)."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pydantic import SecretStr

from ..crypto import (
    DELEGATION_MAX_LIFETIME,
    DELEGATION_TYPE,
    DPOP_ALGORITHM,
    DPOP_PROOF_TYPE,
    SESSION_ID,
    SESSION_JWT_ALGORITHM,
    SESSION_JWT_TYPE,
    jwk_thumbprint,
    normalized_htu,
    public_jwk,
    token_hash,
)
from ..errors import ProofError, SessionError
from ..models import ClientMetadata, JsonWebKeySet
from .points import ReplayCache

#: Companies accept client assertions and delegations signed with these (§4.1, §5.2).
_ALGORITHMS = ("ES256", "PS384")
#: An assertion lives at most this long: `exp` at most five minutes after `iat` (§4.1).
#: The SDKs' own assertions live 60 seconds.
_MAX_LIFETIME = timedelta(seconds=300)
#: A `jti` this short is guessable: its replay key could collide with another's.
_MIN_JTI = 16


async def verify_assertion(  # noqa: C901 - one check per claim, in order
    assertion: SecretStr | str,
    *,
    keys: JsonWebKeySet,
    issuer: str,
    audience: str,
    replay_cache: ReplayCache,
    now: datetime,
    subject: str | None = None,
    error: str = "invalid_client",
) -> dict[str, Any]:
    """Verify signature, `iss`, `aud`, lifetime, and one-time `jti`.

    `audience` is the one value `aud` must be, compared character for
    character: the company's issuer, never an endpoint URL (§4.1, §10.4).
    The `jti` is remembered per `client_id` until the assertion expires.

    A client assertion's `sub` is the `client_id` (`subject=issuer`). Every
    failure is the same `error`, so nothing about which check failed leaks to
    the caller.
    """

    compact = assertion.get_secret_value() if isinstance(assertion, SecretStr) else assertion
    try:
        claims = _decode(compact, keys, issuer=issuer, audience=audience)
    except (KeyError, TypeError, ValueError, jwt.PyJWTError) as exc:
        raise SessionError(error, "Assertion is invalid", status_code=_status(error)) from exc
    if claims is None:
        raise SessionError(error, "Assertion signature is invalid", status_code=_status(error))
    if claims.get("aud") != audience:
        # `aud` is one string, the issuer, exactly: an array, or the token endpoint, is
        # refused, so the assertion works at one company (§4.1, §4.2).
        raise SessionError(error, "Assertion audience is invalid", status_code=_status(error))

    try:
        # Numbers, as JWT says (RFC 7519 §2): a string, a boolean or a time out
        # of range is an invalid assertion, never a 500.
        if not all(
            isinstance(claims[name], int | float) and not isinstance(claims[name], bool)
            for name in ("iat", "exp")
        ):
            raise TypeError("iat and exp are NumericDate")
        issued = datetime.fromtimestamp(int(claims["iat"]), timezone.utc)
        expires = datetime.fromtimestamp(int(claims["exp"]), timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise SessionError(
            error, "Assertion times are invalid", status_code=_status(error)
        ) from exc
    if expires - issued > _MAX_LIFETIME or expires <= issued:
        raise SessionError(error, "Assertion lifetime is invalid", status_code=_status(error))
    jti = claims["jti"]
    if not isinstance(jti, str) or not _MIN_JTI <= len(jti) <= 256:
        raise SessionError(error, "Assertion jti is invalid", status_code=_status(error))
    if subject is not None and claims["sub"] != subject:
        raise SessionError(error, "Assertion subject is invalid", status_code=_status(error))
    skew = timedelta(seconds=30)
    if now > expires + skew or issued > now + skew:
        raise SessionError(error, "Assertion is not active", status_code=_status(error))
    # Remembered for as long as the assertion would be accepted: `exp` and the skew.
    replay_key = f"assertion:{issuer}:{claims['jti']}"
    if not await replay_cache.mark_once(replay_key, expires_at=expires + skew):
        raise SessionError(error, "Assertion has already been used", status_code=_status(error))
    return claims


def _decode(
    compact: str, keys: JsonWebKeySet, *, issuer: str, audience: str
) -> dict[str, Any] | None:
    """The verified claims, or `None` when no published key signed them."""

    header = jwt.get_unverified_header(compact)
    algorithm = str(header.get("alg", ""))
    if algorithm not in _ALGORITHMS:
        raise ValueError("assertion algorithm is not allowed")
    if header.get("typ") not in (None, "JWT"):
        # A Session JWT or a delegation is never a client assertion (§5.2, RFC 8725 §3.11).
        raise ValueError("assertion type is not allowed")
    kid = header.get("kid")
    for key in keys.keys:
        if kid is not None and key.kid is not None and key.kid != kid:
            continue
        if key.alg is not None and key.alg != algorithm:
            continue
        public = jwt.PyJWK.from_dict(
            json.loads(key.model_dump_json(exclude_none=True)), algorithm=algorithm
        ).key
        try:
            return jwt.decode(
                compact,
                public,
                algorithms=[algorithm],
                audience=audience,
                issuer=issuer,
                # Lifetimes are checked against the company's own clock, below.
                options={
                    "require": ["iss", "sub", "aud", "iat", "exp", "jti"],
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.InvalidSignatureError:
            continue
    return None


def _status(error: str) -> int:
    return 401 if error == "invalid_client" else 400


# Session JWTs (§5.2, §5.3) ---------------------------------------------------------

#: The acceptance window of a Session JWT's `iat` (§5.3: such as one minute).
SESSION_JWT_WINDOW = timedelta(seconds=60)
_JTI = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_AGENT_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")

Resolve = Callable[[str, str | None], Awaitable[tuple[ClientMetadata, JsonWebKeySet]]]


@dataclass(frozen=True)
class VerifiedDelegation:
    """A delegation that verified (§5.2): its agent, its delegated key, until when."""

    client_id: str
    public_jwk: dict[str, Any]
    thumbprint: str
    expires_at: datetime


@dataclass(frozen=True)
class VerifiedSessionJwt:
    """A Session JWT that verified (§5.3): who sent the request, in which Session."""

    client_id: str
    sid: str
    sub: str
    agent_id: str | None
    jti: str
    issued_at: datetime
    delegation: VerifiedDelegation


class DelegationCache:
    """Verified delegations, until each expires (§5.2: a resource MAY cache them).

    Keyed by the delegation's digest; bounded, the oldest dropped first.
    """

    def __init__(self, max_entries: int = 4096) -> None:
        self._entries: OrderedDict[str, VerifiedDelegation] = OrderedDict()
        self.max_entries = max_entries

    def get(self, compact: str, now: datetime) -> VerifiedDelegation | None:
        key = hashlib.sha256(compact.encode()).hexdigest()
        found = self._entries.get(key)
        if found is not None and now >= found.expires_at:
            del self._entries[key]
            return None
        return found

    def put(self, compact: str, delegation: VerifiedDelegation) -> None:
        self._entries[hashlib.sha256(compact.encode()).hexdigest()] = delegation
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def __len__(self) -> int:
        return len(self._entries)


def _refused(message: str) -> SessionError:
    return SessionError("invalid_session", message, status_code=400)


def unverified_session_issuer(compact: str) -> str:
    """The `iss` a Session JWT names, unverified: whose policy to ask before fetching anything."""

    try:
        claims = jwt.decode(compact, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise _refused("The Session header is not a JWT") from exc
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer.startswith("https://"):
        raise _refused("The Session JWT names no personal agent")
    return issuer


async def verify_delegation(  # noqa: C901 - the four steps of §5.2, in order
    compact: str,
    *,
    client_id: str,
    resolve: Resolve,
    now: datetime,
    cache: DelegationCache | None = None,
) -> VerifiedDelegation:
    """Steps 1 and 2 of §5.2: the jwks key its `kid` names signed it, and its claims hold."""

    if cache is not None:
        cached = cache.get(compact, now)
        if cached is not None:
            if cached.client_id != client_id:
                raise _refused("The delegation is another agent's")
            return cached
    try:
        header = jwt.get_unverified_header(compact)
    except jwt.PyJWTError as exc:
        raise _refused("The delegation is not a JWT") from exc
    algorithm, kid = header.get("alg"), header.get("kid")
    if algorithm not in _ALGORITHMS or not isinstance(kid, str) or not kid:
        raise _refused("The delegation's algorithm or key ID is not allowed")
    if header.get("typ") != DELEGATION_TYPE:
        raise _refused("A delegation's typ is pap-delegation+jwt")
    try:
        _, keys = await resolve(client_id, kid)
    except Exception as exc:
        raise _refused("The agent's keys could not be fetched") from exc
    key = next((candidate for candidate in keys.keys if candidate.kid == kid), None)
    if key is None or (key.alg is not None and key.alg != algorithm):
        raise _refused("No key of the agent's jwks_uri signed the delegation")
    try:
        public = jwt.PyJWK.from_dict(
            json.loads(key.model_dump_json(exclude_none=True)), algorithm=algorithm
        ).key
        claims = jwt.decode(
            compact,
            public,
            algorithms=[algorithm],
            options={
                "require": ["iss", "cnf", "iat", "exp", "jti"],
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "verify_aud": False,
            },
        )
    except (KeyError, TypeError, ValueError, jwt.PyJWTError) as exc:
        raise _refused("The delegation's signature is invalid") from exc
    if claims.get("iss") != client_id:
        raise _refused("The delegation's iss is not the Session JWT's")
    iat, exp = claims.get("iat"), claims.get("exp")
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in (iat, exp)):
        raise _refused("The delegation's times are not NumericDates")
    try:
        issued = datetime.fromtimestamp(iat, timezone.utc)  # type: ignore[arg-type]
        expires = datetime.fromtimestamp(exp, timezone.utc)  # type: ignore[arg-type]
    except (ValueError, OverflowError, OSError) as exc:
        raise _refused("The delegation's times are out of range") from exc
    if now >= expires:
        raise _refused("The delegation has expired")
    if expires - issued > DELEGATION_MAX_LIFETIME or expires <= issued:
        raise _refused("A delegation expires at most 24 hours after it is issued")
    cnf = claims.get("cnf")
    jwk_value = cnf.get("jwk") if isinstance(cnf, dict) else None
    if (
        not isinstance(jwk_value, dict)
        or jwk_value.get("kty") != "EC"
        or jwk_value.get("crv") != "P-256"
        or any(member in jwk_value for member in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"))
    ):
        # The delegated key signs ES256 Session JWTs: a public P-256 key, nothing private.
        raise _refused("The delegation's cnf.jwk is not a public P-256 key")
    try:
        thumbprint = jwk_thumbprint(jwk_value)
    except (KeyError, TypeError) as exc:
        raise _refused("The delegation's cnf.jwk is incomplete") from exc
    verified = VerifiedDelegation(
        client_id=client_id, public_jwk=dict(jwk_value), thumbprint=thumbprint, expires_at=expires
    )
    if cache is not None:
        cache.put(compact, verified)
    return verified


async def verify_session_jwt(  # noqa: C901 - one check per claim, in the spec's order
    compact: str,
    *,
    issuer: str,
    method: str,
    url: str,
    resolve: Resolve,
    replay_cache: ReplayCache,
    now: datetime,
    access_token: str | None = None,
    delegations: DelegationCache | None = None,
    window: timedelta = SESSION_JWT_WINDOW,
) -> VerifiedSessionJwt:
    """Verify the Session header of one request (§5.2, §5.3); `invalid_session` on any failure.

    The delegation first (`verify_delegation`, cached), then the JWT's signature with
    the delegated key, its `kid` that key's thumbprint, its `iat` no later than the
    delegation's `exp`; then `typ`, `alg`, `aud` (this company's issuer, exactly),
    `htm` and `htu`, `iat` within `window`, and `ath` against the access token, or
    absent without one. A JWT signed directly by a key from `jwks_uri` has no
    delegation and is refused. A reused `jti` is refused (§5.3: a company MAY).
    """

    if compact.count(".") != 2 or any(char in compact for char in ", \t"):
        raise _refused("The Session header is not one compact JWT")
    try:
        header = jwt.get_unverified_header(compact)
    except jwt.PyJWTError as exc:
        raise _refused("The Session header is not a JWT") from exc
    if header.get("typ") != SESSION_JWT_TYPE or header.get("alg") != SESSION_JWT_ALGORITHM:
        raise _refused("A Session JWT's typ is poppy-session+jwt and its alg ES256")
    delegation_compact = header.get("pap_dlg")
    kid = header.get("kid")
    if not isinstance(delegation_compact, str) or not delegation_compact:
        # Signed with a key from jwks_uri itself, or by anyone: never accepted (§5.2).
        raise _refused("A Session JWT carries its delegation")
    if not isinstance(kid, str):
        raise _refused("A Session JWT names its delegated key")
    client_id = unverified_session_issuer(compact)
    delegation = await verify_delegation(
        delegation_compact, client_id=client_id, resolve=resolve, now=now, cache=delegations
    )
    if not hmac.compare_digest(kid, delegation.thumbprint):
        raise _refused("The Session JWT's kid is not its delegated key's thumbprint")
    try:
        public = jwt.PyJWK.from_dict(delegation.public_jwk, algorithm=SESSION_JWT_ALGORITHM).key
        claims = jwt.decode(
            compact,
            public,
            algorithms=[SESSION_JWT_ALGORITHM],
            options={
                "require": ["iss", "aud", "sid", "sub", "htm", "htu", "iat", "jti"],
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
            },
        )
    except (KeyError, TypeError, ValueError, jwt.PyJWTError) as exc:
        raise _refused("The Session JWT's signature is invalid") from exc
    iat = claims.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise _refused("The Session JWT's iat is not a NumericDate")
    try:
        issued = datetime.fromtimestamp(iat, timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise _refused("The Session JWT's iat is out of range") from exc
    if issued > delegation.expires_at:
        raise _refused("The Session JWT was signed after its delegation expired")
    if claims.get("aud") != issuer:
        # One string, this company's issuer, exactly (§5.2, §10.4).
        raise _refused("The Session JWT is for another company")
    try:
        target = normalized_htu(url)
    except ProofError as exc:
        raise _refused("The request URL is not HTTPS") from exc
    if claims.get("htm") != method.upper() or claims.get("htu") != target:
        raise _refused("The Session JWT is for another request")
    if issued < now - window or issued > now + window:
        raise _refused("The Session JWT is outside the acceptance window")
    sid, sub, agent_id, jti = (
        claims.get("sid"),
        claims.get("sub"),
        claims.get("agent_id"),
        claims.get("jti"),
    )
    if not isinstance(sid, str) or not SESSION_ID.fullmatch(sid):
        raise _refused("The Session ID is malformed")
    if not isinstance(sub, str) or not sub or len(sub) > 256:
        raise _refused("The User ID is malformed")
    if agent_id is not None and (
        not isinstance(agent_id, str) or not _AGENT_ID.fullmatch(agent_id)
    ):
        raise _refused("The Agent ID is malformed")
    if not isinstance(jti, str) or not _JTI.fullmatch(jti):
        raise _refused("The Session JWT's jti is malformed")
    ath = claims.get("ath")
    if access_token is not None:
        if not isinstance(ath, str) or not hmac.compare_digest(ath, token_hash(access_token)):
            raise _refused("The Session JWT's ath does not match the access token")
    elif ath is not None:
        raise _refused("A Session JWT without an access token has no ath")
    # Remembered for as long as the JWT would be accepted (§5.3: a company MAY).
    if not await replay_cache.mark_once(f"session:{client_id}:{jti}", expires_at=issued + window):
        raise _refused("The Session JWT has already been used")
    return VerifiedSessionJwt(
        client_id=client_id,
        sid=sid,
        sub=sub,
        agent_id=agent_id,
        jti=jti,
        issued_at=issued,
        delegation=delegation,
    )


@dataclass(frozen=True)
class VerifiedDpopProof:
    """What a verified, newly accepted DPoP proof says: its key's thumbprint, and its nonce."""

    thumbprint: str
    nonce: str | None = None


def _dpop_key(header: dict[str, Any]) -> dict[str, Any]:
    """The proof's public key, a P-256 JWK: a private member or another curve is refused."""

    jwk_value = header.get("jwk")
    if not isinstance(jwk_value, dict):
        raise ProofError("invalid_dpop_proof", "A DPoP proof carries its public key")
    if jwk_value.get("kty") != "EC" or jwk_value.get("crv") != "P-256":
        raise ProofError("invalid_dpop_proof", "A DPoP proof's key is P-256")
    return public_jwk(jwk_value)


async def verify_dpop_proof(  # noqa: C901 - one check per claim, in order
    proof: SecretStr | str,
    *,
    method: str,
    url: str,
    replay_cache: ReplayCache,
    now: datetime,
    window: timedelta,
    access_token: str | None = None,
) -> VerifiedDpopProof:
    """Verify one DPoP proof as RFC 9449 §4.3 says.

    One `DPoP` header holding one JWT: `typ` `dpop+jwt`, `alg` ES256, a public P-256
    `jwk` that signed it, `htm` and `htu` matching the request, `iat` within `window`,
    a `jti` not seen while the proof would be accepted, and `ath` for `access_token`,
    or none without one. Any failure is `ProofError` (`invalid_dpop_proof`). Whether the
    key and the nonce are the right ones is the caller's to decide.
    """

    compact = proof.get_secret_value() if isinstance(proof, SecretStr) else proof
    if compact.count(".") != 2 or any(char in compact for char in ", \t"):
        # Two `DPoP` headers arrive joined: refused (RFC 9449 §4.3).
        raise ProofError("invalid_dpop_proof", "A DPoP header is one compact JWT")
    try:
        header = jwt.get_unverified_header(compact)
        if header.get("typ") != DPOP_PROOF_TYPE or header.get("alg") != DPOP_ALGORITHM:
            raise ProofError("invalid_dpop_proof", "A DPoP proof's typ or alg is wrong")
        key_value = _dpop_key(header)
        key = jwt.PyJWK.from_dict(key_value, algorithm=DPOP_ALGORITHM).key
        claims = jwt.decode(
            compact,
            key,
            algorithms=[DPOP_ALGORITHM],
            options={
                "require": ["jti", "htm", "htu", "iat"],
                "verify_aud": False,
                "verify_iat": False,
                "verify_exp": False,
                "verify_nbf": False,
            },
        )
        thumbprint = jwk_thumbprint(key_value)
    except ProofError:
        raise
    except (KeyError, TypeError, ValueError, jwt.PyJWTError) as exc:
        raise ProofError("invalid_dpop_proof", "A DPoP proof's signature is invalid") from exc
    jti, issued = claims.get("jti"), claims.get("iat")
    if (
        not isinstance(jti, str)
        or not _MIN_JTI <= len(jti) <= 256
        or isinstance(issued, bool)
        or not isinstance(issued, int)
    ):
        raise ProofError("invalid_dpop_proof", "A DPoP proof's jti or iat is invalid")
    issued_at = datetime.fromtimestamp(issued, timezone.utc)
    if abs(issued_at - now) > window:
        raise ProofError("invalid_dpop_proof", "A DPoP proof is outside its acceptance window")
    if claims.get("htm") != method.upper() or claims.get("htu") != normalized_htu(url):
        raise ProofError("invalid_dpop_proof", "A DPoP proof is for another request")
    ath = claims.get("ath")
    if access_token is None:
        if ath is not None:
            raise ProofError("invalid_dpop_proof", "A proof without an access token has no ath")
    elif not isinstance(ath, str) or not hmac.compare_digest(ath, token_hash(access_token)):
        raise ProofError("invalid_dpop_proof", "A DPoP proof's ath does not match the token")
    # Remembered for as long as the proof would be accepted: until `iat` leaves the window.
    if not await replay_cache.mark_once(f"dpop:{thumbprint}:{jti}", expires_at=issued_at + window):
        raise ProofError("invalid_dpop_proof", "A DPoP proof is used once")
    nonce = claims.get("nonce")
    return VerifiedDpopProof(thumbprint, nonce if isinstance(nonce, str) else None)
