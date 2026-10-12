# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Verify a personal agent's client and Session assertions (§4.1, §4.2)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pydantic import SecretStr

from ..errors import SessionError
from ..models import JsonWebKeySet
from .points import ReplayCache

_ALGORITHMS = ("ES256", "RS256")
#: An assertion lives at most this long (`exp - iat`): long enough for any clock, short
#: enough that a captured one is soon useless. The SDKs' own assertions live 60 seconds.
_MAX_LIFETIME = timedelta(seconds=120)
#: A `jti` this short is guessable: its replay key could collide with another's.
_MIN_JTI = 16


async def verify_assertion(  # noqa: C901 - one check per claim, in order
    assertion: SecretStr | str,
    *,
    keys: JsonWebKeySet,
    issuer: str,
    audience: str | Sequence[str],
    replay_cache: ReplayCache,
    now: datetime,
    subject: str | None = None,
    error: str = "invalid_client",
) -> dict[str, Any]:
    """Verify signature, `iss`, `aud`, lifetime, and one-time `jti`.

    `audience` is the one value `aud` must be, or the values it may be: a
    client assertion names the authorization server's issuer, its token
    endpoint, or the endpoint it is sent to (RFC 7523 §3).

    A client assertion's `sub` is the `client_id` (`subject=issuer`); a
    Session assertion's is the pairwise user ID (`subject=None` returns it
    unchecked for the caller to read). Every failure is the same `error`, so
    nothing about which check failed leaks to the caller.
    """

    compact = assertion.get_secret_value() if isinstance(assertion, SecretStr) else assertion
    try:
        claims = _decode(compact, keys, issuer=issuer, audience=audience)
    except (KeyError, TypeError, ValueError, jwt.PyJWTError) as exc:
        raise SessionError(error, "Assertion is invalid", status_code=_status(error)) from exc
    if claims is None:
        raise SessionError(error, "Assertion signature is invalid", status_code=_status(error))
    if not isinstance(claims.get("aud"), str):
        # `aud` is one string, the token endpoint, so the assertion works at one company (§4.2).
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
    compact: str, keys: JsonWebKeySet, *, issuer: str, audience: str | Sequence[str]
) -> dict[str, Any] | None:
    """The verified claims, or `None` when no published key signed them."""

    header = jwt.get_unverified_header(compact)
    algorithm = str(header.get("alg", ""))
    if algorithm not in _ALGORITHMS:
        raise ValueError("assertion algorithm is not allowed")
    if header.get("typ") not in (None, "JWT"):
        # A browser assertion (`poppy-browser+jwt`) or a DPoP proof is never a token assertion.
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
                audience=audience if isinstance(audience, str) else list(audience),
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
