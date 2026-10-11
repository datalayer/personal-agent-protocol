# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Verify a personal agent's client and Session assertions (§4.1, §4.2)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from pydantic import SecretStr

from ..errors import SessionError
from ..models import JsonWebKeySet
from .points import ReplayCache

_ALGORITHMS = ("ES256", "RS256")
_MAX_LIFETIME = timedelta(minutes=5)


async def verify_assertion(
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

    issued = datetime.fromtimestamp(int(claims["iat"]), timezone.utc)
    expires = datetime.fromtimestamp(int(claims["exp"]), timezone.utc)
    if expires - issued > _MAX_LIFETIME:
        raise SessionError(error, "Assertion lives too long", status_code=_status(error))
    if subject is not None and claims["sub"] != subject:
        raise SessionError(error, "Assertion subject is invalid", status_code=_status(error))
    skew = timedelta(seconds=30)
    if now > expires + skew or issued > now + skew:
        raise SessionError(error, "Assertion is not active", status_code=_status(error))
    if not await replay_cache.mark_once(f"assertion:{issuer}:{claims['jti']}", expires_at=expires):
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
