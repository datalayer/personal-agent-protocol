# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""PAP browser-session assertions and controlled form-post handoff."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from pydantic import Field, SecretStr, field_validator, model_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .crypto import JoseAlgorithm, _algorithm
from .errors import BrowserSessionError
from .models import ProtocolModel
from .reactor import (
    BROWSER_FORM_POSTS,
    CLOCKS,
    RANDOM_SOURCES,
    SIGNERS,
    BrowserFormPost,
    Clock,
    RandomSource,
    Signer,
    first_contribution,
)
from .sessions import RandomBytes, _opaque_id

BROWSER_ASSERTION_TYPE = "poppy-browser+jwt"
VerificationKey = EllipticCurvePublicKey | RSAPublicKey | jwt.PyJWK | str | bytes


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{label} must be an HTTPS URL")
    return value


def _company_return_to(value: str, company_domain: str) -> str:
    value = _https_url(value, "return_to")
    host = (urlsplit(value).hostname or "").lower().rstrip(".")
    domain = company_domain.lower().rstrip(".")
    if not domain or (host != domain and not host.endswith(f".{domain}")):
        raise ValueError("return_to must be on the company domain or a subdomain")
    return value


class BrowserAssertionClaims(ProtocolModel):
    """Claims that bind a controlled browser to one PAP Session."""

    iss: str
    sub: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    aud: str
    session_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    return_to: str
    iat: int = Field(ge=0)
    exp: int = Field(gt=0)
    jti: str = Field(pattern=r"^[A-Za-z0-9_-]{22,256}$")

    @field_validator("iss", "aud", "return_to")
    @classmethod
    def validate_urls(cls, value: str, info: object) -> str:
        return _https_url(value, str(getattr(info, "field_name", "URL")))

    @model_validator(mode="after")
    def validate_lifetime(self) -> BrowserAssertionClaims:
        if self.exp <= self.iat or self.exp - self.iat > 60:
            raise ValueError("browser assertion lifetime must be between 1 and 60 seconds")
        return self


def build_browser_assertion_claims(
    *,
    client_id: str,
    pairwise_user_id: str,
    browser_session_endpoint: str,
    session_id: str,
    return_to: str,
    company_domain: str,
    now: datetime | None = None,
    lifetime_seconds: int = 60,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> BrowserAssertionClaims:
    """Build unsigned PAP section 5 claims for protected signing."""

    if not 0 < lifetime_seconds <= 60:
        raise ValueError("browser assertion lifetime must be between 1 and 60 seconds")
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        raise ValueError("browser assertion time must include a timezone")
    iat = int(issued_at.timestamp())
    return BrowserAssertionClaims(
        iss=_https_url(client_id, "client_id"),
        sub=pairwise_user_id,
        aud=_https_url(browser_session_endpoint, "browser_session_endpoint"),
        session_id=session_id,
        return_to=_company_return_to(return_to, company_domain),
        iat=iat,
        exp=iat + lifetime_seconds,
        jti=_opaque_id("jti", random_bytes),
    )


class BrowserSessionStart(ProtocolModel):
    """Safe status after a controlled form POST has started."""

    endpoint: str
    return_to: str
    expires_at: datetime


class BrowserSessionClient:
    """Sign and POST a browser assertion without putting it in a URL."""

    def __init__(self, *, reactor: PluginPlatform) -> None:
        self.reactor = reactor

    async def join(
        self,
        *,
        client_id: str,
        pairwise_user_id: str,
        browser_session_endpoint: str,
        session_id: str,
        return_to: str,
        company_domain: str,
        lifetime_seconds: int = 60,
    ) -> BrowserSessionStart:
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        random = cast(
            RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")
        )
        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        browser = cast(
            BrowserFormPost,
            first_contribution(
                self.reactor,
                BROWSER_FORM_POSTS,
                "browser form POST",
            ),
        )
        now = clock.now()
        claims = build_browser_assertion_claims(
            client_id=client_id,
            pairwise_user_id=pairwise_user_id,
            browser_session_endpoint=browser_session_endpoint,
            session_id=session_id,
            return_to=return_to,
            company_domain=company_domain,
            now=now,
            lifetime_seconds=lifetime_seconds,
            random_bytes=random.bytes,
        )
        assertion = await signer.sign(claims.model_dump(), purpose="browser_assertion")
        await browser.post(claims.aud, {"assertion": assertion})
        return BrowserSessionStart(
            endpoint=claims.aud,
            return_to=claims.return_to,
            expires_at=datetime.fromtimestamp(claims.exp, timezone.utc),
        )


class BrowserAssertionReplayCache(Protocol):
    async def mark_once(self, key: str, *, expires_at: datetime) -> bool: ...


@dataclass(frozen=True)
class VerifiedBrowserAssertion:
    client_id: str
    pairwise_user_id: str
    session_id: str
    return_to: str
    expires_at: datetime


async def verify_browser_assertion(
    assertion: SecretStr | str,
    *,
    public_key: VerificationKey,
    expected_endpoint: str,
    company_domain: str,
    expected_client_id: str,
    expected_pairwise_user_id: str,
    expected_session_id: str,
    replay_cache: BrowserAssertionReplayCache,
    now: datetime | None = None,
) -> VerifiedBrowserAssertion:
    """Verify type, signature, bindings, lifetime, return target, and replay."""

    compact = assertion.get_secret_value() if isinstance(assertion, SecretStr) else assertion
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("verification time must include a timezone")
    try:
        header = jwt.get_unverified_header(compact)
        algorithm: JoseAlgorithm = _algorithm(str(header.get("alg", "")))
        if header.get("typ") != BROWSER_ASSERTION_TYPE:
            raise BrowserSessionError(
                "invalid_browser_assertion", "Browser assertion type is invalid"
            )
        claims: dict[str, Any] = jwt.decode(
            compact,
            public_key,
            algorithms=[algorithm],
            options={
                "require": ["iss", "sub", "aud", "session_id", "return_to", "iat", "exp", "jti"],
                "verify_aud": False,
                "verify_iat": False,
                "verify_exp": False,
            },
        )
    except BrowserSessionError:
        raise
    except (TypeError, ValueError, jwt.PyJWTError) as exc:
        raise BrowserSessionError(
            "invalid_browser_assertion", "Browser assertion signature or claims are invalid"
        ) from exc
    try:
        parsed = BrowserAssertionClaims.model_validate(claims)
        _company_return_to(parsed.return_to, company_domain)
    except ValueError as exc:
        raise BrowserSessionError(
            "invalid_browser_assertion", "Browser assertion claims are invalid"
        ) from exc
    now_seconds = int(current.timestamp())
    if parsed.iat > now_seconds or parsed.exp <= now_seconds:
        raise BrowserSessionError(
            "invalid_browser_assertion", "Browser assertion has expired or is not active"
        )
    if parsed.aud != _https_url(expected_endpoint, "expected_endpoint"):
        raise BrowserSessionError(
            "invalid_browser_assertion", "Browser assertion audience is invalid"
        )
    if (parsed.iss, parsed.sub, parsed.session_id) != (
        expected_client_id,
        expected_pairwise_user_id,
        expected_session_id,
    ):
        raise BrowserSessionError(
            "invalid_browser_assertion", "Browser assertion Session owner is invalid"
        )
    if not await replay_cache.mark_once(
        f"browser:{parsed.iss}:{parsed.jti}",
        expires_at=datetime.fromtimestamp(parsed.exp, timezone.utc),
    ):
        raise BrowserSessionError(
            "invalid_browser_assertion", "Browser assertion has already been used"
        )
    return VerifiedBrowserAssertion(
        parsed.iss,
        parsed.sub,
        parsed.session_id,
        parsed.return_to,
        datetime.fromtimestamp(parsed.exp, timezone.utc),
    )
