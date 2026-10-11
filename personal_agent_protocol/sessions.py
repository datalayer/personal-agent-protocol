# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe wire primitives for PAP session creation and renewal."""

from __future__ import annotations

import base64
import secrets
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Literal, TypedDict, cast
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, field_validator, model_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import ProtocolValidationError, SessionError
from .json import loads_strict
from .models import ProtocolModel
from .reactor import (
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    RANDOM_SOURCES,
    SIGNERS,
    Clock,
    DpopProofProvider,
    DpopProofRequest,
    RandomSource,
    Signer,
    first_contribution,
)

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
JWT_CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

RandomBytes = Callable[[int], bytes]


def _opaque_id(prefix: str, random_bytes: RandomBytes = secrets.token_bytes) -> str:
    """Generate a URL-safe identifier with at least 128 random bits."""

    entropy = random_bytes(16)
    if len(entropy) < 16:
        raise ValueError("identifier generation requires at least 128 random bits")
    encoded = base64.urlsafe_b64encode(entropy).decode().rstrip("=")
    return f"{prefix}_{encoded}"


def generate_pairwise_user_id(random_bytes: RandomBytes = secrets.token_bytes) -> str:
    """Generate a non-PII user ID to persist for one user/company issuer pair."""

    return _opaque_id("usr", random_bytes)


class SessionAssertionClaims(ProtocolModel):
    """Claims signed by the personal agent when starting or renewing a session."""

    iss: str
    sub: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    aud: str
    iat: int = Field(ge=0)
    exp: int = Field(gt=0)
    jti: str = Field(pattern=r"^[A-Za-z0-9_-]{22,256}$")

    @field_validator("iss", "aud")
    @classmethod
    def validate_https_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("assertion issuer and audience must be HTTPS URLs")
        return value

    @model_validator(mode="after")
    def validate_lifetime(self) -> SessionAssertionClaims:
        if self.exp <= self.iat:
            raise ValueError("assertion expiration must be after issuance")
        return self


def build_session_assertion_claims(
    *,
    client_id: str,
    pairwise_user_id: str,
    token_endpoint: str,
    now: datetime | None = None,
    lifetime_seconds: int = 60,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> SessionAssertionClaims:
    """Build unsigned PAP 4.2 claims; a key-custody provider signs them."""

    if lifetime_seconds <= 0:
        raise ValueError("assertion lifetime must be positive")
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        raise ValueError("assertion time must include a timezone")
    issued_at_seconds = int(issued_at.timestamp())
    return SessionAssertionClaims(
        iss=client_id,
        sub=pairwise_user_id,
        aud=token_endpoint,
        iat=issued_at_seconds,
        exp=issued_at_seconds + lifetime_seconds,
        jti=_opaque_id("jti", random_bytes),
    )


class SessionGrant(ProtocolModel):
    """Redacted form values for a PAP JWT-bearer session request."""

    grant_type: Literal["urn:ietf:params:oauth:grant-type:jwt-bearer"] = (
        "urn:ietf:params:oauth:grant-type:jwt-bearer"
    )
    assertion: SecretStr
    client_id: str
    client_assertion_type: Literal["urn:ietf:params:oauth:client-assertion-type:jwt-bearer"] = (
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    )
    client_assertion: SecretStr
    session_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,256}$")
    resource: str | None = None

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("client ID must be an HTTPS URL")
        return value

    def as_form(self) -> dict[str, str]:
        """Reveal assertions only at the final HTTP serialization boundary."""

        values = {
            "grant_type": self.grant_type,
            "assertion": self.assertion.get_secret_value(),
            "client_id": self.client_id,
            "client_assertion_type": self.client_assertion_type,
            "client_assertion": self.client_assertion.get_secret_value(),
        }
        if self.session_id is not None:
            values["session_id"] = self.session_id
        if self.resource is not None:
            values["resource"] = self.resource
        return values


class Who(TypedDict):
    """Whose Session a request is for: the keyword arguments every client call takes."""

    tenant_id: str
    pairwise_user_id: str
    issuer: str


class SessionToken(ProtocolModel):
    """Opaque token response returned by a PAP company."""

    access_token: SecretStr
    token_type: Literal["DPoP", "Bearer"]
    expires_in: int = Field(gt=0)
    scope: str = ""
    session_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    signed_in: bool
    refresh_token: SecretStr | None = None

    @property
    def scopes(self) -> tuple[str, ...]:
        """Granted scopes as an immutable collection."""

        return tuple(scope for scope in self.scope.split(" ") if scope)


class ClientAssertionClaims(ProtocolModel):
    """OAuth private-key JWT claims signed by the personal agent."""

    iss: str
    sub: str
    aud: str
    iat: int = Field(ge=0)
    exp: int = Field(gt=0)
    jti: str = Field(pattern=r"^[A-Za-z0-9_-]{22,256}$")

    @field_validator("iss", "sub", "aud")
    @classmethod
    def validate_https_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("client assertion URLs must use HTTPS")
        return value

    @model_validator(mode="after")
    def validate_lifetime(self) -> ClientAssertionClaims:
        if self.exp <= self.iat:
            raise ValueError("assertion expiration must be after issuance")
        return self


def _mcp_resource(value: str) -> str:
    """An MCP server's `url` as a `resource` indicator: HTTPS, no fragment (RFC 8707)."""

    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError("an MCP resource must be an HTTPS URL without a fragment")
    return value


class SessionClient:
    """Start and renew signed-out PAP sessions over the OAuth token endpoint."""

    def __init__(
        self,
        *,
        reactor: PluginPlatform,
        http_client: httpx.AsyncClient,
        max_response_bytes: int = 100 * 1024,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.reactor = reactor
        self.http = http_client
        self.max_response_bytes = max_response_bytes

    async def start(
        self,
        *,
        client_id: str,
        pairwise_user_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
    ) -> SessionToken:
        """Start a new signed-out session with fresh assertions and DPoP."""

        return await self._request(
            client_id=client_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            token_endpoint=token_endpoint,
            tenant_id=tenant_id,
            session_id=None,
        )

    async def renew(
        self,
        *,
        client_id: str,
        pairwise_user_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
        session_id: str,
    ) -> SessionToken:
        """Renew a signed-out session by including its non-secret session ID."""

        return await self._request(
            client_id=client_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            token_endpoint=token_endpoint,
            tenant_id=tenant_id,
            session_id=session_id,
        )

    async def bearer_for_mcp(
        self,
        *,
        client_id: str,
        pairwise_user_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
        session_id: str,
        resource: str,
    ) -> SessionToken:
        """A signed-out Bearer Session Token for one MCP server (§4.3).

        The renewal request of the Session, without a DPoP proof, with
        `resource` set to the MCP server's `url` from poppy.json. The token
        works only there: hand it to `mcp.McpBearerAuth`, never to an API.
        """

        return await self._request(
            client_id=client_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            token_endpoint=token_endpoint,
            tenant_id=tenant_id,
            session_id=session_id,
            bearer_resource=_mcp_resource(resource),
        )

    async def _request(
        self,
        *,
        client_id: str,
        pairwise_user_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
        session_id: str | None,
        bearer_resource: str | None = None,
    ) -> SessionToken:
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        random_source = cast(
            RandomSource,
            first_contribution(self.reactor, RANDOM_SOURCES, "random source"),
        )
        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        dpop = cast(
            DpopProofProvider,
            first_contribution(
                self.reactor,
                DPOP_PROOF_PROVIDERS,
                "DPoP proof provider",
            ),
        )
        nonce: str | None = None
        for attempt in range(2):
            now = clock.now()
            session_claims = build_session_assertion_claims(
                client_id=client_id,
                pairwise_user_id=pairwise_user_id,
                token_endpoint=token_endpoint,
                now=now,
                random_bytes=random_source.bytes,
            )
            issued_at = int(now.timestamp())
            client_claims = ClientAssertionClaims(
                iss=client_id,
                sub=client_id,
                aud=token_endpoint,
                iat=issued_at,
                exp=issued_at + 60,
                jti=_opaque_id("jti", random_source.bytes),
            )
            assertion = await signer.sign(session_claims.model_dump(), purpose="session_assertion")
            client_assertion = await signer.sign(
                client_claims.model_dump(), purpose="client_assertion"
            )
            headers = {"Accept": "application/json"}
            if bearer_resource is None:
                proof = await dpop.create(
                    DpopProofRequest(
                        method="POST",
                        url=token_endpoint,
                        tenant_id=tenant_id,
                        subject=pairwise_user_id,
                        issuer=issuer,
                        nonce=nonce,
                    )
                )
                headers["DPoP"] = proof.get_secret_value()
            grant = SessionGrant(
                assertion=assertion,
                client_id=client_id,
                client_assertion=client_assertion,
                session_id=session_id,
                resource=bearer_resource,
            )
            try:
                response = await self.http.post(
                    token_endpoint,
                    data=grant.as_form(),
                    headers=headers,
                    follow_redirects=False,
                )
            except httpx.HTTPError as exc:
                raise SessionError("request_failed", "Session token request failed") from exc

            if len(response.content) > self.max_response_bytes:
                raise SessionError(
                    "response_too_large",
                    "Session token response exceeds size limit",
                    status_code=response.status_code,
                )
            payload = self._decode(response)
            if response.is_success:
                try:
                    token = SessionToken.model_validate(payload)
                except (ValueError, ProtocolValidationError) as exc:
                    raise SessionError(
                        "invalid_token_response",
                        "Session token response is malformed",
                        status_code=response.status_code,
                    ) from exc
                expected = "DPoP" if bearer_resource is None else "Bearer"
                if token.token_type != expected or (
                    bearer_resource is not None and token.session_id != session_id
                ):
                    raise SessionError(
                        "unexpected_token_type",
                        f"The Session request must return a {expected} token for this Session",
                        status_code=response.status_code,
                    )
                return token

            error_code = payload.get("error") if isinstance(payload, dict) else None
            safe_code = error_code if isinstance(error_code, str) else "http_error"
            if safe_code == "use_dpop_nonce" and attempt == 0:
                nonce = response.headers.get("dpop-nonce")
                if not nonce:
                    raise SessionError(
                        "missing_dpop_nonce",
                        "Company requested a DPoP nonce but did not send one",
                        status_code=response.status_code,
                    )
                continue
            retry_after = response.headers.get("retry-after")
            raise SessionError(
                safe_code,
                "Company refused the session token request",
                status_code=response.status_code,
                details={"retry_after": retry_after} if retry_after else None,
            )

        raise SessionError("use_dpop_nonce", "Company rejected the refreshed DPoP proof")

    @staticmethod
    def _decode(response: httpx.Response) -> object:
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise SessionError(
                "invalid_content_type",
                "Session token endpoint must return JSON",
                status_code=response.status_code,
            )
        try:
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise SessionError(
                "invalid_json",
                "Session token endpoint returned invalid JSON",
                status_code=response.status_code,
            ) from exc
