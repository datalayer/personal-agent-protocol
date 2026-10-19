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
    send_bounded,
)
from .refusals import refusal_details, refuse_redirect
from .telemetry import by_issuer, session_result, traced

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
JWT_CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

RandomBytes = Callable[[int], bytes]
#: A client or Session assertion's `exp` is at most this long after its `iat` (§4.1, §4.2).
ASSERTION_MAX_LIFETIME_SECONDS = 300


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
        _check_lifetime(self.iat, self.exp)
        return self


def _check_lifetime(iat: int, exp: int) -> None:
    if exp <= iat:
        raise ValueError("assertion expiration must be after issuance")
    if exp - iat > ASSERTION_MAX_LIFETIME_SECONDS:
        raise ValueError("an assertion expires at most five minutes after it is issued")


def _issued_at(now: datetime | None, lifetime_seconds: int) -> int:
    if not 0 < lifetime_seconds <= ASSERTION_MAX_LIFETIME_SECONDS:
        raise ValueError("assertion lifetime must be between 1 and 300 seconds")
    issued_at = now or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        raise ValueError("assertion time must include a timezone")
    return int(issued_at.timestamp())


def build_session_assertion_claims(
    *,
    client_id: str,
    pairwise_user_id: str,
    issuer: str,
    now: datetime | None = None,
    lifetime_seconds: int = 60,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> SessionAssertionClaims:
    """Build unsigned PAP 4.2 claims; a key-custody provider signs them.

    `aud` is the company's `auth.issuer`, one string, never an endpoint (§4.2, §9.4).
    """

    issued_at_seconds = _issued_at(now, lifetime_seconds)
    return SessionAssertionClaims(
        iss=client_id,
        sub=pairwise_user_id,
        aud=issuer,
        iat=issued_at_seconds,
        exp=issued_at_seconds + lifetime_seconds,
        jti=_opaque_id("jti", random_bytes),
    )


def build_client_assertion_claims(
    *,
    client_id: str,
    issuer: str,
    now: datetime | None = None,
    lifetime_seconds: int = 60,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> ClientAssertionClaims:
    """Build unsigned `private_key_jwt` claims for any request to the company's OAuth server.

    `aud` is the company's `auth.issuer`, one string, whichever endpoint the
    assertion goes to: token, revocation, or device authorization (§4.1, §9.4).
    """

    issued_at_seconds = _issued_at(now, lifetime_seconds)
    return ClientAssertionClaims(
        iss=client_id,
        sub=client_id,
        aud=issuer,
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
        _check_lifetime(self.iat, self.exp)
        return self


def token_types(*, dpop: bool, resource: str | None) -> frozenset[str]:
    """The token types a token request may be answered with (§4.3).

    With a proof: DPoP, or, for an MCP server (`resource`) that doesn't
    support DPoP, Bearer. Without one: Bearer, for an MCP server only.
    """

    if not dpop:
        return frozenset({"Bearer"})
    return frozenset({"DPoP", "Bearer"}) if resource is not None else frozenset({"DPoP"})


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

    @traced("pap.session.start", before=by_issuer, after=session_result)
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

    @traced("pap.session.renew", before=by_issuer, after=session_result)
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

    async def token_for_mcp(
        self,
        *,
        client_id: str,
        pairwise_user_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
        resource: str,
        dpop: bool,
        session_id: str | None = None,
    ) -> SessionToken:
        """A signed-out Session Token for one MCP server (§4.3).

        The request that starts the Session (no `session_id`) or renews its
        token, with `resource` set to the MCP server's `url` from poppy.json.
        `dpop` says whether the server supports DPoP, as its protected
        resource metadata lists `dpop_signing_alg_values_supported`
        (`mcp.McpServerMetadata.supports_dpop`): then the request carries a
        proof and the token is a DPoP one; otherwise no proof is sent and the
        token is a Bearer one, which works only at that server
        (`mcp.McpBearerAuth`). A token of the other type is refused.
        """

        return await self._request(
            client_id=client_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            token_endpoint=token_endpoint,
            tenant_id=tenant_id,
            session_id=session_id,
            resource=_mcp_resource(resource),
            dpop=dpop,
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
        resource: str | None = None,
        dpop: bool = True,
    ) -> SessionToken:
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        random_source = cast(
            RandomSource,
            first_contribution(self.reactor, RANDOM_SOURCES, "random source"),
        )
        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        prover = cast(
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
                issuer=issuer,
                now=now,
                random_bytes=random_source.bytes,
            )
            client_claims = build_client_assertion_claims(
                client_id=client_id, issuer=issuer, now=now, random_bytes=random_source.bytes
            )
            assertion = await signer.sign(session_claims.model_dump(), purpose="session_assertion")
            client_assertion = await signer.sign(
                client_claims.model_dump(), purpose="client_assertion"
            )
            headers = {"Accept": "application/json"}
            if dpop:
                proof = await prover.create(
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
                resource=resource,
            )
            try:
                response = await send_bounded(
                    self.http,
                    self.http.build_request(
                        "POST", token_endpoint, data=grant.as_form(), headers=headers
                    ),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise SessionError("request_failed", "Session token request failed") from exc
            refuse_redirect(response, SessionError)

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
                # The scheme `token_type` names is the one used (§4.3). A request with a
                # proof for an MCP server may get a Bearer token (a server without DPoP);
                # one without a proof never gets a DPoP token, nor anything else a Bearer.
                if token.token_type not in token_types(dpop=dpop, resource=resource) or (
                    session_id is not None and token.session_id != session_id
                ):
                    raise SessionError(
                        "unexpected_token_type",
                        "The Session request returned another token type or Session",
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
            raise SessionError(
                safe_code,
                "Company refused the session token request",
                status_code=response.status_code,
                details=refusal_details(response, payload) or None,
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
