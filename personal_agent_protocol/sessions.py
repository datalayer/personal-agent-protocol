# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe wire primitives for PAP session creation and renewal."""

from __future__ import annotations

import base64
import inspect
import secrets
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Literal, TypedDict, cast
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, field_validator, model_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import PersonalAgentProtocolError, ProtocolValidationError, SessionError
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
    #: Which of the User's agents the Session is for (§4.2): User-ID rules, kept for life.
    agent_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]{1,256}$")

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
    agent_id: str | None = None,
) -> SessionAssertionClaims:
    """Build unsigned PAP 4.2 claims; a key-custody provider signs them.

    `aud` is the company's `auth.issuer`, one string, never an endpoint (§4.2, §9.4).
    `agent_id`, when the User has several agents, says which one; left out otherwise.
    """

    issued_at_seconds = _issued_at(now, lifetime_seconds)
    return SessionAssertionClaims(
        iss=client_id,
        sub=pairwise_user_id,
        aud=issuer,
        iat=issued_at_seconds,
        exp=issued_at_seconds + lifetime_seconds,
        jti=_opaque_id("jti", random_bytes),
        agent_id=agent_id,
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
        if self.resource is not None:
            values["resource"] = self.resource
        return values


class Who(TypedDict):
    """Whose Session a request is for: the keyword arguments every client call takes."""

    tenant_id: str
    issuer: str


class TokenResponse(ProtocolModel):
    """A token endpoint's answer, as on the wire (§4.2, §4.4): no Session named in it."""

    access_token: SecretStr
    token_type: Literal["DPoP", "Bearer"]
    expires_in: int = Field(gt=0)
    scope: str | None = None
    refresh_token: SecretStr | None = None
    refresh_token_expires_in: int | None = Field(default=None, gt=0)
    issued_token_type: str | None = None


class SessionToken(ProtocolModel):
    """A Session Token, with what the SDK knows of it beside the wire response.

    `session_key` is the Session Key's thumbprint, which names the Session (§4.3).
    `signed_in` comes from the grant, never from the response (§4.2): the JWT bearer
    grant always answers signed out, a sign-in or an Account Token signed in. `scope`
    is what was granted: a signed-in response that leaves it out granted exactly the
    scopes requested (RFC 6749 §5.1), a signed-out one has none.
    """

    access_token: SecretStr
    token_type: Literal["DPoP", "Bearer"]
    expires_in: int = Field(gt=0)
    scope: str = ""
    session_key: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
    signed_in: bool
    refresh_token: SecretStr | None = None
    refresh_token_expires_in: int | None = None

    @property
    def scopes(self) -> tuple[str, ...]:
        """Granted scopes as an immutable collection."""

        return tuple(scope for scope in self.scope.split(" ") if scope)

    @classmethod
    def from_response(
        cls,
        response: TokenResponse,
        *,
        session_key: str,
        signed_in: bool,
        requested_scopes: tuple[str, ...] = (),
    ) -> SessionToken:
        if signed_in:
            scope = response.scope if response.scope is not None else " ".join(requested_scopes)
            if not scope.strip():
                # A sign-in grants at least one scope; approving none is a decline (§4.4).
                raise ProtocolValidationError(
                    "invalid_token_response", "A signed-in token response grants no scope"
                )
        else:
            scope = response.scope or ""
        return cls(
            access_token=response.access_token,
            token_type=response.token_type,
            expires_in=response.expires_in,
            scope=scope,
            session_key=session_key,
            signed_in=signed_in,
            refresh_token=response.refresh_token,
            refresh_token_expires_in=response.refresh_token_expires_in,
        )


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


TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - an OAuth token or grant type, not a credential
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - an OAuth token or grant type, not a credential


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
    """Start and renew signed-out PAP Sessions, each named by its own key (§4.2, §4.3)."""

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
        agent_id: str | None = None,
        resource: str | None = None,
    ) -> SessionToken:
        """Start a new signed-out Session with a new Session Key (§4.2).

        `resource` asks for a token for one service, such as an MCP server that
        supports DPoP (§4.3).
        """

        session_key = await self._prover().new_session_key(tenant_id=tenant_id, issuer=issuer)
        return await self._assert(
            client_id=client_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            token_endpoint=token_endpoint,
            tenant_id=tenant_id,
            session_key=session_key,
            agent_id=agent_id,
            resource=resource,
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
        session_key: str,
        agent_id: str | None = None,
        resource: str | None = None,
    ) -> SessionToken:
        """Renew a signed-out Session: fresh assertions, a proof from its own key (§4.2).

        `agent_id` is the one the Session started with, or none. `invalid_grant` means
        the Session has ended: its key is discarded, never used again, and the caller
        starts a new Session.
        """

        return await self._assert(
            client_id=client_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            token_endpoint=token_endpoint,
            tenant_id=tenant_id,
            session_key=session_key,
            agent_id=agent_id,
            resource=resource,
        )

    async def token_for_mcp(
        self,
        *,
        client_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
        session_key: str,
        subject_token: SecretStr,
        resource: str,
        scope: str | None = None,
    ) -> SessionToken:
        """A Bearer Session Token for one MCP server without DPoP, by Token Exchange (§4.3).

        `subject_token` is a current DPoP Session Token of the Session `session_key`
        names; the answer is a Bearer token for the same Session, working only at the
        MCP server whose `url` is `resource`, with the subject token's scopes or the
        fewer `scope` asks for. For a server that supports DPoP, start or renew with
        `resource` instead: a DPoP token, used with proofs.
        """

        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": subject_token.get_secret_value(),
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "resource": _mcp_resource(resource),
        }
        if scope is not None:
            form["scope"] = scope
        response = await self.token_request(
            client_id=client_id,
            issuer=issuer,
            token_endpoint=token_endpoint,
            tenant_id=tenant_id,
            session_key=session_key,
            form=lambda: form,
            error=SessionError,
        )
        if response.token_type != "Bearer" or response.issued_token_type != ACCESS_TOKEN_TYPE:  # noqa: S105 - an OAuth token or grant type, not a credential
            raise SessionError(
                "unexpected_token_type", "Token Exchange answered with another token type"
            )
        return SessionToken.from_response(
            response, session_key=session_key, signed_in=response.scope is not None
        )

    async def _assert(
        self,
        *,
        client_id: str,
        pairwise_user_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
        session_key: str,
        agent_id: str | None,
        resource: str | None,
    ) -> SessionToken:
        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        random_source = self._random()

        async def form() -> dict[str, str]:
            claims = build_session_assertion_claims(
                client_id=client_id,
                pairwise_user_id=pairwise_user_id,
                issuer=issuer,
                now=self._clock().now(),
                random_bytes=random_source.bytes,
                agent_id=agent_id,
            )
            assertion = await signer.sign(
                claims.model_dump(exclude_none=True), purpose="session_assertion"
            )
            values = {"grant_type": JWT_BEARER_GRANT, "assertion": assertion.get_secret_value()}
            if resource is not None:
                values["resource"] = _mcp_resource(resource)
            return values

        try:
            response = await self.token_request(
                client_id=client_id,
                issuer=issuer,
                token_endpoint=token_endpoint,
                tenant_id=tenant_id,
                session_key=session_key,
                form=form,
                error=SessionError,
            )
        except SessionError as exc:
            if exc.code == "invalid_grant":
                # The Session has ended or isn't this User's: never this key again (§4.2).
                await self._prover().discard_session_key(
                    tenant_id=tenant_id, issuer=issuer, session_key=session_key
                )
            raise
        if response.token_type != "DPoP":  # noqa: S105 - an OAuth token or grant type, not a credential
            # Bearer Session Tokens come from Token Exchange alone (§4.3).
            raise SessionError(
                "unexpected_token_type", "The Session request returned another token type"
            )
        # The JWT bearer grant always answers signed out (§4.2).
        return SessionToken.from_response(response, session_key=session_key, signed_in=False)

    async def token_request(
        self,
        *,
        client_id: str,
        issuer: str,
        token_endpoint: str,
        tenant_id: str,
        session_key: str,
        form: Callable[[], dict[str, str] | Awaitable[dict[str, str]]],
        error: type[PersonalAgentProtocolError],
    ) -> TokenResponse:
        """POST one grant to the token endpoint with the Session Key's proof (§4.2 to §4.8).

        `form` gives the grant's own fields, made again for a `use_dpop_nonce` retry so
        no assertion is sent twice; the client assertion and a fresh proof signed with
        `session_key`, the Session's name, go with every attempt. Raises `error` with the
        company's OAuth error code.
        """

        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        prover = self._prover()
        random_source = self._random()
        nonce: str | None = None
        for attempt in range(2):
            fields = form()
            if inspect.isawaitable(fields):
                fields = await fields
            client_claims = build_client_assertion_claims(
                client_id=client_id,
                issuer=issuer,
                now=self._clock().now(),
                random_bytes=random_source.bytes,
            )
            client_assertion = await signer.sign(
                client_claims.model_dump(), purpose="client_assertion"
            )
            proof = await prover.create(
                DpopProofRequest(
                    method="POST",
                    url=token_endpoint,
                    tenant_id=tenant_id,
                    issuer=issuer,
                    session_key=session_key,
                    nonce=nonce,
                )
            )
            data = {
                **fields,
                "client_id": client_id,
                "client_assertion_type": JWT_CLIENT_ASSERTION,
                "client_assertion": client_assertion.get_secret_value(),
            }
            try:
                response = await send_bounded(
                    self.http,
                    self.http.build_request(
                        "POST",
                        token_endpoint,
                        data=data,
                        headers={"Accept": "application/json", "DPoP": proof.get_secret_value()},
                    ),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise error("request_failed", "Token request failed") from exc
            refuse_redirect(response, error)
            if len(response.content) > self.max_response_bytes:
                raise error(
                    "response_too_large",
                    "Token response exceeds size limit",
                    status_code=response.status_code,
                )
            payload = self._decode(response, error)
            if response.is_success:
                try:
                    return TokenResponse.model_validate(payload)
                except (ValueError, ProtocolValidationError) as exc:
                    raise error(
                        "invalid_token_response",
                        "Token response is malformed",
                        status_code=response.status_code,
                    ) from exc
            error_code = payload.get("error") if isinstance(payload, dict) else None
            safe_code = error_code if isinstance(error_code, str) else "http_error"
            if safe_code == "use_dpop_nonce" and attempt == 0:
                nonce = response.headers.get("dpop-nonce")
                if not nonce:
                    raise error(
                        "missing_dpop_nonce",
                        "Company requested a DPoP nonce but did not send one",
                        status_code=response.status_code,
                    )
                continue
            raise error(
                safe_code,
                "Company refused the token request",
                status_code=response.status_code,
                details=refusal_details(response, payload) or None,
            )
        raise error("use_dpop_nonce", "Company rejected the refreshed DPoP proof")

    def _prover(self) -> DpopProofProvider:
        return cast(
            DpopProofProvider,
            first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
        )

    def _clock(self) -> Clock:
        return cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))

    def _random(self) -> RandomSource:
        return cast(RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source"))

    @staticmethod
    def _decode(response: httpx.Response, error: type[PersonalAgentProtocolError]) -> object:
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise error(
                "invalid_content_type",
                "Token endpoint must return JSON",
                status_code=response.status_code,
            )
        try:
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise error(
                "invalid_json",
                "Session token endpoint returned invalid JSON",
                status_code=response.status_code,
            ) from exc
