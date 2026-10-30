# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Sessions, client assertions, and plain OAuth token responses (§4, §5).

A Session is local: `SessionClient.start` chooses its `sid` at random and asks
the company nothing (§5.2). Every request then carries a Session JWT the
`pap.sessionSigner` signs for it (`transport.SessionHttpClient`). Account access
is plain OAuth: sign-in and refresh return an access token and a refresh token
(§4.4, §4.5, §4.7). The token endpoint gets a client assertion, and a DPoP proof when
the issuer's metadata lists ES256 (§4.5).
"""

from __future__ import annotations

import base64
import inspect
import secrets
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal, cast
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, field_validator, model_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .crypto import DPOP_ALGORITHM, SESSION_ID
from .errors import PersonalAgentProtocolError, ProtocolValidationError, SessionError
from .json import loads_strict
from .models import ProtocolModel
from .reactor import (
    CLOCKS,
    DPOP_PROVERS,
    RANDOM_SOURCES,
    SIGNERS,
    TOKEN_STORES,
    Clock,
    DpopProofRequest,
    DpopProver,
    RandomSource,
    Signer,
    TokenStore,
    first_contribution,
    send_bounded,
)
from .refusals import refusal_code, refusal_details, refuse_redirect, refused_without_body
from .telemetry import by_issuer, session_result, traced

JWT_CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

RandomBytes = Callable[[int], bytes]
#: The header that carries a DPoP proof (RFC 9449 §4.1).
DPOP_HEADER = "DPoP"
#: The header a server gives a DPoP nonce in (RFC 9449 §8).
DPOP_NONCE_HEADER = "DPoP-Nonce"
#: A client assertion's `exp` is at most this long after its `iat` (§4.1).
ASSERTION_MAX_LIFETIME_SECONDS = 300


def _opaque_id(prefix: str, random_bytes: RandomBytes = secrets.token_bytes) -> str:
    """Generate a URL-safe identifier with at least 128 random bits."""

    return f"{prefix}_{_random_id(random_bytes)}"


def _random_id(random_bytes: RandomBytes) -> str:
    entropy = random_bytes(16)
    if len(entropy) < 16:
        raise ValueError("identifier generation requires at least 128 random bits")
    return base64.urlsafe_b64encode(entropy).decode().rstrip("=")


def generate_pairwise_user_id(random_bytes: RandomBytes = secrets.token_bytes) -> str:
    """Generate a non-PII user ID to persist for one user/company issuer pair."""

    return _opaque_id("usr", random_bytes)


def new_session_id(random_bytes: RandomBytes = secrets.token_bytes) -> str:
    """A new `sid`: 128 random bits, 22 URL-safe characters, never used again (§5.2)."""

    return _random_id(random_bytes)


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


class ClientAssertionClaims(ProtocolModel):
    """OAuth private-key JWT claims signed by the personal agent (§4.1)."""

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


def build_client_assertion_claims(
    *,
    client_id: str,
    issuer: str,
    now: datetime | None = None,
    lifetime_seconds: int = 60,
    random_bytes: RandomBytes = secrets.token_bytes,
) -> ClientAssertionClaims:
    """Build unsigned `private_key_jwt` claims for any request to the company's OAuth server.

    `aud` is the company's issuer, one string, whichever endpoint the assertion goes
    to: token, revocation, or device authorization (§4.1, §10.4). `jti` is drawn
    here, on the device, so a blind signer never chooses it (§10.7).
    """

    issued_at_seconds = _issued_at(now, lifetime_seconds)
    return ClientAssertionClaims(
        iss=client_id,
        sub=client_id,
        aud=issuer,
        iat=issued_at_seconds,
        exp=issued_at_seconds + lifetime_seconds,
        jti=_random_id(random_bytes),
    )


@dataclass
class PapSession:
    """One Session: a User at one Company through this personal agent (§5).

    Local: `sid` names it, chosen at random; `sub` is the User ID for the Company's
    `issuer`, `agent_id` the optional Agent ID, both the same for its whole life.
    When the company answers `invalid_session`, `restart` gives it a new `sid` once
    (§5.5, §7); its handle for a person is `ses_` and the `sid`.
    """

    sid: str
    sub: str
    issuer: str
    client_id: str
    tenant_id: str
    agent_id: str | None = None

    def __post_init__(self) -> None:
        if not SESSION_ID.fullmatch(self.sid):
            raise ValueError("a Session ID is 22 to 256 URL-safe characters")
        if not self.sub:
            raise ValueError("a Session names its User ID")
        for name in ("issuer", "client_id"):
            parsed = urlsplit(getattr(self, name))
            if parsed.scheme != "https" or not parsed.hostname:
                raise ValueError(f"a Session's {name} is an HTTPS URL")
        if not self.tenant_id or len(self.tenant_id) > 256:
            raise ValueError("tenant_id must contain between 1 and 256 characters")

    @property
    def handle(self) -> str:
        """The Session's name for a person or a CLI: `ses_` and its `sid`."""

        return f"ses_{self.sid}"

    @property
    def pairwise_user_id(self) -> str:
        return self.sub

    def restart(self, random_bytes: RandomBytes = secrets.token_bytes) -> str:
        """Start a new Session in its place: a new `sid`, the same User and Agent ID."""

        self.sid = new_session_id(random_bytes)
        return self.sid

    def to_json(self) -> dict[str, str | None]:
        return {
            "sid": self.sid,
            "sub": self.sub,
            "issuer": self.issuer,
            "client_id": self.client_id,
            "tenant_id": self.tenant_id,
            "agent_id": self.agent_id,
        }

    @classmethod
    def from_json(cls, value: dict[str, str | None]) -> PapSession:
        return cls(
            sid=str(value["sid"]),
            sub=str(value["sub"]),
            issuer=str(value["issuer"]),
            client_id=str(value["client_id"]),
            tenant_id=str(value["tenant_id"]),
            agent_id=value.get("agent_id"),
        )


class TokenResponse(ProtocolModel):
    """A token endpoint's answer, as on the wire (§4.7): plain OAuth.

    `token_type` is compared ignoring case (RFC 6749 §5.1): `Bearer` or `DPoP`.
    """

    access_token: SecretStr
    token_type: str
    expires_in: int | None = Field(default=None, gt=0)
    scope: str | None = None
    refresh_token: SecretStr | None = None

    @field_validator("token_type")
    @classmethod
    def validate_token_type(cls, value: str) -> str:
        if value.lower() == "dpop":
            return "DPoP"
        if value.lower() != "bearer":
            raise ValueError("an access token is Bearer or DPoP")
        return "Bearer"


class AccessToken(ProtocolModel):
    """An access token for one account, kept beside what the SDK knows of it (§4.5).

    `resource` is the service it was issued for, or `None` for the default token
    that works at all of the Company's services but one that asks for its own.
    `scope` is what was granted: a response that leaves it out granted exactly the
    scopes requested (RFC 6749 §5.1). Never the refresh token: that one stays in
    `pap.tokenStore`. `token_type` says how it is sent: `DPoP`, bound to the Company's
    DPoP key, with a proof on every request (§4.5). Refresh tokens aren't bound, so
    a lost key means refreshing, not signing in again (RFC 9449 §5).
    """

    access_token: SecretStr
    token_type: Literal["Bearer", "DPoP"] = "Bearer"
    expires_in: int | None = None
    scope: str = ""
    resource: str | None = None

    @property
    def scopes(self) -> tuple[str, ...]:
        """Granted scopes as an immutable collection."""

        return tuple(scope for scope in self.scope.split(" ") if scope)

    @classmethod
    def from_response(
        cls,
        response: TokenResponse,
        *,
        requested_scopes: tuple[str, ...] = (),
        resource: str | None = None,
    ) -> AccessToken:
        scope = response.scope if response.scope is not None else " ".join(requested_scopes)
        if not scope.strip():
            # A sign-in grants at least one scope; approving none is a decline (§4.7).
            raise ProtocolValidationError(
                "invalid_token_response", "A token response grants no scope"
            )
        return cls(
            access_token=response.access_token,
            token_type=cast(Literal["Bearer", "DPoP"], response.token_type),
            expires_in=response.expires_in,
            scope=scope,
            resource=resource,
        )


class SignInResult(ProtocolModel):
    """A completed sign-in (§4.7): the access token, and the refresh token's reference.

    The refresh token never stays in `token`: it is moved into `pap.tokenStore`
    behind `refresh_token_reference`. `missing_scopes` are requested scopes the
    User didn't approve.
    """

    token: AccessToken
    granted_scopes: tuple[str, ...]
    missing_scopes: tuple[str, ...]
    refresh_token_reference: str | None = None


async def finish_sign_in(
    reactor: PluginPlatform,
    response: TokenResponse,
    requested: tuple[str, ...],
    *,
    error: type[PersonalAgentProtocolError],
) -> SignInResult:
    """Check a sign-in's token response and keep its refresh token behind a reference.

    At least one scope is granted, and none beyond those requested (§4.7).
    """

    try:
        token = AccessToken.from_response(response, requested_scopes=requested)
    except ProtocolValidationError as exc:
        raise error("invalid_token_response", exc.message) from exc
    granted = token.scopes
    if any(scope not in requested for scope in granted):
        raise error("scope_escalation", "Company returned a scope that was not requested")
    reference: str | None = None
    if response.refresh_token is not None:
        random = cast(RandomSource, first_contribution(reactor, RANDOM_SOURCES, "random source"))
        reference = _opaque_id("refresh", random.bytes)
        store = cast(TokenStore, first_contribution(reactor, TOKEN_STORES, "token store"))
        await store.put(reference, response.refresh_token)
    return SignInResult(
        token=token,
        granted_scopes=granted,
        missing_scopes=tuple(scope for scope in requested if scope not in granted),
        refresh_token_reference=reference,
    )


class SessionClient:
    """Start Sessions, and send grants to the company's token endpoint (§4, §5)."""

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
        tenant_id: str,
        agent_id: str | None = None,
    ) -> PapSession:
        """A new Session, signed out, with a new random `sid` (§5.2): no request is sent.

        `pairwise_user_id` is the User ID for the Company's `issuer` (§5.1);
        `agent_id`, when the User has several agents, says which one.
        """

        return PapSession(
            sid=new_session_id(self._random().bytes),
            sub=pairwise_user_id,
            issuer=issuer,
            client_id=client_id,
            tenant_id=tenant_id,
            agent_id=agent_id,
        )

    async def token_request(
        self,
        *,
        client_id: str,
        issuer: str,
        token_endpoint: str,
        form: Callable[[], dict[str, str] | Awaitable[dict[str, str]]],
        error: type[PersonalAgentProtocolError],
        tenant_id: str,
        dpop_signing_algs: Sequence[str] | None,
    ) -> TokenResponse:
        """POST one grant to the token endpoint with a fresh client assertion (§4.1, §4.4).

        `form` gives the grant's own fields. No Session header goes to an OAuth
        endpoint (§5.2). `dpop_signing_algs` is the issuer's
        `dpop_signing_alg_values_supported`: when it includes ES256 a DPoP proof goes
        with the request, so the Company can bind the tokens (§4.5), and a
        `use_dpop_nonce` refusal is retried once, with a fresh proof and client
        assertion. Raises `error` with the company's OAuth error code.
        """

        fields = form()
        if inspect.isawaitable(fields):
            fields = await fields
        proves = dpop_signing_algs is not None and DPOP_ALGORITHM in dpop_signing_algs
        nonce: str | None = None
        while True:
            response, payload = await self._post_grant(
                fields,
                client_id=client_id,
                issuer=issuer,
                token_endpoint=token_endpoint,
                error=error,
                proof=(
                    await self._proof(token_endpoint, tenant_id, issuer, nonce) if proves else None
                ),
            )
            given = response.headers.get(DPOP_NONCE_HEADER)
            if (
                not proves
                or nonce is not None
                or given is None
                or response.status_code != 400
                or not isinstance(payload, dict)
                or payload.get("error") != "use_dpop_nonce"
            ):
                break
            nonce = given
        if response.is_success:
            try:
                token = TokenResponse.model_validate(payload)
            except (ValueError, ProtocolValidationError) as exc:
                raise error(
                    "invalid_token_response",
                    "Token response is malformed",
                    status_code=response.status_code,
                ) from exc
            if token.token_type == "DPoP" and not proves:
                raise error(
                    "unsupported_token_type",
                    "The company bound the token to a key no proof showed",
                    status_code=response.status_code,
                )
            return token
        raise error(
            refusal_code(response, payload, "http_error"),
            "Company refused the token request",
            status_code=response.status_code,
            details=refusal_details(response, payload) or None,
        )

    async def _proof(
        self, token_endpoint: str, tenant_id: str, issuer: str, nonce: str | None
    ) -> SecretStr:
        prover = cast(DpopProver, first_contribution(self.reactor, DPOP_PROVERS, "DPoP prover"))
        return await prover.prove(
            DpopProofRequest(
                method="POST",
                url=token_endpoint,
                tenant_id=tenant_id,
                issuer=issuer,
                nonce=nonce,
            )
        )

    async def _post_grant(
        self,
        fields: dict[str, str],
        *,
        client_id: str,
        issuer: str,
        token_endpoint: str,
        error: type[PersonalAgentProtocolError],
        proof: SecretStr | None,
    ) -> tuple[httpx.Response, object]:
        """One POST of a grant, with a fresh client assertion: its response and JSON body."""

        data = {**fields, **(await self.client_authentication(client_id=client_id, issuer=issuer))}
        headers = {"Accept": "application/json"}
        if proof is not None:
            headers[DPOP_HEADER] = proof.get_secret_value()
        try:
            response = await send_bounded(
                self.http,
                self.http.build_request("POST", token_endpoint, data=data, headers=headers),
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
        # A 429 has `Retry-After` and no body (§5.6).
        return response, None if refused_without_body(response) else self._decode(response, error)

    async def client_authentication(self, *, client_id: str, issuer: str) -> dict[str, str]:
        """`client_id` and a fresh client assertion, as form fields (§4.1)."""

        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        claims = build_client_assertion_claims(
            client_id=client_id,
            issuer=issuer,
            now=self._clock().now(),
            random_bytes=self._random().bytes,
        )
        assertion = await signer.sign(claims.model_dump(), purpose="client_assertion")
        return {
            "client_id": client_id,
            "client_assertion_type": JWT_CLIENT_ASSERTION,
            "client_assertion": assertion.get_secret_value(),
        }

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
                "Token endpoint returned invalid JSON",
                status_code=response.status_code,
            ) from exc


__all__ = [
    "ASSERTION_MAX_LIFETIME_SECONDS",
    "DPOP_HEADER",
    "DPOP_NONCE_HEADER",
    "JWT_CLIENT_ASSERTION",
    "AccessToken",
    "ClientAssertionClaims",
    "PapSession",
    "SessionClient",
    "SessionError",
    "SignInResult",
    "TokenResponse",
    "build_client_assertion_claims",
    "finish_sign_in",
    "generate_pairwise_user_id",
    "new_session_id",
]
