# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Device Sign-In with private polling state and proof-bound tokens."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal, cast
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr, field_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .auth import _https_url, _scopes
from .errors import AuthorizationError, ProtocolValidationError
from .json import loads_strict
from .models import Organization, ProtocolModel
from .reactor import (
    AUTHORIZATION_STATE_STORES,
    CLOCKS,
    RANDOM_SOURCES,
    SIGNERS,
    AuthorizationStateStore,
    Clock,
    RandomSource,
    Signer,
    first_contribution,
    send_bounded,
)
from .refusals import refusal_code, refusal_details, refuse_redirect, refused_without_body
from .sessions import (
    JWT_CLIENT_ASSERTION,
    AccessToken,
    SessionClient,
    TokenResponse,
    _opaque_id,
    build_client_assertion_claims,
    finish_sign_in,
)
from .telemetry import sign_in_method, sign_in_result, signed_in_as, traced

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class DeviceAuthorizationResponse(ProtocolModel):
    """Validated response from the OAuth device authorization endpoint."""

    device_code: SecretStr
    user_code: str = Field(min_length=1, max_length=256)
    verification_uri: str
    verification_uri_complete: str | None = None
    expires_in: int = Field(gt=0, le=3600)
    interval: int = Field(default=5, gt=0, le=300)

    @field_validator("verification_uri", "verification_uri_complete")
    @classmethod
    def validate_verification_url(cls, value: str | None) -> str | None:
        return None if value is None else _https_url(value, "verification URI")


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().rstrip(".")


def _within(host: str, domain: str) -> bool:
    return host == domain or host.endswith(f".{domain}")


def verification_host_allowed(url: str, *, issuer: str, protected_resources: Sequence[str]) -> bool:
    """Whether a device sign-in link may be shown for this company (§4.6).

    Its host is the host of `auth.issuer` or of a URL in the issuer's
    `protected_resources`, or a subdomain of either; otherwise a company could
    pass off another company's sign-in page as its own.
    """

    host = _host(url)
    allowed = [_host(issuer), *(_host(resource) for resource in protected_resources)]
    return bool(host) and any(domain and _within(host, domain) for domain in allowed)


class DeviceSignInStart(ProtocolModel):
    """User-facing device instructions without the private device code.

    `organization_name` and `organization_domain` are the company's, shown
    with the link and the code whenever they are (§4.6).
    """

    reference: str = Field(pattern=r"^device_[A-Za-z0-9_-]{22,}$")
    organization_name: str
    organization_domain: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None = None
    expires_at: datetime
    poll_interval: int
    requested_scopes: tuple[str, ...]


class DeviceSignInPoll(ProtocolModel):
    """One poll result; pending responses tell callers when to try again."""

    status: Literal["pending", "complete"]
    retry_at: datetime | None = None
    token: AccessToken | None = None
    refresh_token_reference: str | None = None
    granted_scopes: tuple[str, ...] = ()
    missing_scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _PendingDeviceSignIn:
    device_code: SecretStr
    token_endpoint: str
    issuer: str
    client_id: str
    tenant_id: str
    scopes: tuple[str, ...]
    expires_at: datetime
    next_poll_at: datetime
    interval: int


class DeviceSignInClient:
    """Start and poll PAP Device Sign-In without exposing the device code."""

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
        self.sessions = SessionClient(
            reactor=reactor, http_client=http_client, max_response_bytes=max_response_bytes
        )

    @traced("pap.sign_in.device.begin", before=signed_in_as("device"), after=sign_in_result)
    async def begin(
        self,
        *,
        device_authorization_endpoint: str,
        token_endpoint: str,
        issuer: str,
        client_id: str,
        scopes: tuple[str, ...],
        tenant_id: str,
        organization: Organization,
        protected_resources: Sequence[str],
    ) -> DeviceSignInStart:
        """Request a device code and retain it behind an opaque state reference (§4.3).

        Plain OAuth: the sign-in names no Session. `organization` is the company's, from its
        poppy.json, and
        `protected_resources` its issuer's (OAuth metadata): the verification link
        is refused (`unsafe_verification_uri`) unless its host is the issuer's or
        one of those resources', or a subdomain of either (§4.6).
        """

        clock, random_source, signer = self._proof_inputs()
        now = clock.now()
        endpoint = _https_url(device_authorization_endpoint, "device authorization endpoint")
        token_url = _https_url(token_endpoint, "token endpoint")
        client_url = _https_url(client_id, "client ID")
        issuer_url = _https_url(issuer, "issuer")
        requested_scopes = _scopes(scopes)
        self._validate_context(tenant_id)
        assertion = await signer.sign(
            build_client_assertion_claims(
                client_id=client_url, issuer=issuer_url, now=now, random_bytes=random_source.bytes
            ).model_dump(),
            purpose="client_assertion",
        )
        try:
            response = await send_bounded(
                self.http,
                self.http.build_request(
                    "POST",
                    endpoint,
                    data={
                        "scope": " ".join(requested_scopes),
                        "client_id": client_url,
                        "client_assertion_type": JWT_CLIENT_ASSERTION,
                        "client_assertion": assertion.get_secret_value(),
                    },
                    headers={"Accept": "application/json"},
                ),
                max_bytes=self.max_response_bytes,
            )
        except httpx.HTTPError as exc:
            raise AuthorizationError(
                "request_failed", "Device authorization request failed"
            ) from exc
        refuse_redirect(response, AuthorizationError)
        # A 429 has `Retry-After` and no body (§5.6).
        payload = (
            None
            if refused_without_body(response)
            else self._decode(response, "device authorization")
        )
        if not response.is_success:
            raise self._remote_error(response, payload, "Company refused Device Sign-In")
        try:
            authorization = DeviceAuthorizationResponse.model_validate(payload)
        except ValueError as exc:
            raise AuthorizationError(
                "invalid_device_response",
                "Device authorization response is malformed",
                status_code=response.status_code,
            ) from exc
        for link in (authorization.verification_uri, authorization.verification_uri_complete):
            if link is not None and not verification_host_allowed(
                link, issuer=issuer_url, protected_resources=protected_resources
            ):
                raise AuthorizationError(
                    "unsafe_verification_uri",
                    "The device sign-in link is not on the company's issuer or its domains",
                    status_code=response.status_code,
                )
        expires_at = now + timedelta(seconds=authorization.expires_in)
        reference = _opaque_id("device", random_source.bytes)
        pending = _PendingDeviceSignIn(
            device_code=authorization.device_code,
            token_endpoint=token_url,
            issuer=issuer_url,
            client_id=client_url,
            tenant_id=tenant_id,
            scopes=requested_scopes,
            expires_at=expires_at,
            next_poll_at=now + timedelta(seconds=authorization.interval),
            interval=authorization.interval,
        )
        store = self._state_store()
        await store.put(reference, pending, expires_at=expires_at)
        return DeviceSignInStart(
            reference=reference,
            organization_name=organization.name,
            organization_domain=organization.domain,
            user_code=authorization.user_code,
            verification_uri=authorization.verification_uri,
            verification_uri_complete=authorization.verification_uri_complete,
            expires_at=expires_at,
            poll_interval=authorization.interval,
            requested_scopes=requested_scopes,
        )

    @traced("pap.sign_in.device.poll", before=sign_in_method("device"), after=sign_in_result)
    async def poll(self, reference: str) -> DeviceSignInPoll:
        """Perform at most one protocol poll and enforce RFC 8628 pacing."""

        store = self._state_store()
        pending = await store.take(reference)
        if not isinstance(pending, _PendingDeviceSignIn):
            raise AuthorizationError(
                "invalid_or_expired_device_session",
                "Device Sign-In is unknown, expired, complete, or already being polled",
            )
        clock, random_source, _ = self._proof_inputs()
        now = clock.now()
        if now >= pending.expires_at:
            raise AuthorizationError("expired_token", "Device Sign-In has expired")
        if now < pending.next_poll_at:
            await store.put(reference, pending, expires_at=pending.expires_at)
            return DeviceSignInPoll(status="pending", retry_at=pending.next_poll_at)

        try:
            response = await self.sessions.token_request(
                client_id=pending.client_id,
                issuer=pending.issuer,
                token_endpoint=pending.token_endpoint,
                form=lambda: {
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": pending.device_code.get_secret_value(),
                },
                error=AuthorizationError,
            )
        except AuthorizationError as exc:
            if exc.code in {"authorization_pending", "slow_down"}:
                interval = pending.interval + (5 if exc.code == "slow_down" else 0)
                resumed = replace(
                    pending,
                    interval=interval,
                    next_poll_at=now + timedelta(seconds=interval),
                )
                await store.put(reference, resumed, expires_at=pending.expires_at)
                return DeviceSignInPoll(status="pending", retry_at=resumed.next_poll_at)
            if exc.code in {"access_denied", "expired_token"}:
                raise AuthorizationError(
                    exc.code, "Device Sign-In ended without authorization"
                ) from exc
            await store.put(reference, pending, expires_at=pending.expires_at)
            raise
        except Exception:
            await store.put(reference, pending, expires_at=pending.expires_at)
            raise
        return await self._complete(response, pending, random_source)

    async def _complete(
        self,
        response: TokenResponse,
        pending: _PendingDeviceSignIn,
        random_source: RandomSource,
    ) -> DeviceSignInPoll:
        if response.refresh_token is None:
            raise AuthorizationError(
                "missing_refresh_token", "Device Sign-In did not return a refresh token"
            )
        result = await finish_sign_in(
            self.reactor, response, pending.scopes, error=AuthorizationError
        )
        return DeviceSignInPoll(status="complete", **dict(result))

    def _proof_inputs(self) -> tuple[Clock, RandomSource, Signer]:
        return (
            cast(Clock, first_contribution(self.reactor, CLOCKS, "clock")),
            cast(RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")),
            cast(Signer, first_contribution(self.reactor, SIGNERS, "signer")),
        )

    def _state_store(self) -> AuthorizationStateStore:
        return cast(
            AuthorizationStateStore,
            first_contribution(
                self.reactor, AUTHORIZATION_STATE_STORES, "authorization state store"
            ),
        )

    @staticmethod
    def _validate_context(tenant_id: str) -> None:
        if not tenant_id or len(tenant_id) > 256:
            raise ValueError("tenant_id must contain between 1 and 256 characters")

    def _decode(self, response: httpx.Response, label: str) -> object:
        if len(response.content) > self.max_response_bytes:
            raise AuthorizationError(
                "response_too_large",
                f"{label.title()} response exceeds size limit",
                status_code=response.status_code,
            )
        if response.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise AuthorizationError(
                "invalid_content_type",
                f"{label.title()} endpoint must return JSON",
                status_code=response.status_code,
            )
        try:
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise AuthorizationError(
                "invalid_json",
                f"{label.title()} endpoint returned invalid JSON",
                status_code=response.status_code,
            ) from exc

    @staticmethod
    def _remote_error(
        response: httpx.Response, payload: object, message: str
    ) -> AuthorizationError:
        return AuthorizationError(
            refusal_code(response, payload, "http_error"),
            message,
            status_code=response.status_code,
            details=refusal_details(response, payload) or None,
        )
