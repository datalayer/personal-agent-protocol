# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Device Sign-In with private polling state and proof-bound tokens."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal, cast

import httpx
from pydantic import Field, SecretStr, field_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .auth import _https_url, _scopes
from .errors import AuthorizationError, ProtocolValidationError
from .json import loads_strict
from .models import ProtocolModel
from .reactor import (
    AUTHORIZATION_STATE_STORES,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    RANDOM_SOURCES,
    SIGNERS,
    TOKEN_STORES,
    AuthorizationStateStore,
    Clock,
    DpopProofProvider,
    DpopProofRequest,
    RandomSource,
    Signer,
    TokenStore,
    first_contribution,
)
from .sessions import JWT_CLIENT_ASSERTION, ClientAssertionClaims, SessionToken, _opaque_id
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


class DeviceSignInStart(ProtocolModel):
    """User-facing device instructions without the private device code."""

    reference: str = Field(pattern=r"^device_[A-Za-z0-9_-]{22,}$")
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
    token: SessionToken | None = None
    account_token_reference: str | None = None
    granted_scopes: tuple[str, ...] = ()
    missing_scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _PendingDeviceSignIn:
    device_code: SecretStr
    token_endpoint: str
    issuer: str
    client_id: str
    tenant_id: str
    pairwise_user_id: str
    session_id: str
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
        pairwise_user_id: str,
        session_id: str,
    ) -> DeviceSignInStart:
        """Request a device code and retain it behind an opaque state reference."""

        clock, random_source, signer = self._proof_inputs()
        now = clock.now()
        endpoint = _https_url(device_authorization_endpoint, "device authorization endpoint")
        token_url = _https_url(token_endpoint, "token endpoint")
        client_url = _https_url(client_id, "client ID")
        issuer_url = _https_url(issuer, "issuer")
        requested_scopes = _scopes(scopes)
        self._validate_context(tenant_id, pairwise_user_id, session_id)
        assertion = await signer.sign(
            self._client_assertion(client_url, endpoint, now, random_source).model_dump(),
            purpose="client_assertion",
        )
        try:
            response = await self.http.post(
                endpoint,
                data={
                    "scope": " ".join(requested_scopes),
                    "client_id": client_url,
                    "client_assertion_type": JWT_CLIENT_ASSERTION,
                    "client_assertion": assertion.get_secret_value(),
                },
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise AuthorizationError(
                "request_failed", "Device authorization request failed"
            ) from exc
        payload = self._decode(response, "device authorization")
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
        expires_at = now + timedelta(seconds=authorization.expires_in)
        reference = _opaque_id("device", random_source.bytes)
        pending = _PendingDeviceSignIn(
            device_code=authorization.device_code,
            token_endpoint=token_url,
            issuer=issuer_url,
            client_id=client_url,
            tenant_id=tenant_id,
            pairwise_user_id=pairwise_user_id,
            session_id=session_id,
            scopes=requested_scopes,
            expires_at=expires_at,
            next_poll_at=now + timedelta(seconds=authorization.interval),
            interval=authorization.interval,
        )
        store = self._state_store()
        await store.put(reference, pending, expires_at=expires_at)
        return DeviceSignInStart(
            reference=reference,
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
        clock, random_source, signer = self._proof_inputs()
        now = clock.now()
        if now >= pending.expires_at:
            raise AuthorizationError("expired_token", "Device Sign-In has expired")
        if now < pending.next_poll_at:
            await store.put(reference, pending, expires_at=pending.expires_at)
            return DeviceSignInPoll(status="pending", retry_at=pending.next_poll_at)

        try:
            response, payload = await self._poll_token(pending, now, random_source, signer)
        except Exception:
            await store.put(reference, pending, expires_at=pending.expires_at)
            raise
        if response.is_success:
            return await self._complete(response, payload, pending, random_source)

        error = payload.get("error") if isinstance(payload, dict) else None
        if error in {"authorization_pending", "slow_down"}:
            interval = pending.interval + (5 if error == "slow_down" else 0)
            resumed = replace(
                pending,
                interval=interval,
                next_poll_at=now + timedelta(seconds=interval),
            )
            await store.put(reference, resumed, expires_at=pending.expires_at)
            return DeviceSignInPoll(status="pending", retry_at=resumed.next_poll_at)
        if error in {"access_denied", "expired_token"}:
            raise AuthorizationError(error, "Device Sign-In ended without authorization")
        await store.put(reference, pending, expires_at=pending.expires_at)
        raise self._remote_error(response, payload, "Company refused the device token request")

    async def _poll_token(
        self,
        pending: _PendingDeviceSignIn,
        now: datetime,
        random_source: RandomSource,
        signer: Signer,
    ) -> tuple[httpx.Response, object]:
        assertion = await signer.sign(
            self._client_assertion(
                pending.client_id, pending.token_endpoint, now, random_source
            ).model_dump(),
            purpose="client_assertion",
        )
        dpop = cast(
            DpopProofProvider,
            first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
        )
        proof = await dpop.create(
            DpopProofRequest(
                method="POST",
                url=pending.token_endpoint,
                tenant_id=pending.tenant_id,
                subject=pending.pairwise_user_id,
                issuer=pending.issuer,
            )
        )
        try:
            response = await self.http.post(
                pending.token_endpoint,
                data={
                    "grant_type": DEVICE_CODE_GRANT,
                    "device_code": pending.device_code.get_secret_value(),
                    "session_id": pending.session_id,
                    "client_id": pending.client_id,
                    "client_assertion_type": JWT_CLIENT_ASSERTION,
                    "client_assertion": assertion.get_secret_value(),
                },
                headers={"Accept": "application/json", "DPoP": proof.get_secret_value()},
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise AuthorizationError("request_failed", "Device token request failed") from exc
        return response, self._decode(response, "device token")

    async def _complete(
        self,
        response: httpx.Response,
        payload: object,
        pending: _PendingDeviceSignIn,
        random_source: RandomSource,
    ) -> DeviceSignInPoll:
        try:
            token = SessionToken.model_validate(payload)
        except ValueError as exc:
            raise AuthorizationError(
                "invalid_token_response",
                "Device Sign-In token response is malformed",
                status_code=response.status_code,
            ) from exc
        if (
            token.token_type != "DPoP"  # noqa: S105 - OAuth token type, not a credential
            or not token.signed_in
            or token.session_id != pending.session_id
        ):
            raise AuthorizationError(
                "invalid_token_response",
                "Device Sign-In must return the signed-in proof-bound Session",
                status_code=response.status_code,
            )
        if any(scope not in pending.scopes for scope in token.scopes):
            raise AuthorizationError(
                "scope_escalation",
                "Company returned a scope that was not requested",
                status_code=response.status_code,
            )
        if token.refresh_token is None:
            raise AuthorizationError(
                "missing_account_token",
                "Device Sign-In did not return an Account Token",
                status_code=response.status_code,
            )
        token_reference = _opaque_id("account", random_source.bytes)
        token_store = cast(
            TokenStore,
            first_contribution(self.reactor, TOKEN_STORES, "token store"),
        )
        await token_store.put(token_reference, token.refresh_token)
        public_token = token.model_copy(update={"refresh_token": None})
        return DeviceSignInPoll(
            status="complete",
            token=public_token,
            account_token_reference=token_reference,
            granted_scopes=public_token.scopes,
            missing_scopes=tuple(
                scope for scope in pending.scopes if scope not in public_token.scopes
            ),
        )

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
    def _validate_context(tenant_id: str, pairwise_user_id: str, session_id: str) -> None:
        import re

        if not tenant_id or len(tenant_id) > 256:
            raise ValueError("tenant_id must contain between 1 and 256 characters")
        for label, value in (("pairwise_user_id", pairwise_user_id), ("session_id", session_id)):
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", value):
                raise ValueError(f"{label} must be an opaque URL-safe identifier")

    @staticmethod
    def _client_assertion(
        client_id: str,
        audience: str,
        now: datetime,
        random_source: RandomSource,
    ) -> ClientAssertionClaims:
        issued_at = int(now.timestamp())
        return ClientAssertionClaims(
            iss=client_id,
            sub=client_id,
            aud=audience,
            iat=issued_at,
            exp=issued_at + 60,
            jti=_opaque_id("jti", random_source.bytes),
        )

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
        remote = payload.get("error") if isinstance(payload, dict) else None
        return AuthorizationError(
            remote if isinstance(remote, str) else "http_error",
            message,
            status_code=response.status_code,
        )
