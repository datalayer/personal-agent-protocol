# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Mediated Sign-In extension v1: the user's credentials, as an OAuth extension grant.

A company that can't offer Direct or Device Sign-In yet lists
`extensions["mediated-sign-in"]` in its `poppy.json` and the grant type in its
issuer's `grant_types_supported`. It is the one sign-in where a password passes
through the agent's host, so this client narrows what the host can do with it:

- The values are collected through the Reactor `pap.protectedInput`
  contribution, the host's own trusted surface, never from a model or a tool
  argument, and must be exactly the declared fields.
- They are sent to the `token_endpoint` of the company's issuer, with this grant,
  and nowhere else: no redirect is followed.
- They are sent once. A `code_required` answer continues with `sign_in_id` and the
  one-time code alone: no credentials, no scope.
- They are dropped as soon as the request is sent; no result, error, or log
  carries them, and the refresh token is kept behind an opaque reference.

Errors are OAuth errors from the token endpoint, raised as `AuthorizationError`:
`invalid_grant`, `expired_token`, `access_denied`, `invalid_scope`, and a rate
limit (`rate_limited`, HTTP 429 with `Retry-After`). Mediated Sign-In is
transitional: prefer Direct or Device Sign-In when the company offers them.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Literal, cast

import httpx
from pydantic import Field, SecretStr, ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .auth import _scopes
from .errors import AuthorizationError
from .models import (
    MEDIATED_EXTENSION,
    DiscoveredCompany,
    MediatedSignIn,
    ProtocolModel,
)
from .reactor import (
    AUTHORIZATION_STATE_STORES,
    CLOCKS,
    PROTECTED_INPUTS,
    RANDOM_SOURCES,
    AuthorizationStateStore,
    Clock,
    ProtectedInput,
    ProtectedInputField,
    ProtectedInputRequest,
    RandomSource,
    first_contribution,
)
from .sessions import AccessToken, SessionClient, TokenResponse, _opaque_id, finish_sign_in
from .telemetry import sign_in_result, signed_in_as, traced

MEDIATED_VERSION = "1"
MEDIATED_GRANT = "https://personalagentprotocol.org/grant/mediated-sign-in"

_SIGN_IN_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def _declared(company: DiscoveredCompany) -> dict[str, object] | None:
    """The extension's entry at this version, when the issuer lists the grant too."""

    descriptor = company.document.extensions.get(MEDIATED_EXTENSION)
    metadata = company.oauth_metadata
    if (
        descriptor is None
        or descriptor.version != MEDIATED_VERSION
        or metadata is None
        or MEDIATED_GRANT not in metadata.grant_types_supported
    ):
        return None
    return descriptor.model_dump()


def mediated_sign_in(company: DiscoveredCompany) -> MediatedSignIn | None:
    """What the company's Mediated Sign-In asks for, or `None` when it offers none.

    An entry whose fields can't be used, such as one named `client_id`, is an
    extension this SDK can't use either.
    """

    declared = _declared(company)
    if declared is None:
        return None
    try:
        return MediatedSignIn.model_validate(declared)
    except ValidationError:
        return None


class MediatedSignInResult(ProtocolModel):
    """Where a Mediated Sign-In stands, without any credential.

    `code_required` carries an opaque `reference` to continue with, where the
    company sent the code (`sent_to`, as the company wrote it), and when it ends.
    """

    status: Literal["complete", "code_required"]
    reference: str | None = None
    sent_to: str | None = None
    expires_at: datetime | None = None
    token: AccessToken | None = None
    refresh_token_reference: str | None = None
    granted_scopes: tuple[str, ...] = ()
    missing_scopes: tuple[str, ...] = ()


class _CodeRequired(ProtocolModel):
    sign_in_id: str = Field(pattern=_SIGN_IN_ID.pattern)
    sent_to: str | None = None
    expires_in: int = Field(gt=0)


@dataclass(frozen=True)
class _PendingCode:
    token_endpoint: str
    issuer: str
    client_id: str
    scopes: tuple[str, ...]
    company_name: str
    company_domain: str
    tenant_id: str
    dpop_signing_algs: Sequence[str] | None = None
    sign_in_id: str = ""
    sent_to: str | None = None
    expires_at: datetime = datetime.max


class MediatedSignInClient:
    """Sign in with the user's credentials at the issuer's token endpoint, once."""

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
        self.sessions = SessionClient(
            reactor=reactor, http_client=http_client, max_response_bytes=max_response_bytes
        )

    @traced("pap.sign_in.mediated.sign_in", before=signed_in_as("mediated"), after=sign_in_result)
    async def sign_in(
        self,
        *,
        company: DiscoveredCompany,
        client_id: str,
        scopes: tuple[str, ...],
        tenant_id: str,
    ) -> MediatedSignInResult:
        """Collect the declared fields from the user and send them with the grant.

        A DPoP proof goes with the grant when the issuer's metadata lists ES256 (§4.5).
        """

        mediated = self._offered(company)
        metadata = company.require_oauth()
        organization = company.document.organization
        requested = _scopes(scopes)
        credentials = await self._collect(
            ProtectedInputRequest(
                purpose="credentials",
                company_name=organization.name,
                company_domain=organization.domain,
                issuer=metadata.issuer,
                fields=tuple(
                    ProtectedInputField(name=field.name, label=field.label, secret=field.secret)
                    for field in mediated.fields
                ),
            ),
            expected={field.name for field in mediated.fields},
        )
        pending = _PendingCode(
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=client_id,
            scopes=requested,
            company_name=organization.name,
            company_domain=organization.domain,
            tenant_id=tenant_id,
            dpop_signing_algs=metadata.dpop_signing_alg_values_supported,
        )
        try:
            form = {
                "grant_type": MEDIATED_GRANT,
                "scope": " ".join(requested),
                **{name: value.get_secret_value() for name, value in credentials.items()},
            }
        finally:
            credentials.clear()
        return await self._grant(form, pending, reference=None)

    @traced(
        "pap.sign_in.mediated.submit_code", before=signed_in_as("mediated"), after=sign_in_result
    )
    async def submit_code(self, reference: str) -> MediatedSignInResult:
        """Continue a `code_required` sign-in with the code the user received."""

        store = self._state()
        pending = await store.take(reference)
        if not isinstance(pending, _PendingCode):
            raise AuthorizationError(
                "invalid_or_expired_sign_in",
                "Mediated Sign-In is unknown, expired, or already complete",
            )
        code = await self._collect(
            ProtectedInputRequest(
                purpose="one_time_code",
                company_name=pending.company_name,
                company_domain=pending.company_domain,
                issuer=pending.issuer,
                fields=(ProtectedInputField(name="code", label="Code", secret=True),),
                sent_to=pending.sent_to,
            ),
            expected={"code"},
        )
        try:
            form = {
                "grant_type": MEDIATED_GRANT,
                "sign_in_id": pending.sign_in_id,
                "one_time_code": code["code"].get_secret_value(),
            }
        finally:
            code.clear()
        return await self._grant(form, pending, reference=reference)

    def _offered(self, company: DiscoveredCompany) -> MediatedSignIn:
        declared = _declared(company)
        if declared is None:
            raise AuthorizationError("no_mediated", "The company offers no Mediated Sign-In")
        try:
            return MediatedSignIn.model_validate(declared)
        except ValidationError as exc:
            # A field named like `client_id` would overwrite the grant's own parameters.
            raise AuthorizationError(
                "invalid_mediated_extension", "The company's Mediated Sign-In can't be used"
            ) from exc

    async def _grant(
        self, form: dict[str, str], pending: _PendingCode, *, reference: str | None
    ) -> MediatedSignInResult:
        try:
            response = await self.sessions.token_request(
                client_id=pending.client_id,
                issuer=pending.issuer,
                token_endpoint=pending.token_endpoint,
                form=lambda: form,
                error=AuthorizationError,
                tenant_id=pending.tenant_id,
                dpop_signing_algs=pending.dpop_signing_algs,
            )
        except AuthorizationError as exc:
            if exc.code == "code_required":
                return await self._code_required(exc, pending, reference)
            if reference is not None and exc.code == "rate_limited":
                await self._state().put(reference, pending, expires_at=pending.expires_at)
            raise
        finally:
            form.clear()
        return await self._complete(response, pending)

    async def _code_required(
        self, refusal: AuthorizationError, pending: _PendingCode, reference: str | None
    ) -> MediatedSignInResult:
        try:
            challenge = _CodeRequired.model_validate(refusal.details or {})
        except ValueError as exc:
            raise AuthorizationError(
                "invalid_mediated_response",
                "Mediated Sign-In code challenge is malformed",
                status_code=refusal.status_code,
            ) from exc
        if pending.sign_in_id and challenge.sign_in_id != pending.sign_in_id:
            raise AuthorizationError(
                "invalid_mediated_response",
                "Mediated Sign-In changed its sign-in ID",
                status_code=refusal.status_code,
            )
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        expires_at = clock.now() + timedelta(seconds=challenge.expires_in)
        continued = replace(
            pending,
            sign_in_id=challenge.sign_in_id,
            sent_to=challenge.sent_to,
            expires_at=expires_at,
        )
        random_source = cast(
            RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")
        )
        reference = reference or _opaque_id("mediated", random_source.bytes)
        await self._state().put(reference, continued, expires_at=expires_at)
        return MediatedSignInResult(
            status="code_required",
            reference=reference,
            sent_to=challenge.sent_to,
            expires_at=expires_at,
        )

    async def _complete(
        self, response: TokenResponse, pending: _PendingCode
    ) -> MediatedSignInResult:
        if response.refresh_token is None:
            raise AuthorizationError(
                "missing_refresh_token", "Mediated Sign-In did not return a refresh token"
            )
        # `scope` as at the token endpoint: left out only when exactly as requested.
        result = await finish_sign_in(
            self.reactor, response, pending.scopes, error=AuthorizationError
        )
        return MediatedSignInResult(status="complete", **dict(result))

    async def _collect(
        self, request: ProtectedInputRequest, *, expected: set[str]
    ) -> dict[str, SecretStr]:
        source = cast(
            ProtectedInput, first_contribution(self.reactor, PROTECTED_INPUTS, "protected input")
        )
        values = await source.collect(request)
        if set(values) != expected or any(
            not isinstance(value, SecretStr) or not value.get_secret_value()
            for value in values.values()
        ):
            values.clear()
            raise AuthorizationError(
                "invalid_protected_input",
                "Protected input must answer exactly the declared fields, none empty",
            )
        return values

    def _state(self) -> AuthorizationStateStore:
        return cast(
            AuthorizationStateStore,
            first_contribution(self.reactor, AUTHORIZATION_STATE_STORES, "authorization state"),
        )
