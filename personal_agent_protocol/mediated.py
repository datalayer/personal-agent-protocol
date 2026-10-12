# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Mediated Sign-In: the user's credentials, relayed to one endpoint (§4.7).

Mediated Sign-In is the mode a company offers when its users cannot leave for
a browser: the personal agent collects the fields the company declares
(`auth.mediated.fields`) and sends them to `auth.mediated.endpoint`, with the
Session's DPoP token. It is the one mode where a password passes through the
agent's host, so this client narrows what the host can do with it:

- The values are collected through the Reactor `pap.protectedInput`
  contribution — the host's own trusted surface — never from a model or a
  tool argument, and must be exactly the declared fields.
- They are sent to `auth.mediated.endpoint` and nowhere else: no redirect is
  followed, and an endpoint off the company's domain is refused.
- They are sent once. A `code_required` answer continues with the one-time
  code alone, at `…/{sign_in_id}`, from the Session that started it.
- They are dropped as soon as the request is sent; no result, error, or log
  carries them, and the Account Token is kept behind an opaque reference.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, cast
from urllib.parse import urlsplit

import httpx
from pydantic import Field, SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .auth import _scopes
from .errors import AuthorizationError, ProtocolValidationError, TransportError
from .json import loads_strict
from .models import MediatedSignIn, Organization, ProtocolModel
from .reactor import (
    AUTHORIZATION_STATE_STORES,
    PROTECTED_INPUTS,
    RANDOM_SOURCES,
    TOKEN_STORES,
    AuthorizationStateStore,
    ProtectedInput,
    ProtectedInputField,
    ProtectedInputRequest,
    RandomSource,
    TokenStore,
    first_contribution,
)
from .sessions import SessionToken, _opaque_id
from .telemetry import sign_in_result, signed_in_as, traced
from .transport import DpopHttpClient

_SIGN_IN_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def _compact(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


class MediatedSignInResult(ProtocolModel):
    """Where a Mediated Sign-In stands, without any credential.

    `code_required` carries an opaque `reference` to continue with and where
    the company sent the code (`sent_to`, as the company masked it).
    """

    status: Literal["complete", "code_required", "failed", "expired"]
    reference: str | None = None
    sent_to: str | None = None
    expires_at: datetime | None = None
    token: SessionToken | None = None
    account_token_reference: str | None = None
    granted_scopes: tuple[str, ...] = ()
    missing_scopes: tuple[str, ...] = ()


class _CodeRequired(ProtocolModel):
    status: Literal["code_required"]
    sign_in_id: str = Field(pattern=_SIGN_IN_ID.pattern)
    code: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime


@dataclass(frozen=True)
class _PendingCode:
    endpoint: str
    sign_in_id: str
    session_id: str
    scopes: tuple[str, ...]
    company_name: str
    company_domain: str
    sent_to: str | None
    expires_at: datetime


class MediatedSignInClient:
    """Relay a user's credentials to the company's mediated endpoint, once."""

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
        # Credentials go to one URL: a redirect is refused, never followed.
        self.transport = DpopHttpClient(
            reactor=reactor,
            http_client=http_client,
            max_redirects=0,
            max_response_bytes=max_response_bytes,
        )
        self.max_response_bytes = max_response_bytes

    @traced("pap.sign_in.mediated.sign_in", before=signed_in_as("mediated"), after=sign_in_result)
    async def sign_in(
        self,
        *,
        mediated: MediatedSignIn,
        organization: Organization,
        issuer: str,
        scopes: tuple[str, ...],
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
    ) -> MediatedSignInResult:
        """Collect the declared fields from the user and sign the Session in."""

        endpoint = self._endpoint_on_company_domain(mediated.endpoint, organization.domain)
        requested = _scopes(scopes)
        credentials = await self._collect(
            ProtectedInputRequest(
                purpose="credentials",
                company_name=organization.name,
                company_domain=organization.domain,
                fields=tuple(
                    ProtectedInputField(name=field.name, label=field.label, secret=field.secret)
                    for field in mediated.fields
                ),
            ),
            expected={field.name for field in mediated.fields},
        )
        try:
            body = _compact(
                {
                    "scope": " ".join(requested),
                    "credentials": {
                        name: value.get_secret_value() for name, value in credentials.items()
                    },
                }
            )
        finally:
            credentials.clear()
        response = await self._post(endpoint, body, token, tenant_id, pairwise_user_id, issuer)
        return await self._result(
            response,
            pending=_PendingCode(
                endpoint=endpoint,
                sign_in_id="",
                session_id=token.session_id,
                scopes=requested,
                company_name=organization.name,
                company_domain=organization.domain,
                sent_to=None,
                expires_at=datetime.max,
            ),
        )

    @traced(
        "pap.sign_in.mediated.submit_code", before=signed_in_as("mediated"), after=sign_in_result
    )
    async def submit_code(
        self,
        reference: str,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
    ) -> MediatedSignInResult:
        """Continue a `code_required` sign-in with the code the user received."""

        store = self._state()
        pending = await store.take(reference)
        if not isinstance(pending, _PendingCode):
            raise AuthorizationError(
                "invalid_or_expired_sign_in",
                "Mediated Sign-In is unknown, expired, or already complete",
            )
        if token.session_id != pending.session_id:
            # Only the Session that started a sign-in can finish it (§4.7).
            await store.put(reference, pending, expires_at=pending.expires_at)
            raise AuthorizationError(
                "session_mismatch", "Only the Session that started this sign-in can finish it"
            )
        code = await self._collect(
            ProtectedInputRequest(
                purpose="one_time_code",
                company_name=pending.company_name,
                company_domain=pending.company_domain,
                fields=(ProtectedInputField(name="code", label="Code", secret=True),),
                sent_to=pending.sent_to,
            ),
            expected={"code"},
        )
        try:
            body = _compact({"code": code["code"].get_secret_value()})
        finally:
            code.clear()
        response = await self._post(
            f"{pending.endpoint.rstrip('/')}/{pending.sign_in_id}",
            body,
            token,
            tenant_id,
            pairwise_user_id,
            issuer,
        )
        return await self._result(response, pending=pending, reference=reference)

    async def _result(
        self,
        response: httpx.Response,
        *,
        pending: _PendingCode,
        reference: str | None = None,
    ) -> MediatedSignInResult:
        payload = self._decode(response)
        if not response.is_success:
            error = payload.get("error") if isinstance(payload, dict) else None
            retry_after = response.headers.get("retry-after")
            raise AuthorizationError(
                error if isinstance(error, str) else "http_error",
                "Company refused the Mediated Sign-In",
                status_code=response.status_code,
                details={"retry_after": retry_after} if retry_after else None,
            )
        status = payload.get("status") if isinstance(payload, dict) else None
        if status in {"failed", "expired"}:
            return MediatedSignInResult(status=cast(Literal["failed", "expired"], status))
        if status == "code_required":
            return await self._code_required(response, payload, pending, reference)
        if status == "complete":
            return await self._complete(response, payload, pending)
        raise AuthorizationError(
            "invalid_mediated_response",
            "Mediated Sign-In response has no known status",
            status_code=response.status_code,
        )

    async def _code_required(
        self,
        response: httpx.Response,
        payload: object,
        pending: _PendingCode,
        reference: str | None,
    ) -> MediatedSignInResult:
        try:
            challenge = _CodeRequired.model_validate(payload)
        except ValueError as exc:
            raise AuthorizationError(
                "invalid_mediated_response",
                "Mediated Sign-In code challenge is malformed",
                status_code=response.status_code,
            ) from exc
        if pending.sign_in_id and challenge.sign_in_id != pending.sign_in_id:
            raise AuthorizationError(
                "invalid_mediated_response",
                "Mediated Sign-In changed its sign-in ID",
                status_code=response.status_code,
            )
        sent_to = challenge.code.get("sent_to")
        continued = _PendingCode(
            endpoint=pending.endpoint,
            sign_in_id=challenge.sign_in_id,
            session_id=pending.session_id,
            scopes=pending.scopes,
            company_name=pending.company_name,
            company_domain=pending.company_domain,
            sent_to=sent_to if isinstance(sent_to, str) else None,
            expires_at=challenge.expires_at,
        )
        random_source = cast(
            RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")
        )
        reference = reference or _opaque_id("mediated", random_source.bytes)
        await self._state().put(reference, continued, expires_at=challenge.expires_at)
        return MediatedSignInResult(
            status="code_required",
            reference=reference,
            sent_to=continued.sent_to,
            expires_at=challenge.expires_at,
        )

    async def _complete(
        self, response: httpx.Response, payload: object, pending: _PendingCode
    ) -> MediatedSignInResult:
        fields = dict(payload) if isinstance(payload, dict) else {}
        fields.pop("status", None)
        try:
            token = SessionToken.model_validate(fields)
        except ValueError as exc:
            raise AuthorizationError(
                "invalid_token_response",
                "Mediated Sign-In token response is malformed",
                status_code=response.status_code,
            ) from exc
        if (
            token.token_type != "DPoP"  # noqa: S105 - OAuth token type, not a credential
            or not token.signed_in
            or token.session_id != pending.session_id
        ):
            raise AuthorizationError(
                "invalid_token_response",
                "Mediated Sign-In must sign in the same proof-bound Session",
                status_code=response.status_code,
            )
        if any(scope not in pending.scopes for scope in token.scopes):
            raise AuthorizationError(
                "scope_escalation",
                "Company returned a scope that was not requested",
                status_code=response.status_code,
            )
        account_reference: str | None = None
        if token.refresh_token is not None:
            random_source = cast(
                RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")
            )
            account_reference = _opaque_id("account", random_source.bytes)
            store = cast(TokenStore, first_contribution(self.reactor, TOKEN_STORES, "token store"))
            await store.put(account_reference, token.refresh_token)
        public = token.model_copy(update={"refresh_token": None})
        return MediatedSignInResult(
            status="complete",
            token=public,
            account_token_reference=account_reference,
            granted_scopes=public.scopes,
            missing_scopes=tuple(scope for scope in pending.scopes if scope not in public.scopes),
        )

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

    async def _post(
        self,
        url: str,
        body: bytes,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
    ) -> httpx.Response:
        try:
            response = await self.transport.request(
                "POST",
                url,
                token=token,
                tenant_id=tenant_id,
                pairwise_user_id=pairwise_user_id,
                issuer=issuer,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                content=body,
            )
        except TransportError as exc:
            raise AuthorizationError(exc.code, "Mediated Sign-In request failed") from exc
        if len(response.content) > self.max_response_bytes:
            raise AuthorizationError(
                "response_too_large",
                "Mediated Sign-In response exceeds size limit",
                status_code=response.status_code,
            )
        return response

    def _state(self) -> AuthorizationStateStore:
        return cast(
            AuthorizationStateStore,
            first_contribution(self.reactor, AUTHORIZATION_STATE_STORES, "authorization state"),
        )

    @staticmethod
    def _endpoint_on_company_domain(endpoint: str, domain: str) -> str:
        host = (urlsplit(endpoint).hostname or "").lower()
        domain = domain.lower()
        if host != domain and not host.endswith(f".{domain}"):
            raise AuthorizationError(
                "unsafe_mediated_endpoint",
                "Credentials are sent only to an endpoint on the company's own domain",
            )
        return endpoint

    @staticmethod
    def _decode(response: httpx.Response) -> object:
        if response.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            raise AuthorizationError(
                "invalid_content_type",
                "Mediated Sign-In endpoint must return JSON",
                status_code=response.status_code,
            )
        try:
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise AuthorizationError(
                "invalid_json",
                "Mediated Sign-In endpoint returned invalid JSON",
                status_code=response.status_code,
            ) from exc
