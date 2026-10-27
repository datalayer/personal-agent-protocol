# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Account Tokens: refresh, rotation, narrowing, and revocation (§4.8, §4.9).

An Account Token is the `refresh_token` a sign-in returns. It is used only at
the company's `token_endpoint` and `revocation_endpoint`, always behind an
opaque reference in a Reactor `TokenStore`, and never reaches a model, a
conversation, a log, or a URL.

- **Refresh** signs a Session in: `grant_type=refresh_token`, a fresh client
  assertion, and a fresh DPoP proof signed with the Session's key, which names it;
  a new key starts a new Session already signed in.
- **Rotation** is serialized per reference through the Reactor
  `pap.accountTokenLock` contribution: when the company returns a new
  `refresh_token`, it replaces the old one before the call returns.
- **Narrowing** asks for fewer scopes (or an RFC 8707 `resource`); a wider
  request is the company's `invalid_scope`, reported as `re_consent_required`
  so the host signs the user in again rather than retrying.
- **`invalid_grant`** means the Account Token or the Session ended; renewing the
  Session with its assertion tells which (`signed_out` or `session_ended`).
- **Revocation** (RFC 7009) signs out every Session signed in with the token;
  the local copy is deleted once the company has answered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, cast

import httpx
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .auth import _https_url, _scopes
from .errors import AuthorizationError, ProtocolValidationError, SessionError
from .json import loads_strict
from .models import ProtocolModel
from .reactor import (
    ACCOUNT_TOKEN_LOCKS,
    CLOCKS,
    RANDOM_SOURCES,
    SIGNERS,
    TOKEN_STORES,
    AccountTokenLock,
    Clock,
    RandomSource,
    Signer,
    TokenStore,
    first_contribution,
    send_bounded,
)
from .refusals import refusal_details, refuse_redirect
from .sessions import (
    JWT_CLIENT_ASSERTION,
    SessionClient,
    SessionToken,
    build_client_assertion_claims,
)
from .telemetry import sign_in_result, signed_in_as, traced

REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105 - OAuth grant type, not a credential


class AccountRefreshResult(ProtocolModel):
    """What a refresh did, without the Account Token itself.

    `token` is the signed-in Session Token on `signed_in` (its `refresh_token`
    always removed); `rotated` says the stored Account Token was replaced;
    `missing_scopes` are requested scopes the company left out. `session_ended`
    means the Session the refresh named has ended while the Account Token still
    works: start a new Session with it (§4.8).
    """

    status: Literal["signed_in", "signed_out", "session_ended", "re_consent_required"]
    token: SessionToken | None = None
    rotated: bool = False
    granted_scopes: tuple[str, ...] = ()
    missing_scopes: tuple[str, ...] = ()


class AccountRevocationResult(ProtocolModel):
    """A revocation the company acknowledged; the local copy is gone."""

    revoked: bool
    deleted_locally: bool


@dataclass(frozen=True)
class AccountTokenContext:
    """Where an Account Token is used, and for whom (all non-secret)."""

    token_endpoint: str
    issuer: str
    client_id: str
    tenant_id: str
    pairwise_user_id: str
    revocation_endpoint: str | None = None


class AccountTokenClient:
    """Use a stored Account Token without ever handing it to a caller."""

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

    @traced(
        "pap.sign_in.account_token.refresh",
        before=signed_in_as("account_token"),
        after=sign_in_result,
    )
    async def refresh(
        self,
        reference: str,
        *,
        context: AccountTokenContext,
        session_key: str | None = None,
        scopes: tuple[str, ...] | None = None,
        resource: str | None = None,
    ) -> AccountRefreshResult:
        """A signed-in Session Token from the Account Token behind `reference` (§4.8).

        With `session_key`, for that Session, signing it in if it was signed out;
        without, a new Session Key starts a new Session already signed in. `scopes`
        narrows the request; omitted, the company grants what the token holds. A
        `resource` asks for a token for one service, such as an MCP server that
        supports DPoP; one without DPoP takes Token Exchange
        (`SessionClient.token_for_mcp`).
        """

        requested = _scopes(scopes) if scopes is not None else None
        resource_url = _https_url(resource, "resource") if resource is not None else None
        token_url = _https_url(context.token_endpoint, "token endpoint")
        new_session = session_key is None
        key = session_key or await self.sessions._prover().new_session_key(
            tenant_id=context.tenant_id, issuer=context.issuer
        )
        lock = cast(
            AccountTokenLock,
            first_contribution(self.reactor, ACCOUNT_TOKEN_LOCKS, "Account Token lock"),
        )
        store = self._store()
        async with lock.hold(reference):
            account_token = await store.get(reference)
            if account_token is None:
                return AccountRefreshResult(status="signed_out")
            form = {
                "grant_type": REFRESH_TOKEN_GRANT,
                "refresh_token": account_token.get_secret_value(),
                **({"scope": " ".join(requested)} if requested is not None else {}),
                **({"resource": resource_url} if resource_url is not None else {}),
            }
            try:
                response = await self.sessions.token_request(
                    client_id=context.client_id,
                    issuer=context.issuer,
                    token_endpoint=token_url,
                    tenant_id=context.tenant_id,
                    session_key=key,
                    form=lambda: form,
                    error=AuthorizationError,
                )
            except AuthorizationError as exc:
                if exc.code == "invalid_scope":
                    return AccountRefreshResult(status="re_consent_required")
                if exc.code != "invalid_grant":
                    raise
                return await self._invalid_grant(reference, context, key, new_session, store)
            if response.token_type != "DPoP":  # noqa: S105 - an OAuth token or grant type, not a credential
                raise AuthorizationError(
                    "invalid_token_response",
                    "An Account Token request answers with a DPoP Session Token",
                )
            try:
                token = SessionToken.from_response(
                    response,
                    session_key=key,
                    signed_in=True,
                    requested_scopes=requested or (),
                )
            except ProtocolValidationError as exc:
                raise AuthorizationError("invalid_token_response", exc.message) from exc
            if requested is not None and any(scope not in requested for scope in token.scopes):
                raise AuthorizationError(
                    "scope_escalation", "Company returned a scope that was not requested"
                )
            rotated = token.refresh_token is not None
            if token.refresh_token is not None:
                # The new token replaces the old before anyone can use either again.
                await store.put(reference, token.refresh_token)
        public = token.model_copy(update={"refresh_token": None})
        return AccountRefreshResult(
            status="signed_in",
            token=public,
            rotated=rotated,
            granted_scopes=public.scopes,
            missing_scopes=tuple(
                scope for scope in (requested or ()) if scope not in public.scopes
            ),
        )

    async def _invalid_grant(
        self,
        reference: str,
        context: AccountTokenContext,
        key: str,
        new_session: bool,
        store: TokenStore,
    ) -> AccountRefreshResult:
        """Tell an ended Account Token from an ended Session (§4.8).

        With a new key only the Account Token can be at fault. With an existing
        Session's key, renewing that Session with its assertion tells them apart:
        refused there, the Session has ended (its key is discarded); accepted, the
        Account Token is what ended, and the Session carries on signed out.
        """

        if not new_session:
            try:
                renewed = await self.sessions.renew(
                    client_id=context.client_id,
                    pairwise_user_id=context.pairwise_user_id,
                    issuer=context.issuer,
                    token_endpoint=context.token_endpoint,
                    tenant_id=context.tenant_id,
                    session_key=key,
                )
            except SessionError as exc:
                if exc.code == "invalid_grant":
                    return AccountRefreshResult(status="session_ended")
                raise
            await store.delete(reference)
            return AccountRefreshResult(status="signed_out", token=renewed)
        await self.sessions._prover().discard_session_key(
            tenant_id=context.tenant_id, issuer=context.issuer, session_key=key
        )
        # Expired or revoked: the stored copy is useless and must go.
        await store.delete(reference)
        return AccountRefreshResult(status="signed_out")

    @traced(
        "pap.sign_in.account_token.revoke",
        before=signed_in_as("account_token"),
        after=sign_in_result,
    )
    async def revoke(
        self, reference: str, *, context: AccountTokenContext
    ) -> AccountRevocationResult:
        """Revoke the Account Token at the company (RFC 7009), then forget it.

        Revocation carries no proof (§4.3): no Session Token, no token request.
        """

        if context.revocation_endpoint is None:
            raise ValueError("Revocation needs the company's revocation_endpoint")
        endpoint = _https_url(context.revocation_endpoint, "revocation endpoint")
        lock = cast(
            AccountTokenLock,
            first_contribution(self.reactor, ACCOUNT_TOKEN_LOCKS, "Account Token lock"),
        )
        store = self._store()
        async with lock.hold(reference):
            account_token = await store.get(reference)
            if account_token is None:
                return AccountRevocationResult(revoked=False, deleted_locally=False)
            clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
            random_source = cast(
                RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")
            )
            signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
            assertion = await signer.sign(
                build_client_assertion_claims(
                    client_id=context.client_id,
                    issuer=context.issuer,
                    now=clock.now(),
                    random_bytes=random_source.bytes,
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
                            "token": account_token.get_secret_value(),
                            "token_type_hint": REFRESH_TOKEN_GRANT,
                            "client_id": context.client_id,
                            "client_assertion_type": JWT_CLIENT_ASSERTION,
                            "client_assertion": assertion.get_secret_value(),
                        },
                        headers={"Accept": "application/json"},
                    ),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise AuthorizationError("request_failed", "Account Token request failed") from exc
            refuse_redirect(response, AuthorizationError)
            payload = self._decode(response, required=not response.is_success)
            if not response.is_success:
                # Kept so the host can retry: a token it believes revoked must be.
                raise self._remote_error(response, payload, "Company refused the revocation")
            await store.delete(reference)
        return AccountRevocationResult(revoked=True, deleted_locally=True)

    def _store(self) -> TokenStore:
        return cast(TokenStore, first_contribution(self.reactor, TOKEN_STORES, "token store"))

    def _decode(self, response: httpx.Response, *, required: bool) -> object:
        if len(response.content) > self.max_response_bytes:
            raise AuthorizationError(
                "response_too_large",
                "Account Token response exceeds size limit",
                status_code=response.status_code,
            )
        if not response.content and not required:
            return {}
        if response.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            if not required:
                return {}
            raise AuthorizationError(
                "invalid_content_type",
                "Account Token endpoint must return JSON",
                status_code=response.status_code,
            )
        try:
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise AuthorizationError(
                "invalid_json",
                "Account Token endpoint returned invalid JSON",
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
            details=refusal_details(response, payload) or None,
        )
