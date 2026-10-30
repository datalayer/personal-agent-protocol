# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Refresh tokens: access tokens, rotation, narrowing, tokens for one service, sign-out.

A refresh token is what a sign-in returns (§4.4). It is used only at the
company's `token_endpoint` and `revocation_endpoint`, always behind an opaque
reference in a Reactor `TokenStore`, and never reaches a model, a conversation,
a log, or a URL.

- **Refresh** gets an access token: `grant_type=refresh_token` and a fresh client
  assertion. No Session is named: any of the User's Sessions uses the access
  token with its Session header (§4.4, §5.4).
- **Rotation** is serialized per reference through `pap.refreshTokenLock`: when
  the company returns a new `refresh_token`, it replaces the old one before the
  call returns.
- **Narrowing** asks for fewer scopes; a wider request is the company's
  `invalid_scope`, reported as `re_consent_required` so the host signs the user
  in again rather than retrying.
- **Tokens for one service** ask with `resource` (RFC 8707) for a service whose
  protected resource metadata names a resource other than the Company's domain,
  such as an MCP server (§4.5, §7). `ServiceTokens` reads that metadata before
  the first signed-in call to a service, and again when a service says it is stale.
- **`invalid_grant`** means the refresh token is no longer valid: the stored copy
  is deleted and the Sessions continue signed out (§5.5).
- **Sign-out** revokes every refresh token held for the account (RFC 7009, §4.6,
  §5.5); each local copy is deleted once the company has answered.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal, cast

import httpx
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .auth import _https_url, _scopes
from .errors import AuthorizationError, PersonalAgentProtocolError, ProtocolValidationError
from .json import loads_strict
from .models import DiscoveredCompany, ProtectedResourceMetadata, ProtocolModel
from .reactor import (
    REFRESH_TOKEN_LOCKS,
    TOKEN_STORES,
    RefreshTokenLock,
    TokenStore,
    first_contribution,
    send_bounded,
)
from .refusals import refusal_code, refusal_details, refuse_redirect, refused_without_body
from .sessions import AccessToken, SessionClient
from .telemetry import sign_in_result, signed_in_as, traced

if TYPE_CHECKING:
    from .discovery import DiscoveryClient

REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105 - OAuth grant type, not a credential


class RefreshResult(ProtocolModel):
    """What a refresh did, without the refresh token itself.

    `token` is the access token on `signed_in`; `rotated` says the stored refresh
    token was replaced; `missing_scopes` are requested scopes the company left out.
    `signed_out`: no valid refresh token is held any more (§5.5).
    """

    status: Literal["signed_in", "signed_out", "re_consent_required"]
    token: AccessToken | None = None
    rotated: bool = False
    granted_scopes: tuple[str, ...] = ()
    missing_scopes: tuple[str, ...] = ()


class RevocationResult(ProtocolModel):
    """A revocation the company acknowledged; the local copy is gone."""

    revoked: bool
    deleted_locally: bool


class SignOutResult(ProtocolModel):
    """Sign-out (§5.5): how many refresh tokens were revoked, and whether all were."""

    revoked: int
    signed_out: bool


@dataclass(frozen=True)
class RefreshTokenContext:
    """Where a refresh token is used, and for whom (all non-secret).

    `dpop_signing_algs` is the issuer's `dpop_signing_alg_values_supported`: a refresh
    sends a DPoP proof when it includes ES256 (§4.5).
    """

    token_endpoint: str
    issuer: str
    client_id: str
    tenant_id: str
    revocation_endpoint: str | None = None
    dpop_signing_algs: Sequence[str] | None = None


class RefreshTokenClient:
    """Use a stored refresh token without ever handing it to a caller."""

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
        "pap.sign_in.refresh_token.refresh",
        before=signed_in_as("refresh_token"),
        after=sign_in_result,
    )
    async def refresh(
        self,
        reference: str,
        *,
        context: RefreshTokenContext,
        scopes: tuple[str, ...] | None = None,
        resource: str | None = None,
    ) -> RefreshResult:
        """An access token from the refresh token behind `reference` (§4.4).

        `scopes` narrows the request; omitted, the company grants what the token
        holds. `resource` asks for a token for one service (RFC 8707, §4.5), used
        only there.
        """

        requested = _scopes(scopes) if scopes is not None else None
        resource_url = _https_url(resource, "resource") if resource is not None else None
        token_url = _https_url(context.token_endpoint, "token endpoint")
        lock = cast(
            RefreshTokenLock,
            first_contribution(self.reactor, REFRESH_TOKEN_LOCKS, "refresh token lock"),
        )
        store = self._store()
        async with lock.hold(reference):
            refresh_token = await store.get(reference)
            if refresh_token is None:
                return RefreshResult(status="signed_out")
            form = {
                "grant_type": REFRESH_TOKEN_GRANT,
                "refresh_token": refresh_token.get_secret_value(),
                **({"scope": " ".join(requested)} if requested is not None else {}),
                **({"resource": resource_url} if resource_url is not None else {}),
            }
            try:
                response = await self.sessions.token_request(
                    client_id=context.client_id,
                    issuer=context.issuer,
                    token_endpoint=token_url,
                    form=lambda: form,
                    error=AuthorizationError,
                    tenant_id=context.tenant_id,
                    dpop_signing_algs=context.dpop_signing_algs,
                )
            except AuthorizationError as exc:
                if exc.code == "invalid_scope":
                    return RefreshResult(status="re_consent_required")
                if exc.code != "invalid_grant":
                    raise
                # Expired, revoked, or the User disconnected the agent: the stored copy
                # is useless and must go; the Sessions continue signed out (§5.5).
                await store.delete(reference)
                return RefreshResult(status="signed_out")
            try:
                token = AccessToken.from_response(
                    response, requested_scopes=requested or (), resource=resource_url
                )
            except ProtocolValidationError as exc:
                raise AuthorizationError("invalid_token_response", exc.message) from exc
            if requested is not None and any(scope not in requested for scope in token.scopes):
                raise AuthorizationError(
                    "scope_escalation", "Company returned a scope that was not requested"
                )
            rotated = response.refresh_token is not None
            if response.refresh_token is not None:
                # The new token replaces the old before anyone can use either again (§4.4).
                await store.put(reference, response.refresh_token)
        return RefreshResult(
            status="signed_in",
            token=token,
            rotated=rotated,
            granted_scopes=token.scopes,
            missing_scopes=tuple(scope for scope in (requested or ()) if scope not in token.scopes),
        )

    async def token_for_mcp(
        self,
        reference: str,
        *,
        context: RefreshTokenContext,
        server: ProtectedResourceMetadata,
        scopes: tuple[str, ...] | None = None,
    ) -> RefreshResult:
        """An access token for one MCP server: `resource` is its `url` from poppy.json (§7).

        `server` is its protected resource metadata, as `fetch_mcp_server_metadata` returns
        it. MCP's baseline is Bearer: a proof goes only when `server` lists ES256, whatever
        the issuer lists, so a server that doesn't gets a Bearer token.
        """

        return await self.refresh(
            reference,
            context=replace(context, dpop_signing_algs=server.dpop_signing_alg_values_supported),
            scopes=scopes,
            resource=server.resource,
        )

    @traced(
        "pap.sign_in.refresh_token.revoke",
        before=signed_in_as("refresh_token"),
        after=sign_in_result,
    )
    async def revoke(self, reference: str, *, context: RefreshTokenContext) -> RevocationResult:
        """Revoke the refresh token at the company (RFC 7009, §4.6), then forget it."""

        if context.revocation_endpoint is None:
            raise ValueError("Revocation needs the company's revocation_endpoint")
        endpoint = _https_url(context.revocation_endpoint, "revocation endpoint")
        lock = cast(
            RefreshTokenLock,
            first_contribution(self.reactor, REFRESH_TOKEN_LOCKS, "refresh token lock"),
        )
        store = self._store()
        async with lock.hold(reference):
            refresh_token = await store.get(reference)
            if refresh_token is None:
                return RevocationResult(revoked=False, deleted_locally=False)
            client = await self.sessions.client_authentication(
                client_id=context.client_id, issuer=context.issuer
            )
            try:
                response = await send_bounded(
                    self.http,
                    self.http.build_request(
                        "POST",
                        endpoint,
                        data={
                            "token": refresh_token.get_secret_value(),
                            "token_type_hint": REFRESH_TOKEN_GRANT,
                            **client,
                        },
                        headers={"Accept": "application/json"},
                    ),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise AuthorizationError("request_failed", "Revocation request failed") from exc
            refuse_redirect(response, AuthorizationError)
            required = not response.is_success and not refused_without_body(response)
            payload = self._decode(response, required=required)
            if not response.is_success:
                # Kept so the host can retry: a token it believes revoked must be.
                raise self._remote_error(response, payload, "Company refused the revocation")
            await store.delete(reference)
        return RevocationResult(revoked=True, deleted_locally=True)

    async def sign_out(
        self, references: Iterable[str], *, context: RefreshTokenContext
    ) -> SignOutResult:
        """Sign out of an account: revoke every refresh token held for it (§4.6, §5.5).

        `references` are all the refresh tokens the agent holds for the account,
        from every sign-in. The account is signed out once none is valid; the
        Sessions continue signed out, sending the Session header alone.
        """

        revoked = 0
        for reference in dict.fromkeys(references):
            result = await self.revoke(reference, context=context)
            revoked += result.revoked
        store = self._store()
        remaining = [ref for ref in dict.fromkeys(references) if await store.get(ref) is not None]
        return SignOutResult(revoked=revoked, signed_out=not remaining)

    def _store(self) -> TokenStore:
        return cast(TokenStore, first_contribution(self.reactor, TOKEN_STORES, "token store"))

    def _decode(self, response: httpx.Response, *, required: bool) -> object:
        if len(response.content) > self.max_response_bytes:
            raise AuthorizationError(
                "response_too_large",
                "Revocation response exceeds size limit",
                status_code=response.status_code,
            )
        if not response.content and not required:
            return {}
        if response.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
            if not required:
                return {}
            raise AuthorizationError(
                "invalid_content_type",
                "Revocation endpoint must return JSON",
                status_code=response.status_code,
            )
        try:
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise AuthorizationError(
                "invalid_json",
                "Revocation endpoint returned invalid JSON",
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


def stale_resource_metadata(error: PersonalAgentProtocolError) -> bool:
    """Whether a service refused a token not issued for it (§4.5).

    `invalid_token` with `resource_metadata` in its challenge: the agent's view of
    which resource the service asks tokens for is stale; read it again.
    """

    return error.code == "invalid_token" and bool(error.details.get("resource_metadata"))


@dataclass
class ServiceTokens:
    """The access tokens of one account, one per service that asks for its own (§4.5).

    Before the first signed-in call to a service (an MCP server's `url`, the URL in
    an OpenAPI description's `servers`, a conversation `endpoint`), `token_for`
    reads the service's protected resource metadata: a `resource` other than
    `https://{organization.domain}` gets a token requested for it, used only there;
    otherwise the default token serves. After a service answers `invalid_token`
    with `resource_metadata`, `token_for(url, fresh=True)` reads it again. A token for
    an MCP server the Company lists proves as that server's metadata says (§7);
    every other as the issuer's does (§4.5).
    """

    refresh: RefreshTokenClient
    discovery: DiscoveryClient
    company: DiscoveredCompany
    reference: str
    context: RefreshTokenContext
    scopes: tuple[str, ...] | None = None
    _tokens: dict[str | None, AccessToken] = field(default_factory=dict)

    async def resource_for(self, service_url: str, *, fresh: bool = False) -> str | None:
        """The `resource` to request for `service_url`, or `None` for the default token."""

        return await self.discovery.service_resource(self.company, service_url, fresh=fresh)

    async def token_for(self, service_url: str, *, fresh: bool = False) -> AccessToken | None:
        """The access token to call `service_url` with, or `None` once signed out."""

        metadata = await self.discovery.service_metadata(self.company, service_url, fresh=fresh)
        resource = None if metadata is None else metadata.resource
        if fresh:
            self._tokens.pop(resource, None)
        known = self._tokens.get(resource)
        if known is not None:
            return known
        if metadata is not None and self._is_mcp(metadata.resource):
            result = await self.refresh.token_for_mcp(
                self.reference, context=self.context, server=metadata, scopes=self.scopes
            )
        else:
            result = await self.refresh.refresh(
                self.reference, context=self.context, scopes=self.scopes, resource=resource
            )
        if result.status != "signed_in" or result.token is None:
            self._tokens.clear()
            return None
        self._tokens[resource] = result.token
        return result.token

    def _is_mcp(self, resource: str) -> bool:
        return any(api.type == "mcp" and api.url == resource for api in self.company.document.apis)

    def forget(self) -> None:
        """Drop every access token held: signed out, or a new sign-in replaces them."""

        self._tokens.clear()


__all__ = [
    "REFRESH_TOKEN_GRANT",
    "RefreshResult",
    "RefreshTokenClient",
    "RefreshTokenContext",
    "RevocationResult",
    "ServiceTokens",
    "SignOutResult",
    "stale_resource_metadata",
]
