# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Account Tokens: refresh, rotation, narrowing, and revocation (§4.8, §4.9).

An Account Token is the `refresh_token` a sign-in returns. It is used only at
the company's `token_endpoint` and `revocation_endpoint`, always behind an
opaque reference in a Reactor `TokenStore`, and never reaches a model, a
conversation, a log, or a URL.

- **Refresh** signs a Session in again: `grant_type=refresh_token` with the
  Session's `session_id`, a fresh client assertion, and a fresh DPoP proof.
- **Rotation** is serialized per reference through the Reactor
  `pap.accountTokenLock` contribution: when the company returns a new
  `refresh_token`, it replaces the old one before the call returns.
- **Narrowing** asks for fewer scopes (or an RFC 8707 `resource`); a wider
  request is the company's `invalid_scope`, reported as `re_consent_required`
  so the host signs the user in again rather than retrying.
- **`invalid_grant`** deletes the stored token; the Session continues signed
  out (`signed_out`).
- **Revocation** (RFC 7009) signs out every Session signed in with the token;
  the local copy is deleted once the company has answered.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, cast

import httpx
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .auth import _https_url, _scopes
from .errors import AuthorizationError, ProtocolValidationError
from .json import loads_strict
from .models import ProtocolModel
from .reactor import (
    ACCOUNT_TOKEN_LOCKS,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    RANDOM_SOURCES,
    SIGNERS,
    TOKEN_STORES,
    AccountTokenLock,
    Clock,
    DpopProofProvider,
    DpopProofRequest,
    RandomSource,
    Signer,
    TokenStore,
    first_contribution,
    send_bounded,
)
from .refusals import refusal_details, refuse_redirect
from .sessions import (
    JWT_CLIENT_ASSERTION,
    SessionToken,
    _mcp_resource,
    build_client_assertion_claims,
    token_types,
)
from .telemetry import sign_in_result, signed_in_as, traced

REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105 - OAuth grant type, not a credential
_OPAQUE = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


class AccountRefreshResult(ProtocolModel):
    """What a refresh did, without the Account Token itself.

    `token` is the signed-in Session Token on `signed_in` (its
    `refresh_token` always removed); `rotated` says the stored Account Token
    was replaced; `missing_scopes` are requested scopes the company left out.
    """

    status: Literal["signed_in", "signed_out", "re_consent_required"]
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
        session_id: str,
        scopes: tuple[str, ...] | None = None,
        resource: str | None = None,
    ) -> AccountRefreshResult:
        """Sign `session_id` in again with the Account Token behind `reference`.

        `scopes` narrows the request; omitted, the company grants what the
        token holds. A `resource` is an RFC 8707 indicator narrowing the DPoP
        token to one service (for an MCP server, use `token_for_mcp`).
        """

        return await self._refresh(
            reference, context=context, session_id=session_id, scopes=scopes, resource=resource
        )

    async def _refresh(
        self,
        reference: str,
        *,
        context: AccountTokenContext,
        session_id: str,
        scopes: tuple[str, ...] | None,
        resource: str | None,
        dpop: bool = True,
        mcp: bool = False,
    ) -> AccountRefreshResult:
        if not _OPAQUE.fullmatch(session_id):
            raise ValueError("session_id must be an opaque URL-safe identifier")
        requested = _scopes(scopes) if scopes is not None else None
        resource_url = _https_url(resource, "resource") if resource is not None else None
        # Only a request for an MCP server may be answered with a Bearer token.
        bearer_ok = mcp
        token_url = _https_url(context.token_endpoint, "token endpoint")
        lock = cast(
            AccountTokenLock,
            first_contribution(self.reactor, ACCOUNT_TOKEN_LOCKS, "Account Token lock"),
        )
        store = self._store()
        async with lock.hold(reference):
            account_token = await store.get(reference)
            if account_token is None:
                return AccountRefreshResult(status="signed_out")
            response, payload = await self._post_with_nonce(
                token_url,
                context,
                lambda assertion: {
                    "grant_type": REFRESH_TOKEN_GRANT,
                    "refresh_token": account_token.get_secret_value(),
                    "session_id": session_id,
                    "client_id": context.client_id,
                    "client_assertion_type": JWT_CLIENT_ASSERTION,
                    "client_assertion": assertion,
                    **({"scope": " ".join(requested)} if requested is not None else {}),
                    **({"resource": resource_url} if resource_url is not None else {}),
                },
                dpop=dpop,
            )
            if not response.is_success:
                error = payload.get("error") if isinstance(payload, dict) else None
                if error == "invalid_grant":
                    # Expired or revoked: the stored copy is useless and must go.
                    await store.delete(reference)
                    return AccountRefreshResult(status="signed_out")
                if error == "invalid_scope":
                    return AccountRefreshResult(status="re_consent_required")
                raise self._remote_error(response, payload, "Company refused the Account Token")
            token = self._session_token(
                response,
                payload,
                session_id,
                requested,
                types=token_types(dpop=dpop, resource=resource_url if bearer_ok else None),
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

    async def token_for_mcp(
        self,
        reference: str,
        *,
        context: AccountTokenContext,
        session_id: str,
        resource: str,
        dpop: bool,
        scopes: tuple[str, ...] | None = None,
    ) -> AccountRefreshResult:
        """A signed-in Session Token for one MCP server (§4.3).

        The Account Token request of the Session with `resource` set to the
        MCP server's `url` from poppy.json. For a server that supports DPoP
        (`dpop`, from its protected resource metadata) the request carries a
        proof and the token is a DPoP one; otherwise it carries none and the
        token is a Bearer one, which works only at that server
        (`mcp.McpBearerAuth`). A rotated Account Token is stored as with `refresh`.
        """

        return await self._refresh(
            reference,
            context=context,
            session_id=session_id,
            scopes=scopes,
            resource=_mcp_resource(resource),
            dpop=dpop,
            mcp=True,
        )

    @traced(
        "pap.sign_in.account_token.revoke",
        before=signed_in_as("account_token"),
        after=sign_in_result,
    )
    async def revoke(
        self, reference: str, *, context: AccountTokenContext
    ) -> AccountRevocationResult:
        """Revoke the Account Token at the company (RFC 7009), then forget it."""

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
            response, payload = await self._post_with_nonce(
                endpoint,
                context,
                lambda assertion: {
                    "token": account_token.get_secret_value(),
                    "token_type_hint": REFRESH_TOKEN_GRANT,
                    "client_id": context.client_id,
                    "client_assertion_type": JWT_CLIENT_ASSERTION,
                    "client_assertion": assertion,
                },
                dpop=False,
                json_body=False,
            )
            if not response.is_success:
                # Kept so the host can retry: a token it believes revoked must be.
                raise self._remote_error(response, payload, "Company refused the revocation")
            await store.delete(reference)
        return AccountRevocationResult(revoked=True, deleted_locally=True)

    async def _post_with_nonce(
        self,
        url: str,
        context: AccountTokenContext,
        build: Callable[[str], dict[str, str]],
        *,
        dpop: bool,
        json_body: bool = True,
    ) -> tuple[httpx.Response, object]:
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        random_source = cast(
            RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")
        )
        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        nonce: str | None = None
        for attempt in range(2):
            now = clock.now()
            assertion = await signer.sign(
                build_client_assertion_claims(
                    client_id=context.client_id,
                    issuer=context.issuer,
                    now=now,
                    random_bytes=random_source.bytes,
                ).model_dump(),
                purpose="client_assertion",
            )
            headers = {"Accept": "application/json"}
            if dpop:
                provider = cast(
                    DpopProofProvider,
                    first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
                )
                proof = await provider.create(
                    DpopProofRequest(
                        method="POST",
                        url=url,
                        tenant_id=context.tenant_id,
                        subject=context.pairwise_user_id,
                        issuer=context.issuer,
                        nonce=nonce,
                    )
                )
                headers["DPoP"] = proof.get_secret_value()
            try:
                response = await send_bounded(
                    self.http,
                    self.http.build_request(
                        "POST", url, data=build(assertion.get_secret_value()), headers=headers
                    ),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise AuthorizationError("request_failed", "Account Token request failed") from exc
            refuse_redirect(response, AuthorizationError)
            payload = self._decode(response, required=json_body or not response.is_success)
            error = payload.get("error") if isinstance(payload, dict) else None
            if dpop and error == "use_dpop_nonce" and attempt == 0:
                nonce = response.headers.get("dpop-nonce")
                if not nonce:
                    raise AuthorizationError(
                        "missing_dpop_nonce",
                        "Company requested a DPoP nonce but did not send one",
                        status_code=response.status_code,
                    )
                continue
            return response, payload
        raise AuthorizationError("use_dpop_nonce", "Company rejected the refreshed DPoP proof")

    def _session_token(
        self,
        response: httpx.Response,
        payload: object,
        session_id: str,
        requested: tuple[str, ...] | None,
        *,
        types: frozenset[str],
    ) -> SessionToken:
        try:
            token = SessionToken.model_validate(payload)
        except ValueError as exc:
            raise AuthorizationError(
                "invalid_token_response",
                "Account Token response is malformed",
                status_code=response.status_code,
            ) from exc
        if token.token_type not in types or not token.signed_in or token.session_id != session_id:
            raise AuthorizationError(
                "invalid_token_response",
                "A refresh must sign in the same Session with the token type asked for",
                status_code=response.status_code,
            )
        if requested is not None and any(scope not in requested for scope in token.scopes):
            raise AuthorizationError(
                "scope_escalation",
                "Company returned a scope that was not requested",
                status_code=response.status_code,
            )
        return token

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
