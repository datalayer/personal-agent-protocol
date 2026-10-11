# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A framework-neutral PAP company: discovery, Sessions, sign-in, conversations, operations.

`CompanyService.handle` takes a neutral request and returns a neutral
response, so any web framework can serve it (`asgi.company_app` serves it
over plain ASGI). Every part a company would replace is a Reactor
contribution (`points`): its store, accounts, agent, operation executors,
client policy and resolver, and replay cache.

What it implements of draft 0.1 and Operations v1:

- Discovery (`/.well-known/poppy.json`) and OAuth metadata
  (`/.well-known/oauth-authorization-server`), one issuer on the company's
  own domain.
- Sessions (§4.2): the JWT-bearer grant with a verified client assertion and
  Session assertion, DPoP-bound tokens, renewal by `session_id`.
- Device Sign-In (§4.6) with `authorization_pending` and `slow_down`, and the
  company's own approval page as `approve_device` (the user's action).
- Mediated Sign-In (§4.7) with a one-time code, attempt limits, and uniform
  failures; credentials are checked by the account directory and dropped.
- Account Tokens (§4.8, §4.9): rotation on every refresh, narrower scopes
  only, `invalid_grant` for an expired, revoked, or rotated-away token, and
  revocation that signs out every Session signed in with it.
- Conversations (§7): idempotent messages, ordered cursor events, waited
  replies, SSE, handoff, Direct Conversations, `authorization` events, and
  closing; a conversation that is not yours is `conversation_not_found`.
- Operations v1: proposals from the company agent, read, confirm (latest
  revision, approval rules, scope, extension negotiation), at most once, and
  cancel.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Literal, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from ..crypto import verify_dpop_proof
from ..errors import PersonalAgentProtocolError, ProofError, SessionError
from ..json import loads_strict
from ..models import Message, Operation, OperationConfirmation, OperationResult
from ..reactor import CLOCKS, RANDOM_SOURCES, Clock, RandomSource, first_contribution
from ..sessions import JWT_BEARER_GRANT, JWT_CLIENT_ASSERTION, _opaque_id
from .points import (
    CLIENT_POLICIES,
    CLIENT_RESOLVERS,
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    COMPANY_APIS,
    COMPANY_STORES,
    OPERATION_EXECUTORS,
    REPLAY_CACHES,
    AccountDirectory,
    AccountGrant,
    ApiCall,
    ApiResult,
    ClientPolicy,
    ClientResolver,
    CompanyAgent,
    CompanyApi,
    CompanyStore,
    IssuedCode,
    IssuedSession,
    OperationExecutor,
    PendingAuthorization,
    PendingDevice,
    PendingMediated,
    ReplayCache,
    Reply,
    StoredConversation,
    StoredEvent,
    StoredOperation,
    Turn,
)
from .verify import verify_assertion

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105 - OAuth grant type
_PAGE = 50


@dataclass(frozen=True)
class CompanyConfig:
    """What the company publishes and allows."""

    name: str
    domain: str
    scopes: tuple[str, ...]
    write_scopes: tuple[str, ...] = ()
    mediated_fields: tuple[tuple[str, str, bool], ...] = ()
    device: bool = True
    direct: bool = True
    operations: bool = True
    humans_available: bool = False
    session_lifetime: timedelta = timedelta(hours=1)
    account_token_lifetime: timedelta = timedelta(days=90)
    operation_lifetime: timedelta = timedelta(minutes=15)
    device_interval: int = 5
    max_code_attempts: int = 3
    custom_scopes: Mapping[str, str] = field(default_factory=dict)

    @property
    def base(self) -> str:
        return f"https://{self.domain}"

    @property
    def token_endpoint(self) -> str:
        return f"{self.base}/oauth/token"

    @property
    def device_endpoint(self) -> str:
        return f"{self.base}/oauth/device"

    @property
    def authorization_endpoint(self) -> str:
        return f"{self.base}/oauth/authorize"

    @property
    def api_description(self) -> str:
        return f"{self.base}/api/openapi.json"

    @property
    def revocation_endpoint(self) -> str:
        return f"{self.base}/oauth/revoke"

    @property
    def mediated_endpoint(self) -> str:
        return f"{self.base}/poppy/sign-in"

    @property
    def conversations_endpoint(self) -> str:
        return f"{self.base}/poppy/conversations"

    @property
    def operations_endpoint(self) -> str:
        return f"{self.base}/poppy/operations"


@dataclass(frozen=True)
class CompanyRequest:
    """A request as any framework hands it over: full HTTPS URL, lower-case headers."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes = b""


@dataclass(frozen=True)
class CompanyResponse:
    status: int
    body: Any = None
    headers: Mapping[str, str] = field(default_factory=dict)
    stream: AsyncIterator[bytes] | None = None


class _RefusedError(Exception):
    def __init__(self, status: int, error: str, **extra: object) -> None:
        super().__init__(error)
        self.status = status
        self.error = error
        self.extra = extra


def _json_error(status: int, error: str, **extra: object) -> CompanyResponse:
    return CompanyResponse(status, {"error": error, **extra}, {"Cache-Control": "no-store"})


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class CompanyService:
    """One company's PAP endpoints over Reactor contributions."""

    def __init__(self, *, config: CompanyConfig, reactor: PluginPlatform) -> None:
        self.config = config
        self.reactor = reactor
        self.extensions: dict[str, frozenset[str]] = {}

    # Contributions -----------------------------------------------------------------

    @property
    def store(self) -> CompanyStore:
        return cast(CompanyStore, first_contribution(self.reactor, COMPANY_STORES, "company store"))

    def _now(self) -> datetime:
        return cast(Clock, first_contribution(self.reactor, CLOCKS, "clock")).now()

    def _id(self, prefix: str) -> str:
        random = cast(RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random"))
        return _opaque_id(prefix, random.bytes)

    def _replay(self) -> ReplayCache:
        return cast(ReplayCache, first_contribution(self.reactor, REPLAY_CACHES, "replay cache"))

    # Routing -----------------------------------------------------------------------

    async def handle(self, request: CompanyRequest) -> CompanyResponse:  # noqa: C901 - the route table
        path = urlsplit(request.url).path
        method = request.method.upper()
        try:
            if method == "GET" and path == "/.well-known/poppy.json":
                return CompanyResponse(200, self.discovery_document())
            if method == "GET" and path == "/.well-known/oauth-authorization-server":
                return CompanyResponse(200, self.oauth_metadata())
            if method == "POST" and path == "/oauth/token":
                return await self._token(request)
            if method == "GET" and path == "/oauth/authorize" and self.config.direct:
                return await self._authorize(request)
            if method == "GET" and path == "/api/openapi.json" and self._api() is not None:
                return CompanyResponse(200, cast(CompanyApi, self._api()).openapi())
            if path.startswith("/api/") and self._api() is not None:
                return await self._api_call(request, method, path)
            if method == "POST" and path == "/oauth/device" and self.config.device:
                return await self._device(request)
            if method == "POST" and path == "/oauth/revoke":
                return await self._revoke(request)
            if method == "POST" and path == "/poppy/sign-in" and self.config.mediated_fields:
                return await self._mediated(request)
            if method == "POST" and path.startswith("/poppy/sign-in/"):
                return await self._mediated_code(request, path.rsplit("/", 1)[1])
            if path == "/poppy/conversations" and method == "POST":
                return await self._start_conversation(request)
            if path.startswith("/poppy/conversations/"):
                return await self._conversation_route(request, method, path)
            if path.startswith("/poppy/operations/") and self.config.operations:
                return await self._operation_route(request, method, path)
        except _RefusedError as refused:
            return _json_error(refused.status, refused.error, **refused.extra)
        except (SessionError, ProofError) as error:
            status = error.status_code or (401 if error.code == "invalid_client" else 400)
            return _json_error(status, error.code)
        return _json_error(404, "not_found")

    # Discovery ---------------------------------------------------------------------

    def discovery_document(self) -> dict[str, Any]:
        config = self.config
        auth: dict[str, Any] = {"issuer": config.base}
        if config.direct:
            auth["direct"] = {"scopes": list(config.scopes)}
        if config.device:
            auth["device"] = {"scopes": list(config.scopes)}
        if config.mediated_fields:
            auth["mediated"] = {
                "endpoint": config.mediated_endpoint,
                "fields": [
                    {"name": name, "label": label, "secret": secret}
                    for name, label, secret in config.mediated_fields
                ],
                "scopes": list(config.scopes),
            }
        if config.custom_scopes:
            auth["custom_scopes"] = dict(config.custom_scopes)
        document: dict[str, Any] = {
            "protocol_version": "0.1",
            "organization": {"name": config.name, "domain": config.domain},
            "auth": auth,
            "agent": {"protocols": [{"type": "poppy", "endpoint": config.conversations_endpoint}]},
        }
        api = self._api()
        if api is not None:
            document["apis"] = [
                {"type": "openapi", "url": config.api_description, "description": api.description}
            ]
        if config.operations:
            document["extensions"] = {
                "operations": {"version": "1", "endpoint": config.operations_endpoint}
            }
        return document

    def oauth_metadata(self) -> dict[str, Any]:
        config = self.config
        metadata = {
            "issuer": config.base,
            "token_endpoint": config.token_endpoint,
            "revocation_endpoint": config.revocation_endpoint,
            "poppy_domains": [config.domain],
            "dpop_signing_alg_values_supported": ["ES256", "RS256"],
        }
        if config.device:
            metadata["device_authorization_endpoint"] = config.device_endpoint
        if config.direct:
            metadata["authorization_endpoint"] = config.authorization_endpoint
            metadata["code_challenge_methods_supported"] = ["S256"]
        return metadata

    # OAuth -------------------------------------------------------------------------

    async def _client(self, form: Mapping[str, str], audience: str) -> str:
        """Verify the client assertion, the agent's keys, and the company's policy."""

        client_id = form.get("client_id", "")
        if form.get("client_assertion_type") != JWT_CLIENT_ASSERTION or not client_id:
            raise _RefusedError(401, "invalid_client")
        policy = cast(ClientPolicy, first_contribution(self.reactor, CLIENT_POLICIES, "policy"))
        if not await policy.allows(client_id):
            raise _RefusedError(401, "invalid_client")
        resolver = cast(
            ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client resolver")
        )
        try:
            metadata, keys = await resolver.resolve(client_id)
        except PersonalAgentProtocolError as exc:
            raise _RefusedError(401, "invalid_client") from exc
        await verify_assertion(
            form.get("client_assertion", ""),
            keys=keys,
            issuer=client_id,
            audience=audience,
            subject=client_id,
            replay_cache=self._replay(),
            now=self._now(),
        )
        self.extensions[client_id] = frozenset(metadata.extensions)
        return client_id

    async def _dpop(self, request: CompanyRequest, access_token: str | None = None) -> str:
        proof = request.headers.get("dpop")
        if not proof:
            raise _RefusedError(400 if access_token is None else 401, "invalid_dpop_proof")
        verified = await verify_dpop_proof(
            proof,
            method=request.method,
            url=request.url,
            replay_cache=self._replay(),
            access_token=SecretStr(access_token) if access_token is not None else None,
            now=self._now(),
        )
        return verified.key_thumbprint

    async def _token(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        grant = form.get("grant_type")
        client_id = await self._client(form, self.config.token_endpoint)
        thumbprint = await self._dpop(request)
        if grant == JWT_BEARER_GRANT:
            return await self._session_grant(form, client_id, thumbprint)
        if grant == REFRESH_TOKEN_GRANT:
            return await self._refresh_grant(form, client_id, thumbprint)
        if grant == "authorization_code" and self.config.direct:
            return await self._code_grant(form, client_id, thumbprint)
        if grant == DEVICE_CODE_GRANT and self.config.device:
            return await self._device_grant(form, client_id, thumbprint)
        raise _RefusedError(400, "unsupported_grant_type")

    async def _session_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        resolver = cast(
            ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client")
        )
        _, keys = await resolver.resolve(client_id)
        claims = await verify_assertion(
            form.get("assertion", ""),
            keys=keys,
            issuer=client_id,
            audience=self.config.token_endpoint,
            replay_cache=self._replay(),
            now=self._now(),
            error="invalid_grant",
        )
        pairwise = str(claims["sub"])
        session_id = form.get("session_id")
        if session_id is None:
            session = IssuedSession(
                session_id=self._id("ses"),
                client_id=client_id,
                pairwise_user_id=pairwise,
                key_thumbprint=thumbprint,
                expires_at=self._now() + self.config.session_lifetime,
            )
        else:
            session = self._session_by_id(session_id)
            if session is None or (session.client_id, session.pairwise_user_id) != (
                client_id,
                pairwise,
            ):
                raise _RefusedError(400, "invalid_session")
            self._drop_tokens_of(session.session_id)
            session = replace(
                session,
                key_thumbprint=thumbprint,
                expires_at=self._now() + self.config.session_lifetime,
            )
        return self._issue(session)

    async def _refresh_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        presented = form.get("refresh_token", "")
        grant = self.store.account_tokens.get(_digest(presented))
        now = self._now()
        if (
            grant is None
            or grant.revoked
            or now >= grant.expires_at
            or grant.client_id != client_id
        ):
            raise _RefusedError(400, "invalid_grant")
        session = self._session_by_id(form.get("session_id", ""))
        if session is None or session.client_id != client_id:
            raise _RefusedError(400, "invalid_session")
        if session.pairwise_user_id != grant.pairwise_user_id:
            raise _RefusedError(400, "account_mismatch")
        requested = tuple(scope for scope in form.get("scope", "").split(" ") if scope)
        if requested and any(scope not in grant.scopes for scope in requested):
            raise _RefusedError(400, "invalid_scope")
        # Rotation: the presented token stops working the moment its successor exists.
        grant.revoked = True
        rotated = self._id("acct")
        self.store.account_tokens[_digest(rotated)] = replace(grant, revoked=False)
        self._drop_tokens_of(session.session_id)
        signed_in = replace(
            session,
            key_thumbprint=thumbprint,
            account_id=grant.account_id,
            scopes=requested or grant.scopes,
            account_token=_digest(rotated),
            expires_at=now + self.config.session_lifetime,
            resource=form.get("resource"),
        )
        return self._issue(signed_in, refresh_token=rotated)

    async def _device(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        client_id = await self._client(form, self.config.device_endpoint)
        scopes = tuple(scope for scope in form.get("scope", "").split(" ") if scope)
        if not scopes or any(scope not in self.config.scopes for scope in scopes):
            raise _RefusedError(400, "invalid_scope")
        device_code = self._id("dev")
        user_code = self._id("u")[2:10].upper().replace("-", "X").replace("_", "Y")
        user_code = f"{user_code[:4]}-{user_code[4:]}"
        lifetime = 600
        self.store.devices[_digest(device_code)] = PendingDevice(
            client_id=client_id,
            scopes=scopes,
            user_code=user_code,
            expires_at=self._now() + timedelta(seconds=lifetime),
            interval=self.config.device_interval,
        )
        return CompanyResponse(
            200,
            {
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": f"{self.config.base}/device",
                "verification_uri_complete": f"{self.config.base}/device?user_code={user_code}",
                "expires_in": lifetime,
                "interval": self.config.device_interval,
            },
            {"Cache-Control": "no-store"},
        )

    def approve_device(
        self, user_code: str, *, account_id: str, scopes: Sequence[str] | None = None
    ) -> tuple[str, ...]:
        """The user signed in on the company's page and approved: what they granted.

        `scopes` may be fewer than requested (partial consent); omitted, all.
        """

        for pending in self.store.devices.values():
            if pending.user_code == user_code and pending.account_id is None:
                granted = tuple(s for s in (scopes or pending.scopes) if s in pending.scopes)
                pending.account_id = account_id
                pending.granted = granted
                return granted
        raise KeyError("unknown or already approved user code")

    def deny_device(self, user_code: str) -> None:
        for pending in self.store.devices.values():
            if pending.user_code == user_code:
                pending.denied = True
                return
        raise KeyError("unknown user code")

    async def _device_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        key = _digest(form.get("device_code", ""))
        pending = self.store.devices.get(key)
        now = self._now()
        if pending is None or pending.client_id != client_id:
            raise _RefusedError(400, "invalid_grant")
        if now >= pending.expires_at:
            self.store.devices.pop(key, None)
            raise _RefusedError(400, "expired_token")
        if pending.denied:
            self.store.devices.pop(key, None)
            raise _RefusedError(400, "access_denied")
        if pending.last_poll is not None and now - pending.last_poll < timedelta(
            seconds=pending.interval
        ):
            pending.interval += 5
            pending.last_poll = now
            raise _RefusedError(400, "slow_down")
        pending.last_poll = now
        if pending.account_id is None:
            raise _RefusedError(400, "authorization_pending")
        session = self._session_by_id(form.get("session_id", ""))
        if session is None or session.client_id != client_id:
            raise _RefusedError(400, "invalid_session")
        self.store.devices.pop(key, None)
        return self._sign_in(session, pending.account_id, pending.granted, thumbprint)

    async def _revoke(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        client_id = await self._client(form, self.config.revocation_endpoint)
        key = _digest(form.get("token", ""))
        grant = self.store.account_tokens.get(key)
        if grant is not None and grant.client_id == client_id:
            grant.revoked = True
            # Every Session signed in with it continues signed out (§4.9).
            for token_key, session in list(self.store.sessions.items()):
                if session.account_token == key:
                    self.store.sessions[token_key] = replace(
                        session, account_id=None, scopes=(), account_token=None
                    )
        return CompanyResponse(200, {}, {"Cache-Control": "no-store"})

    def _sign_in(
        self,
        session: IssuedSession,
        account_id: str,
        scopes: tuple[str, ...],
        thumbprint: str | None = None,
    ) -> CompanyResponse:
        account_token = self._id("acct")
        self.store.account_tokens[_digest(account_token)] = AccountGrant(
            account_id=account_id,
            client_id=session.client_id,
            pairwise_user_id=session.pairwise_user_id,
            scopes=scopes,
            expires_at=self._now() + self.config.account_token_lifetime,
        )
        self._drop_tokens_of(session.session_id)
        signed_in = replace(
            session,
            account_id=account_id,
            scopes=scopes,
            account_token=_digest(account_token),
            key_thumbprint=thumbprint or session.key_thumbprint,
        )
        return self._issue(signed_in, refresh_token=account_token)

    def _issue(
        self, session: IssuedSession, *, refresh_token: str | None = None
    ) -> CompanyResponse:
        access_token = self._id("sat")
        self.store.sessions[_digest(access_token)] = session
        body: dict[str, object] = {
            "access_token": access_token,
            "token_type": "DPoP",
            "expires_in": int((session.expires_at - self._now()).total_seconds()),
            "scope": " ".join(session.scopes),
            "session_id": session.session_id,
            "signed_in": session.signed_in,
        }
        if refresh_token is not None:
            body["refresh_token"] = refresh_token
        return CompanyResponse(200, body, {"Cache-Control": "no-store"})

    def _session_by_id(self, session_id: str) -> IssuedSession | None:
        for session in self.store.sessions.values():
            if session.session_id == session_id:
                return session
        return None

    def _drop_tokens_of(self, session_id: str) -> None:
        for key in [k for k, s in self.store.sessions.items() if s.session_id == session_id]:
            del self.store.sessions[key]

    # Direct Sign-In (§4.5) -------------------------------------------------------------

    async def _authorize(self, request: CompanyRequest) -> CompanyResponse:
        """The company's own sign-in and consent page for a personal agent's request."""

        query = dict(parse_qsl(urlsplit(request.url).query))
        client_id = query.get("client_id", "")
        redirect_uri = query.get("redirect_uri", "")
        policy = cast(ClientPolicy, first_contribution(self.reactor, CLIENT_POLICIES, "policy"))
        resolver = cast(
            ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client")
        )
        try:
            metadata, _ = await resolver.resolve(client_id)
        except (PersonalAgentProtocolError, ValueError):
            return self._page(400, "This agent could not be verified.")
        # An unknown client or redirect is never redirected to: that would be an open redirector.
        if not await policy.allows(client_id) or redirect_uri not in metadata.redirect_uris:
            return self._page(400, "This sign-in request is not valid.")
        state = query.get("state", "")
        scopes = tuple(scope for scope in query.get("scope", "").split(" ") if scope)
        if query.get("response_type") != "code":
            return self._redirect(redirect_uri, error="unsupported_response_type", state=state)
        if query.get("code_challenge_method") != "S256" or not query.get("code_challenge"):
            return self._redirect(redirect_uri, error="invalid_request", state=state)
        if not scopes or any(scope not in self.config.scopes for scope in scopes):
            return self._redirect(redirect_uri, error="invalid_scope", state=state)
        request_id = self._id("authz")
        self.store.authorizations[request_id] = PendingAuthorization(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=state,
            code_challenge=query["code_challenge"],
            expires_at=self._now() + timedelta(minutes=10),
        )
        agent = html.escape(metadata.client_name)
        agent_domain = html.escape(urlsplit(client_id).hostname or "")
        described = "".join(
            f"<li>{html.escape(self.config.custom_scopes.get(scope, scope))}</li>"
            for scope in scopes
        )
        return self._page(
            200,
            f"<h1>{html.escape(self.config.name)}</h1>"
            f"<p><strong>{agent}</strong> ({agent_domain}) asks to:</p><ul>{described}</ul>"
            f'<form method="post" data-request-id="{request_id}">'
            f'<input type="hidden" name="request_id" value="{request_id}">'
            '<button name="decision" value="allow">Allow</button>'
            '<button name="decision" value="deny">Deny</button></form>',
        )

    def approve_authorization(
        self, request_id: str, *, account_id: str, scopes: Sequence[str] | None = None
    ) -> str:
        """The user, signed in on the company's page, allowed: where their browser goes next.

        `scopes` may be fewer than requested (partial consent); omitted, all.
        """

        pending = self._pending_authorization(request_id)
        granted = tuple(s for s in (scopes or pending.scopes) if s in pending.scopes)
        code = self._id("code")
        self.store.codes[_digest(code)] = IssuedCode(
            client_id=pending.client_id,
            redirect_uri=pending.redirect_uri,
            code_challenge=pending.code_challenge,
            account_id=account_id,
            scopes=granted,
            expires_at=self._now() + timedelta(seconds=60),
        )
        return self._redirect_url(pending.redirect_uri, code=code, state=pending.state)

    def deny_authorization(self, request_id: str) -> str:
        """The user refused: the agent learns only `access_denied`."""

        pending = self._pending_authorization(request_id)
        return self._redirect_url(pending.redirect_uri, error="access_denied", state=pending.state)

    def _pending_authorization(self, request_id: str) -> PendingAuthorization:
        pending = self.store.authorizations.pop(request_id, None)
        if pending is None or self._now() >= pending.expires_at:
            raise KeyError("unknown, used, or expired sign-in request")
        return pending

    async def _code_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        issued = self.store.codes.pop(_digest(form.get("code", "")), None)
        if (
            issued is None
            or self._now() >= issued.expires_at
            or issued.client_id != client_id
            or issued.redirect_uri != form.get("redirect_uri")
        ):
            raise _RefusedError(400, "invalid_grant")
        verifier = form.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(
            b"="
        )
        if not hmac.compare_digest(challenge.decode(), issued.code_challenge):
            raise _RefusedError(400, "invalid_grant")
        session = self._session_by_id(form.get("session_id", ""))
        if session is None or session.client_id != client_id:
            raise _RefusedError(400, "invalid_session")
        return self._sign_in(session, issued.account_id, issued.scopes, thumbprint)

    def _redirect_url(self, redirect_uri: str, **values: str) -> str:
        parts = urlsplit(redirect_uri)
        query = parse_qsl(parts.query, keep_blank_values=True)
        query.extend((k, v) for k, v in values.items() if v)
        query.append(("iss", self.config.base))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

    def _redirect(self, redirect_uri: str, **values: str) -> CompanyResponse:
        return CompanyResponse(
            303,
            None,
            {"Location": self._redirect_url(redirect_uri, **values), "Cache-Control": "no-store"},
        )

    @staticmethod
    def _page(status: int, body: str) -> CompanyResponse:
        """A consent page: never framed, never cached (upstream guides, consent pages)."""

        return CompanyResponse(
            status,
            f"<!doctype html><meta charset=utf-8><title>Sign in</title>{body}",
            {
                "Content-Type": "text/html; charset=utf-8",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'",
                "Cache-Control": "no-store",
            },
        )

    # OpenAPI API (§6, Operations §4.1) -----------------------------------------------------

    def _api(self) -> CompanyApi | None:
        contributions = self.reactor.get_contributions(COMPANY_APIS)
        return cast(CompanyApi, contributions[0].value) if contributions else None

    async def _api_call(self, request: CompanyRequest, method: str, path: str) -> CompanyResponse:
        _, session = await self._caller(request)
        body = loads_strict(request.body) if request.body else None
        result: ApiResult = await cast(CompanyApi, self._api()).handle(
            ApiCall(
                method=method,
                path=path.removeprefix("/api"),
                query=dict(parse_qsl(urlsplit(request.url).query)),
                body=body,
                account_id=session.account_id,
                scopes=session.scopes,
                client_id=session.client_id,
            )
        )
        if result.operation is None:
            return CompanyResponse(result.status, result.body)
        if session.account_id is None:
            raise _RefusedError(403, "sign_in_required")
        if "operations" not in self.extensions.get(session.client_id, frozenset()):
            raise _RefusedError(403, "extension_required", extension="operations")
        operation = self._propose(session, Reply(operation=result.operation))
        return CompanyResponse(202, {"operation": operation.model_dump(mode="json")})

    # Resource requests ---------------------------------------------------------------

    async def _caller(self, request: CompanyRequest) -> tuple[str, IssuedSession]:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme != "DPoP" or not token:
            raise _RefusedError(401, "invalid_token")
        key = _digest(token)
        session = self.store.sessions.get(key)
        if session is None or self._now() >= session.expires_at:
            raise _RefusedError(401, "invalid_token")
        thumbprint = await self._dpop(request, access_token=token)
        if thumbprint != session.key_thumbprint:
            raise _RefusedError(401, "invalid_dpop_proof")
        return key, session

    async def _mediated(self, request: CompanyRequest) -> CompanyResponse:
        _, session = await self._caller(request)
        body = loads_strict(request.body) if request.body else {}
        credentials = body.get("credentials") if isinstance(body, dict) else None
        if not isinstance(credentials, dict):
            raise _RefusedError(400, "invalid_request")
        requested = tuple(s for s in str(body.get("scope", "")).split(" ") if s)
        granted = tuple(scope for scope in requested if scope in self.config.scopes)
        accounts = cast(
            AccountDirectory, first_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        )
        secrets = {name: SecretStr(str(value)) for name, value in credentials.items()}
        credentials.clear()
        authenticated = await accounts.authenticate(secrets)
        secrets.clear()
        if authenticated is None:
            return CompanyResponse(200, {"status": "failed"}, {"Cache-Control": "no-store"})
        if authenticated.code_reference is None:
            return self._signed_in_body(session, authenticated.account_id, granted)
        sign_in_id = self._id("si")
        expires_at = self._now() + timedelta(minutes=5)
        self.store.mediated[sign_in_id] = PendingMediated(
            session_id=session.session_id,
            account_id=authenticated.account_id,
            scopes=granted,
            code_reference=authenticated.code_reference,
            expires_at=expires_at,
        )
        return CompanyResponse(
            200,
            {
                "status": "code_required",
                "sign_in_id": sign_in_id,
                "code": {"sent_to": authenticated.sent_to or "your device"},
                "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            },
            {"Cache-Control": "no-store"},
        )

    async def _mediated_code(self, request: CompanyRequest, sign_in_id: str) -> CompanyResponse:
        _, session = await self._caller(request)
        pending = self.store.mediated.get(sign_in_id)
        if pending is None or pending.session_id != session.session_id:
            # Only the Session that started it can finish it; nothing else is said.
            raise _RefusedError(404, "not_found")
        if self._now() >= pending.expires_at:
            del self.store.mediated[sign_in_id]
            return CompanyResponse(200, {"status": "expired"}, {"Cache-Control": "no-store"})
        body = loads_strict(request.body) if request.body else {}
        code = body.get("code") if isinstance(body, dict) else None
        accounts = cast(
            AccountDirectory, first_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        )
        if not isinstance(code, str) or not await accounts.check_code(
            pending.code_reference, SecretStr(code)
        ):
            pending.attempts += 1
            if pending.attempts >= self.config.max_code_attempts:
                del self.store.mediated[sign_in_id]
                return CompanyResponse(200, {"status": "failed"}, {"Cache-Control": "no-store"})
            return CompanyResponse(
                200,
                {
                    "status": "code_required",
                    "sign_in_id": sign_in_id,
                    "code": {},
                    "expires_at": pending.expires_at.isoformat().replace("+00:00", "Z"),
                },
                {"Cache-Control": "no-store"},
            )
        del self.store.mediated[sign_in_id]
        return self._signed_in_body(session, pending.account_id, pending.scopes)

    def _signed_in_body(
        self, session: IssuedSession, account_id: str, scopes: tuple[str, ...]
    ) -> CompanyResponse:
        response = self._sign_in(session, account_id, scopes)
        return replace(response, body={"status": "complete", **cast(dict, response.body)})

    # Conversations -------------------------------------------------------------------

    def _owned(self, conversation_id: str, session: IssuedSession) -> StoredConversation:
        conversation = self.store.conversations.get(conversation_id)
        if conversation is None or conversation.owner != (
            session.client_id,
            session.pairwise_user_id,
        ):
            raise _RefusedError(404, "conversation_not_found")
        return conversation

    def _event(self, conversation: StoredConversation, **payload: object) -> None:
        event_id = self._id("evt")
        created = self._now().isoformat().replace("+00:00", "Z")
        conversation.events.append(
            StoredEvent(event_id, {"id": event_id, "created_at": created, **payload})
        )

    def _state(self, conversation: StoredConversation) -> None:
        self._event(
            conversation, type="state", status=conversation.status, responder=conversation.responder
        )

    async def _start_conversation(self, request: CompanyRequest) -> CompanyResponse:
        _, session = await self._caller(request)
        body = loads_strict(request.body)
        message = Message.model_validate(body.get("message"))
        owner = (session.client_id, session.pairwise_user_id)
        replay = self._replayed(owner, message)
        if replay is not None:
            return self._answer(request, self.store.conversations[replay], 201)
        parent_id = body.get("parent_conversation_id")
        parent: StoredConversation | None = None
        if parent_id is not None:
            parent = self._owned(str(parent_id), session)
            if parent.status == "closed":
                raise _RefusedError(409, "conversation_closed")
            if parent.parent_id is not None:
                raise _RefusedError(404, "conversation_not_found")
            if parent.direct_child is not None:
                raise _RefusedError(
                    409, "direct_conversation_open", conversation_id=parent.direct_child
                )
        conversation = StoredConversation(
            conversation_id=self._id("cnv"),
            owner=owner,
            parent_id=parent.conversation_id if parent else None,
        )
        self.store.conversations[conversation.conversation_id] = conversation
        if parent is not None:
            parent.direct_child = conversation.conversation_id
            self._event(parent, type="direct_opened", conversation_id=conversation.conversation_id)
        await self._receive(conversation, session, message)
        return self._answer(request, conversation, 201)

    async def _conversation_route(  # noqa: C901 - one dispatcher per conversation path
        self, request: CompanyRequest, method: str, path: str
    ) -> CompanyResponse:
        parts = path.split("/")
        conversation_id = parts[3]
        action = parts[4] if len(parts) > 4 else ""
        _, session = await self._caller(request)
        conversation = self._owned(conversation_id, session)
        if method == "GET" and action == "events":
            if "text/event-stream" in request.headers.get("accept", ""):
                return self._stream(conversation, request.headers.get("last-event-id"))
            return self._page_response(request, conversation, 200)
        if method != "POST":
            raise _RefusedError(405, "method_not_allowed")
        if action == "close":
            self._close(conversation)
            return self._receipt(conversation, 200)
        if conversation.status == "closed":
            raise _RefusedError(409, "conversation_closed")
        if conversation.direct_child is not None:
            raise _RefusedError(
                409, "direct_conversation_open", conversation_id=conversation.direct_child
            )
        if action == "handoff":
            conversation.status = "queued"
            self._state(conversation)
            if self.config.humans_available:
                conversation.status, conversation.responder = "idle", "human"
            else:
                conversation.status = "idle"
            self._state(conversation)
            return self._receipt(conversation, 202)
        if action == "messages":
            message = Message.model_validate(loads_strict(request.body).get("message"))
            owner = (session.client_id, session.pairwise_user_id)
            replay = self._replayed(owner, message)
            if replay is None:
                await self._receive(conversation, session, message)
            return self._answer(request, conversation, 202)
        raise _RefusedError(404, "not_found")

    def _replayed(self, owner: tuple[str, str], message: Message) -> str | None:
        """A retried message returns its conversation; a reused ID with new content conflicts."""

        digest = hashlib.sha256(message.model_dump_json(exclude_none=True).encode()).hexdigest()
        key = (*owner, message.id)
        known = self.store.message_ids.get(key)
        if known is None:
            return None
        conversation_id, known_digest = known.split(":", 1)
        if known_digest != digest:
            raise _RefusedError(409, "message_id_conflict")
        return conversation_id

    async def _receive(
        self, conversation: StoredConversation, session: IssuedSession, message: Message
    ) -> None:
        digest = hashlib.sha256(message.model_dump_json(exclude_none=True).encode()).hexdigest()
        self.store.message_ids[(*conversation.owner, message.id)] = (
            f"{conversation.conversation_id}:{digest}"
        )
        incoming = message.model_dump(mode="json", exclude_none=True)
        self._event(conversation, type="message", message={**incoming, "role": "user"})
        if conversation.responder == "human":
            return
        agent = cast(
            CompanyAgent, first_contribution(self.reactor, COMPANY_AGENTS, "company agent")
        )
        replies = await agent.respond(
            Turn(
                conversation_id=conversation.conversation_id,
                text=message.text,
                data=message.data,
                sender=message.sender,
                account_id=session.account_id,
                scopes=session.scopes,
                client_id=session.client_id,
                is_direct=conversation.parent_id is not None,
            )
        )
        for reply in replies:
            self._reply(conversation, session, reply)
        conversation.status = "idle"

    def _reply(
        self, conversation: StoredConversation, session: IssuedSession, reply: Reply
    ) -> None:
        if reply.authorization is not None:
            error, scope = reply.authorization
            self._event(conversation, type="authorization", error=error, scope=scope)
            return
        if reply.user_requested is not None:
            self._event(conversation, type="user_requested", reason=reply.user_requested)
            return
        message: dict[str, object] = {"id": self._id("msg"), "sender": "agent", "role": "company"}
        if reply.text is not None:
            message["text"] = reply.text
        if reply.data is not None:
            message["data"] = reply.data
        if reply.operation is not None and session.account_id is not None:
            if "operations" in self.extensions.get(session.client_id, frozenset()):
                message["operation"] = self._propose(session, reply).model_dump(mode="json")
        if len(message) > 3:
            self._event(conversation, type="message", message=message)

    def _close(self, conversation: StoredConversation) -> None:
        if conversation.status == "closed":
            return
        if conversation.direct_child is not None:
            self._close(self.store.conversations[conversation.direct_child])
        conversation.status = "closed"
        self._state(conversation)
        if conversation.parent_id is not None:
            parent = self.store.conversations[conversation.parent_id]
            parent.direct_child = None
            self._event(parent, type="direct_closed", conversation_id=conversation.conversation_id)

    def _receipt(self, conversation: StoredConversation, status: int) -> CompanyResponse:
        return CompanyResponse(
            status,
            {
                "conversation_id": conversation.conversation_id,
                "status": conversation.status,
                "responder": conversation.responder,
            },
        )

    def _answer(
        self, request: CompanyRequest, conversation: StoredConversation, status: int
    ) -> CompanyResponse:
        query = dict(parse_qsl(urlsplit(request.url).query))
        if "wait" in query or "cursor" in query:
            return self._page_response(request, conversation, status)
        return self._receipt(conversation, status)

    def _page_response(
        self, request: CompanyRequest, conversation: StoredConversation, status: int
    ) -> CompanyResponse:
        cursor = dict(parse_qsl(urlsplit(request.url).query)).get("cursor")
        events = self._after(conversation, cursor)
        page, more = events[:_PAGE], len(events) > _PAGE
        last = page[-1].id if page else (cursor or self._start_cursor(conversation))
        return CompanyResponse(
            status,
            {
                "conversation_id": conversation.conversation_id,
                "events": [event.payload for event in page],
                "cursor": last,
                "has_more": more,
                "status": conversation.status,
                "responder": conversation.responder,
            },
        )

    def _start_cursor(self, conversation: StoredConversation) -> str:
        return f"start_{conversation.conversation_id}"

    def _after(self, conversation: StoredConversation, cursor: str | None) -> list[StoredEvent]:
        if cursor is None or cursor == self._start_cursor(conversation):
            return list(conversation.events)
        for index, event in enumerate(conversation.events):
            if event.id == cursor:
                return conversation.events[index + 1 :]
        raise _RefusedError(400, "invalid_cursor")

    def _stream(
        self, conversation: StoredConversation, last_event_id: str | None
    ) -> CompanyResponse:
        events = self._after(conversation, last_event_id)

        async def frames() -> AsyncIterator[bytes]:
            yield b": poppy\n\n"
            for event in events:
                message = event.payload.get("message")
                if (
                    isinstance(message, dict)
                    and message.get("role") == "company"
                    and message.get("text")
                ):
                    text = str(message["text"])
                    half = text[: max(1, len(text) // 2)]
                    delta = {"message_id": message["id"], "text": half}
                    yield f"event: text-delta\ndata: {json.dumps(delta)}\n\n".encode()
                yield f"id: {event.id}\ndata: {json.dumps(event.payload)}\n\n".encode()

        return CompanyResponse(
            200,
            headers={"Content-Type": "text/event-stream", "Cache-Control": "no-store"},
            stream=frames(),
        )

    # Operations ----------------------------------------------------------------------

    def _propose(self, session: IssuedSession, reply: Reply) -> Operation:
        proposal = cast(Any, reply.operation)
        operation = Operation(
            operation_id=self._id("op"),
            revision=1,
            state="proposed",
            summary=proposal.summary,
            terms=proposal.terms,
            expires_at=self._now() + self.config.operation_lifetime,
            user_approval_required=proposal.user_approval_required,
            confirmation=None,
            result=None,
        )
        self.store.operations[operation.operation_id] = StoredOperation(
            operation=operation,
            action=proposal.action,
            owner=(session.client_id, session.pairwise_user_id),
            account_id=cast(str, session.account_id),
        )
        return operation

    def revise(self, operation_id: str, *, summary: str, terms: dict[str, Any]) -> Operation:
        """The company changes a proposal's terms: a new revision, the old one unconfirmable."""

        stored = self.store.operations[operation_id]
        current = stored.operation
        stored.operation = current.model_copy(
            update={"revision": current.revision + 1, "summary": summary, "terms": terms}
        )
        return stored.operation

    async def _operation_route(
        self, request: CompanyRequest, method: str, path: str
    ) -> CompanyResponse:
        parts = path.split("/")
        operation_id = parts[3]
        action = parts[4] if len(parts) > 4 else ""
        _, session = await self._caller(request)
        if "operations" not in self.extensions.get(session.client_id, frozenset()):
            raise _RefusedError(403, "extension_required", extension="operations")
        stored = self.store.operations.get(operation_id)
        if (
            stored is None
            or stored.owner != (session.client_id, session.pairwise_user_id)
            or stored.account_id != session.account_id
        ):
            raise _RefusedError(404, "operation_not_found")
        self._expire(stored)
        if method == "GET" and not action:
            return CompanyResponse(200, stored.operation.model_dump(mode="json"))
        if method == "POST" and action == "cancel":
            if stored.operation.state == "proposed":
                stored.operation = stored.operation.model_copy(
                    update={
                        "state": "cancelled",
                        "result": OperationResult(summary="Nothing was changed."),
                    }
                )
            return CompanyResponse(200, stored.operation.model_dump(mode="json"))
        if method == "POST" and action == "confirm":
            return await self._confirm(request, session, stored)
        raise _RefusedError(404, "not_found")

    def _expire(self, stored: StoredOperation) -> None:
        operation = stored.operation
        if (
            operation.state == "proposed"
            and operation.expires_at
            and self._now() >= operation.expires_at
        ):
            stored.operation = operation.model_copy(
                update={
                    "state": "expired",
                    "result": OperationResult(summary="Nothing was changed; the proposal expired."),
                }
            )

    async def _confirm(
        self, request: CompanyRequest, session: IssuedSession, stored: StoredOperation
    ) -> CompanyResponse:
        body = loads_strict(request.body)
        revision = body.get("revision")
        approved_by = body.get("approved_by")
        operation = stored.operation
        if any(scope not in session.scopes for scope in self.config.write_scopes):
            raise _RefusedError(403, "insufficient_scope", scope=" ".join(self.config.write_scopes))
        if operation.state != "proposed":
            # At most once: a retried or late confirmation returns the record unchanged.
            return CompanyResponse(200, operation.model_dump(mode="json"))
        if revision != operation.revision:
            raise _RefusedError(409, "terms_changed", operation=operation.model_dump(mode="json"))
        if approved_by not in {"user", "standing_permission"}:
            raise _RefusedError(400, "invalid_request")
        if approved_by == "standing_permission" and operation.user_approval_required:
            raise _RefusedError(403, "user_approval_required")
        confirmation = OperationConfirmation(
            revision=operation.revision,
            approved_by=cast(Literal["user", "standing_permission"], approved_by),
            confirmed_at=self._now(),
        )
        stored.operation = operation.model_copy(
            update={"state": "in_progress", "confirmation": confirmation, "expires_at": None}
        )
        executors = [
            cast(OperationExecutor, c.value)
            for c in self.reactor.get_contributions(OPERATION_EXECUTORS)
            if getattr(c.value, "action", None) == stored.action
        ]
        if len(executors) != 1:
            # Nobody can perform it: it stays in progress rather than claim a failure.
            return CompanyResponse(
                200, stored.operation.model_dump(mode="json"), {"Retry-After": "5"}
            )
        result = await executors[0].perform(stored.operation, stored.account_id)
        stored.performed = True
        stored.operation = stored.operation.model_copy(
            update={"state": "succeeded", "result": result}
        )
        return CompanyResponse(200, stored.operation.model_dump(mode="json"))
