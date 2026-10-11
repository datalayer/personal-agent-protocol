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
- MCP (§4.3, §6), when a `pap.company.mcp` contribution is present: a
  Streamable HTTP endpoint at `/mcp` accepting only Bearer Session Tokens
  issued for its url (requested without DPoP, `resource` = that url), its
  protected resource metadata (RFC 9728), and tools that propose operations
  in `structuredContent` (Operations §4.2). Bearer tokens work nowhere else.
- Web browsing (§5), with `web=True`: the browser-session endpoint sets the
  company's own cookie for a Session, and each operation's `url` shows it in
  that Session, where it can be confirmed or cancelled — the same operation,
  performed at most once (Operations §4.4).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
from collections.abc import AsyncIterator, Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from http.cookies import CookieError, SimpleCookie
from typing import Any, Literal, Protocol, TypeVar, cast
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import jwt
from pydantic import SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from ..browser import verify_browser_assertion
from ..crypto import verify_dpop_proof
from ..errors import PersonalAgentProtocolError, ProofError, SessionError
from ..json import loads_strict
from ..models import Message, Operation, OperationConfirmation, OperationResult
from ..operations import OPERATIONS_VERSION
from ..profile import PROTOCOL_PROFILE
from ..reactor import (
    CLOCKS,
    RANDOM_SOURCES,
    Clock,
    RandomSource,
    first_contribution,
    optional_contribution,
)
from ..sessions import JWT_BEARER_GRANT, JWT_CLIENT_ASSERTION, _opaque_id
from .points import (
    CLIENT_POLICIES,
    CLIENT_RESOLVERS,
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    COMPANY_APIS,
    COMPANY_MCP,
    COMPANY_STORES,
    OPERATION_EXECUTORS,
    REPLAY_CACHES,
    AccountDirectory,
    ApiCall,
    ApiResult,
    ClientPolicy,
    ClientResolver,
    CompanyAgent,
    CompanyApi,
    CompanyMcp,
    OperationExecutor,
    OperationFailed,
    OperationOutcomeUnknown,
    ReplayCache,
    Reply,
    Turn,
)
from .store import (
    ACCOUNT_AGENT,
    ACCOUNT_FAMILY,
    ACCOUNT_TOKEN,
    AUTHORIZATION,
    BROWSER_COOKIE,
    CLIENT,
    CODE,
    CONVERSATION,
    DEVICE,
    MEDIATED,
    MESSAGE_ID,
    OPERATION,
    PROPOSAL,
    SESSION,
    SESSION_TOKEN,
    USER_CODE,
    AccountAgent,
    AccountFamily,
    AccountGrant,
    CompanyStore,
    IssuedCode,
    IssuedSession,
    JsonObject,
    KnownClient,
    MessageReceipt,
    OperationProposal,
    PendingAuthorization,
    PendingDevice,
    PendingMediated,
    SessionPointer,
    StoredConversation,
    StoredEvent,
    StoredOperation,
    StoredSession,
    UserCode,
)
from .verify import verify_assertion

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105 - OAuth grant type
_PAGE = 50
#: How often a compare-and-set is retried against concurrent writers before giving up.
_CAS_ATTEMPTS = 32
#: How long an expired device or Mediated sign-in is kept, to answer that it expired.
_KEPT_EXPIRED = timedelta(minutes=10)
_EVERY_TOKEN_TYPE = frozenset({"DPoP", "Bearer"})


class _Record(Protocol):
    def to_json(self) -> JsonObject: ...


_R = TypeVar("_R", bound=_Record)


def _key_id(compact: str) -> str | None:
    """The `kid` a compact JWT's header names, if any (never trusted beyond key lookup)."""

    try:
        kid = jwt.get_unverified_header(compact).get("kid")
    except jwt.PyJWTError:
        return None
    return kid if isinstance(kid, str) else None


#: The consent page's cookie: `__Host-`, so no other host or path can set it.
CONSENT_COOKIE = "__Host-poppy_consent"
#: The website's cookie, standing for the agent's Session in its own browser (§5).
WEB_COOKIE = "poppy_session"


def _bound(secret: str, purpose: str) -> str:
    """A form's CSRF token: only a page whose browser holds `secret` (a cookie) can know it."""

    mac = hmac.new(secret.encode(), purpose.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def _cookie(request: CompanyRequest, name: str) -> str | None:
    cookies = SimpleCookie()
    try:
        cookies.load(request.headers.get("cookie", ""))
    except CookieError:
        return None
    morsel = cookies.get(name)
    return morsel.value if morsel is not None and morsel.value else None


def _from_this_site(request: CompanyRequest, base: str) -> bool:
    """A POST a page of this site sent: never one another site's page made the browser send.

    `Sec-Fetch-Site`, when the browser sends it, must be `same-origin`, and
    `Origin`, when sent, the company's own; the form's CSRF token is checked
    besides (Guides, consent pages).
    """

    site = request.headers.get("sec-fetch-site")
    origin = request.headers.get("origin")
    return (site is None or site == "same-origin") and (origin is None or origin == base)


@dataclass(frozen=True)
class ConsentDecision:
    """What the user decided on the company's own consent page, checked by `consent_decision`."""

    request_id: str
    allow: bool


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
    web: bool = False
    #: A hosted Device Sign-In page (`verification_uri`); `&code=<user_code>` completes it.
    device_page: str | None = None
    #: A hosted consent page with `{request_id}`: `GET /oauth/authorize` answers 303 to it.
    consent_page: str | None = None

    def __post_init__(self) -> None:
        for name, value in (("device_page", self.device_page), ("consent_page", self.consent_page)):
            if value is None:
                continue
            parsed = urlsplit(value.replace("{request_id}", "x"))
            if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
                raise ValueError(f"{name} must be an HTTPS URL without a fragment")
        if self.consent_page is not None and "{request_id}" not in self.consent_page:
            raise ValueError("consent_page must contain {request_id}")

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

    @property
    def mcp_url(self) -> str:
        return f"{self.base}/mcp"

    @property
    def mcp_resource_metadata(self) -> str:
        return f"{self.base}/.well-known/oauth-protected-resource/mcp"

    @property
    def browser_session_endpoint(self) -> str:
        return f"{self.base}/poppy/browser-session"


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


_CHALLENGED = frozenset(
    {"invalid_token", "sign_in_required", "insufficient_scope", "invalid_dpop_proof"}
)


def _json_error(status: int, error: str, **extra: object) -> CompanyResponse:
    headers = {"Cache-Control": "no-store"}
    if error in _CHALLENGED and status in {401, 403}:
        # Token errors are also in WWW-Authenticate (§6, RFC 9449).
        scope = extra.get("scope")
        challenge = f'DPoP error="{error}"'
        if isinstance(scope, str):
            challenge += f', scope="{scope}"'
        headers["WWW-Authenticate"] = challenge
    return CompanyResponse(status, {"error": error, **extra}, headers)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _composite(*parts: str) -> str:
    """One store key for several values (never ambiguous)."""

    return _digest(json.dumps(parts))


def _with(items: tuple[str, ...], item: str | None) -> tuple[str, ...]:
    return items if item is None or item in items else (*items, item)


class CompanyService:
    """One company's PAP endpoints over Reactor contributions."""

    def __init__(self, *, config: CompanyConfig, reactor: PluginPlatform) -> None:
        self.config = config
        self.reactor = reactor

    # Contributions -----------------------------------------------------------------

    @property
    def store(self) -> CompanyStore:
        return cast(CompanyStore, first_contribution(self.reactor, COMPANY_STORES, "company store"))

    async def _read(self, kind: str, key: str, decode: Callable[[JsonObject], _R]) -> _R | None:
        entry = await self.store.get(kind, key)
        return None if entry is None else decode(entry.value)

    async def _change(
        self,
        kind: str,
        key: str,
        decode: Callable[[JsonObject], _R],
        change: Callable[[_R], _R],
    ) -> tuple[_R, _R] | None:
        """Compare-and-set: `change` maps the current record to the next, retried on conflict.

        Returns `(before, after)`, or `None` when the record is absent; a change
        returning the same object writes nothing. Its expiry is kept.
        """

        for _ in range(_CAS_ATTEMPTS):
            entry = await self.store.get(kind, key)
            if entry is None:
                return None
            before = decode(entry.value)
            after = change(before)
            if after is before:
                return before, after
            if await self.store.replace(
                kind, key, entry.version, after.to_json(), expires_at=entry.expires_at
            ):
                return before, after
        raise _RefusedError(503, "temporarily_unavailable")

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
            if path == "/.well-known/oauth-protected-resource/mcp" and self._mcp() is not None:
                return CompanyResponse(200, self.protected_resource_metadata())
            if path == "/mcp" and self._mcp() is not None:
                return await self._mcp_route(request)
            if method == "POST" and path == "/poppy/browser-session" and self.config.web:
                return await self._browser_session(request)
            if path.startswith("/operations/") and self.config.web and self.config.operations:
                return await self._operation_page(request, method, path.split("/")[2])
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
            "protocol_version": PROTOCOL_PROFILE,
            "organization": {"name": config.name, "domain": config.domain},
            "auth": auth,
            "agent": {"protocols": [{"type": "poppy", "endpoint": config.conversations_endpoint}]},
        }
        apis: list[dict[str, str]] = []
        api = self._api()
        if api is not None:
            apis.append(
                {"type": "openapi", "url": config.api_description, "description": api.description}
            )
        mcp = self._mcp()
        if mcp is not None:
            apis.append({"type": "mcp", "url": config.mcp_url, "description": mcp.description})
        if apis:
            document["apis"] = apis
        if config.web:
            document["web"] = {"browser_session_endpoint": config.browser_session_endpoint}
        if config.operations:
            document["extensions"] = {
                "operations": {"version": OPERATIONS_VERSION, "endpoint": config.operations_endpoint}
            }
        return document

    def protected_resource_metadata(self) -> dict[str, Any]:
        """RFC 9728 metadata for the MCP server: its issuer is the company's (§6)."""

        return {
            "resource": self.config.mcp_url,
            "authorization_servers": [self.config.base],
            "scopes_supported": list(self.config.scopes),
            "bearer_methods_supported": ["header"],
        }

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
            metadata, keys = await resolver.resolve(
                client_id, kid=_key_id(form.get("client_assertion", ""))
            )
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
        extensions = tuple(sorted(metadata.extensions))
        known = await self._read(CLIENT, client_id, KnownClient.from_json)
        if known is None or known.extensions != extensions:
            await self.store.put(CLIENT, client_id, KnownClient(extensions).to_json())
        return client_id

    async def _supports_operations(self, client_id: str) -> bool:
        """Whether the agent declared the Operations extension when it last authenticated."""

        known = await self._read(CLIENT, client_id, KnownClient.from_json)
        return known is not None and "operations" in known.extensions

    async def _dpop(self, request: CompanyRequest, access_token: str | None = None) -> str:
        status = 400 if access_token is None else 401
        proof = request.headers.get("dpop")
        if not proof:
            raise _RefusedError(status, "invalid_dpop_proof")
        try:
            verified = await verify_dpop_proof(
                proof,
                method=request.method,
                url=request.url,
                replay_cache=self._replay(),
                access_token=SecretStr(access_token) if access_token is not None else None,
                now=self._now(),
            )
        except ProofError as error:
            raise _RefusedError(status, error.code) from error
        return verified.key_thumbprint

    async def _token(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        grant = form.get("grant_type")
        client_id = await self._client(form, self.config.token_endpoint)
        if "dpop" not in request.headers and self._mcp() is not None:
            # A Bearer token, only for the MCP server's url and an existing Session (§4.3).
            if form.get("resource") != self.config.mcp_url:
                raise _RefusedError(400, "invalid_dpop_proof")
            if grant not in {JWT_BEARER_GRANT, REFRESH_TOKEN_GRANT} or not form.get("session_id"):
                raise _RefusedError(400, "invalid_request")
            if grant == JWT_BEARER_GRANT:
                return await self._session_grant(form, client_id, "", bearer=True)
            return await self._refresh_grant(form, client_id, "", bearer=True)
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
        self, form: Mapping[str, str], client_id: str, thumbprint: str, *, bearer: bool = False
    ) -> CompanyResponse:
        resolver = cast(
            ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client")
        )
        _, keys = await resolver.resolve(client_id, kid=_key_id(form.get("assertion", "")))
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
            return await self._issue(session)
        known = await self._session_by_id(session_id)
        if known is None or (known.client_id, known.pairwise_user_id) != (client_id, pairwise):
            raise _RefusedError(400, "invalid_session")
        token_type: Literal["DPoP", "Bearer"] = "Bearer" if bearer else "DPoP"
        # Renewal with the assertion gives a signed-out token; a signed-in Session is
        # renewed with its Account Token instead (§4.2, §4.8).
        session = replace(
            known,
            key_thumbprint=thumbprint,
            expires_at=self._now() + self.config.session_lifetime,
            token_type=token_type,
            resource=form.get("resource"),
            account_id=None,
            scopes=(),
            account_token=None,
        )
        return await self._issue(session, replacing={token_type})

    async def _refresh_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str, *, bearer: bool = False
    ) -> CompanyResponse:
        presented = _digest(form.get("refresh_token", ""))
        entry = await self.store.get(ACCOUNT_TOKEN, presented)
        grant = None if entry is None else AccountGrant.from_json(entry.value)
        now = self._now()
        if (
            entry is None
            or grant is None
            or grant.revoked
            or now >= grant.expires_at
            or grant.client_id != client_id
        ):
            raise _RefusedError(400, "invalid_grant")
        session = await self._session_by_id(form.get("session_id", ""))
        if session is None or (session.client_id, session.pairwise_user_id) != (
            client_id,
            grant.pairwise_user_id,
        ):
            raise _RefusedError(400, "invalid_session")
        if session.account_id is not None and session.account_id != grant.account_id:
            # A Session signed in to one account never switches to another (§4.4).
            raise _RefusedError(400, "account_mismatch")
        requested = tuple(scope for scope in form.get("scope", "").split(" ") if scope)
        if requested and any(scope not in grant.scopes for scope in requested):
            raise _RefusedError(400, "invalid_scope")
        # Rotation: exactly one refresh claims the presented token, which stops working
        # the moment it is claimed; a concurrent or later reuse is `invalid_grant`.
        if not await self.store.replace(
            ACCOUNT_TOKEN,
            presented,
            entry.version,
            replace(grant, revoked=True).to_json(),
            expires_at=entry.expires_at,
        ):
            raise _RefusedError(400, "invalid_grant")
        rotated = self._id("acct")
        await self.store.put(
            ACCOUNT_TOKEN,
            _digest(rotated),
            replace(grant, revoked=False).to_json(),
            expires_at=grant.expires_at,
        )
        if not await self._join_family(grant.family, _digest(rotated), session.session_id):
            # The sign-in was revoked meanwhile: its new token is too.
            await self._revoke_grants((_digest(rotated),))
            raise _RefusedError(400, "invalid_grant")
        token_type: Literal["DPoP", "Bearer"] = "Bearer" if bearer else "DPoP"
        signed_in = replace(
            session,
            key_thumbprint=thumbprint,
            account_id=grant.account_id,
            scopes=requested or grant.scopes,
            account_token=_digest(rotated),
            expires_at=now + self.config.session_lifetime,
            resource=form.get("resource"),
            token_type=token_type,
        )
        response = await self._issue(signed_in, refresh_token=rotated, replacing={token_type})
        family = await self._read(ACCOUNT_FAMILY, grant.family, AccountFamily.from_json)
        if family is None or family.revoked:
            # Revoked while this token was issued: the Session continues signed out (§4.9).
            await self._sign_out_session(session.session_id, {_digest(rotated)})
            raise _RefusedError(400, "invalid_grant")
        return response

    async def _device(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        client_id = await self._client(form, self.config.device_endpoint)
        scopes = tuple(scope for scope in form.get("scope", "").split(" ") if scope)
        if not scopes or any(scope not in self.config.scopes for scope in scopes):
            raise _RefusedError(400, "invalid_scope")
        device_code = self._id("dev")
        lifetime = 600
        expires_at = self._now() + timedelta(seconds=lifetime)
        while True:
            user_code = self._id("u")[2:10].upper().replace("-", "X").replace("_", "Y")
            user_code = f"{user_code[:4]}-{user_code[4:]}"
            if await self.store.create(
                USER_CODE,
                user_code,
                UserCode(_digest(device_code)).to_json(),
                expires_at=expires_at + _KEPT_EXPIRED,
            ):
                break
        await self.store.put(
            DEVICE,
            _digest(device_code),
            PendingDevice(
                client_id=client_id,
                scopes=scopes,
                user_code=user_code,
                expires_at=expires_at,
                interval=self.config.device_interval,
            ).to_json(),
            expires_at=expires_at + _KEPT_EXPIRED,
        )
        if self.config.device_page is not None:
            verification_uri = self.config.device_page
            joiner = "&" if urlsplit(verification_uri).query else "?"
            complete = f"{verification_uri}{joiner}{urlencode({'code': user_code})}"
        else:
            verification_uri = f"{self.config.base}/device"
            complete = f"{self.config.base}/device?user_code={user_code}"
        return CompanyResponse(
            200,
            {
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": verification_uri,
                "verification_uri_complete": complete,
                "expires_in": lifetime,
                "interval": self.config.device_interval,
            },
            {"Cache-Control": "no-store"},
        )

    async def approve_device(
        self, user_code: str, *, account_id: str, scopes: Sequence[str] | None = None
    ) -> tuple[str, ...]:
        """The user signed in on the company's page and approved: what they granted.

        `scopes` may be fewer than requested (partial consent); omitted, all.
        Approving twice, or an unknown code, raises `KeyError`.
        """

        def approve(pending: PendingDevice) -> PendingDevice:
            if pending.user_code != user_code or pending.account_id is not None:
                raise KeyError("unknown or already approved user code")
            granted = tuple(s for s in (scopes or pending.scopes) if s in pending.scopes)
            return replace(pending, account_id=account_id, granted=granted)

        pointer = await self._read(USER_CODE, user_code, UserCode.from_json)
        changed = (
            None
            if pointer is None
            else await self._change(DEVICE, pointer.device, PendingDevice.from_json, approve)
        )
        if changed is None:
            raise KeyError("unknown or already approved user code")
        return changed[1].granted

    async def deny_device(self, user_code: str) -> None:
        pointer = await self._read(USER_CODE, user_code, UserCode.from_json)
        changed = (
            None
            if pointer is None
            else await self._change(
                DEVICE,
                pointer.device,
                PendingDevice.from_json,
                lambda pending: replace(pending, denied=True),
            )
        )
        if changed is None:
            raise KeyError("unknown user code")

    async def _device_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        key = _digest(form.get("device_code", ""))
        for _ in range(_CAS_ATTEMPTS):
            entry = await self.store.get(DEVICE, key)
            pending = None if entry is None else PendingDevice.from_json(entry.value)
            now = self._now()
            if entry is None or pending is None or pending.client_id != client_id:
                raise _RefusedError(400, "invalid_grant")
            if now >= pending.expires_at:
                await self._forget_device(key, pending)
                raise _RefusedError(400, "expired_token")
            if pending.denied:
                await self._forget_device(key, pending)
                raise _RefusedError(400, "access_denied")
            if pending.last_poll is not None and now - pending.last_poll < timedelta(
                seconds=pending.interval
            ):
                polled = replace(pending, interval=pending.interval + 5, last_poll=now)
                refusal = "slow_down"
            elif pending.account_id is None:
                polled = replace(pending, last_poll=now)
                refusal = "authorization_pending"
            else:
                break
            if await self.store.replace(
                DEVICE, key, entry.version, polled.to_json(), expires_at=entry.expires_at
            ):
                raise _RefusedError(400, refusal)
        else:
            raise _RefusedError(503, "temporarily_unavailable")
        session = await self._session_by_id(form.get("session_id", ""))
        if session is None or session.client_id != client_id:
            raise _RefusedError(400, "invalid_session")
        # Consumed once: of concurrent polls, only the one that takes it signs in.
        taken = await self.store.take(DEVICE, key)
        approved = None if taken is None else PendingDevice.from_json(taken)
        if approved is None or approved.account_id is None:
            raise _RefusedError(400, "invalid_grant")
        await self.store.delete(USER_CODE, approved.user_code)
        return await self._sign_in(session, approved.account_id, approved.granted, thumbprint)

    async def _forget_device(self, key: str, pending: PendingDevice) -> None:
        await self.store.delete(DEVICE, key)
        await self.store.delete(USER_CODE, pending.user_code)

    async def _revoke(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        client_id = await self._client(form, self.config.revocation_endpoint)
        grant = await self._read(
            ACCOUNT_TOKEN, _digest(form.get("token", "")), AccountGrant.from_json
        )
        if grant is not None and grant.client_id == client_id:
            # The token and every one rotated from the same sign-in: each Session signed
            # in with any of them continues signed out (§4.9).
            await self._sign_out((grant.family,))
        return CompanyResponse(200, {}, {"Cache-Control": "no-store"})

    async def _sign_out(self, families: Collection[str]) -> int:
        """Revoke whole sign-ins: their tokens stop working, their Sessions sign out.

        Returns how many Account Tokens this revoked (the others already were).
        """

        revoked = 0
        for family_id in families:
            changed = await self._change(
                ACCOUNT_FAMILY,
                family_id,
                AccountFamily.from_json,
                lambda family: family if family.revoked else replace(family, revoked=True),
            )
            if changed is None:
                continue
            family = changed[1]
            revoked += await self._revoke_grants(family.tokens)
            for session_id in family.sessions:
                await self._sign_out_session(session_id, set(family.tokens))
        return revoked

    async def _revoke_grants(self, tokens: Collection[str]) -> int:
        revoked = 0
        for token in tokens:
            changed = await self._change(
                ACCOUNT_TOKEN,
                token,
                AccountGrant.from_json,
                lambda grant: grant if grant.revoked else replace(grant, revoked=True),
            )
            revoked += changed is not None and not changed[0].revoked
        return revoked

    async def _sign_out_session(self, session_id: str, account_tokens: Collection[str]) -> None:
        """Each token of the Session signed in with one of `account_tokens` continues signed out."""

        def sign_out(stored: StoredSession) -> StoredSession:
            tokens = {
                digest: replace(token, account_id=None, scopes=(), account_token=None)
                if token.account_token in account_tokens
                else token
                for digest, token in stored.tokens.items()
            }
            if tokens == stored.tokens:
                return stored
            return replace(stored, tokens=tokens)

        await self._change(SESSION, session_id, StoredSession.from_json, sign_out)

    async def _join_family(self, family_id: str, token: str | None, session_id: str) -> bool:
        """Add a token and a Session to a sign-in; `False` once it is revoked."""

        changed = await self._change(
            ACCOUNT_FAMILY,
            family_id,
            AccountFamily.from_json,
            lambda family: family
            if family.revoked
            else replace(
                family,
                tokens=_with(family.tokens, token),
                sessions=_with(family.sessions, session_id),
            ),
        )
        return changed is not None and not changed[1].revoked

    async def disconnect(self, client_id: str, account_id: str) -> int:
        """The user disconnects an agent in account settings: its tokens go, Sessions sign out.

        Returns how many Account Tokens were revoked (upstream guides, account settings).
        """

        agent = await self._read(
            ACCOUNT_AGENT, _composite(client_id, account_id), AccountAgent.from_json
        )
        return 0 if agent is None else await self._sign_out(agent.families)

    async def _sign_in(
        self,
        session: IssuedSession,
        account_id: str,
        scopes: tuple[str, ...],
        thumbprint: str | None = None,
    ) -> CompanyResponse:
        if session.account_id is not None and session.account_id != account_id:
            raise _RefusedError(400, "account_mismatch")
        account_token = self._id("acct")
        family = _digest(account_token)
        expires_at = self._now() + self.config.account_token_lifetime
        await self.store.put(
            ACCOUNT_TOKEN,
            family,
            AccountGrant(
                account_id=account_id,
                client_id=session.client_id,
                pairwise_user_id=session.pairwise_user_id,
                scopes=scopes,
                expires_at=expires_at,
                family=family,
            ).to_json(),
            expires_at=expires_at,
        )
        await self.store.put(
            ACCOUNT_FAMILY,
            family,
            AccountFamily(
                client_id=session.client_id,
                account_id=account_id,
                tokens=(family,),
                sessions=(session.session_id,),
            ).to_json(),
            expires_at=expires_at,
        )
        await self._remember_family(session.client_id, account_id, family)
        signed_in = replace(
            session,
            account_id=account_id,
            scopes=scopes,
            account_token=family,
            key_thumbprint=thumbprint or session.key_thumbprint,
        )
        return await self._issue(signed_in, refresh_token=account_token)

    async def _remember_family(self, client_id: str, account_id: str, family: str) -> None:
        key = _composite(client_id, account_id)
        for _ in range(_CAS_ATTEMPTS):
            if await self.store.create(ACCOUNT_AGENT, key, AccountAgent((family,)).to_json()):
                return
            changed = await self._change(
                ACCOUNT_AGENT,
                key,
                AccountAgent.from_json,
                lambda agent: replace(agent, families=_with(agent.families, family)),
            )
            if changed is not None:
                return
        raise _RefusedError(503, "temporarily_unavailable")

    async def _issue(
        self,
        session: IssuedSession,
        *,
        refresh_token: str | None = None,
        replacing: Collection[str] = _EVERY_TOKEN_TYPE,
    ) -> CompanyResponse:
        """Issue a token for the Session; it replaces the Session's tokens of `replacing` types."""

        access_token = self._id("sat")
        digest = _digest(access_token)
        await self._record_token(session, digest, replacing)
        await self.store.put(
            SESSION_TOKEN,
            digest,
            SessionPointer(session.session_id).to_json(),
            expires_at=session.expires_at,
        )
        body: dict[str, object] = {
            "access_token": access_token,
            "token_type": session.token_type,
            "expires_in": int((session.expires_at - self._now()).total_seconds()),
            "scope": " ".join(session.scopes),
            "session_id": session.session_id,
            "signed_in": session.signed_in,
        }
        if refresh_token is not None:
            body["refresh_token"] = refresh_token
        return CompanyResponse(200, body, {"Cache-Control": "no-store"})

    async def _record_token(
        self, session: IssuedSession, digest: str, replacing: Collection[str]
    ) -> None:
        """One write: the new token joins the Session, the ones it replaces leave it."""

        for _ in range(_CAS_ATTEMPTS):
            entry = await self.store.get(SESSION, session.session_id)
            if entry is None:
                stored = StoredSession(
                    session_id=session.session_id,
                    client_id=session.client_id,
                    pairwise_user_id=session.pairwise_user_id,
                    tokens={digest: session},
                    latest=digest,
                )
                if await self.store.create(
                    SESSION,
                    session.session_id,
                    stored.to_json(),
                    expires_at=self._session_expiry(stored),
                ):
                    return
                continue
            current = StoredSession.from_json(entry.value)
            tokens = {
                key: token
                for key, token in current.tokens.items()
                if token.token_type not in replacing
            }
            stored = replace(current, tokens={**tokens, digest: session}, latest=digest)
            if await self.store.replace(
                SESSION,
                session.session_id,
                entry.version,
                stored.to_json(),
                expires_at=self._session_expiry(stored),
            ):
                return
        raise _RefusedError(503, "temporarily_unavailable")

    def _session_expiry(self, stored: StoredSession) -> datetime:
        """A Session is forgotten once no Account Token could renew it any more."""

        latest = max(token.expires_at for token in stored.tokens.values())
        return latest + self.config.account_token_lifetime

    async def _session_by_id(self, session_id: str) -> IssuedSession | None:
        stored = await self._read(SESSION, session_id, StoredSession.from_json)
        return None if stored is None else stored.current

    async def _token_session(self, token: str) -> IssuedSession | None:
        """The state of the Session token `token`, while the Session still holds it."""

        digest = _digest(token)
        pointer = await self._read(SESSION_TOKEN, digest, SessionPointer.from_json)
        if pointer is None:
            return None
        stored = await self._read(SESSION, pointer.session_id, StoredSession.from_json)
        return None if stored is None else stored.tokens.get(digest)

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
        expires_at = self._now() + timedelta(minutes=10)
        # The company's own page binds the request to this browser: its consent cookie
        # (kept if it has one) and a form token only that cookie yields.
        hosted = self.config.consent_page
        browser = _cookie(request, CONSENT_COOKIE) or self._id("consent")
        await self.store.put(
            AUTHORIZATION,
            request_id,
            PendingAuthorization(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scopes=scopes,
                state=state,
                code_challenge=query["code_challenge"],
                expires_at=expires_at,
                client_name=metadata.client_name,
                browser_binding=None if hosted is not None else _digest(browser),
            ).to_json(),
            expires_at=expires_at,
        )
        if hosted is not None:
            # A hosted consent page reads the request back (`authorization_request`).
            return CompanyResponse(
                303,
                None,
                {
                    "Location": hosted.replace("{request_id}", quote(request_id, safe="")),
                    "Cache-Control": "no-store",
                },
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
            f'<form method="post" action="{self.config.authorization_endpoint}" '
            f'data-request-id="{request_id}">'
            f'<input type="hidden" name="request_id" value="{request_id}">'
            f'<input type="hidden" name="csrf" value="{_bound(browser, f"consent:{request_id}")}">'
            '<button name="decision" value="allow">Allow</button>'
            '<button name="decision" value="deny">Deny</button></form>',
            cookie=f"{CONSENT_COOKIE}={browser}; Path=/; Secure; HttpOnly; SameSite=Strict",
        )

    async def consent_decision(self, request: CompanyRequest) -> ConsentDecision:
        """The decision the company's own consent form posted, once it is shown to be the user's.

        The company's web layer, which knows who is signed in, calls this on the
        form's POST and then `approve_authorization` or `deny_authorization`.
        Refused (`PermissionError`) unless the POST comes from this site
        (`Sec-Fetch-Site`, `Origin`), carries the consent cookie the request was
        bound to when its page was shown, and the form token only that cookie
        yields: another site's page cannot make the browser decide, and a form
        replayed from another browser does not match (Guides, consent pages).
        """

        refused = PermissionError("this decision did not come from the page that asked")
        if request.method.upper() != "POST" or not _from_this_site(request, self.config.base):
            raise refused
        form = dict(parse_qsl(request.body.decode()))
        request_id = form.get("request_id", "")
        browser = _cookie(request, CONSENT_COOKIE)
        pending = await self._read(AUTHORIZATION, request_id, PendingAuthorization.from_json)
        if (
            browser is None
            or pending is None
            or pending.browser_binding is None
            or not hmac.compare_digest(_digest(browser), pending.browser_binding)
            or not hmac.compare_digest(
                form.get("csrf", ""), _bound(browser, f"consent:{request_id}")
            )
            or form.get("decision") not in {"allow", "deny"}
        ):
            raise refused
        return ConsentDecision(request_id=request_id, allow=form["decision"] == "allow")

    async def authorization_request(self, request_id: str) -> dict[str, Any]:
        """A pending Direct Sign-In request, for a consent page to show; not consumed.

        Who asks (the agent's `client_name` and its `client_id` domain), for what
        (each requested scope with its `custom_scopes` words), until when. No
        `state`, PKCE challenge, or redirect: nothing that helps answer it.
        Raises `KeyError` for an unknown, used, or expired request.
        """

        pending = await self._read(AUTHORIZATION, request_id, PendingAuthorization.from_json)
        if pending is None or self._now() >= pending.expires_at:
            raise KeyError("unknown, used, or expired sign-in request")
        return {
            "request_id": request_id,
            "client_name": pending.client_name,
            "client_domain": urlsplit(pending.client_id).hostname or "",
            "scopes": [
                {"scope": scope, "description": self.config.custom_scopes.get(scope, scope)}
                for scope in pending.scopes
            ],
            "expires_at": pending.expires_at.isoformat().replace("+00:00", "Z"),
        }

    async def approve_authorization(
        self, request_id: str, *, account_id: str, scopes: Sequence[str] | None = None
    ) -> str:
        """The user, signed in on the company's page, allowed: where their browser goes next.

        `scopes` may be fewer than requested (partial consent); omitted, all.
        """

        pending = await self._pending_authorization(request_id)
        granted = tuple(s for s in (scopes or pending.scopes) if s in pending.scopes)
        code = self._id("code")
        expires_at = self._now() + timedelta(seconds=60)
        await self.store.put(
            CODE,
            _digest(code),
            IssuedCode(
                client_id=pending.client_id,
                redirect_uri=pending.redirect_uri,
                code_challenge=pending.code_challenge,
                account_id=account_id,
                scopes=granted,
                expires_at=expires_at,
            ).to_json(),
            expires_at=expires_at,
        )
        return self._redirect_url(pending.redirect_uri, code=code, state=pending.state)

    async def deny_authorization(self, request_id: str) -> str:
        """The user refused: the agent learns only `access_denied`."""

        pending = await self._pending_authorization(request_id)
        return self._redirect_url(pending.redirect_uri, error="access_denied", state=pending.state)

    async def _pending_authorization(self, request_id: str) -> PendingAuthorization:
        """The request, taken: of two decisions on it, only the first counts."""

        taken = await self.store.take(AUTHORIZATION, request_id)
        pending = None if taken is None else PendingAuthorization.from_json(taken)
        if pending is None or self._now() >= pending.expires_at:
            raise KeyError("unknown, used, or expired sign-in request")
        return pending

    async def _code_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        taken = await self.store.take(CODE, _digest(form.get("code", "")))
        issued = None if taken is None else IssuedCode.from_json(taken)
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
        session = await self._session_by_id(form.get("session_id", ""))
        if session is None or session.client_id != client_id:
            raise _RefusedError(400, "invalid_session")
        return await self._sign_in(session, issued.account_id, issued.scopes, thumbprint)

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
    def _page(status: int, body: str, *, cookie: str | None = None) -> CompanyResponse:
        """A consent page: never framed, never cached (upstream guides, consent pages)."""

        headers = {
            "Content-Type": "text/html; charset=utf-8",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'",
            "Cache-Control": "no-store",
        }
        if cookie is not None:
            headers["Set-Cookie"] = cookie
        return CompanyResponse(
            status, f"<!doctype html><meta charset=utf-8><title>Sign in</title>{body}", headers
        )

    # OpenAPI API (§6, Operations §4.1) -----------------------------------------------------

    def _api(self) -> CompanyApi | None:
        return cast(CompanyApi | None, optional_contribution(self.reactor, COMPANY_APIS, "API"))

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
        if not await self._supports_operations(session.client_id):
            raise _RefusedError(403, "extension_required", extension="operations")
        operation = await self._propose(session, Reply(operation=result.operation))
        return CompanyResponse(202, {"operation": operation.model_dump(mode="json")})

    # Resource requests ---------------------------------------------------------------

    async def _caller(self, request: CompanyRequest) -> tuple[str, IssuedSession]:
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme != "DPoP" or not token:
            raise _RefusedError(401, "invalid_token")
        key = _digest(token)
        session = await self._token_session(token)
        bearer = session is not None and session.token_type != "DPoP"  # noqa: S105
        if session is None or self._now() >= session.expires_at or bearer:
            # A Bearer token works only at the MCP server it was issued for (§4.3).
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
            return await self._signed_in_body(session, authenticated.account_id, granted)
        sign_in_id = self._id("si")
        expires_at = self._now() + timedelta(minutes=5)
        await self.store.put(
            MEDIATED,
            sign_in_id,
            PendingMediated(
                session_id=session.session_id,
                account_id=authenticated.account_id,
                scopes=granted,
                code_reference=authenticated.code_reference,
                expires_at=expires_at,
            ).to_json(),
            expires_at=expires_at + _KEPT_EXPIRED,
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
        pending = await self._read(MEDIATED, sign_in_id, PendingMediated.from_json)
        if pending is None or pending.session_id != session.session_id:
            # Only the Session that started it can finish it; nothing else is said.
            raise _RefusedError(404, "not_found")
        if self._now() >= pending.expires_at:
            await self.store.delete(MEDIATED, sign_in_id)
            return CompanyResponse(200, {"status": "expired"}, {"Cache-Control": "no-store"})
        body = loads_strict(request.body) if request.body else {}
        code = body.get("code") if isinstance(body, dict) else None
        accounts = cast(
            AccountDirectory, first_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        )
        if not isinstance(code, str) or not await accounts.check_code(
            pending.code_reference, SecretStr(code)
        ):
            # Every wrong code counts, however many replicas check them at once.
            counted = await self._change(
                MEDIATED,
                sign_in_id,
                PendingMediated.from_json,
                lambda current: replace(current, attempts=current.attempts + 1),
            )
            if counted is None or counted[1].attempts >= self.config.max_code_attempts:
                await self.store.delete(MEDIATED, sign_in_id)
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
        # One use: of two right codes sent at once, only the one that takes it signs in.
        taken = await self.store.take(MEDIATED, sign_in_id)
        if taken is None:
            return CompanyResponse(200, {"status": "failed"}, {"Cache-Control": "no-store"})
        completed = PendingMediated.from_json(taken)
        return await self._signed_in_body(session, completed.account_id, completed.scopes)

    async def _signed_in_body(
        self, session: IssuedSession, account_id: str, scopes: tuple[str, ...]
    ) -> CompanyResponse:
        response = await self._sign_in(session, account_id, scopes)
        return replace(response, body={"status": "complete", **cast(dict, response.body)})

    # Conversations -------------------------------------------------------------------

    async def _conversation(self, conversation_id: str) -> StoredConversation:
        conversation = await self._read(CONVERSATION, conversation_id, StoredConversation.from_json)
        if conversation is None:
            raise _RefusedError(404, "conversation_not_found")
        return conversation

    async def _owned(self, conversation_id: str, session: IssuedSession) -> StoredConversation:
        conversation = await self._read(CONVERSATION, conversation_id, StoredConversation.from_json)
        if conversation is None or conversation.owner != (
            session.client_id,
            session.pairwise_user_id,
        ):
            raise _RefusedError(404, "conversation_not_found")
        if conversation.account_id is not None and session.account_id != conversation.account_id:
            # Once it used the account, it belongs to that account (§7.2, §7.11).
            if session.account_id is None:
                raise _RefusedError(403, "sign_in_required")
            raise _RefusedError(404, "conversation_not_found")
        return conversation

    def _event(self, **payload: object) -> StoredEvent:
        event_id = self._id("evt")
        created = self._now().isoformat().replace("+00:00", "Z")
        return StoredEvent(event_id, {"id": event_id, "created_at": created, **payload})

    def _state(self, status: str, responder: str) -> StoredEvent:
        return self._event(type="state", status=status, responder=responder)

    @staticmethod
    def _open(conversation: StoredConversation) -> None:
        """A message or handoff goes only to an open conversation with no Direct one open."""

        if conversation.status == "closed":
            raise _RefusedError(409, "conversation_closed")
        if conversation.direct_child is not None:
            raise _RefusedError(
                409, "direct_conversation_open", conversation_id=conversation.direct_child
            )

    async def _start_conversation(self, request: CompanyRequest) -> CompanyResponse:
        _, session = await self._caller(request)
        body = loads_strict(request.body)
        message = Message.model_validate(body.get("message"))
        owner = (session.client_id, session.pairwise_user_id)
        replay = await self._replayed(owner, message)
        if replay is not None:
            return self._answer(request, await self._conversation(replay), 201)
        parent_id = body.get("parent_conversation_id")
        parent = None if parent_id is None else await self._direct_parent(str(parent_id), session)
        conversation = StoredConversation(
            conversation_id=self._id("cnv"),
            owner=owner,
            parent_id=parent.conversation_id if parent else None,
        )
        conversation_id = conversation.conversation_id
        replay = await self._claim(owner, message, conversation_id)
        if replay is not None:
            return self._answer(request, await self._conversation(replay), 201)
        await self.store.put(CONVERSATION, conversation_id, conversation.to_json())
        if parent is not None:
            await self._open_direct(parent.conversation_id, conversation_id, owner, message)
        conversation = await self._receive(conversation_id, session, message)
        return self._answer(request, conversation, 201)

    async def _direct_parent(self, parent_id: str, session: IssuedSession) -> StoredConversation:
        """The conversation a Direct Conversation opens under, if it can (§7.9)."""

        parent = await self._owned(parent_id, session)
        if parent.status == "closed":
            raise _RefusedError(409, "conversation_closed")
        if parent.parent_id is not None:
            raise _RefusedError(404, "conversation_not_found")
        self._open(parent)
        return parent

    async def _open_direct(
        self, parent_id: str, conversation_id: str, owner: tuple[str, str], message: Message
    ) -> None:
        """One write marks the parent's Direct Conversation; if it cannot, none was started."""

        opened = self._event(type="direct_opened", conversation_id=conversation_id)

        def open_direct(current: StoredConversation) -> StoredConversation:
            self._open(current)
            return replace(current, direct_child=conversation_id, events=(*current.events, opened))

        try:
            changed = await self._change(
                CONVERSATION, parent_id, StoredConversation.from_json, open_direct
            )
            if changed is None:
                raise _RefusedError(404, "conversation_not_found")
        except _RefusedError:
            await self.store.delete(CONVERSATION, conversation_id)
            await self.store.delete(MESSAGE_ID, _composite(*owner, message.id))
            raise

    async def _conversation_route(
        self, request: CompanyRequest, method: str, path: str
    ) -> CompanyResponse:
        parts = path.split("/")
        conversation_id = parts[3]
        action = parts[4] if len(parts) > 4 else ""
        _, session = await self._caller(request)
        conversation = await self._owned(conversation_id, session)
        if method == "GET" and action == "events":
            if "text/event-stream" in request.headers.get("accept", ""):
                return self._stream(conversation, request.headers.get("last-event-id"))
            return self._page_response(request, conversation, 200)
        if method != "POST":
            raise _RefusedError(405, "method_not_allowed")
        if action == "close":
            await self._close(conversation_id)
            return self._receipt(await self._conversation(conversation_id), 200)
        self._open(conversation)
        if action == "handoff":

            def handoff(current: StoredConversation) -> StoredConversation:
                self._open(current)
                responder = "human" if self.config.humans_available else current.responder
                return replace(
                    current,
                    status="idle",
                    responder=responder,
                    events=(
                        *current.events,
                        self._state("queued", current.responder),
                        self._state("idle", responder),
                    ),
                )

            changed = await self._change(
                CONVERSATION, conversation_id, StoredConversation.from_json, handoff
            )
            if changed is None:
                raise _RefusedError(404, "conversation_not_found")
            return self._receipt(changed[1], 202)
        if action == "messages":
            message = Message.model_validate(loads_strict(request.body).get("message"))
            owner = (session.client_id, session.pairwise_user_id)
            replay = await self._replayed(owner, message)
            if replay is None and await self._claim(owner, message, conversation_id) is None:
                await self._receive(conversation_id, session, message)
            return self._answer(request, await self._conversation(conversation_id), 202)
        raise _RefusedError(404, "not_found")

    @staticmethod
    def _message_digest(message: Message) -> str:
        return hashlib.sha256(message.model_dump_json(exclude_none=True).encode()).hexdigest()

    async def _replayed(self, owner: tuple[str, str], message: Message) -> str | None:
        """A retried message returns its conversation; a reused ID with new content conflicts."""

        known = await self._read(
            MESSAGE_ID, _composite(*owner, message.id), MessageReceipt.from_json
        )
        if known is None:
            return None
        if known.digest != self._message_digest(message):
            raise _RefusedError(409, "message_id_conflict")
        return known.conversation_id

    async def _claim(
        self, owner: tuple[str, str], message: Message, conversation_id: str
    ) -> str | None:
        """Record the message ID, once: `None` when this call did, else the earlier conversation."""

        receipt = MessageReceipt(conversation_id, self._message_digest(message))
        for _ in range(_CAS_ATTEMPTS):
            if await self.store.create(
                MESSAGE_ID, _composite(*owner, message.id), receipt.to_json()
            ):
                return None
            replay = await self._replayed(owner, message)
            if replay is not None:
                return replay
        raise _RefusedError(503, "temporarily_unavailable")

    async def _receive(
        self, conversation_id: str, session: IssuedSession, message: Message
    ) -> StoredConversation:
        incoming = message.model_dump(mode="json", exclude_none=True)
        received = self._event(type="message", message={**incoming, "role": "user"})

        def accept(current: StoredConversation) -> StoredConversation:
            self._open(current)
            return replace(
                current,
                account_id=session.account_id or current.account_id,
                events=(*current.events, received),
            )

        try:
            changed = await self._change(
                CONVERSATION, conversation_id, StoredConversation.from_json, accept
            )
            if changed is None:
                raise _RefusedError(404, "conversation_not_found")
        except _RefusedError:
            # Not received: the same message may be sent again.
            owner = (session.client_id, session.pairwise_user_id)
            await self.store.delete(MESSAGE_ID, _composite(*owner, message.id))
            raise
        conversation = changed[1]
        if conversation.responder == "human":
            return conversation
        agent = cast(
            CompanyAgent, first_contribution(self.reactor, COMPANY_AGENTS, "company agent")
        )
        replies = await agent.respond(
            Turn(
                conversation_id=conversation_id,
                text=message.text,
                data=message.data,
                sender=message.sender,
                account_id=session.account_id,
                scopes=session.scopes,
                client_id=session.client_id,
                is_direct=conversation.parent_id is not None,
            )
        )
        events: list[StoredEvent] = []
        for reply in replies:
            event = await self._reply(session, reply)
            if event is not None:
                events.append(event)

        def answered(current: StoredConversation) -> StoredConversation:
            status: Literal["idle", "closed"] = "closed" if current.status == "closed" else "idle"
            return replace(current, status=status, events=(*current.events, *events))

        changed = await self._change(
            CONVERSATION, conversation_id, StoredConversation.from_json, answered
        )
        return conversation if changed is None else changed[1]

    async def _reply(self, session: IssuedSession, reply: Reply) -> StoredEvent | None:
        if reply.authorization is not None:
            error, scope = reply.authorization
            return self._event(type="authorization", error=error, scope=scope)
        if reply.user_requested is not None:
            return self._event(type="user_requested", reason=reply.user_requested)
        message: dict[str, object] = {"id": self._id("msg"), "sender": "agent", "role": "company"}
        if reply.text is not None:
            message["text"] = reply.text
        if reply.data is not None:
            message["data"] = reply.data
        if reply.operation is not None and session.account_id is not None:
            if await self._supports_operations(session.client_id):
                operation = await self._propose(session, reply)
                message["operation"] = operation.model_dump(mode="json")
        if len(message) > 3:
            return self._event(type="message", message=message)
        return None

    async def _close(self, conversation_id: str) -> None:
        conversation = await self._read(CONVERSATION, conversation_id, StoredConversation.from_json)
        if conversation is None or conversation.status == "closed":
            return
        if conversation.direct_child is not None:
            await self._close(conversation.direct_child)

        def close(current: StoredConversation) -> StoredConversation:
            if current.status == "closed":
                return current
            closed = self._state("closed", current.responder)
            return replace(current, status="closed", events=(*current.events, closed))

        changed = await self._change(
            CONVERSATION, conversation_id, StoredConversation.from_json, close
        )
        if changed is None or changed[0].status == "closed":
            return
        if conversation.parent_id is not None:
            event = self._event(type="direct_closed", conversation_id=conversation_id)
            await self._change(
                CONVERSATION,
                conversation.parent_id,
                StoredConversation.from_json,
                lambda parent: replace(parent, direct_child=None, events=(*parent.events, event)),
            )

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

    async def forget_events(self, conversation_id: str, *, keep: int = 0) -> None:
        """Retention: drop all but the last `keep` events; their cursors expire (§7.5)."""

        def forget(conversation: StoredConversation) -> StoredConversation:
            cut = max(len(conversation.events) - keep, 0)
            return replace(
                conversation,
                events=conversation.events[cut:],
                forgotten=conversation.forgotten
                | {event.id for event in conversation.events[:cut]},
            )

        if (
            await self._change(CONVERSATION, conversation_id, StoredConversation.from_json, forget)
            is None
        ):
            raise KeyError(conversation_id)

    def _after(self, conversation: StoredConversation, cursor: str | None) -> list[StoredEvent]:
        if cursor is None or cursor == self._start_cursor(conversation):
            return list(conversation.events)
        if cursor in conversation.forgotten:
            raise _RefusedError(410, "cursor_expired")
        for index, event in enumerate(conversation.events):
            if event.id == cursor:
                return list(conversation.events[index + 1 :])
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

    async def _propose(self, session: IssuedSession, reply: Reply) -> Operation:
        proposal = cast(Any, reply.operation)
        owner = (session.client_id, session.pairwise_user_id)
        account_id = cast(str, session.account_id)
        # The same action through another channel is the same operation (Operations §4).
        key = _composite(
            *owner,
            account_id,
            proposal.action,
            proposal.summary,
            json.dumps(proposal.terms, sort_keys=True, default=str),
        )
        known = await self._read(PROPOSAL, key, OperationProposal.from_json)
        if known is not None:
            current = await self._current_operation(known.operation_id)
            if (
                current is not None
                and current.owner == owner
                and current.account_id == account_id
                and current.action == proposal.action
                and current.operation.state == "proposed"
                and current.operation.summary == proposal.summary
                and current.operation.terms == proposal.terms
            ):
                return current.operation
        operation_id = self._id("op")
        operation = Operation(
            operation_id=operation_id,
            revision=1,
            state="proposed",
            summary=proposal.summary,
            terms=proposal.terms,
            expires_at=self._now() + self.config.operation_lifetime,
            user_approval_required=proposal.user_approval_required,
            url=f"{self.config.base}/operations/{operation_id}",
            confirmation=None,
            result=None,
        )
        stored = StoredOperation(
            operation=operation, action=proposal.action, owner=owner, account_id=account_id
        )
        await self.store.put(OPERATION, operation_id, stored.to_json())
        await self.store.put(
            PROPOSAL,
            key,
            OperationProposal(operation_id).to_json(),
            expires_at=operation.expires_at,
        )
        return operation

    async def operation_record(self, operation_id: str) -> StoredOperation:
        """An operation as the company keeps it: its record, action, owner, and account."""

        stored = await self._current_operation(operation_id)
        if stored is None:
            raise KeyError(operation_id)
        return stored

    async def revise(self, operation_id: str, *, summary: str, terms: dict[str, Any]) -> Operation:
        """The company changes a proposal's terms: a new revision, the old one unconfirmable."""

        def revise(stored: StoredOperation) -> StoredOperation:
            current = stored.operation
            if current.state != "proposed":
                raise ValueError("only a proposed operation can be revised")
            return replace(
                stored,
                operation=current.model_copy(
                    update={
                        "revision": current.revision + 1,
                        "summary": summary,
                        "terms": terms,
                        "expires_at": self._now() + self.config.operation_lifetime,
                    }
                ),
            )

        changed = await self._change(OPERATION, operation_id, StoredOperation.from_json, revise)
        if changed is None:
            raise KeyError(operation_id)
        return changed[1].operation

    async def settle(
        self, operation_id: str, result: OperationResult, *, succeeded: bool
    ) -> Operation:
        """The company found out how an operation left `in_progress` ended."""

        def settle(stored: StoredOperation) -> StoredOperation:
            if stored.operation.state != "in_progress":
                raise ValueError("only an operation in progress can be settled")
            return replace(
                stored,
                performed=succeeded or stored.performed,
                operation=stored.operation.model_copy(
                    update={"state": "succeeded" if succeeded else "failed", "result": result}
                ),
            )

        changed = await self._change(OPERATION, operation_id, StoredOperation.from_json, settle)
        if changed is None:
            raise KeyError(operation_id)
        return changed[1].operation

    async def _operation_route(
        self, request: CompanyRequest, method: str, path: str
    ) -> CompanyResponse:
        parts = path.split("/")
        operation_id = parts[3]
        action = parts[4] if len(parts) > 4 else ""
        _, session = await self._caller(request)
        if not await self._supports_operations(session.client_id):
            raise _RefusedError(403, "extension_required", extension="operations")
        stored = await self._usable(operation_id, session)
        if method == "GET" and not action:
            return self._operation_response(stored)
        if method == "POST" and action == "cancel":
            return await self._cancel_operation(operation_id)
        if method == "POST" and action == "confirm":
            return await self._confirm(request, session, stored)
        raise _RefusedError(404, "not_found")

    async def _cancel_operation(self, operation_id: str) -> CompanyResponse:
        def cancel(stored: StoredOperation) -> StoredOperation:
            stored = self._expired(stored)
            if stored.operation.state != "proposed":
                # In progress, it stays so until the company knows whether it stopped (§7).
                return stored
            return replace(
                stored,
                operation=stored.operation.model_copy(
                    update={
                        "state": "cancelled",
                        "result": OperationResult(summary="Nothing was changed."),
                    }
                ),
            )

        changed = await self._change(OPERATION, operation_id, StoredOperation.from_json, cancel)
        if changed is None:
            raise _RefusedError(404, "operation_not_found")
        return self._operation_response(changed[1])

    async def _usable(self, operation_id: str, session: IssuedSession) -> StoredOperation:
        """The operation, if this Session may use it (Operations §3.2)."""

        stored = await self._read(OPERATION, operation_id, StoredOperation.from_json)
        if (
            stored is None
            or stored.owner != (session.client_id, session.pairwise_user_id)
            or stored.account_id != session.account_id
        ):
            raise _RefusedError(404, "operation_not_found")
        current = await self._current_operation(operation_id)
        if current is None:
            raise _RefusedError(404, "operation_not_found")
        return current

    async def _current_operation(self, operation_id: str) -> StoredOperation | None:
        """The operation now: a proposal past its expiry is recorded as expired."""

        changed = await self._change(
            OPERATION, operation_id, StoredOperation.from_json, self._expired
        )
        return None if changed is None else changed[1]

    def _expired(self, stored: StoredOperation) -> StoredOperation:
        operation = stored.operation
        if (
            operation.state == "proposed"
            and operation.expires_at
            and self._now() >= operation.expires_at
        ):
            return replace(
                stored,
                operation=operation.model_copy(
                    update={
                        "state": "expired",
                        "result": OperationResult(
                            summary="Nothing was changed; the proposal expired."
                        ),
                    }
                ),
            )
        return stored

    async def _confirm(
        self, request: CompanyRequest, session: IssuedSession, stored: StoredOperation
    ) -> CompanyResponse:
        body = loads_strict(request.body)
        if not isinstance(body, dict):
            raise _RefusedError(400, "invalid_request")
        return await self._confirm_operation(
            session, stored, body.get("revision"), body.get("approved_by")
        )

    async def _confirm_operation(
        self,
        session: IssuedSession,
        stored: StoredOperation,
        revision: object,
        approved_by: object,
    ) -> CompanyResponse:
        """Confirm, whichever channel it comes through: at most once (Operations §4.4, §6)."""

        operation = stored.operation
        if any(scope not in session.scopes for scope in self.config.write_scopes):
            raise _RefusedError(403, "insufficient_scope", scope=" ".join(self.config.write_scopes))
        if operation.state != "proposed":
            # At most once: a retried or late confirmation returns the record unchanged.
            return CompanyResponse(200, operation.model_dump(mode="json"))
        confirmation = self._confirmation(operation, revision, approved_by)

        def confirm(current: StoredOperation) -> StoredOperation:
            current = self._expired(current)
            if current.operation.state != "proposed":
                return current
            if current.operation.revision != revision:
                raise _RefusedError(
                    409, "terms_changed", operation=current.operation.model_dump(mode="json")
                )
            return replace(
                current,
                operation=current.operation.model_copy(
                    update={
                        "state": "in_progress",
                        "confirmation": confirmation,
                        "expires_at": None,
                    }
                ),
            )

        # The one compare-and-set from `proposed` to `in_progress`: only its winner performs.
        changed = await self._change(
            OPERATION, operation.operation_id, StoredOperation.from_json, confirm
        )
        if changed is None:
            raise _RefusedError(404, "operation_not_found")
        before, confirmed = changed
        if before.operation.state != "proposed" or confirmed.operation.state != "in_progress":
            return CompanyResponse(200, confirmed.operation.model_dump(mode="json"))
        return await self._perform(confirmed)

    def _confirmation(
        self, operation: Operation, revision: object, approved_by: object
    ) -> OperationConfirmation:
        """The confirmation of the latest revision, approved as the rules allow."""

        if revision != operation.revision:
            raise _RefusedError(409, "terms_changed", operation=operation.model_dump(mode="json"))
        if approved_by not in {"user", "standing_permission"}:
            raise _RefusedError(400, "invalid_request")
        if approved_by == "standing_permission" and operation.user_approval_required:
            raise _RefusedError(403, "user_approval_required")
        return OperationConfirmation(
            revision=operation.revision,
            approved_by=approved_by,
            confirmed_at=self._now(),
        )

    async def _perform(self, confirmed: StoredOperation) -> CompanyResponse:
        """Perform a just-confirmed operation with its action's executor.

        The action's lowest-order executor performs it; two at that order are ambiguous.
        """

        executors = [
            contribution
            for contribution in self.reactor.get_contributions(OPERATION_EXECUTORS)
            if getattr(contribution.value, "action", None) == confirmed.action
        ]
        if not executors or (len(executors) > 1 and executors[0].order == executors[1].order):
            # Nobody can perform it: it stays in progress rather than claim a failure.
            return self._operation_response(confirmed)
        executor = cast(OperationExecutor, executors[0].value)
        try:
            result = await executor.perform(confirmed.operation, confirmed.account_id)
        except OperationFailed as failed:
            # Failed partway: the result says every change that was made (Operations §6).
            return await self._finish(confirmed, "failed", failed.result)
        except OperationOutcomeUnknown:
            # Never `failed` while it may have taken effect: it stays in progress.
            return self._operation_response(confirmed)
        return await self._finish(confirmed, "succeeded", result)

    async def _finish(
        self,
        confirmed: StoredOperation,
        state: Literal["succeeded", "failed"],
        result: OperationResult,
    ) -> CompanyResponse:
        def finish(current: StoredOperation) -> StoredOperation:
            if current.operation.state != "in_progress":
                return current
            return replace(
                current,
                performed=True,
                operation=current.operation.model_copy(update={"state": state, "result": result}),
            )

        changed = await self._change(
            OPERATION, confirmed.operation.operation_id, StoredOperation.from_json, finish
        )
        return self._operation_response(confirmed if changed is None else changed[1])

    @staticmethod
    def _operation_response(stored: StoredOperation) -> CompanyResponse:
        headers = {"Retry-After": "5"} if stored.operation.state == "in_progress" else {}
        return CompanyResponse(200, stored.operation.model_dump(mode="json"), headers)

    # MCP (§4.3, §6, Operations §4.2) -------------------------------------------------------

    def _mcp(self) -> CompanyMcp | None:
        return cast(CompanyMcp | None, optional_contribution(self.reactor, COMPANY_MCP, "MCP server"))

    def _bearer_refusal(self, status: int, error: str, scope: str | None = None) -> CompanyResponse:
        challenge = (
            f'Bearer error="{error}", resource_metadata="{self.config.mcp_resource_metadata}"'
        )
        if scope is not None:
            challenge += f', scope="{scope}"'
        body: dict[str, object] = {"error": error}
        if scope is not None:
            body["scope"] = scope
        return CompanyResponse(
            status, body, {"WWW-Authenticate": challenge, "Cache-Control": "no-store"}
        )

    async def _bearer_caller(self, request: CompanyRequest) -> IssuedSession | None:
        """The Session of a Bearer token issued for this MCP server, else `None`."""

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme != "Bearer" or not token:
            return None
        session = await self._token_session(token)
        if (
            session is None
            or self._now() >= session.expires_at
            or session.token_type != "Bearer"  # noqa: S105 - OAuth token type
            or session.resource != self.config.mcp_url
        ):
            return None
        return session

    async def _mcp_route(  # noqa: C901 - the JSON-RPC methods
        self, request: CompanyRequest
    ) -> CompanyResponse:
        session = await self._bearer_caller(request)
        if session is None:
            # A missing, expired, DPoP, or other-resource token: none is accepted here.
            return self._bearer_refusal(401, "invalid_token")
        if request.method.upper() != "POST":
            return CompanyResponse(405, {"error": "method_not_allowed"}, {"Allow": "POST"})
        try:
            message = loads_strict(request.body)
        except (ValueError, PersonalAgentProtocolError):
            return _rpc_error(None, -32700, "Parse error")
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _rpc_error(None, -32600, "Invalid Request")
        request_id = message.get("id")
        method = message.get("method")
        if request_id is None:
            return CompanyResponse(202, None)  # a notification, such as notifications/initialized
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        mcp = cast(CompanyMcp, self._mcp())
        if method == "initialize":
            result: object = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": self.config.name, "version": "1"},
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": mcp.tools()}
        elif method == "tools/call":
            outcome = await self._mcp_tool(session, mcp, cast(dict, params))
            if isinstance(outcome, CompanyResponse):
                return outcome
            result = outcome
        else:
            return _rpc_error(request_id, -32601, "Method not found")
        return CompanyResponse(200, {"jsonrpc": "2.0", "id": request_id, "result": result})

    async def _mcp_tool(
        self, session: IssuedSession, mcp: CompanyMcp, params: dict[str, Any]
    ) -> dict[str, Any] | CompanyResponse:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _rpc_error(None, -32602, "Invalid params")
        answer = await mcp.call(
            name,
            arguments,
            ApiCall(
                method="TOOL",
                path=name,
                query={},
                body=arguments,
                account_id=session.account_id,
                scopes=session.scopes,
                client_id=session.client_id,
            ),
        )
        if answer.refusal is not None:
            status, error, scope = answer.refusal
            return self._bearer_refusal(status, error, scope)
        if answer.operation is not None:
            if session.account_id is None:
                return self._bearer_refusal(403, "sign_in_required")
            if not await self._supports_operations(session.client_id):
                return _json_error(403, "extension_required", extension="operations")
            operation = await self._propose(session, Reply(operation=answer.operation))
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Proposed: {operation.summary} Not done until confirmed.",
                    }
                ],
                "structuredContent": {"operation": operation.model_dump(mode="json")},
            }
        text = answer.text if answer.text is not None else json.dumps(answer.structured or {})
        result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
        if answer.structured is not None:
            result["structuredContent"] = answer.structured
        if answer.is_error:
            result["isError"] = True
        return result

    # Web browsing (§5, Operations §4.4) --------------------------------------------------

    async def _live_session(self, session_id: str) -> IssuedSession | None:
        """The Session as it is now: its latest unexpired DPoP token's record."""

        stored = await self._read(SESSION, session_id, StoredSession.from_json)
        now = self._now()
        live = [
            session
            for session in (stored.tokens.values() if stored is not None else ())
            if session.token_type == "DPoP"  # noqa: S105 - OAuth token type
            and now < session.expires_at
        ]
        return max(live, key=lambda session: session.expires_at) if live else None

    async def _browser_session(self, request: CompanyRequest) -> CompanyResponse:
        refused = self._page(400, "This browser could not join the session.")
        assertion = dict(parse_qsl(request.body.decode())).get("assertion", "")
        try:
            claims = jwt.decode(assertion, options={"verify_signature": False})
            header = jwt.get_unverified_header(assertion)
            client_id = str(claims["iss"])
            resolver = cast(
                ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client")
            )
            _, keys = await resolver.resolve(client_id, kid=_key_id(assertion))
        except (KeyError, TypeError, ValueError, jwt.PyJWTError, PersonalAgentProtocolError):
            return refused
        algorithm = str(header.get("alg", ""))
        verified = None
        for key in keys.keys:
            if header.get("kid") not in {None, key.kid} or key.alg not in {None, algorithm}:
                continue
            try:
                public = jwt.PyJWK.from_dict(
                    json.loads(key.model_dump_json(exclude_none=True)), algorithm=algorithm
                ).key
                verified = await verify_browser_assertion(
                    assertion,
                    public_key=public,
                    expected_endpoint=self.config.browser_session_endpoint,
                    company_domain=self.config.domain,
                    expected_client_id=client_id,
                    expected_pairwise_user_id=str(claims.get("sub", "")),
                    expected_session_id=str(claims.get("session_id", "")),
                    replay_cache=self._replay(),
                    now=self._now(),
                )
                break
            except (PersonalAgentProtocolError, jwt.PyJWTError, ValueError, TypeError):
                continue
        if verified is None:
            return refused
        if verified.expires_at - timedelta(seconds=60) > datetime.fromtimestamp(
            int(claims["iat"]), verified.expires_at.tzinfo
        ):
            return refused  # exp is at most 60 seconds after iat
        session = await self._live_session(verified.session_id)
        if session is None or (session.client_id, session.pairwise_user_id) != (
            verified.client_id,
            verified.pairwise_user_id,
        ):
            return refused
        cookie = self._id("web")
        await self.store.put(
            BROWSER_COOKIE,
            _digest(cookie),
            SessionPointer(session.session_id).to_json(),
            expires_at=session.expires_at + self.config.account_token_lifetime,
        )
        return CompanyResponse(
            303,
            None,
            {
                "Location": verified.return_to,
                # The company's own cookie: no Max-Age, and only as alive as its Session.
                "Set-Cookie": f"{WEB_COOKIE}={cookie}; Path=/; Secure; HttpOnly; SameSite=Lax",
                "Cache-Control": "no-store",
            },
        )

    async def _web_session(self, cookie: str | None) -> IssuedSession | None:
        """The Session a browser's cookie stands for, as it is now (§5)."""

        if cookie is None:
            return None
        pointer = await self._read(BROWSER_COOKIE, _digest(cookie), SessionPointer.from_json)
        if pointer is None:
            return None
        session = await self._live_session(pointer.session_id)
        if session is None:
            # The cookie does not outlive the Session.
            await self.store.delete(BROWSER_COOKIE, _digest(cookie))
        return session

    async def _operation_page(
        self, request: CompanyRequest, method: str, operation_id: str
    ) -> CompanyResponse:
        cookie = _cookie(request, WEB_COOKIE)
        session = await self._web_session(cookie)
        if cookie is None or session is None:
            return self._page(401, "Your agent's session has ended. Ask it to open this again.")
        try:
            stored = await self._usable(operation_id, session)
        except _RefusedError:
            return self._page(404, "There is nothing to show here.")
        page_url = f"{self.config.base}/operations/{operation_id}"
        csrf = _bound(cookie, f"operation:{operation_id}")
        if method == "POST":
            form = dict(parse_qsl(request.body.decode()))
            # This site's page, in the browser this cookie is in: never another site's
            # page, nor a form copied from another Session's page (Guides, consent pages).
            if not _from_this_site(request, self.config.base) or not hmac.compare_digest(
                form.get("csrf", ""), csrf
            ):
                return self._page(403, "This request did not come from this site.")
            try:
                if form.get("action") == "cancel":
                    await self._cancel_operation(operation_id)
                else:
                    revision = int(form["revision"]) if form.get("revision", "").isdigit() else None
                    await self._confirm_operation(
                        session, stored, revision, form.get("approved_by", "user")
                    )
            except _RefusedError as refusal:
                return self._page(refusal.status, f"Not done: {html.escape(refusal.error)}.")
            return CompanyResponse(303, None, {"Location": page_url, "Cache-Control": "no-store"})
        if method != "GET":
            return self._page(405, "Not allowed.")
        operation = stored.operation
        body = (
            f"<h1>{html.escape(self.config.name)}</h1>"
            f'<section data-operation-id="{html.escape(operation.operation_id)}" '
            f'data-revision="{operation.revision}" data-state="{operation.state}">'
            f"<p>{html.escape(operation.summary)}</p><p>Status: {operation.state}</p>"
        )
        if operation.result is not None:
            body += f"<p>{html.escape(operation.result.summary)}</p>"
        if operation.state == "proposed":
            body += (
                f'<form method="post" action="{page_url}">'
                f'<input type="hidden" name="revision" value="{operation.revision}">'
                '<input type="hidden" name="approved_by" value="user">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                '<button name="action" value="confirm">Confirm</button>'
                '<button name="action" value="cancel">Cancel</button></form>'
            )
        return self._page(200, body + "</section>")


def _rpc_error(request_id: object, code: int, message: str) -> CompanyResponse:
    return CompanyResponse(
        200, {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    )
