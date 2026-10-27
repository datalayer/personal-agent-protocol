# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A framework-neutral PAP company: discovery, Sessions, sign-in, conversations, operations.

`CompanyService.handle` takes a neutral request and returns a neutral
response, so any web framework can serve it (`asgi.company_app` serves it
over plain ASGI). Every part a company would replace is a Reactor
contribution (`points`): its store, accounts, agent, operation executors,
client policy and resolver, and replay cache.

What it implements of draft 0.2 and Operations v1:

- Discovery (`/.well-known/poppy.json`) and OAuth metadata
  (`/.well-known/oauth-authorization-server`), one issuer on the company's
  own domain.
- Sessions (§4.2): the JWT-bearer grant with a verified client assertion and
  Session assertion, DPoP-bound tokens, renewal by `session_key`.
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
  Once a conversation is handed to the company's people, one of them
  answers in it (`staff_reply`), over the last event they read.
- Operations v1: proposals from the company agent, read, confirm (latest
  revision, approval rules, scope, extension negotiation), at most once, and
  cancel.
- MCP (§4.3, §6), when a `pap.company.mcp` contribution is present: a
  Streamable HTTP endpoint at `/mcp` accepting only Session Tokens issued
  for its url (`resource` = that url), its protected resource metadata
  (RFC 9728), and tools that propose operations in `structuredContent`
  (Operations §4.2). With `mcp_dpop` (the default) the server supports
  DPoP: personal agents get DPoP tokens for it and send proofs; without
  it, they get Bearer tokens, which work nowhere else.
- Feedback (§8), with `feedback` (the default): reports of tasks the
  protocol can't do, kept for the company's operator (`feedback_reports`).
- Web browsing (§5), with `web=True`: the browser-session endpoint sets the
  company's own cookie for a Session, and each operation's `url` shows it in
  that Session, where it can be confirmed or cancelled — the same operation,
  performed at most once (Operations §4.4).
- Taking a company down: its owner reads what is under way (`open_work`),
  settles each open operation as cancelled (`cancel_open_operations`) and
  ends every sign-in (`end_sign_ins`), before its records go.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import math
import re
import time
from collections.abc import AsyncIterator, Callable, Collection, Mapping, Sequence
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from http.cookies import CookieError, SimpleCookie
from typing import Any, Literal, Protocol, TypeVar, cast
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import jwt
from pydantic import SecretStr, ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from ..apis import IDEMPOTENCY_KEY, WRITE_METHODS
from ..crypto import verify_dpop_proof
from ..errors import (
    PersonalAgentProtocolError,
    ProofError,
    ProtocolValidationError,
    SessionError,
)
from ..json import loads_strict
from ..models import (
    AUTHORIZATION_CODE_GRANT,
    DEVICE_CODE_GRANT,
    REFRESH_TOKEN_GRANT,
    TOKEN_EXCHANGE_GRANT,
    Author,
    ConversationEvent,
    Message,
    Operation,
    OperationConfirmation,
    OperationResult,
    redirect_uri_matches,
)
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
from ..sessions import ACCESS_TOKEN_TYPE, JWT_BEARER_GRANT, JWT_CLIENT_ASSERTION, _opaque_id
from ..telemetry import emit, telemetry_sink
from .points import (
    CLIENT_POLICIES,
    CLIENT_RESOLVERS,
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    COMPANY_APIS,
    COMPANY_MCP,
    COMPANY_RATE_LIMITS,
    COMPANY_STORES,
    OPERATION_EXECUTORS,
    REPLAY_CACHES,
    AccountDirectory,
    AccountSignOuts,
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
    RateLimit,
    ReplayCache,
    Reply,
    SignInContext,
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
    DPOP,
    DPOP_NONCE,
    FEEDBACK,
    IDEMPOTENCY,
    JOIN_CODE,
    MEDIATED,
    MESSAGE_ID,
    OPERATION,
    PROPOSAL,
    SESSION,
    SESSION_TOKEN,
    SIGN_IN_ATTEMPTS,
    USER_CODE,
    AccountAgent,
    AccountFamily,
    AccountGrant,
    CompanyStore,
    IdempotencyRecord,
    IssuedCode,
    IssuedNonce,
    IssuedSession,
    JoinCode,
    JsonObject,
    KnownClient,
    MessageReceipt,
    OperationProposal,
    PendingAuthorization,
    PendingDevice,
    PendingMediated,
    SessionPointer,
    SignInAttempts,
    StoredConversation,
    StoredEvent,
    StoredFeedback,
    StoredOperation,
    StoredSession,
    UserCode,
)
from .verify import verify_assertion

REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105 - OAuth grant type
_PAGE = 50
#: How often a compare-and-set is retried against concurrent writers before giving up.
_CAS_ATTEMPTS = 32
#: How long an expired device or Mediated sign-in is kept, to answer that it expired.
_KEPT_EXPIRED = timedelta(minutes=10)
#: How long the first request with an `Idempotency-Key` holds it: a repeat in that time
#: is told to wait (503, `Retry-After`); a holder that never answered lets it go then.
_IDEMPOTENCY_HELD = timedelta(minutes=1)
#: The DPoP algorithms the company accepts: ES256, which every company must (§3.2), and RS256.
DPOP_ALGORITHMS = ("ES256", "RS256")
#: The longest `wait` the company holds a read for; a larger one is held this long (§7.5).
MAX_WAIT_SECONDS = 30


class _Record(Protocol):
    def to_json(self) -> JsonObject: ...


_R = TypeVar("_R", bound=_Record)


_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_THUMBPRINT = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _key_id(compact: str) -> str | None:
    """The `kid` a compact JWT's header names, if any (never trusted beyond key lookup)."""

    try:
        kid = jwt.get_unverified_header(compact).get("kid")
    except jwt.PyJWTError:
        return None
    return kid if isinstance(kid, str) else None


#: The consent page's cookie: `__Host-`, so no other host or path can set it.
CONSENT_COOKIE = "__Host-poppy_consent"
#: The website's cookie, standing for the agent's Session in its own browser (§5): `__Host-`
#: (Secure, Path=/, no Domain), so no other host or path can set or shadow it.
WEB_COOKIE = "__Host-poppy_session"
#: Ties a join code to the browser that loaded the join page (§5).
JOIN_COOKIE = "__Host-poppy_join"
#: A join code lives at most this long (§5: no more than 60 seconds).
_JOIN_LIFETIME = timedelta(seconds=60)


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


def _check_aliases(domain: str, aliases: tuple[str, ...]) -> None:
    """Each alias a DNS name in small letters, another than `domain`, named once."""
    for alias in aliases:
        if alias != alias.lower().rstrip(".") or not alias or "/" in alias or ":" in alias:
            raise ValueError("an alias is a DNS domain name, in small letters")
    if domain in aliases or len(set(aliases)) != len(aliases):
        raise ValueError("each alias is another domain, named once")


def _check_positive(**lifetimes: timedelta) -> None:
    for name, lifetime in lifetimes.items():
        if lifetime <= timedelta(0):
            raise ValueError(f"{name} must be positive")


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
    #: Failed Mediated Sign-In attempts (credentials or codes) a key may make before it
    #: is locked out: an account identifier, an agent's user, a Session, an account's codes.
    max_sign_in_failures: int = 5
    #: How long the first lockout lasts; each failure past the limit doubles it (at most a
    #: day), and the count is forgotten once a key has failed nothing for this long.
    sign_in_lockout: timedelta = timedelta(minutes=15)
    #: What each scope allows, in words a user and a model understand, published as
    #: `auth.scopes` (§3.1, §4.4): every scope in `scopes` needs one.
    scope_descriptions: Mapping[str, str] = field(default_factory=dict)
    #: `auth.scope_hints` (§4.4): per scope, its most consequential operation's
    #: `changes` (none, reversible, irreversible) and whether it touches personal data.
    scope_hints: Mapping[str, tuple[str, bool]] = field(default_factory=dict)
    #: The tasks the company chose not to offer through the protocol, published at
    #: `/poppy/excluded-tasks.json` (§8.1): each a `task` and an optional `alternative`.
    excluded_tasks: tuple[Mapping[str, Any], ...] = ()
    #: Tasks a feedback report may name that can be done after all: the alternative
    #: (§8.2) the company answers with, HTTP 200, keyed by task, compared ignoring case.
    feedback_answers: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    web: bool = False
    #: A hosted Device Sign-In page (`verification_uri`); `&code=<user_code>` completes it.
    device_page: str | None = None
    #: A hosted consent page with `{request_id}`: `GET /oauth/authorize` answers 303 to it.
    consent_page: str | None = None
    #: Other domains that are this company (§3): each publishes its discovery document,
    #: naming itself as the organization's domain, and the issuer's metadata lists it in
    #: `protected_resources`. Everything else stays on `domain`, the issuer's: an alias is never
    #: a second identity, and answers nothing but its discovery document.
    aliases: tuple[str, ...] = ()
    #: The MCP server supports DPoP (§4.3; new MCP servers SHOULD): its protected resource
    #: metadata lists `dpop_signing_alg_values_supported`, and personal agents get DPoP
    #: tokens for it. Off, it is an MCP server that doesn't: they get Bearer tokens.
    mcp_dpop: bool = True
    #: Accept feedback reports at `/poppy/feedback` and list it in poppy.json (§8).
    feedback: bool = True
    #: Require DPoP proofs to carry a nonce the company issued (§4.3, RFC 9449 §8, §9).
    dpop_nonce: bool = False
    #: How long an issued DPoP nonce is accepted.
    dpop_nonce_lifetime: timedelta = timedelta(minutes=5)
    #: How long an ended Session's key is remembered and refused (§4.2: a Company SHOULD).
    ended_session_memory: timedelta = timedelta(days=30)
    #: How long an API write's `Idempotency-Key` is remembered in its Session, with the
    #: original response a repeated key gets again (guides, *Retries*: a set time, a day).
    idempotency_lifetime: timedelta = timedelta(days=1)

    def __post_init__(self) -> None:
        _check_aliases(self.domain, self.aliases)
        _check_positive(idempotency_lifetime=self.idempotency_lifetime)
        for name, value in (("device_page", self.device_page), ("consent_page", self.consent_page)):
            if value is None:
                continue
            parsed = urlsplit(value.replace("{request_id}", "x"))
            if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
                raise ValueError(f"{name} must be an HTTPS URL without a fragment")
        if self.consent_page is not None and "{request_id}" not in self.consent_page:
            raise ValueError("consent_page must contain {request_id}")
        if self.device_page is not None:
            host = (urlsplit(self.device_page).hostname or "").lower()
            if not any(host == d or host.endswith(f".{d}") for d in (self.domain, *self.aliases)):
                # A personal agent shows the link only on the issuer's host or the host of
                # one of its protected_resources, or a subdomain of either (§4.6).
                raise ValueError("device_page must be on the company's domain or a subdomain")
        if any(scope not in self.scopes for scope in self.write_scopes):
            raise ValueError("write_scopes must be among scopes")
        if any(scope.startswith("poppy:") for scope in self.scopes):
            raise ValueError("scope names starting with poppy: are reserved (§4.4)")
        if set(self.scope_descriptions) != set(self.scopes) or not all(
            self.scope_descriptions.values()
        ):
            # Every scope in scopes_supported is described (§4.4).
            raise ValueError("scope_descriptions must describe every scope, and only those")
        for name, (changes, _personal) in self.scope_hints.items():
            if name not in self.scopes or changes not in ("none", "reversible", "irreversible"):
                raise ValueError("scope_hints name a scope and its changes")
        if self.max_sign_in_failures < 1 or self.sign_in_lockout <= timedelta(0):
            raise ValueError("sign-in attempts need a positive limit and lockout")
        if self.operations and not self.write_scopes:
            # Confirming an operation needs a write scope: without one, any signed-in
            # Session, whatever it was granted, could confirm (Operations §3.3).
            raise ValueError("operations need write_scopes: the scopes confirming one requires")

    @property
    def base(self) -> str:
        return f"https://{self.domain}"

    def organization_domain(self, domain: str | None = None) -> str:
        """The domain a discovery document names: the company's own, or one of its aliases."""
        if domain is None or domain == self.domain:
            return self.domain
        if domain not in self.aliases:
            raise ValueError(f"{domain} is not one of this company's domains")
        return domain

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

    @property
    def excluded_tasks_url(self) -> str:
        return f"{self.base}/poppy/excluded-tasks.json"

    @property
    def feedback_endpoint(self) -> str:
        return f"{self.base}/poppy/feedback"


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


@dataclass(frozen=True)
class OpenWork:
    """What a company has under way: what its owner settles and ends before taking it down.

    `operations` are those still `proposed` or `in_progress` (a proposal past
    its expiry is not open); `sign_ins` are the agents and accounts, as
    `(client_id, account_id)`, with a sign-in not ended — each one ended
    whole by `CompanyService.disconnect`.
    """

    operations: tuple[Operation, ...] = ()
    sign_ins: tuple[tuple[str, str], ...] = ()

    @property
    def empty(self) -> bool:
        return not self.operations and not self.sign_ins


#: The states an operation is not final in (Operations §6).
_OPEN_STATES = frozenset({"proposed", "in_progress"})


class StaleConversationError(ValueError):
    """One of the company's people answered over events they had not read: read again."""

    def __init__(self, conversation_id: str, after: str) -> None:
        super().__init__(f"{conversation_id} has events after {after}: read it again")
        self.conversation_id = conversation_id
        self.after = after


class _RefusedError(Exception):
    def __init__(
        self,
        status: int,
        error: str,
        *,
        headers: Mapping[str, str] | None = None,
        **extra: object,
    ) -> None:
        super().__init__(error)
        self.status = status
        self.error = error
        self.headers = dict(headers or {})
        self.extra = extra


def _insufficient_scope(scopes: Sequence[str]) -> _RefusedError:
    """`insufficient_scope` (RFC 6750), naming the scopes the request needs (§4.4, §6).

    What a signed-out token gets for anything that needs the account: it has no
    scopes, so the error fits, and the agent signs in or uses an Account Token.
    """

    return _RefusedError(403, "insufficient_scope", scope=" ".join(scopes))


class _RateLimitedError(_RefusedError):
    """The host's rate limit refused the request: `429` and when to ask again."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(429, "rate_limited")
        self.retry_after = retry_after


_CHALLENGED = frozenset(
    {
        "invalid_token",
        "insufficient_scope",
        "invalid_dpop_proof",
        "use_dpop_nonce",
    }
)


def _json_error(
    status: int, error: str, headers: Mapping[str, str] | None = None, **extra: object
) -> CompanyResponse:
    """A JSON error; a token error at 401 or 403 also in `WWW-Authenticate` (§6).

    The token endpoint answers DPoP failures as OAuth errors with HTTP 400 and
    no challenge; APIs and conversation endpoints answer them with HTTP 401 and
    the `DPoP` challenge (§4.3). `use_dpop_nonce` carries `DPoP-Nonce` either way.
    """

    out = {"Cache-Control": "no-store", **(headers or {})}
    if error in _CHALLENGED and status in {401, 403}:
        out["WWW-Authenticate"] = _challenge("DPoP", error, extra)
    return CompanyResponse(status, {"error": error, **extra}, out)


def _challenge(scheme: str, error: str, extra: Mapping[str, object]) -> str:
    """One `WWW-Authenticate` challenge with the error's `scope` or `extension`."""

    challenge = f'{scheme} error="{error}"'
    for name in ("scope", "extension", "resource_metadata"):
        value = extra.get(name)
        if isinstance(value, str):
            challenge += f', {name}="{value}"'
    return challenge


_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def _query(request: CompanyRequest) -> dict[str, str]:
    return dict(parse_qsl(urlsplit(request.url).query, keep_blank_values=True))


def _wait(request: CompanyRequest) -> int | None:
    """The `wait` query parameter: a whole number of seconds, 0 or more (§7.5).

    Anything else is `invalid_request`; a larger value than the company holds
    a request for is held for its cap (`MAX_WAIT_SECONDS`), never refused.
    """

    value = _query(request).get("wait")
    if value is None:
        return None
    if not value.isascii() or not value.isdigit():
        raise _RefusedError(400, "invalid_request")
    return min(int(value), MAX_WAIT_SECONDS)


def _incoming(value: object) -> Message:
    """A message as the personal agent sent it; a `role` it set is ignored (§7.4)."""

    message = Message.model_validate(value)
    return message if message.role is None else message.model_copy(update={"role": None})


def _json_object(body: bytes) -> dict[str, Any]:
    """A request body that must be one JSON object: anything else is `invalid_request`."""

    value = loads_strict(body)
    if not isinstance(value, dict):
        raise _RefusedError(400, "invalid_request")
    return value


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _composite(*parts: str) -> str:
    """One store key for several values (never ambiguous)."""

    return _digest(json.dumps(parts))


def _with(items: tuple[str, ...], item: str | None) -> tuple[str, ...]:
    return items if item is None or item in items else (*items, item)


#: The device flow's progress: answered as errors by OAuth, never refusals (RFC 8628 §3.5).
_PROGRESS = frozenset({"authorization_pending", "slow_down"})

#: The route a request took, for telemetry: its path's first part, never an ID.
_NAMED_ROUTES = frozenset(
    {
        "oauth_token",
        "oauth_authorize",
        "oauth_device",
        "oauth_revoke",
        "poppy_browser_session",
        "poppy_sign_in",
        "poppy_conversations",
        "poppy_operations",
        "poppy_feedback",
    }
)
_ROUTES: dict[str, str] = {
    "operations": "operation_page",
    "api": "api",
    "mcp": "mcp",
    ".well-known": "discovery",
}


@dataclass
class _Exchange:
    """What a request came to, so far: for the telemetry reported when it ends."""

    started: float
    route: str
    client_id: str | None = None
    replayed: bool = False


_EXCHANGE: ContextVar[_Exchange | None] = ContextVar("pap_company_exchange", default=None)


def _route_of(path: str) -> str:
    parts = [part for part in path.split("/") if part]
    if not parts:
        return "unknown"
    if parts[0] in {"oauth", "poppy"} and len(parts) > 1:
        route = f"{parts[0]}_{parts[1].replace('-', '_')}"
        # Only the routes the company serves: a path never carries its own words out.
        return route if route in _NAMED_ROUTES else "unknown"
    return _ROUTES.get(parts[0], "unknown")


class _WatchedReplayCache:
    """The company's replay cache, noting on the request when it refused a replay."""

    def __init__(self, cache: ReplayCache) -> None:
        self.cache = cache

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        first = await self.cache.mark_once(key, expires_at=expires_at)
        exchange = _EXCHANGE.get()
        if not first and exchange is not None:
            exchange.replayed = True
        return first


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
        cache = cast(ReplayCache, first_contribution(self.reactor, REPLAY_CACHES, "replay cache"))
        return _WatchedReplayCache(cache)

    # Telemetry ---------------------------------------------------------------------

    def _report(
        self, name: str, outcome: Literal["ok", "error"], attributes: Mapping[str, object]
    ) -> None:
        """One `pap.telemetry` event of this request, when the host contributes a sink."""

        sink = telemetry_sink(self.reactor)
        if sink is None:
            return
        # Outside a request (the host signing an account out, say): no route, no agent.
        exchange = _EXCHANGE.get()
        emit(
            sink,
            name,
            outcome,
            (time.perf_counter() - exchange.started) * 1000 if exchange is not None else 0.0,
            {
                "pap.company.issuer": self.config.base,
                "pap.company.domain": self.config.domain,
                "pap.company.route": exchange.route if exchange is not None else None,
                "pap.client.id": exchange.client_id if exchange is not None else None,
                **attributes,
            },
        )

    def _report_refusal(self, response: CompanyResponse) -> None:
        """A request answered with an error: the protocol's code, never the body's text."""

        body = response.body if isinstance(response.body, dict) else {}
        error = body.get("error")
        code = error if isinstance(error, str) else "refused"
        if code in _PROGRESS or (response.status == 404 and code == "not_found"):
            return  # progress, or a path the company does not serve
        exchange = _EXCHANGE.get()
        self._report(
            "pap.company.refused",
            "error",
            {
                "pap.error": code,
                "pap.http.status": response.status,
                "pap.replayed": bool(exchange and exchange.replayed),
            },
        )

    def _report_session(self, session: IssuedSession, *, renewed: bool, for_mcp: bool) -> None:
        """A Session started or renewed; a token for the MCP server moves it there."""

        if for_mcp:
            self._report(
                "pap.company.interface.switch",
                "ok",
                {"pap.interface": "mcp", "pap.session.signed_in": session.signed_in},
            )
            return
        self._report(
            "pap.company.session.renew" if renewed else "pap.company.session.start",
            "ok",
            {"pap.session.signed_in": session.signed_in, "pap.scopes.granted": len(session.scopes)},
        )

    # Routing -----------------------------------------------------------------------

    async def handle(self, request: CompanyRequest) -> CompanyResponse:
        """Answer one request; what it came to is reported to `pap.telemetry`."""

        path = urlsplit(request.url).path
        token = _EXCHANGE.set(_Exchange(started=time.perf_counter(), route=_route_of(path)))
        try:
            response = await self._dispatch(request)
            if response.status >= 400:
                self._report_refusal(response)
            return response
        finally:
            _EXCHANGE.reset(token)

    async def _dispatch(self, request: CompanyRequest) -> CompanyResponse:  # noqa: C901 - the route table
        path = urlsplit(request.url).path
        method = request.method.upper()
        if any(
            name == "access_token"
            for name, _ in parse_qsl(urlsplit(request.url).query, keep_blank_values=True)
        ):
            # A token in a URL is logged, cached, and leaked in Referer: never accepted,
            # even beside a header that would be (§4.3, RFC 6750 §2.3).
            if path == "/mcp" and self._mcp() is not None:
                return self._mcp_refusal(400, "invalid_request")
            return _json_error(400, "invalid_request")
        try:
            host = request.headers.get("host", "").split(":", 1)[0].lower()
            if host in self.config.aliases:
                # An alias publishes the company's discovery document, and nothing else (§3).
                if method == "GET" and path == "/.well-known/poppy.json":
                    return CompanyResponse(200, self.discovery_document(host))
                return _json_error(404, "not_found")
            if method == "GET" and path == "/.well-known/poppy.json":
                return CompanyResponse(200, self.discovery_document())
            if method == "GET" and path == "/.well-known/oauth-authorization-server":
                return CompanyResponse(200, self.oauth_metadata())
            if path == "/.well-known/oauth-protected-resource/mcp" and self._mcp() is not None:
                return CompanyResponse(200, self.protected_resource_metadata())
            if path == "/mcp" and self._mcp() is not None:
                return await self._mcp_route(request)
            if method == "GET" and path == "/poppy/browser-session" and self.config.web:
                return await self._join_page()
            if method == "POST" and path == "/poppy/browser-session" and self.config.web:
                return await self._browser_session(request)
            if method == "GET" and path == "/poppy/excluded-tasks.json" and self.config.excluded_tasks:
                return CompanyResponse(200, {"tasks": [dict(task) for task in self.config.excluded_tasks]})
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
            if method == "POST" and path == "/poppy/feedback" and self.config.feedback:
                return await self._feedback(request)
        except _RateLimitedError as limited:
            return self._rate_limited(limited.retry_after)
        except _RefusedError as refused:
            return _json_error(refused.status, refused.error, refused.headers, **refused.extra)
        except (SessionError, ProofError) as error:
            status = error.status_code or (401 if error.code == "invalid_client" else 400)
            return _json_error(status, error.code)
        except (ProtocolValidationError, ValidationError):
            # A body that is not JSON, or not the shape the protocol defines: the
            # caller's mistake, never the company's (no 500).
            return _json_error(400, "invalid_request")
        return _json_error(404, "not_found")

    # Discovery ---------------------------------------------------------------------

    def discovery_document(
        self, domain: str | None = None
    ) -> dict[str, Any]:
        """The discovery document published at `domain`: the company's own, or one of its
        aliases, which it names as the organization's domain; its endpoints stay on `base`.

        Every domain's document has the same `auth`, which describes the issuer (§3.2).
        """
        config = self.config
        organization = config.organization_domain(domain)
        # Direct and Device Sign-In are the issuer's grants, not listed here (§3.2, §4.4).
        auth: dict[str, Any] = {"issuer": config.base}
        if config.mediated_fields:
            auth["mediated"] = {
                "endpoint": config.mediated_endpoint,
                "fields": [
                    {"name": name, "label": label, "secret": secret}
                    for name, label, secret in config.mediated_fields
                ],
                "scopes": list(config.scopes),
            }
        auth["scopes"] = {scope: config.scope_descriptions[scope] for scope in config.scopes}
        if config.scope_hints:
            auth["scope_hints"] = {
                scope: {"changes": changes, "personal_data": personal}
                for scope, (changes, personal) in config.scope_hints.items()
            }
        document: dict[str, Any] = {
            "protocol_version": PROTOCOL_PROFILE,
            "organization": {"name": config.name, "domain": organization},
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
        if config.feedback:
            document["feedback"] = {"endpoint": config.feedback_endpoint}
        if config.excluded_tasks:
            document["excluded_tasks"] = {"url": config.excluded_tasks_url}
        if config.operations:
            document["extensions"] = {
                "operations": {
                    "version": OPERATIONS_VERSION,
                    "endpoint": config.operations_endpoint,
                }
            }
        return document

    def protected_resource_metadata(self) -> dict[str, Any]:
        """RFC 9728 metadata for the MCP server: its issuer is the company's (§6)."""

        metadata: dict[str, Any] = {
            "resource": self.config.mcp_url,
            "authorization_servers": [self.config.base],
            "scopes_supported": list(self.config.scopes),
            "bearer_methods_supported": ["header"],
        }
        if self.config.mcp_dpop:
            # It supports DPoP (RFC 9728 §2), ES256 among its algorithms (§4.3).
            metadata["dpop_signing_alg_values_supported"] = list(DPOP_ALGORITHMS)
        return metadata

    def oauth_metadata(self) -> dict[str, Any]:
        config = self.config
        grants = [JWT_BEARER_GRANT, REFRESH_TOKEN_GRANT]
        metadata: dict[str, Any] = {
            "issuer": config.base,
            "token_endpoint": config.token_endpoint,
            "revocation_endpoint": config.revocation_endpoint,
            "grant_types_supported": grants,
            "scopes_supported": list(config.scopes),
            # `https://{domain}` for each domain whose poppy.json names the issuer, then
            # the MCP server: exact strings (§3.2, RFC 9728 §4).
            "protected_resources": [
                f"https://{domain}" for domain in (config.domain, *config.aliases)
            ],
            "dpop_signing_alg_values_supported": list(DPOP_ALGORITHMS),
        }
        if self._mcp() is not None:
            metadata["protected_resources"].append(config.mcp_url)
            if not config.mcp_dpop:
                # Bearer tokens for it come from Token Exchange alone (§4.3).
                grants.append(TOKEN_EXCHANGE_GRANT)
        if config.direct:
            grants.append(AUTHORIZATION_CODE_GRANT)
            metadata["authorization_endpoint"] = config.authorization_endpoint
            metadata["code_challenge_methods_supported"] = ["S256"]
        if config.device:
            grants.append(DEVICE_CODE_GRANT)
            metadata["device_authorization_endpoint"] = config.device_endpoint
        return metadata

    # OAuth -------------------------------------------------------------------------

    async def _client(self, form: Mapping[str, str]) -> str:
        """Verify the client assertion, the agent's keys, and the company's policy.

        The assertion's `aud` is the issuer, exactly, whichever endpoint it is
        sent to (§4.1); its `jti` is refused again until it expires.
        """

        client_id = form.get("client_id", "")
        if form.get("client_assertion_type") != JWT_CLIENT_ASSERTION or not client_id:
            raise _RefusedError(401, "invalid_client")
        if not await self._allowed(client_id):
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
            audience=self.config.base,
            subject=client_id,
            replay_cache=self._replay(),
            now=self._now(),
        )
        extensions = tuple(sorted(metadata.extensions))
        exchange = _EXCHANGE.get()
        if exchange is not None:
            exchange.client_id = client_id
        known = await self._read(CLIENT, client_id, KnownClient.from_json)
        if known is None or known.extensions != extensions:
            await self.store.put(CLIENT, client_id, KnownClient(extensions).to_json())
            # Its identity verified for the first time, or with new metadata.
            self._report("pap.company.identity.check", "ok", {})
        return client_id

    async def _allowed(self, client_id: str) -> bool:
        """The company's policy on this agent, asked before anything is fetched for it.

        A blocked `client_id` is never resolved (no metadata or keys fetched from
        its domain), and a blocked agent's tokens stop working at once.
        """

        policy = cast(ClientPolicy, first_contribution(self.reactor, CLIENT_POLICIES, "policy"))
        return bool(await policy.allows(client_id))

    async def _supports_operations(self, client_id: str) -> bool:
        """Whether the agent declared the Operations extension when it last authenticated."""

        known = await self._read(CLIENT, client_id, KnownClient.from_json)
        return known is not None and "operations" in known.extensions

    async def _dpop(self, request: CompanyRequest, access_token: str | None = None) -> str:
        """Validate the request's DPoP proof as RFC 9449 §4.3 says; its key's thumbprint.

        One `DPoP` header holding one well-formed JWT, `typ` `dpop+jwt`, an
        accepted asymmetric `alg`, a public `jwk` only, the signature, `htm`
        and `htu`, `iat` within the window, a nonce the company issued when it
        requires them, and with a Session Token, `ath`. A replayed `jti` is
        refused everywhere: at the token endpoint it must be (§4.3). At the
        token endpoint a failure is an OAuth error, HTTP 400; elsewhere it is
        HTTP 401 with the `DPoP` challenge.
        """

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
        if self.config.dpop_nonce and not await self._nonce_issued(verified.nonce):
            raise _RefusedError(
                status, "use_dpop_nonce", headers={"DPoP-Nonce": await self._issue_nonce()}
            )
        return verified.key_thumbprint

    async def _issue_nonce(self) -> str:
        nonce = self._id("nonce")
        await self.store.put(
            DPOP_NONCE,
            nonce,
            IssuedNonce().to_json(),
            expires_at=self._now() + self.config.dpop_nonce_lifetime,
        )
        return nonce

    async def _nonce_issued(self, nonce: str | None) -> bool:
        return nonce is not None and await self.store.get(DPOP_NONCE, nonce) is not None

    async def _token(self, request: CompanyRequest) -> CompanyResponse:
        """The token endpoint: every grant carries a proof, whose key names the Session (§4.3).

        The JWT bearer grant starts a Session with a new key or renews the one a known
        key names; the refresh grant signs in the key's Session, or starts one signed in
        with a new key; the code and device grants sign in the Session their code is
        bound to; Token Exchange turns a DPoP Session Token into a Bearer one for an MCP
        server without DPoP, and nothing else issues a Bearer token.
        """

        form = dict(parse_qsl(request.body.decode()))
        grant = form.get("grant_type")
        client_id = await self._client(form)
        thumbprint = await self._dpop(request)
        if grant == TOKEN_EXCHANGE_GRANT and self._bearer_mcp_resource(form):
            return await self._exchange_grant(form, client_id, thumbprint)
        if grant == TOKEN_EXCHANGE_GRANT or self._bearer_mcp_resource(form):
            # Token Exchange only for an MCP server without DPoP, and such a server's
            # tokens only by Token Exchange (§4.3).
            raise _RefusedError(400, "invalid_target")
        if grant == JWT_BEARER_GRANT:
            return await self._session_grant(form, client_id, thumbprint)
        if grant == REFRESH_TOKEN_GRANT:
            return await self._refresh_grant(form, client_id, thumbprint)
        if grant == AUTHORIZATION_CODE_GRANT and self.config.direct:
            return await self._code_grant(form, client_id, thumbprint)
        if grant == DEVICE_CODE_GRANT and self.config.device:
            return await self._device_grant(form, client_id, thumbprint)
        raise _RefusedError(400, "unsupported_grant_type")

    def _bearer_mcp_resource(self, form: Mapping[str, str]) -> bool:
        """Whether `resource` names the MCP server that doesn't support DPoP (§4.3)."""

        return (
            self._mcp() is not None
            and not self.config.mcp_dpop
            and form.get("resource") == self.config.mcp_url
        )

    def _resource(self, form: Mapping[str, str]) -> str | None:
        """The `resource` a token is issued for (RFC 8707): one this company serves."""

        resource = form.get("resource")
        if resource is not None and resource not in {self.config.mcp_url, self.config.base}:
            raise _RefusedError(400, "invalid_target")
        return resource

    def _account_scopes(self) -> tuple[str, ...]:
        """The scopes that read the account: the company's scopes that change nothing."""

        read = tuple(scope for scope in self.config.scopes if scope not in self.config.write_scopes)
        return read or self.config.scopes

    def _kind(self, session: IssuedSession) -> str:
        """Which of a Session's tokens this is: its own, or its token for the MCP server.

        A Session has one of each at a time (§4.3); a new one replaces only its kind.
        """

        if session.resource is not None and session.resource == self.config.mcp_url:
            return "mcp"
        return "own"

    async def _session_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        """Start a Session with a new key, or renew the signed-out one a known key names (§4.2)."""

        resolver = cast(
            ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client")
        )
        _, keys = await resolver.resolve(client_id, kid=_key_id(form.get("assertion", "")))
        claims = await verify_assertion(
            form.get("assertion", ""),
            keys=keys,
            issuer=client_id,
            audience=self.config.base,
            replay_cache=self._replay(),
            now=self._now(),
            error="invalid_grant",
        )
        pairwise = str(claims["sub"])
        agent_id = claims.get("agent_id")
        if agent_id is not None and (
            not isinstance(agent_id, str) or not _OPAQUE_ID.fullmatch(agent_id)
        ):
            raise _RefusedError(400, "invalid_grant")
        resource = self._resource(form)
        known = await self._session_by_key(thumbprint)
        if known is None:
            session = IssuedSession(
                session_key=thumbprint,
                client_id=client_id,
                pairwise_user_id=pairwise,
                key_thumbprint=thumbprint,
                expires_at=self._now() + self.config.session_lifetime,
                resource=resource,
                agent_id=agent_id,
            )
            response = await self._issue(session)
            self._report_session(session, renewed=False, for_mcp=resource is not None)
            return response
        if (known.client_id, known.pairwise_user_id) != (client_id, pairwise):
            # The key names another agent's or user's Session (§4.2).
            raise _RefusedError(400, "invalid_grant")
        if known.agent_id != agent_id:
            # A Session keeps the Agent ID it started with, or none (§4.2).
            raise _RefusedError(400, "invalid_grant")
        # Renewal with the assertion gives a signed-out token; a signed-in Session is
        # renewed with its Account Token instead (§4.2, §4.8).
        session = replace(
            known,
            expires_at=self._now() + self.config.session_lifetime,
            token_type="DPoP",
            resource=resource,
            account_id=None,
            scopes=(),
            account_token=None,
        )
        response = await self._issue(session, replacing={self._kind(session)})
        self._report_session(session, renewed=True, for_mcp=resource is not None)
        return response

    async def _refresh_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        """Sign in the key's Session with an Account Token, or start one signed in (§4.8)."""

        resource = self._resource(form)
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
        if await self._sign_in_ended(grant):
            raise _RefusedError(400, "invalid_grant")
        session = await self._session_by_key(thumbprint)
        if session is None:
            # A new key: a new Session, already signed in, with no Agent ID (§4.2, §4.8).
            session = IssuedSession(
                session_key=thumbprint,
                client_id=client_id,
                pairwise_user_id=grant.pairwise_user_id,
                key_thumbprint=thumbprint,
                expires_at=now + self.config.session_lifetime,
            )
        elif (session.client_id, session.pairwise_user_id) != (
            client_id,
            grant.pairwise_user_id,
        ):
            raise _RefusedError(400, "invalid_grant")
        else:
            await self._check_account(session.session_key, grant.account_id)
        requested = tuple(scope for scope in form.get("scope", "").split(" ") if scope)
        if requested and any(scope not in grant.scopes for scope in requested):
            raise _RefusedError(400, "invalid_scope")
        if not self._offers(requested or grant.scopes):
            # A scope the company no longer offers (a rollback, a narrower version): asked
            # within what it offers now, the same Account Token still serves.
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
        if not await self._join_family(grant.family, _digest(rotated), session.session_key):
            # The sign-in was revoked meanwhile: its new token is too.
            await self._revoke_grants((_digest(rotated),))
            raise _RefusedError(400, "invalid_grant")
        signed_in = replace(
            session,
            account_id=grant.account_id,
            scopes=requested or grant.scopes,
            account_token=_digest(rotated),
            expires_at=now + self.config.session_lifetime,
            resource=resource,
            token_type="DPoP",
        )
        response = await self._issue(
            signed_in,
            refresh_token=rotated,
            replacing={self._kind(signed_in)},
            # A refresh naming no scope gets them in the response: the agent can't know.
            requested=requested,
            account_token_expires_at=grant.expires_at,
        )
        family = await self._read(ACCOUNT_FAMILY, grant.family, AccountFamily.from_json)
        if family is None or family.revoked:
            # Revoked while this token was issued: the Session continues signed out (§4.9).
            await self._sign_out_session(session.session_key, {_digest(rotated)})
            raise _RefusedError(400, "invalid_grant")
        self._report_session(signed_in, renewed=True, for_mcp=resource is not None)
        return response

    async def _exchange_grant(
        self, form: Mapping[str, str], client_id: str, thumbprint: str
    ) -> CompanyResponse:
        """A Bearer Session Token for the MCP server without DPoP, by Token Exchange (§4.3).

        The subject token is a current DPoP Session Token of the same agent, bound to
        the proof's key; the answer belongs to the same Session, with its scopes or the
        fewer `scope` asks for, and works only at that server.
        """

        if form.get("subject_token_type") != ACCESS_TOKEN_TYPE:
            raise _RefusedError(400, "invalid_request")
        subject = await self._token_session(form.get("subject_token", ""))
        if (
            subject is None
            or subject.token_type != "DPoP"
            or subject.client_id != client_id
            or subject.key_thumbprint != thumbprint
            or subject.expires_at <= self._now()
            or self._kind(subject) != "own"
        ):
            raise _RefusedError(400, "invalid_grant")
        requested = tuple(scope for scope in form.get("scope", "").split(" ") if scope)
        if any(scope not in subject.scopes for scope in requested):
            raise _RefusedError(400, "invalid_scope")
        bearer = replace(
            subject,
            token_type="Bearer",
            key_thumbprint="",
            resource=self.config.mcp_url,
            scopes=requested or subject.scopes,
            expires_at=min(subject.expires_at, self._now() + self.config.session_lifetime),
        )
        response = await self._issue(
            bearer, replacing={self._kind(bearer)}, requested=requested, exchanged=True
        )
        self._report_session(bearer, renewed=False, for_mcp=True)
        return response

    async def _device(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        client_id = await self._client(form)
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
            if pending.session_key not in (None, thumbprint):
                # Bound to the key of its first poll: any other key is refused (§4.6).
                raise _RefusedError(400, "invalid_grant")
            if pending.session_key is None:
                pending = replace(pending, session_key=thumbprint)
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
        # Approved: the Session the bound key names is signed in (§4.6).
        session = await self._session_by_key(thumbprint)
        if session is None or session.client_id != client_id:
            raise _RefusedError(400, "invalid_grant")
        # Consumed once: of concurrent polls, only the one that takes it signs in.
        taken = await self.store.take(DEVICE, key)
        approved = None if taken is None else PendingDevice.from_json(taken)
        if approved is None or approved.account_id is None:
            raise _RefusedError(400, "invalid_grant")
        await self.store.delete(USER_CODE, approved.user_code)
        return await self._sign_in(
            session, approved.account_id, approved.granted, thumbprint, requested=approved.scopes
        )

    async def _forget_device(self, key: str, pending: PendingDevice) -> None:
        await self.store.delete(DEVICE, key)
        await self.store.delete(USER_CODE, pending.user_code)

    async def _revoke(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        client_id = await self._client(form)
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
            if not changed[0].revoked:
                # A whole sign-in ended: by its agent, a password reset, or its host.
                self._report("pap.company.sign_out", "ok", {"pap.session.signed_in": False})
            revoked += await self._revoke_grants(family.tokens)
            for session_key in family.sessions:
                await self._sign_out_session(session_key, set(family.tokens))
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

    async def _sign_out_session(self, session_key: str, account_tokens: Collection[str]) -> None:
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

        await self._change(SESSION, session_key, StoredSession.from_json, sign_out)

    async def _join_family(self, family_id: str, token: str | None, session_key: str) -> bool:
        """Add a token and a Session to a sign-in; `False` once it is revoked."""

        changed = await self._change(
            ACCOUNT_FAMILY,
            family_id,
            AccountFamily.from_json,
            lambda family: (
                family
                if family.revoked
                else replace(
                    family,
                    tokens=_with(family.tokens, token),
                    sessions=_with(family.sessions, session_key),
                )
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
        thumbprint: str,
        *,
        requested: tuple[str, ...],
    ) -> CompanyResponse:
        """Sign the Session in: `session` is its DPoP record, `thumbprint` the proven key.

        `scopes` are the ones the user approved of those `requested`; the response
        leaves `scope` out when they are the same (§4.4, RFC 6749 §5.1).
        """

        if not scopes:
            # A sign-in grants at least one scope: approving none is a decline (§4.4).
            raise _RefusedError(400, "access_denied")
        # Checked before anything is issued: a mismatch issues no tokens (§4.4).
        await self._check_account(session.session_key, account_id)
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
                signed_in_at=self._now(),
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
                sessions=(session.session_key,),
            ).to_json(),
            expires_at=expires_at,
        )
        await self._remember_family(session.client_id, account_id, family)
        # The signed-in token is the Session's own: DPoP, bound to the key that proved
        # possession, for no single resource. It replaces only that token; a token for the
        # MCP server is renewed with the Account Token (§4.3, §4.8).
        signed_in = IssuedSession(
            session_key=session.session_key,
            client_id=session.client_id,
            pairwise_user_id=session.pairwise_user_id,
            key_thumbprint=thumbprint,
            expires_at=session.expires_at,
            account_id=account_id,
            scopes=scopes,
            account_token=family,
            token_type=DPOP,
            resource=None,
            agent_id=session.agent_id,
        )
        return await self._issue(
            signed_in,
            refresh_token=account_token,
            replacing={self._kind(signed_in)},
            requested=requested,
            account_token_expires_at=expires_at,
        )

    async def _check_account(self, session_key: str, account_id: str) -> None:
        """A Session that was ever signed in to another account is `account_mismatch` (§4.4).

        Even signed out since (§4.9): the code exchange, the device poll,
        Mediated Sign-In, and an Account Token all refuse, and issue nothing.
        """

        stored = await self._read(SESSION, session_key, StoredSession.from_json)
        if stored is not None and stored.account_id not in (None, account_id):
            raise _RefusedError(400, "account_mismatch")

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
        replacing: Collection[str] = (),
        requested: tuple[str, ...] = (),
        account_token_expires_at: datetime | None = None,
        exchanged: bool = False,
    ) -> CompanyResponse:
        """Issue a token for the Session; it replaces the Session's tokens of `replacing` kinds.

        The response names no Session: its key does (§4.3). `scope` follows RFC 6749:
        left out of a signed-out token's response, and of a signed-in one granting
        exactly the scopes `requested` (§4.2, §4.4).
        """

        access_token = self._id("sat")
        digest = _digest(access_token)
        await self._record_token(session, digest, replacing)
        await self.store.put(
            SESSION_TOKEN,
            digest,
            SessionPointer(session.session_key).to_json(),
            expires_at=session.expires_at,
        )
        body: dict[str, object] = {
            "access_token": access_token,
            "token_type": session.token_type,
            "expires_in": int((session.expires_at - self._now()).total_seconds()),
        }
        if session.scopes and set(session.scopes) != set(requested):
            body["scope"] = " ".join(session.scopes)
        if exchanged:
            body["issued_token_type"] = ACCESS_TOKEN_TYPE
        if refresh_token is not None:
            body["refresh_token"] = refresh_token
            if account_token_expires_at is not None:
                # So the agent tells an expired Account Token from a revoked one (guides).
                body["refresh_token_expires_in"] = int(
                    (account_token_expires_at - self._now()).total_seconds()
                )
        return CompanyResponse(200, body, {"Cache-Control": "no-store"})

    async def _record_token(
        self, session: IssuedSession, digest: str, replacing: Collection[str]
    ) -> None:
        """One write: the new token joins the Session, the ones it replaces leave it.

        `replacing` names token kinds (`_kind`): the Session's own token, or its
        token for one resource. A signed-in token records the account the
        Session is tied to from then on, signed out or not (§4.4).
        """

        for _ in range(_CAS_ATTEMPTS):
            entry = await self.store.get(SESSION, session.session_key)
            if entry is None:
                stored = StoredSession(
                    session_key=session.session_key,
                    client_id=session.client_id,
                    pairwise_user_id=session.pairwise_user_id,
                    tokens={digest: session},
                    latest=digest,
                    account_id=session.account_id,
                )
                stored = replace(stored, ends_at=self._session_end(stored))
                if await self.store.create(
                    SESSION,
                    session.session_key,
                    stored.to_json(),
                    expires_at=self._session_expiry(stored),
                ):
                    return
                continue
            current = StoredSession.from_json(entry.value)
            if session.account_id is not None and current.account_id not in (
                None,
                session.account_id,
            ):
                raise _RefusedError(400, "account_mismatch")
            tokens = {
                key: token
                for key, token in current.tokens.items()
                if self._kind(token) not in replacing
            }
            stored = replace(
                current,
                tokens={**tokens, digest: session},
                latest=digest,
                account_id=current.account_id or session.account_id,
            )
            stored = replace(stored, ends_at=self._session_end(stored))
            if await self.store.replace(
                SESSION,
                session.session_key,
                entry.version,
                stored.to_json(),
                expires_at=self._session_expiry(stored),
            ):
                return
        raise _RefusedError(503, "temporarily_unavailable")

    def _session_end(self, stored: StoredSession) -> datetime:
        """A Session ends once no Account Token could renew it any more."""

        latest = max(token.expires_at for token in stored.tokens.values())
        return latest + self.config.account_token_lifetime

    def _session_expiry(self, stored: StoredSession) -> datetime:
        """How long the record is kept: past its end, so its key is refused, not reused (§4.2)."""

        return (stored.ends_at or self._session_end(stored)) + self.config.ended_session_memory

    async def _session_by_key(self, session_key: str) -> IssuedSession | None:
        """The Session a key's thumbprint names, or `None` for a key never seen (§4.3).

        A key whose Session has ended is refused, `invalid_grant`, rather than starting
        a new Session the agent would not know of (§4.2).
        """

        stored = await self._read(SESSION, session_key, StoredSession.from_json)
        if stored is not None and stored.ends_at is not None and stored.ends_at <= self._now():
            raise _RefusedError(400, "invalid_grant")
        return await self._session_record(session_key)

    async def _session_record(self, session_key: str) -> IssuedSession | None:
        """The Session by its key: its own latest token's record, else its token for MCP.

        A token for the MCP server stands for the Session only there (§4.3): a
        grant naming the Session builds on the record of its own token, and on
        the MCP one only when the Session was started for the MCP server alone.
        Every grant replaces what a record says of the token (its key, type,
        resource, account, and lifetime); only the Session's identity is read.
        """

        stored = await self._read(SESSION, session_key, StoredSession.from_json)
        if stored is None:
            return None
        latest = stored.tokens.get(stored.latest)
        if latest is not None and self._kind(latest) == "own":
            return latest
        own = [token for token in stored.tokens.values() if self._kind(token) == "own"]
        if own:
            return max(own, key=lambda token: token.expires_at)
        if not stored.tokens:
            return None
        base = max(stored.tokens.values(), key=lambda token: token.expires_at)
        return replace(base, account_id=None, scopes=(), account_token=None, resource=None)

    async def _token_session(self, token: str) -> IssuedSession | None:
        """The state of the Session token `token`, while the Session still holds it."""

        digest = _digest(token)
        pointer = await self._read(SESSION_TOKEN, digest, SessionPointer.from_json)
        if pointer is None:
            return None
        stored = await self._read(SESSION, pointer.session_key, StoredSession.from_json)
        session = None if stored is None else stored.tokens.get(digest)
        if session is not None and await self._signed_in_before_its_end(session):
            return None
        return session

    async def _signed_in_before_its_end(self, session: IssuedSession) -> bool:
        """Whether this signed-in token's sign-in ended since (`AccountSignOuts`); ends it if so."""

        if session.account_id is None or session.account_token is None:
            return False
        grant = await self._read(ACCOUNT_TOKEN, session.account_token, AccountGrant.from_json)
        if grant is None:
            # Its Account Token is gone (expired, deleted): nothing to hold it to.
            return await self._signed_out_before(session.account_id) is not None
        return await self._sign_in_ended(grant)

    async def _signed_out_before(self, account_id: str) -> datetime | None:
        accounts = optional_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        if not isinstance(accounts, AccountSignOuts):
            return None
        return await accounts.signed_out_before(account_id)

    async def _sign_in_ended(self, grant: AccountGrant) -> bool:
        """Whether the account's sign-ins ended after this one: then it ends, whole.

        A password reset, an account locked: its Account Tokens are revoked and
        the Sessions signed in with them continue signed out (`_sign_out`).
        """

        before = await self._signed_out_before(grant.account_id)
        if before is None or (grant.signed_in_at is not None and grant.signed_in_at >= before):
            return False
        await self._sign_out((grant.family,))
        return True

    # Direct Sign-In (§4.5) -------------------------------------------------------------

    async def _authorize(self, request: CompanyRequest) -> CompanyResponse:
        """The company's own sign-in and consent page for a personal agent's request."""

        query = dict(parse_qsl(urlsplit(request.url).query))
        client_id = query.get("client_id", "")
        redirect_uri = query.get("redirect_uri", "")
        if not client_id or not await self._allowed(client_id):
            return self._page(400, "This sign-in request is not valid.")
        resolver = cast(
            ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client")
        )
        try:
            metadata, _ = await resolver.resolve(client_id)
        except (PersonalAgentProtocolError, ValueError):
            return self._page(400, "This agent could not be verified.")
        # An unknown client or redirect is never redirected to: that would be an open redirector.
        # Exactly, but a loopback redirect URI matches with any port (§4.5, RFC 8252 §7.3).
        if not any(redirect_uri_matches(entry, redirect_uri) for entry in metadata.redirect_uris):
            return self._page(400, "This sign-in request is not valid.")
        state = query.get("state", "")
        scopes = tuple(scope for scope in query.get("scope", "").split(" ") if scope)
        if query.get("response_type") != "code":
            return self._redirect(redirect_uri, error="unsupported_response_type", state=state)
        if query.get("code_challenge_method") != "S256" or not query.get("code_challenge"):
            return self._redirect(redirect_uri, error="invalid_request", state=state)
        if not _THUMBPRINT.fullmatch(query.get("dpop_jkt", "")):
            # The code is bound to the Session Key: without one it could sign in no Session
            # (§4.5, RFC 9449 §10).
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
                dpop_jkt=query["dpop_jkt"],
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
            f"<li>{html.escape(self.config.scope_descriptions.get(scope, scope))}</li>"
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
                {"scope": scope, "description": self.config.scope_descriptions.get(scope, scope)}
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
                dpop_jkt=pending.dpop_jkt,
                requested=pending.scopes,
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
            or issued.dpop_jkt != thumbprint
        ):
            # Expired, reused, or redeemed with another key than the one it is bound to.
            raise _RefusedError(400, "invalid_grant")
        verifier = form.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(
            b"="
        )
        if not hmac.compare_digest(challenge.decode(), issued.code_challenge):
            raise _RefusedError(400, "invalid_grant")
        session = await self._session_by_key(thumbprint)
        if session is None or session.client_id != client_id:
            raise _RefusedError(400, "invalid_grant")
        return await self._sign_in(
            session, issued.account_id, issued.scopes, thumbprint, requested=issued.requested
        )

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
        key = request.headers.get("idempotency-key")
        if key is None or method not in WRITE_METHODS:
            return await self._api_answer(request, method, path, session, body)
        # A write with an Idempotency-Key (guides, *Retries*): remembered per Session for
        # `idempotency_lifetime`, a repeat answered with the original response.
        if not IDEMPOTENCY_KEY.fullmatch(key):
            raise _RefusedError(400, "invalid_request")
        record = _composite(session.session_key, key)
        request_digest = _composite(
            method,
            path,
            urlsplit(request.url).query,
            json.dumps(body, sort_keys=True, separators=(",", ":")),
        )
        earlier = await self._hold_idempotency_key(record, request_digest)
        if earlier is not None:
            return earlier
        try:
            response = await self._api_answer(request, method, path, session, body)
        except BaseException:
            await self.store.delete(IDEMPOTENCY, record)
            raise
        if 200 <= response.status < 300:
            answered = IdempotencyRecord(request_digest, response.status, response.body)
            await self.store.put(
                IDEMPOTENCY,
                record,
                answered.to_json(),
                expires_at=self._now() + self.config.idempotency_lifetime,
            )
        else:
            # A refusal is not remembered: the retry, once signed in or granted, is new.
            await self.store.delete(IDEMPOTENCY, record)
        return response

    async def _hold_idempotency_key(self, record: str, digest: str) -> CompanyResponse | None:
        """Hold the key for this request: `None` when held, else the answer to a repeat.

        A repeat with another request is `409 idempotency_key_conflict`; a repeat while
        the first is under way waits (`503`, `Retry-After`).
        """

        held = IdempotencyRecord(digest)
        for _ in range(_CAS_ATTEMPTS):
            if await self.store.create(
                IDEMPOTENCY, record, held.to_json(), expires_at=self._now() + _IDEMPOTENCY_HELD
            ):
                return None
            known = await self._read(IDEMPOTENCY, record, IdempotencyRecord.from_json)
            if known is None:
                continue
            if known.digest != digest:
                raise _RefusedError(409, "idempotency_key_conflict")
            if known.status is None:
                raise _RefusedError(503, "temporarily_unavailable", headers={"Retry-After": "1"})
            return CompanyResponse(known.status, known.body)
        raise _RefusedError(503, "temporarily_unavailable")

    async def _api_answer(
        self,
        request: CompanyRequest,
        method: str,
        path: str,
        session: IssuedSession,
        body: Any,
    ) -> CompanyResponse:
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
            raise _insufficient_scope(self.config.write_scopes)
        if not await self._supports_operations(session.client_id):
            # At an API, in the WWW-Authenticate challenge with its `extension` (§3.3, §6).
            raise _RefusedError(
                403,
                "extension_required",
                headers={
                    "WWW-Authenticate": 'DPoP error="extension_required", extension="operations"'
                },
                extension="operations",
            )
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
        for_mcp = session is not None and self._kind(session) == "mcp"
        if session is None or self._now() >= session.expires_at or bearer or for_mcp:
            # A token for the MCP server, Bearer or DPoP, works only there (§4.3).
            raise _RefusedError(401, "invalid_token")
        if not self._offers(session.scopes):
            # The company no longer offers a scope this Session holds (a rollback, a narrower
            # version): the Session ends here, and a new one is the way back.
            raise _RefusedError(401, "invalid_token")
        if not await self._allowed(session.client_id):
            raise _RefusedError(401, "invalid_token")
        thumbprint = await self._dpop(request, access_token=token)
        if thumbprint != session.key_thumbprint:
            raise _RefusedError(401, "invalid_dpop_proof")
        wait = await self._admitted(session)
        if wait is not None:
            raise _RateLimitedError(wait)
        return key, session

    async def _admitted(self, session: IssuedSession) -> int | None:
        """The host's rate limit on this agent and its signed-in account: seconds to wait, or
        None."""

        limit = optional_contribution(self.reactor, COMPANY_RATE_LIMITS, "rate limit")
        if limit is None:
            return None
        wait = await cast(RateLimit, limit).admit(session.client_id, session.account_id)
        return None if wait is None else max(1, int(wait))

    # Mediated Sign-In attempt limits (§4.7: a company MUST rate-limit attempts) ---------

    def _attempt_keys(
        self, session: IssuedSession, credentials: Mapping[str, object]
    ) -> tuple[str, ...]:
        """What a credential attempt counts against: the account, the agent's user, the Session.

        The account is named by the declared fields that are not secret (an
        email, a username), normalized; its password is never part of a key.
        """

        keys = [
            _composite("user", session.client_id, session.pairwise_user_id),
            _composite("session", session.session_key),
        ]
        named = [
            str(credentials.get(name, "")).strip().casefold()
            for name, _, secret in self.config.mediated_fields
            if not secret
        ]
        if any(named):
            keys.insert(0, _composite("account", *named))
        return tuple(keys)

    @staticmethod
    def _code_key(account_id: str) -> str:
        return _composite("code", account_id)

    async def _locked_for(self, keys: Sequence[str]) -> int | None:
        """Seconds until every key may try again, or `None` when none is locked out."""

        now = self._now()
        waits = []
        for key in keys:
            attempts = await self._read(SIGN_IN_ATTEMPTS, key, SignInAttempts.from_json)
            if attempts is not None and attempts.locked_until is not None:
                if now < attempts.locked_until:
                    waits.append((attempts.locked_until - now).total_seconds())
        return max(1, math.ceil(max(waits))) if waits else None

    async def _attempt_failed(self, keys: Sequence[str]) -> None:
        """Count one failure against each key; at the limit, lock it out, doubling each time."""

        config = self.config
        for key in keys:
            for _ in range(_CAS_ATTEMPTS):
                now = self._now()
                entry = await self.store.get(SIGN_IN_ATTEMPTS, key)
                before = (
                    SignInAttempts() if entry is None else SignInAttempts.from_json(entry.value)
                )
                failures = before.failures + 1
                locked_until = before.locked_until
                if failures >= config.max_sign_in_failures:
                    over = min(failures - config.max_sign_in_failures, 7)
                    locked_until = now + min(config.sign_in_lockout * 2**over, timedelta(days=1))
                after = SignInAttempts(failures=failures, locked_until=locked_until)
                # Forgotten once the key has failed nothing for a lockout's length.
                expires_at = max(now, locked_until or now) + config.sign_in_lockout
                if entry is None:
                    written = await self.store.create(
                        SIGN_IN_ATTEMPTS, key, after.to_json(), expires_at=expires_at
                    )
                else:
                    written = await self.store.replace(
                        SIGN_IN_ATTEMPTS, key, entry.version, after.to_json(), expires_at=expires_at
                    )
                if written:
                    break
            else:
                raise _RefusedError(503, "temporarily_unavailable")

    async def _attempts_cleared(self, keys: Sequence[str]) -> None:
        for key in keys:
            await self.store.delete(SIGN_IN_ATTEMPTS, key)

    @staticmethod
    def _rate_limited(retry_after: int) -> CompanyResponse:
        return CompanyResponse(
            429,
            {"error": "rate_limited"},
            {"Retry-After": str(retry_after), "Cache-Control": "no-store"},
        )

    async def _mediated(self, request: CompanyRequest) -> CompanyResponse:
        _, session = await self._caller(request)
        body = loads_strict(request.body) if request.body else {}
        credentials = body.get("credentials") if isinstance(body, dict) else None
        if not isinstance(credentials, dict):
            raise _RefusedError(400, "invalid_request")
        scope = body.get("scope")
        granted = tuple(s for s in scope.split(" ") if s) if isinstance(scope, str) else ()
        if not granted or any(s not in self.config.scopes for s in granted):
            # Missing, unknown, or unavailable scopes are refused, never narrowed (§4.4).
            raise _RefusedError(400, "invalid_scope")
        keys = self._attempt_keys(session, credentials)
        locked = await self._locked_for(keys)
        if locked is not None:
            # Locked out: the credentials are not even checked (§4.2, `rate_limited`).
            credentials.clear()
            return self._rate_limited(locked)
        accounts = cast(
            AccountDirectory, first_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        )
        secrets = {name: SecretStr(str(value)) for name, value in credentials.items()}
        credentials.clear()
        authenticated = await accounts.authenticate(
            secrets, SignInContext(client_id=session.client_id, session_key=session.session_key)
        )
        secrets.clear()
        if authenticated is None:
            await self._attempt_failed(keys)
            return CompanyResponse(200, {"status": "failed"}, {"Cache-Control": "no-store"})
        # Tied to another account, even signed out since: refused before any code is sent.
        await self._check_account(session.session_key, authenticated.account_id)
        code_key = self._code_key(authenticated.account_id)
        if authenticated.code_reference is None:
            await self._attempts_cleared(keys)
            return await self._signed_in_body(session, authenticated.account_id, granted)
        locked = await self._locked_for((code_key,))
        if locked is not None:
            # Too many wrong codes for this account: no new code until the lockout ends.
            return self._rate_limited(locked)
        sign_in_id = self._id("si")
        expires_at = self._now() + timedelta(minutes=5)
        await self.store.put(
            MEDIATED,
            sign_in_id,
            PendingMediated(
                session_key=session.session_key,
                account_id=authenticated.account_id,
                scopes=granted,
                code_reference=authenticated.code_reference,
                expires_at=expires_at,
                attempt_keys=keys,
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
        if pending is None or pending.session_key != session.session_key:
            # Unknown, or another Session's: the same error for both (§4.7).
            raise _RefusedError(404, "sign_in_not_found")
        if pending.status != "code_required":
            # Once failed or expired, it stays so: the same status again, HTTP 200 (§4.7).
            return CompanyResponse(200, {"status": pending.status}, {"Cache-Control": "no-store"})
        if self._now() >= pending.expires_at:
            return await self._mediated_ended(sign_in_id, "expired")
        code_key = self._code_key(pending.account_id)
        if await self._locked_for((code_key,)) is not None:
            # The account's code budget is spent, whichever sign-in spent it.
            return await self._mediated_ended(sign_in_id, "failed")
        body = loads_strict(request.body) if request.body else {}
        code = body.get("code") if isinstance(body, dict) else None
        accounts = cast(
            AccountDirectory, first_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        )
        if not isinstance(code, str) or not await accounts.check_code(
            pending.code_reference, SecretStr(code)
        ):
            # Every wrong code counts, however many replicas check them at once: against
            # this sign-in, and against the account across every sign-in started for it.
            await self._attempt_failed((code_key,))
            counted = await self._change(
                MEDIATED,
                sign_in_id,
                PendingMediated.from_json,
                lambda current: replace(current, attempts=current.attempts + 1),
            )
            if (
                counted is None
                or counted[1].attempts >= self.config.max_code_attempts
                or await self._locked_for((code_key,)) is not None
            ):
                return await self._mediated_ended(sign_in_id, "failed")
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
        completed = None if taken is None else PendingMediated.from_json(taken)
        if completed is None or completed.status != "code_required":
            return CompanyResponse(200, {"status": "failed"}, {"Cache-Control": "no-store"})
        await self._attempts_cleared((*completed.attempt_keys, code_key))
        return await self._signed_in_body(session, completed.account_id, completed.scopes)

    async def _mediated_ended(
        self, sign_in_id: str, status: Literal["failed", "expired"]
    ) -> CompanyResponse:
        """The sign-in ends as `status`, kept so a later code gets the same answer (§4.7)."""

        def end(current: PendingMediated) -> PendingMediated:
            return current if current.status != "code_required" else replace(current, status=status)

        changed = await self._change(MEDIATED, sign_in_id, PendingMediated.from_json, end)
        ended = status if changed is None else changed[1].status
        return CompanyResponse(200, {"status": ended}, {"Cache-Control": "no-store"})

    async def _signed_in_body(
        self, session: IssuedSession, account_id: str, scopes: tuple[str, ...]
    ) -> CompanyResponse:
        # Every requested scope is granted here, so `scope` is left out, as at the token
        # endpoint (§4.4, §4.7).
        response = await self._sign_in(
            session, account_id, scopes, session.key_thumbprint, requested=scopes
        )
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
                raise _insufficient_scope(self._account_scopes())
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
        _wait(request)
        body = _json_object(request.body)
        message = _incoming(body.get("message"))
        owner = (session.client_id, session.pairwise_user_id)
        replay = await self._replayed(owner, message)
        if replay is not None:
            # A retried start answers only a caller that may read the conversation now.
            return self._answer(request, await self._owned(replay, session), 201)
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
            return self._answer(request, await self._owned(replay, session), 201)
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

    async def _conversation_route(  # noqa: C901 - the conversation's actions
        self, request: CompanyRequest, method: str, path: str
    ) -> CompanyResponse:
        parts = path.split("/")
        conversation_id = parts[3]
        action = parts[4] if len(parts) > 4 else ""
        _, session = await self._caller(request)
        if not _IDENTIFIER.fullmatch(conversation_id):
            # An ID with characters not allowed is malformed, not unknown (§7.2, §7.13).
            raise _RefusedError(400, "invalid_request")
        _wait(request)
        conversation = await self._owned(conversation_id, session)
        if method == "GET" and action == "events":
            if "text/event-stream" in request.headers.get("accept", ""):
                # Last-Event-ID wins over `cursor`: an SSE client adds it to the URL the
                # stream was first opened with (§7.6).
                cursor = request.headers.get("last-event-id") or _query(request).get("cursor")
                return self._stream(conversation, cursor)
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
                if current.status == "queued" or current.responder == "human":
                    # Already asked for, or with a person: 202, nothing changes (§7.9).
                    return current
                responder: Literal["agent", "human"] = (
                    "human" if self.config.humans_available else current.responder
                )
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
            message = _incoming(_json_object(request.body).get("message"))
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
            if current.responder == "human":
                return replace(
                    current,
                    account_id=session.account_id or current.account_id,
                    events=(*current.events, received),
                )
            # The agent works on it: every change of status adds a state event (§7).
            return replace(
                current,
                status="working",
                account_id=session.account_id or current.account_id,
                events=(*current.events, received, self._state("working", current.responder)),
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
                author=message.author.type,
                account_id=session.account_id,
                scopes=session.scopes,
                client_id=session.client_id,
                is_direct=conversation.parent_id is not None,
                supports_operations=await self._supports_operations(session.client_id),
            )
        )
        events: list[StoredEvent] = []
        for reply in replies:
            event = await self._reply(session, reply)
            if event is not None:
                events.append(event)

        def answered(current: StoredConversation) -> StoredConversation:
            if current.status == "closed":
                return replace(current, events=(*current.events, *events))
            idle = self._state("idle", current.responder)
            return replace(current, status="idle", events=(*current.events, *events, idle))

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
        author: dict[str, object] = {"type": "agent", **(reply.persona or {})}
        message: dict[str, object] = {"id": self._id("msg"), "author": author, "role": "company"}
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
        query = _query(request)
        if "wait" in query or "cursor" in query:
            return self._page_response(request, conversation, status)
        return self._receipt(conversation, status)

    def _page_response(
        self, request: CompanyRequest, conversation: StoredConversation, status: int
    ) -> CompanyResponse:
        cursor = _query(request).get("cursor")
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

    # Feedback (§8) -------------------------------------------------------------------

    async def _feedback(self, request: CompanyRequest) -> CompanyResponse:
        """Accept a report with a Session Token, signed in or out, no scope needed.

        Any `kind` is accepted, so later versions can add kinds; `task` (at
        most 200 characters) and `description` (at most 2,000) are required.
        The text is kept as data for the operator, never acted on.
        """

        _, session = await self._caller(request)
        body = _json_object(request.body)
        kind, task, description = body.get("kind"), body.get("task"), body.get("description")
        if (
            not isinstance(kind, str)
            or not kind
            or not isinstance(task, str)
            or not 0 < len(task) <= 200
            or not isinstance(description, str)
            or not 0 < len(description) <= 2000
        ):
            raise _RefusedError(400, "invalid_request")
        report = StoredFeedback(
            report_id=self._id("fb"),
            kind=kind,
            task=task,
            description=description,
            client_id=session.client_id,
            pairwise_user_id=session.pairwise_user_id,
            received_at=self._now(),
        )
        await self.store.put(FEEDBACK, report.report_id, report.to_json())
        answers = {key.casefold(): value for key, value in self.config.feedback_answers.items()}
        alternative = answers.get(task.casefold())
        if alternative is not None:
            # The task can be done after all: here is how (§8.3).
            return CompanyResponse(200, dict(alternative), {"Cache-Control": "no-store"})
        return CompanyResponse(202, None, {"Cache-Control": "no-store"})

    async def feedback_reports(self) -> tuple[StoredFeedback, ...]:
        """The feedback reports personal agents sent, oldest first, for the operator (§8).

        A report can be wrong or written to mislead: its text is data, never
        an instruction, including when a model reads it.
        """

        reports = [
            StoredFeedback.from_json(record.value) for record in await self.store.records(FEEDBACK)
        ]
        return tuple(sorted(reports, key=lambda report: (report.received_at, report.report_id)))

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
            operation=operation,
            action=proposal.action,
            owner=owner,
            account_id=account_id,
            scopes=self._operation_scopes(proposal),
        )
        await self.store.put(OPERATION, operation_id, stored.to_json())
        await self.store.put(
            PROPOSAL,
            key,
            OperationProposal(operation_id).to_json(),
            expires_at=operation.expires_at,
        )
        return operation

    def _operation_scopes(self, proposal: Any) -> tuple[str, ...]:
        """The scopes confirming this operation requires: its own, else the write scopes."""

        scopes = tuple(proposal.scopes) or self.config.write_scopes
        if any(scope not in self.config.scopes for scope in scopes):
            raise ValueError("an operation's scopes must be among the company's scopes")
        return scopes

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

    # One of the company's people -------------------------------------------------

    async def conversation_record(self, conversation_id: str) -> StoredConversation:
        """A conversation as the company keeps it: its status, responder, and events."""

        conversation = await self._read(CONVERSATION, conversation_id, StoredConversation.from_json)
        if conversation is None:
            raise KeyError(conversation_id)
        return conversation

    async def staff_reply(
        self,
        conversation_id: str,
        *,
        after: str,
        text: str | None = None,
        data: dict[str, Any] | None = None,
        author_id: str | None = None,
        author_name: str | None = None,
        author_image: str | None = None,
    ) -> ConversationEvent:
        """One of the company's people answers in a conversation handed to them (§7.9).

        `after` is the ID of the last event they read: compare-and-set, so an
        answer written over anything they have not read is refused
        (`StaleConversationError`) and they read the conversation again. Their
        message is the company's (`role: company`) and written by a person
        (`author.type: human`, with the person's `id`, display `name`, and
        `image` when given, §7.4); a conversation not handed to people, closed, or
        with a Direct Conversation open takes none (`ValueError`). The event
        written is returned: its ID is their next `after`.
        """

        if text is None and data is None:
            raise ValueError("a reply says something: text, data, or both")
        message = Message(
            id=self._id("msg"),
            author=Author(type="human", id=author_id, name=author_name, image=author_image),
            role="company",
            text=text,
            data=data,
        )
        event = self._event(
            type="message", message=message.model_dump(mode="json", exclude_none=True)
        )

        def reply(current: StoredConversation) -> StoredConversation:
            if current.status == "closed":
                raise ValueError("the conversation is closed")
            if current.responder != "human":
                raise ValueError("the conversation is not handed to the company's people")
            if current.direct_child is not None:
                raise ValueError("a Direct Conversation is open under this conversation")
            if not current.events or current.events[-1].id != after:
                raise StaleConversationError(conversation_id, after)
            return replace(current, events=(*current.events, event))

        changed = await self._change(
            CONVERSATION, conversation_id, StoredConversation.from_json, reply
        )
        if changed is None:
            raise KeyError(conversation_id)
        return ConversationEvent.model_validate(event.payload)

    # Taking the company down ---------------------------------------------------------

    async def open_work(self) -> OpenWork:
        """What is under way: open operations and sign-ins not ended, read from the store."""

        operations = []
        for record in await self.store.records(OPERATION):
            stored = self._expired(StoredOperation.from_json(record.value))
            if stored.operation.state in _OPEN_STATES:
                operations.append(stored.operation)
        sign_ins = set()
        for record in await self.store.records(ACCOUNT_FAMILY):
            family = AccountFamily.from_json(record.value)
            if not family.revoked:
                sign_ins.add((family.client_id, family.account_id))
        operations.sort(key=lambda operation: operation.operation_id)
        return OpenWork(operations=tuple(operations), sign_ins=tuple(sorted(sign_ins)))

    async def cancel_open_operations(self, reason: str) -> int:
        """Settle every open operation as `cancelled`, because of `reason` (a sentence).

        For a company being taken down: nothing will perform or settle them
        after, and a personal agent would otherwise read one as in progress for
        ever. A proposal was never performed: *Nothing was changed.* One in
        progress may have changed something before it stopped, which its result
        says (Operations §6). A proposal past its expiry is recorded as expired.
        Returns how many were cancelled.
        """

        reason = reason.strip()
        if not reason:
            raise ValueError("say why the operations are cancelled")
        stopped = OperationResult(
            summary=(
                "It was stopped before it finished, and nothing more will be done: "
                f"whatever it changed until then stands. {reason}"
            )
        )
        untouched = OperationResult(summary=f"Nothing was changed. {reason}")

        def cancel(stored: StoredOperation) -> StoredOperation:
            stored = self._expired(stored)
            state = stored.operation.state
            if state not in _OPEN_STATES:
                return stored
            return replace(
                stored,
                operation=stored.operation.model_copy(
                    update={
                        "state": "cancelled",
                        "result": stopped if state == "in_progress" else untouched,
                    }
                ),
            )

        cancelled = 0
        for record in await self.store.records(OPERATION):
            operation_id = StoredOperation.from_json(record.value).operation.operation_id
            changed = await self._change(OPERATION, operation_id, StoredOperation.from_json, cancel)
            if changed is not None and changed[1].operation.state == "cancelled":
                cancelled += changed[0].operation.state != "cancelled"
        return cancelled

    async def end_sign_ins(self) -> int:
        """End every sign-in, as each agent's disconnect does: tokens revoked, Sessions signed out.

        Returns how many agents' sign-ins to an account were ended.
        """

        work = await self.open_work()
        for client_id, account_id in work.sign_ins:
            await self.disconnect(client_id, account_id)
        return len(work.sign_ins)

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
        """The operation, if this Session may use it now (Operations §3.2).

        One proposed signed in belongs to the account: any Session of the same
        personal agent and user may use it while signed in to that account,
        checked at each request. Signed out, that Session gets
        `insufficient_scope` (Operations 3.2); anyone else `operation_not_found`.
        """

        stored = await self._read(OPERATION, operation_id, StoredOperation.from_json)
        if stored is None or stored.owner != (session.client_id, session.pairwise_user_id):
            raise _RefusedError(404, "operation_not_found")
        if stored.account_id != session.account_id:
            if session.account_id is None:
                raise _insufficient_scope(self.config.write_scopes)
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
        # The scopes recorded with the operation when it was proposed, whichever
        # channel (API, MCP, conversation) proposed it and whichever confirms it.
        if any(scope not in session.scopes for scope in stored.scopes):
            raise _RefusedError(403, "insufficient_scope", scope=" ".join(stored.scopes))
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
        return cast(
            CompanyMcp | None, optional_contribution(self.reactor, COMPANY_MCP, "MCP server")
        )

    def _mcp_refusal(
        self,
        status: int,
        error: str,
        scope: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> CompanyResponse:
        """A token refusal at the MCP server: one challenge per scheme it accepts (§6).

        `Bearer`, and `DPoP` when it supports DPoP, each with
        `resource_metadata` (RFC 9728 §5.1) and the error's `scope`.
        """

        extra: dict[str, object] = {"resource_metadata": self.config.mcp_resource_metadata}
        if scope is not None:
            extra["scope"] = scope
        schemes = ("Bearer", "DPoP") if self.config.mcp_dpop else ("Bearer",)
        body: dict[str, object] = {"error": error}
        if scope is not None:
            body["scope"] = scope
        return CompanyResponse(
            status,
            body,
            {
                "WWW-Authenticate": ", ".join(_challenge(name, error, extra) for name in schemes),
                "Cache-Control": "no-store",
                **(headers or {}),
            },
        )

    async def _mcp_caller(self, request: CompanyRequest) -> IssuedSession | CompanyResponse:
        """The Session of a token issued for this MCP server, else its refusal (§4.3, §6).

        A Bearer token issued for its url (from a personal agent when it doesn't
        support DPoP, or from an MCP client that doesn't implement the protocol),
        or, when it supports DPoP, a DPoP token issued for its url with a valid
        proof. A DPoP token sent with the `Bearer` scheme is refused (RFC 9449 §7.1).
        """

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        accepted = {"Bearer", "DPoP"} if self.config.mcp_dpop else {"Bearer"}
        if scheme not in accepted or not token:
            return self._mcp_refusal(401, "invalid_token")
        session = await self._token_session(token)
        if (
            session is None
            or self._now() >= session.expires_at
            or session.token_type != scheme
            or session.resource != self.config.mcp_url
            or not self._offers(session.scopes)
            or not await self._allowed(session.client_id)
        ):
            return self._mcp_refusal(401, "invalid_token")
        if scheme == "DPoP":
            try:
                thumbprint = await self._dpop(request, access_token=token)
            except _RefusedError as refused:
                return self._mcp_refusal(401, refused.error, headers=refused.headers)
            if thumbprint != session.key_thumbprint:
                return self._mcp_refusal(401, "invalid_dpop_proof")
        return session

    def _offers(self, scopes: Sequence[str]) -> bool:
        """Whether this company offers every one of these scopes now.

        A Session holding a scope the company no longer offers — rolled back
        to a version without it, or narrowed — is refused as `invalid_token`,
        so the personal agent starts a new one within what is offered; an
        Account Token refreshed for such a scope is `invalid_scope`, and
        serves again when asked within what is offered.
        """
        return all(scope in self.config.scopes for scope in scopes)

    async def _mcp_route(  # noqa: C901 - the JSON-RPC methods
        self, request: CompanyRequest
    ) -> CompanyResponse:
        session = await self._mcp_caller(request)
        if isinstance(session, CompanyResponse):
            # A missing, expired, or other-resource token, or a token in the wrong scheme.
            return session
        wait = await self._admitted(session)
        if wait is not None:
            return self._rate_limited(wait)
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
            return self._mcp_refusal(status, error, scope)
        if answer.operation is not None:
            if session.account_id is None:
                return self._mcp_refusal(
                    403, "insufficient_scope", " ".join(self.config.write_scopes)
                )
            if not await self._supports_operations(session.client_id):
                # A tool can't be refused with `extension_required`, which refuses the
                # personal agent entirely: an ordinary tool error (Operations §2, §6).
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": "This tool needs the Operations extension, which your "
                            "agent doesn't list.",
                        }
                    ],
                    "isError": True,
                }
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

    async def _live_session(self, session_key: str) -> IssuedSession | None:
        """The Session as it is now: its latest unexpired DPoP token's record."""

        stored = await self._read(SESSION, session_key, StoredSession.from_json)
        now = self._now()
        live = [
            session
            for session in (stored.tokens.values() if stored is not None else ())
            if session.token_type == "DPoP"  # noqa: S105 - OAuth token type
            and now < session.expires_at
        ]
        latest = max(live, key=lambda session: session.expires_at) if live else None
        if latest is not None and await self._signed_in_before_its_end(latest):
            return None
        return latest

    async def _join_page(self) -> CompanyResponse:
        """Step 1 of joining a browser (§5): a form with a one-time code, tied to this browser.

        Loading it starts, ends or changes no Session and no other cookie. The page is
        never cached, framed, or kept by the page that opened it.
        """

        code = self._id("bc")
        browser = self._id("join")
        await self.store.put(
            JOIN_CODE,
            _digest(code),
            JoinCode(_digest(browser)).to_json(),
            expires_at=self._now() + _JOIN_LIFETIME,
        )
        body = (
            "<!doctype html><meta charset=utf-8><title>Connecting</title>"
            f'<form method="post" action="/poppy/browser-session">'
            f'<input type="hidden" name="code" value="{html.escape(code)}">'
            '<input type="text" name="proof"></form>'
        )
        return CompanyResponse(
            200,
            body,
            {
                "Content-Type": "text/html; charset=utf-8",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "frame-ancestors 'none'",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Set-Cookie": (
                    f"{JOIN_COOKIE}={browser}; Path=/; Max-Age=60; Secure; HttpOnly; "
                    "SameSite=Strict"
                ),
            },
        )

    async def _browser_session(self, request: CompanyRequest) -> CompanyResponse:
        """Step 3 (§5): the cookie, the code, and a proof over it from an active Session's key.

        A code is used by the first request that sends it, whatever the result. A key
        the company doesn't know is an error here, never a new Session.
        """

        refused = replace(
            self._page(400, "This browser could not join the session."),
            headers={
                **self._page(400, "").headers,
                "Set-Cookie": f"{JOIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict",
            },
        )
        form = dict(parse_qsl(request.body.decode()))
        code, proof, browser = form.get("code", ""), form.get("proof", ""), _cookie(request, JOIN_COOKIE)
        taken = await self.store.take(JOIN_CODE, _digest(code)) if code else None
        issued = None if taken is None else JoinCode.from_json(taken)
        if issued is None or browser is None or not hmac.compare_digest(
            issued.browser, _digest(browser)
        ):
            return refused
        try:
            verified = await verify_dpop_proof(
                proof,
                method="POST",
                url=self.config.browser_session_endpoint,
                replay_cache=self._replay(),
                nonce=code,
                now=self._now(),
            )
        except ProofError:
            return refused
        session = await self._live_session(verified.key_thumbprint)
        if session is None or not await self._allowed(session.client_id):
            return refused
        cookie = self._id("web")
        await self.store.put(
            BROWSER_COOKIE,
            _digest(cookie),
            SessionPointer(session.session_key).to_json(),
            expires_at=session.expires_at + self.config.account_token_lifetime,
        )
        exchange = _EXCHANGE.get()
        if exchange is not None:
            exchange.client_id = session.client_id
        self._report(
            "pap.company.interface.switch",
            "ok",
            {"pap.interface": "web", "pap.session.signed_in": session.signed_in},
        )
        return CompanyResponse(
            303,
            None,
            {
                "Location": f"{self.config.base}/",
                # The company's own cookie, `__Host-`: no Max-Age, only as alive as its
                # Session (§5). The join cookie is cleared.
                "Set-Cookie": (
                    f"{WEB_COOKIE}={cookie}; Path=/; Secure; HttpOnly; SameSite=Strict\n"
                    f"{JOIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
                ),
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
        session = await self._live_session(pointer.session_key)
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
