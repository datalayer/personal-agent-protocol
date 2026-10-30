# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A framework-neutral PAP company: discovery, Sessions, sign-in, conversations, operations.

`CompanyService.handle` takes a neutral request and returns a neutral
response, so any web framework can serve it (`asgi.company_app` serves it
over plain ASGI). Every part a company would replace is a Reactor
contribution (`points`): its store, accounts, agent, operation executors,
client policy and resolver, and replay cache.

What it implements of draft 0.3 (upstream 3e9bada) and Operations v2:

- Discovery (`/.well-known/poppy.json`), the domain's protected resource
  metadata naming the issuer (`/.well-known/oauth-protected-resource`), and
  OAuth metadata (`/.well-known/oauth-authorization-server`), one issuer on the
  company's own domain.
- Sessions (§5): the Session header on every request, verified in the spec's
  order (delegation, delegated key, claims, access token), Sessions kept by
  `client_id` and `sid`, ended ones remembered; any failure is
  `invalid_session` (HTTP 400). Its own access token without the header is refused.
- OAuth (§4): access tokens, Bearer or, with `dpop_binding`, bound with DPoP (§4.5),
  and refresh tokens, never bound; Direct Sign-In, Device
  Sign-In with `authorization_pending` and `slow_down`, refresh with rotation,
  narrower scopes and `resource` (RFC 8707: `invalid_target` for one it doesn't
  serve), and revocation (RFC 7009) whose sign-in ends whole.
- The Mediated Sign-In extension v1, an extension grant at the token endpoint, with a
  one-time code, attempt limits, and uniform failures; credentials are checked by the
  account directory and dropped.
- Conversations (§8): idempotent messages, ordered cursor events, waited
  replies, SSE, handoff, Direct Conversations, `authorization` events, and
  closing; a conversation that is not yours is `conversation_not_found`.
  Once a conversation is handed to the company's people, one of them
  answers in it (`staff_reply`), over the last event they read.
- Operations v2, at no endpoint of their own: a request for an action that needs
  approval is refused with the operation (`403 approval_required`, an MCP error
  result, a company message), and the same request with the approval
  (`Poppy-Approval`, `_meta`, a message's `approval`) is checked in the extension's
  order and performed at most once; a repeat gets the original response, a request
  while it is performed `503` and `Retry-After`, and a failed check a new revision.
- MCP (§7), when a `pap.company.mcp` contribution is present: a Streamable HTTP
  endpoint at `/mcp` accepting the Session header and access tokens issued for
  its url (`resource` = that url), its protected resource metadata (RFC 9728),
  and tools that return operations in `structuredContent` (Operations 4).
  A token issued for another resource is `invalid_token` with `resource_metadata`.
- Feedback (§9.3), with `feedback` (the default): reports of tasks the
  protocol can't do, kept for the company's operator (`feedback_reports`).
- Web browsing (§6), with `web=True`: the browser-session page with a one-time
  code, `{endpoint}/authorize` for the personal agent, and the company's own
  cookie for the Session.
- Rate limits (§5.6): HTTP 429 and `Retry-After`, no body.
- Taking a company down: its owner reads what is under way (`open_work`),
  settles each open operation (`settle_open_operations`) and ends every
  sign-in (`end_sign_ins`), before its records go.
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
from typing import Any, Literal, NoReturn, Protocol, TypeVar, cast
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import jwt
from pydantic import SecretStr, ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from ..apis import IDEMPOTENCY_KEY, WRITE_METHODS
from ..crypto import DPOP_ALGORITHM
from ..errors import (
    PersonalAgentProtocolError,
    ProofError,
    ProtocolValidationError,
    SessionError,
)
from ..json import loads_strict
from ..mediated import MEDIATED_EXTENSION, MEDIATED_GRANT, MEDIATED_VERSION
from ..models import (
    AUTHORIZATION_CODE_GRANT,
    DEVICE_CODE_GRANT,
    MEDIATED_RESERVED_FIELDS,
    REFRESH_TOKEN_GRANT,
    Approval,
    Author,
    ClientMetadata,
    ConversationEvent,
    JsonWebKeySet,
    Message,
    Operation,
    redirect_uri_matches,
)
from ..operations import (
    ACTION_FAILED,
    APPROVAL_HEADER,
    OPERATIONS_EXTENSION,
    OPERATIONS_VERSION,
    approval_from_meta,
    parse_approval_header,
)
from ..profile import PROTOCOL_PROFILE
from ..reactor import (
    CLOCKS,
    RANDOM_SOURCES,
    Clock,
    RandomSource,
    first_contribution,
    optional_contribution,
)
from ..sessions import JWT_CLIENT_ASSERTION, _opaque_id
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
    ActionResult,
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
    ProposedOperation,
    RateLimit,
    ReplayCache,
    Reply,
    SignInContext,
    SignInRefused,
    Turn,
)
from .store import (
    ACCESS_TOKEN,
    ACCOUNT_AGENT,
    ACCOUNT_FAMILY,
    AUTHORIZATION,
    BROWSER_COOKIE,
    CLIENT,
    CODE,
    CONVERSATION,
    DEVICE,
    DPOP_NONCE,
    FEEDBACK,
    IDEMPOTENCY,
    JOIN_CODE,
    MEDIATED,
    MESSAGE_ID,
    OPERATION,
    PROPOSAL,
    REFRESH_TOKEN,
    SESSION,
    SIGN_IN_ATTEMPTS,
    USER_CODE,
    AccountAgent,
    AccountFamily,
    AccountGrant,
    CompanyStore,
    IdempotencyRecord,
    IssuedAccessToken,
    IssuedCode,
    IssuedNonce,
    JoinCode,
    JsonObject,
    KnownClient,
    MessageReceipt,
    OperationOutcome,
    OperationProposal,
    OperationRevision,
    PendingAuthorization,
    PendingDevice,
    PendingMediated,
    SignInAttempts,
    StoredConversation,
    StoredEvent,
    StoredFeedback,
    StoredOperation,
    StoredSession,
    UserCode,
    WebSession,
)
from .verify import (
    DelegationCache,
    unverified_session_issuer,
    verify_assertion,
    verify_dpop_proof,
    verify_session_jwt,
)

_PAGE = 50
#: How often a compare-and-set is retried against concurrent writers before giving up.
_CAS_ATTEMPTS = 32
#: The key prefix of a `client_id`'s Mediated Sign-In attempts: it has its own limit.
_CLIENT_ATTEMPTS = "client:"
#: How long a Mediated Sign-In's one-time code can be sent.
_MEDIATED_CODE_LIFETIME = timedelta(minutes=5)
#: The error a Mediated Sign-In that ended answers with, for good.
_MEDIATED_ENDED = {"failed": "invalid_grant", "expired": "expired_token"}
#: How long an expired device or Mediated sign-in is kept, to answer that it expired.
_KEPT_EXPIRED = timedelta(minutes=10)
#: How long the first request with an `Idempotency-Key` holds it: a repeat in that time
#: is told to wait (503, `Retry-After`); a holder that never answered lets it go then.
_IDEMPOTENCY_HELD = timedelta(minutes=1)
#: The longest `wait` the company holds a read for; a larger one is held this long (§7.5).
MAX_WAIT_SECONDS = 30


class _Record(Protocol):
    def to_json(self) -> JsonObject: ...


_R = TypeVar("_R", bound=_Record)


_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


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
    #: Mediated Sign-In's `fields`: `(name, label, secret)`. None, it isn't offered.
    mediated_fields: tuple[tuple[str, str, bool], ...] = ()
    #: The scopes Mediated Sign-In can grant, its `scopes`: none named, all of `scopes`.
    mediated_scopes: tuple[str, ...] = ()
    device: bool = True
    direct: bool = True
    operations: bool = True
    #: Whether the company has an OAuth issuer (§3.2). Without one it runs no OAuth server:
    #: its protected resource metadata and OAuth endpoints are 404, it publishes no `auth`,
    #: `identifier` is its HTTPS domain, and every Session stays signed out.
    oauth: bool = True
    humans_available: bool = False
    #: How long a Session lasts (§5.5: the Company decides); then it has ended.
    session_lifetime: timedelta = timedelta(days=1)
    #: How long an access token works (§4.5; guides: an hour).
    access_token_lifetime: timedelta = timedelta(hours=1)
    #: How long a sign-in's refresh tokens work (§4.4).
    refresh_token_lifetime: timedelta = timedelta(days=90)
    operation_lifetime: timedelta = timedelta(minutes=15)
    device_interval: int = 5
    max_code_attempts: int = 3
    #: Failed Mediated Sign-In attempts (credentials or codes) a key may make before it
    #: is locked out: an account identifier, an account's codes.
    max_sign_in_failures: int = 5
    #: The same for all of a `client_id`'s attempts, which many users' sign-ins share.
    max_client_sign_in_failures: int = 100
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
    #: Accept feedback reports at `/poppy/feedback` and list it in poppy.json (§9.3).
    feedback: bool = True
    #: How long an ended Session's `sid` is remembered and refused (§5.5: a Company MAY).
    ended_session_memory: timedelta = timedelta(days=30)
    #: The acceptance window of a Session JWT's `iat` (§5.3: such as one minute).
    session_jwt_window: timedelta = timedelta(seconds=60)
    #: How long an API write's `Idempotency-Key` is remembered in its Session, with the
    #: original response a repeated key gets again (guides, *Retries*: a set time, a day).
    idempotency_lifetime: timedelta = timedelta(days=1)
    #: Whether access tokens are bound with DPoP, the Company's choice (§4.5). `off` lists
    #: no algorithm and issues Bearer tokens. `optional` binds a token when a proof comes
    #: with its request. `required` also refuses a token request with no proof.
    dpop_binding: Literal["off", "optional", "required"] = "off"
    #: Proofs must carry a nonce the company gave (RFC 9449 §8, §9).
    dpop_nonces: bool = False
    #: How long a given nonce is accepted.
    dpop_nonce_lifetime: timedelta = timedelta(minutes=5)
    #: The acceptance window of a proof's `iat`.
    dpop_proof_window: timedelta = timedelta(seconds=60)

    def __post_init__(self) -> None:  # noqa: C901 - one branch per protocol rule
        _check_aliases(self.domain, self.aliases)
        _check_positive(
            idempotency_lifetime=self.idempotency_lifetime,
            session_lifetime=self.session_lifetime,
            access_token_lifetime=self.access_token_lifetime,
            refresh_token_lifetime=self.refresh_token_lifetime,
            session_jwt_window=self.session_jwt_window,
            dpop_nonce_lifetime=self.dpop_nonce_lifetime,
            dpop_proof_window=self.dpop_proof_window,
        )
        if not self.oauth and (
            self.mediated_fields or self.operations or self.aliases or self.dpop_binding != "off"
        ):
            # Each needs an issuer: sign-in, an approving account, the domains it joins (§3.2).
            raise ValueError(
                "a company with no issuer has no mediated_fields, operations, aliases or DPoP"
            )
        if self.dpop_binding not in ("off", "optional", "required"):
            raise ValueError("dpop_binding is off, optional or required")
        if self.dpop_nonces and self.dpop_binding == "off":
            raise ValueError("dpop_nonces need dpop_binding")
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
        if set(self.scope_descriptions) != set(self.scopes) or not all(
            self.scope_descriptions.values()
        ):
            # Every scope in scopes_supported is described (§4.4).
            raise ValueError("scope_descriptions must describe every scope, and only those")
        for name, (changes, _personal) in self.scope_hints.items():
            if name not in self.scopes or changes not in ("none", "reversible", "irreversible"):
                raise ValueError("scope_hints name a scope and its changes")
        if (
            self.max_sign_in_failures < 1
            or self.max_client_sign_in_failures < 1
            or self.sign_in_lockout <= timedelta(0)
        ):
            raise ValueError("sign-in attempts need a positive limit and lockout")
        if any(name in MEDIATED_RESERVED_FIELDS for name, _, _ in self.mediated_fields):
            # A field would overwrite the grant's own parameters (Mediated Sign-In 2).
            raise ValueError("a Mediated Sign-In field can't use a reserved parameter name")
        if any(scope not in self.scopes for scope in self.mediated_scopes):
            raise ValueError("mediated_scopes must be among scopes")
        if self.operations and not self.write_scopes:
            # Approving an operation needs a write scope: without one, any signed-in
            # Session, whatever it was granted, could approve.
            raise ValueError("operations need write_scopes: the scopes approving one requires")

    @property
    def base(self) -> str:
        return f"https://{self.domain}"

    @property
    def identifier(self) -> str:
        """The company's identifier (§3.2): its issuer, else its lowercase HTTPS domain."""

        return self.base if self.oauth else f"https://{self.domain.lower()}"

    @property
    def token_schemes(self) -> tuple[str, ...]:
        """The `Authorization` schemes a resource accepts, each challenged (§7)."""

        return {
            "off": ("Bearer",),
            "optional": ("Bearer", "DPoP"),
            "required": ("DPoP",),
        }[self.dpop_binding]

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
    def mediated_grant_scopes(self) -> tuple[str, ...]:
        """The extension's `scopes`: what Mediated Sign-In can grant."""
        return self.mediated_scopes or self.scopes

    @property
    def conversations_endpoint(self) -> str:
        return f"{self.base}/poppy/conversations"

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
class CallerSession:
    """Who a verified request is from (§5.3): its Session, and its account when signed in.

    `session_key` names the Session in the store (`client_id` and `sid`). `account_id`,
    `scopes`, `family` and `resource` are the access token's, for this request only:
    a Session is signed in on each request that carries one (§5.4).
    """

    session_key: str
    client_id: str
    sid: str
    pairwise_user_id: str
    agent_id: str | None = None
    account_id: str | None = None
    scopes: tuple[str, ...] = ()
    family: str | None = None
    resource: str | None = None

    @property
    def signed_in(self) -> bool:
        return self.account_id is not None


#: The header that carries the Session JWT (§5.2).
SESSION_HEADER = "poppy-session"


@dataclass(frozen=True)
class OpenWork:
    """What a company has under way: what its owner settles and ends before taking it down.

    `operations` are those that can still be approved, or are being performed (one
    whose revisions have all expired is not open); `sign_ins` are the agents and accounts, as
    `(client_id, account_id)`, with a sign-in not ended — each one ended
    whole by `CompanyService.disconnect`.
    """

    operations: tuple[Operation, ...] = ()
    sign_ins: tuple[tuple[str, str], ...] = ()

    @property
    def empty(self) -> bool:
        return not self.operations and not self.sign_ins


#: How long a request for an operation being performed waits before trying again.
_PERFORMING_RETRY_AFTER = "5"


@dataclass(frozen=True)
class _Asked:
    """What a request asks for: the action, its terms now, and the request's fingerprint."""

    action: str
    #: The `OperationProposal` key: requests with the same one are the same operation.
    key: str
    summary: str
    terms: dict[str, Any] | None
    scopes: tuple[str, ...]
    #: The request's fingerprint, and what the action said for it.
    request: str
    digest: str


@dataclass(frozen=True)
class _Decision:
    """What an operation's request comes to, whichever interface it came through.

    `operation`: ask for approval of this revision. `outcome`: it was performed, the
    response as it would have been without operations. Neither: it is being performed.
    """

    operation: Operation | None = None
    outcome: OperationOutcome | None = None


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


#: A 401 challenge with no error code: the request needs the account and has no
#: access token; its `scope` names the scopes needed (§7, RFC 6750 §3.1).
_SIGNED_OUT = ""


def _needs_account(account_id: str | None, scopes: Sequence[str]) -> _RefusedError:
    """The refusal of a request that needs `scopes` of the account (§5.4, §7).

    Signed out (no access token): a 401 challenge with `scope` and no error code.
    Signed in without them: `insufficient_scope` (HTTP 403), naming them.
    """

    if account_id is None:
        return _RefusedError(401, _SIGNED_OUT, scope=" ".join(scopes))
    return _RefusedError(403, "insufficient_scope", scope=" ".join(scopes))


class _RateLimitedError(_RefusedError):
    """The host's rate limit refused the request: `429` and when to ask again (§5.6)."""

    def __init__(self, retry_after: int) -> None:
        super().__init__(429, "rate_limited")
        self.retry_after = retry_after


#: What a company with no issuer doesn't serve (§3.2).
_OAUTH_PATHS = ("/oauth/", "/.well-known/oauth-")
#: A proof's refusals: challenged as `DPoP`, the one scheme that has proofs (RFC 9449 §7.1).
_PROOF_REFUSALS = frozenset({"invalid_dpop_proof", "use_dpop_nonce"})
_CHALLENGED = frozenset({"invalid_token", "insufficient_scope", _SIGNED_OUT, *_PROOF_REFUSALS})


def _json_error(
    status: int,
    error: str,
    headers: Mapping[str, str] | None = None,
    *,
    schemes: Sequence[str] = ("Bearer",),
    **extra: object,
) -> CompanyResponse:
    """A JSON error; a token error at 401 or 403 in `WWW-Authenticate` too (§7).

    A signed-out request for the account gets the challenge alone: no error code,
    no body. `invalid_session` is a JSON body, HTTP 400 (§5.3).
    """

    out = {"Cache-Control": "no-store", **(headers or {})}
    if error in _CHALLENGED and status in {401, 403}:
        out["WWW-Authenticate"] = _challenges(schemes, error, extra)
    if error == _SIGNED_OUT:
        return CompanyResponse(status, None, out)
    return CompanyResponse(status, {"error": error, **extra}, out)


def _challenge(scheme: str, error: str, extra: Mapping[str, object]) -> str:
    """One `WWW-Authenticate` challenge with the error's `scope`, `extension`, metadata URL."""

    parts = [f'error="{error}"'] if error else []
    for name in ("scope", "extension", "resource_metadata"):
        value = extra.get(name)
        if isinstance(value, str):
            parts.append(f'{name}="{value}"')
    return f"{scheme} {', '.join(parts)}" if parts else scheme


def _challenges(schemes: Sequence[str], error: str, extra: Mapping[str, object]) -> str:
    """A challenge for each scheme the resource accepts (§7)."""

    named = ("DPoP",) if error in _PROOF_REFUSALS else schemes
    return ", ".join(_challenge(scheme, error, extra) for scheme in named)


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
#: The code a refusal without a body is reported under (§5.6).
_NO_BODY_CODES = {429: "rate_limited"}

#: The route a request took, for telemetry: its path's first part, never an ID.
_NAMED_ROUTES = frozenset(
    {
        "oauth_token",
        "oauth_authorize",
        "oauth_device",
        "oauth_revoke",
        "poppy_browser_session",
        "poppy_conversations",
        "poppy_feedback",
    }
)
_ROUTES: dict[str, str] = {
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
        #: Verified delegations, until each expires (§5.2: a resource MAY cache them).
        self.delegations = DelegationCache()

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
                "pap.company.issuer": self.config.identifier,
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
        code = error if isinstance(error, str) else _NO_BODY_CODES.get(response.status, "refused")
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

    def _report_session(self, *, signed_in: bool, interface: str | None = None) -> None:
        """A Session started here; or a request moved one to the MCP server or the website."""

        if interface is not None:
            self._report(
                "pap.company.interface.switch",
                "ok",
                {"pap.interface": interface, "pap.session.signed_in": signed_in},
            )
            return
        self._report("pap.company.session.start", "ok", {"pap.session.signed_in": signed_in})

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
            if not self.config.oauth and path.startswith(_OAUTH_PATHS):
                # No issuer: a 404 is how an agent learns it (§3.2).
                return _json_error(404, "not_found")
            if host in self.config.aliases:
                # An alias publishes the company's discovery document, and nothing else (§3).
                if method == "GET" and path == "/.well-known/poppy.json":
                    return CompanyResponse(200, self.discovery_document(host))
                if method == "GET" and path == "/.well-known/oauth-protected-resource":
                    return CompanyResponse(200, self.domain_resource_metadata(host))
                return _json_error(404, "not_found")
            if method == "GET" and path == "/.well-known/poppy.json":
                return CompanyResponse(200, self.discovery_document())
            if method == "GET" and path == "/.well-known/oauth-protected-resource":
                return CompanyResponse(200, self.domain_resource_metadata())
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
            if method == "POST" and path == "/poppy/browser-session/authorize" and self.config.web:
                return await self._authorize_join(request)
            if (
                method == "GET"
                and path == "/poppy/excluded-tasks.json"
                and self.config.excluded_tasks
            ):
                return CompanyResponse(
                    200, {"tasks": [dict(task) for task in self.config.excluded_tasks]}
                )
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
            if path == "/poppy/conversations" and method == "POST":
                return await self._start_conversation(request)
            if path.startswith("/poppy/conversations/"):
                return await self._conversation_route(request, method, path)
            if method == "POST" and path == "/poppy/feedback" and self.config.feedback:
                return await self._feedback(request)
        except _RateLimitedError as limited:
            return self._rate_limited(limited.retry_after)
        except _RefusedError as refused:
            return _json_error(
                refused.status,
                refused.error,
                refused.headers,
                schemes=self.config.token_schemes,
                **refused.extra,
            )
        except (SessionError, ProofError) as error:
            status = error.status_code or (401 if error.code == "invalid_client" else 400)
            if error.code == "invalid_session":
                # A JSON body, HTTP 400, whichever check failed (§5.3).
                return _json_error(400, "invalid_session")
            return _json_error(status, error.code)
        except (ProtocolValidationError, ValidationError):
            # A body that is not JSON, or not the shape the protocol defines: the
            # caller's mistake, never the company's (no 500).
            return _json_error(400, "invalid_request")
        return _json_error(404, "not_found")

    # Discovery ---------------------------------------------------------------------

    def discovery_document(  # noqa: C901 - one branch per member
        self, domain: str | None = None
    ) -> dict[str, Any]:
        """The discovery document published at `domain`: the company's own, or one of its
        aliases, which it names as the organization's domain; its endpoints stay on `base`.

        Every domain's document has the same `auth`, which describes the issuer (§3.2).
        """
        config = self.config
        organization = config.organization_domain(domain)
        document: dict[str, Any] = {
            "protocol_version": PROTOCOL_PROFILE,
            "organization": {"name": config.name, "domain": organization},
            "agent": {"protocols": [{"type": "poppy", "endpoint": config.conversations_endpoint}]},
        }
        if config.oauth:
            # Direct and Device Sign-In are the issuer's grants, not listed here (§3.2, §4.4).
            auth: dict[str, Any] = {"issuer": config.base}
            auth["scopes"] = {scope: config.scope_descriptions[scope] for scope in config.scopes}
            if config.scope_hints:
                auth["scope_hints"] = {
                    scope: {"changes": changes, "personal_data": personal}
                    for scope, (changes, personal) in config.scope_hints.items()
                }
            document["auth"] = auth
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
        extensions: dict[str, Any] = {}
        if config.operations:
            extensions[OPERATIONS_EXTENSION] = {"version": OPERATIONS_VERSION}
        if config.mediated_fields:
            extensions[MEDIATED_EXTENSION] = {
                "version": MEDIATED_VERSION,
                "fields": [
                    {"name": name, "label": label, "secret": secret}
                    for name, label, secret in config.mediated_fields
                ],
                "scopes": list(config.mediated_grant_scopes),
            }
        if extensions:
            document["extensions"] = extensions
        return document

    def domain_resource_metadata(self, domain: str | None = None) -> dict[str, Any]:
        """RFC 9728 metadata of `https://{domain}`, naming the issuer (§3.2).

        Published by the company's own domain and each alias: `resource` is exactly
        `https://{domain}` and its one authorization server is the company's issuer.
        """

        organization = self.config.organization_domain(domain)
        return {
            "resource": f"https://{organization}",
            "authorization_servers": [self.config.base],
            "scopes_supported": list(self.config.scopes),
            "bearer_methods_supported": ["header"],
        }

    def protected_resource_metadata(self) -> dict[str, Any]:
        """RFC 9728 metadata for the MCP server: its `url`, and the company's issuer (§7).

        Its `resource` is the server's own: it accepts only access tokens issued for
        it (§4.5).
        """

        return {
            "resource": self.config.mcp_url,
            "authorization_servers": [self.config.base],
            "scopes_supported": list(self.config.scopes),
            "bearer_methods_supported": ["header"],
        }

    def oauth_metadata(self) -> dict[str, Any]:
        config = self.config
        grants = [REFRESH_TOKEN_GRANT]
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
        }
        if self._mcp() is not None:
            metadata["protected_resources"].append(config.mcp_url)
        if config.direct:
            grants.append(AUTHORIZATION_CODE_GRANT)
            metadata["authorization_endpoint"] = config.authorization_endpoint
            metadata["code_challenge_methods_supported"] = ["S256"]
        if config.device:
            grants.append(DEVICE_CODE_GRANT)
            metadata["device_authorization_endpoint"] = config.device_endpoint
        if config.mediated_fields:
            grants.append(MEDIATED_GRANT)
        if config.dpop_binding != "off":
            metadata["dpop_signing_alg_values_supported"] = [DPOP_ALGORITHM]
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
        exchange = _EXCHANGE.get()
        if exchange is not None:
            exchange.client_id = client_id
        await self._remember_client(client_id, metadata)
        return client_id

    async def _remember_client(self, client_id: str, metadata: ClientMetadata) -> None:
        """What a personal agent declares, kept whichever request verified it first."""

        extensions = {name: item.version for name, item in metadata.extensions.items()}
        known = await self._read(CLIENT, client_id, KnownClient.from_json)
        if known is None or known.extensions != extensions:
            await self.store.put(CLIENT, client_id, KnownClient(extensions).to_json())
            # Its identity verified for the first time, or with new metadata.
            self._report("pap.company.identity.check", "ok", {})

    async def _allowed(self, client_id: str) -> bool:
        """The company's policy on this agent, asked before anything is fetched for it.

        A blocked `client_id` is never resolved (no metadata or keys fetched from
        its domain), and a blocked agent's tokens stop working at once.
        """

        policy = cast(ClientPolicy, first_contribution(self.reactor, CLIENT_POLICIES, "policy"))
        return bool(await policy.allows(client_id))

    async def _supports_operations(self, client_id: str) -> bool:
        """Whether the agent listed this version of Operations when it last authenticated."""

        known = await self._read(CLIENT, client_id, KnownClient.from_json)
        return (
            known is not None and known.extensions.get(OPERATIONS_EXTENSION) == OPERATIONS_VERSION
        )

    async def _token(self, request: CompanyRequest) -> CompanyResponse:
        """The token endpoint (§4): every grant carries a client assertion, and nothing else.

        The refresh grant issues an access token, for a `resource` this company
        serves when one is named (RFC 8707); the code and device grants sign in.
        No Session is named: any of the User's Sessions uses the access token (§5.4).
        """

        form = dict(parse_qsl(request.body.decode()))
        grant = form.get("grant_type")
        client_id = await self._client(form)
        # Before any grant is used: a proof refused spends no code.
        jkt = await self._token_binding(request)
        if grant == REFRESH_TOKEN_GRANT:
            return await self._refresh_grant(form, client_id, jkt)
        if grant == AUTHORIZATION_CODE_GRANT and self.config.direct:
            return await self._code_grant(form, client_id, jkt)
        if grant == DEVICE_CODE_GRANT and self.config.device:
            return await self._device_grant(form, client_id, jkt)
        if grant == MEDIATED_GRANT and self.config.mediated_fields:
            # The request itself uses the extension: no client metadata entry is asked
            # for, and `extension_required` can't refuse it (§3.3).
            return await self._mediated_grant(form, client_id, jkt)
        raise _RefusedError(400, "unsupported_grant_type")

    async def _token_binding(self, request: CompanyRequest) -> str | None:
        """The thumbprint the tokens of this request are bound to, or `None` for Bearer."""

        if self.config.dpop_binding == "off":
            return None
        if request.headers.get("dpop"):
            return await self._dpop_proof(request, status=400)
        if self.config.dpop_binding == "required":
            raise _RefusedError(400, "invalid_dpop_proof")
        return None

    async def _dpop_proof(
        self,
        request: CompanyRequest,
        *,
        status: int,
        access_token: str | None = None,
        bound_to: str | None = None,
    ) -> str:
        """Check the request's proof (RFC 9449 §4.3): its key's thumbprint.

        `status` is the endpoint's: 400 at the token endpoint, as OAuth errors are,
        and 401 at a resource. `bound_to` is the key an access token needs. With
        `dpop_nonces`, a proof with no nonce the company gave is `use_dpop_nonce`, with
        one in `DPoP-Nonce`.
        """

        proof = request.headers.get("dpop")
        if not proof:
            raise _RefusedError(status, "invalid_dpop_proof")
        try:
            verified = await verify_dpop_proof(
                proof,
                method=request.method,
                url=request.url,
                replay_cache=self._replay(),
                now=self._now(),
                window=self.config.dpop_proof_window,
                access_token=access_token,
            )
        except ProofError as exc:
            raise _RefusedError(status, "invalid_dpop_proof") from exc
        if bound_to is not None and not hmac.compare_digest(verified.thumbprint, bound_to):
            raise _RefusedError(status, "invalid_dpop_proof")
        if self.config.dpop_nonces and not await self._dpop_nonce_given(verified.nonce):
            raise _RefusedError(
                status, "use_dpop_nonce", headers={"DPoP-Nonce": await self._give_dpop_nonce()}
            )
        return verified.thumbprint

    async def _give_dpop_nonce(self) -> str:
        nonce = self._id("nonce")
        await self.store.put(
            DPOP_NONCE,
            nonce,
            IssuedNonce().to_json(),
            expires_at=self._now() + self.config.dpop_nonce_lifetime,
        )
        return nonce

    async def _dpop_nonce_given(self, nonce: str | None) -> bool:
        return nonce is not None and await self.store.get(DPOP_NONCE, nonce) is not None

    def _resource(self, form: Mapping[str, str]) -> str | None:
        """The `resource` a token is issued for (RFC 8707, §4.5): one this company serves.

        `https://{domain}` (or an alias's) is the default token's, `None`; the MCP
        server's `url` gets a token for it alone; anything else is `invalid_target`.
        """

        resource = form.get("resource")
        if resource is None:
            return None
        if resource in {
            f"https://{domain}" for domain in (self.config.domain, *self.config.aliases)
        }:
            return None
        if self._mcp() is not None and resource == self.config.mcp_url:
            return resource
        raise _RefusedError(400, "invalid_target")

    def _account_scopes(self) -> tuple[str, ...]:
        """The scopes that read the account: the company's scopes that change nothing."""

        read = tuple(scope for scope in self.config.scopes if scope not in self.config.write_scopes)
        return read or self.config.scopes

    async def _refresh_grant(
        self, form: Mapping[str, str], client_id: str, jkt: str | None
    ) -> CompanyResponse:
        """An access token from a refresh token, which is rotated (§4.4).

        Narrower scopes only; `resource` for one service. Exactly one refresh claims
        the presented token, which stops working the moment it is claimed.
        """

        resource = self._resource(form)
        presented = _digest(form.get("refresh_token", ""))
        entry = await self.store.get(REFRESH_TOKEN, presented)
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
        requested = tuple(scope for scope in form.get("scope", "").split(" ") if scope)
        if requested and any(scope not in grant.scopes for scope in requested):
            raise _RefusedError(400, "invalid_scope")
        if not self._offers(requested or grant.scopes):
            # A scope the company no longer offers (a rollback, a narrower version): asked
            # within what it offers now, the same refresh token still serves.
            raise _RefusedError(400, "invalid_scope")
        if not await self.store.replace(
            REFRESH_TOKEN,
            presented,
            entry.version,
            replace(grant, revoked=True).to_json(),
            expires_at=entry.expires_at,
        ):
            raise _RefusedError(400, "invalid_grant")
        rotated = self._id("rt")
        await self.store.put(
            REFRESH_TOKEN,
            _digest(rotated),
            replace(grant, revoked=False).to_json(),
            expires_at=grant.expires_at,
        )
        if not await self._join_family(grant.family, refresh_token=_digest(rotated)):
            # The sign-in was revoked meanwhile: its new token is too.
            await self._revoke_grants((_digest(rotated),))
            raise _RefusedError(400, "invalid_grant")
        response = await self._issue(
            client_id=client_id,
            account_id=grant.account_id,
            scopes=requested or grant.scopes,
            family=grant.family,
            resource=resource,
            refresh_token=rotated,
            # A refresh naming no scope gets them in the response: the agent can't know.
            requested=requested,
            jkt=jkt,
        )
        family = await self._read(ACCOUNT_FAMILY, grant.family, AccountFamily.from_json)
        if family is None or family.revoked:
            # Revoked while this token was issued: it ends with its sign-in (§5.5).
            await self._sign_out((grant.family,))
            raise _RefusedError(400, "invalid_grant")
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
        self, form: Mapping[str, str], client_id: str, jkt: str | None
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
        # Consumed once: of concurrent polls, only the one that takes it signs in.
        taken = await self.store.take(DEVICE, key)
        approved = None if taken is None else PendingDevice.from_json(taken)
        if approved is None or approved.account_id is None:
            raise _RefusedError(400, "invalid_grant")
        await self.store.delete(USER_CODE, approved.user_code)
        return await self._sign_in(
            client_id, approved.account_id, approved.granted, requested=approved.scopes, jkt=jkt
        )

    async def _forget_device(self, key: str, pending: PendingDevice) -> None:
        await self.store.delete(DEVICE, key)
        await self.store.delete(USER_CODE, pending.user_code)

    async def _revoke(self, request: CompanyRequest) -> CompanyResponse:
        form = dict(parse_qsl(request.body.decode()))
        client_id = await self._client(form)
        grant = await self._read(
            REFRESH_TOKEN, _digest(form.get("token", "")), AccountGrant.from_json
        )
        if grant is not None and grant.client_id == client_id:
            # The token and every one rotated from the same sign-in, and the access tokens
            # they gave (RFC 7009 §2.1): the Sessions continue signed out (§5.5).
            await self._sign_out((grant.family,))
        return CompanyResponse(200, {}, {"Cache-Control": "no-store"})

    async def _sign_out(self, families: Collection[str]) -> int:
        """Revoke whole sign-ins: their refresh and access tokens stop working.

        Returns how many refresh tokens this revoked (the others already were).
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
            for digest in family.access_tokens:
                await self.store.delete(ACCESS_TOKEN, digest)
        return revoked

    async def _revoke_grants(self, tokens: Collection[str]) -> int:
        revoked = 0
        for token in tokens:
            changed = await self._change(
                REFRESH_TOKEN,
                token,
                AccountGrant.from_json,
                lambda grant: grant if grant.revoked else replace(grant, revoked=True),
            )
            revoked += changed is not None and not changed[0].revoked
        return revoked

    async def _join_family(
        self,
        family_id: str,
        *,
        refresh_token: str | None = None,
        access_token: str | None = None,
    ) -> bool:
        """Add a refresh or an access token to a sign-in; `False` once it is revoked."""

        changed = await self._change(
            ACCOUNT_FAMILY,
            family_id,
            AccountFamily.from_json,
            lambda family: (
                family
                if family.revoked
                else replace(
                    family,
                    tokens=_with(family.tokens, refresh_token),
                    access_tokens=_with(family.access_tokens, access_token),
                )
            ),
        )
        return changed is not None and not changed[1].revoked

    async def disconnect(self, client_id: str, account_id: str) -> int:
        """The user disconnects an agent in account settings: its tokens go (§5.5).

        Returns how many refresh tokens were revoked (upstream guides, account settings).
        """

        agent = await self._read(
            ACCOUNT_AGENT, _composite(client_id, account_id), AccountAgent.from_json
        )
        return 0 if agent is None else await self._sign_out(agent.families)

    async def _sign_in(
        self,
        client_id: str,
        account_id: str,
        scopes: tuple[str, ...],
        *,
        requested: tuple[str, ...],
        jkt: str | None,
    ) -> CompanyResponse:
        """A sign-in: a new refresh token, and an access token (§4.7).

        `scopes` are the ones the user approved of those `requested`; the response
        leaves `scope` out when they are the same (RFC 6749 §5.1). Plain OAuth: no
        Session is named or signed in here (§5.4).
        """

        if not scopes:
            # A sign-in grants at least one scope: approving none is a decline (§4.7).
            raise _RefusedError(400, "access_denied")
        refresh_token = self._id("rt")
        family = _digest(refresh_token)
        expires_at = self._now() + self.config.refresh_token_lifetime
        await self.store.put(
            REFRESH_TOKEN,
            family,
            AccountGrant(
                account_id=account_id,
                client_id=client_id,
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
            AccountFamily(client_id=client_id, account_id=account_id, tokens=(family,)).to_json(),
            expires_at=expires_at,
        )
        await self._remember_family(client_id, account_id, family)
        return await self._issue(
            client_id=client_id,
            account_id=account_id,
            scopes=scopes,
            family=family,
            resource=None,
            refresh_token=refresh_token,
            requested=requested,
            jkt=jkt,
        )

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
        *,
        client_id: str,
        account_id: str,
        scopes: tuple[str, ...],
        family: str,
        resource: str | None,
        refresh_token: str | None,
        requested: tuple[str, ...],
        jkt: str | None,
    ) -> CompanyResponse:
        """A token response (§4.7): an access token, and the refresh token if any.

        Bearer, or `DPoP` bound to the key `jkt` names; a refresh token is never bound
        (RFC 9449 §5). `scope` follows RFC 6749: left out when it grants exactly the
        scopes requested.
        """

        access_token = self._id("at")
        digest = _digest(access_token)
        expires_at = self._now() + self.config.access_token_lifetime
        await self.store.put(
            ACCESS_TOKEN,
            digest,
            IssuedAccessToken(
                client_id=client_id,
                account_id=account_id,
                scopes=scopes,
                expires_at=expires_at,
                family=family,
                resource=resource,
                dpop_jkt=jkt,
            ).to_json(),
            expires_at=expires_at,
        )
        if not await self._join_family(family, access_token=digest):
            await self.store.delete(ACCESS_TOKEN, digest)
            raise _RefusedError(400, "invalid_grant")
        body: dict[str, object] = {
            "access_token": access_token,
            "token_type": "Bearer" if jkt is None else "DPoP",
            "expires_in": int(self.config.access_token_lifetime.total_seconds()),
        }
        if set(scopes) != set(requested):
            body["scope"] = " ".join(scopes)
        if refresh_token is not None:
            body["refresh_token"] = refresh_token
        return CompanyResponse(200, body, {"Cache-Control": "no-store"})

    async def _access_token(self, token: str) -> IssuedAccessToken | None:
        """The access token's record while it works: issued here, unexpired, sign-in not ended."""

        issued = await self._read(ACCESS_TOKEN, _digest(token), IssuedAccessToken.from_json)
        if issued is None or self._now() >= issued.expires_at:
            return None
        grant = await self._read(REFRESH_TOKEN, issued.family, AccountGrant.from_json)
        if grant is None:
            # Its sign-in's records are gone (expired, deleted): nothing to hold it to.
            if await self._signed_out_before(issued.account_id) is not None:
                return None
        elif await self._sign_in_ended(grant):
            return None
        return issued

    async def _signed_out_before(self, account_id: str) -> datetime | None:
        accounts = optional_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        if not isinstance(accounts, AccountSignOuts):
            return None
        return await accounts.signed_out_before(account_id)

    async def _sign_in_ended(self, grant: AccountGrant) -> bool:
        """Whether the account's sign-ins ended after this one: then it ends, whole.

        A password reset, an account locked: its refresh tokens are revoked and its
        access tokens stop working (`_sign_out`).
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
        self, form: Mapping[str, str], client_id: str, jkt: str | None
    ) -> CompanyResponse:
        taken = await self.store.take(CODE, _digest(form.get("code", "")))
        issued = None if taken is None else IssuedCode.from_json(taken)
        if (
            issued is None
            or self._now() >= issued.expires_at
            or issued.client_id != client_id
            or issued.redirect_uri != form.get("redirect_uri")
        ):
            # Expired, reused, another agent's, or for another redirect (§4.2).
            raise _RefusedError(400, "invalid_grant")
        verifier = form.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(
            b"="
        )
        if not hmac.compare_digest(challenge.decode(), issued.code_challenge):
            raise _RefusedError(400, "invalid_grant")
        return await self._sign_in(
            client_id, issued.account_id, issued.scopes, requested=issued.requested, jkt=jkt
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

    # OpenAPI API (§6, Operations 4, 6) -----------------------------------------------------

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
        session: CallerSession,
        body: Any,
    ) -> CompanyResponse:
        negotiated = await self._supports_operations(session.client_id)
        approval = (
            parse_approval_header(request.headers.get(APPROVAL_HEADER.lower()))
            if negotiated
            else None
        )
        target = await self._approval_target(session, approval)
        settled = None if target is None else self._settled(target)
        if settled is not None:
            return self._api_decision(settled)
        result: ApiResult = await cast(CompanyApi, self._api()).handle(
            ApiCall(
                method=method,
                path=path.removeprefix("/api"),
                query=dict(parse_qsl(urlsplit(request.url).query)),
                body=body,
                account_id=session.account_id,
                scopes=session.scopes,
                client_id=session.client_id,
                carries_approval=approval is not None,
            )
        )
        if result.operation is None:
            body = result.body if isinstance(result.body, dict) else {}
            if result.status == 403 and body.get("error") == "insufficient_scope":
                # In the challenge, and signed out with no error code (§7).
                raise _needs_account(session.account_id, str(body.get("scope", "")).split(" "))
            return CompanyResponse(result.status, result.body)
        if not negotiated:
            # At an API, in the WWW-Authenticate challenge with its `extension` (§3.3, §7).
            raise _RefusedError(
                403,
                "extension_required",
                headers={
                    "WWW-Authenticate": _challenges(
                        self.config.token_schemes,
                        "extension_required",
                        {"extension": "operations"},
                    )
                },
                extension="operations",
            )
        fingerprint = _fingerprint("api", method, path, urlsplit(request.url).query, body)
        asked = self._asked(session, result.operation, fingerprint)
        return self._api_decision(await self._decide(session, asked, approval, target))

    @staticmethod
    def _api_decision(decision: _Decision) -> CompanyResponse:
        """The API's answer: the operation, what it came to, or `503` while it is performed."""

        if decision.operation is not None:
            return _json_error(
                403, "approval_required", operation=decision.operation.model_dump(mode="json")
            )
        outcome = decision.outcome
        if outcome is None:
            return _json_error(
                503, "temporarily_unavailable", {"Retry-After": _PERFORMING_RETRY_AFTER}
            )
        body: dict[str, Any] = {"summary": outcome.summary}
        if outcome.data is not None:
            body["data"] = outcome.data
        if outcome.succeeded:
            return CompanyResponse(200, body)
        # It didn't finish: an API error, saying every change that was made.
        return CompanyResponse(422, {"error": ACTION_FAILED, **body})

    # Resource requests ---------------------------------------------------------------

    async def _caller(  # noqa: C901 - the checks of §5.3 and §7, in order
        self, request: CompanyRequest, *, resource: str | None = None
    ) -> tuple[str, CallerSession]:
        """Verify the request's Session header, and its access token if any (§5.3, §7).

        `resource` is the service the request is for: `None` for the company's own
        endpoints, which take the default token, or the MCP server's `url`. Returns
        the access token's digest (or `""`) and the caller's Session. A token bound with
        DPoP needs the `DPoP` scheme and a proof by its key; an unbound one is sent as
        `Bearer` (§4.5, RFC 9449 §7.1), each after the Session header's checks.
        """

        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        kind = scheme.lower()
        accepted = kind == "bearer" or (kind == "dpop" and self.config.dpop_binding != "off")
        presented = token if accepted and token else None
        if request.headers.get("authorization") and presented is None:
            raise _RefusedError(401, "invalid_token")
        header = request.headers.get(SESSION_HEADER)
        if not header:
            # A copied access token is useless without the agent's key (§5.3); and every
            # request names its Session (§5.2).
            raise SessionError("invalid_session", "No Session header", status_code=400)
        client_id = unverified_session_issuer(header)
        if not await self._allowed(client_id):
            # A refused personal agent: `invalid_session` at a resource (§4.1).
            raise SessionError("invalid_session", "Refused agent", status_code=400)
        resolver = cast(
            ClientResolver, first_contribution(self.reactor, CLIENT_RESOLVERS, "client resolver")
        )

        declared: ClientMetadata | None = None

        async def resolve(agent: str, kid: str | None) -> tuple[ClientMetadata, JsonWebKeySet]:
            nonlocal declared
            declared, keys = await resolver.resolve(agent, kid=kid)
            return declared, keys

        verified = await verify_session_jwt(
            header,
            issuer=self.config.identifier,
            method=request.method,
            url=request.url,
            resolve=resolve,
            replay_cache=self._replay(),
            now=self._now(),
            access_token=presented,
            delegations=self.delegations,
            window=self.config.session_jwt_window,
        )
        exchange = _EXCHANGE.get()
        if exchange is not None:
            exchange.client_id = verified.client_id
        # A request can be the agent's first: a Session needs no OAuth endpoint (§4). Only now
        # is its identity verified, so a forged JWT is never reported as a check, or remembered.
        if declared is not None:
            await self._remember_client(verified.client_id, declared)
        issued: IssuedAccessToken | None = None
        if presented is not None:
            issued = await self._access_token(presented)
            if issued is not None and issued.client_id != verified.client_id:
                # Issued to another agent than the Session JWT's (§5.3).
                raise SessionError("invalid_session", "Token of another agent", status_code=400)
            if issued is None or not self._offers(issued.scopes):
                raise _RefusedError(401, "invalid_token")
            if issued.resource != resource:
                # Not issued for this service: where to read which one it is (§4.5, §7).
                raise _RefusedError(
                    401, "invalid_token", resource_metadata=self._resource_metadata_url(resource)
                )
            if (issued.dpop_jkt is not None) != (kind == "dpop"):
                raise _RefusedError(401, "invalid_token")
            if issued.dpop_jkt is not None:
                await self._dpop_proof(
                    request, status=401, access_token=presented, bound_to=issued.dpop_jkt
                )
        session_key = await self._session(verified)
        session = CallerSession(
            session_key=session_key,
            client_id=verified.client_id,
            sid=verified.sid,
            pairwise_user_id=verified.sub,
            agent_id=verified.agent_id,
            account_id=None if issued is None else issued.account_id,
            scopes=() if issued is None else issued.scopes,
            family=None if issued is None else issued.family,
            resource=resource,
        )
        wait = await self._admitted(session)
        if wait is not None:
            raise _RateLimitedError(wait)
        return ("" if presented is None else _digest(presented)), session

    def _resource_metadata_url(self, resource: str | None) -> str:
        """The protected resource metadata URL of the service a request was for (RFC 9728)."""

        if resource == self.config.mcp_url:
            return self.config.mcp_resource_metadata
        return f"{self.config.base}/.well-known/oauth-protected-resource"

    async def _session(self, verified: Any) -> str:
        """The Session by `client_id` and `sid`: started when unknown, checked when known (§5.3).

        A known Session keeps its User ID and Agent ID; one that has ended, and is
        still remembered, is `invalid_session` (§5.5).
        """

        key = _composite(verified.client_id, verified.sid)
        now = self._now()
        for _ in range(_CAS_ATTEMPTS):
            known = await self._read(SESSION, key, StoredSession.from_json)
            if known is None:
                started = StoredSession(
                    client_id=verified.client_id,
                    sid=verified.sid,
                    pairwise_user_id=verified.sub,
                    agent_id=verified.agent_id,
                    ends_at=now + self.config.session_lifetime,
                )
                if await self.store.create(
                    SESSION,
                    key,
                    started.to_json(),
                    expires_at=started.ends_at + self.config.ended_session_memory,
                ):
                    self._report_session(signed_in=False)
                    return key
                continue
            if known.ended or now >= known.ends_at:
                raise SessionError("invalid_session", "The Session has ended", status_code=400)
            if (known.pairwise_user_id, known.agent_id) != (verified.sub, verified.agent_id):
                # A Session keeps its User ID and Agent ID, or none, for its life (§5.2).
                raise SessionError("invalid_session", "Another User's Session", status_code=400)
            return key
        raise _RefusedError(503, "temporarily_unavailable")

    async def end_session(self, client_id: str, sid: str) -> bool:
        """The company ends a Session: requests naming its `sid` get `invalid_session` (§5.5).

        Remembered for `ended_session_memory`. Returns whether a Session was ended.
        """

        key = _composite(client_id, sid)
        changed = await self._change(
            SESSION,
            key,
            StoredSession.from_json,
            lambda stored: stored if stored.ended else replace(stored, ended=True),
        )
        return changed is not None and not changed[0].ended

    async def _admitted(self, session: CallerSession) -> int | None:
        """The host's rate limit on this agent and its signed-in account: seconds to wait, or
        None."""

        limit = optional_contribution(self.reactor, COMPANY_RATE_LIMITS, "rate limit")
        if limit is None:
            return None
        wait = await cast(RateLimit, limit).admit(session.client_id, session.account_id)
        return None if wait is None else max(1, int(wait))

    # Mediated Sign-In attempt limits (§4.7: a company MUST rate-limit attempts) ---------

    def _attempt_keys(self, client_id: str, credentials: Mapping[str, object]) -> tuple[str, ...]:
        """What a credential attempt counts against: the account, and the `client_id`.

        The account is named by the declared fields that are not secret (an
        email, a username), normalized; its password is never part of a key.
        """

        keys = [f"{_CLIENT_ATTEMPTS}{_composite(client_id)}"]
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
                limit = (
                    config.max_client_sign_in_failures
                    if key.startswith(_CLIENT_ATTEMPTS)
                    else config.max_sign_in_failures
                )
                if failures >= limit:
                    over = min(failures - limit, 7)
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
        """HTTP 429 and `Retry-After`, and no body (§5.6)."""

        return CompanyResponse(
            429, None, {"Retry-After": str(retry_after), "Cache-Control": "no-store"}
        )

    async def _mediated_grant(
        self, form: Mapping[str, str], client_id: str, jkt: str | None
    ) -> CompanyResponse:
        """The grant's first request: credentials and `scope` (Mediated Sign-In 3)."""

        if "sign_in_id" in form or "one_time_code" in form:
            return await self._mediated_code(form, client_id, jkt)
        config = self.config
        granted = tuple(s for s in form.get("scope", "").split(" ") if s)
        if not granted or any(s not in config.mediated_grant_scopes for s in granted):
            # Missing, unknown, or unavailable scopes are refused, never narrowed.
            raise _RefusedError(400, "invalid_scope")
        credentials = {name: form.get(name) for name, _, _ in config.mediated_fields}
        if any(value is None for value in credentials.values()):
            raise _RefusedError(400, "invalid_request")
        keys = self._attempt_keys(client_id, credentials)
        locked = await self._locked_for(keys)
        if locked is not None:
            # Locked out: the credentials are not even checked.
            credentials.clear()
            raise _RateLimitedError(locked)
        accounts = cast(
            AccountDirectory, first_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        )
        secrets = {name: SecretStr(str(value)) for name, value in credentials.items()}
        credentials.clear()
        try:
            authenticated = await accounts.authenticate(secrets, SignInContext(client_id=client_id))
        except SignInRefused as refused:
            raise _RefusedError(400, "access_denied") from refused
        finally:
            secrets.clear()
        if authenticated is None:
            await self._attempt_failed(keys)
            # The same answer for an unknown account and a wrong password.
            raise _RefusedError(400, "invalid_grant")
        code_key = self._code_key(authenticated.account_id)
        if authenticated.code_reference is None:
            await self._attempts_cleared(keys)
            return await self._sign_in(
                client_id, authenticated.account_id, granted, requested=granted, jkt=jkt
            )
        locked = await self._locked_for((code_key,))
        if locked is not None:
            # Too many wrong codes for this account: no new code until the lockout ends.
            raise _RateLimitedError(locked)
        sign_in_id = self._id("sgn")
        expires_at = self._now() + _MEDIATED_CODE_LIFETIME
        pending = PendingMediated(
            client_id=client_id,
            account_id=authenticated.account_id,
            scopes=granted,
            code_reference=authenticated.code_reference,
            sent_to=authenticated.sent_to or "your device",
            expires_at=expires_at,
            attempt_keys=keys,
        )
        await self.store.put(
            MEDIATED, sign_in_id, pending.to_json(), expires_at=expires_at + _KEPT_EXPIRED
        )
        return self._code_required(sign_in_id, pending)

    def _code_required(self, sign_in_id: str, pending: PendingMediated) -> CompanyResponse:
        """A code is on its way: send it with `sign_in_id` (Mediated Sign-In 4)."""

        left = math.ceil((pending.expires_at - self._now()).total_seconds())
        return _json_error(
            400,
            "code_required",
            sign_in_id=sign_in_id,
            sent_to=pending.sent_to,
            expires_in=max(1, left),
        )

    async def _mediated_code(
        self, form: Mapping[str, str], client_id: str, jkt: str | None
    ) -> CompanyResponse:
        """The grant's continuation: `sign_in_id` and the code, nothing else (Mediated 4)."""

        sign_in_id, code = form.get("sign_in_id"), form.get("one_time_code")
        if (
            sign_in_id is None
            or code is None
            or "scope" in form
            or any(name in form for name, _, _ in self.config.mediated_fields)
        ):
            raise _RefusedError(400, "invalid_request")
        pending = await self._read(MEDIATED, sign_in_id, PendingMediated.from_json)
        if pending is None or pending.client_id != client_id:
            # Unknown, or another client's: the same error for both.
            raise _RefusedError(400, "invalid_grant")
        if pending.status != "code_required":
            # Once failed or expired, it stays so: the same error again.
            raise _RefusedError(400, _MEDIATED_ENDED[pending.status])
        if self._now() >= pending.expires_at:
            await self._mediated_ended(sign_in_id, "expired")
        code_key = self._code_key(pending.account_id)
        if await self._locked_for((code_key,)) is not None:
            # The account's code budget is spent, whichever sign-in spent it.
            await self._mediated_ended(sign_in_id, "failed")
        accounts = cast(
            AccountDirectory, first_contribution(self.reactor, COMPANY_ACCOUNTS, "accounts")
        )
        if not await accounts.check_code(pending.code_reference, SecretStr(code)):
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
                await self._mediated_ended(sign_in_id, "failed")
            return self._code_required(sign_in_id, pending)
        # One use: of two right codes sent at once, only the one that takes it signs in.
        taken = await self.store.take(MEDIATED, sign_in_id)
        completed = None if taken is None else PendingMediated.from_json(taken)
        if completed is None or completed.status != "code_required":
            raise _RefusedError(400, "invalid_grant")
        await self._attempts_cleared((*completed.attempt_keys, code_key))
        return await self._sign_in(
            client_id, completed.account_id, completed.scopes, requested=completed.scopes, jkt=jkt
        )

    async def _mediated_ended(
        self, sign_in_id: str, status: Literal["failed", "expired"]
    ) -> NoReturn:
        """The sign-in ends as `status`, kept so a later code gets the same error."""

        def end(current: PendingMediated) -> PendingMediated:
            return current if current.status != "code_required" else replace(current, status=status)

        changed = await self._change(MEDIATED, sign_in_id, PendingMediated.from_json, end)
        ended = status if changed is None else changed[1].status
        raise _RefusedError(400, _MEDIATED_ENDED[ended])

    # Conversations -------------------------------------------------------------------

    async def _conversation(self, conversation_id: str) -> StoredConversation:
        conversation = await self._read(CONVERSATION, conversation_id, StoredConversation.from_json)
        if conversation is None:
            raise _RefusedError(404, "conversation_not_found")
        return conversation

    async def _owned(self, conversation_id: str, session: CallerSession) -> StoredConversation:
        conversation = await self._read(CONVERSATION, conversation_id, StoredConversation.from_json)
        if conversation is None or conversation.owner != (
            session.client_id,
            session.pairwise_user_id,
        ):
            raise _RefusedError(404, "conversation_not_found")
        if conversation.account_id is not None and session.account_id != conversation.account_id:
            # Once it used the account, it belongs to that account (§7.2, §7.11).
            if session.account_id is None:
                raise _needs_account(None, self._account_scopes())
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

    async def _direct_parent(self, parent_id: str, session: CallerSession) -> StoredConversation:
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

    async def _receive(  # noqa: C901 - a message, its approval, and the agent's turn
        self, conversation_id: str, session: CallerSession, message: Message
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

        negotiated = await self._supports_operations(session.client_id)
        try:
            target = await self._approval_target(session, message.approval) if negotiated else None
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
        events: list[StoredEvent] = []
        if target is not None:
            # Only `approval` approves: its message's text is no question for the agent.
            event = await self._conversation_approval(conversation_id, session, target, message)
            if event is not None:
                events.append(event)
        elif conversation.responder == "human":
            return conversation
        elif message.text is not None or message.data is not None or message.approval is None:
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
                    supports_operations=negotiated,
                )
            )
            for reply in replies:
                event = await self._reply(conversation_id, session, reply)
                if event is not None:
                    events.append(event)

        def answered(current: StoredConversation) -> StoredConversation:
            if current.status != "working":
                return replace(current, events=(*current.events, *events))
            idle = self._state("idle", current.responder)
            return replace(current, status="idle", events=(*current.events, *events, idle))

        changed = await self._change(
            CONVERSATION, conversation_id, StoredConversation.from_json, answered
        )
        return conversation if changed is None else changed[1]

    async def _conversation_approval(
        self,
        conversation_id: str,
        session: CallerSession,
        target: StoredOperation,
        message: Message,
    ) -> StoredEvent | None:
        """A message's approval: the action performed, and how it went, in a later message.

        A new message with the approval of an operation already performed, or being
        performed, adds nothing (Operations 7).
        """

        if self._settled(target) is not None:
            return None
        approval = cast(Approval, message.approval)
        latest = target.latest
        named = next(
            (item for item in target.revisions if item.revision == approval.revision), latest
        )
        asked = _Asked(
            action=target.action,
            key=target.key,
            summary=latest.summary,
            terms=latest.terms,
            scopes=target.scopes,
            request=_fingerprint("conversation", conversation_id),
            digest=named.asked,
        )
        decision = await self._decide(session, asked, approval, target)
        author: dict[str, object] = {"type": "agent"}
        reply: dict[str, object] = {"id": self._id("msg"), "author": author, "role": "company"}
        if decision.operation is not None:
            reply["text"] = "That approval doesn't cover these terms. Here they are to approve."
            reply["operation"] = decision.operation.model_dump(mode="json")
        elif decision.outcome is None:
            reply["text"] = "This is still being done. I'll say how it went here."
        else:
            reply["text"] = decision.outcome.summary
            if decision.outcome.data is not None:
                reply["data"] = decision.outcome.data
        return self._event(type="message", message=reply)

    async def _reply(
        self, conversation_id: str, session: CallerSession, reply: Reply
    ) -> StoredEvent | None:
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
        if reply.operation is not None and await self._supports_operations(session.client_id):
            fingerprint = _fingerprint("conversation", conversation_id)
            asked = self._asked(session, reply.operation, fingerprint)
            decision = await self._decide(session, asked, None, None)
            message["operation"] = cast(Operation, decision.operation).model_dump(mode="json")
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
        """Accept a report with the Session header, signed in or out, no scope needed.

        `task` (at most 200 characters) and `description` (at most 2,000) are
        required; other members are ignored. The text is kept as data for the
        operator, never acted on.
        """

        _, session = await self._caller(request)
        body = _json_object(request.body)
        task, description = body.get("task"), body.get("description")
        if (
            not isinstance(task, str)
            or not 0 < len(task) <= 200
            or not isinstance(description, str)
            or not 0 < len(description) <= 2000
        ):
            raise _RefusedError(400, "invalid_request")
        report = StoredFeedback(
            report_id=self._id("fb"),
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

    # Operations (the extension's sections 3, 6 and 7) ---------------------------------

    def _asked(self, session: CallerSession, proposal: ProposedOperation, request: str) -> _Asked:
        """What a request asks for: one action of one account, or of one signed-out Session."""

        scopes = tuple(proposal.scopes) or self.config.write_scopes
        if any(scope not in self.config.scopes for scope in scopes):
            raise ValueError("an operation's scopes must be among the company's scopes")
        return _Asked(
            action=proposal.action,
            key=_composite(
                session.client_id,
                session.pairwise_user_id,
                session.account_id or session.session_key,
                proposal.action,
                proposal.subject,
            ),
            summary=proposal.summary,
            terms=proposal.terms,
            scopes=scopes,
            request=request,
            digest=_fingerprint(proposal.summary, proposal.terms),
        )

    async def _approval_target(
        self, session: CallerSession, approval: Approval | None
    ) -> StoredOperation | None:
        """Check 1: the operation, if this Session can approve it (Operations 3, 6).

        One returned signed out can be approved only in that Session. One returned
        signed in belongs to the account: any Session of the same personal agent and
        user, signed in to it. A signed-out Session of theirs gets a challenge for the
        account, and one without its scopes `insufficient_scope`. Anyone else's request
        is handled as if it had no approval: `None`.
        """

        if approval is None:
            return None
        stored = await self._read(OPERATION, approval.operation_id, StoredOperation.from_json)
        if stored is None or stored.owner != (session.client_id, session.pairwise_user_id):
            return None
        if stored.account_id is None:
            return stored if stored.session_key == session.session_key else None
        if session.account_id is None:
            raise _needs_account(None, stored.scopes)
        if session.account_id != stored.account_id:
            return None
        if any(scope not in session.scopes for scope in stored.scopes):
            raise _needs_account(session.account_id, stored.scopes)
        return stored

    @staticmethod
    def _settled(stored: StoredOperation) -> _Decision | None:
        """Check 2: what an operation performed, or being performed, answers (Operations 7)."""

        if stored.status == "performed":
            return _Decision(outcome=stored.outcome)
        if stored.status == "performing":
            return _Decision()
        return None

    def _approves(
        self, stored: StoredOperation, revision: OperationRevision | None, asked: _Asked
    ) -> bool:
        """Check 3: a revision the company returned, unexpired, for exactly this request."""

        return (
            revision is not None
            and stored.status == "open"
            and not revision.withdrawn
            and self._now() <= revision.expires_at
            and revision.request == asked.request
            and revision.asked == asked.digest
        )

    async def _decide(
        self,
        session: CallerSession,
        asked: _Asked,
        approval: Approval | None,
        target: StoredOperation | None,
    ) -> _Decision:
        """Checks 1 and 2 passed for `target`, if any: check 3, then perform or ask."""

        if target is not None and approval is not None:
            revision = next(
                (item for item in target.revisions if item.revision == approval.revision), None
            )
            if self._approves(target, revision, asked):
                return await self._perform(target, cast(OperationRevision, revision))
        current = target if target is not None and target.key == asked.key else None
        if current is None or current.status != "open":
            current = await self._open_operation(asked.key)
        named = None if approval is None else approval.revision
        return _Decision(operation=await self._revision_for(session, current, asked, named))

    async def _open_operation(self, key: str) -> StoredOperation | None:
        known = await self._read(PROPOSAL, key, OperationProposal.from_json)
        if known is None:
            return None
        stored = await self._read(OPERATION, known.operation_id, StoredOperation.from_json)
        return stored if stored is not None and stored.status == "open" else None

    async def _revision_for(
        self,
        session: CallerSession,
        current: StoredOperation | None,
        asked: _Asked,
        named: str | None,
    ) -> Operation:
        """The revision to approve for what the request asks: never the one an approval named.

        The latest one, while it still is what this request asks. Otherwise a new one of
        the same operation, with the same terms when the company changed them since the
        action said them (`revise`), or a new operation for a new action.
        """

        expires_at = self._now() + self.config.operation_lifetime
        fresh = OperationRevision(
            revision=self._id("rev"),
            summary=asked.summary,
            terms=asked.terms,
            expires_at=expires_at,
            request=asked.request,
            asked=asked.digest,
        )
        if current is not None:
            latest = current.latest
            if self._approves(current, latest, asked) and latest.revision != named:
                return current.revision(latest)
            if latest.request == asked.request and latest.asked == asked.digest:
                fresh = replace(fresh, summary=latest.summary, terms=latest.terms)

            def extend(stored: StoredOperation) -> StoredOperation:
                if stored.status != "open":
                    return stored
                return replace(stored, revisions=(*stored.revisions, fresh))

            changed = await self._change(
                OPERATION, current.operation_id, StoredOperation.from_json, extend
            )
            if changed is not None and changed[1].status == "open":
                return changed[1].revision(fresh)
        signed_in = session.account_id is not None
        stored = StoredOperation(
            operation_id=self._id("op"),
            action=asked.action,
            owner=(session.client_id, session.pairwise_user_id),
            key=asked.key,
            revisions=(fresh,),
            account_id=session.account_id,
            session_key=None if signed_in else session.session_key,
            scopes=asked.scopes if signed_in else (),
        )
        await self.store.put(OPERATION, stored.operation_id, stored.to_json())
        await self.store.put(PROPOSAL, asked.key, OperationProposal(stored.operation_id).to_json())
        return stored.operation

    async def _perform(self, target: StoredOperation, revision: OperationRevision) -> _Decision:
        """The one compare-and-set from `open` to `performing`: only its winner performs."""

        approved_at = self._now()

        def claim(current: StoredOperation) -> StoredOperation:
            if current.status != "open":
                return current
            return replace(
                current, status="performing", approved=revision.revision, approved_at=approved_at
            )

        changed = await self._change(
            OPERATION, target.operation_id, StoredOperation.from_json, claim
        )
        if changed is None:
            return _Decision()
        before, claimed = changed
        if before.status != "open":
            return self._settled(claimed) or _Decision()
        executors = [
            contribution
            for contribution in self.reactor.get_contributions(OPERATION_EXECUTORS)
            if getattr(contribution.value, "action", None) == claimed.action
        ]
        if not executors or (len(executors) > 1 and executors[0].order == executors[1].order):
            # Nobody can perform it: being performed, rather than claim a failure.
            return _Decision()
        executor = cast(OperationExecutor, executors[0].value)
        try:
            result = await executor.perform(claimed.revision(revision), claimed.account_id)
        except OperationFailed as failed:
            # Failed partway: the result says every change that was made.
            return await self._finish(claimed, failed.result, succeeded=False)
        except OperationOutcomeUnknown:
            # Never reported as failed while it may have taken effect (Operations 7).
            return _Decision()
        return await self._finish(claimed, result, succeeded=True)

    async def _finish(
        self, claimed: StoredOperation, result: ActionResult, *, succeeded: bool
    ) -> _Decision:
        outcome = OperationOutcome(result.summary, result.data, succeeded)

        def finish(current: StoredOperation) -> StoredOperation:
            if current.status != "performing":
                return current
            return replace(current, status="performed", outcome=outcome)

        changed = await self._change(
            OPERATION, claimed.operation_id, StoredOperation.from_json, finish
        )
        return _Decision(outcome=outcome if changed is None else changed[1].outcome)

    async def operation_record(self, operation_id: str) -> StoredOperation:
        """An operation as the company keeps it: each revision, action, owner, and outcome."""

        stored = await self._read(OPERATION, operation_id, StoredOperation.from_json)
        if stored is None:
            raise KeyError(operation_id)
        return stored

    async def revise(self, operation_id: str, *, summary: str, terms: dict[str, Any]) -> Operation:
        """The company changes an operation's terms: a new revision, earlier ones withdrawn."""

        def revise(stored: StoredOperation) -> StoredOperation:
            if stored.status != "open":
                raise ValueError("only an operation not yet approved can be revised")
            latest = stored.latest
            return replace(
                stored,
                revisions=(
                    *(replace(item, withdrawn=True) for item in stored.revisions),
                    replace(
                        latest,
                        revision=self._id("rev"),
                        summary=summary,
                        terms=terms,
                        expires_at=self._now() + self.config.operation_lifetime,
                    ),
                ),
            )

        changed = await self._change(OPERATION, operation_id, StoredOperation.from_json, revise)
        if changed is None:
            raise KeyError(operation_id)
        return changed[1].operation

    async def settle(
        self, operation_id: str, result: ActionResult, *, succeeded: bool
    ) -> StoredOperation:
        """The company found out how an operation being performed ended."""

        def settle(stored: StoredOperation) -> StoredOperation:
            if stored.status != "performing":
                raise ValueError("only an operation being performed can be settled")
            return replace(
                stored,
                status="performed",
                outcome=OperationOutcome(result.summary, result.data, succeeded),
            )

        changed = await self._change(OPERATION, operation_id, StoredOperation.from_json, settle)
        if changed is None:
            raise KeyError(operation_id)
        return changed[1]

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

    def _is_open(self, stored: StoredOperation) -> bool:
        if stored.status == "performing":
            return True
        return stored.status == "open" and any(
            not item.withdrawn and self._now() <= item.expires_at for item in stored.revisions
        )

    async def open_work(self) -> OpenWork:
        """What is under way: open operations and sign-ins not ended, read from the store."""

        operations = []
        for record in await self.store.records(OPERATION):
            stored = StoredOperation.from_json(record.value)
            if self._is_open(stored):
                operations.append(stored.operation)
        sign_ins = set()
        for record in await self.store.records(ACCOUNT_FAMILY):
            family = AccountFamily.from_json(record.value)
            if not family.revoked:
                sign_ins.add((family.client_id, family.account_id))
        operations.sort(key=lambda operation: operation.operation_id)
        return OpenWork(operations=tuple(operations), sign_ins=tuple(sorted(sign_ins)))

    async def settle_open_operations(self, reason: str) -> int:
        """Settle every open operation, because of `reason` (a sentence).

        For a company being taken down: nothing will perform or settle them after, and
        a personal agent retrying an approval would otherwise wait for ever. One not
        yet approved is withdrawn, never to be performed. One being performed may have
        changed something before it stopped: a retry is told so, as a failure whose
        summary says it. Returns how many were settled.
        """

        reason = reason.strip()
        if not reason:
            raise ValueError("say why the operations are settled")
        stopped = OperationOutcome(
            summary=(
                "It was stopped before it finished, and nothing more will be done: "
                f"whatever it changed until then stands. {reason}"
            ),
            succeeded=False,
        )

        def settle(stored: StoredOperation) -> StoredOperation:
            if not self._is_open(stored):
                return stored
            if stored.status == "performing":
                return replace(stored, status="performed", outcome=stopped)
            return replace(stored, status="withdrawn")

        settled = 0
        for record in await self.store.records(OPERATION):
            operation_id = StoredOperation.from_json(record.value).operation_id
            changed = await self._change(OPERATION, operation_id, StoredOperation.from_json, settle)
            if changed is not None and self._is_open(changed[0]):
                settled += 1
        return settled

    async def end_sign_ins(self) -> int:
        """End every sign-in, as each agent's disconnect does: tokens revoked, Sessions signed out.

        Returns how many agents' sign-ins to an account were ended.
        """

        work = await self.open_work()
        for client_id, account_id in work.sign_ins:
            await self.disconnect(client_id, account_id)
        return len(work.sign_ins)

    # MCP (§4.3, §6, Operations 4, 6) -------------------------------------------------------

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
        """A token refusal at the MCP server: its challenges, with `resource_metadata`.

        RFC 9728 §5.1: so a client with stale metadata learns where to read it (§4.5,
        §7). A signed-out call for the account gets the challenge with `scope` and no
        error code.
        """

        extra: dict[str, object] = {}
        if self.config.oauth:
            extra["resource_metadata"] = self.config.mcp_resource_metadata
        if scope is not None:
            extra["scope"] = scope
        body: dict[str, object] | None = {"error": error} if error else None
        if body is not None and scope is not None:
            body["scope"] = scope
        return CompanyResponse(
            status,
            body,
            {
                "WWW-Authenticate": _challenges(self.config.token_schemes, error, extra),
                "Cache-Control": "no-store",
                **(headers or {}),
            },
        )

    async def _mcp_caller(self, request: CompanyRequest) -> CallerSession | CompanyResponse:
        """The caller at the MCP server: the Session header, and a token issued for it (§7).

        The reference MCP server accepts the Session header, so signed-out calls carry
        it alone; a token issued for another resource is `invalid_token` with
        `resource_metadata`. So is an invented one, and a request with neither token nor
        Session header gets the challenge: where a client finds how to sign in (§7). Only
        a token this company issued, without the header, is `invalid_session` (§5.3).
        """

        if self.config.oauth and not request.headers.get(SESSION_HEADER):
            _, _, presented = request.headers.get("authorization", "").partition(" ")
            if not presented:
                return self._mcp_refusal(401, "")
            if await self._access_token(presented) is None:
                return self._mcp_refusal(401, "invalid_token")
        try:
            _, session = await self._caller(request, resource=self.config.mcp_url)
        except _RateLimitedError:
            raise
        except _RefusedError as refused:
            return self._mcp_refusal(refused.status, refused.error, headers=refused.headers)
        if session.account_id is not None:
            self._report_session(signed_in=True, interface="mcp")
        return session

    def _offers(self, scopes: Sequence[str]) -> bool:
        """Whether this company offers every one of these scopes now.

        An access token holding a scope the company no longer offers — rolled
        back to a version without it, or narrowed — is refused as `invalid_token`,
        so the personal agent gets a new one within what is offered; a refresh
        token refreshed for such a scope is `invalid_scope`, and serves again
        when asked within what is offered.
        """
        return all(scope in self.config.scopes for scope in scopes)

    async def _mcp_route(  # noqa: C901 - the JSON-RPC methods
        self, request: CompanyRequest
    ) -> CompanyResponse:
        session = await self._mcp_caller(request)
        if isinstance(session, CompanyResponse):
            # An expired or other-resource token.
            return session
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
        self, session: CallerSession, mcp: CompanyMcp, params: dict[str, Any]
    ) -> dict[str, Any] | CompanyResponse:
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _rpc_error(None, -32602, "Invalid params")
        negotiated = await self._supports_operations(session.client_id)
        approval = approval_from_meta(params.get("_meta")) if negotiated else None
        try:
            target = await self._approval_target(session, approval)
        except _RefusedError as refused:
            return self._mcp_refusal(refused.status, refused.error, str(refused.extra["scope"]))
        settled = None if target is None else self._settled(target)
        if settled is not None:
            return self._mcp_decision(settled)
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
                carries_approval=approval is not None,
            ),
        )
        if answer.refusal is not None:
            status, error, scope = answer.refusal
            if error == "insufficient_scope" and session.account_id is None:
                # Signed out: the challenge with `scope`, no error code (§7).
                status, error = 401, ""
            return self._mcp_refusal(status, error, scope)
        if answer.operation is not None:
            if not negotiated:
                # A tool can't be refused with `extension_required`, which refuses the
                # personal agent entirely: an ordinary tool error (Operations 2).
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
            asked = self._asked(session, answer.operation, _fingerprint("mcp", name, arguments))
            return self._mcp_decision(await self._decide(session, asked, approval, target))
        text = answer.text if answer.text is not None else json.dumps(answer.structured or {})
        result: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
        if answer.structured is not None:
            result["structuredContent"] = answer.structured
        if answer.is_error:
            result["isError"] = True
        return result

    @staticmethod
    def _mcp_decision(decision: _Decision) -> dict[str, Any] | CompanyResponse:
        """The tool's result: the operation, what it came to, or `503` while it is performed."""

        operation, outcome = decision.operation, decision.outcome
        if operation is not None:
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": "Not done yet. This needs the user's approval: "
                        f"{operation.summary}",
                    }
                ],
                "structuredContent": {"operation": operation.model_dump(mode="json")},
            }
        if outcome is None:
            return _json_error(
                503, "temporarily_unavailable", {"Retry-After": _PERFORMING_RETRY_AFTER}
            )
        result: dict[str, Any] = {"content": [{"type": "text", "text": outcome.summary}]}
        if outcome.data is not None:
            result["structuredContent"] = outcome.data
        if not outcome.succeeded:
            result["isError"] = True
        return result

    # Web browsing (§6) ---------------------------------------------------------------------

    async def _join_page(self) -> CompanyResponse:
        """Step 1 of joining a browser (§6): a form with a one-time code, tied to this browser.

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
            "<button>Continue</button></form>"
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

    async def _authorize_join(self, request: CompanyRequest) -> CompanyResponse:
        """Step 2 (§6): the personal agent authorizes a code for its Session, and account.

        The Session header is checked as at any resource, which starts the Session if
        its `sid` is new; a code that isn't one issued, unexpired, and not authorized
        before is `invalid_request`. HTTP 204.
        """

        _, session = await self._caller(request)
        body = _json_object(request.body)
        code = body.get("code")
        if not isinstance(code, str) or not code:
            raise _RefusedError(400, "invalid_request")
        stored = await self._read(SESSION, session.session_key, StoredSession.from_json)
        if stored is None:
            raise _RefusedError(400, "invalid_request")
        authorized = WebSession(
            client_id=session.client_id,
            sid=session.sid,
            pairwise_user_id=session.pairwise_user_id,
            agent_id=session.agent_id,
            account_id=session.account_id,
            scopes=session.scopes,
            family=session.family,
            expires_at=stored.ends_at,
        )

        def authorize(current: JoinCode) -> JoinCode:
            if current.authorized is not None:
                raise _RefusedError(400, "invalid_request")
            return replace(current, authorized=authorized)

        if await self._change(JOIN_CODE, _digest(code), JoinCode.from_json, authorize) is None:
            raise _RefusedError(400, "invalid_request")
        return CompanyResponse(204, None, {"Cache-Control": "no-store"})

    async def _browser_session(self, request: CompanyRequest) -> CompanyResponse:
        """Step 3 (§6): the browser submits the code with step 1's cookie: the Session's cookie.

        A code is used by the first request that submits it, whatever the result. A
        refusal sets no cookie, not even a cleared one.
        """

        refused = self._page(400, "This browser could not join the session.")
        form = dict(parse_qsl(request.body.decode()))
        code, browser = form.get("code", ""), _cookie(request, JOIN_COOKIE)
        taken = await self.store.take(JOIN_CODE, _digest(code)) if code else None
        issued = None if taken is None else JoinCode.from_json(taken)
        if (
            issued is None
            or issued.authorized is None
            or browser is None
            or not hmac.compare_digest(issued.browser, _digest(browser))
        ):
            return refused
        joined = issued.authorized
        if not await self._allowed(joined.client_id) or self._now() >= joined.expires_at:
            return refused
        cookie = self._id("web")
        await self.store.put(
            BROWSER_COOKIE, _digest(cookie), joined.to_json(), expires_at=joined.expires_at
        )
        exchange = _EXCHANGE.get()
        if exchange is not None:
            exchange.client_id = joined.client_id
        self._report_session(signed_in=joined.account_id is not None, interface="web")
        return CompanyResponse(
            303,
            None,
            {
                "Location": f"{self.config.base}/",
                # The company's own cookie, `__Host-`: no Max-Age, only as alive as its
                # Session (§6). The join cookie is cleared.
                "Set-Cookie": (
                    f"{WEB_COOKIE}={cookie}; Path=/; Secure; HttpOnly; SameSite=Strict\n"
                    f"{JOIN_COOKIE}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
                ),
                "Cache-Control": "no-store",
            },
        )

    async def web_session(self, cookie: str | None) -> CallerSession | None:
        """The Session a browser's cookie stands for, as it is now, for the company's pages (§6).

        Signed out once its sign-in has ended (§5.5); gone once its Session has.
        """

        if cookie is None:
            return None
        joined = await self._read(BROWSER_COOKIE, _digest(cookie), WebSession.from_json)
        if joined is None:
            return None
        key = _composite(joined.client_id, joined.sid)
        stored = await self._read(SESSION, key, StoredSession.from_json)
        if stored is None or stored.ended or self._now() >= stored.ends_at:
            # The cookie does not outlive the Session.
            await self.store.delete(BROWSER_COOKIE, _digest(cookie))
            return None
        account_id, scopes = joined.account_id, joined.scopes
        if joined.family is not None:
            family = await self._read(ACCOUNT_FAMILY, joined.family, AccountFamily.from_json)
            grant = await self._read(REFRESH_TOKEN, joined.family, AccountGrant.from_json)
            if (
                family is None
                or family.revoked
                or (grant is not None and await self._sign_in_ended(grant))
            ):
                # The User signed out or disconnected the agent: no account any more.
                account_id, scopes = None, ()
        return CallerSession(
            session_key=key,
            client_id=joined.client_id,
            sid=joined.sid,
            pairwise_user_id=joined.pairwise_user_id,
            agent_id=joined.agent_id,
            account_id=account_id,
            scopes=scopes,
            family=joined.family if account_id is not None else None,
        )


def _fingerprint(*parts: object) -> str:
    """A digest of what a request asks, or of what an action said: canonical JSON."""

    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _rpc_error(request_id: object, code: int, message: str) -> CompanyResponse:
    return CompanyResponse(
        200, {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    )
