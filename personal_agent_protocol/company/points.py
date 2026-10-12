# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The company side's Reactor contribution points, and their in-memory defaults.

A company assembles its PAP service from contributions, each replaceable
without touching the service:

- `pap.company.store` keeps Sessions, Account Tokens, sign-ins,
  conversations, and operations as versioned JSON records (`store`; in
  memory by default, a database in production).
- `pap.company.accounts` checks a user's credentials and second factor for
  Mediated Sign-In, and stands for the company's own sign-in page in Device
  Sign-In.
- `pap.company.agent` answers conversation messages: the company agent.
- `pap.company.operationExecutor` performs a confirmed operation, by action.
- `pap.company.clientPolicy` allows or blocks personal agents by `client_id`.
- `pap.company.clientResolver` fetches a personal agent's client metadata
  and JWKS (over HTTPS through `AgentIdentityClient` by default).
- `pap.company.replayCache` remembers assertion and proof IDs once: by
  default in the contributed store (`StoreReplayCache`), so every replica
  sharing a durable store shares the cache.
- `pap.company.api` answers the company's OpenAPI API (`/api/…`), its
  consequential calls proposing operations (`202`, Operations §4.1).
- `pap.company.mcp` answers the company's MCP server (`/mcp`): its tools,
  called with resource-bound Bearer Session Tokens (§4.3, §6), a
  consequential tool proposing an operation in `structuredContent`
  (Operations §4.2).
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import SecretStr
from reactor import define_contribution_point  # type: ignore[import-untyped]

from ..models import ClientMetadata, JsonWebKeySet, Operation, OperationResult
from ..reactor import Clock, SystemClock
from .store import (
    DPOP,
    REPLAY,
    AccountGrant,
    CompanyStore,
    IssuedCode,
    IssuedSession,
    MemoryCompanyStore,
    PendingAuthorization,
    PendingDevice,
    PendingMediated,
    StoredConversation,
    StoredEvent,
    StoredOperation,
    StoredRecord,
)

COMPANY_STORES = define_contribution_point("pap.company.store")
COMPANY_ACCOUNTS = define_contribution_point("pap.company.accounts")
COMPANY_AGENTS = define_contribution_point("pap.company.agent")
OPERATION_EXECUTORS = define_contribution_point("pap.company.operationExecutor")
CLIENT_POLICIES = define_contribution_point("pap.company.clientPolicy")
CLIENT_RESOLVERS = define_contribution_point("pap.company.clientResolver")
REPLAY_CACHES = define_contribution_point("pap.company.replayCache")
COMPANY_APIS = define_contribution_point("pap.company.api")
COMPANY_MCP = define_contribution_point("pap.company.mcp")


@dataclass(frozen=True)
class Authenticated:
    """Mediated Sign-In's first step: the account, and a code to ask for when needed."""

    account_id: str
    code_reference: str | None = None
    sent_to: str | None = None


@dataclass(frozen=True)
class SignInContext:
    """Who a Mediated Sign-In attempt comes from: the agent and its Session."""

    client_id: str
    session_id: str


@runtime_checkable
class AccountDirectory(Protocol):
    """The company's own accounts: credentials and second factors.

    The service limits Mediated Sign-In attempts itself (by account
    identifier, by agent and user, by Session, and wrong codes by account),
    but a directory MUST also throttle its own checks: it is the one place
    that sees every path to an account, and `context` says which agent and
    Session each attempt comes from (§4.7, a company MUST rate-limit).
    """

    async def authenticate(
        self, credentials: dict[str, SecretStr], context: SignInContext
    ) -> Authenticated | None: ...

    async def check_code(self, code_reference: str, code: SecretStr) -> bool: ...


@runtime_checkable
class AccountSignOuts(Protocol):
    """What an `AccountDirectory` may also say: since when an account's earlier sign-ins are over.

    A password reset, an account locked or recovered: every sign-in to the
    account from before that moment ends — its Account Tokens are refused and
    revoked, and the Sessions signed in with them continue signed out — while
    a sign-in after it works. `None` when nothing ended them. Asked on every
    signed-in request, so a directory answers from a cache it keeps short.
    """

    async def signed_out_before(self, account_id: str) -> datetime | None: ...


@dataclass(frozen=True)
class Turn:
    """One message the company agent answers, and who it is answering."""

    conversation_id: str
    text: str | None
    data: dict[str, Any] | None
    sender: Literal["agent", "human"]
    account_id: str | None
    scopes: tuple[str, ...]
    client_id: str
    is_direct: bool
    #: Whether the personal agent negotiated Operations: without it, a proposed
    #: operation is never sent, so the agent's words must not promise one.
    supports_operations: bool


@dataclass(frozen=True)
class ProposedOperation:
    """An operation the agent proposes; the service gives it an ID and expiry.

    `scopes` are what a Session must hold to confirm it, recorded with it;
    none named, the company's `write_scopes`.
    """

    action: str
    summary: str
    terms: dict[str, Any]
    user_approval_required: bool = False
    scopes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Reply:
    """What the company agent says back.

    `authorization` asks the personal agent to sign in or widen scopes
    (§7.11) instead of answering; `operation` proposes an operation with the
    reply (Operations §4.3).
    """

    text: str | None = None
    data: dict[str, Any] | None = None
    operation: ProposedOperation | None = None
    authorization: tuple[Literal["sign_in_required", "insufficient_scope"], str] | None = None
    user_requested: str | None = None


@runtime_checkable
class CompanyAgent(Protocol):
    """Answer one turn of a conversation."""

    async def respond(self, turn: Turn) -> Sequence[Reply]: ...


class OperationFailed(Exception):  # noqa: N818 - an outcome, raised by an executor
    """The action was not completed; `result.summary` says every change that was made."""

    def __init__(self, result: OperationResult) -> None:
        super().__init__(result.summary)
        self.result = result


class OperationOutcomeUnknown(Exception):  # noqa: N818 - an outcome, raised by an executor
    """A downstream system did not answer: the operation stays `in_progress` (Operations §6)."""


@runtime_checkable
class OperationExecutor(Protocol):
    """Perform one confirmed operation; `operation_id` is its idempotency key.

    Return the result of a completed action; raise `OperationFailed` with the
    changes made when it failed partway, or `OperationOutcomeUnknown` while it
    is not known whether it took effect (never reported as failed).
    """

    action: str

    async def perform(self, operation: Operation, account_id: str) -> OperationResult: ...


@runtime_checkable
class ClientPolicy(Protocol):
    """Allow or block a personal agent by its `client_id`."""

    async def allows(self, client_id: str) -> bool: ...


class AllowEveryAgent:
    """The default policy: any agent with valid identity is welcome."""

    async def allows(self, client_id: str) -> bool:
        return True


@runtime_checkable
class ClientResolver(Protocol):
    """Resolve a `client_id` to its verified metadata and keys.

    `kid` is the key an assertion names: a resolver that caches keys fetches
    them again when the cached set lacks it (rate-limited; Guides, rotating keys).
    """

    async def resolve(
        self, client_id: str, *, kid: str | None = None
    ) -> tuple[ClientMetadata, JsonWebKeySet]: ...


@runtime_checkable
class ReplayCache(Protocol):
    async def mark_once(self, key: str, *, expires_at: datetime) -> bool: ...


_FIRST_SWEEP = 1024


class MemoryReplayCache:
    """A replay cache in one process, entries dropped after expiry (not the default).

    For a verifier used on its own (`verify_assertion`, `verify_dpop_proof`);
    a company's default is `StoreReplayCache` over its store.

    An identifier is refused until its `expires_at` by `clock` (the
    assertion or proof it names is refused as expired after that). Expired
    entries are swept whenever the cache has doubled since the last sweep,
    so it holds about twice the identifiers still alive, never every one
    ever seen.
    """

    def __init__(self, clock: Clock | None = None) -> None:
        self.clock: Clock = clock or SystemClock()
        self._seen: dict[str, datetime] = {}
        self._sweep_at = _FIRST_SWEEP

    def __len__(self) -> int:
        return len(self._seen)

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        now = self.clock.now()
        seen = self._seen.get(key)
        # Seen until its expiry, inclusive.
        if seen is not None and now <= seen:
            return False
        self._seen[key] = expires_at
        if len(self._seen) >= self._sweep_at:
            self._seen = {k: until for k, until in self._seen.items() if now < until}
            self._sweep_at = max(_FIRST_SWEEP, 2 * len(self._seen))
        return True


#: A mark is kept a second past its expiry, so an identifier is refused until then, inclusive.
_INCLUSIVE = timedelta(seconds=1)


class StoreReplayCache:
    """The default replay cache: one atomic `create` in the company's store per identifier.

    The identifier is kept (as its SHA-256) until a second after its
    `expires_at`, so it is refused until its expiry, inclusive. The store is
    looked up at each call, the contributed `pap.company.store`: a durable
    store shared by every replica implies a replay cache shared by every
    replica, so a proof captured at one replica is refused at another, and
    after a restart. With the memory store it is one process, as that store is.
    """

    def __init__(self, store: Callable[[], CompanyStore]) -> None:
        self._store = store

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return await self._store().create(REPLAY, digest, {}, expires_at=expires_at + _INCLUSIVE)


@dataclass(frozen=True)
class ApiCall:
    """One verified call to the company's API: who, with what authority."""

    method: str
    path: str
    query: dict[str, str]
    body: Any
    account_id: str | None
    scopes: tuple[str, ...]
    client_id: str


@dataclass(frozen=True)
class ApiResult:
    """The API's answer: a JSON body, or an operation to propose (`202`)."""

    status: int = 200
    body: Any = None
    operation: ProposedOperation | None = None

    @staticmethod
    def sign_in_required(scope: str) -> ApiResult:
        return ApiResult(403, {"error": "sign_in_required", "scope": scope})

    @staticmethod
    def insufficient_scope(scope: str) -> ApiResult:
        return ApiResult(403, {"error": "insufficient_scope", "scope": scope})

    @staticmethod
    def not_found() -> ApiResult:
        return ApiResult(404, {"error": "not_found"})


@runtime_checkable
class CompanyApi(Protocol):
    """The company's OpenAPI API: its description, and each call."""

    description: str

    def openapi(self) -> dict[str, Any]: ...

    async def handle(self, call: ApiCall) -> ApiResult: ...


@dataclass(frozen=True)
class ToolResult:
    """An MCP tool's answer: text and structured content, or an operation to propose.

    `refusal` is `(status, error, scope)` for a token error the server returns
    over HTTP with a Bearer challenge (`sign_in_required`, `insufficient_scope`).
    """

    text: str | None = None
    structured: dict[str, Any] | None = None
    operation: ProposedOperation | None = None
    is_error: bool = False
    refusal: tuple[int, str, str | None] | None = None

    @staticmethod
    def sign_in_required(scope: str) -> ToolResult:
        return ToolResult(refusal=(403, "sign_in_required", scope))

    @staticmethod
    def insufficient_scope(scope: str) -> ToolResult:
        return ToolResult(refusal=(403, "insufficient_scope", scope))


@runtime_checkable
class CompanyMcp(Protocol):
    """The company's MCP server: its tools, and each call (with the caller's authority)."""

    description: str

    def tools(self) -> list[dict[str, Any]]: ...

    async def call(self, name: str, arguments: dict[str, Any], call: ApiCall) -> ToolResult: ...


__all__ = [
    "CLIENT_POLICIES",
    "CLIENT_RESOLVERS",
    "COMPANY_ACCOUNTS",
    "COMPANY_AGENTS",
    "COMPANY_APIS",
    "COMPANY_MCP",
    "COMPANY_STORES",
    "DPOP",
    "OPERATION_EXECUTORS",
    "REPLAY_CACHES",
    "AccountDirectory",
    "AccountGrant",
    "AllowEveryAgent",
    "ApiCall",
    "ApiResult",
    "Authenticated",
    "ClientPolicy",
    "ClientResolver",
    "CompanyAgent",
    "CompanyApi",
    "CompanyMcp",
    "CompanyStore",
    "IssuedCode",
    "IssuedSession",
    "MemoryCompanyStore",
    "MemoryReplayCache",
    "OperationExecutor",
    "OperationFailed",
    "OperationOutcomeUnknown",
    "PendingAuthorization",
    "PendingDevice",
    "PendingMediated",
    "ProposedOperation",
    "ReplayCache",
    "Reply",
    "SignInContext",
    "StoreReplayCache",
    "StoredConversation",
    "StoredEvent",
    "StoredOperation",
    "StoredRecord",
    "ToolResult",
    "Turn",
]
