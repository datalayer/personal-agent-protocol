# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The company side's Reactor contribution points, and their in-memory defaults.

A company assembles its PAP service from contributions, each replaceable
without touching the service:

- `pap.company.store` keeps Sessions, Account Tokens, sign-ins,
  conversations, and operations (in memory by default; a database in
  production).
- `pap.company.accounts` checks a user's credentials and second factor for
  Mediated Sign-In, and stands for the company's own sign-in page in Device
  Sign-In.
- `pap.company.agent` answers conversation messages: the company agent.
- `pap.company.operationExecutor` performs a confirmed operation, by action.
- `pap.company.clientPolicy` allows or blocks personal agents by `client_id`.
- `pap.company.clientResolver` fetches a personal agent's client metadata
  and JWKS (over HTTPS through `AgentIdentityClient` by default).
- `pap.company.replayCache` remembers assertion and proof IDs once.
- `pap.company.api` answers the company's OpenAPI API (`/api/…`), its
  consequential calls proposing operations (`202`, Operations §4.1).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import SecretStr
from reactor import define_contribution_point  # type: ignore[import-untyped]

from ..models import ClientMetadata, JsonWebKeySet, Operation, OperationResult

COMPANY_STORES = define_contribution_point("pap.company.store")
COMPANY_ACCOUNTS = define_contribution_point("pap.company.accounts")
COMPANY_AGENTS = define_contribution_point("pap.company.agent")
OPERATION_EXECUTORS = define_contribution_point("pap.company.operationExecutor")
CLIENT_POLICIES = define_contribution_point("pap.company.clientPolicy")
CLIENT_RESOLVERS = define_contribution_point("pap.company.clientResolver")
REPLAY_CACHES = define_contribution_point("pap.company.replayCache")
COMPANY_APIS = define_contribution_point("pap.company.api")


@dataclass
class IssuedSession:
    """A Session the company issued; its token is bound to a DPoP key."""

    session_id: str
    client_id: str
    pairwise_user_id: str
    key_thumbprint: str
    expires_at: datetime
    account_id: str | None = None
    scopes: tuple[str, ...] = ()
    account_token: str | None = None
    token_type: Literal["DPoP", "Bearer"] = "DPoP"  # noqa: S105 - OAuth token type
    resource: str | None = None

    @property
    def signed_in(self) -> bool:
        return self.account_id is not None


@dataclass
class AccountGrant:
    """What an Account Token is: one account, one agent, one user, some scopes."""

    account_id: str
    client_id: str
    pairwise_user_id: str
    scopes: tuple[str, ...]
    expires_at: datetime
    revoked: bool = False


@dataclass
class PendingDevice:
    client_id: str
    scopes: tuple[str, ...]
    user_code: str
    expires_at: datetime
    interval: int
    last_poll: datetime | None = None
    account_id: str | None = None
    granted: tuple[str, ...] = ()
    denied: bool = False


@dataclass
class PendingAuthorization:
    """A Direct Sign-In request waiting on the user's decision on the company's page."""

    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    state: str
    code_challenge: str
    expires_at: datetime


@dataclass
class IssuedCode:
    """A one-use authorization code, at most a minute old."""

    client_id: str
    redirect_uri: str
    code_challenge: str
    account_id: str
    scopes: tuple[str, ...]
    expires_at: datetime


@dataclass
class PendingMediated:
    session_id: str
    account_id: str
    scopes: tuple[str, ...]
    code_reference: str
    expires_at: datetime
    attempts: int = 0


@dataclass
class StoredEvent:
    id: str
    payload: dict[str, Any]


@dataclass
class StoredConversation:
    conversation_id: str
    owner: tuple[str, str]
    status: Literal["working", "idle", "queued", "closed"] = "idle"
    responder: Literal["agent", "human"] = "agent"
    parent_id: str | None = None
    direct_child: str | None = None
    events: list[StoredEvent] = field(default_factory=list)
    message_ids: dict[str, str] = field(default_factory=dict)


@dataclass
class StoredOperation:
    operation: Operation
    action: str
    owner: tuple[str, str]
    account_id: str
    performed: bool = False


@runtime_checkable
class CompanyStore(Protocol):
    """Everything a company remembers, by kind and key."""

    sessions: dict[str, IssuedSession]
    account_tokens: dict[str, AccountGrant]
    devices: dict[str, PendingDevice]
    authorizations: dict[str, PendingAuthorization]
    codes: dict[str, IssuedCode]
    mediated: dict[str, PendingMediated]
    conversations: dict[str, StoredConversation]
    operations: dict[str, StoredOperation]
    message_ids: dict[tuple[str, str, str], str]


class MemoryCompanyStore:
    """The default store: one process, nothing persisted."""

    def __init__(self) -> None:
        self.sessions: dict[str, IssuedSession] = {}
        self.account_tokens: dict[str, AccountGrant] = {}
        self.devices: dict[str, PendingDevice] = {}
        self.authorizations: dict[str, PendingAuthorization] = {}
        self.codes: dict[str, IssuedCode] = {}
        self.mediated: dict[str, PendingMediated] = {}
        self.conversations: dict[str, StoredConversation] = {}
        self.operations: dict[str, StoredOperation] = {}
        self.message_ids: dict[tuple[str, str, str], str] = {}


@dataclass(frozen=True)
class Authenticated:
    """Mediated Sign-In's first step: the account, and a code to ask for when needed."""

    account_id: str
    code_reference: str | None = None
    sent_to: str | None = None


@runtime_checkable
class AccountDirectory(Protocol):
    """The company's own accounts: credentials and second factors."""

    async def authenticate(self, credentials: dict[str, SecretStr]) -> Authenticated | None: ...

    async def check_code(self, code_reference: str, code: SecretStr) -> bool: ...


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


@dataclass(frozen=True)
class ProposedOperation:
    """An operation the agent proposes; the service gives it an ID and expiry."""

    action: str
    summary: str
    terms: dict[str, Any]
    user_approval_required: bool = False


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


@runtime_checkable
class OperationExecutor(Protocol):
    """Perform one confirmed operation; `operation_id` is its idempotency key."""

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
    """Resolve a `client_id` to its verified metadata and keys."""

    async def resolve(self, client_id: str) -> tuple[ClientMetadata, JsonWebKeySet]: ...


@runtime_checkable
class ReplayCache(Protocol):
    async def mark_once(self, key: str, *, expires_at: datetime) -> bool: ...


class MemoryReplayCache:
    """The default replay cache: one process, entries dropped after expiry."""

    def __init__(self) -> None:
        self._seen: dict[str, datetime] = {}

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        if key in self._seen:
            return False
        self._seen[key] = expires_at
        return True


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
