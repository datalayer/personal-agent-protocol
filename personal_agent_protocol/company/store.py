# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What a company remembers: an async keyed store of JSON records, and the records.

A `CompanyStore` (the `pap.company.store` contribution) keeps JSON objects
by kind and key, each with a version and an optional expiry. The service
never changes a record in place: every change is an explicit write, and
every transition that must not race between replicas goes through
`create` (only if absent), `take` (read and delete at once), or `replace`
(compare-and-set on the version read). An expired record reads as absent.

Any backend (a database, a key-value service) implements the six methods;
`personal_agent_protocol.company.testing.check_store` checks one.
`MemoryCompanyStore` is the default: one process, nothing persisted.
"""

from __future__ import annotations

import itertools
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Protocol, cast, runtime_checkable

from ..models import Operation
from ..reactor import Clock, SystemClock

#: A record as stored: a JSON object (strings, numbers, booleans, null, lists, objects).
JsonObject = dict[str, Any]

#: The OAuth token type of a proof-bound Session Token.
DPOP: Literal["DPoP"] = "DPoP"

# The kinds of record a company keeps.
SESSION = "session"
SESSION_TOKEN = "session_token"  # noqa: S105 - a record kind, not a secret
ACCOUNT_TOKEN = "account_token"  # noqa: S105 - a record kind, not a secret
ACCOUNT_FAMILY = "account_family"
ACCOUNT_AGENT = "account_agent"
CLIENT = "client"
DEVICE = "device"
USER_CODE = "user_code"
AUTHORIZATION = "authorization"
CODE = "code"
MEDIATED = "mediated"
CONVERSATION = "conversation"
MESSAGE_ID = "message_id"
OPERATION = "operation"
PROPOSAL = "proposal"
BROWSER_COOKIE = "browser_cookie"
#: An assertion, proof, or browser-assertion ID seen once (the default replay cache).
REPLAY = "replay"
#: Failed sign-in attempts by one key, and until when it is locked out (§4.7).
SIGN_IN_ATTEMPTS = "sign_in_attempts"

RECORD_KINDS = (
    SESSION,
    SESSION_TOKEN,
    ACCOUNT_TOKEN,
    ACCOUNT_FAMILY,
    ACCOUNT_AGENT,
    CLIENT,
    DEVICE,
    USER_CODE,
    AUTHORIZATION,
    CODE,
    MEDIATED,
    CONVERSATION,
    MESSAGE_ID,
    OPERATION,
    PROPOSAL,
    BROWSER_COOKIE,
    REPLAY,
    SIGN_IN_ATTEMPTS,
)


@dataclass(frozen=True)
class StoredRecord:
    """A record read from the store: its value, its version, and when it expires."""

    value: JsonObject
    version: str
    expires_at: datetime | None = None


@runtime_checkable
class CompanyStore(Protocol):
    """Everything a company remembers, as JSON records by kind and key.

    - `get` reads a record, or `None` when absent or expired.
    - `put` writes it unconditionally (a new version).
    - `create` writes it only if absent (or expired): `True` when written.
    - `replace` writes it only if its version is still `version`: `True` when written.
    - `take` reads and deletes it at once: exactly one caller gets it.
    - `delete` removes it, if present.

    Values are JSON objects; a backend stores copies, never the caller's object.
    """

    async def get(self, kind: str, key: str) -> StoredRecord | None: ...

    async def put(
        self, kind: str, key: str, value: JsonObject, *, expires_at: datetime | None = None
    ) -> None: ...

    async def create(
        self, kind: str, key: str, value: JsonObject, *, expires_at: datetime | None = None
    ) -> bool: ...

    async def replace(
        self,
        kind: str,
        key: str,
        version: str,
        value: JsonObject,
        *,
        expires_at: datetime | None = None,
    ) -> bool: ...

    async def take(self, kind: str, key: str) -> JsonObject | None: ...

    async def delete(self, kind: str, key: str) -> None: ...


#: The memory store sweeps expired records once it holds this many, then whenever it doubles.
_FIRST_SWEEP = 1024


class MemoryCompanyStore:
    """The default store: one process, nothing persisted, versions and expiry real.

    `clock` judges expiry; `build_company` binds the company's own clock.
    Expired records are swept whenever the store has doubled since the last
    sweep, so it holds about twice the records still alive, never every one
    ever written (replay IDs, sign-in attempts, pointers).
    """

    def __init__(self, clock: Clock | None = None) -> None:
        self.clock: Clock = clock or SystemClock()
        self._entries: dict[tuple[str, str], tuple[str, str, datetime | None]] = {}
        self._versions = itertools.count(1)
        self._sweep_at = _FIRST_SWEEP

    def __len__(self) -> int:
        return len(self._entries)

    def _live(self, kind: str, key: str) -> tuple[str, str, datetime | None] | None:
        entry = self._entries.get((kind, key))
        if entry is not None and entry[2] is not None and self.clock.now() >= entry[2]:
            del self._entries[(kind, key)]
            return None
        return entry

    def _write(self, kind: str, key: str, value: JsonObject, expires_at: datetime | None) -> None:
        text = json.dumps(value, allow_nan=False, separators=(",", ":"))
        self._entries[(kind, key)] = (text, str(next(self._versions)), expires_at)
        if len(self._entries) >= self._sweep_at:
            now = self.clock.now()
            self._entries = {
                at: entry
                for at, entry in self._entries.items()
                if entry[2] is None or now < entry[2]
            }
            self._sweep_at = max(_FIRST_SWEEP, 2 * len(self._entries))

    async def get(self, kind: str, key: str) -> StoredRecord | None:
        entry = self._live(kind, key)
        if entry is None:
            return None
        return StoredRecord(json.loads(entry[0]), entry[1], entry[2])

    async def put(
        self, kind: str, key: str, value: JsonObject, *, expires_at: datetime | None = None
    ) -> None:
        self._write(kind, key, value, expires_at)

    async def create(
        self, kind: str, key: str, value: JsonObject, *, expires_at: datetime | None = None
    ) -> bool:
        if self._live(kind, key) is not None:
            return False
        self._write(kind, key, value, expires_at)
        return True

    async def replace(
        self,
        kind: str,
        key: str,
        version: str,
        value: JsonObject,
        *,
        expires_at: datetime | None = None,
    ) -> bool:
        entry = self._live(kind, key)
        if entry is None or entry[1] != version:
            return False
        self._write(kind, key, value, expires_at)
        return True

    async def take(self, kind: str, key: str) -> JsonObject | None:
        entry = self._live(kind, key)
        if entry is None:
            return None
        del self._entries[(kind, key)]
        return cast(JsonObject, json.loads(entry[0]))

    async def delete(self, kind: str, key: str) -> None:
        self._entries.pop((kind, key), None)

    def keys(self, kind: str) -> list[str]:
        """The live keys of one kind, oldest first: for tests and inspection, not the service."""

        return [key for (k, key) in list(self._entries) if k == kind and self._live(k, key)]


# Records ---------------------------------------------------------------------------


def _time(value: datetime) -> str:
    return value.isoformat()


def _maybe_time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _maybe_parse(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


@dataclass(frozen=True)
class IssuedSession:
    """One token of a Session, as issued; the token is bound to a DPoP key (or Bearer)."""

    session_id: str
    client_id: str
    pairwise_user_id: str
    key_thumbprint: str
    expires_at: datetime
    account_id: str | None = None
    scopes: tuple[str, ...] = ()
    account_token: str | None = None
    token_type: Literal["DPoP", "Bearer"] = DPOP
    resource: str | None = None

    @property
    def signed_in(self) -> bool:
        return self.account_id is not None

    def to_json(self) -> JsonObject:
        return {
            "session_id": self.session_id,
            "client_id": self.client_id,
            "pairwise_user_id": self.pairwise_user_id,
            "key_thumbprint": self.key_thumbprint,
            "expires_at": _time(self.expires_at),
            "account_id": self.account_id,
            "scopes": list(self.scopes),
            "account_token": self.account_token,
            "token_type": self.token_type,
            "resource": self.resource,
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> IssuedSession:
        return cls(
            session_id=value["session_id"],
            client_id=value["client_id"],
            pairwise_user_id=value["pairwise_user_id"],
            key_thumbprint=value["key_thumbprint"],
            expires_at=_parse(value["expires_at"]),
            account_id=value["account_id"],
            scopes=tuple(value["scopes"]),
            account_token=value["account_token"],
            token_type=value["token_type"],
            resource=value["resource"],
        )


@dataclass(frozen=True)
class StoredSession:
    """A Session by its ID: each live token's state by digest, and the latest issued."""

    session_id: str
    client_id: str
    pairwise_user_id: str
    tokens: dict[str, IssuedSession]
    latest: str

    @property
    def current(self) -> IssuedSession:
        return self.tokens[self.latest]

    def to_json(self) -> JsonObject:
        return {
            "session_id": self.session_id,
            "client_id": self.client_id,
            "pairwise_user_id": self.pairwise_user_id,
            "tokens": {digest: token.to_json() for digest, token in self.tokens.items()},
            "latest": self.latest,
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> StoredSession:
        return cls(
            session_id=value["session_id"],
            client_id=value["client_id"],
            pairwise_user_id=value["pairwise_user_id"],
            tokens={
                digest: IssuedSession.from_json(token) for digest, token in value["tokens"].items()
            },
            latest=value["latest"],
        )


@dataclass(frozen=True)
class AccountGrant:
    """What an Account Token is: one account, one agent, one user, some scopes."""

    account_id: str
    client_id: str
    pairwise_user_id: str
    scopes: tuple[str, ...]
    expires_at: datetime
    revoked: bool = False
    #: The sign-in it comes from: every token rotated from one sign-in shares it.
    family: str = ""
    #: When that sign-in happened, carried by every token rotated from it: a
    #: sign-in from before the account's sign-ins all ended (a password reset)
    #: ends. Unknown (`None`) is taken for before any such moment.
    signed_in_at: datetime | None = None

    def to_json(self) -> JsonObject:
        return {
            "account_id": self.account_id,
            "client_id": self.client_id,
            "pairwise_user_id": self.pairwise_user_id,
            "scopes": list(self.scopes),
            "expires_at": _time(self.expires_at),
            "revoked": self.revoked,
            "family": self.family,
            "signed_in_at": _maybe_time(self.signed_in_at),
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> AccountGrant:
        return cls(
            account_id=value["account_id"],
            client_id=value["client_id"],
            pairwise_user_id=value["pairwise_user_id"],
            scopes=tuple(value["scopes"]),
            expires_at=_parse(value["expires_at"]),
            revoked=value["revoked"],
            family=value["family"],
            signed_in_at=_maybe_parse(value.get("signed_in_at")),
        )


@dataclass(frozen=True)
class AccountFamily:
    """One sign-in: every Account Token rotated from it, and the Sessions signed in with them."""

    client_id: str
    account_id: str
    tokens: tuple[str, ...] = ()
    sessions: tuple[str, ...] = ()
    #: Revoked (§4.9) or disconnected: no token joins it any more.
    revoked: bool = False

    def to_json(self) -> JsonObject:
        return {
            "client_id": self.client_id,
            "account_id": self.account_id,
            "tokens": list(self.tokens),
            "sessions": list(self.sessions),
            "revoked": self.revoked,
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> AccountFamily:
        return cls(
            client_id=value["client_id"],
            account_id=value["account_id"],
            tokens=tuple(value["tokens"]),
            sessions=tuple(value["sessions"]),
            revoked=value["revoked"],
        )


@dataclass(frozen=True)
class AccountAgent:
    """The sign-ins of one agent to one account, for disconnecting it."""

    families: tuple[str, ...] = ()

    def to_json(self) -> JsonObject:
        return {"families": list(self.families)}

    @classmethod
    def from_json(cls, value: JsonObject) -> AccountAgent:
        return cls(families=tuple(value["families"]))


@dataclass(frozen=True)
class KnownClient:
    """What a verified personal agent declared: the extensions it supports.

    One record per `client_id` that authenticated, kept without expiry. Only
    an agent with valid metadata and keys at its own domain adds one, but an
    operator of many domains can add many: a company bounds that with its
    `pap.company.clientPolicy` (or a store that ages records out).
    """

    extensions: tuple[str, ...] = ()

    def to_json(self) -> JsonObject:
        return {"extensions": list(self.extensions)}

    @classmethod
    def from_json(cls, value: JsonObject) -> KnownClient:
        return cls(extensions=tuple(value["extensions"]))


@dataclass(frozen=True)
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

    def to_json(self) -> JsonObject:
        return {
            "client_id": self.client_id,
            "scopes": list(self.scopes),
            "user_code": self.user_code,
            "expires_at": _time(self.expires_at),
            "interval": self.interval,
            "last_poll": _maybe_time(self.last_poll),
            "account_id": self.account_id,
            "granted": list(self.granted),
            "denied": self.denied,
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> PendingDevice:
        return cls(
            client_id=value["client_id"],
            scopes=tuple(value["scopes"]),
            user_code=value["user_code"],
            expires_at=_parse(value["expires_at"]),
            interval=value["interval"],
            last_poll=_maybe_parse(value["last_poll"]),
            account_id=value["account_id"],
            granted=tuple(value["granted"]),
            denied=value["denied"],
        )


@dataclass(frozen=True)
class UserCode:
    """The device sign-in a user code stands for (by device-code digest)."""

    device: str

    def to_json(self) -> JsonObject:
        return {"device": self.device}

    @classmethod
    def from_json(cls, value: JsonObject) -> UserCode:
        return cls(device=value["device"])


@dataclass(frozen=True)
class PendingAuthorization:
    """A Direct Sign-In request waiting on the user's decision on the company's page."""

    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    state: str
    code_challenge: str
    expires_at: datetime
    client_name: str = ""
    #: The digest of the consent cookie of the browser the company's own page was
    #: shown to; `None` when a hosted consent page answers (it protects its own form).
    browser_binding: str | None = None

    def to_json(self) -> JsonObject:
        return {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scopes": list(self.scopes),
            "state": self.state,
            "code_challenge": self.code_challenge,
            "expires_at": _time(self.expires_at),
            "client_name": self.client_name,
            "browser_binding": self.browser_binding,
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> PendingAuthorization:
        return cls(
            client_id=value["client_id"],
            redirect_uri=value["redirect_uri"],
            scopes=tuple(value["scopes"]),
            state=value["state"],
            code_challenge=value["code_challenge"],
            expires_at=_parse(value["expires_at"]),
            client_name=value["client_name"],
            browser_binding=value["browser_binding"],
        )


@dataclass(frozen=True)
class IssuedCode:
    """A one-use authorization code, at most a minute old."""

    client_id: str
    redirect_uri: str
    code_challenge: str
    account_id: str
    scopes: tuple[str, ...]
    expires_at: datetime

    def to_json(self) -> JsonObject:
        return {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "code_challenge": self.code_challenge,
            "account_id": self.account_id,
            "scopes": list(self.scopes),
            "expires_at": _time(self.expires_at),
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> IssuedCode:
        return cls(
            client_id=value["client_id"],
            redirect_uri=value["redirect_uri"],
            code_challenge=value["code_challenge"],
            account_id=value["account_id"],
            scopes=tuple(value["scopes"]),
            expires_at=_parse(value["expires_at"]),
        )


@dataclass(frozen=True)
class PendingMediated:
    session_id: str
    account_id: str
    scopes: tuple[str, ...]
    code_reference: str
    expires_at: datetime
    #: The `SIGN_IN_ATTEMPTS` keys the credentials counted against, cleared on success.
    attempt_keys: tuple[str, ...] = ()
    attempts: int = 0

    def to_json(self) -> JsonObject:
        return {
            "session_id": self.session_id,
            "account_id": self.account_id,
            "scopes": list(self.scopes),
            "code_reference": self.code_reference,
            "expires_at": _time(self.expires_at),
            "attempt_keys": list(self.attempt_keys),
            "attempts": self.attempts,
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> PendingMediated:
        return cls(
            session_id=value["session_id"],
            account_id=value["account_id"],
            scopes=tuple(value["scopes"]),
            code_reference=value["code_reference"],
            expires_at=_parse(value["expires_at"]),
            attempt_keys=tuple(value["attempt_keys"]),
            attempts=value["attempts"],
        )


@dataclass(frozen=True)
class StoredEvent:
    id: str
    payload: JsonObject

    def to_json(self) -> JsonObject:
        return {"id": self.id, "payload": self.payload}

    @classmethod
    def from_json(cls, value: JsonObject) -> StoredEvent:
        return cls(id=value["id"], payload=value["payload"])


@dataclass(frozen=True)
class StoredConversation:
    conversation_id: str
    owner: tuple[str, str]
    status: Literal["working", "idle", "queued", "closed"] = "idle"
    responder: Literal["agent", "human"] = "agent"
    parent_id: str | None = None
    direct_child: str | None = None
    #: The account the conversation used; from then on it belongs to that account.
    account_id: str | None = None
    events: tuple[StoredEvent, ...] = ()
    #: Event IDs the company no longer keeps: a cursor naming one is `cursor_expired`.
    forgotten: frozenset[str] = field(default_factory=frozenset)

    def to_json(self) -> JsonObject:
        return {
            "conversation_id": self.conversation_id,
            "owner": list(self.owner),
            "status": self.status,
            "responder": self.responder,
            "parent_id": self.parent_id,
            "direct_child": self.direct_child,
            "account_id": self.account_id,
            "events": [event.to_json() for event in self.events],
            "forgotten": sorted(self.forgotten),
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> StoredConversation:
        client_id, pairwise_user_id = value["owner"]
        return cls(
            conversation_id=value["conversation_id"],
            owner=(client_id, pairwise_user_id),
            status=value["status"],
            responder=value["responder"],
            parent_id=value["parent_id"],
            direct_child=value["direct_child"],
            account_id=value["account_id"],
            events=tuple(StoredEvent.from_json(event) for event in value["events"]),
            forgotten=frozenset(value["forgotten"]),
        )


@dataclass(frozen=True)
class MessageReceipt:
    """A message ID seen from one agent and user: its conversation and content digest."""

    conversation_id: str
    digest: str

    def to_json(self) -> JsonObject:
        return {"conversation_id": self.conversation_id, "digest": self.digest}

    @classmethod
    def from_json(cls, value: JsonObject) -> MessageReceipt:
        return cls(conversation_id=value["conversation_id"], digest=value["digest"])


@dataclass(frozen=True)
class StoredOperation:
    operation: Operation
    action: str
    owner: tuple[str, str]
    account_id: str
    #: The scopes a Session must hold to confirm it, recorded when it was proposed.
    scopes: tuple[str, ...]
    performed: bool = False

    def to_json(self) -> JsonObject:
        return {
            "operation": self.operation.model_dump(mode="json"),
            "action": self.action,
            "owner": list(self.owner),
            "account_id": self.account_id,
            "scopes": list(self.scopes),
            "performed": self.performed,
        }

    @classmethod
    def from_json(cls, value: JsonObject) -> StoredOperation:
        client_id, pairwise_user_id = value["owner"]
        return cls(
            operation=Operation.model_validate(value["operation"]),
            action=value["action"],
            owner=(client_id, pairwise_user_id),
            account_id=value["account_id"],
            scopes=tuple(value["scopes"]),
            performed=value["performed"],
        )


@dataclass(frozen=True)
class OperationProposal:
    """The operation an identical proposal returns (Operations §4: one action, one operation)."""

    operation_id: str

    def to_json(self) -> JsonObject:
        return {"operation_id": self.operation_id}

    @classmethod
    def from_json(cls, value: JsonObject) -> OperationProposal:
        return cls(operation_id=value["operation_id"])


@dataclass(frozen=True)
class SessionPointer:
    """The Session a token or a browser cookie stands for (by digest)."""

    session_id: str

    def to_json(self) -> JsonObject:
        return {"session_id": self.session_id}

    @classmethod
    def from_json(cls, value: JsonObject) -> SessionPointer:
        return cls(session_id=value["session_id"])


@dataclass(frozen=True)
class ReplayMark:
    """An identifier seen once: the record is its presence, until its expiry."""

    def to_json(self) -> JsonObject:
        return {}

    @classmethod
    def from_json(cls, value: JsonObject) -> ReplayMark:
        if value:
            raise ValueError("a replay mark has no members")
        return cls()


@dataclass(frozen=True)
class SignInAttempts:
    """Failed sign-in attempts by one key (an account, a user, a Session, a code).

    `locked_until` is set once `failures` reach the company's limit: until
    then every attempt by the key is refused (`429`, `Retry-After`).
    """

    failures: int = 0
    locked_until: datetime | None = None

    def to_json(self) -> JsonObject:
        return {"failures": self.failures, "locked_until": _maybe_time(self.locked_until)}

    @classmethod
    def from_json(cls, value: JsonObject) -> SignInAttempts:
        return cls(failures=value["failures"], locked_until=_maybe_parse(value["locked_until"]))


#: Each kind's record type: `to_json()` writes it, `from_json()` reads it back.
RECORD_TYPES: dict[str, Callable[[JsonObject], Any]] = {
    SESSION: StoredSession.from_json,
    SESSION_TOKEN: SessionPointer.from_json,
    ACCOUNT_TOKEN: AccountGrant.from_json,
    ACCOUNT_FAMILY: AccountFamily.from_json,
    ACCOUNT_AGENT: AccountAgent.from_json,
    CLIENT: KnownClient.from_json,
    DEVICE: PendingDevice.from_json,
    USER_CODE: UserCode.from_json,
    AUTHORIZATION: PendingAuthorization.from_json,
    CODE: IssuedCode.from_json,
    MEDIATED: PendingMediated.from_json,
    CONVERSATION: StoredConversation.from_json,
    MESSAGE_ID: MessageReceipt.from_json,
    OPERATION: StoredOperation.from_json,
    PROPOSAL: OperationProposal.from_json,
    BROWSER_COOKIE: SessionPointer.from_json,
    REPLAY: ReplayMark.from_json,
    SIGN_IN_ATTEMPTS: SignInAttempts.from_json,
}
