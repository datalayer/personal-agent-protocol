# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A conformance kit for `pap.company.store` backends.

```python
from personal_agent_protocol.company.testing import check_store

async def test_my_store_conforms() -> None:
    await check_store(lambda: MyDatabaseStore(url))
```

`check_store` raises `StoreConformanceError` naming the first property a
store breaks: absent and present records, expiry, `take` once under
concurrency, `create` only if absent, compare-and-set conflicts, kinds kept
apart, values copied rather than shared, every live record of a kind read
at once (`records`), and a JSON round trip of every
record kind the company keeps. `make_store` returns a fresh, empty store
(or an awaitable of one); `now` is the clock the store judges expiry by;
`concurrency` is how many callers race for one record.

`check_replay_cache` does the same for `pap.company.replayCache`: of
`concurrency` callers marking one identifier at once, exactly one wins, and
the identifier stays refused; distinct identifiers are all accepted.

```python
async def test_my_replay_cache_conforms() -> None:
    await check_replay_cache(lambda: RedisReplayCache(url), concurrency=200)
```
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from .points import ReplayCache
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
    RECORD_KINDS,
    RECORD_TYPES,
    REFRESH_TOKEN,
    REPLAY,
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
    KnownClient,
    MessageReceipt,
    OperationOutcome,
    OperationProposal,
    OperationRevision,
    PendingAuthorization,
    PendingDevice,
    PendingMediated,
    ReplayMark,
    SignInAttempts,
    StoredConversation,
    StoredEvent,
    StoredFeedback,
    StoredOperation,
    StoredSession,
    UserCode,
    WebSession,
)

_CONCURRENCY = 16


class StoreConformanceError(AssertionError):
    """A company store does not behave as `pap.company.store` requires."""


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise StoreConformanceError(message)


def record_samples(now: datetime) -> dict[str, Any]:
    """One record of every kind the company keeps, each field set, for round trips."""

    later = now + timedelta(minutes=5)
    access = IssuedAccessToken(
        client_id="https://atlas.example",
        account_id="acct_1",
        scopes=("orders:read", "orders:write"),
        expires_at=later,
        family="fam_1",
        resource="https://shop.example/mcp",
        dpop_jkt="NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    )
    web = WebSession(
        client_id="https://atlas.example",
        sid="Yx2b7Qd_Kp8mR3vT1nWc4A",
        pairwise_user_id="usr_1",
        expires_at=later,
        agent_id="agt_1",
        account_id="acct_1",
        scopes=("orders:read",),
        family="fam_1",
    )
    operation = StoredOperation(
        operation_id="op_1",
        action="exchange",
        owner=("c", "u"),
        key="key",
        revisions=(
            OperationRevision(
                revision="rev_1",
                summary="Exchange the jacket.",
                terms={"order_id": "ord_1", "price": {"amount": "1.00", "currency": "USD"}},
                expires_at=later,
                request="request",
                asked="asked",
                withdrawn=True,
            ),
        ),
        account_id="acct_1",
        scopes=("orders:write",),
        status="performed",
        approved="rev_1",
        approved_at=now,
        outcome=OperationOutcome("Exchanged.", {"order": "ord_1"}),
    )
    return {
        SESSION: StoredSession(
            client_id="https://atlas.example",
            sid="Yx2b7Qd_Kp8mR3vT1nWc4A",
            pairwise_user_id="usr_1",
            ends_at=later,
            agent_id="agt_1",
            ended=True,
        ),
        ACCESS_TOKEN: access,
        REFRESH_TOKEN: AccountGrant("acct_1", "c", ("a", "b"), later, True, "fam_1", now),
        ACCOUNT_FAMILY: AccountFamily("c", "acct_1", ("t1", "t2"), ("a1",), True),
        ACCOUNT_AGENT: AccountAgent(("fam_1", "fam_2")),
        CLIENT: KnownClient({"operations": "2"}),
        DEVICE: PendingDevice("c", ("a",), "ABCD-EFGH", later, 10, now, "acct_1", ("a",), True),
        USER_CODE: UserCode("dev_digest"),
        AUTHORIZATION: PendingAuthorization(
            "c", "https://atlas.example/cb", ("a",), "st", "chal", later, "Atlas", "bind"
        ),
        CODE: IssuedCode("c", "https://atlas.example/cb", "chal", ("a",), "acct_1", ("a",), later),
        MEDIATED: PendingMediated(
            "c", "acct_1", ("a",), "ref", later, "a•••@example.com", ("k1", "k2"), 2, "failed"
        ),
        CONVERSATION: StoredConversation(
            conversation_id="cnv_1",
            owner=("c", "u"),
            status="queued",
            responder="human",
            parent_id="cnv_0",
            direct_child="cnv_2",
            account_id="acct_1",
            events=(StoredEvent("evt_1", {"id": "evt_1", "type": "state", "nested": [1, None]}),),
            forgotten=frozenset({"evt_0"}),
        ),
        MESSAGE_ID: MessageReceipt("cnv_1", "digest"),
        OPERATION: operation,
        PROPOSAL: OperationProposal("op_1"),
        BROWSER_COOKIE: web,
        JOIN_CODE: JoinCode("browser_digest", web),
        REPLAY: ReplayMark(),
        DPOP_NONCE: IssuedNonce(),
        SIGN_IN_ATTEMPTS: SignInAttempts(3, later),
        FEEDBACK: StoredFeedback(
            "fb_1", "Pay with a gift card", "No gift card field.", "c", "u", now
        ),
        IDEMPOTENCY: IdempotencyRecord("digest", 200, {"summary": "Exchanged."}),
    }


async def check_store(
    make_store: Callable[[], CompanyStore | Awaitable[CompanyStore]],
    *,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    concurrency: int = _CONCURRENCY,
) -> None:
    """Check that the stores `make_store` returns keep the company store contract."""

    _check(concurrency >= 2, "concurrency must be at least 2")

    async def fresh() -> CompanyStore:
        made = make_store()
        return await made if inspect.isawaitable(made) else made

    await _absent(await fresh())
    await _present(await fresh())
    await _expiry(await fresh(), now())
    await _take_once(await fresh(), concurrency)
    await _create_once(await fresh(), concurrency)
    await _compare_and_set(await fresh(), concurrency)
    await _round_trips(await fresh(), now())
    await _records(await fresh(), now())


async def check_replay_cache(
    make_cache: Callable[[], ReplayCache | Awaitable[ReplayCache]],
    *,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    concurrency: int = _CONCURRENCY,
) -> None:
    """Check that the caches `make_cache` returns accept each identifier exactly once."""

    _check(concurrency >= 2, "concurrency must be at least 2")
    made = make_cache()
    cache = await made if inspect.isawaitable(made) else made
    until = now() + timedelta(minutes=5)
    marked = await asyncio.gather(
        *(cache.mark_once("proof:one", expires_at=until) for _ in range(concurrency))
    )
    _check(sum(marked) == 1, f"one identifier was accepted {sum(marked)} times, not once")
    _check(
        not await cache.mark_once("proof:one", expires_at=until),
        "an accepted identifier stays refused until it expires",
    )
    distinct = await asyncio.gather(
        *(cache.mark_once(f"proof:{n}:distinct", expires_at=until) for n in range(concurrency))
    )
    _check(all(distinct), "distinct identifiers are each accepted")


async def _absent(store: CompanyStore) -> None:
    _check(await store.get("conversation", "missing") is None, "get of a missing record")
    _check(await store.take("conversation", "missing") is None, "take of a missing record")
    _check(
        not await store.replace("conversation", "missing", "1", {"a": 1}),
        "replace of a missing record must fail",
    )
    await store.delete("conversation", "missing")


async def _present(store: CompanyStore) -> None:
    await store.put("conversation", "k", {"a": 1})
    first = await store.get("conversation", "k")
    _check(first is not None and first.value == {"a": 1}, "put then get returns the value")
    _check(await store.get("operation", "k") is None, "kinds are separate namespaces")
    await store.put("conversation", "k", {"a": 2})
    second = await store.get("conversation", "k")
    _check(second is not None and second.value == {"a": 2}, "put overwrites")
    _check(
        first is not None and second is not None and first.version != second.version,
        "every write gives a new version",
    )
    # Values are copies: changing what was written or read changes nothing stored.
    written: dict[str, Any] = {"list": [1], "nested": {"b": True}}
    await store.put("conversation", "copy", written)
    written["list"].append(2)
    read = await store.get("conversation", "copy")
    _check(read is not None and read.value["list"] == [1], "the store keeps a copy of the value")
    if read is not None:
        read.value["nested"]["b"] = False
    again = await store.get("conversation", "copy")
    _check(again is not None and again.value["nested"]["b"] is True, "reads return copies")
    await store.delete("conversation", "k")
    _check(await store.get("conversation", "k") is None, "delete removes the record")


async def _expiry(store: CompanyStore, now: datetime) -> None:
    past, future = now - timedelta(seconds=1), now + timedelta(hours=1)
    await store.put("code", "old", {"a": 1}, expires_at=past)
    _check(await store.get("code", "old") is None, "an expired record reads as absent")
    _check(await store.take("code", "old") is None, "an expired record cannot be taken")
    _check(
        await store.create("code", "old", {"a": 2}, expires_at=future),
        "create succeeds over an expired record",
    )
    entry = await store.get("code", "old")
    _check(entry is not None and entry.value == {"a": 2}, "the created record replaced it")
    _check(
        entry is not None
        and entry.expires_at is not None
        and abs((entry.expires_at - future).total_seconds()) < 1,
        "get returns the record's expiry",
    )
    await store.put("code", "lasting", {"a": 1})
    lasting = await store.get("code", "lasting")
    _check(lasting is not None and lasting.expires_at is None, "a record without expiry")
    if entry is not None:
        _check(
            await store.replace("code", "old", entry.version, {"a": 3}, expires_at=past),
            "replace may set an expiry",
        )
        _check(await store.get("code", "old") is None, "replace to a past expiry expires it")


async def _take_once(store: CompanyStore, concurrency: int) -> None:
    await store.put("authorization", "once", {"a": 1})
    taken = await asyncio.gather(*(store.take("authorization", "once") for _ in range(concurrency)))
    winners = [value for value in taken if value is not None]
    _check(len(winners) == 1, f"take returned the record {len(winners)} times, not once")
    _check(winners[0] == {"a": 1}, "take returns the value")
    _check(await store.get("authorization", "once") is None, "a taken record is gone")


async def _create_once(store: CompanyStore, concurrency: int) -> None:
    created = await asyncio.gather(
        *(store.create("message_id", "m", {"n": n}) for n in range(concurrency))
    )
    _check(sum(created) == 1, f"create succeeded {sum(created)} times, not once")
    entry = await store.get("message_id", "m")
    _check(
        entry is not None and entry.value == {"n": created.index(True)},
        "the record is the one whose create succeeded",
    )
    _check(not await store.create("message_id", "m", {"n": -1}), "create of a present record")


async def _compare_and_set(store: CompanyStore, concurrency: int) -> None:
    await store.put("operation", "op", {"state": "proposed"})
    entry = await store.get("operation", "op")
    _check(entry is not None, "the record is present")
    if entry is None:
        return
    replaced = await asyncio.gather(
        *(
            store.replace("operation", "op", entry.version, {"state": "in_progress", "n": n})
            for n in range(concurrency)
        )
    )
    _check(sum(replaced) == 1, f"replace on one version succeeded {sum(replaced)} times")
    _check(
        not await store.replace("operation", "op", entry.version, {"state": "stale"}),
        "replace with a stale version fails",
    )
    current = await store.get("operation", "op")
    _check(
        current is not None
        and current.value == {"state": "in_progress", "n": replaced.index(True)},
        "the record is the winning replace's",
    )
    _check(current is not None and current.version != entry.version, "replace gives a new version")


async def _round_trips(store: CompanyStore, now: datetime) -> None:
    samples = record_samples(now)
    _check(set(samples) == set(RECORD_KINDS), "a sample of every record kind")
    for kind in RECORD_KINDS:
        record = samples[kind]
        await store.put(kind, f"{kind}_key", record.to_json())
        entry = await store.get(kind, f"{kind}_key")
        _check(entry is not None, f"{kind}: the record reads back")
        if entry is not None:
            _check(RECORD_TYPES[kind](entry.value) == record, f"{kind}: the record round-trips")


async def _records(store: CompanyStore, now: datetime) -> None:
    later = now + timedelta(hours=1)
    await store.put("operation", "a", {"n": 1})
    await store.put("operation", "b", {"n": 2}, expires_at=later)
    await store.put("operation", "gone", {"n": 3}, expires_at=now - timedelta(seconds=1))
    await store.put("operation", "taken", {"n": 4})
    await store.take("operation", "taken")
    await store.put("operation", "deleted", {"n": 5})
    await store.delete("operation", "deleted")
    await store.put("conversation", "a", {"n": 6})
    found = await store.records("operation")
    _check(
        sorted(record.value["n"] for record in found) == [1, 2],
        "records reads every live record of its kind: nothing expired, taken, deleted"
        " or of another kind",
    )
    for record in found:
        entry = await store.get("operation", "a" if record.value["n"] == 1 else "b")
        _check(
            entry is not None
            and entry.version == record.version
            and entry.expires_at == record.expires_at,
            "records gives each record's version and expiry, as get does",
        )
        record.value["n"] = 0
    _check(
        sorted(record.value["n"] for record in await store.records("operation")) == [1, 2],
        "records returns copies",
    )
    _check(await store.records("device") == [], "records of a kind with nothing live")
