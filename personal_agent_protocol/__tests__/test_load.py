# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Bounded load tests: replay caches, rate-limit budgets, device polling, SSE fan-out.

Every test is marked `load` and sized by `PAP_LOAD_SIZE` (64 by default, so the
default run stays quick; the `load` CI job runs them at 512). Each prints its
numbers (`-s` shows them); `docs/docs/protocol/load-tests.mdx` records a run.

- **Replay.** `PAP_LOAD_SIZE` concurrent verifications of one DPoP proof, of one
  client assertion, and of one whole token request at the company: exactly one
  is accepted. The memory store and replay cache pass their conformance kits
  (`check_store`, `check_replay_cache`) at the same concurrency, and the replay
  cache stays bounded by the identifiers still alive.
- **Rate limits.** Concurrent callers on four companies' shared budgets: no
  company is ever sent more than its burst and rate allow, a company's pause
  holds every caller, and callers beyond `max_wait` are refused locally.
- **Device polling.** Many pollers: eager pollers send nothing before their
  interval, every round sends exactly one poll per sign-in, a company that sees
  polls too fast answers `slow_down` and the pollers add five seconds, and two
  polls of one sign-in at once send one.
- **SSE fan-out.** One conversation streamed to many subscribers, each from its
  own cursor, while the conversation grows and closes: each gets every event
  after its cursor once, in order.
"""

from __future__ import annotations

import asyncio
import os
import random
import time
from collections import Counter
from collections.abc import MutableMapping
from dataclasses import replace
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qsl

import pytest

from personal_agent_protocol import (
    DeviceSignInClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.company import MemoryCompanyStore, MemoryReplayCache
from personal_agent_protocol.company.store import DEVICE, PendingDevice
from personal_agent_protocol.company.testing import check_replay_cache, check_store
from personal_agent_protocol.company.verify import verify_assertion
from personal_agent_protocol.conversations import StreamReconnected, TextDelta
from personal_agent_protocol.crypto import JoseDpopProofProvider, verify_dpop_proof
from personal_agent_protocol.demo.kit import DpopKeys, MutableClock
from personal_agent_protocol.errors import (
    PersonalAgentProtocolError,
    ProofError,
    SessionError,
    TransportError,
)
from personal_agent_protocol.models import JsonWebKeySet
from personal_agent_protocol.reactor import DpopProofRequest, SharedRateLimitBudget

from .test_company_end_to_end import PAIRWISE, TENANT, World

pytestmark = pytest.mark.load

SIZE = int(os.environ.get("PAP_LOAD_SIZE", "64"))
TOKEN = "https://manzanita.example/oauth/token"


def report(name: str, **numbers: object) -> None:
    """The test's numbers, one line, in the test output."""

    shown = ", ".join(f"{key}={value}" for key, value in numbers.items())
    print(f"[load] {name}: size={SIZE}, {shown}")  # noqa: T201 - the numbers are the output


def _ms(start: float) -> str:
    return f"{(time.perf_counter() - start) * 1000:.1f}ms"


# Replay caches -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_replays_of_one_proof_and_one_assertion_accept_exactly_one() -> None:
    world = World()
    clock = world.clock
    now = clock.now()

    # One DPoP proof, verified by SIZE callers at once.
    provider = JoseDpopProofProvider(DpopKeys(), now=clock.now)
    proof = await provider.create(
        DpopProofRequest(
            method="POST", url=TOKEN, tenant_id=TENANT, subject=PAIRWISE, issuer="https://m"
        )
    )
    cache = MemoryReplayCache(clock)
    start = time.perf_counter()
    outcomes = await asyncio.gather(
        *(
            verify_dpop_proof(proof, method="POST", url=TOKEN, replay_cache=cache, now=now)
            for _ in range(SIZE)
        ),
        return_exceptions=True,
    )
    proof_time = _ms(start)
    accepted = [o for o in outcomes if not isinstance(o, BaseException)]
    refused = [o for o in outcomes if isinstance(o, ProofError)]
    assert len(accepted) == 1 and len(refused) == SIZE - 1
    assert {error.code for error in refused} == {"invalid_dpop_proof"}

    # One client assertion, verified by SIZE callers at once.
    claims = {
        "iss": world.atlas.client_id,
        "sub": world.atlas.client_id,
        "aud": TOKEN,
        "iat": int(now.timestamp()),
        "exp": int(now.timestamp()) + 60,
        "jti": "jti_one_assertion_many_callers",
    }
    assertion = await world.atlas.signer().sign(claims, purpose="client_assertion")
    keys = JsonWebKeySet.model_validate(world.atlas.jwks)
    start = time.perf_counter()
    outcomes = await asyncio.gather(
        *(
            verify_assertion(
                assertion,
                keys=keys,
                issuer=world.atlas.client_id,
                audience=TOKEN,
                subject=world.atlas.client_id,
                replay_cache=cache,
                now=now,
            )
            for _ in range(SIZE)
        ),
        return_exceptions=True,
    )
    assertion_time = _ms(start)
    accepted = [o for o in outcomes if not isinstance(o, BaseException)]
    assert len(accepted) == 1
    assert all(isinstance(o, SessionError) for o in outcomes if o not in accepted)

    # The kits, at the same concurrency.
    start = time.perf_counter()
    await check_replay_cache(lambda: MemoryReplayCache(clock), now=clock.now, concurrency=SIZE)
    await check_store(lambda: MemoryCompanyStore(clock), now=clock.now, concurrency=SIZE)
    kits_time = _ms(start)
    report(
        "replay",
        proof=f"1 of {SIZE} accepted in {proof_time}",
        assertion=f"1 of {SIZE} accepted in {assertion_time}",
        kits=kits_time,
    )


@pytest.mark.asyncio
async def test_one_token_request_replayed_concurrently_is_accepted_once() -> None:
    world = World()
    await world.signed_out_session()
    captured: dict[str, Any] = {}
    company = world.network.apps["manzanita.example"]

    async def capture_first(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        if scope["path"] == "/oauth/token" and "body" not in captured:
            body, more = b"", True
            while more:
                message = await receive()
                body += message.get("body", b"")
                more = message.get("more_body", False)
            captured["headers"] = {k.decode(): v.decode() for k, v in scope["headers"]}
            captured["body"] = body
            await send({"type": "http.response.start", "status": 503, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        await company(scope, receive, send)

    world.network.add("manzanita.example", capture_first)
    with pytest.raises(PersonalAgentProtocolError):
        await SessionClient(reactor=world.reactor, http_client=world.http).start(
            client_id=world.atlas.client_id,
            pairwise_user_id=PAIRWISE,
            issuer=world.who["issuer"],
            token_endpoint=TOKEN,
            tenant_id=TENANT,
        )
    world.network.add("manzanita.example", company)
    headers = {
        name: value
        for name, value in captured["headers"].items()
        if name in {"dpop", "content-type", "accept"}
    }
    start = time.perf_counter()
    answers = await asyncio.gather(
        *(world.http.post(TOKEN, content=captured["body"], headers=headers) for _ in range(SIZE))
    )
    statuses = Counter(answer.status_code for answer in answers)
    errors = Counter(answer.json()["error"] for answer in answers if answer.status_code != 200)
    assert statuses[200] == 1, statuses
    assert sum(errors.values()) == SIZE - 1
    assert set(errors) <= {"invalid_dpop_proof", "invalid_client"}
    report("token request replay", accepted=1, refused=dict(errors), time=_ms(start))


@pytest.mark.asyncio
async def test_the_memory_replay_cache_holds_only_live_identifiers() -> None:
    clock = MutableClock()
    cache = MemoryReplayCache(clock)
    rounds, per_round = 20, max(SIZE, 1024)
    largest = 0
    for round_ in range(rounds):
        until = clock.now() + timedelta(seconds=60)
        for n in range(per_round):
            assert await cache.mark_once(f"proof:{round_}:{n}", expires_at=until)
        largest = max(largest, len(cache))
        clock.advance(61)  # every identifier of this round has expired
    # Never every identifier ever seen: about twice those of one round.
    assert largest <= 2 * per_round + 1
    live = clock.now() + timedelta(seconds=60)
    assert await cache.mark_once("proof:live", expires_at=live)
    assert not await cache.mark_once("proof:live", expires_at=live)
    report("replay cache", identifiers=rounds * per_round, largest=largest)


# Rate-limit budgets ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shared_budgets_never_exceed_rate_and_burst_under_concurrent_callers() -> None:
    rate, burst = 2000.0, 8
    budget = SharedRateLimitBudget(rate=rate, burst=burst, max_wait=30.0)
    companies = [f"https://shop-{n}.example:443" for n in range(4)]
    admitted: dict[str, list[float]] = {company: [] for company in companies}
    asked: dict[str, float] = {}

    async def caller(company: str) -> None:
        asked.setdefault(company, time.monotonic())
        await budget.acquire(company)
        admitted[company].append(time.monotonic())

    callers = [companies[n % len(companies)] for n in range(SIZE * len(companies))]
    random.Random(7).shuffle(callers)  # noqa: S311 - an order, not a secret
    start = time.perf_counter()
    await asyncio.gather(*(caller(company) for company in callers))
    elapsed = _ms(start)
    tolerance = 0.001  # the event loop's clock granularity
    for company, times in admitted.items():
        assert len(times) == SIZE
        times.sort()
        for j in range(burst, len(times)):
            # The j-th request never goes before the budget, which started when the first
            # asked, had refilled for it.
            assert times[j] - asked[company] >= (j - burst + 1) / rate - tolerance
    report("rate budgets", companies=len(companies), requests=len(callers), time=elapsed)


@pytest.mark.asyncio
async def test_a_company_pause_holds_every_caller_and_long_waits_are_refused() -> None:
    rate, burst, pause, max_wait = 1000.0, 4, 0.03, 0.05
    budget = SharedRateLimitBudget(rate=rate, burst=burst, max_wait=max_wait)
    company = "https://shop.example:443"
    callers = SIZE + 64  # more than the burst and the rate can serve within max_wait
    await budget.defer(company, pause)
    start = time.monotonic()
    went: list[float] = []
    asked: list[float] = []

    async def caller() -> None:
        asked.append(time.monotonic())
        await budget.acquire(company)
        went.append(time.monotonic() - start)

    outcomes = await asyncio.gather(*(caller() for _ in range(callers)), return_exceptions=True)
    admitted = [o for o in outcomes if o is None]
    refused = [o for o in outcomes if isinstance(o, TransportError)]
    waited = max(went)
    assert min(went) >= pause - 0.002  # nobody went before the company's pause ended
    # Within max_wait: the burst at the pause's end, then what the rate allows until then
    # (the last callers ask a little later, so their max_wait reaches a little further).
    expected = burst + int((max_wait - pause) * rate)
    spread = int((max(asked) - min(asked)) * rate)
    assert expected - 1 <= len(admitted) <= expected + 1 + spread
    assert len(admitted) + len(refused) == callers
    assert {error.code for error in refused} <= {"rate_limited"}
    assert all(error.details.get("retry_after") for error in refused)
    report("rate pause", admitted=len(admitted), refused=len(refused), waited=f"{waited:.3f}s")


# Device-flow polling -------------------------------------------------------------------------


def _counting_device_polls(company: Any, polls: Counter[str]) -> Any:
    """The company's app, counting the device-grant token requests it receives."""

    async def counting(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        if scope["path"] != "/oauth/token":
            await company(scope, receive, send)
            return
        body, more = b"", True
        while more:
            message = await receive()
            body += message.get("body", b"")
            more = message.get("more_body", False)
        if dict(parse_qsl(body.decode())).get("grant_type", "").endswith("device_code"):
            polls["http"] += 1
        delivered = False

        async def replay() -> dict[str, Any]:
            nonlocal delivered
            if delivered:
                return {"type": "http.disconnect"}
            delivered = True
            return {"type": "http.request", "body": body, "more_body": False}

        await company(scope, replay, send)

    return counting


@pytest.mark.asyncio
async def test_many_device_pollers_respect_interval_and_slow_down() -> None:
    world = World()
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None and metadata.device_authorization_endpoint is not None
    polls: Counter[str] = Counter()
    counting = _counting_device_polls(world.network.apps["manzanita.example"], polls)
    world.network.add("manzanita.example", counting)
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    users = [f"usr_poller_{n:06d}_padding_0000" for n in range(SIZE)]
    start = time.perf_counter()

    async def begin(user: str) -> Any:
        session = await sessions.start(
            client_id=world.atlas.client_id,
            pairwise_user_id=user,
            issuer=metadata.issuer,
            token_endpoint=metadata.token_endpoint,
            tenant_id=TENANT,
        )
        return await device.begin(
            device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=world.atlas.client_id,
            scopes=("orders:read",),
            tenant_id=TENANT,
            pairwise_user_id=user,
            session_id=session.session_id,
        )

    started = await asyncio.gather(*(begin(user) for user in users))
    begun = _ms(start)
    interval = started[0].poll_interval

    async def round_(times: int = 1) -> list[Any]:
        before = polls["http"]
        results = await asyncio.gather(
            *(device.poll(s.reference) for s in started for _ in range(times)),
            return_exceptions=True,
        )
        polls["round"] = polls["http"] - before
        return results

    # Eager pollers, before the interval: nothing is sent.
    eager = await round_(times=1)
    assert polls["round"] == 0 and all(r.status == "pending" for r in eager)
    # Each interval: exactly one poll per sign-in, and no slow_down.
    for _ in range(3):
        world.clock.advance(interval)
        paced = await round_()
        assert polls["round"] == SIZE and all(r.status == "pending" for r in paced)
    store = world.shop.store
    for key in store.keys(DEVICE):
        entry = await store.get(DEVICE, key)
        assert entry is not None and PendingDevice.from_json(entry.value).interval == interval

    # Two polls of one sign-in at once: one is sent; the other is refused while the first
    # is in flight, or answered locally after it.
    world.clock.advance(interval)
    doubled = await round_(times=2)
    assert polls["round"] == SIZE
    assert all(isinstance(r, PersonalAgentProtocolError) or r.status == "pending" for r in doubled)

    # The company saw polls just now (another replica, a retry): slow_down for everyone.
    world.clock.advance(interval)
    for key in store.keys(DEVICE):
        entry = await store.get(DEVICE, key)
        assert entry is not None
        seen = replace(PendingDevice.from_json(entry.value), last_poll=world.clock.now())
        await store.put(DEVICE, key, seen.to_json(), expires_at=entry.expires_at)
    slowed = await round_()
    assert polls["round"] == SIZE and all(r.status == "pending" for r in slowed)
    world.clock.advance(interval)  # the old interval is no longer enough: nothing is sent
    await round_()
    assert polls["round"] == 0
    world.clock.advance(5)
    await round_()
    assert polls["round"] == SIZE

    # Half approve; the next round completes them, once each.
    for s in started[::2]:
        await world.shop.approve_device(s.user_code, account_id="acct_ada")
    world.clock.advance(interval + 5)
    final = await round_()
    complete = [r for r in final if r.status == "complete"]
    assert len(complete) == len(started[::2]) and polls["round"] == SIZE
    report(
        "device polling",
        pollers=SIZE,
        begun=begun,
        http_polls=polls["http"],
        time=_ms(start),
    )


# SSE fan-out ----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_one_conversation_fans_out_to_many_subscribers_from_their_cursors() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    conversations = world.conversations

    def message(text: str) -> Message:
        return Message(id=generate_message_id(world.reactor), sender="human", text=text)

    page = await conversations.start(endpoint, message("Hello"), token=session, wait=0, **world.who)
    conversation_id = page.conversation_id
    for n in range(4):
        await conversations.send(
            endpoint, conversation_id, message(f"Before {n}"), token=session, wait=0, **world.who
        )
    initial = await conversations.read_events(endpoint, conversation_id, token=session, **world.who)
    cursors = [None, *(event.id for event in initial.events)]
    reconnects: Counter[str] = Counter()

    async def subscriber(n: int) -> tuple[str | None, list[str]]:
        cursor = cursors[n % len(cursors)]
        received: list[str] = []
        async for item in conversations.stream(
            endpoint,
            conversation_id,
            token=session,
            last_event_id=cursor,
            max_reconnects=1_000_000,
            **world.who,
        ):
            if isinstance(item, StreamReconnected):
                reconnects["reconnects"] += 1
                await asyncio.sleep(0.001)  # the stream ended: reconnect from the last event
            elif not isinstance(item, TextDelta):
                received.append(item.id)
        return cursor, received

    async def producer() -> None:
        for n in range(8):
            await conversations.send(
                endpoint,
                conversation_id,
                message(f"During {n}"),
                token=session,
                wait=0,
                **world.who,
            )
            await asyncio.sleep(0.002)
        await conversations.close(endpoint, conversation_id, token=session, **world.who)

    start = time.perf_counter()
    results, _ = await asyncio.gather(
        asyncio.gather(*(subscriber(n) for n in range(SIZE))), producer()
    )
    elapsed = _ms(start)
    everything = [
        event.id
        async for event in conversations.events(
            endpoint, conversation_id, token=session, wait=0, **world.who
        )
    ]
    assert len(everything) == len(set(everything))
    delivered = 0
    for cursor, received in results:
        expected = everything[everything.index(cursor) + 1 :] if cursor else everything
        assert received == expected  # every event after the cursor, once, in order
        delivered += len(received)
    report(
        "SSE fan-out",
        subscribers=SIZE,
        events=len(everything),
        delivered=delivered,
        reconnects=reconnects["reconnects"],
        time=elapsed,
    )
