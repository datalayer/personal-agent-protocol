# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Guide-level behaviour: bounded metadata caching, overlapping JWKS, retries, shared budgets."""

from __future__ import annotations

import asyncio
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    AgentIdentityClient,
    DiscoveryClient,
    DpopHttpClient,
    DpopProofRequest,
    SessionToken,
    TransportError,
    build_pap_reactor,
)
from personal_agent_protocol.caching import CacheBounds, cache_lifetime
from personal_agent_protocol.company import IdentityClientResolver
from personal_agent_protocol.demo.kit import MutableClock
from personal_agent_protocol.reactor import (
    RATE_LIMIT_BUDGETS,
    RETRY_POLICIES,
    RetryPolicy,
    SharedRateLimitBudget,
    parse_retry_after,
)

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"
CLIENT_ID = "https://agent.example/agent.json"
NOW = datetime(2026, 10, 11, 9, tzinfo=timezone.utc)


def fixture(name: str) -> dict[str, Any]:
    return json.loads((FIXTURES / name).read_text())


async def public(_: str) -> list[str]:
    return ["93.184.216.34"]


class Host:
    """A personal agent's contributions for these tests: a clock and DPoP proofs."""

    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock
        self.proofs: list[DpopProofRequest] = []

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.proofs.append(request)
        return SecretStr(f"proof-{len(self.proofs)}")

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(CLOCKS, self.clock, contribution_id="test-clock")
        contribute(DPOP_PROOF_PROVIDERS, self, contribution_id="proofs")


def reactor_with(http: httpx.AsyncClient, host: Host, *extra: tuple[object, object]) -> Any:
    class Extra:
        def provide_contributions(self, contributions: object) -> None:
            for point, value in extra:
                contributions.contribute(point, value, contribution_id="test", order=1)  # type: ignore[attr-defined]

    reactor, _ = build_pap_reactor(
        http_client=http,
        address_resolver=public,
        plugins=[
            (PluginManifest(name="guidance-host", version="1"), host),
            (PluginManifest(name="guidance-extra", version="1"), Extra()),
        ],
    )
    return reactor


# Cache-Control within bounds ---------------------------------------------------------


@pytest.mark.parametrize(
    ("header", "seconds"),
    [
        (None, 60.0),
        ("max-age=3600", 3600.0),
        ("public, max-age=10", 60.0),  # at least a minute
        ("max-age=172800", 86_400.0),  # at most a day
        ("no-store", None),
        ("no-cache", None),
        ("max-age=0", None),
        ("max-age=soon", None),
        ("public", 60.0),
    ],
)
def test_cache_lifetime_follows_cache_control_within_bounds(
    header: str | None, seconds: float | None
) -> None:
    headers = {} if header is None else {"Cache-Control": header}
    assert cache_lifetime(headers, CacheBounds()) == seconds


def test_cache_bounds_are_checked() -> None:
    with pytest.raises(ValueError):
        CacheBounds(min_seconds=120, max_seconds=60)
    with pytest.raises(ValueError):
        CacheBounds(default_seconds=10)


@pytest.mark.asyncio
async def test_discovery_and_oauth_metadata_are_cached_until_they_expire() -> None:
    fetched: list[str] = []
    cache_control = {"example.com": "max-age=300", "auth.example.com": "max-age=30"}

    def handler(request: httpx.Request) -> httpx.Response:
        fetched.append(request.url.host)
        name = (
            "discovery-valid.json"
            if request.url.host == "example.com"
            else "oauth-metadata-valid.json"
        )
        return httpx.Response(
            200,
            json=fixture(name),
            headers={"Cache-Control": cache_control[request.url.host]},
        )

    clock = MutableClock(NOW)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = DiscoveryClient(reactor=reactor_with(http, Host(clock)))
        await client.discover("example.com")
        await client.discover("example.com")
        assert fetched == ["example.com", "auth.example.com"]
        clock.advance(61)  # the OAuth metadata's 30 s became a minute; it is now stale
        await client.discover("example.com")
        assert fetched == ["example.com", "auth.example.com", "auth.example.com"]
        clock.advance(300)
        await client.discover("example.com")
    assert fetched[-2:] == ["example.com", "auth.example.com"]


@pytest.mark.asyncio
async def test_no_store_metadata_is_fetched_every_time() -> None:
    fetched: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetched.append(request.url.path)
        return httpx.Response(
            200, json=fixture("client-metadata-valid.json"), headers={"Cache-Control": "no-store"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = AgentIdentityClient(reactor=reactor_with(http, Host(MutableClock(NOW))))
        await client.fetch_metadata(CLIENT_ID)
        await client.fetch_metadata(CLIENT_ID)
    assert fetched == ["/agent.json", "/agent.json"]


# Overlapping JWKS ---------------------------------------------------------------------


def _rotated_jwks() -> dict[str, Any]:
    keys = fixture("jwks-valid.json")
    newer = copy.deepcopy(keys["keys"][0])
    newer["kid"] = "agent-signing-2026-11"
    return {"keys": [*keys["keys"], newer]}


@pytest.mark.asyncio
async def test_unknown_kid_refetches_the_overlapping_jwks_rate_limited() -> None:
    jwks = [fixture("jwks-valid.json")]
    fetches: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetches.append(request.url.path)
        if request.url.path == "/agent.json":
            return httpx.Response(200, json=fixture("client-metadata-valid.json"))
        return httpx.Response(200, json=jwks[-1], headers={"Cache-Control": "max-age=3600"})

    clock = MutableClock(NOW)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        identity = AgentIdentityClient(reactor=reactor_with(http, Host(clock)))
        resolver = IdentityClientResolver(identity)
        _, keys = await resolver.resolve(CLIENT_ID, kid="agent-signing-2026-10")
        assert [key.kid for key in keys.keys] == ["agent-signing-2026-10"]
        # The agent publishes its next key beside the current one (overlap) and uses it.
        jwks.append(_rotated_jwks())
        _, keys = await resolver.resolve(CLIENT_ID, kid="agent-signing-2026-11")
        assert [key.kid for key in keys.keys] == ["agent-signing-2026-10", "agent-signing-2026-11"]
        # A known kid, and a stream of unknown ones, cause no further fetch for a while.
        await resolver.resolve(CLIENT_ID, kid="agent-signing-2026-10")
        for forged in ("forged-1", "forged-2", "forged-3"):
            await resolver.resolve(CLIENT_ID, kid=forged)
        assert fetches.count("/jwks.json") == 2
        clock.advance(61)
        await resolver.resolve(CLIENT_ID, kid="forged-4")
        assert fetches.count("/jwks.json") == 3
    # Metadata without Cache-Control is kept a minute: once in the first minute, once after.
    assert fetches.count("/agent.json") == 2


# Retry-After, backoff and jitter ------------------------------------------------------


def test_retry_policy_honours_retry_after_backs_off_with_jitter_and_caps() -> None:
    policy = RetryPolicy(max_attempts=5, base_delay=1.0, max_delay=4.0, max_retry_after=10.0)
    # Never sooner than Retry-After; jitter adds at most base_delay.
    assert policy.delay(1, 3.0, 0.0) == 3.0
    assert policy.delay(1, 3.0, 0.999) == pytest.approx(3.999)
    # A Retry-After longer than the policy allows goes back to the caller.
    assert policy.delay(1, 30.0, 0.5) is None
    # Exponential backoff with "equal jitter": within [backoff/2, backoff], capped.
    for attempts, backoff in ((1, 1.0), (2, 2.0), (3, 4.0), (4, 4.0)):
        low, high = policy.delay(attempts, None, 0.0), policy.delay(attempts, None, 0.999999)
        assert low == backoff / 2
        assert high == pytest.approx(backoff, rel=1e-5)
    # A limited number of attempts.
    assert policy.delay(5, None, 0.5) is None
    assert policy.delay(5, 1.0, 0.5) is None


def test_retry_after_parses_seconds_and_dates() -> None:
    assert parse_retry_after("120", NOW) == 120.0
    assert parse_retry_after("Sun, 11 Oct 2026 09:00:30 GMT", NOW) == 30.0
    assert parse_retry_after("Sun, 11 Oct 2026 08:00:00 GMT", NOW) == 0.0
    assert parse_retry_after("later", NOW) is None
    assert parse_retry_after(None, NOW) is None


class FakeTime:
    """A monotonic clock that `sleep` moves, recording each wait."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.slept: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.slept.append(round(seconds, 6))
        self.now += seconds


def session() -> SessionToken:
    return SessionToken(
        access_token=SecretStr("session-secret"),
        token_type="DPoP",  # noqa: S106 - the OAuth token type
        expires_in=300,
        session_key="K" * 43,
        signed_in=True,
        scope="orders:read",
    )


WHO = {"tenant_id": "t", "issuer": "https://shop.example"}


@pytest.mark.asyncio
async def test_safe_requests_retry_after_retry_after_with_fresh_proofs() -> None:
    answers = [
        httpx.Response(503, headers={"Retry-After": "2"}),
        httpx.Response(429, headers={"Retry-After": "1"}),
        httpx.Response(200, json={"orders": []}),
    ]
    seen: list[str] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["dpop"])
        return answers.pop(0)

    time = FakeTime()
    budget = SharedRateLimitBudget(sleep=time.sleep, monotonic=time.monotonic)
    host = Host(MutableClock(NOW))
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor = reactor_with(
            http,
            host,
            (RATE_LIMIT_BUDGETS, budget),
            (RETRY_POLICIES, RetryPolicy(base_delay=0.5, max_attempts=3)),
        )
        response = await DpopHttpClient(reactor=reactor, http_client=http).request(
            "GET", "https://shop.example/api/orders", token=session(), **WHO
        )
    assert response.status_code == 200
    assert seen == ["proof-1", "proof-2", "proof-3"]  # a fresh proof for every attempt
    assert len(time.slept) == 2
    assert 2.0 <= time.slept[0] <= 2.5
    assert 1.0 <= time.slept[1] <= 1.5


@pytest.mark.asyncio
async def test_writes_and_long_pauses_go_back_to_the_caller_and_are_shared() -> None:
    calls = 0
    retry_after = ["5"]

    def company(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429, headers={"Retry-After": retry_after[-1]})

    time = FakeTime()
    budget = SharedRateLimitBudget(sleep=time.sleep, monotonic=time.monotonic, max_wait=10)
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor = reactor_with(http, Host(MutableClock(NOW)), (RATE_LIMIT_BUDGETS, budget))
        client = DpopHttpClient(reactor=reactor, http_client=http)
        refused = await client.request(
            "POST", "https://shop.example/api/orders", token=session(), content=b"{}", **WHO
        )
        assert refused.status_code == 429
        assert calls == 1  # a write is never retried on its own
        # Another task, for the same company, now waits out the shared pause first.
        await budget.acquire("https://shop.example:443")
        assert time.slept == [5.0]
        # Told to wait longer than the policy's maximum: reported, not waited for.
        retry_after.append("30")
        refused = await client.request(
            "GET", "https://shop.example/api/orders", token=session(), **WHO
        )
        assert refused.status_code == 429
        assert calls == 2
        assert time.slept == [5.0]


@pytest.mark.asyncio
async def test_shared_budget_paces_tasks_and_refuses_long_waits() -> None:
    time = FakeTime()
    budget = SharedRateLimitBudget(
        rate=2.0, burst=2, max_wait=3.0, sleep=time.sleep, monotonic=time.monotonic
    )
    await asyncio.gather(*(budget.acquire("https://shop.example:443") for _ in range(4)))
    # Two in the burst, then one every half second, whichever task asks.
    assert time.slept == [0.5, 0.5]
    await budget.acquire("https://other.example:443")  # another company has its own budget
    assert time.slept == [0.5, 0.5]
    await budget.defer("https://shop.example:443", 60)
    with pytest.raises(TransportError) as raised:
        await budget.acquire("https://shop.example:443")
    assert raised.value.code == "rate_limited"
    assert raised.value.details == {"retry_after": "60"}


def test_the_core_contributes_cache_retry_and_budget_defaults() -> None:
    from personal_agent_protocol import CACHES

    reactor, owned = build_pap_reactor()
    try:
        assert reactor.get_contributions(CACHES)
        assert isinstance(reactor.get_contributions(RETRY_POLICIES)[0].value, RetryPolicy)
        assert isinstance(
            reactor.get_contributions(RATE_LIMIT_BUDGETS)[0].value, SharedRateLimitBudget
        )
    finally:
        assert owned is not None
        asyncio.run(owned.aclose())
