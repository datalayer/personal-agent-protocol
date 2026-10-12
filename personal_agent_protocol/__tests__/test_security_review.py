# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Regression tests for the findings of the 0.10.0 security review (docs: security/review).

Each test is a reviewer's probe turned into an assertion: it failed before the
fix it names, and passes after.
"""

from __future__ import annotations

import json

import httpx
import pytest
from reactor import PluginManifest

from personal_agent_protocol import DeviceSignInClient, SessionClient
from personal_agent_protocol.company import CLIENT_POLICIES, CompanyConfig
from personal_agent_protocol.company.asgi import company_app
from personal_agent_protocol.company.service import WEB_COOKIE
from personal_agent_protocol.company.store import SESSION, StoredSession
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE

from .test_company_end_to_end import PAIRWISE, TENANT, World
from .test_company_refusals import signed_in

MEDIATED = "https://manzanita.example/poppy/sign-in"


async def _post_json(world: World, session: object, url: str, body: object) -> httpx.Response:
    return await world.transport.request(
        "POST",
        url,
        token=session,  # type: ignore[arg-type]
        content=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
        **world.who,
    )


def _spy_token_responses(world: World) -> list[httpx.Response]:
    captured: list[httpx.Response] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        response = await original(request)
        if request.url.path in {"/oauth/token", "/poppy/sign-in"} or request.url.path.startswith(
            "/poppy/sign-in/"
        ):
            await response.aread()
            captured.append(response)
        return response

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    return captured


async def _bearer(world: World, session_id: str) -> None:
    md = world.company.oauth_metadata
    mcp = next(a.url for a in world.company.document.apis if a.type == "mcp")  # type: ignore[union-attr]
    bearer = await SessionClient(reactor=world.reactor, http_client=world.http).bearer_for_mcp(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=md.issuer,  # type: ignore[union-attr]
        token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
        tenant_id=TENANT,
        session_id=session_id,
        resource=mcp,
    )
    assert bearer.token_type == "Bearer"


async def _assert_signed_in_dpop(world: World, session_id: str, access_token: str) -> None:
    stored = StoredSession.from_json(
        (await world.shop.store.get(SESSION, session_id)).value  # type: ignore[union-attr]
    )
    kinds = sorted((t.token_type, t.signed_in, t.resource) for t in stored.tokens.values())
    # The signed-in token is DPoP and for no resource; the MCP Bearer token is kept, signed out.
    assert kinds == [("Bearer", False, "https://manzanita.example/mcp"), ("DPoP", True, None)]
    used = await world.http.post(
        "https://manzanita.example/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"authorization": f"Bearer {access_token}"},
    )
    assert used.status_code == 401


@pytest.mark.asyncio
async def test_finding_1_device_sign_in_after_an_mcp_bearer_token_stays_dpop() -> None:
    world = World()
    session = await world.signed_out_session()
    md = world.company.oauth_metadata
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=md.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
        issuer=md.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    await _bearer(world, session.session_id)
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    captured = _spy_token_responses(world)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.token is not None
    assert done.token.token_type == "DPoP" and done.token.signed_in
    await _assert_signed_in_dpop(world, session.session_id, captured[-1].json()["access_token"])


@pytest.mark.asyncio
async def test_finding_1_mediated_sign_in_after_an_mcp_bearer_token_stays_dpop() -> None:
    world = World()
    session = await world.signed_out_session()
    await _bearer(world, session.session_id)
    started = await _post_json(
        world, session, MEDIATED, {"credentials": dict(ADA), "scope": "orders:read"}
    )
    sign_in_id = started.json()["sign_in_id"]
    done = await _post_json(world, session, f"{MEDIATED}/{sign_in_id}", {"code": ADA_CODE})
    body = done.json()
    assert body["status"] == "complete" and body["token_type"] == "DPoP"
    await _assert_signed_in_dpop(world, session.session_id, body["access_token"])


@pytest.mark.asyncio
async def test_finding_3_a_retried_start_answers_only_who_may_read_the_conversation() -> None:
    world = World()
    token = await signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    message = world.message("Where is my jacket order?")
    await world.conversations.start(endpoint, message, token=token, wait=0, **world.who)
    signed_out = await world.signed_out_session()
    retried = await _post_json(
        world,
        signed_out,
        endpoint + "?wait=0",
        {"message": message.model_dump(mode="json", exclude_none=True)},
    )
    assert retried.status_code == 403
    assert retried.json() == {"error": "sign_in_required"}


def test_finding_5_operations_without_a_write_scope_is_a_configuration_error() -> None:
    with pytest.raises(ValueError, match="write_scopes"):
        CompanyConfig(name="Shop", domain="shop.example", scopes=("orders:read",))
    with pytest.raises(ValueError, match="among scopes"):
        CompanyConfig(
            name="Shop", domain="shop.example", scopes=("a:read",), write_scopes=("a:write",)
        )
    CompanyConfig(name="Shop", domain="shop.example", scopes=("orders:read",), operations=False)


@pytest.mark.asyncio
async def test_finding_5_an_operation_records_and_requires_its_scopes() -> None:
    from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
    from personal_agent_protocol.operations import OperationError, OperationsClient, approve

    world = World()
    session = await world.signed_out_session()
    md = world.company.oauth_metadata
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=md.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
        issuer=md.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Exchange my jacket for a warmer one"),
        token=done.token,
        wait=0,
        **world.who,
    )
    proposal = next(e.message.operation for e in page.events if e.message and e.message.operation)
    record = await world.shop.operation_record(proposal.operation_id)
    assert record.scopes == ("orders:write",)
    narrowed = await AccountTokenClient(reactor=world.reactor, http_client=world.http).refresh(
        done.account_token_reference,  # type: ignore[arg-type]
        context=AccountTokenContext(
            token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
            revocation_endpoint=md.revocation_endpoint,  # type: ignore[union-attr]
            issuer=md.issuer,  # type: ignore[union-attr]
            client_id=world.atlas.client_id,
            tenant_id=TENANT,
            pairwise_user_id=PAIRWISE,
        ),
        session_id=session.session_id,
        scopes=("orders:read",),
    )
    assert narrowed.token is not None
    operations = OperationsClient(transport=world.transport)
    with pytest.raises(OperationError) as raised:
        await operations.confirm(
            world.company.document.extensions["operations"].endpoint,  # type: ignore[index,union-attr]
            proposal,
            approval=approve(proposal),
            token=narrowed.token,
            **world.who,
        )
    assert raised.value.code == "insufficient_scope"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scope", "expected"),
    [("orders:read bogus:scope", 400), (None, 400), ("", 400), ("admin:all", 400), (7, 400)],
)
async def test_finding_8_mediated_sign_in_refuses_unknown_or_missing_scopes(
    scope: object, expected: int
) -> None:
    world = World()
    session = await world.signed_out_session()
    body: dict[str, object] = {"credentials": dict(ADA)}
    if scope is not None:
        body["scope"] = scope
    response = await _post_json(world, session, MEDIATED, body)
    assert response.status_code == expected
    assert response.json() == {"error": "invalid_scope"}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [b"[]", b'"text"', b"{", b'{"message": {"id": 3}}', b'{"message": []}'],
)
async def test_finding_10_a_malformed_conversation_body_is_a_400(body: bytes) -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    response = await world.transport.request(
        "POST",
        endpoint,
        token=session,
        content=body,
        headers={"content-type": "application/json"},
        **world.who,
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [b"authorization", b"dpop"])
async def test_finding_10_a_repeated_credential_header_is_refused(name: bytes) -> None:
    world = World()
    await world.signed_out_session()
    app = company_app(world.shop)
    sent: list[dict[str, object]] = []

    async def receive() -> dict[str, object]:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(message: dict[str, object]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "method": "POST",
            "path": "/poppy/conversations",
            "query_string": b"",
            "headers": [(name, b"DPoP one"), (name, b"DPoP two")],
        },
        receive,  # type: ignore[arg-type]
        send,  # type: ignore[arg-type]
    )
    assert sent[0]["status"] == 400
    assert json.loads(sent[1]["body"]) == {"error": "invalid_request"}  # type: ignore[arg-type]


class _Blocklist:
    def __init__(self) -> None:
        self.blocked: set[str] = set()

    async def allows(self, client_id: str) -> bool:
        return client_id not in self.blocked


def _block(world: World) -> _Blocklist:
    policy = _Blocklist()

    class Policy:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(CLIENT_POLICIES, policy, contribution_id="blocklist", order=10)  # type: ignore[attr-defined]

    world.shop.reactor.register_plugin(PluginManifest(name="blocklist", version="1"), Policy())
    return policy


@pytest.mark.asyncio
async def test_finding_11_a_blocked_agent_is_never_resolved_and_its_tokens_stop() -> None:
    world = World()
    session = await world.signed_out_session()
    policy = _block(world)
    resolver_calls: list[str] = []
    from personal_agent_protocol.company import CLIENT_RESOLVERS
    from personal_agent_protocol.reactor import first_contribution

    resolver = first_contribution(world.shop.reactor, CLIENT_RESOLVERS, "client")
    resolve = resolver.resolve  # type: ignore[attr-defined]

    async def counting(client_id: str, **kwargs: object):  # type: ignore[no-untyped-def]
        resolver_calls.append(client_id)
        return await resolve(client_id, **kwargs)

    resolver.resolve = counting  # type: ignore[attr-defined]
    policy.blocked.add(world.atlas.client_id)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    started = await world.transport.request(
        "POST",
        endpoint,
        token=session,
        content=json.dumps(
            {"message": world.message("hi").model_dump(mode="json", exclude_none=True)}
        ).encode(),
        headers={"content-type": "application/json"},
        **world.who,
    )
    assert started.status_code == 401 and started.json()["error"] == "invalid_token"
    authorize = await world.http.get(
        "https://manzanita.example/oauth/authorize",
        params={
            "client_id": world.atlas.client_id,
            "redirect_uri": "https://atlas.example/callback",
            "response_type": "code",
            "scope": "orders:read",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 400
    browser = await world.http.post(
        "https://manzanita.example/poppy/browser-session",
        data={"assertion": _unsigned({"iss": world.atlas.client_id})},
    )
    assert browser.status_code == 400
    assert resolver_calls == []


def _unsigned(claims: dict[str, object]) -> str:
    import base64

    def part(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'ES256', 'typ': 'JWT'})}.{part(claims)}.{part('sig')}"


def test_finding_17_the_web_cookie_is_a_host_cookie() -> None:
    assert WEB_COOKIE == "__Host-poppy_session"


def _ignore_retry_after(world: World) -> None:
    """The host would wait out each `Retry-After` itself: these tests ask the company anyway."""

    from personal_agent_protocol.reactor import RATE_LIMIT_BUDGETS

    class Unlimited:
        async def acquire(self, key: str) -> None:
            return None

        async def defer(self, key: str, seconds: float) -> None:
            return None

    class Plugin:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(
                RATE_LIMIT_BUDGETS, Unlimited(), contribution_id="unlimited", order=10
            )  # type: ignore[attr-defined]

    world.reactor.register_plugin(PluginManifest(name="unlimited", version="1"), Plugin())


@pytest.mark.asyncio
async def test_finding_2_wrong_passwords_lock_the_account_out_with_backoff() -> None:
    world = World()
    _ignore_retry_after(world)
    session = await world.signed_out_session()
    directory = world.plugin.accounts  # type: ignore[attr-defined]
    seen: list[object] = []
    authenticate = directory.authenticate

    async def spy(credentials, context):  # type: ignore[no-untyped-def]
        seen.append(context)
        return await authenticate(credentials, context)

    directory.authenticate = spy
    wrong = {"email": ADA["email"], "password": "wrong"}
    answers = [
        await _post_json(world, session, MEDIATED, {"credentials": wrong, "scope": "orders:read"})
        for _ in range(8)
    ]
    assert [a.status_code for a in answers] == [200] * 5 + [429] * 3
    assert {a.json().get("status") for a in answers[:5]} == {"failed"}
    assert answers[5].json() == {"error": "rate_limited"}
    assert int(answers[5].headers["retry-after"]) == 15 * 60
    # Locked out: the directory is not asked, even with the right password.
    assert len(seen) == 5
    right = await _post_json(
        world, session, MEDIATED, {"credentials": dict(ADA), "scope": "orders:read"}
    )
    assert right.status_code == 429 and len(seen) == 5
    # The directory hears which agent and Session each attempt came from.
    assert seen[0].client_id == world.atlas.client_id  # type: ignore[attr-defined]
    assert seen[0].session_id == session.session_id  # type: ignore[attr-defined]
    # Once the lockout ends, the next failure locks the account out twice as long.
    world.clock.advance(15 * 60)
    again = await _post_json(
        world, session, MEDIATED, {"credentials": wrong, "scope": "orders:read"}
    )
    assert again.status_code == 200
    doubled = await _post_json(
        world, session, MEDIATED, {"credentials": wrong, "scope": "orders:read"}
    )
    assert doubled.status_code == 429 and int(doubled.headers["retry-after"]) == 30 * 60


@pytest.mark.asyncio
async def test_finding_2_wrong_codes_count_per_account_across_sign_ins() -> None:
    world = World()
    _ignore_retry_after(world)
    session = await world.signed_out_session()
    last = None
    for _ in range(5):
        started = await _post_json(
            world,
            session,
            MEDIATED,
            {"credentials": dict(ADA), "scope": "orders:read orders:write"},
        )
        if started.status_code == 429:
            last = started
            break
        sign_in_id = started.json()["sign_in_id"]
        for attempt in range(3):
            answer = await _post_json(
                world, session, f"{MEDIATED}/{sign_in_id}", {"code": f"00000{attempt}"}
            )
            if answer.json().get("status") == "failed":
                break
    assert last is not None and last.json() == {"error": "rate_limited"}
    # A right code after the account's code budget is spent does not sign in either.
    world.clock.advance(15 * 60)
    started = await _post_json(
        world, session, MEDIATED, {"credentials": dict(ADA), "scope": "orders:read"}
    )
    done = await _post_json(
        world, session, f"{MEDIATED}/{started.json()['sign_in_id']}", {"code": ADA_CODE}
    )
    assert done.json()["status"] == "complete"


@pytest.mark.asyncio
async def test_finding_4_a_proof_replayed_at_another_replica_is_refused() -> None:
    world = World(durable=True)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("hello"), token=session, wait=0, **world.who
    )
    captured: list[httpx.Request] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await original(request)

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    await world.conversations.read_events(
        endpoint, page.conversation_id, token=session, **world.who
    )
    request = next(r for r in captured if r.method == "GET")
    world.restart()  # another replica over the same store, with the default replay cache
    other = await world.http.get(str(request.url), headers=dict(request.headers))
    assert other.status_code == 401 and other.json()["error"] == "invalid_dpop_proof"


@pytest.mark.asyncio
async def test_finding_4_the_memory_store_forgets_expired_records() -> None:
    from datetime import timedelta

    from personal_agent_protocol.company import MemoryCompanyStore, StoreReplayCache
    from personal_agent_protocol.company.testing import check_replay_cache
    from personal_agent_protocol.demo.kit import MutableClock

    clock = MutableClock()
    store = MemoryCompanyStore(clock)
    cache = StoreReplayCache(lambda: store)
    for index in range(5000):
        assert await cache.mark_once(f"jti-{index}", expires_at=clock.now() + timedelta(seconds=60))
        if index % 100 == 99:
            clock.advance(61)
    assert len(store) < 2100

    def fresh() -> StoreReplayCache:
        one = MemoryCompanyStore()
        return StoreReplayCache(lambda: one)

    await check_replay_cache(fresh)
