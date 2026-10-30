# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Regression tests for the findings of the 0.10.0 security review (docs: security/review).

Each test is a reviewer's probe turned into an assertion: it failed before the
fix it names, and passes after.
"""

from __future__ import annotations

import json
from typing import cast

import httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    DeviceSignInClient,
    PapSession,
    SessionClient,
)
from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
from personal_agent_protocol.company import CLIENT_POLICIES, CompanyConfig
from personal_agent_protocol.company.asgi import company_app
from personal_agent_protocol.company.service import WEB_COOKIE
from personal_agent_protocol.crypto import (
    SESSION_JWT_ALGORITHM,
    SESSION_JWT_TYPE,
    DelegatedSessionSigner,
    session_jwt_claims,
)
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE
from personal_agent_protocol.models import ProtectedResourceMetadata
from personal_agent_protocol.reactor import SESSION_SIGNERS, SessionJwtRequest, first_contribution
from personal_agent_protocol.sessions import AccessToken
from personal_agent_protocol.transport import SESSION_HEADER, session_headers

from .test_company_end_to_end import TENANT, World
from .test_company_refusals import signed_in

MCP = "https://manzanita.example/mcp"


async def _post_json(
    world: World, session: object, url: str, body: object, *, token: object = None
) -> httpx.Response:
    return await world.transport.request(
        "POST",
        url,
        session=session,  # type: ignore[arg-type]
        token=token,  # type: ignore[arg-type]
        content=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )


def _spy_token_responses(world: World) -> list[httpx.Response]:
    captured: list[httpx.Response] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        response = await original(request)
        if request.url.path == "/oauth/token":
            await response.aread()
            captured.append(response)
        return response

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    return captured


async def session_jwt(
    world: World,
    session: PapSession,
    method: str,
    url: str,
    *,
    token: AccessToken | None = None,
    claims: dict[str, object] | None = None,
    without: tuple[str, ...] = (),
    headers: dict[str, object] | None = None,
    key: object = None,
) -> str:
    """A Session JWT from the agent's delegated key, with some of it changed."""

    signer = cast(
        DelegatedSessionSigner, first_contribution(world.reactor, SESSION_SIGNERS, "signer")
    )
    request = SessionJwtRequest(
        method=method,
        url=url,
        tenant_id=session.tenant_id,
        issuer=session.issuer,
        client_id=session.client_id,
        sid=session.sid,
        sub=session.sub,
        agent_id=session.agent_id,
        access_token=None if token is None else token.access_token,
    )
    now = world.clock.now()
    delegated = await signer.key_for(request, now=now)
    payload = {**session_jwt_claims(request, issued_at=now), **(claims or {})}
    for name in without:
        payload.pop(name, None)
    return pyjwt.encode(
        payload,
        key or delegated.private_key,  # type: ignore[arg-type]
        algorithm=SESSION_JWT_ALGORITHM,
        headers={
            "typ": SESSION_JWT_TYPE,
            "kid": delegated.thumbprint,
            "pap_dlg": delegated.delegation.get_secret_value(),
            **(headers or {}),
        },
    )


async def _for_mcp(world: World) -> AccessToken:
    """Sign in, and take a token for the MCP server: a refresh with its `url` (§4.5, §7)."""

    await signed_in(world)
    md = world.company.oauth_metadata
    assert world.refresh_reference is not None
    result = await RefreshTokenClient(reactor=world.reactor, http_client=world.http).token_for_mcp(
        world.refresh_reference,
        context=RefreshTokenContext(
            token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
            issuer=md.issuer,  # type: ignore[union-attr]
            client_id=world.atlas.client_id,
            tenant_id=TENANT,
        ),
        server=ProtectedResourceMetadata(resource=MCP),
    )
    assert result.token is not None and result.token.resource == MCP
    return result.token


async def _assert_the_default_token(
    world: World, session: PapSession, access_token: SecretStr, for_mcp: AccessToken
) -> None:
    """A sign-in's token is the default one, for no resource; the MCP server's own is kept."""

    issued = await world.shop._access_token(access_token.get_secret_value())
    assert issued is not None and issued.resource is None
    assert (await world.shop._access_token(for_mcp.access_token.get_secret_value())) is not None
    token = AccessToken(access_token=access_token, scope="orders:read")
    used = await world.http.post(
        MCP,
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers=await session_headers(world.reactor, "POST", MCP, session=session, token=token),
    )
    assert used.status_code == 401


@pytest.mark.asyncio
async def test_finding_1_device_sign_in_after_an_mcp_token_issues_the_default_token() -> None:
    world = World()
    for_mcp = await _for_mcp(world)
    session = world.session
    assert session is not None
    md = world.company.oauth_metadata
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=md.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
        issuer=md.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=world.company.document.organization,
        protected_resources=md.protected_resources,  # type: ignore[union-attr]
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.token is not None
    assert done.token.token_type == "Bearer" and done.token.resource is None
    await _assert_the_default_token(world, session, done.token.access_token, for_mcp)


@pytest.mark.asyncio
async def test_finding_1_mediated_sign_in_after_an_mcp_token_issues_the_default_token() -> None:
    world = World()
    for_mcp = await _for_mcp(world)
    session = world.session
    assert session is not None
    started = await world.mediated_grant(**ADA, scope="orders:read")
    sign_in_id = started.json()["sign_in_id"]
    done = await world.mediated_grant(sign_in_id=sign_in_id, one_time_code=ADA_CODE)
    body = done.json()
    assert done.status_code == 200 and body["token_type"] == "Bearer"
    await _assert_the_default_token(world, session, SecretStr(body["access_token"]), for_mcp)


@pytest.mark.asyncio
async def test_finding_3_a_retried_start_answers_only_who_may_read_the_conversation() -> None:
    world = World()
    token = await signed_in(world)
    assert world.session is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    message = world.message("Where is my jacket order?")
    await world.conversations.start(endpoint, message, session=world.session, token=token, wait=0)
    signed_out = await world.signed_out_session()
    retried = await _post_json(
        world,
        signed_out,
        endpoint + "?wait=0",
        {"message": message.model_dump(mode="json", exclude_none=True)},
    )
    # Signed out: the challenge with `scope`, no error code and no body (§7).
    assert retried.status_code == 401 and not retried.content
    assert retried.headers["www-authenticate"] == 'Bearer scope="orders:read"'


def test_finding_5_operations_without_a_write_scope_is_a_configuration_error() -> None:
    with pytest.raises(ValueError, match="write_scopes"):
        CompanyConfig(
            name="Shop",
            domain="shop.example",
            scopes=("orders:read",),
            scope_descriptions={"orders:read": "See orders"},
        )
    with pytest.raises(ValueError, match="among scopes"):
        CompanyConfig(
            name="Shop",
            domain="shop.example",
            scopes=("a:read",),
            write_scopes=("a:write",),
            scope_descriptions={"a:read": "Read"},
        )
    CompanyConfig(
        name="Shop",
        domain="shop.example",
        scopes=("orders:read",),
        scope_descriptions={"orders:read": "See orders"},
        operations=False,
    )


@pytest.mark.asyncio
async def test_finding_5_an_operation_records_and_requires_its_scopes() -> None:
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
        organization=world.company.document.organization,
        protected_resources=md.protected_resources,  # type: ignore[union-attr]
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Exchange my jacket for a warmer one"),
        session=session,
        token=done.token,
        wait=0,
    )
    proposal = next(e.message.operation for e in page.events if e.message and e.message.operation)
    conversation_id = page.conversation_id
    record = await world.shop.operation_record(proposal.operation_id)
    assert record.scopes == ("orders:write",)
    narrowed = await RefreshTokenClient(reactor=world.reactor, http_client=world.http).refresh(
        done.refresh_token_reference,  # type: ignore[arg-type]
        context=RefreshTokenContext(
            token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
            revocation_endpoint=md.revocation_endpoint,  # type: ignore[union-attr]
            issuer=md.issuer,  # type: ignore[union-attr]
            client_id=world.atlas.client_id,
            tenant_id=TENANT,
        ),
        scopes=("orders:read",),
    )
    assert narrowed.token is not None
    answer = await _post_json(
        world,
        session,
        f"{endpoint}/{conversation_id}/messages",
        {
            "message": {
                "id": world.message("x").id,
                "author": {"type": "agent"},
                "approval": {
                    "operation_id": proposal.operation_id,
                    "revision": proposal.revision,
                },
            }
        },
        token=narrowed.token,
    )
    assert answer.status_code == 403
    assert 'error="insufficient_scope"' in answer.headers["www-authenticate"]
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("scope", "expected"),
    [("orders:read bogus:scope", 400), (None, 400), ("", 400), ("admin:all", 400), ("7", 400)],
)
async def test_finding_8_mediated_sign_in_refuses_unknown_or_missing_scopes(
    scope: str | None, expected: int
) -> None:
    world = World()
    await world.signed_out_session()
    response = await world.mediated_grant(**ADA, **({} if scope is None else {"scope": scope}))
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
        session=session,
        content=body,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_request"}


@pytest.mark.asyncio
async def test_finding_10_a_repeated_session_header_is_invalid_session() -> None:
    """Exactly one Session header, holding one JWT (§5.2, §5.3)."""

    world = World()
    session = await world.signed_out_session()
    app = company_app(world.shop)
    sent: list[dict[str, object]] = []
    url = "https://manzanita.example/poppy/conversations"
    jwts = [await session_jwt(world, session, "POST", url) for _ in range(2)]

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
            "headers": [(b"poppy-session", jwts[0].encode()), (b"poppy-session", jwts[1].encode())],
        },
        receive,  # type: ignore[arg-type]
        send,  # type: ignore[arg-type]
    )
    assert sent[0]["status"] == 400
    assert json.loads(sent[1]["body"])["error"] == "invalid_session"  # type: ignore[arg-type]


@pytest.mark.asyncio
@pytest.mark.parametrize("name", [b"authorization"])
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
            "headers": [(name, b"Bearer one"), (name, b"Bearer two")],
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
    # A join the agent authorized before it was blocked.
    browser = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    page = await browser.get("https://manzanita.example/poppy/browser-session")
    code = page.text.split('name="code" value="', 1)[1].split('"', 1)[0]
    authorized = await world.transport.request(
        "POST",
        "https://manzanita.example/poppy/browser-session/authorize",
        session=session,
        content=json.dumps({"code": code}).encode(),
        headers={"content-type": "application/json"},
    )
    assert authorized.status_code == 204
    resolver_calls: list[str] = []
    from personal_agent_protocol.company import CLIENT_RESOLVERS

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
        session=session,
        content=json.dumps(
            {"message": world.message("hi").model_dump(mode="json", exclude_none=True)}
        ).encode(),
        headers={"content-type": "application/json"},
    )
    # A refused agent gets `invalid_session`, in the new Session it starts too (§4.1, §7).
    assert started.status_code == 400 and started.json()["error"] == "invalid_session"
    forged = await world.http.get(
        "https://manzanita.example/api/orders",
        headers={SESSION_HEADER: _unsigned({"iss": world.atlas.client_id})},
    )
    assert forged.status_code == 400 and forged.json()["error"] == "invalid_session"
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
    assert (
        await browser.post("https://manzanita.example/poppy/browser-session", data={"code": code})
    ).status_code == 400
    await browser.aclose()
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
    await world.signed_out_session()
    directory = world.plugin.accounts  # type: ignore[attr-defined]
    seen: list[object] = []
    authenticate = directory.authenticate

    async def spy(credentials, context):  # type: ignore[no-untyped-def]
        seen.append(context)
        return await authenticate(credentials, context)

    directory.authenticate = spy
    wrong = {"email": ADA["email"], "password": "wrong"}
    answers = [await world.mediated_grant(**wrong, scope="orders:read") for _ in range(8)]
    assert [a.status_code for a in answers] == [400] * 5 + [429] * 3
    assert {a.json().get("error") for a in answers[:5]} == {"invalid_grant"}
    assert not answers[5].content
    assert int(answers[5].headers["retry-after"]) == 15 * 60
    # Locked out: the directory is not asked, even with the right password.
    assert len(seen) == 5
    right = await world.mediated_grant(**ADA, scope="orders:read")
    assert right.status_code == 429 and len(seen) == 5
    # The directory hears which agent each attempt came from.
    assert seen[0].client_id == world.atlas.client_id  # type: ignore[attr-defined]
    # Once the lockout ends, the next failure locks the account out twice as long.
    world.clock.advance(15 * 60)
    again = await world.mediated_grant(**wrong, scope="orders:read")
    assert again.status_code == 400
    doubled = await world.mediated_grant(**wrong, scope="orders:read")
    assert doubled.status_code == 429 and int(doubled.headers["retry-after"]) == 30 * 60


@pytest.mark.asyncio
async def test_finding_2_wrong_codes_count_per_account_across_sign_ins() -> None:
    world = World()
    _ignore_retry_after(world)
    await world.signed_out_session()
    last = None
    for _ in range(5):
        started = await world.mediated_grant(**ADA, scope="orders:read orders:write")
        if started.status_code == 429:
            last = started
            break
        sign_in_id = started.json()["sign_in_id"]
        for attempt in range(3):
            answer = await world.mediated_grant(
                sign_in_id=sign_in_id, one_time_code=f"00000{attempt}"
            )
            if answer.json().get("error") == "invalid_grant":
                break
    assert last is not None and last.status_code == 429 and not last.content
    # A right code after the account's code budget is spent does not sign in either.
    world.clock.advance(15 * 60)
    started = await world.mediated_grant(**ADA, scope="orders:read")
    done = await world.mediated_grant(
        sign_in_id=started.json()["sign_in_id"], one_time_code=ADA_CODE
    )
    assert done.status_code == 200 and done.json()["access_token"]


@pytest.mark.asyncio
async def test_finding_4_a_session_jwt_replayed_at_another_replica_is_refused() -> None:
    world = World(durable=True)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("hello"), session=session, wait=0
    )
    captured: list[httpx.Request] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await original(request)

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    await world.conversations.read_events(endpoint, page.conversation_id, session=session)
    request = next(r for r in captured if r.method == "GET")
    world.restart()  # another replica over the same store, with the default replay cache
    other = await world.http.get(str(request.url), headers=dict(request.headers))
    assert other.status_code == 400 and other.json()["error"] == "invalid_session"


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


@pytest.mark.asyncio
async def test_finding_9_the_demo_agents_read_nothing_without_the_read_scope() -> None:
    from personal_agent_protocol.company import Turn
    from personal_agent_protocol.demo.manzanita import ManzanitaAgent
    from personal_agent_protocol.demo.northwind import NorthwindAgent

    def turn(text: str, scopes: tuple[str, ...]) -> Turn:
        return Turn(
            conversation_id="cnv_1",
            text=text,
            data=None,
            author="human",
            account_id="acct_ada",
            scopes=scopes,
            client_id="https://atlas.example/agent.json",
            is_direct=False,
            supports_operations=True,
        )

    manzanita = await ManzanitaAgent().respond(turn("Where is my order?", ("orders:write",)))
    assert [(r.text, r.data, r.authorization) for r in manzanita] == [
        (None, None, ("insufficient_scope", "orders:read"))
    ]
    northwind = await NorthwindAgent().respond(turn("What is my balance?", ("payments:write",)))
    assert [(r.text, r.data, r.authorization) for r in northwind] == [
        (None, None, ("insufficient_scope", "accounts:read"))
    ]
    read = await ManzanitaAgent().respond(turn("Where is my order?", ("orders:read",)))
    assert read[0].data is not None


@pytest.mark.parametrize(
    ("address", "is_global"),
    [
        ("64:ff9b::7f00:1", False),
        ("64:ff9b::a9fe:a9fe", False),
        ("::7f00:1", False),
        ("::a9fe:a9fe", False),
        ("::ffff:127.0.0.1", False),
        ("2002:7f00:1::", False),
        ("64:ff9b:1::808:808", False),
        ("fd00:ec2::254", False),
        ("100.100.100.200", False),
        ("::", False),
        ("64:ff9b::808:808", True),
        ("2606:4700::1111", True),
        ("8.8.8.8", True),
    ],
)
def test_finding_13_an_ipv4_address_inside_ipv6_is_judged_as_ipv4(
    address: str, is_global: bool
) -> None:
    import ipaddress

    from personal_agent_protocol.reactor import is_global_address

    assert is_global_address(ipaddress.ip_address(address)) is is_global


@pytest.mark.asyncio
async def test_finding_13_a_host_resolving_to_nat64_loopback_is_refused() -> None:
    from personal_agent_protocol.errors import DiscoveryError
    from personal_agent_protocol.reactor import PublicUrlSafetyPolicy

    async def nat64(host: str) -> list[str]:
        return ["64:ff9b::a9fe:a9fe"]

    with pytest.raises(DiscoveryError) as refused:
        await PublicUrlSafetyPolicy(nat64).assert_safe("https://metadata.example/agent.json")
    assert refused.value.code == "unsafe_address"


class _Endless(httpx.AsyncByteStream):
    """A body that never ends, counting how much of it was read."""

    def __init__(self) -> None:
        self.sent = 0

    async def __aiter__(self):  # type: ignore[no-untyped-def,override]
        while True:
            self.sent += 1
            yield b"x" * 65536


@pytest.mark.asyncio
async def test_finding_15_a_token_response_is_read_only_up_to_its_limit() -> None:
    from personal_agent_protocol import SessionError

    world = World()
    await world.signed_out_session()
    endless = _Endless()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=endless)

    client = SessionClient(
        reactor=world.reactor,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        max_response_bytes=100 * 1024,
    )
    md = world.company.oauth_metadata
    with pytest.raises(SessionError) as refused:
        await client.token_request(
            client_id=world.atlas.client_id,
            issuer=md.issuer,  # type: ignore[union-attr]
            token_endpoint=md.token_endpoint,  # type: ignore[union-attr]
            form=lambda: {"grant_type": "refresh_token", "refresh_token": "x"},
            error=SessionError,
            tenant_id="t",
            dpop_signing_algs=None,
        )
    assert refused.value.code == "response_too_large"
    assert endless.sent <= 3  # 64 KiB chunks: stopped just past 100 KiB


@pytest.mark.asyncio
async def test_finding_15_a_resource_response_is_read_only_up_to_its_limit() -> None:
    from personal_agent_protocol.transport import SessionHttpClient

    world = World()
    session = await world.signed_out_session()
    endless = _Endless()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=endless)

    transport = SessionHttpClient(
        reactor=world.reactor,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        max_response_bytes=100 * 1024,
    )
    response = await transport.request(
        "GET", "https://manzanita.example/api/orders", session=session
    )
    assert len(response.content) == 100 * 1024 + 1
    assert endless.sent <= 3


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_finding_7_a_body_is_never_sent_to_a_redirect(status: int) -> None:
    from personal_agent_protocol.errors import TransportError
    from personal_agent_protocol.transport import SessionHttpClient

    world = World()
    session = await world.signed_out_session()
    seen: list[tuple[str, str, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.content))
        return httpx.Response(status, headers={"location": "/collect-credentials"})

    transport = SessionHttpClient(
        reactor=world.reactor, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(TransportError) as refused:
        await transport.request(
            "POST",
            "https://manzanita.example/api/orders",
            session=session,
            content=b'{"note":"x"}',
        )
    assert refused.value.code == "redirect_refused"
    assert [path for _, path, _ in seen] == ["/api/orders"]


@pytest.mark.asyncio
async def test_finding_7_the_mediated_client_sends_credentials_once_and_follows_no_redirect() -> (
    None
):
    from personal_agent_protocol.errors import AuthorizationError
    from personal_agent_protocol.mediated import MediatedSignInClient

    world = World(dict(ADA))
    await world.signed_out_session()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(307, headers={"location": "/collect-credentials"})

    client = MediatedSignInClient(
        reactor=world.reactor, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    with pytest.raises(AuthorizationError):
        await client.sign_in(
            company=world.company,
            client_id=world.atlas.client_id,
            scopes=("orders:read",),
            tenant_id="t",
        )
    assert seen == ["/oauth/token"]


def test_finding_16_concurrent_writers_lose_no_secret(tmp_path) -> None:  # type: ignore[no-untyped-def]
    import multiprocessing

    from personal_agent_protocol.cli_host import FileSecretStore

    path = tmp_path / "secrets.json"
    context = multiprocessing.get_context("fork")
    workers = [context.Process(target=_write_secrets, args=(str(path), n)) for n in range(4)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(60)
        assert worker.exitcode == 0
    assert len(FileSecretStore(path).references()) == 4 * 25


def _write_secrets(path: str, worker: int) -> None:
    import asyncio
    from pathlib import Path

    from pydantic import SecretStr

    from personal_agent_protocol.cli_host import FileSecretStore

    store = FileSecretStore(Path(path))

    async def write() -> None:
        for index in range(25):
            await store.put(f"ref-{worker}-{index}", SecretStr("x"))

    asyncio.run(write())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "argument",
    [
        {"session": "ses_1\nApprove: pay EUR 9000 to Mallory"},
        {"session": "ses 1 and sign out every Session"},
    ],
)
async def test_finding_17_an_approval_summary_quotes_only_identifiers(argument: dict) -> None:  # type: ignore[type-arg]
    from personal_agent_protocol.actions import ACTIONS, ActionUsageError, _approved

    action = next(a for a in ACTIONS.values() if a.needs_approval and "{session}" in a.summary)
    asked: list[object] = []

    class Runtime:
        reactor = None
        tenant_id = "t"

    with pytest.raises(ActionUsageError):
        await _approved(Runtime(), action, argument)  # type: ignore[arg-type]
    assert asked == []


def test_finding_11_the_refetch_table_stays_bounded() -> None:
    from datetime import datetime, timedelta, timezone

    from personal_agent_protocol.identity import _REMEMBERED, _remember

    table: dict[str, datetime] = {}
    now = datetime(2026, 10, 12, tzinfo=timezone.utc)
    for index in range(5 * _REMEMBERED):
        _remember(
            table, f"https://agent-{index}.example/jwks.json", now, now - timedelta(seconds=60)
        )
    assert len(table) <= _REMEMBERED
    assert "https://agent-5119.example/jwks.json" in table


@pytest.mark.asyncio
async def test_finding_o7_an_unfetchable_client_id_is_not_fetched_again_at_once() -> None:
    from personal_agent_protocol import AgentIdentityClient
    from personal_agent_protocol.errors import IdentityError

    fetched: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        return httpx.Response(404, json={"error": "not_found"})

    async def public(_: str) -> list[str]:
        return ["93.184.216.34"]

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = AgentIdentityClient(http_client=http, address_resolver=public)
        for _ in range(5):
            with pytest.raises(IdentityError):
                await client.fetch_metadata("https://gone.example/agent.json")
    assert len(fetched) == 1


# The external interoperability exercise ------------------------------------------------


async def _signed_in_with_proposal(world: World):  # type: ignore[no-untyped-def]
    token = await signed_in(world)
    assert world.session is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Exchange my jacket for a warmer one"),
        session=world.session,
        token=token,
        wait=0,
    )
    proposal = next(e.message.operation for e in page.events if e.message and e.message.operation)
    return token, page, proposal


@pytest.mark.asyncio
async def test_o1_an_operation_has_no_null_members() -> None:
    world = World()
    _, _, proposal = await _signed_in_with_proposal(world)
    body = proposal.model_dump(mode="json")
    assert set(body) == {"operation_id", "revision", "summary", "terms", "expires_at"}
    assert [name for name, value in body.items() if value is None] == []


async def _assertion(
    world: World, audience: str, *, lifetime: int = 60, jti: str | None = None
) -> str:
    import secrets as random

    now = int(world.clock.now().timestamp())
    signed = await world.atlas.signer().sign(
        {
            "iss": world.atlas.client_id,
            "sub": world.atlas.client_id,
            "aud": audience,
            "iat": now,
            "exp": now + lifetime,
            "jti": jti or random.token_urlsafe(16),
        },
        purpose="client_assertion",
    )
    return signed.get_secret_value()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("audience", "status"),
    [
        # The issuer, compared character for character, and nothing else (§4.1, §9.4).
        ("https://manzanita.example/oauth/device", 401),
        ("https://manzanita.example/oauth/token", 401),
        ("https://manzanita.example/", 401),
        ("https://Manzanita.example", 401),
        ("https://manzanita.example", 200),
        ("https://other.example/oauth/token", 401),
    ],
)
async def test_o2_a_client_assertion_names_the_issuer_only(audience: str, status: int) -> None:
    from personal_agent_protocol.sessions import JWT_CLIENT_ASSERTION

    world = World()
    await world.signed_out_session()
    answer = await world.http.post(
        "https://manzanita.example/oauth/device",
        data={
            "client_id": world.atlas.client_id,
            "client_assertion_type": JWT_CLIENT_ASSERTION,
            "client_assertion": await _assertion(world, audience),
            "scope": "orders:read",
        },
    )
    assert answer.status_code == status


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("lifetime", "jti", "status"),
    [(600, None, 401), (301, None, 401), (300, None, 200), (60, "short-jti", 401)],
)
async def test_o7_an_assertion_lives_at_most_five_minutes_and_names_a_long_jti(
    lifetime: int, jti: str | None, status: int
) -> None:
    from personal_agent_protocol.sessions import JWT_CLIENT_ASSERTION

    world = World()
    await world.signed_out_session()
    answer = await world.http.post(
        "https://manzanita.example/oauth/device",
        data={
            "client_id": world.atlas.client_id,
            "client_assertion_type": JWT_CLIENT_ASSERTION,
            "client_assertion": await _assertion(
                world, "https://manzanita.example", lifetime=lifetime, jti=jti
            ),
            "scope": "orders:read",
        },
    )
    assert answer.status_code == status


@pytest.mark.asyncio
async def test_o7_a_session_jwt_with_a_short_jti_is_refused() -> None:
    world = World()
    session = await world.signed_out_session()
    url = "https://manzanita.example/api/orders"
    answer = await world.http.get(
        url,
        headers={
            SESSION_HEADER: await session_jwt(world, session, "GET", url, claims={"jti": "short"})
        },
    )
    assert answer.status_code == 400 and answer.json()["error"] == "invalid_session"


@pytest.mark.asyncio
async def test_a_copied_access_token_is_worth_nothing_without_the_agents_session_jwt() -> None:
    """What DPoP proofs did: `ath` ties a Session JWT to its token, and the delegation ties
    its key to the agent's `jwks_uri` (§5.2, §5.3). Each forgery is `invalid_session`."""

    world = World()
    token = await signed_in(world)
    session = world.session
    assert session is not None
    url = "https://manzanita.example/api/orders"
    bearer = {"authorization": f"Bearer {token.access_token.get_secret_value()}"}
    other = AccessToken(access_token=SecretStr("another-access-token"), scope="orders:read")
    someone = ec.generate_private_key(ec.SECP256R1())
    forged = {
        "no ath": await session_jwt(world, session, "GET", url),
        "another token's ath": await session_jwt(world, session, "GET", url, token=other),
        "another method": await session_jwt(world, session, "POST", url, token=token),
        "another url": await session_jwt(world, session, "GET", f"{url}/x", token=token),
        "another company": await session_jwt(
            world, session, "GET", url, token=token, claims={"aud": "https://other.example"}
        ),
        "an old iat": await session_jwt(
            world,
            session,
            "GET",
            url,
            token=token,
            claims={"iat": int(world.clock.now().timestamp()) - 61},
        ),
        "no jti": await session_jwt(world, session, "GET", url, token=token, without=("jti",)),
        "another key": await session_jwt(world, session, "GET", url, token=token, key=someone),
        "no delegation": await session_jwt(
            world, session, "GET", url, token=token, headers={"pap_dlg": None}
        ),
        "signed by the agent's own key": await session_jwt(
            world,
            session,
            "GET",
            url,
            token=token,
            headers={"pap_dlg": None},
            key=world.atlas.private_key,
        ),
    }
    for what, value in forged.items():
        answer = await world.http.get(url, headers={**bearer, SESSION_HEADER: value})
        assert answer.status_code == 400, what
        assert answer.json()["error"] == "invalid_session", what
    copied = await world.http.get(url, headers=bearer)
    assert copied.status_code == 400 and copied.json()["error"] == "invalid_session"
    # The genuine one, and that same one only once.
    genuine = await session_jwt(world, session, "GET", url, token=token)
    headers = {**bearer, SESSION_HEADER: genuine}
    assert (await world.http.get(url, headers=headers)).status_code == 200
    replayed = await world.http.get(url, headers=headers)
    assert replayed.status_code == 400 and replayed.json()["error"] == "invalid_session"


@pytest.mark.asyncio
async def test_o3_a_token_endpoint_refusal_is_an_oauth_error() -> None:
    """At the token endpoint, an OAuth error with HTTP 400; at APIs a 401 challenge (§4.4, §7)."""

    from personal_agent_protocol.sessions import JWT_CLIENT_ASSERTION

    world = World()
    session = await world.signed_out_session()
    answer = await world.http.post(
        "https://manzanita.example/oauth/token",
        data={
            "grant_type": "refresh_token",
            "client_id": world.atlas.client_id,
            "client_assertion_type": JWT_CLIENT_ASSERTION,
            "client_assertion": await _assertion(world, "https://manzanita.example"),
            "refresh_token": "x",
        },
    )
    assert answer.status_code == 400 and answer.json() == {"error": "invalid_grant"}
    assert "www-authenticate" not in answer.headers
    url = "https://manzanita.example/api/orders"
    api = await world.http.get(
        url,
        headers=await session_headers(
            world.reactor,
            "GET",
            url,
            session=session,
            token=AccessToken(access_token=SecretStr("unknown")),
        ),
    )
    assert api.status_code == 401 and api.json()["error"] == "invalid_token"
    assert api.headers["www-authenticate"].startswith('Bearer error="invalid_token"')


@pytest.mark.asyncio
async def test_o4_a_token_in_the_query_is_refused_even_beside_a_valid_header() -> None:
    world = World()
    bearer = await _for_mcp(world)
    assert world.session is not None
    value = bearer.access_token.get_secret_value()
    for query in (f"access_token={value}", "access_token="):
        url = f"{MCP}?{query}"
        answer = await world.http.post(
            url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers=await session_headers(
                world.reactor, "POST", url, session=world.session, token=bearer
            ),
        )
        assert answer.status_code == 400
        assert answer.json()["error"] == "invalid_request"


@pytest.mark.asyncio
async def test_o8_a_reply_is_framed_by_working_and_idle_state_events() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Hello"), session=session, wait=0
    )
    kinds = [(e.type, e.status) for e in page.events]
    assert kinds == [("message", None), ("state", "working"), ("message", None), ("state", "idle")]
    assert page.status == "idle"


@pytest.mark.asyncio
async def test_o9_the_demo_promises_no_operation_to_an_agent_without_operations() -> None:
    from personal_agent_protocol.company import Turn
    from personal_agent_protocol.demo.manzanita import ManzanitaAgent

    replies = await ManzanitaAgent().respond(
        Turn(
            conversation_id="cnv_1",
            text="Exchange it for something warmer",
            data=None,
            author="human",
            account_id="acct_ada",
            scopes=("orders:read", "orders:write"),
            client_id="https://atlas.example/agent.json",
            is_direct=False,
            supports_operations=False,
        )
    )
    assert [r.operation for r in replies] == [None]
    assert "Here is the exchange" not in (replies[0].text or "")


@pytest.mark.asyncio
async def test_o6_the_suite_signs_in_through_direct_sign_in_with_the_drivers_hook() -> None:
    from personal_agent_protocol.demo.conformance import ManzanitaConformance

    demo = ManzanitaConformance()
    ctx = demo.context()
    metadata = await ctx.metadata()
    # A company offering Direct Sign-In and no Device Sign-In.
    object.__setattr__(
        metadata,
        "grant_types_supported",
        [g for g in metadata.grant_types_supported if not g.endswith(":device_code")],
    )
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session, granted=("orders:read",))
    assert signed.session is session and signed.token.scopes == ("orders:read",)
    assert ctx.url("/api/orders") == "https://manzanita.example/api/orders"
