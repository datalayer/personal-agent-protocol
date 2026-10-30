# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Release-gate demonstrations: each attack or failure, run against Manzanita, ends safely.

One test per property of the release gate "replay, issuer mix-up, cross-tenant
access, stale approval, retries, restart, rollback, revocation, and rotation are
demonstrated safely". Each runs a real journey — Atlas, Ada's personal agent,
with Manzanita, the reference company, over HTTP in one process with real keys —
then does the unsafe thing and asserts the safe outcome: refused, or done exactly
once. `docs/docs/security/demonstrations.mdx` lists them; the TypeScript twin is
`src/__tests__/security-demonstrations.test.mjs`.
"""

from __future__ import annotations

import asyncio
import dataclasses
from dataclasses import replace
from typing import Any

import httpx
import pytest
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    Author,
    AuthorizationError,
    ConversationError,
    DeviceSignInClient,
    Message,
    PapSession,
    SessionClient,
    TokenStore,
)
from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.company import (
    build_company,
    company_app,
)
from personal_agent_protocol.company.store import DEVICE
from personal_agent_protocol.demo import manzanita as manzanita_demo
from personal_agent_protocol.demo.kit import ClockPlugin, StorePlugin
from personal_agent_protocol.models import Approval
from personal_agent_protocol.operations import OperationsClient
from personal_agent_protocol.reactor import TOKEN_STORES, first_contribution
from personal_agent_protocol.sessions import AccessToken
from personal_agent_protocol.transport import session_headers

from .test_company_end_to_end import TENANT, World
from .test_company_refusals import signed_in
from .test_direct_and_api import begin, direct_world
from .test_guide_security import RotatingSite, same_agent_with, session_accepted

ORDERS = "https://manzanita.example/api/orders"


class Wire:
    """Every request the agent sends on its client, and a way to lose one answer."""

    def __init__(self, world: World) -> None:
        self.requests: list[httpx.Request] = []
        self.lose: str | None = None
        transport = world.http._transport  # type: ignore[attr-defined]
        original = transport.handle_async_request

        async def spy(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            response = await original(request)
            if self.lose is not None and request.url.path.endswith(self.lose):
                self.lose = None
                await response.aread()
                raise httpx.ReadTimeout("the answer was lost", request=request)
            return response

        transport.handle_async_request = spy

    def last(self, method: str, path: str) -> httpx.Request:
        return next(r for r in reversed(self.requests) if (r.method, r.url.path) == (method, path))

    async def resend(self, world: World, request: httpx.Request) -> httpx.Response:
        """The captured request again, byte for byte: what an attacker who saw it can do."""

        copy = httpx.Request(
            request.method, request.url, headers=request.headers, content=request.content
        )
        return await world.http.send(copy)


async def probe(world: World, session: PapSession, token: AccessToken | None = None) -> int:
    """Read Ada's orders: 200, or the status the company refused with."""

    try:
        return (
            await ApiClient(transport=world.transport).call(
                "GET", ORDERS, session=session, token=token
            )
        ).status
    except ApiError as refused:
        return int(refused.status_code or 0)


def context(world: World) -> RefreshTokenContext:
    metadata = world.company.oauth_metadata
    assert metadata is not None
    return RefreshTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
    )


async def device_sign_in(world: World) -> tuple[AccessToken, str]:
    """Device Sign-In, Ada approving: the access token and its refresh token's reference."""

    metadata = world.company.oauth_metadata
    assert metadata is not None and metadata.device_authorization_endpoint is not None
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.token is not None and done.refresh_token_reference is not None
    return done.token, done.refresh_token_reference


EXCHANGE = "https://manzanita.example/api/orders/ord_7Hk2/exchanges"


async def proposal(world: World, session: PapSession, token: AccessToken) -> Any:
    """Ada asks for a warmer jacket: Manzanita returns the exchange, performing nothing."""

    answer = await ApiClient(transport=world.transport).call(
        "POST", EXCHANGE, session=session, token=token, body={}
    )
    assert answer.status == 403 and answer.operation is not None
    return answer.operation


async def approve_it(world: World, operation: Any, session: PapSession, token: AccessToken) -> Any:
    """The same request again, with the approval of this revision."""

    return await ApiClient(transport=world.transport).call(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        body={},
        approval=Approval(operation_id=operation.operation_id, revision=operation.revision),
    )


@pytest.mark.asyncio
async def test_replay_is_refused() -> None:
    """A captured token request or API call, sent again byte for byte, is refused."""

    world = World()
    wire = Wire(world)
    token = await signed_in(world)
    session = world.session
    assert session is not None
    assert await probe(world, session, token) == 200

    # The token request (its client assertion, its device code): each is one-time.
    replayed = await wire.resend(world, wire.last("POST", "/oauth/token"))
    assert replayed.status_code in {400, 401}
    assert replayed.json()["error"] in {"invalid_client", "invalid_grant"}
    # The API call: its Session JWT's ID was seen.
    replayed = await wire.resend(world, wire.last("GET", "/api/orders"))
    assert replayed.status_code == 400 and replayed.json()["error"] == "invalid_session"
    assert "orders" not in replayed.text
    # A request with an approval, replayed, performs nothing more.
    operation = await proposal(world, session, token)
    await approve_it(world, operation, session, token)
    approved = wire.last("POST", "/api/orders/ord_7Hk2/exchanges")
    assert (await wire.resend(world, approved)).status_code == 400
    assert world.plugin.executor.performed == [operation.operation_id]
    # The agent itself carries on: a fresh Session JWT every time.
    assert await probe(world, session, token) == 200


@pytest.mark.asyncio
async def test_issuer_mix_up_is_refused() -> None:
    """A sign-in answer naming another issuer is refused before any code is exchanged."""

    world, browser = direct_world()
    wire = Wire(world)
    session = await world.signed_out_session()
    client = await begin(world, browser, session, ("orders:read",))
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    assert "iss=https%3A%2F%2Fmanzanita.example" in callback
    exchanged = len([r for r in wire.requests if r.url.path == "/oauth/token"])

    # The answer arrives claiming another company issued it (RFC 9207 mix-up).
    mixed_up = callback.replace(
        "iss=https%3A%2F%2Fmanzanita.example", "iss=https%3A%2F%2Fnorthwind.example"
    )
    with pytest.raises(AuthorizationError) as refused:
        await client.complete(mixed_up)
    assert refused.value.code == "issuer_mismatch"
    # No code went to any token endpoint, and the sign-in state is spent: the genuine
    # answer cannot be raced in afterwards either.
    assert len([r for r in wire.requests if r.url.path == "/oauth/token"]) == exchanged
    with pytest.raises(AuthorizationError) as spent:
        await client.complete(callback)
    assert spent.value.code == "invalid_or_expired_state"
    assert await probe(world, session) == 401  # still signed out

    # Starting again works: the user signs in at the issuer the agent discovered.
    client = await begin(world, browser, session, ("orders:read",))
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    result = await client.complete(callback)
    assert await probe(world, session, result.token) == 200


@pytest.mark.asyncio
async def test_cross_tenant_access_is_refused() -> None:
    """One tenant's Session, used from another tenant of the same agent, is refused."""

    world = World()
    token = await signed_in(world)
    session = world.session
    assert session is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), session=session, token=token, wait=0
    )
    assert await probe(world, session, token) == 200

    # Another tenant of Atlas has another User ID, and another delegated key (§5.2). Naming
    # Ada's `sid` it is another User in her Session: `invalid_session`, not a way in (§5.3).
    stranger = "usr_somebody_else_000000"
    other = dataclasses.replace(session, sub=stranger, tenant_id="another-tenant")
    refused = await world.http.get(
        ORDERS,
        headers=await session_headers(world.reactor, "GET", ORDERS, session=other, token=None),
    )
    assert refused.status_code == 400 and refused.json()["error"] == "invalid_session"
    keys = world.host.delegated_keys
    theirs = await keys.current(tenant_id="another-tenant", issuer=session.issuer, sub=stranger)
    ours = await keys.current(tenant_id=TENANT, issuer=session.issuer, sub=session.sub)
    assert theirs is not None and ours is not None and theirs.thumbprint != ours.thumbprint
    # Another user of the same tenant gets a Session of their own, which sees nothing of Ada's.
    metadata = world.company.oauth_metadata
    assert metadata is not None
    strangers = await SessionClient(reactor=world.reactor, http_client=world.http).start(
        client_id=world.atlas.client_id,
        pairwise_user_id=stranger,
        issuer=metadata.issuer,
        tenant_id=TENANT,
    )
    with pytest.raises(ConversationError) as hidden:
        await world.conversations.read_events(endpoint, page.conversation_id, session=strangers)
    assert hidden.value.code == "conversation_not_found"
    # Ada's own tenant is unaffected.
    assert await probe(world, session, token) == 200


@pytest.mark.asyncio
async def test_stale_approval_is_refused() -> None:
    """An approval of revision 1 never confirms revision 2: the user approves again."""

    world = World()
    token = await signed_in(world)
    session = world.session
    assert session is not None
    operation = await proposal(world, session, token)
    await world.shop.revise(
        operation.operation_id,
        summary="Exchange for USD 85.00 more.",
        terms={"order_id": "ord_7Hk2", "price_difference": {"amount": "85.00", "currency": "USD"}},
    )
    # The approval of the replaced revision performs nothing: the new one comes back.
    answered = await approve_it(world, operation, session, token)
    newer = answered.operation
    assert newer is not None and newer.operation_id == operation.operation_id
    assert newer.revision != operation.revision and newer.summary.startswith("Exchange for USD 85")
    assert world.plugin.executor.performed == []

    done = await approve_it(world, newer, session, token)
    assert done.status == 200
    # The approval of the first revision, presented once more, gets the response given.
    late = await approve_it(world, operation, session, token)
    assert late.body == done.body
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_retries_are_safe() -> None:
    """A retried message is one message; an approval whose answer is lost is done once."""

    world = World()
    wire = Wire(world)
    token = await signed_in(world)
    session = world.session
    assert session is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    # The same message ID, sent twice: one conversation, one message.
    message = Message(id="msg_retry_demo_0000000001", author=Author(type="human"), text="Hello")
    first = await world.conversations.start(endpoint, message, session=session, token=token)
    again = await world.conversations.start(endpoint, message, session=session, token=token)
    assert again.conversation_id == first.conversation_id
    page = await world.conversations.read_events(
        endpoint, first.conversation_id, session=session, token=token
    )
    sent = [e for e in page.events if e.message is not None and e.message.id == message.id]
    assert len(sent) == 1

    # The approval reaches Manzanita, which performs it; its answer is lost on the way back.
    operation = await proposal(world, session, token)
    wire.lose = "/api/orders/ord_7Hk2/exchanges"
    api = ApiClient(transport=world.transport)

    async def request(approval: Approval) -> Any:
        return await api.call(
            "POST", EXCHANGE, session=session, token=token, body={}, approval=approval
        )

    sent = await OperationsClient(reactor=world.reactor).send(
        request, Approval(operation_id=operation.operation_id, revision=operation.revision)
    )
    # Sent again with the same approval, never assumed failed, and not performed twice.
    assert sent.status == "answered" and sent.answer.status == 200  # type: ignore[union-attr]
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_restart_is_safe() -> None:
    """Restarted over its store, which holds the replay cache: it goes on, replays stay refused."""

    world = World(durable=True)
    wire = Wire(world)
    session = await world.signed_out_session()
    token, _ = await device_sign_in(world)
    operation = await proposal(world, session, token)
    assert await probe(world, session, token) == 200
    captured = wire.last("GET", "/api/orders")

    world.restart()

    # A Session JWT seen before the restart is still refused after it.
    assert (await wire.resend(world, captured)).status_code == 400
    # The Session, the proposal and its single performance carry over.
    assert await probe(world, session, token) == 200
    done = await approve_it(world, operation, session, token)
    assert done.status == 200
    performed = list(world.plugin.executor.performed)

    world.restart()
    again = await approve_it(world, operation, session, token)
    assert again.body == done.body
    assert performed == [operation.operation_id] and world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_rollback_is_safe() -> None:
    """Rolled back to an earlier release over the same store: nothing done is undone or redone."""

    world = World(durable=True)
    session = await world.signed_out_session()
    _, reference = await device_sign_in(world)
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    tokens = first_contribution(world.reactor, TOKEN_STORES, "token store")
    assert isinstance(tokens, TokenStore)
    before = await tokens.get(reference)
    refreshed = await accounts.refresh(reference, context=context(world))
    assert refreshed.rotated and refreshed.token is not None
    rotated = await tokens.get(reference)
    operation = await proposal(world, session, refreshed.token)
    done = await approve_it(world, operation, session, refreshed.token)
    assert done.status == 200
    assert world.store is not None and world.store.keys(DEVICE) == []  # the code was taken

    # Roll back: the previous release (no website yet), over the same store.
    previous = replace(manzanita_demo.CONFIG, web=False)
    plugin = manzanita_demo.ManzanitaPlugin()
    world.shop = build_company(
        previous,
        http_client=world.network.client(),
        address_resolver=world.network.resolve,
        plugins=[
            (PluginManifest(name="manzanita", version="0"), plugin),
            (PluginManifest(name="manzanita-clock", version="1"), ClockPlugin(world.clock)),
            (PluginManifest(name="manzanita-store", version="1"), StorePlugin(world.store)),
        ],
    )
    world.plugin = plugin
    world.network.add(manzanita_demo.DOMAIN, company_app(world.shop))

    # The rotated-away refresh token stays refused; the current one works.
    assert before is not None and rotated is not None
    await tokens.put(reference, before)
    stale = await accounts.refresh(reference, context=context(world))
    assert stale.status == "signed_out"
    await tokens.put(reference, rotated)
    current = await accounts.refresh(reference, context=context(world))
    assert current.status == "signed_in" and current.token is not None
    # The performed operation is not performed again by the earlier release.
    again = await approve_it(world, operation, session, current.token)
    assert again.body == done.body
    assert plugin.executor.performed == []
    # The earlier release serves what it has: no website, the same API and Sessions.
    assert world.company.document.web is not None  # what the agent discovered before
    assert await probe(world, session, current.token) == 200


@pytest.mark.asyncio
async def test_revocation_is_safe() -> None:
    """Signing out takes effect at once: every access token of the sign-in stops working."""

    world = World()
    session = await world.signed_out_session()
    token, reference = await device_sign_in(world)
    assert await probe(world, session, token) == 200
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    second = await world.signed_out_session()
    other = await accounts.refresh(reference, context=context(world))
    assert other.status == "signed_in" and other.token is not None
    assert await probe(world, second, other.token) == 200

    revoked = await accounts.revoke(reference, context=context(world))
    assert revoked.revoked and revoked.deleted_locally
    # Both tokens of that sign-in stop right away, not at expiry: `invalid_token`.
    for session_used, stopped in ((session, token), (second, other.token)):
        with pytest.raises(ApiError) as refused:
            await ApiClient(transport=world.transport).call(
                "GET", ORDERS, session=session_used, token=stopped
            )
        assert (refused.value.code, refused.value.status_code) == ("invalid_token", 401)
    # The refresh token is gone locally and refused at the company.
    after = await accounts.refresh(reference, context=context(world))
    assert after.status == "signed_out"
    # The Sessions continue signed out, sending no token: asked to sign in, not refused.
    with pytest.raises(ApiError) as signed_out:
        await ApiClient(transport=world.transport).call("GET", ORDERS, session=session)
    assert signed_out.value.code == "insufficient_scope"


@pytest.mark.asyncio
async def test_rotation_is_safe() -> None:
    """Refresh tokens rotate one refresh at a time; the agent's key rotates with overlap."""

    world = World()
    site = RotatingSite(world.atlas, max_age=600)
    world.network.add(world.atlas.domain, site)
    await world.signed_out_session()
    _, reference = await device_sign_in(world)
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    tokens = first_contribution(world.reactor, TOKEN_STORES, "token store")
    assert isinstance(tokens, TokenStore)
    first = await tokens.get(reference)

    # Two refreshes at once: serialized, each rotating; the last token is the live one.
    results = await asyncio.gather(
        accounts.refresh(reference, context=context(world)),
        accounts.refresh(reference, context=context(world)),
    )
    assert [r.status for r in results] == ["signed_in", "signed_in"]
    assert all(r.rotated for r in results)
    live = await tokens.get(reference)
    assert first is not None and live is not None
    assert live.get_secret_value() != first.get_secret_value()
    # The first token, rotated away, is refused; the live one works.
    await tokens.put(reference, first)
    refused = await accounts.refresh(reference, context=context(world))
    assert refused.status == "signed_out"
    await tokens.put(reference, live)
    assert (await accounts.refresh(reference, context=context(world))).status == "signed_in"

    # The agent's signing key: both keys published during the overlap, then the old retired.
    newer = same_agent_with(world, "key-2")
    site.keys = [*world.atlas.jwks["keys"], *newer.jwks["keys"]]
    assert await session_accepted(world, newer)
    assert await session_accepted(world, world.atlas)
    site.keys = list(newer.jwks["keys"])
    world.clock.advance(601)  # the company's cached key set expires
    assert not await session_accepted(world, world.atlas)
    assert await session_accepted(world, newer)
