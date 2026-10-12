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
from dataclasses import replace
from typing import Any

import httpx
import pytest
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    AuthorizationError,
    ConversationError,
    DeviceSignInClient,
    Message,
    PersonalAgentProtocolError,
    SessionClient,
    SessionToken,
    TokenStore,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.company import (
    build_company,
    company_app,
)
from personal_agent_protocol.company.store import DEVICE
from personal_agent_protocol.demo import manzanita as manzanita_demo
from personal_agent_protocol.demo.kit import ClockPlugin, StorePlugin
from personal_agent_protocol.operations import OperationError, OperationsClient, approve
from personal_agent_protocol.reactor import TOKEN_STORES, first_contribution

from .test_company_end_to_end import PAIRWISE, TENANT, World
from .test_company_refusals import signed_in
from .test_direct_and_api import begin, direct_world
from .test_guide_security import RotatingSite, same_agent_with, start_session

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


async def probe(world: World, token: SessionToken, **who: str) -> int:
    """Read Ada's orders: 200, or the status the company refused with."""

    try:
        return (
            await ApiClient(transport=world.transport).call(
                "GET", ORDERS, token=token, **(who or world.who)
            )
        ).status
    except ApiError as refused:
        return int(refused.status_code or 0)


def context(world: World) -> AccountTokenContext:
    metadata = world.company.oauth_metadata
    assert metadata is not None
    return AccountTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )


async def device_sign_in(world: World, session: SessionToken) -> tuple[SessionToken, str]:
    """Device Sign-In for `session`, Ada approving: the token and its Account Token reference."""

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
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.token is not None and done.account_token_reference is not None
    return done.token, done.account_token_reference


async def proposal(world: World, token: SessionToken) -> Any:
    """Ada asks for a warmer jacket: Manzanita proposes the exchange, performing nothing."""

    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Exchange it for something warmer"), token=token, wait=0,
        **world.who,
    )  # fmt: skip
    operation = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    assert operation is not None and operation.state == "proposed"
    return operation


@pytest.mark.asyncio
async def test_replay_is_refused() -> None:
    """A captured token request or API call, sent again byte for byte, is refused."""

    world = World()
    wire = Wire(world)
    token = await signed_in(world)
    assert await probe(world, token) == 200

    # The token request (client and Session assertions, DPoP proof): each is one-time.
    replayed = await wire.resend(world, wire.last("POST", "/oauth/token"))
    assert replayed.status_code in {400, 401}
    assert replayed.json()["error"] in {"invalid_client", "invalid_dpop_proof", "invalid_grant"}
    # The API call: its DPoP proof's ID was seen.
    replayed = await wire.resend(world, wire.last("GET", "/api/orders"))
    assert replayed.status_code == 401
    assert "orders" not in replayed.text
    # An operation's confirmation, replayed, performs nothing more.
    operation = await proposal(world, token)
    ops = world.shop.config.operations_endpoint
    await OperationsClient(transport=world.transport).confirm(
        ops, operation, approval=approve(operation), token=token, **world.who
    )
    confirm = wire.last("POST", f"/poppy/operations/{operation.operation_id}/confirm")
    assert (await wire.resend(world, confirm)).status_code == 401
    assert world.plugin.executor.performed == [operation.operation_id]
    # The agent itself carries on: fresh proofs every time.
    assert await probe(world, token) == 200


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
    assert await probe(world, session) == 403  # still signed out

    # Starting again works: the user signs in at the issuer the agent discovered.
    client = await begin(world, browser, session, ("orders:read",))
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    result = await client.complete(callback)
    assert await probe(world, result.token) == 200


@pytest.mark.asyncio
async def test_cross_tenant_access_is_refused() -> None:
    """One tenant's Session, used from another tenant of the same agent, is refused."""

    world = World()
    token = await signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), token=token, wait=0, **world.who
    )
    assert await probe(world, token) == 200

    # Another tenant of Atlas presents the token: its proofs are signed with that
    # tenant's own DPoP key, which the token is not bound to.
    other = {**world.who, "tenant_id": "another-tenant"}
    assert await probe(world, token, **other) == 401
    with pytest.raises(ConversationError) as refused:
        await world.conversations.read_events(endpoint, page.conversation_id, token=token, **other)
    assert refused.value.status_code == 401
    # Another user of the same tenant gets a Session of their own, which sees nothing of Ada's.
    stranger = "usr_somebody_else_000000"
    metadata = world.company.oauth_metadata
    assert metadata is not None
    strangers = await SessionClient(reactor=world.reactor, http_client=world.http).start(
        client_id=world.atlas.client_id,
        pairwise_user_id=stranger,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=TENANT,
    )
    with pytest.raises(ConversationError) as hidden:
        await world.conversations.read_events(
            endpoint,
            page.conversation_id,
            token=strangers,
            tenant_id=TENANT,
            pairwise_user_id=stranger,
            issuer=metadata.issuer,
        )
    assert hidden.value.code == "conversation_not_found"
    # Ada's own tenant is unaffected.
    assert await probe(world, token) == 200


@pytest.mark.asyncio
async def test_stale_approval_is_refused() -> None:
    """An approval of revision 1 never confirms revision 2: the user approves again."""

    world = World()
    token = await signed_in(world)
    operation = await proposal(world, token)
    stale = approve(operation)
    await world.shop.revise(
        operation.operation_id,
        summary="Exchange for USD 85.00 more.",
        terms={"order_id": "ord_7Hk2", "price_difference": {"amount": "85.00", "currency": "USD"}},
    )
    operations = OperationsClient(transport=world.transport)
    ops = world.shop.config.operations_endpoint

    outcome = await operations.confirm(ops, operation, approval=stale, token=token, **world.who)
    assert outcome.status == "terms_changed"
    assert outcome.changed == ("summary", "price_difference.amount")
    newer = outcome.operation
    assert newer is not None and newer.revision == 2
    # The stale approval does not fit the new revision, locally, before anything is sent.
    with pytest.raises(OperationError) as refused:
        await operations.confirm(ops, newer, approval=stale, token=token, **world.who)
    assert refused.value.code == "approval_mismatch"
    assert world.plugin.executor.performed == []

    done = await operations.confirm(ops, newer, approval=approve(newer), token=token, **world.who)
    assert done.status == "confirmed" and done.operation.state == "succeeded"  # type: ignore[union-attr]
    # The stale approval of the first revision, presented once more, performs nothing.
    # Manzanita answers with the record as it is (revision 2, succeeded), which the agent
    # refuses to take as a confirmation of revision 1.
    with pytest.raises(OperationError) as late:
        await operations.confirm(ops, operation, approval=stale, token=token, **world.who)
    assert late.value.code == "invalid_operation"
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_retries_are_safe() -> None:
    """A retried message is one message; a confirmation whose answer is lost is done once."""

    world = World()
    wire = Wire(world)
    token = await signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    # The same message ID, sent twice: one conversation, one message.
    message = Message(id="msg_retry_demo_0000000001", sender="human", text="Hello")
    first = await world.conversations.start(endpoint, message, token=token, **world.who)
    again = await world.conversations.start(endpoint, message, token=token, **world.who)
    assert again.conversation_id == first.conversation_id
    page = await world.conversations.read_events(
        endpoint, first.conversation_id, token=token, **world.who
    )
    sent = [e for e in page.events if e.message is not None and e.message.id == message.id]
    assert len(sent) == 1

    # The confirmation reaches Manzanita, which performs it; its answer is lost on the way back.
    operation = await proposal(world, token)
    operations = OperationsClient(transport=world.transport)
    ops = world.shop.config.operations_endpoint
    wire.lose = f"/{operation.operation_id}/confirm"
    recovered = await operations.confirm(
        ops, operation, approval=approve(operation), token=token, **world.who
    )
    assert recovered.status == "confirmed"
    assert recovered.operation.state == "succeeded"  # type: ignore[union-attr]
    # Read back by the same ID, never assumed failed; retried, it is not performed twice.
    retried = await operations.confirm(
        ops, operation, approval=approve(operation), token=token, **world.who
    )
    assert retried.operation.state == "succeeded"  # type: ignore[union-attr]
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_restart_is_safe() -> None:
    """Restarted over its store, which holds the replay cache: it goes on, replays stay refused."""

    world = World(durable=True)
    wire = Wire(world)
    session = await world.signed_out_session()
    token, _ = await device_sign_in(world, session)
    operation = await proposal(world, token)
    assert await probe(world, token) == 200
    captured = wire.last("GET", "/api/orders")

    world.restart()

    # A proof seen before the restart is still refused after it.
    assert (await wire.resend(world, captured)).status_code == 401
    # The Session, the proposal and its single performance carry over.
    assert await probe(world, token) == 200
    ops = world.shop.config.operations_endpoint
    operations = OperationsClient(transport=world.transport)
    done = await operations.confirm(
        ops, operation, approval=approve(operation), token=token, **world.who
    )
    assert done.operation.state == "succeeded"  # type: ignore[union-attr]
    performed = list(world.plugin.executor.performed)

    world.restart()
    again = await operations.confirm(
        ops, operation, approval=approve(operation), token=token, **world.who
    )
    assert again.operation.state == "succeeded"  # type: ignore[union-attr]
    assert performed == [operation.operation_id] and world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_rollback_is_safe() -> None:
    """Rolled back to an earlier release over the same store: nothing done is undone or redone."""

    world = World(durable=True)
    session = await world.signed_out_session()
    token, reference = await device_sign_in(world, session)
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    tokens = first_contribution(world.reactor, TOKEN_STORES, "token store")
    assert isinstance(tokens, TokenStore)
    before = await tokens.get(reference)
    refreshed = await accounts.refresh(
        reference, context=context(world), session_id=session.session_id
    )
    assert refreshed.rotated and refreshed.token is not None
    rotated = await tokens.get(reference)
    operation = await proposal(world, refreshed.token)
    ops = world.shop.config.operations_endpoint
    operations = OperationsClient(transport=world.transport)
    done = await operations.confirm(
        ops, operation, approval=approve(operation), token=refreshed.token, **world.who
    )
    assert done.operation.state == "succeeded"  # type: ignore[union-attr]
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

    # The rotated-away Account Token stays refused; the current one works.
    assert before is not None and rotated is not None
    await tokens.put(reference, before)
    stale = await accounts.refresh(reference, context=context(world), session_id=session.session_id)
    assert stale.status == "signed_out"
    await tokens.put(reference, rotated)
    current = await accounts.refresh(
        reference, context=context(world), session_id=session.session_id
    )
    assert current.status == "signed_in" and current.token is not None
    # The confirmed operation is not performed again by the earlier release.
    again = await operations.confirm(
        ops, operation, approval=approve(operation), token=current.token, **world.who
    )
    assert again.operation.state == "succeeded"  # type: ignore[union-attr]
    assert plugin.executor.performed == []
    # The earlier release serves what it has: no website, the same API and Sessions.
    assert world.company.document.web is not None  # what the agent discovered before
    assert await probe(world, current.token) == 200


@pytest.mark.asyncio
async def test_revocation_is_safe() -> None:
    """Signing out takes effect at once: every signed-in token reads as signed out."""

    world = World()
    session = await world.signed_out_session()
    token, reference = await device_sign_in(world, session)
    assert await probe(world, token) == 200
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    second = await world.signed_out_session()
    other = await accounts.refresh(reference, context=context(world), session_id=second.session_id)
    assert other.status == "signed_in" and other.token is not None

    revoked = await accounts.revoke(reference, context=context(world))
    assert revoked.revoked and revoked.deleted_locally
    # Both Sessions signed in from that sign-in are signed out right away, not at expiry.
    assert await probe(world, token) == 403
    assert await probe(world, other.token) == 403
    # The Account Token is gone locally and refused at the company; Sessions continue signed out.
    after = await accounts.refresh(reference, context=context(world), session_id=session.session_id)
    assert after.status == "signed_out"
    metadata = world.company.oauth_metadata
    assert metadata is not None
    renewed = await SessionClient(reactor=world.reactor, http_client=world.http).renew(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=TENANT,
        session_id=session.session_id,
    )
    assert renewed.signed_in is False and await probe(world, renewed) == 403


@pytest.mark.asyncio
async def test_rotation_is_safe() -> None:
    """Account Tokens rotate one refresh at a time; the agent's signing key rotates with overlap."""

    world = World()
    site = RotatingSite(world.atlas, max_age=600)
    world.network.add(world.atlas.domain, site)
    session = await world.signed_out_session()
    _, reference = await device_sign_in(world, session)
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    tokens = first_contribution(world.reactor, TOKEN_STORES, "token store")
    assert isinstance(tokens, TokenStore)
    first = await tokens.get(reference)

    # Two refreshes at once: serialized, each rotating; the last token is the live one.
    results = await asyncio.gather(
        accounts.refresh(reference, context=context(world), session_id=session.session_id),
        accounts.refresh(reference, context=context(world), session_id=session.session_id),
    )
    assert [r.status for r in results] == ["signed_in", "signed_in"]
    assert all(r.rotated for r in results)
    live = await tokens.get(reference)
    assert first is not None and live is not None
    assert live.get_secret_value() != first.get_secret_value()
    # The first token, rotated away, is refused; the live one works.
    await tokens.put(reference, first)
    refused = await accounts.refresh(
        reference, context=context(world), session_id=session.session_id
    )
    assert refused.status == "signed_out"
    await tokens.put(reference, live)
    assert (
        await accounts.refresh(reference, context=context(world), session_id=session.session_id)
    ).status == "signed_in"

    # The agent's signing key: both keys published during the overlap, then the old retired.
    newer = same_agent_with(world, "key-2")
    site.keys = [*world.atlas.jwks["keys"], *newer.jwks["keys"]]
    assert (await start_session(world, newer)).signed_in is False
    assert (await start_session(world, world.atlas)).signed_in is False
    site.keys = list(newer.jwks["keys"])
    world.clock.advance(601)  # the company's cached key set expires
    with pytest.raises(PersonalAgentProtocolError) as retired:
        await start_session(world, world.atlas)
    assert retired.value.code == "invalid_client"
    assert (await start_session(world, newer)).signed_in is False
