# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What the reference company refuses, and how it says so."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from reactor import PluginManifest

from personal_agent_protocol import ConversationError, Message, SessionError
from personal_agent_protocol.company import CLIENT_POLICIES
from personal_agent_protocol.company.store import DEVICE, PendingDevice
from personal_agent_protocol.operations import OperationError, OperationsClient, approve

from .test_company_end_to_end import PAIRWISE, TENANT, World


async def signed_in(world: World):  # type: ignore[no-untyped-def]
    """Sign Ada in through Device Sign-In, the company page approving."""

    from personal_agent_protocol import DeviceSignInClient

    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    return (await device.poll(started.reference)).token


@pytest.mark.asyncio
async def test_a_replayed_token_request_is_refused() -> None:
    """The same assertion and DPoP proof sent twice: one-time IDs refuse the second."""

    world = World()
    await world.signed_out_session()
    captured: list[httpx.Request] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await original(request)

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    await world.signed_out_session()
    token_request = next(r for r in captured if r.url.path == "/oauth/token")
    replay = await world.http.post(
        str(token_request.url), content=token_request.content, headers=dict(token_request.headers)
    )
    assert replay.status_code in {400, 401}
    assert replay.json()["error"] in {"invalid_client", "invalid_dpop_proof"}


@pytest.mark.asyncio
async def test_a_session_token_with_another_key_is_refused() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    # Another user's DPoP key (a different subject) signs the proof for Ada's token.
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint,
            world.message("hi"),
            token=session,
            tenant_id=TENANT,
            pairwise_user_id="usr_someone_else_0000000",
            issuer=world.who["issuer"],
        )
    assert raised.value.status_code == 401


@pytest.mark.asyncio
async def test_polling_too_fast_is_slow_down() -> None:
    world = World()
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    # The company saw a poll just now: polling again within the interval is slow_down.
    from personal_agent_protocol import DeviceSignInClient

    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read",),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    store = world.shop.store
    (key,) = store.keys(DEVICE)
    entry = await store.get(DEVICE, key)
    assert entry is not None
    world.clock.advance(started.poll_interval)
    polled = replace(PendingDevice.from_json(entry.value), last_poll=world.clock.now())
    await store.put(DEVICE, key, polled.to_json(), expires_at=entry.expires_at)
    first = await device.poll(started.reference)
    assert first.status == "pending"
    after = await store.get(DEVICE, key)
    assert after is not None
    assert PendingDevice.from_json(after.value).interval == started.poll_interval + 5


@pytest.mark.asyncio
async def test_a_reused_message_id_with_new_text_conflicts_and_a_retry_replays() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    first = Message(id="msg_fixed_id_0000000000", sender="human", text="Hello")
    started = await world.conversations.start(endpoint, first, token=session, **world.who)
    replayed = await world.conversations.start(endpoint, first, token=session, **world.who)
    assert replayed.conversation_id == started.conversation_id
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint,
            first.model_copy(update={"text": "Something else"}),
            token=session,
            **world.who,
        )
    assert raised.value.code == "message_id_conflict"


@pytest.mark.asyncio
async def test_a_direct_conversation_locks_its_parent_until_it_closes() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    parent = await world.conversations.start(
        endpoint, world.message("Hello"), token=session, **world.who
    )
    direct = await world.conversations.start_direct(
        endpoint,
        parent.conversation_id,
        world.message("It's Ada, talking directly"),
        token=session,
        **world.who,
    )
    with pytest.raises(ConversationError) as raised:
        await world.conversations.send(
            endpoint,
            parent.conversation_id,
            world.message("Still there?"),
            token=session,
            **world.who,
        )
    assert raised.value.details == {"conversation_id": direct.conversation_id}
    await world.conversations.close(endpoint, direct.conversation_id, token=session, **world.who)
    page = await world.conversations.read_events(
        endpoint, parent.conversation_id, token=session, **world.who
    )
    assert [e.type for e in page.events if e.type.startswith("direct")] == [
        "direct_opened",
        "direct_closed",
    ]
    await world.conversations.send(
        endpoint, parent.conversation_id, world.message("Back"), token=session, **world.who
    )


@pytest.mark.asyncio
async def test_a_revised_operation_is_terms_changed_and_never_performed_twice() -> None:
    world = World()
    token = await signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Exchange it for something warmer"),
        token=token,
        wait=0,
        **world.who,
    )
    proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    await world.shop.revise(
        proposal.operation_id,
        summary="Exchange for USD 85.00 more.",  # type: ignore[union-attr]
        terms={"order_id": "ord_7Hk2", "price_difference": {"amount": "85.00", "currency": "USD"}},
    )
    operations = OperationsClient(transport=world.transport)
    ops = world.shop.config.operations_endpoint
    outcome = await operations.confirm(
        ops, proposal, approval=approve(proposal), token=token, **world.who
    )  # type: ignore[arg-type]
    assert outcome.status == "terms_changed"
    assert outcome.changed == ("summary", "price_difference.amount")
    newer = outcome.operation
    # A standing permission is never used for a revision that needs the user.
    with pytest.raises(OperationError) as raised:
        await operations.confirm(
            ops, newer, standing=("x", "y", "orders.exchange"), token=token, **world.who
        )  # type: ignore[arg-type]
    assert raised.value.code == "user_approval_required"
    done = await operations.confirm(ops, newer, approval=approve(newer), token=token, **world.who)  # type: ignore[arg-type]
    assert done.operation.state == "succeeded"  # type: ignore[union-attr]
    assert world.plugin.executor.performed == [proposal.operation_id]  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_an_agent_without_the_extension_gets_no_operations() -> None:
    world = World()
    world.atlas.extensions = ()
    world.network.add(world.atlas.domain, world.atlas.website())
    token = await signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Exchange it for something warmer"),
        token=token,
        wait=0,
        **world.who,
    )
    assert all(e.message is None or e.message.operation is None for e in page.events)


@pytest.mark.asyncio
async def test_a_blocked_agent_cannot_start_a_session() -> None:
    world = World()

    class Blocklist:
        async def allows(self, client_id: str) -> bool:
            return not client_id.startswith("https://atlas.example/")

    class Policy:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(CLIENT_POLICIES, Blocklist(), contribution_id="blocklist")  # type: ignore[attr-defined]

    world.shop.reactor.register_plugin(PluginManifest(name="blocklist", version="1"), Policy())
    with pytest.raises(SessionError) as raised:
        await world.signed_out_session()
    assert raised.value.code == "invalid_client"
