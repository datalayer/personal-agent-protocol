# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What the reference company refuses, and how it says so."""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from reactor import PluginManifest

from personal_agent_protocol import Author, ConversationError, Message, SessionError
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
        session_key=session.session_key,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
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
    # Another Session's key signs the proof for this Session's token.
    other = await world.signed_out_session()
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint,
            world.message("hi"),
            token=session.model_copy(update={"session_key": other.session_key}),
            tenant_id=TENANT,
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
        session_key=session.session_key,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
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
    first = Message(id="msg_fixed_id_0000000000", author=Author(type="human"), text="Hello")
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


@pytest.mark.asyncio
async def test_a_scope_no_longer_offered_ends_the_sessions_holding_it() -> None:
    """A company rolled back to a version that no longer offers a scope (PAP_DATALAYER D-05).

    A Session holding it is refused (`invalid_token`): the personal agent starts a
    new Session within what is offered. Its Account Token is not refreshed for that
    scope (`invalid_scope`, re-consent) but still serves when asked within it.
    """

    from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
    from personal_agent_protocol.device import DeviceSignInClient

    world = World()
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        session_key=session.session_key,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.token is not None and done.account_token_reference is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    await world.conversations.start(
        endpoint, world.message("hi"), token=done.token, wait=0, **world.who
    )

    # Rolled back: the version now served offers no `orders:write`, so no operations either.
    config = world.shop.config
    world.shop.config = replace(
        config,
        scopes=tuple(s for s in config.scopes if s != "orders:write"),
        scope_descriptions={
            s: d for s, d in config.scope_descriptions.items() if s != "orders:write"
        },
        scope_hints={s: h for s, h in config.scope_hints.items() if s != "orders:write"},
        write_scopes=(),
        operations=False,
    )
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint, world.message("hi"), token=done.token, wait=0, **world.who
        )
    assert raised.value.status_code == 401

    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    context = AccountTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )
    fresh = await world.signed_out_session()
    reference = done.account_token_reference
    asked_all = await accounts.refresh(reference, context=context, session_key=fresh.session_key)
    assert asked_all.status == "re_consent_required"
    within = await accounts.refresh(
        reference, context=context, session_key=fresh.session_key, scopes=("orders:read",)
    )
    assert within.status == "signed_in" and within.token is not None
    await world.conversations.start(
        endpoint, world.message("hi"), token=within.token, wait=0, **world.who
    )


@pytest.mark.asyncio
async def test_a_password_reset_ends_the_sign_ins_from_before_it() -> None:
    """An account's sign-ins all end at a password reset (PAP_DATALAYER V-06).

    A directory that is also `AccountSignOuts` says since when: a signed-in
    Session from before is refused, its Account Token is not refreshed (and is
    revoked), the Session continues signed out, and signing in again works.
    """

    from datetime import datetime

    from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
    from personal_agent_protocol.company import COMPANY_ACCOUNTS, AccountSignOuts

    class Directory:
        def __init__(self) -> None:
            self.before: dict[str, datetime] = {}

        async def authenticate(self, credentials, context):  # type: ignore[no-untyped-def]
            return None

        async def check_code(self, code_reference, code):  # type: ignore[no-untyped-def]
            return False

        async def signed_out_before(self, account_id: str) -> datetime | None:
            return self.before.get(account_id)

    directory = Directory()
    assert isinstance(directory, AccountSignOuts)

    class Accounts:
        def provide_contributions(self, contributions):  # type: ignore[no-untyped-def]
            contributions.contribute(
                COMPANY_ACCOUNTS, directory, contribution_id="resets", order=-1
            )

    world = World()
    world.shop.reactor.register_plugin(PluginManifest(name="resets", version="1"), Accounts())
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    from personal_agent_protocol.device import DeviceSignInClient

    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read",),
        tenant_id=TENANT,
        session_key=session.session_key,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.token is not None and done.account_token_reference is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    await world.conversations.start(
        endpoint, world.message("hi"), token=done.token, wait=0, **world.who
    )
    # Another person's reset ends nothing of Ada's.
    directory.before["acct_bob"] = world.clock.now()
    await world.conversations.start(
        endpoint, world.message("hi"), token=done.token, wait=0, **world.who
    )

    # Ada resets her password a minute later.
    world.clock.advance(60)
    directory.before["acct_ada"] = world.clock.now()
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint, world.message("hi"), token=done.token, wait=0, **world.who
        )
    assert raised.value.status_code == 401

    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    context = AccountTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )
    fresh = await world.signed_out_session()
    refreshed = await accounts.refresh(
        done.account_token_reference, context=context, session_key=fresh.session_key
    )
    # The Account Token ended; the Session it named renews signed out (§4.8).
    assert refreshed.status == "signed_out"
    assert refreshed.token is not None and not refreshed.token.signed_in
    # Ended whole: its Session goes on signed out, even once nothing is said ended any more.
    directory.before.clear()
    kept = await world.shop._token_session(done.token.access_token.get_secret_value())
    assert kept is not None and not kept.signed_in and kept.account_token is None

    # A sign-in after the reset works.
    directory.before["acct_ada"] = world.clock.now()
    world.clock.advance(1)
    again = await signed_in(world)
    assert again is not None
    await world.conversations.start(endpoint, world.message("hi"), token=again, wait=0, **world.who)


@pytest.mark.asyncio
async def test_the_hosts_rate_limit_refuses_with_when_to_ask_again() -> None:
    """`pap.company.rateLimit` (PAP_DATALAYER B-06): asked once a request's Session is verified,
    with its agent and its signed-in account; a refusal is `429 rate_limited` with `Retry-After`,
    and nothing is done for the request. A forged token is refused before it is ever counted."""

    from personal_agent_protocol.company import COMPANY_RATE_LIMITS

    admitted: list[tuple[str, str | None]] = []

    class OncePerAgent:
        async def admit(self, client_id: str, account_id: str | None) -> int | None:
            admitted.append((client_id, account_id))
            return None if len(admitted) == 1 else 42

    class Limit:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(COMPANY_RATE_LIMITS, OncePerAgent(), contribution_id="limit")  # type: ignore[attr-defined]

    world = World()
    world.shop.reactor.register_plugin(PluginManifest(name="limit", version="1"), Limit())
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    started = await world.conversations.start(
        endpoint, world.message("hi"), token=session, **world.who
    )
    assert started.conversation_id
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint, world.message("hi again"), token=session, **world.who
        )
    assert raised.value.status_code == 429 and raised.value.code == "rate_limited"
    assert raised.value.details["retry_after"] == "42"
    assert admitted == [(world.atlas.client_id, None)] * 2
    forged = await world.http.post(endpoint, json={}, headers={"Authorization": "DPoP forged"})
    assert forged.status_code == 401 and len(admitted) == 2
