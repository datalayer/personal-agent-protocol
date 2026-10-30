# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What the reference company refuses, and how it says so."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from reactor import PluginManifest

from personal_agent_protocol import (
    Author,
    AuthorizationError,
    ConversationError,
    DeviceSignInClient,
    Message,
)
from personal_agent_protocol.company import CLIENT_POLICIES
from personal_agent_protocol.company.store import DEVICE, PendingDevice
from personal_agent_protocol.conversations import generate_message_id
from personal_agent_protocol.models import Approval
from personal_agent_protocol.transport import session_headers

from .test_company_end_to_end import TENANT, World


async def signed_in(world: World):  # type: ignore[no-untyped-def]
    """Sign Ada in through Device Sign-In, the company page approving: her access token.

    `world.session` is a Session to use it in, and `world.refresh_reference` where
    its refresh token is kept.
    """

    world.session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    world.refresh_reference = done.refresh_token_reference
    return done.token


@pytest.mark.asyncio
async def test_a_replayed_token_request_is_refused() -> None:
    """The same client assertion sent twice: its one-time `jti` refuses the second."""

    world = World()
    captured: list[httpx.Request] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await original(request)

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    await signed_in(world)
    token_request = next(r for r in captured if r.url.path == "/oauth/token")
    replay = await world.http.post(
        str(token_request.url), content=token_request.content, headers=dict(token_request.headers)
    )
    assert (replay.status_code, replay.json()["error"]) == (401, "invalid_client")


@pytest.mark.asyncio
async def test_a_session_jwt_signed_with_another_key_is_refused() -> None:
    """Valid in every claim and delegation, but not signed by the delegated key (§5.3)."""

    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    genuine = (await session_headers(world.reactor, "POST", endpoint, session=session, token=None))[
        "Poppy-Session"
    ]
    header = jwt.get_unverified_header(genuine)
    claims = jwt.decode(genuine, options={"verify_signature": False})
    forged = jwt.encode(
        claims,
        ec.generate_private_key(ec.SECP256R1()),
        algorithm="ES256",
        headers={name: header[name] for name in ("typ", "kid", "pap_dlg")},
    )
    refused = await world.http.post(endpoint, json={}, headers={"Poppy-Session": forged})
    assert (refused.status_code, refused.json()) == (400, {"error": "invalid_session"})


@pytest.mark.asyncio
async def test_polling_too_fast_is_slow_down() -> None:
    world = World()
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    # The company saw a poll just now: polling again within the interval is slow_down.
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read",),
        tenant_id=TENANT,
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
    started = await world.conversations.start(endpoint, first, session=session)
    replayed = await world.conversations.start(endpoint, first, session=session)
    assert replayed.conversation_id == started.conversation_id
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint,
            first.model_copy(update={"text": "Something else"}),
            session=session,
        )
    assert raised.value.code == "message_id_conflict"


@pytest.mark.asyncio
async def test_a_direct_conversation_locks_its_parent_until_it_closes() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    parent = await world.conversations.start(endpoint, world.message("Hello"), session=session)
    direct = await world.conversations.start_direct(
        endpoint,
        parent.conversation_id,
        world.message("It's Ada, talking directly"),
        session=session,
    )
    with pytest.raises(ConversationError) as raised:
        await world.conversations.send(
            endpoint,
            parent.conversation_id,
            world.message("Still there?"),
            session=session,
        )
    assert raised.value.details == {"conversation_id": direct.conversation_id}
    await world.conversations.close(endpoint, direct.conversation_id, session=session)
    page = await world.conversations.read_events(endpoint, parent.conversation_id, session=session)
    assert [e.type for e in page.events if e.type.startswith("direct")] == [
        "direct_opened",
        "direct_closed",
    ]
    await world.conversations.send(
        endpoint, parent.conversation_id, world.message("Back"), session=session
    )


@pytest.mark.asyncio
async def test_a_revised_operation_answers_a_new_revision_and_is_never_performed_twice() -> None:
    world = World()
    token = await signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Exchange it for something warmer"),
        session=world.session,
        token=token,
        wait=0,
    )
    proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    await world.shop.revise(
        proposal.operation_id,
        summary="Exchange for USD 85.00 more.",  # type: ignore[union-attr]
        terms={"order_id": "ord_7Hk2", "price_difference": {"amount": "85.00", "currency": "USD"}},
    )
    send = world.conversations.send

    async def approving(operation: Any) -> Any:
        message = Message(
            id=generate_message_id(world.reactor),
            author=Author(type="agent"),
            approval=Approval(operation_id=operation.operation_id, revision=operation.revision),
        )
        page_ = await send(
            endpoint, page.conversation_id, message, session=world.session, token=token, wait=0
        )
        return [e.message for e in page_.events if e.message is not None][-1]

    told = await approving(proposal)
    newer = told.operation
    assert newer is not None and newer.operation_id == proposal.operation_id  # type: ignore[union-attr]
    assert newer.revision != proposal.revision  # type: ignore[union-attr]
    assert newer.summary == "Exchange for USD 85.00 more."
    assert world.plugin.executor.performed == []
    done = await approving(newer)
    assert done.operation is None and done.text.startswith("Exchanged")
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
        session=world.session,
        token=token,
        wait=0,
    )
    assert all(e.message is None or e.message.operation is None for e in page.events)


@pytest.mark.asyncio
async def test_a_blocked_agent_cannot_start_a_session() -> None:
    """A Session starts on the agent's side: the company refuses its first request (§4.1)."""

    world = World()

    class Blocklist:
        async def allows(self, client_id: str) -> bool:
            return not client_id.startswith("https://atlas.example/")

    class Policy:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(CLIENT_POLICIES, Blocklist(), contribution_id="blocklist")  # type: ignore[attr-defined]

    world.shop.reactor.register_plugin(PluginManifest(name="blocklist", version="1"), Policy())
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(endpoint, world.message("hi"), session=session)
    assert (raised.value.code, raised.value.status_code) == ("invalid_session", 400)
    # And its sign-in stops at the first client assertion.
    metadata = world.company.oauth_metadata
    with pytest.raises(AuthorizationError) as refused:
        await DeviceSignInClient(reactor=world.reactor, http_client=world.http).begin(
            device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
            token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
            issuer=metadata.issuer,  # type: ignore[union-attr]
            client_id=world.atlas.client_id,
            scopes=("orders:read",),
            tenant_id=TENANT,
            organization=world.company.document.organization,
            protected_resources=metadata.protected_resources,  # type: ignore[union-attr]
        )
    assert refused.value.code == "invalid_client"


@pytest.mark.asyncio
async def test_a_scope_no_longer_offered_ends_the_access_tokens_holding_it() -> None:
    """A company rolled back to a version that no longer offers a scope.

    An access token holding it is refused (`invalid_token`). Its refresh token is not
    refreshed for that scope (`invalid_scope`, re-consent) but still serves when asked
    within what is offered.
    """

    from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext

    world = World()
    token = await signed_in(world)
    session = world.session
    metadata = world.company.oauth_metadata
    assert metadata is not None and world.refresh_reference is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    await world.conversations.start(
        endpoint, world.message("hi"), session=session, token=token, wait=0
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
            endpoint, world.message("hi"), session=session, token=token, wait=0
        )
    assert (raised.value.code, raised.value.status_code) == ("invalid_token", 401)

    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    context = RefreshTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
    )
    reference = world.refresh_reference
    asked_all = await accounts.refresh(reference, context=context)
    assert asked_all.status == "re_consent_required"
    within = await accounts.refresh(reference, context=context, scopes=("orders:read",))
    assert within.status == "signed_in" and within.token is not None
    await world.conversations.start(
        endpoint, world.message("hi"), session=session, token=within.token, wait=0
    )


@pytest.mark.asyncio
async def test_a_password_reset_ends_the_sign_ins_from_before_it() -> None:
    """An account's sign-ins all end at a password reset.

    A directory that is also `AccountSignOuts` says since when: an access token from
    before is refused, its refresh token is not refreshed (and is revoked), the Session
    continues signed out, and signing in again works.
    """

    from datetime import datetime

    from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
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
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.token is not None and done.refresh_token_reference is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    await world.conversations.start(
        endpoint, world.message("hi"), session=session, token=done.token, wait=0
    )
    # Another person's reset ends nothing of Ada's.
    directory.before["acct_bob"] = world.clock.now()
    await world.conversations.start(
        endpoint, world.message("hi"), session=session, token=done.token, wait=0
    )

    # Ada resets her password a minute later.
    world.clock.advance(60)
    directory.before["acct_ada"] = world.clock.now()
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(
            endpoint, world.message("hi"), session=session, token=done.token, wait=0
        )
    assert (raised.value.code, raised.value.status_code) == ("invalid_token", 401)

    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    context = RefreshTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
    )
    refreshed = await accounts.refresh(done.refresh_token_reference, context=context)
    # The refresh token ended with the sign-in: the Session continues signed out (§5.5).
    assert refreshed.status == "signed_out" and refreshed.token is None
    # Ended whole: its access token stays refused, even once nothing is said ended any more.
    directory.before.clear()
    assert await world.shop._access_token(done.token.access_token.get_secret_value()) is None
    await world.conversations.start(endpoint, world.message("hi"), session=session, wait=0)

    # A sign-in after the reset works.
    directory.before["acct_ada"] = world.clock.now()
    world.clock.advance(1)
    again = await signed_in(world)
    assert again is not None
    await world.conversations.start(
        endpoint, world.message("hi"), session=world.session, token=again, wait=0
    )


@pytest.mark.asyncio
async def test_the_hosts_rate_limit_refuses_with_when_to_ask_again() -> None:
    """`pap.company.rateLimit`: asked once a request's Session is verified,
    with its agent and its signed-in account; a refusal is HTTP 429 with `Retry-After`, and
    nothing is done for the request. A forged request is refused before it is ever counted."""

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
    started = await world.conversations.start(endpoint, world.message("hi"), session=session)
    assert started.conversation_id
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(endpoint, world.message("hi again"), session=session)
    assert raised.value.status_code == 429 and raised.value.code == "rate_limited"
    assert raised.value.details["retry_after"] == "42"
    assert admitted == [(world.atlas.client_id, None)] * 2
    forged = await world.http.post(endpoint, json={}, headers={"Authorization": "Bearer forged"})
    assert (forged.status_code, forged.json()) == (400, {"error": "invalid_session"})
    assert len(admitted) == 2
