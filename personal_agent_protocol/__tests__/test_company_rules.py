# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The reference company's rules of draft 0.2, each with the personal agent's view of it.

A Session tied to the account it was ever signed in to (§4.4, §4.8); what
continues after sign-out (§4.9, Operations §3.2); Mediated Sign-In's
statuses and errors (§4.7); conversation requests (§7.3 to §7.13); DPoP
nonces in both shapes (§4.3); `extension_required` at an API (§3.3).
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import httpx
import pytest

from personal_agent_protocol import (
    AuthorizationError,
    ConversationError,
    DeviceSignInClient,
    Message,
    SessionClient,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE
from personal_agent_protocol.mediated import MediatedSignInClient
from personal_agent_protocol.models import Author, ConversationEventPage
from personal_agent_protocol.operations import OperationError, OperationsClient
from personal_agent_protocol.sessions import SessionToken

from .test_company_end_to_end import PAIRWISE, TENANT, World

MEDIATED = "https://manzanita.example/poppy/sign-in"
ORDERS = "https://manzanita.example/api/orders"
EXCHANGE = "https://manzanita.example/api/orders/ord_7Hk2/exchanges"


def context(world: World) -> AccountTokenContext:
    metadata = world.company.oauth_metadata
    assert metadata is not None
    return AccountTokenContext(
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        revocation_endpoint=metadata.revocation_endpoint,
    )


async def device_sign_in(
    world: World, session: SessionToken, account_id: str
) -> tuple[SessionToken | None, str | None, AuthorizationError | None]:
    """Device Sign-In of `session`, the user approving as `account_id`."""

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
        session_key=session.session_key,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    assert (started.organization_name, started.organization_domain) == (
        "Manzanita Outfitters",
        "manzanita.example",
    )
    await world.shop.approve_device(started.user_code, account_id=account_id)
    world.clock.advance(started.poll_interval)
    try:
        done = await device.poll(started.reference)
    except AuthorizationError as error:
        return None, None, error
    return done.token, done.account_token_reference, None


async def post_json(world: World, token: SessionToken, url: str, body: Any) -> httpx.Response:
    return await world.transport.request(
        "POST",
        url,
        token=token,
        headers={"Content-Type": "application/json"},
        content=json.dumps(body).encode(),
        **world.who,
    )


# A Session stays tied to its account (§4.4, §4.8) ---------------------------------------


@pytest.mark.asyncio
async def test_a_signed_out_session_is_never_signed_in_to_another_account() -> None:
    world = World()
    session = await world.signed_out_session()
    token, reference, _ = await device_sign_in(world, session, "acct_ada")
    assert token is not None and reference is not None
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    await accounts.revoke(reference, context=context(world))
    renewed = await SessionClient(reactor=world.reactor, http_client=world.http).renew(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=world.who["issuer"],
        token_endpoint=world.company.oauth_metadata.token_endpoint,  # type: ignore[union-attr]
        tenant_id=TENANT,
        session_key=session.session_key,
    )
    assert not renewed.signed_in  # it continues signed out (§4.9)

    # Signed out since, it is still tied to acct_ada: the device poll issues nothing.
    other, other_reference, refused = await device_sign_in(world, renewed, "acct_bob")
    assert other is None and other_reference is None
    assert refused is not None and refused.code == "account_mismatch"
    assert refused.status_code == 400

    # An Account Token for acct_bob, from another Session, is refused here too.
    fresh = await world.signed_out_session()
    bob, bob_reference, _ = await device_sign_in(world, fresh, "acct_bob")
    assert bob is not None and bob_reference is not None
    with pytest.raises(AuthorizationError) as mismatch:
        await accounts.refresh(bob_reference, context=context(world), session_key=session.session_key)
    assert mismatch.value.code == "account_mismatch"

    # The same account is welcome back.
    back, _, none = await device_sign_in(world, renewed, "acct_ada")
    assert none is None and back is not None and back.session_key == session.session_key


@pytest.mark.asyncio
async def test_mediated_sign_in_of_a_session_tied_to_another_account_is_account_mismatch() -> None:
    world = World(dict(ADA))
    session = await world.signed_out_session()
    _, reference, _ = await device_sign_in(world, session, "acct_bob")
    assert reference is not None
    await AccountTokenClient(reactor=world.reactor, http_client=world.http).revoke(
        reference, context=context(world)
    )
    session = await SessionClient(reactor=world.reactor, http_client=world.http).renew(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=world.who["issuer"],
        token_endpoint=world.company.oauth_metadata.token_endpoint,  # type: ignore[union-attr]
        tenant_id=TENANT,
        session_key=session.session_key,
    )
    auth = world.company.document.auth
    assert auth is not None and auth.mediated is not None
    with pytest.raises(AuthorizationError) as raised:
        await MediatedSignInClient(reactor=world.reactor, http_client=world.http).sign_in(
            mediated=auth.mediated,
            organization=world.company.document.organization,
            issuer=auth.issuer,
            scopes=("orders:read",),
            token=session,
            tenant_id=TENANT,
        )
    assert (raised.value.code, raised.value.status_code) == ("account_mismatch", 400)
    # The host asked for the credentials naming the company and its issuer (§4.7).
    asked = world.host.protected_input.asked[0]
    assert (asked.company_name, asked.company_domain, asked.issuer) == (
        "Manzanita Outfitters",
        "manzanita.example",
        "https://manzanita.example",
    )


# After sign-out (§4.9, §7.11, Operations §3.2) --------------------------------------------


@pytest.mark.asyncio
async def test_after_sign_out_what_used_the_account_stays_and_asks_for_sign_in() -> None:
    world = World()
    session = await world.signed_out_session()
    token, reference, _ = await device_sign_in(world, session, "acct_ada")
    assert token is not None and reference is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), token=token, wait=0, **world.who
    )
    proposed = await ApiClient(transport=world.transport).call(
        "POST", EXCHANGE, token=token, body={}, **world.who
    )
    assert proposed.operation is not None
    await AccountTokenClient(reactor=world.reactor, http_client=world.http).revoke(
        reference, context=context(world)
    )
    signed_out = await SessionClient(reactor=world.reactor, http_client=world.http).renew(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=world.who["issuer"],
        token_endpoint=world.company.oauth_metadata.token_endpoint,  # type: ignore[union-attr]
        tenant_id=TENANT,
        session_key=session.session_key,
    )
    # The conversation stays open, and a signed-out token on it gets sign_in_required.
    record = await world.shop.conversation_record(page.conversation_id)
    assert record.status != "closed"
    with pytest.raises(ConversationError) as read:
        await world.conversations.read_events(
            endpoint, page.conversation_id, token=signed_out, **world.who
        )
    assert (read.value.code, read.value.status_code) == ("insufficient_scope", 403)
    # The operation belongs to the account: signed out, the same Session is asked to sign in.
    operations = OperationsClient(transport=world.transport)
    with pytest.raises(OperationError) as op:
        await operations.read(
            world.shop.config.operations_endpoint,
            proposed.operation.operation_id,
            token=signed_out,
            **world.who,
        )
    assert (op.value.code, op.value.status_code) == ("insufficient_scope", 403)
    # Signed in again to the same account, the Session continues both.
    back, _, _ = await device_sign_in(world, signed_out, "acct_ada")
    assert back is not None
    again = await world.conversations.read_events(
        endpoint, page.conversation_id, token=back, **world.who
    )
    assert again.conversation_id == page.conversation_id
    current = await operations.read(
        world.shop.config.operations_endpoint,
        proposed.operation.operation_id,
        token=back,
        **world.who,
    )
    assert current.operation_id == proposed.operation.operation_id
    # Another account's Session never learns it exists.
    stranger = await world.signed_out_session()
    bob, _, _ = await device_sign_in(world, stranger, "acct_bob")
    assert bob is not None
    with pytest.raises(OperationError) as hidden:
        await operations.read(
            world.shop.config.operations_endpoint,
            proposed.operation.operation_id,
            token=bob,
            **world.who,
        )
    assert hidden.value.code == "operation_not_found"


# Mediated Sign-In's statuses and errors (§4.7) ---------------------------------------------


@pytest.mark.asyncio
async def test_a_failed_or_expired_mediated_sign_in_stays_so_and_unknown_is_not_found() -> None:
    world = World()
    session = await world.signed_out_session()
    started = await post_json(
        world, session, MEDIATED, {"credentials": dict(ADA), "scope": "orders:read"}
    )
    assert started.status_code == 200 and started.json()["status"] == "code_required"
    sign_in_id = started.json()["sign_in_id"]
    statuses = []
    for _ in range(4):
        answer = await post_json(world, session, f"{MEDIATED}/{sign_in_id}", {"code": "000000"})
        assert answer.status_code == 200  # every status comes with HTTP 200
        statuses.append(answer.json()["status"])
    assert statuses == ["code_required", "code_required", "failed", "failed"]
    # Even the right code: once failed, the same status again.
    right = await post_json(world, session, f"{MEDIATED}/{sign_in_id}", {"code": ADA_CODE})
    assert (right.status_code, right.json()) == (200, {"status": "failed"})

    later = await world.signed_out_session()
    started = await post_json(
        world, later, MEDIATED, {"credentials": dict(ADA), "scope": "orders:read"}
    )
    expiring = started.json()["sign_in_id"]
    world.clock.advance(6 * 60)
    renewed = await world.signed_out_session()
    for _ in range(2):
        answer = await post_json(world, later, f"{MEDIATED}/{expiring}", {"code": ADA_CODE})
        assert (answer.status_code, answer.json()) == (200, {"status": "expired"})

    # Unknown, or another Session's: the same 404 sign_in_not_found.
    for token, target in ((renewed, expiring), (later, "si_unknown")):
        missing = await post_json(world, token, f"{MEDIATED}/{target}", {"code": ADA_CODE})
        assert (missing.status_code, missing.json()) == (404, {"error": "sign_in_not_found"})
    unknown_scope = await post_json(
        world, renewed, MEDIATED, {"credentials": dict(ADA), "scope": "orders:everything"}
    )
    assert (unknown_scope.status_code, unknown_scope.json()) == (400, {"error": "invalid_scope"})


# Conversation requests (§7.3 to §7.13) -----------------------------------------------------


@pytest.mark.asyncio
async def test_wait_is_a_whole_number_of_seconds_and_a_larger_one_is_capped() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Hello"), token=session, wait=0, **world.who
    )
    events = f"{endpoint}/{page.conversation_id}/events"
    for wait in ("-1", "1.5", "soon", "", "\u0661"):
        refused = await world.transport.request(
            "GET", f"{events}?wait={wait}", token=session, **world.who
        )
        assert (refused.status_code, refused.json()) == (400, {"error": "invalid_request"}), wait
    capped = await world.conversations.read_events(
        endpoint, page.conversation_id, token=session, wait=86_400, **world.who
    )
    assert capped.conversation_id == page.conversation_id
    # A malformed message on the POSTs: none of text, data, context.
    bad = await post_json(
        world,
        session,
        f"{endpoint}/{page.conversation_id}/messages",
        {"message": {"id": "msg_x", "author": {"type": "agent"}}},
    )
    assert (bad.status_code, bad.json()) == (400, {"error": "invalid_request"})
    # An ID with characters not allowed is malformed, not unknown (§7.2).
    odd = await world.transport.request(
        "GET", f"{endpoint}/cnv.bad/events", token=session, **world.who
    )
    assert (odd.status_code, odd.json()) == (400, {"error": "invalid_request"})


@pytest.mark.asyncio
async def test_a_message_is_recorded_as_sent_and_its_role_is_the_companys_to_set() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    started = await post_json(
        world,
        session,
        f"{endpoint}?wait=0",
        {
            "message": {
                "id": "msg_role_sent",
                "author": {"type": "agent"},
                "role": "company",
                "text": "Hi",
                "data": {"order": "ord_1"},
                "context": {"locale": "en-US"},
            }
        },
    )
    assert started.status_code == 201
    page = ConversationEventPage.model_validate(started.json())
    first = page.events[0].message
    assert first is not None and first.role == "user"  # the company ignores a role sent
    assert first.text == "Hi" and first.data == {"order": "ord_1"}
    assert first.context == {"locale": "en-US"}
    # A message with only context is recorded too.
    only_context = Message(id="msg_only_ctx", author=Author(type="agent"), context={"user_available": True})
    answer = await world.conversations.send(
        endpoint,
        page.conversation_id,
        only_context,
        token=session,
        cursor=page.cursor,
        wait=0,
        **world.who,
    )
    assert isinstance(answer, ConversationEventPage)
    recorded = [e.message for e in answer.events if e.type == "message"]
    assert recorded and recorded[0] is not None and recorded[0].id == "msg_only_ctx"
    assert recorded[0].context == {"user_available": True} and recorded[0].role == "user"
    # The personal agent never sends a role.
    with pytest.raises(Exception, match="role"):
        await world.conversations.send(
            endpoint,
            page.conversation_id,
            Message(id="msg_with_role", author=Author(type="agent"), role="user", text="x"),
            token=session,
            **world.who,
        )


@pytest.mark.asyncio
async def test_repeated_handoff_and_close_change_nothing() -> None:
    world = World()
    world.shop.config = dataclasses.replace(world.shop.config, humans_available=True)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("A person, please"), token=session, wait=0, **world.who
    )
    first = await world.conversations.handoff(
        endpoint, page.conversation_id, token=session, **world.who
    )
    assert first.responder == "human"
    count = len((await world.shop.conversation_record(page.conversation_id)).events)
    again = await world.conversations.handoff(
        endpoint, page.conversation_id, token=session, **world.who
    )
    assert (again.status, again.responder) == (first.status, first.responder)
    assert len((await world.shop.conversation_record(page.conversation_id)).events) == count
    closed = await world.conversations.close(
        endpoint, page.conversation_id, token=session, **world.who
    )
    count = len((await world.shop.conversation_record(page.conversation_id)).events)
    closed_again = await world.conversations.close(
        endpoint, page.conversation_id, token=session, **world.who
    )
    assert closed_again == closed and closed.status == "closed"
    assert len((await world.shop.conversation_record(page.conversation_id)).events) == count


@pytest.mark.asyncio
async def test_last_event_id_wins_over_cursor_on_a_stream() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Hello"), token=session, wait=0, **world.who
    )
    await world.conversations.close(endpoint, page.conversation_id, token=session, **world.who)
    ids = [event.id for event in page.events]
    response = await world.transport.request(
        "GET",
        f"{endpoint}/{page.conversation_id}/events?cursor={ids[0]}",
        token=session,
        headers={"Accept": "text/event-stream", "Last-Event-ID": ids[-1]},
        **world.who,
    )
    streamed = [
        json.loads(line[5:])["id"]
        for line in response.text.splitlines()
        if line.startswith("data:") and '"type"' in line
    ]
    # Only what follows Last-Event-ID; the cursor (the first event) is ignored.
    assert ids[1] not in streamed and streamed and streamed[-1] != ids[-1]


def test_a_read_without_its_fields_is_refused() -> None:
    base = {
        "conversation_id": "cnv_1",
        "events": [],
        "cursor": "evt_1",
        "has_more": False,
        "status": "idle",
        "responder": "agent",
    }
    assert ConversationEventPage.model_validate(base).events == []
    for missing in ("conversation_id", "events"):
        with pytest.raises(ValueError):
            ConversationEventPage.model_validate({k: v for k, v in base.items() if k != missing})


# DPoP nonces, and extension_required at an API (§3.3, §4.3) -----------------------------------


@pytest.mark.asyncio
async def test_a_company_requiring_nonces_and_the_personal_agent_retrying_with_them() -> None:
    world = World()
    world.shop.config = dataclasses.replace(world.shop.config, dpop_nonce=True)
    captured: list[httpx.Response] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        response = await original(request)
        await response.aread()
        captured.append(response)
        return response

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    session = await world.signed_out_session()
    token_endpoint = [r for r in captured if r.request.url.path == "/oauth/token"]
    # At the token endpoint: an OAuth error, HTTP 400, the nonce in DPoP-Nonce; one retry.
    assert [r.status_code for r in token_endpoint] == [400, 200]
    assert token_endpoint[0].json() == {"error": "use_dpop_nonce"}
    assert token_endpoint[0].headers["dpop-nonce"]
    # At an API: HTTP 401 with the DPoP challenge and DPoP-Nonce; one retry.
    with pytest.raises(ApiError) as raised:
        await ApiClient(transport=world.transport).call("GET", ORDERS, token=session, **world.who)
    assert raised.value.code == "insufficient_scope"
    api = [r for r in captured if r.request.url.path == "/api/orders"]
    assert [r.status_code for r in api] == [401, 403]
    assert api[0].headers["www-authenticate"] == 'DPoP error="use_dpop_nonce"'
    assert api[0].headers["dpop-nonce"]
    # Device Sign-In's poll retries with the token endpoint's nonce too.
    token, _, error = await device_sign_in(world, session, "acct_ada")
    assert error is None and token is not None and token.signed_in


@pytest.mark.asyncio
async def test_extension_required_at_an_api_is_in_the_challenge() -> None:
    world = World()
    world.atlas.extensions = ()
    world.network.add(world.atlas.domain, world.atlas.website())
    session = await world.signed_out_session()
    token, _, _ = await device_sign_in(world, session, "acct_ada")
    assert token is not None
    response = await post_json(world, token, EXCHANGE, {})
    assert response.status_code == 403
    assert response.headers["www-authenticate"] == (
        'DPoP error="extension_required", extension="operations"'
    )
    with pytest.raises(ApiError) as raised:
        await ApiClient(transport=world.transport).call(
            "POST", EXCHANGE, token=token, body={}, **world.who
        )
    assert raised.value.code == "extension_required"
    assert raised.value.details == {"extension": "operations"}


@pytest.mark.asyncio
async def test_the_company_never_fetches_an_agent_on_a_private_address() -> None:
    """A URL the other party gave never reaches a loopback, private, or link-local address (§3)."""

    from personal_agent_protocol.company import CLIENT_RESOLVERS, build_company
    from personal_agent_protocol.demo.kit import AgentIdentity, InProcessNetwork
    from personal_agent_protocol.demo.manzanita import CONFIG
    from personal_agent_protocol.errors import PersonalAgentProtocolError
    from personal_agent_protocol.reactor import first_contribution

    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())

    async def resolve(host: str) -> list[str]:
        return ["10.0.0.7"] if host == atlas.domain else await network.resolve(host)

    service = build_company(CONFIG, http_client=network.client(), address_resolver=resolve)
    resolver = first_contribution(service.reactor, CLIENT_RESOLVERS, "client resolver")
    with pytest.raises(PersonalAgentProtocolError) as refused:
        await resolver.resolve(atlas.client_id)
    assert refused.value.code == "unsafe_address"
