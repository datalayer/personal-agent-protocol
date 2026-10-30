# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The reference company's rules of draft 0.3, each with the personal agent's view of it.

A Session signed in on each request, by whichever account's token it carries (§5.4);
what continues after sign-out (§5.5, Operations 3); the Mediated Sign-In extension's
statuses and errors; conversation requests (§8.2 to §8.13); a new Session in place of
one that ended (§5.5); `extension_required` at an API (§3.3).
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import httpx
import pytest

from personal_agent_protocol import (
    AccessToken,
    AuthorizationError,
    ConversationError,
    DeviceSignInClient,
    DiscoveryClient,
    Message,
    SessionClient,
)
from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
from personal_agent_protocol.apis import ApiClient, ApiError
from personal_agent_protocol.company import SignInRefused
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    PersonalAgentHost,
    ScriptedInput,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE, manzanita
from personal_agent_protocol.demo.manzanita import CONFIG as MANZANITA
from personal_agent_protocol.mediated import (
    MEDIATED_GRANT,
    MediatedSignInClient,
    mediated_sign_in,
)
from personal_agent_protocol.models import Approval, Author, ConversationEventPage
from personal_agent_protocol.sessions import PapSession

from .test_company_end_to_end import TENANT, World

ORDERS = "https://manzanita.example/api/orders"
EXCHANGE = "https://manzanita.example/api/orders/ord_7Hk2/exchanges"


def context(world: World) -> RefreshTokenContext:
    metadata = world.company.oauth_metadata
    assert metadata is not None
    return RefreshTokenContext(
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        revocation_endpoint=metadata.revocation_endpoint,
    )


async def device_sign_in(
    world: World, account_id: str
) -> tuple[AccessToken | None, str | None, AuthorizationError | None]:
    """Device Sign-In, the user approving as `account_id`: it names no Session (§5.4)."""

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
    return done.token, done.refresh_token_reference, None


async def post_json(
    world: World, session: PapSession, url: str, body: Any, token: AccessToken | None = None
) -> httpx.Response:
    return await world.transport.request(
        "POST",
        url,
        session=session,
        token=token,
        headers={"Content-Type": "application/json"},
        content=json.dumps(body).encode(),
    )


# A Session is signed in on each request (§5.4) ---------------------------------------------


@pytest.mark.asyncio
async def test_a_signed_out_session_can_use_another_accounts_token() -> None:
    """A company never refuses an account change in a Session (§5.4: a MAY it doesn't take)."""

    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    ada, reference, _ = await device_sign_in(world, "acct_ada")
    assert ada is not None and reference is not None
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), session=session, token=ada, wait=0
    )
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    await accounts.revoke(reference, context=context(world))

    # The same Session, signed out since, signs in to acct_bob.
    bob, bob_reference, refused = await device_sign_in(world, "acct_bob")
    assert refused is None and bob is not None and bob_reference is not None
    answer = await ApiClient(transport=world.transport).call(
        "GET", ORDERS, session=session, token=bob
    )
    assert answer.status == 200

    # What used acct_ada stays hers: under acct_bob's token it does not exist.
    with pytest.raises(ConversationError) as hidden:
        await world.conversations.read_events(
            endpoint, page.conversation_id, session=session, token=bob
        )
    assert hidden.value.code == "conversation_not_found"

    # The same account is welcome back.
    back, _, none = await device_sign_in(world, "acct_ada")
    assert none is None and back is not None
    again = await world.conversations.read_events(
        endpoint, page.conversation_id, session=session, token=back
    )
    assert again.conversation_id == page.conversation_id


@pytest.mark.asyncio
async def test_mediated_sign_in_in_a_session_another_account_used_signs_in() -> None:
    world = World(dict(ADA), {"code": ADA_CODE})
    session = await world.signed_out_session()
    _, reference, _ = await device_sign_in(world, "acct_bob")
    assert reference is not None
    await RefreshTokenClient(reactor=world.reactor, http_client=world.http).revoke(
        reference, context=context(world)
    )
    mediated = MediatedSignInClient(reactor=world.reactor, http_client=world.http)
    started = await mediated.sign_in(
        company=world.company, client_id=session.client_id, scopes=("orders:read",)
    )
    assert started.status == "code_required" and started.reference is not None
    done = await mediated.submit_code(started.reference)
    assert done.status == "complete" and done.token is not None
    # The host asked for the credentials naming the company and its issuer (Mediated Sign-In).
    asked = world.host.protected_input.asked[0]
    assert (asked.company_name, asked.company_domain, asked.issuer) == (
        "Manzanita Outfitters",
        "manzanita.example",
        "https://manzanita.example",
    )


# After sign-out (§5.5, §8.11, Operations 3) --------------------------------------------


@pytest.mark.asyncio
async def test_after_sign_out_what_used_the_account_stays_and_asks_for_sign_in() -> None:
    world = World()
    session = await world.signed_out_session()
    token, reference, _ = await device_sign_in(world, "acct_ada")
    assert token is not None and reference is not None
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), session=session, token=token, wait=0
    )
    proposed = await ApiClient(transport=world.transport).call(
        "POST", EXCHANGE, session=session, token=token, body={}
    )
    assert proposed.operation is not None
    await RefreshTokenClient(reactor=world.reactor, http_client=world.http).revoke(
        reference, context=context(world)
    )
    # The sign-in's access tokens went with it: the agent finds out, and goes on signed out.
    with pytest.raises(ConversationError) as revoked:
        await world.conversations.read_events(
            endpoint, page.conversation_id, session=session, token=token
        )
    assert (revoked.value.code, revoked.value.status_code) == ("invalid_token", 401)
    # The conversation stays open, and a request on it without a token gets the challenge.
    record = await world.shop.conversation_record(page.conversation_id)
    assert record.status != "closed"
    with pytest.raises(ConversationError) as read:
        await world.conversations.read_events(endpoint, page.conversation_id, session=session)
    assert (read.value.code, read.value.status_code) == ("insufficient_scope", 401)
    # The operation belongs to the account: signed out, the same Session is asked to sign in.
    api = ApiClient(transport=world.transport)
    operation = proposed.operation
    approval = Approval(operation_id=operation.operation_id, revision=operation.revision)
    with pytest.raises(ApiError) as op:
        await api.call("POST", EXCHANGE, session=session, body={}, approval=approval)
    assert (op.value.code, op.value.status_code) == ("insufficient_scope", 401)
    # Signed in again to the same account, the Session continues both.
    back, _, _ = await device_sign_in(world, "acct_ada")
    assert back is not None
    again = await world.conversations.read_events(
        endpoint, page.conversation_id, session=session, token=back
    )
    assert again.conversation_id == page.conversation_id
    # Another account never learns it exists: as if the approval weren't there.
    stranger = await world.signed_out_session()
    bob, _, _ = await device_sign_in(world, "acct_bob")
    assert bob is not None
    hidden = await api.call(
        "POST", EXCHANGE, session=stranger, token=bob, body={}, approval=approval
    )
    assert hidden.operation is not None and hidden.operation.operation_id != operation.operation_id
    assert world.plugin.executor.performed == []
    done = await api.call("POST", EXCHANGE, session=session, token=back, body={}, approval=approval)
    assert done.status == 200
    assert world.plugin.executor.performed == [operation.operation_id]


# Mediated Sign-In's errors --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_failed_or_expired_mediated_sign_in_stays_so_and_unknown_is_invalid_grant() -> None:
    world = World()
    await world.signed_out_session()
    started = await world.mediated_grant(**ADA, scope="orders:read")
    assert started.status_code == 400 and started.json()["error"] == "code_required"
    assert started.json()["sent_to"] == "a•••@example.com"
    assert started.json()["expires_in"] == 300
    sign_in_id = started.json()["sign_in_id"]
    errors = []
    for _ in range(4):
        answer = await world.mediated_grant(sign_in_id=sign_in_id, one_time_code="000000")
        assert answer.status_code == 400
        errors.append(answer.json()["error"])
    assert errors == ["code_required", "code_required", "invalid_grant", "invalid_grant"]
    # Even the right code: once failed, the same error again.
    right = await world.mediated_grant(sign_in_id=sign_in_id, one_time_code=ADA_CODE)
    assert (right.status_code, right.json()) == (400, {"error": "invalid_grant"})

    started = await world.mediated_grant(**ADA, scope="orders:read")
    expiring = started.json()["sign_in_id"]
    world.clock.advance(6 * 60)
    for _ in range(2):
        answer = await world.mediated_grant(sign_in_id=expiring, one_time_code=ADA_CODE)
        assert (answer.status_code, answer.json()) == (400, {"error": "expired_token"})

    missing = await world.mediated_grant(sign_in_id="sgn_unknown", one_time_code=ADA_CODE)
    assert (missing.status_code, missing.json()) == (400, {"error": "invalid_grant"})
    unknown_scope = await world.mediated_grant(**ADA, scope="orders:everything")
    assert (unknown_scope.status_code, unknown_scope.json()) == (400, {"error": "invalid_scope"})


@pytest.mark.asyncio
async def test_only_the_client_that_started_a_mediated_sign_in_can_finish_it() -> None:
    world = World()
    await world.signed_out_session()
    started = (await world.mediated_grant(**ADA, scope="orders:read")).json()
    other = AgentIdentity(domain="other.example", name="Other")
    world.network.add(other.domain, other.website())
    sessions = SessionClient(
        reactor=personal_agent_reactor(
            PersonalAgentHost(other, world.clock), network=world.network, http_client=world.http
        ),
        http_client=world.http,
    )
    answer = await world.http.post(
        "https://manzanita.example/oauth/token",
        data={
            "grant_type": MEDIATED_GRANT,
            "sign_in_id": started["sign_in_id"],
            "one_time_code": ADA_CODE,
            **await sessions.client_authentication(
                client_id=other.client_id, issuer="https://manzanita.example"
            ),
        },
    )
    assert (answer.status_code, answer.json()) == (400, {"error": "invalid_grant"})
    finished = await world.mediated_grant(sign_in_id=started["sign_in_id"], one_time_code=ADA_CODE)
    assert finished.status_code == 200 and finished.json()["refresh_token"]


@pytest.mark.asyncio
async def test_a_mediated_continuation_takes_no_credentials_or_scope() -> None:
    world = World()
    await world.signed_out_session()
    started = (await world.mediated_grant(**ADA, scope="orders:read")).json()
    for extra in ({"scope": "orders:write"}, {"password": ADA["password"]}):
        answer = await world.mediated_grant(
            sign_in_id=started["sign_in_id"], one_time_code=ADA_CODE, **extra
        )
        assert (answer.status_code, answer.json()) == (400, {"error": "invalid_request"})
    no_code = await world.mediated_grant(sign_in_id=started["sign_in_id"])
    assert (no_code.status_code, no_code.json()) == (400, {"error": "invalid_request"})
    # A missing field of the first request is the same.
    missing = await world.mediated_grant(email=ADA["email"], scope="orders:read")
    assert (missing.status_code, missing.json()) == (400, {"error": "invalid_request"})


@pytest.mark.asyncio
async def test_the_company_grants_only_the_extensions_scopes() -> None:
    config = dataclasses.replace(MANZANITA, mediated_scopes=("orders:read",))
    world = World()
    world.shop, world.plugin = manzanita(world.network, world.clock, config=config)
    company = await DiscoveryClient(reactor=world.reactor, http_client=world.http).discover(
        "manzanita.example"
    )
    assert mediated_sign_in(company).scopes == ["orders:read"]  # type: ignore[union-attr]
    refused = await world.mediated_grant(**ADA, scope="orders:read orders:write")
    assert (refused.status_code, refused.json()) == (400, {"error": "invalid_scope"})


@pytest.mark.asyncio
async def test_a_company_can_refuse_a_mediated_sign_in_with_access_denied() -> None:
    world = World()
    await world.signed_out_session()

    async def refuse(credentials: object, context: object) -> None:
        raise SignInRefused

    world.plugin.accounts.authenticate = refuse  # type: ignore[method-assign,assignment]
    answer = await world.mediated_grant(**ADA, scope="orders:read")
    assert (answer.status_code, answer.json()) == (400, {"error": "access_denied"})


@pytest.mark.asyncio
async def test_an_extension_used_by_the_request_needs_no_client_metadata_entry() -> None:
    """Plain lists no extension: the grant type says it uses Mediated Sign-In (§3.3)."""

    world = World()
    plain = AgentIdentity(domain="plain.example", name="Plain", extensions=())
    world.network.add(plain.domain, plain.website())
    assert plain.metadata["extensions"] == {}
    reactor = personal_agent_reactor(
        PersonalAgentHost(
            plain, world.clock, protected_input=ScriptedInput(dict(ADA), {"code": ADA_CODE})
        ),
        network=world.network,
        http_client=world.http,
    )
    company = await DiscoveryClient(reactor=reactor, http_client=world.http).discover(
        "manzanita.example"
    )
    client = MediatedSignInClient(reactor=reactor, http_client=world.http)
    started = await client.sign_in(
        company=company, client_id=plain.client_id, scopes=("orders:read",)
    )
    assert started.status == "code_required"
    done = await client.submit_code(started.reference)  # type: ignore[arg-type]
    assert done.status == "complete"
    # The company lists the grant and the extension, and no such refusal exists for it.
    assert MEDIATED_GRANT in company.oauth_metadata.grant_types_supported  # type: ignore[union-attr]
    assert "mediated-sign-in" in company.document.extensions


def test_a_company_cannot_publish_a_reserved_mediated_field() -> None:
    with pytest.raises(ValueError, match="reserved"):
        dataclasses.replace(MANZANITA, mediated_fields=(("client_id", "Client", False),))
    with pytest.raises(ValueError, match="mediated_scopes"):
        dataclasses.replace(MANZANITA, mediated_scopes=("nothing:here",))


# Conversation requests (§8.2 to §8.13) -----------------------------------------------------


@pytest.mark.asyncio
async def test_wait_is_a_whole_number_of_seconds_and_a_larger_one_is_capped() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Hello"), session=session, wait=0
    )
    events = f"{endpoint}/{page.conversation_id}/events"
    for wait in ("-1", "1.5", "soon", "", "\u0661"):
        refused = await world.transport.request("GET", f"{events}?wait={wait}", session=session)
        assert (refused.status_code, refused.json()) == (400, {"error": "invalid_request"}), wait
    capped = await world.conversations.read_events(
        endpoint, page.conversation_id, session=session, wait=86_400
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
    # An ID with characters not allowed is malformed, not unknown (§8.2).
    odd = await world.transport.request("GET", f"{endpoint}/cnv.bad/events", session=session)
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
    only_context = Message(
        id="msg_only_ctx", author=Author(type="agent"), context={"user_available": True}
    )
    answer = await world.conversations.send(
        endpoint,
        page.conversation_id,
        only_context,
        session=session,
        cursor=page.cursor,
        wait=0,
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
            session=session,
        )


@pytest.mark.asyncio
async def test_repeated_handoff_and_close_change_nothing() -> None:
    world = World()
    world.shop.config = dataclasses.replace(world.shop.config, humans_available=True)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("A person, please"), session=session, wait=0
    )
    first = await world.conversations.handoff(endpoint, page.conversation_id, session=session)
    assert first.responder == "human"
    count = len((await world.shop.conversation_record(page.conversation_id)).events)
    again = await world.conversations.handoff(endpoint, page.conversation_id, session=session)
    assert (again.status, again.responder) == (first.status, first.responder)
    assert len((await world.shop.conversation_record(page.conversation_id)).events) == count
    closed = await world.conversations.close(endpoint, page.conversation_id, session=session)
    count = len((await world.shop.conversation_record(page.conversation_id)).events)
    closed_again = await world.conversations.close(endpoint, page.conversation_id, session=session)
    assert closed_again == closed and closed.status == "closed"
    assert len((await world.shop.conversation_record(page.conversation_id)).events) == count


@pytest.mark.asyncio
async def test_last_event_id_wins_over_cursor_on_a_stream() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Hello"), session=session, wait=0
    )
    await world.conversations.close(endpoint, page.conversation_id, session=session)
    ids = [event.id for event in page.events]
    response = await world.transport.request(
        "GET",
        f"{endpoint}/{page.conversation_id}/events?cursor={ids[0]}",
        session=session,
        headers={"Accept": "text/event-stream", "Last-Event-ID": ids[-1]},
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


# A new Session once, and extension_required at an API (§3.3, §5.5) ---------------------------


@pytest.mark.asyncio
async def test_a_company_ending_a_session_and_the_personal_agent_starting_a_new_one() -> None:
    world = World()
    captured: list[httpx.Response] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        response = await original(request)
        await response.aread()
        captured.append(response)
        return response

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    session = await world.signed_out_session()
    ended = session.sid
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    await world.conversations.start(endpoint, world.message("Hello"), session=session, wait=0)
    assert await world.shop.end_session(session.client_id, ended)
    captured.clear()

    # `invalid_session`, HTTP 400, JSON; the request sent once more with a new `sid`.
    await world.conversations.start(endpoint, world.message("Hello"), session=session, wait=0)
    assert [r.status_code for r in captured] == [400, 201]
    assert captured[0].json() == {"error": "invalid_session"}
    assert session.sid != ended


@pytest.mark.asyncio
async def test_extension_required_at_an_api_is_in_the_challenge() -> None:
    world = World()
    world.atlas.extensions = ()
    world.network.add(world.atlas.domain, world.atlas.website())
    session = await world.signed_out_session()
    token, _, _ = await device_sign_in(world, "acct_ada")
    assert token is not None
    response = await post_json(world, session, EXCHANGE, {}, token=token)
    assert response.status_code == 403
    assert response.headers["www-authenticate"] == (
        'Bearer error="extension_required", extension="operations"'
    )
    with pytest.raises(ApiError) as raised:
        await ApiClient(transport=world.transport).call(
            "POST", EXCHANGE, session=session, token=token, body={}
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
