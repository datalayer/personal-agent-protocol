# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A user with a company, both sides from this SDK, over HTTP in one process (K-06)."""

from __future__ import annotations

import dataclasses
from typing import Any

import httpx
import pytest

from personal_agent_protocol import (
    AccessToken,
    ConversationClient,
    ConversationError,
    DeviceSignInClient,
    DiscoveryClient,
    Message,
    PapSession,
    SessionClient,
    SessionHttpClient,
    generate_message_id,
)
from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
from personal_agent_protocol.company import MemoryCompanyStore, StaleConversationError
from personal_agent_protocol.conversations import StreamReconnected, TextDelta
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    ScriptedApprovals,
    ScriptedInput,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE, manzanita
from personal_agent_protocol.mediated import MEDIATED_GRANT, MediatedSignInClient
from personal_agent_protocol.models import Author, ClientMetadata
from personal_agent_protocol.operations import OperationsClient, operations_negotiated

SHOP = "https://manzanita.example"
TENANT = "atlas-demo"
PAIRWISE = "usr_ada_at_manzanita_000000"


class World:
    def __init__(self, *answers: dict[str, str], durable: bool = False) -> None:
        self.clock = MutableClock()
        self.network = InProcessNetwork()
        self.atlas = AgentIdentity(domain="atlas.example", name="Atlas")
        self.network.add(self.atlas.domain, self.atlas.website())
        # Durable: the company's state is in a store that outlives it (`restart`).
        self.store = MemoryCompanyStore(self.clock) if durable else None
        self.shop, self.plugin = manzanita(self.network, self.clock, store=self.store)
        self.http = self.network.client()
        self.host = PersonalAgentHost(
            self.atlas,
            self.clock,
            protected_input=ScriptedInput(*answers),
            approvals=ScriptedApprovals(always=True),
        )
        self.reactor = personal_agent_reactor(
            self.host, network=self.network, http_client=self.http
        )
        self.transport = SessionHttpClient(reactor=self.reactor, http_client=self.http)
        self.conversations = ConversationClient(transport=self.transport)
        #: The Session `test_company_refusals.signed_in` signed in, and its refresh token.
        self.session: PapSession | None = None
        self.refresh_reference: str | None = None

    async def mediated_grant(self, **fields: str) -> httpx.Response:
        """The Mediated Sign-In grant, as a personal agent sends it, with `fields` as given."""

        form = {
            "grant_type": MEDIATED_GRANT,
            **fields,
            **await SessionClient(
                reactor=self.reactor, http_client=self.http
            ).client_authentication(client_id=self.atlas.client_id, issuer=SHOP),
        }
        return await self.http.post(f"{SHOP}/oauth/token", data=form)

    def account_context(self) -> RefreshTokenContext:
        metadata = self.company.oauth_metadata
        assert metadata is not None
        return RefreshTokenContext(
            token_endpoint=metadata.token_endpoint,
            revocation_endpoint=metadata.revocation_endpoint,
            issuer=metadata.issuer,
            client_id=self.atlas.client_id,
            tenant_id=TENANT,
        )

    async def refreshed(self, scopes: tuple[str, ...] | None = None) -> AccessToken:
        """A new access token from the refresh token `signed_in` kept, narrowed to `scopes`."""

        assert self.refresh_reference is not None
        result = await RefreshTokenClient(reactor=self.reactor, http_client=self.http).refresh(
            self.refresh_reference, context=self.account_context(), scopes=scopes
        )
        assert result.token is not None
        return result.token

    async def signed_out_session(self):  # type: ignore[no-untyped-def]
        company = await DiscoveryClient(reactor=self.reactor, http_client=self.http).discover(
            "manzanita.example"
        )
        assert company.oauth_metadata is not None
        self.company = company
        self.who = {"tenant_id": TENANT, "issuer": company.oauth_metadata.issuer}
        return await SessionClient(reactor=self.reactor, http_client=self.http).start(
            client_id=self.atlas.client_id,
            pairwise_user_id=PAIRWISE,
            issuer=company.oauth_metadata.issuer,
            tenant_id=TENANT,
        )

    def restart(self) -> None:
        """Manzanita stops and starts again (or another replica answers) over its store."""

        self.shop, self.plugin = manzanita(self.network, self.clock, store=self.store)

    def message(self, text: str) -> Message:
        return Message(id=generate_message_id(self.reactor), author=Author(type="human"), text=text)


@pytest.mark.asyncio
async def test_a_user_and_a_company_from_question_to_confirmed_exchange() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    # A question the company can only answer for a signed-in user.
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), session=session, wait=0
    )
    kinds = [event.type for event in page.events]
    assert kinds == ["message", "state", "message", "authorization", "state"]
    assert [e for e in page.events if e.type != "state"][-1].error == "insufficient_scope"

    # Device Sign-In: the user approves on Manzanita's own page.
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    metadata = world.company.oauth_metadata
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
    world.clock.advance(started.poll_interval)
    assert (await device.poll(started.reference)).status == "pending"
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.token is not None
    signed_in = done.token
    assert signed_in.scopes == ("orders:read", "orders:write")

    # The same conversation continues, signed in.
    page = await world.conversations.send(
        endpoint,
        page.conversation_id,
        world.message("Exchange it for something warmer"),
        session=session,
        token=signed_in,
        cursor=page.cursor,
        wait=0,
    )
    proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    assert proposal is not None

    # The user approves exactly this revision; it is performed once.
    client_metadata = ClientMetadata.model_validate(world.atlas.metadata)
    assert operations_negotiated(world.company.document, client_metadata)
    approval = await OperationsClient(reactor=world.reactor).ask_user(
        proposal, organization=world.company.document.organization, tenant_id=TENANT
    )
    assert world.host.approvals.asked[-1].summary == proposal.summary  # type: ignore[union-attr]

    async def approved() -> Any:
        return await world.conversations.send(
            endpoint,
            page.conversation_id,
            Message(
                id=generate_message_id(world.reactor),
                author=Author(type="agent"),
                approval=approval,
            ),
            session=session,
            token=signed_in,
            wait=0,
        )

    outcome = await approved()
    told = [e.message for e in outcome.events if e.message is not None][-1]
    assert told.text.startswith("Exchanged the Ridge Jacket")
    await approved()
    assert world.plugin.executor.performed == [proposal.operation_id]

    # The Account Token: narrower refresh, then revocation signs the Session out.
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    context = RefreshTokenContext(
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        revocation_endpoint=metadata.revocation_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
    )
    narrowed = await accounts.refresh(
        done.refresh_token_reference,
        context=context,  # type: ignore[arg-type]
        scopes=("orders:read",),
    )
    assert narrowed.status == "signed_in" and narrowed.rotated
    assert narrowed.granted_scopes == ("orders:read",)
    wider = await accounts.refresh(
        done.refresh_token_reference,
        context=context,  # type: ignore[arg-type]
        scopes=("orders:read", "orders:admin"),
    )
    assert wider.status == "re_consent_required"
    revoked = await accounts.revoke(done.refresh_token_reference, context=context)  # type: ignore[arg-type]
    assert revoked.revoked
    after = await accounts.refresh(
        done.refresh_token_reference,
        context=context,  # type: ignore[arg-type]
    )
    assert after.status == "signed_out"


@pytest.mark.asyncio
async def test_mediated_sign_in_with_a_one_time_code() -> None:
    world = World(dict(ADA), {"code": "000000"}, {"code": ADA_CODE})
    session = await world.signed_out_session()
    mediated = MediatedSignInClient(reactor=world.reactor, http_client=world.http)
    started = await mediated.sign_in(
        company=world.company, client_id=session.client_id, scopes=("orders:read",)
    )
    assert started.status == "code_required" and started.sent_to == "a•••@example.com"
    wrong = await mediated.submit_code(started.reference)  # type: ignore[arg-type]
    assert wrong.status == "code_required"
    done = await mediated.submit_code(started.reference)  # type: ignore[arg-type]
    assert done.status == "complete" and done.granted_scopes == ("orders:read",)
    assert [request.purpose for request in world.host.protected_input.asked] == [
        "credentials",
        "one_time_code",
        "one_time_code",
    ]


@pytest.mark.asyncio
async def test_the_conversation_streams_and_a_stranger_cannot_read_it() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Hello"), session=session, wait=0
    )
    await world.conversations.close(endpoint, page.conversation_id, session=session)
    items = [
        item
        async for item in world.conversations.stream(
            endpoint, page.conversation_id, session=session
        )
    ]
    deltas = [item for item in items if isinstance(item, TextDelta)]
    events = [item for item in items if not isinstance(item, TextDelta | StreamReconnected)]
    assert deltas and all(delta.actionable is False for delta in deltas)
    assert events[-1].type == "state" and events[-1].status == "closed"

    other = await SessionClient(reactor=world.reactor, http_client=world.http).start(
        client_id=world.atlas.client_id,
        pairwise_user_id="usr_somebody_else_000000",
        issuer=session.issuer,
        tenant_id=TENANT,
    )
    with pytest.raises(ConversationError) as raised:
        await world.conversations.read_events(
            endpoint,
            page.conversation_id,
            session=other,
        )
    assert raised.value.code == "conversation_not_found"


def test_a_demo_reactor_stops_cleanly() -> None:
    world = World()
    world.reactor.stop()


@pytest.mark.asyncio
async def test_one_of_the_companys_people_answers_over_what_they_read() -> None:
    world = World()
    world.shop.config = dataclasses.replace(world.shop.config, humans_available=True)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Hello"), session=session, wait=0
    )
    conversation_id = page.conversation_id
    read = await world.shop.conversation_record(conversation_id)
    with pytest.raises(ValueError, match="not handed"):
        await world.shop.staff_reply(conversation_id, after=read.events[-1].id, text="Marta here.")

    await world.conversations.handoff(endpoint, conversation_id, session=session)
    read = await world.shop.conversation_record(conversation_id)
    assert read.responder == "human"
    took = await world.shop.staff_reply(
        conversation_id, after=read.events[-1].id, text="Marta here."
    )
    assert took.message is not None
    assert (took.message.author.type, took.message.role) == ("human", "company")

    # The person writes while Marta answers from what she read before: hers is refused.
    await world.conversations.send(
        endpoint, conversation_id, world.message("Is it shipped?"), session=session
    )
    with pytest.raises(StaleConversationError):
        await world.shop.staff_reply(conversation_id, after=took.id, text="Anything else?")
    read = await world.shop.conversation_record(conversation_id)
    answered = await world.shop.staff_reply(
        conversation_id, after=read.events[-1].id, text="It is.", data={"order_id": "ord_7Hk2"}
    )

    seen = await world.conversations.read_events(endpoint, conversation_id, session=session)
    written = [
        (event.message.author.type, event.message.role, event.message.text)
        for event in seen.events
        if event.type == "message" and event.message is not None
    ]
    assert written[-3:] == [
        ("human", "company", "Marta here."),
        ("human", "user", "Is it shipped?"),
        ("human", "company", "It is."),
    ]
    assert seen.events[-1].id == answered.id
    assert (seen.status, seen.responder) == ("idle", "human")

    await world.conversations.close(endpoint, conversation_id, session=session)
    read = await world.shop.conversation_record(conversation_id)
    with pytest.raises(ValueError, match="closed"):
        await world.shop.staff_reply(conversation_id, after=read.events[-1].id, text="Bye.")
    with pytest.raises(ValueError, match="says something"):
        await world.shop.staff_reply(conversation_id, after=read.events[-1].id)
    with pytest.raises(KeyError):
        await world.shop.staff_reply("cnv_nobody", after="evt_none", text="Hello?")
