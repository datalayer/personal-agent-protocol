# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A user with a company, both sides from this SDK, over HTTP in one process (K-06)."""

from __future__ import annotations

import pytest

from personal_agent_protocol import (
    ConversationClient,
    ConversationError,
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.company import MemoryCompanyStore
from personal_agent_protocol.conversations import StreamReconnected, TextDelta
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    ScriptedInput,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE, manzanita
from personal_agent_protocol.mediated import MediatedSignInClient
from personal_agent_protocol.models import ClientMetadata
from personal_agent_protocol.operations import OperationsClient, approve, operations_endpoint

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
            self.atlas, self.clock, protected_input=ScriptedInput(*answers)
        )
        self.reactor = personal_agent_reactor(
            self.host, network=self.network, http_client=self.http
        )
        self.transport = DpopHttpClient(reactor=self.reactor, http_client=self.http)
        self.conversations = ConversationClient(transport=self.transport)

    async def signed_out_session(self):  # type: ignore[no-untyped-def]
        company = await DiscoveryClient(reactor=self.reactor, http_client=self.http).discover(
            "manzanita.example"
        )
        assert company.oauth_metadata is not None
        self.company = company
        self.who = {
            "tenant_id": TENANT,
            "pairwise_user_id": PAIRWISE,
            "issuer": company.oauth_metadata.issuer,
        }
        return await SessionClient(reactor=self.reactor, http_client=self.http).start(
            client_id=self.atlas.client_id,
            pairwise_user_id=PAIRWISE,
            issuer=company.oauth_metadata.issuer,
            token_endpoint=company.oauth_metadata.token_endpoint,
            tenant_id=TENANT,
        )

    def restart(self) -> None:
        """Manzanita stops and starts again (or another replica answers) over its store."""

        self.shop, self.plugin = manzanita(self.network, self.clock, store=self.store)

    def message(self, text: str) -> Message:
        return Message(id=generate_message_id(self.reactor), sender="human", text=text)


@pytest.mark.asyncio
async def test_a_user_and_a_company_from_question_to_confirmed_exchange() -> None:
    world = World()
    session = await world.signed_out_session()
    assert session.signed_in is False
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    # A question the company can only answer for a signed-in user.
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), token=session, wait=0, **world.who
    )
    kinds = [event.type for event in page.events]
    assert kinds == ["message", "state", "message", "authorization", "state"]
    assert [e for e in page.events if e.type != "state"][-1].error == "sign_in_required"

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
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    world.clock.advance(started.poll_interval)
    assert (await device.poll(started.reference)).status == "pending"
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.token is not None
    signed_in = done.token
    assert signed_in.signed_in and signed_in.session_id == session.session_id

    # The same conversation continues, signed in.
    page = await world.conversations.send(
        endpoint,
        page.conversation_id,
        world.message("Exchange it for something warmer"),
        token=signed_in,
        cursor=page.cursor,
        wait=0,
        **world.who,
    )
    proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    assert proposal is not None and proposal.state == "proposed"

    # The user approves exactly this revision; it is confirmed once.
    client_metadata = ClientMetadata.model_validate(world.atlas.metadata)
    ops_endpoint = operations_endpoint(world.company.document, client_metadata)
    assert ops_endpoint is not None
    operations = OperationsClient(transport=world.transport)
    outcome = await operations.confirm(
        ops_endpoint, proposal, approval=approve(proposal), token=signed_in, **world.who
    )
    assert outcome.status == "confirmed"
    assert outcome.operation.state == "succeeded"  # type: ignore[union-attr]
    assert outcome.operation.result.summary.startswith("Exchanged the Ridge Jacket")  # type: ignore[union-attr]
    again = await operations.confirm(
        ops_endpoint, proposal, approval=approve(proposal), token=signed_in, **world.who
    )
    assert again.operation.state == "succeeded"  # type: ignore[union-attr]
    assert world.plugin.executor.performed == [proposal.operation_id]

    # The Account Token: narrower refresh, then revocation signs the Session out.
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    context = AccountTokenContext(
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        revocation_endpoint=metadata.revocation_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )
    narrowed = await accounts.refresh(
        done.account_token_reference,
        context=context,  # type: ignore[arg-type]
        session_id=session.session_id,
        scopes=("orders:read",),
    )
    assert narrowed.status == "signed_in" and narrowed.rotated
    assert narrowed.granted_scopes == ("orders:read",)
    wider = await accounts.refresh(
        done.account_token_reference,
        context=context,  # type: ignore[arg-type]
        session_id=session.session_id,
        scopes=("orders:read", "orders:admin"),
    )
    assert wider.status == "re_consent_required"
    revoked = await accounts.revoke(done.account_token_reference, context=context)  # type: ignore[arg-type]
    assert revoked.revoked
    after = await accounts.refresh(
        done.account_token_reference,
        context=context,
        session_id=session.session_id,  # type: ignore[arg-type]
    )
    assert after.status == "signed_out"


@pytest.mark.asyncio
async def test_mediated_sign_in_with_a_one_time_code() -> None:
    world = World(dict(ADA), {"code": "000000"}, {"code": ADA_CODE})
    session = await world.signed_out_session()
    auth = world.company.document.auth
    mediated = MediatedSignInClient(reactor=world.reactor, http_client=world.http)
    started = await mediated.sign_in(
        mediated=auth.mediated,  # type: ignore[union-attr,arg-type]
        organization=world.company.document.organization,
        issuer=auth.issuer,  # type: ignore[union-attr]
        scopes=("orders:read",),
        token=session,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )
    assert started.status == "code_required" and started.sent_to == "a•••@example.com"
    wrong = await mediated.submit_code(started.reference, token=session, **world.who)  # type: ignore[arg-type]
    assert wrong.status == "code_required"
    done = await mediated.submit_code(started.reference, token=session, **world.who)  # type: ignore[arg-type]
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
        endpoint, world.message("Hello"), token=session, wait=0, **world.who
    )
    await world.conversations.close(endpoint, page.conversation_id, token=session, **world.who)
    items = [
        item
        async for item in world.conversations.stream(
            endpoint, page.conversation_id, token=session, **world.who
        )
    ]
    deltas = [item for item in items if isinstance(item, TextDelta)]
    events = [item for item in items if not isinstance(item, TextDelta | StreamReconnected)]
    assert deltas and all(delta.actionable is False for delta in deltas)
    assert events[-1].type == "state" and events[-1].status == "closed"

    other = await SessionClient(reactor=world.reactor, http_client=world.http).start(
        client_id=world.atlas.client_id,
        pairwise_user_id="usr_somebody_else_000000",
        issuer=world.who["issuer"],
        token_endpoint=world.company.oauth_metadata.token_endpoint,  # type: ignore[union-attr]
        tenant_id=TENANT,
    )
    with pytest.raises(ConversationError) as raised:
        await world.conversations.read_events(
            endpoint,
            page.conversation_id,
            token=other,
            tenant_id=TENANT,
            pairwise_user_id="usr_somebody_else_000000",
            issuer=world.who["issuer"],
        )
    assert raised.value.code == "conversation_not_found"


def test_a_demo_reactor_stops_cleanly() -> None:
    world = World()
    world.reactor.stop()
