# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Two companies working together (K-07): Ledgerly acts for Ada at Northwind Bank."""

from __future__ import annotations

import pytest

from personal_agent_protocol import (
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.ledgerly import ledgerly
from personal_agent_protocol.demo.northwind import ACCOUNT, northwind
from personal_agent_protocol.operations import OperationsClient, approve

TENANT = "atlas-demo"
PAIRWISE = "usr_ada_at_ledgerly_00000000"


@pytest.mark.asyncio
async def test_ledgerly_pays_at_northwind_for_ada_with_her_approval_then_within_her_bounds() -> (
    None
):
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    bank, bank_plugin = northwind(network, clock)
    firm, _ = ledgerly(network, clock)

    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    transport = DpopHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)
    operations = OperationsClient(transport=transport)

    # Atlas signs Ada in to Ledgerly (Device Sign-In on Ledgerly's page).
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover("ledgerly.example")
    metadata = company.oauth_metadata
    assert metadata is not None
    who = {"tenant_id": TENANT, "pairwise_user_id": PAIRWISE, "issuer": metadata.issuer}
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=TENANT,
    )
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("books:read", "payments:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    await firm.approve_device(started.user_code, account_id="acct_ada_ledgerly")
    clock.advance(started.poll_interval)
    token = (await device.poll(started.reference)).token
    assert token is not None and token.signed_in

    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    ops = firm.config.operations_endpoint

    def say(text: str) -> Message:
        return Message(id=generate_message_id(reactor), sender="human", text=text)

    # 1. Ledgerly is not yet connected to Northwind: Ada approves it on Northwind's page.
    page = await conversations.start(endpoint, say("Pay INV-0042"), token=token, wait=0, **who)
    connect = page.events[-1].message.data["connect"]  # type: ignore[union-attr,index]
    assert connect["verification_uri"] == "https://northwind.example/device"
    await bank.approve_device(connect["user_code"], account_id=ACCOUNT)
    clock.advance(5)

    # 2. Northwind's proposal comes back as a Ledgerly operation, quoting it as written.
    page = await conversations.send(
        endpoint,
        page.conversation_id,
        say("Done. Pay INV-0042"),
        token=token,
        cursor=page.cursor,
        wait=0,
        **who,
    )
    relayed = page.events[-1].message.operation  # type: ignore[union-attr]
    assert relayed is not None and relayed.user_approval_required
    assert relayed.summary.startswith(
        "At Northwind Bank: Pay EUR 1250.00 to Acme GmbH for INV-0042"
    )
    assert bank_plugin.executor.performed == []

    # 3. Ada approves in Atlas; Ledgerly confirms that exact revision at Northwind.
    paid = await operations.confirm(ops, relayed, approval=approve(relayed), token=token, **who)
    assert paid.operation.state == "succeeded"  # type: ignore[union-attr]
    assert paid.operation.result.summary.startswith(  # type: ignore[union-attr]
        "Northwind Bank: Sent EUR 1250.00 to Acme GmbH for INV-0042"
    )
    assert len(bank_plugin.executor.performed) == 1
    bank_record = (await bank.operation_record(bank_plugin.executor.performed[0])).operation
    assert bank_record.confirmation.approved_by == "user"  # type: ignore[union-attr]

    # 4. Ada grants a bounded standing permission, itself an operation she approves.
    page = await conversations.send(
        endpoint,
        page.conversation_id,
        say("Allow Ledgerly to pay Acme invoices up to EUR 2000 without asking"),
        token=token,
        cursor=page.cursor,
        wait=0,
        **who,
    )
    grant = page.events[-1].message.operation  # type: ignore[union-attr]
    granted = await operations.confirm(ops, grant, approval=approve(grant), token=token, **who)  # type: ignore[arg-type]
    assert granted.operation.state == "succeeded"  # type: ignore[union-attr]

    # 5. Within the bounds: paid under the standing permission, Ada told what was done.
    page = await conversations.send(
        endpoint,
        page.conversation_id,
        say("Pay INV-0043"),
        token=token,
        cursor=page.cursor,
        wait=0,
        **who,
    )
    told = page.events[-1].message  # type: ignore[union-attr]
    assert told.operation is None  # type: ignore[union-attr]
    assert "Sent EUR 980.00 to Acme GmbH for INV-0043" in told.text  # type: ignore[union-attr,operator]
    second = (await bank.operation_record(bank_plugin.executor.performed[1])).operation
    assert second.confirmation.approved_by == "standing_permission"  # type: ignore[union-attr]

    # 6. Beyond the bounds: Ada is asked again.
    page = await conversations.send(
        endpoint,
        page.conversation_id,
        say("Pay INV-0044"),
        token=token,
        cursor=page.cursor,
        wait=0,
        **who,
    )
    over = page.events[-1].message.operation  # type: ignore[union-attr]
    assert over is not None and "EUR 3400.00" in over.summary
    assert len(bank_plugin.executor.performed) == 2
