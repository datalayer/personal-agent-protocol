# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Two companies working together: Ledgerly acts for Ada at Northwind Bank."""

from __future__ import annotations

from typing import Any

import pytest

from personal_agent_protocol import (
    Author,
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    Message,
    SessionClient,
    SessionHttpClient,
    generate_message_id,
)
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    ScriptedApprovals,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.ledgerly import ledgerly
from personal_agent_protocol.demo.northwind import ACCOUNT, northwind
from personal_agent_protocol.operations import OperationsClient

TENANT = "atlas-demo"
PAIRWISE = "usr_ada_at_ledgerly_00000000"


@pytest.mark.asyncio
async def test_ledgerly_pays_at_northwind_for_ada_asking_her_about_every_payment() -> None:
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    bank, bank_plugin = northwind(network, clock)
    firm, _ = ledgerly(network, clock)

    http = network.client()
    host = PersonalAgentHost(atlas, clock, approvals=ScriptedApprovals(always=True))
    reactor = personal_agent_reactor(host, network=network, http_client=http)
    transport = SessionHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)
    operations = OperationsClient(reactor=reactor)

    # Atlas signs Ada in to Ledgerly (Device Sign-In on Ledgerly's page).
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover("ledgerly.example")
    metadata = company.oauth_metadata
    assert metadata is not None
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
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
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await firm.approve_device(started.user_code, account_id="acct_ada_ledgerly")
    clock.advance(started.poll_interval)
    token = (await device.poll(started.reference)).token
    assert token is not None

    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    def say(text: str) -> Message:
        return Message(id=generate_message_id(reactor), author=Author(type="human"), text=text)

    # 1. Ledgerly is not yet connected to Northwind: Ada approves it on Northwind's page.
    page = await conversations.start(
        endpoint, say("Pay INV-0042"), session=session, token=token, wait=0
    )
    connect = [e for e in page.events if e.type != "state"][-1].message.data["connect"]  # type: ignore[union-attr,index]
    assert connect["verification_uri"] == "https://northwind.example/device"
    await bank.approve_device(connect["user_code"], account_id=ACCOUNT)
    clock.advance(5)

    # 2. Northwind's operation comes back as a Ledgerly operation, quoting it as written.
    async def pay(invoice: str, conversation_page: Any) -> Any:
        return await conversations.send(
            endpoint,
            conversation_page.conversation_id,
            say(f"Done. Pay {invoice}"),
            session=session,
            token=token,
            cursor=conversation_page.cursor,
            wait=0,
        )

    page = await pay("INV-0042", page)
    relayed = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    assert relayed is not None
    assert relayed.summary.startswith(
        "At Northwind Bank: Pay EUR 1250.00 to Acme GmbH for INV-0042"
    )
    assert bank_plugin.executor.performed == []

    # 3. Ada approves in Atlas; Ledgerly sends Northwind the approval of that exact revision.
    approval = await operations.ask_user(
        relayed, organization=company.document.organization, tenant_id=TENANT
    )
    assert host.approvals.asked[-1].company_name == "Ledgerly"  # type: ignore[union-attr]
    paid = await conversations.send(
        endpoint,
        page.conversation_id,
        Message(
            id=generate_message_id(reactor),
            author=Author(type="agent"),
            approval=approval,
        ),
        session=session,
        token=token,
        wait=0,
    )
    told = [e.message for e in paid.events if e.message is not None and e.message.role == "company"]
    assert told[-1].text.startswith("Northwind Bank: Sent EUR 1250.00 to Acme GmbH for INV-0042")
    assert len(bank_plugin.executor.performed) == 1
    bank_record = await bank.operation_record(bank_plugin.executor.performed[0])
    assert bank_record.status == "performed"
    assert bank_record.approved == relayed.terms["northwind_revision"]  # type: ignore[index]

    # 4. Every payment is asked about: nothing is paid in advance, however like the last.
    page = await pay("INV-0043", paid)
    over = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    assert over is not None and "EUR 980.00" in over.summary
    assert len(bank_plugin.executor.performed) == 1
    asked_before = len(host.approvals.asked)  # type: ignore[union-attr]
    await operations.ask_user(over, organization=company.document.organization, tenant_id=TENANT)
    assert len(host.approvals.asked) == asked_before + 1  # type: ignore[union-attr]
