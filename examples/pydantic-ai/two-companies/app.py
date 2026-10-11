# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent showing two companies working together over PAP, by composition.

Draft 0.1 defines no company-to-company protocol. Ledgerly, an accounting firm, is
a PAP company to Ada's personal agent (Atlas) and, for the same Ada, a PAP personal
agent at Northwind Bank. Every approval is an Operation, and a standing permission
is itself an Operation Ada approves.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

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
from personal_agent_protocol.demo.ledgerly import DOMAIN as LEDGERLY
from personal_agent_protocol.demo.ledgerly import ledgerly
from personal_agent_protocol.demo.northwind import ACCOUNT, northwind
from personal_agent_protocol.operations import OperationsClient, approve

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_ledgerly_00000000"

agent = Agent(
    instructions=(
        "Use run_two_companies to show how Ledgerly pays Ada's invoices at Northwind "
        "Bank for her. Be clear that this is composition of two PAP relationships, not "
        "a company-to-company protocol. Never expose tokens, codes, or proofs."
    ),
)


@agent.tool_plain
async def run_two_companies() -> dict[str, Any]:
    """Run Ada → Atlas → Ledgerly → Northwind; return safe evidence."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    bank, bank_plugin = northwind(network, clock)
    firm, at_northwind = ledgerly(network, clock)
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    transport = DpopHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)
    operations = OperationsClient(transport=transport)

    # Atlas signs Ada in to Ledgerly (Device Sign-In on Ledgerly's page).
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(LEDGERLY)
    metadata = company.oauth_metadata
    if not (metadata is not None and metadata.device_authorization_endpoint is not None):
        raise RuntimeError("the example world is incomplete")
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
        device_authorization_endpoint=metadata.device_authorization_endpoint,
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
    if not (token is not None):
        raise RuntimeError("the example world is incomplete")
    chat = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    ops = firm.config.operations_endpoint
    cursor: dict[str, Any] = {}

    async def say(text: str):  # type: ignore[no-untyped-def]
        message = Message(id=generate_message_id(reactor), sender="human", text=text)
        if not cursor:
            page = await conversations.start(chat, message, token=token, wait=0, **who)
        else:
            page = await conversations.send(
                chat, cursor["id"], message, token=token, cursor=cursor["at"], wait=0, **who
            )
        cursor.update(id=page.conversation_id, at=page.cursor)
        return page.events[-1].message

    # 1. Ledgerly is not yet connected to Northwind: Ada approves it on Northwind's page.
    connect = (await say("Pay INV-0042")).data["connect"]
    await bank.approve_device(connect["user_code"], account_id=ACCOUNT)
    clock.advance(5)

    # 2. Northwind's proposal comes back as a Ledgerly operation quoting it as written.
    relayed = (await say("Done. Pay INV-0042")).operation
    performed_before_approval = len(bank_plugin.executor.performed)

    # 3. Ada approves in Atlas; Ledgerly confirms that exact revision at Northwind.
    paid = await operations.confirm(ops, relayed, approval=approve(relayed), token=token, **who)
    first = (await bank.operation_record(bank_plugin.executor.performed[0])).operation

    # 4. A standing permission is itself an operation Ada approves.
    allow = "Allow Ledgerly to pay Acme invoices up to EUR 2000 without asking"
    grant = (await say(allow)).operation
    granted = await operations.confirm(ops, grant, approval=approve(grant), token=token, **who)

    # 5. Within the bounds: paid under the permission, Ada told what was done.
    told = await say("Pay INV-0043")
    second = (await bank.operation_record(bank_plugin.executor.performed[1])).operation

    # 6. Beyond the bounds: Ada is asked again.
    over = (await say("Pay INV-0044")).operation
    await http.aclose()

    return {
        "composition": (
            "Atlas is Ada's personal agent at Ledgerly; Ledgerly is Ada's personal agent "
            "at Northwind. No company-to-company protocol is involved."
        ),
        "ledgerly_identity_at_northwind": at_northwind.identity.client_id,
        "connect_at": connect["verification_uri"],
        "relayed_summary": relayed.summary,
        "relayed_requires_ada": relayed.user_approval_required,
        "bank_payments_before_ada_approved": performed_before_approval,
        "after_ada_approved": paid.operation.result.summary if paid.operation else None,
        "bank_record_approved_by": first.confirmation.approved_by if first.confirmation else None,
        "standing_permission_summary": grant.summary,
        "standing_permission_granted": granted.operation.state if granted.operation else None,
        "within_bounds_told": told.text,
        "within_bounds_new_proposal_for_ada": told.operation is not None,
        "within_bounds_bank_record_approved_by": second.confirmation.approved_by
        if second.confirmation
        else None,
        "beyond_bounds_asks_ada": over.summary if over else None,
        "bank_payments_performed": len(bank_plugin.executor.performed),
        "tokens_codes_and_proofs_withheld": True,
    }


async def main() -> None:
    result = await agent.run(
        "Have Ledgerly pay my Acme invoices from my Northwind account. Pay the first with "
        "my approval, then let Ledgerly pay Acme up to EUR 2000 without asking.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
