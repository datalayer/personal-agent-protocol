# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent walking one user through a whole PAP journey with one company.

Ada asks her personal agent, Atlas, to exchange a jacket at Manzanita Outfitters:
discovery, a signed-out Session, sign-in mid-conversation, an exact approval, a
confirmed exchange, and finally narrowing and revoking the Account Token.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import (
    ClientMetadata,
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import DOMAIN, manzanita
from personal_agent_protocol.operations import OperationsClient, approve, operations_endpoint

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"

agent = Agent(
    instructions=(
        "Use run_manzanita_journey to show how Ada's personal agent exchanges a jacket "
        "with Manzanita over PAP. Say what Ada approved and what the company did. Never "
        "expose tokens, codes, or proofs."
    ),
)


@agent.tool_plain
async def run_manzanita_journey() -> dict[str, Any]:
    """Run the whole journey against the reference company; return safe evidence."""

    steps: list[str] = []
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    shop, shop_plugin = manzanita(network, clock)
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    transport = DpopHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)

    def say(text: str) -> Message:
        return Message(id=generate_message_id(reactor), sender="human", text=text)

    # Discovery and a signed-out Session.
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
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
    steps.append(f"discovered {company.document.organization.name}; signed-out Session")

    # A question only a signed-in user can have answered.
    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await conversations.start(
        endpoint, say("Where is my jacket order?"), token=session, wait=0, **who
    )
    asked = page.events[-1]
    conversation_id = page.conversation_id
    steps.append(f"company asked to sign in: {asked.error} ({asked.scope})")

    # Device Sign-In: Ada approves on Manzanita's own page.
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    steps.append(f"Ada opened {started.verification_uri} and entered the code")
    shop.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    signed_in = done.token
    if not (signed_in is not None and done.account_token_reference is not None):
        raise RuntimeError("the example world is incomplete")
    steps.append(f"same Session signed in with {', '.join(done.granted_scopes)}")

    # The same conversation continues; the company proposes the exchange.
    page = await conversations.send(
        endpoint,
        page.conversation_id,
        say("Exchange it for something warmer"),
        token=signed_in,
        cursor=page.cursor,
        wait=0,
        **who,
    )
    proposal = page.events[-1].message.operation  # type: ignore[union-attr]
    if not (proposal is not None):
        raise RuntimeError("the example world is incomplete")
    steps.append(f"company proposed revision {proposal.revision}: {proposal.summary}")

    # Ada approves exactly that revision; it is confirmed once.
    operations_url = operations_endpoint(
        company.document, ClientMetadata.model_validate(atlas.metadata)
    )
    if not (operations_url is not None):
        raise RuntimeError("the example world is incomplete")
    operations = OperationsClient(transport=transport)
    outcome = await operations.confirm(
        operations_url, proposal, approval=approve(proposal), token=signed_in, **who
    )
    again = await operations.confirm(
        operations_url, proposal, approval=approve(proposal), token=signed_in, **who
    )
    result = outcome.operation.result if outcome.operation else None
    steps.append(f"Ada approved; Manzanita: {result.summary if result else 'pending'}")

    # The Account Token: narrowed for read-only follow-up, then revoked.
    accounts = AccountTokenClient(reactor=reactor, http_client=http)
    context = AccountTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )
    narrowed = await accounts.refresh(
        done.account_token_reference,
        context=context,
        session_id=session.session_id,
        scopes=("orders:read",),
    )
    revoked = await accounts.revoke(done.account_token_reference, context=context)
    steps.append("Ada signed out: Account Token revoked")
    await http.aclose()

    return {
        "steps": steps,
        "conversation_kept_its_id_across_sign_in": page.conversation_id == conversation_id,
        "user_approval_required": proposal.user_approval_required,
        "confirmed_state": outcome.operation.state if outcome.operation else None,
        "approved_by": outcome.operation.confirmation.approved_by
        if outcome.operation and outcome.operation.confirmation
        else None,
        "second_confirm_state": again.operation.state if again.operation else None,
        "exchanges_performed": len(shop_plugin.executor.performed),
        "narrowed_to": narrowed.granted_scopes,
        "revoked": revoked.revoked,
        "tokens_codes_and_proofs_withheld": True,
    }


async def main() -> None:
    result = await agent.run(
        "My Ridge Jacket from Manzanita is not warm enough. Exchange it for the insulated "
        "one, and tell me what you did at each step.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
