# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent demonstrating PAP conversation control.

Sign-in mid-conversation, Direct Conversations, handoff to a person, and closing.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import replace
from typing import Any

from pydantic_ai import Agent
from reactor import PluginManifest

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
from personal_agent_protocol.company import build_company, company_app
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    ClockPlugin,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import CONFIG, DOMAIN, ManzanitaPlugin

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"

agent = Agent(
    instructions=(
        "Use explain_conversation_control to explain how a PAP conversation is signed "
        "in to, handed to the user directly or to a person at the company, and closed. "
        "Never expose tokens, codes, or proofs."
    ),
)


@agent.tool_plain
async def explain_conversation_control() -> dict[str, Any]:
    """Drive one Manzanita conversation through every control; return safe evidence."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    # Manzanita, this time with a support desk staffed (`humans_available`).
    shop = build_company(
        replace(CONFIG, humans_available=True),
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=[
            (PluginManifest(name="manzanita", version="1"), ManzanitaPlugin()),
            (PluginManifest(name="manzanita-clock", version="1"), ClockPlugin(clock)),
        ],
    )
    network.add(DOMAIN, company_app(shop))
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
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
    conversations = ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http))
    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    def say(text: str, sender: str = "agent") -> Message:
        return Message(id=generate_message_id(reactor), sender=sender, text=text)  # type: ignore[arg-type]

    # 1. Signed out, the company answers with an `authorization` event instead.
    page = await conversations.start(
        endpoint, say("Where is my jacket order?"), token=session, wait=0, **who
    )
    parent = page.conversation_id
    asked = page.events[-1]

    # 2. The host signs Ada in (Device Sign-In on Manzanita's page); the same
    #    conversation continues with the signed-in token.
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=tuple((asked.scope or "").split()),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    shop.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    token = (await device.poll(started.reference)).token
    if not (token is not None):
        raise RuntimeError("the example world is incomplete")
    page = await conversations.send(
        endpoint,
        parent,
        say("Where is my jacket order?"),
        token=token,
        cursor=page.cursor,
        wait=0,
        **who,
    )
    answered = page.events[-1].message

    # 3. Ada wants to talk to Manzanita herself: a Direct Conversation under the parent.
    direct = await conversations.start_direct(
        endpoint, parent, say("I'd like to ask about sizing myself", "human"), token=token, **who
    )
    refusals: dict[str, object] = {}
    for action in ("send", "handoff"):
        try:
            if action == "send":
                await conversations.send(endpoint, parent, say("Still there?"), token=token, **who)
            else:
                await conversations.handoff(endpoint, parent, token=token, **who)
        except ConversationError as error:
            refusals[action] = error.code
            refusals[f"{action}_names_the_open_direct_conversation"] = (error.details or {}).get(
                "conversation_id"
            ) == direct.conversation_id
    direct_closed = await conversations.close(endpoint, direct.conversation_id, token=token, **who)

    # 4. Handoff to a person at the company; their replies come as `human`.
    handed = await conversations.handoff(endpoint, parent, token=token, **who)
    page = await conversations.send(
        endpoint, parent, say("Thank you"), token=token, cursor=page.cursor, wait=0, **who
    )
    after_handoff = [
        f"{event.type}:{event.status}" if event.status else event.type for event in page.events
    ]

    # 5. Closing ends the conversation; what it started is not cancelled.
    closed = await conversations.close(endpoint, parent, token=token, **who)
    try:
        await conversations.send(endpoint, parent, say("One more thing"), token=token, **who)
        after_close = "accepted"
    except ConversationError as error:
        after_close = error.code
    await http.aclose()

    return {
        "signed_out_answer": f"{asked.type}: {asked.error} ({asked.scope})",
        "signed_in_same_conversation": page.conversation_id == parent,
        "signed_in_answer": answered.text if answered else None,
        "direct_conversation_opened": direct.conversation_id != parent,
        "parent_while_direct_is_open": refusals,
        "direct_conversation_closed": direct_closed.status,
        "handoff_status": handed.status,
        "handoff_responder": handed.responder,
        "events_after_handoff": after_handoff,
        "closed": closed.status,
        "message_after_close": after_close,
        "tokens_and_codes_withheld": True,
    }


async def main() -> None:
    result = await agent.run(
        "Explain how a personal agent signs in mid-conversation, lets the user talk to a "
        "company directly, hands off to a person, and closes the conversation.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
