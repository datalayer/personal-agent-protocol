# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent showing what a `PapSignIn` display tells a model and a page.

Atlas, Ada's personal agent, starts a real Device Sign-In at Manzanita Outfitters
and answers with a `PapSignIn` display (`personal_agent_protocol.ui`, the `ui`
extra). The page gets the whole display — in an MCP result's
`_meta["reactor.ui/display"]` — with the sign-in page to open and the code to
enter there. The model gets `model_view()`: the display's text, which names only
the company's domain, and neither the link (a verification URL may carry the code)
nor the code. Ada then approves on Manzanita's page, and the Session is signed in.

The tool hands the model the model view as is, and of the page's display only its
shape: field names, the page's host, and whether the link and the code are there.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any

from pydantic_ai import Agent
from reactor.ui import DISPLAY_META_KEY

from personal_agent_protocol import DeviceSignInClient, DiscoveryClient, SessionClient
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import DOMAIN, manzanita
from personal_agent_protocol.ui import WAITING_FOR_THE_PERSON, PapSignIn

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"

agent = Agent(
    instructions=(
        "Use read_sign_in_display to explain what a person's page shows for a PAP "
        "sign-in and what a model is told of it. Never ask the person for a code or "
        "a link in the conversation: the page shows them."
    ),
)


@agent.tool_plain
async def read_sign_in_display() -> dict[str, Any]:
    """Start a Device Sign-In at Manzanita; return the model's view and the page's shape."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    shop, _ = manzanita(network, clock)
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )

    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    if not (metadata is not None and metadata.device_authorization_endpoint is not None):
        raise RuntimeError("the example world is incomplete")
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
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        session_key=session.session_key,
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
    )

    # A sign-in tool's answer, and the display a page draws for it.
    answer = {
        "status": WAITING_FOR_THE_PERSON,
        "mode": "device",
        "open": started.verification_uri_complete or started.verification_uri,
        "code": started.user_code,
        "expires_at": started.expires_at,
        # The company that asks for the code, by name and domain (§4.6).
        "organization_name": started.organization_name,
        "organization_domain": started.organization_domain,
    }
    display = PapSignIn.from_answer(answer)
    if display is None:
        raise RuntimeError("the example world is incomplete")
    model_view = display.model_view()
    meta = display.tool_meta()
    page = meta[DISPLAY_META_KEY]
    told = json.dumps(model_view, default=str)
    received = PapSignIn.from_wire(page)

    # Ada opens the page, enters the code there, and approves.
    await shop.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    await http.aclose()

    return {
        "model_view": model_view,
        "the_model_is_told_the_link": answer["open"] in told,
        "the_model_is_told_the_code": started.user_code in told,
        "page": {
            "meta_key": DISPLAY_META_KEY,
            "type": page["type"],
            "version": page["version"],
            "text": page["text"],
            "fields": sorted(page["data"]),
            "page_only_fields": sorted(set(page["data"]) - set(model_view["data"])),
            "opens_a_page_at": display.host,
            "has_the_link": page["data"].get("open") == answer["open"],
            "has_the_code": page["data"].get("code") == started.user_code,
            "rebuilt_on_the_page": received == display,
        },
        "after_approval": {
            "status": done.status,
            "signed_in": bool(done.token and done.token.signed_in),
        },
    }


async def main() -> None:
    """Ask the agent to explain the display."""

    result = await agent.run(
        "Atlas needs Ada to sign in at Manzanita. What does her page show, and what are you told?",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
