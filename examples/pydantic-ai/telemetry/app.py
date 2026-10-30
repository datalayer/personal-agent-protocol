# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent reading the PAP telemetry of a journey with Manzanita.

Atlas, Ada's personal agent, contributes a `pap.telemetry` sink to its Reactor and
runs a journey: discovery, a signed-out Session, a question, Device Sign-In, and a
approved exchange. Each protocol stage is one event whose attributes come from an
allowlist — a domain, an issuer, a status, a count — so what the tool hands the
model is exactly what a trace or an analytics pipeline would receive, and holds no
token, code, Session JWT, or identifier. With `opentelemetry-api` installed, the same
events become spans through `OpenTelemetrySink`.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections import Counter
from typing import Any

from pydantic_ai import Agent
from reactor import PluginManifest

from personal_agent_protocol import (
    TELEMETRY_SINKS,
    Author,
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    Message,
    RecordingTelemetrySink,
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
from personal_agent_protocol.demo.manzanita import DOMAIN, manzanita
from personal_agent_protocol.operations import OperationsClient

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"

agent = Agent(
    instructions=(
        "Use read_pap_telemetry to explain, stage by stage, what Ada's personal agent did "
        "with Manzanita and how long each stage took. The events are all you need."
    ),
)


class Telemetry:
    """Atlas's host contributes its sink ahead of any other (a lower order)."""

    def __init__(self, sink: RecordingTelemetrySink) -> None:
        self.sink = sink

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(TELEMETRY_SINKS, self.sink, contribution_id="atlas", order=50)


@agent.tool_plain
async def read_pap_telemetry() -> dict[str, Any]:
    """Run a journey with Manzanita and return its telemetry events, as recorded."""

    sink = RecordingTelemetrySink()
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    shop, _ = manzanita(network, clock)
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock, approvals=ScriptedApprovals(always=True)),
        network=network,
        http_client=http,
        plugins=[(PluginManifest(name="atlas-telemetry", version="1"), Telemetry(sink))],
    )
    transport = SessionHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)

    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    if not (metadata is not None and metadata.device_authorization_endpoint is not None):
        raise RuntimeError("the example world is incomplete")
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        tenant_id=TENANT,
    )
    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    def say(text: str) -> Message:
        return Message(id=generate_message_id(reactor), author=Author(type="human"), text=text)

    page = await conversations.start(
        endpoint, say("Where is my jacket order?"), session=session, wait=0
    )
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await shop.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    signed_in = (await device.poll(started.reference)).token
    if signed_in is None:
        raise RuntimeError("the example world is incomplete")
    page = await conversations.send(
        endpoint,
        page.conversation_id,
        say("Exchange it for something warmer"),
        session=session,
        token=signed_in,
        cursor=page.cursor,
        wait=0,
    )
    proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    if proposal is None:
        raise RuntimeError("the example world is incomplete")
    approval = await OperationsClient(reactor=reactor).ask_user(
        proposal, organization=company.document.organization, tenant_id=TENANT
    )
    await conversations.send(
        endpoint,
        page.conversation_id,
        Message(id=generate_message_id(reactor), author=Author(type="agent"), approval=approval),
        session=session,
        token=signed_in,
        wait=0,
    )

    events = [event.as_dict() for event in sink.events]
    return {
        "events": [
            {key: event[key] for key in ("name", "outcome", "attributes")} for event in events
        ],
        "stages": dict(Counter(event["stage"] for event in events)),
        "total_ms": round(sum(event["duration_ms"] for event in events), 1),
    }


async def main() -> None:
    """Ask the agent to explain the journey from its telemetry."""

    result = await agent.run(
        "What did Atlas do with Manzanita, stage by stage?",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
