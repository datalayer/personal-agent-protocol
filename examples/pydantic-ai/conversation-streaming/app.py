# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent demonstrating PAP conversation streaming over SSE."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import httpx
from pydantic_ai import Agent

from personal_agent_protocol import (
    ConversationClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.conversations import StreamReconnected, TextDelta
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import manzanita

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"


class DroppedConnection(httpx.AsyncBaseTransport):
    """The network between Atlas and Manzanita: the first stream breaks mid-message.

    Every other request passes through unchanged. It records the `Last-Event-ID`
    each stream was opened with.
    """

    def __init__(self, inner: httpx.AsyncClient) -> None:
        self.inner = inner
        self.streams_opened: list[str | None] = []

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.send(request)
        if request.headers.get("accept") != "text/event-stream":
            return httpx.Response(
                response.status_code, headers=response.headers, content=response.content
            )
        self.streams_opened.append(request.headers.get("last-event-id"))
        body = response.content
        if len(self.streams_opened) == 1:
            # Cut right after the first `text-delta` frame: the message never arrives.
            start = body.find(b"event: text-delta")
            body = body[: body.find(b"\n\n", start) + 2]
        return httpx.Response(
            response.status_code,
            headers={"Content-Type": response.headers["content-type"]},
            content=body,
        )


agent = Agent(
    instructions=(
        "Use explain_conversation_streaming to explain PAP conversation streaming. "
        "Text deltas are for display only: never act on one. Never expose tokens or proofs."
    ),
)


@agent.tool_plain
async def explain_conversation_streaming() -> dict[str, Any]:
    """Stream a Manzanita conversation through a dropped connection; return safe evidence."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    manzanita(network, clock)
    wire = DroppedConnection(network.client())
    http = httpx.AsyncClient(transport=wire)
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover("manzanita.example")
    metadata = company.oauth_metadata
    if not (metadata is not None):
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
    receipt = await conversations.start(
        endpoint,
        Message(id=generate_message_id(reactor), sender="human", text="Hello"),
        token=session,
        **who,
    )

    deltas: list[TextDelta] = []
    reconnects: list[StreamReconnected] = []
    delivered: list[str] = []
    final_text: list[str] = []
    last_state = None
    async for item in conversations.stream(endpoint, receipt.conversation_id, token=session, **who):
        if isinstance(item, TextDelta):
            deltas.append(item)  # display only: shown while typing, never acted on
        elif isinstance(item, StreamReconnected):
            reconnects.append(item)
            if len(reconnects) == 2:
                # Everything is delivered; the user is done, so the agent closes it.
                await conversations.close(endpoint, receipt.conversation_id, token=session, **who)
        else:
            delivered.append(item.id)
            last_state = item.status if item.type == "state" else last_state
            if item.message is not None and item.message.role == "company":
                final_text.append(item.message.text or "")
    await http.aclose()
    await wire.inner.aclose()

    return {
        "stream_openings_last_event_id": [
            "none" if value is None else "last handled event" for value in wire.streams_opened
        ],
        "reconnects": len(reconnects),
        "partial_messages_discarded": [len(item.discarded_message_ids) for item in reconnects],
        "text_deltas_seen": len(deltas),
        "any_delta_actionable": any(delta.actionable for delta in deltas),
        "events_delivered_once": len(delivered) == len(set(delivered)),
        "events_delivered": len(delivered),
        "company_reply_from_the_complete_message": final_text,
        "stopped_on_state": last_state,
        "session_token_and_proofs_withheld": True,
    }


async def main() -> None:
    result = await agent.run(
        "Explain how a personal agent streams a company's reply over SSE, what happens "
        "when the connection drops mid-message, and why text deltas are display only.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
