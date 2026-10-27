# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Streaming, handoff, Direct Conversations, authorization and closing (§7.6 to 7.12)."""

from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    Author,
    ConversationClient,
    ConversationError,
    DpopHttpClient,
    DpopProofRequest,
    Message,
    SessionToken,
    build_pap_reactor,
)
from personal_agent_protocol.conversations import StreamReconnected, TextDelta

ENDPOINT = "https://api.example/conversations"
WHO = {"tenant_id": "tenant", "issuer": "https://auth.example"}


class Proofs:
    async def create(self, request: DpopProofRequest) -> SecretStr:
        return SecretStr("proof")


class Plugin:
    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(DPOP_PROOF_PROVIDERS, Proofs(), contribution_id="proofs")  # type: ignore[attr-defined]


def token(signed_in: bool = False) -> SessionToken:
    return SessionToken(
        access_token=SecretStr("session-secret"),
        token_type="DPoP",  # noqa: S106 - OAuth token type
        expires_in=300,
        session_key="K" * 43,
        signed_in=signed_in,
    )


def client_for(handler) -> tuple[ConversationClient, httpx.AsyncClient]:  # type: ignore[no-untyped-def]
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    reactor.register_plugin(PluginManifest(name="control-test", version="1"), Plugin())
    return ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http)), http


def event(event_id: str, **fields: object) -> dict[str, object]:
    return {"id": event_id, "created_at": "2026-10-11T10:00:00Z", **fields}


def sse(*frames: str) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "text/event-stream"},
        content="".join(frames).encode(),
    )


def frame(data: dict[str, object], *, name: str | None = None, with_id: bool = True) -> str:
    lines = []
    if name:
        lines.append(f"event: {name}")
    if with_id and "id" in data:
        lines.append(f"id: {data['id']}")
    lines.append(f"data: {json.dumps(data)}")
    return "\n".join(lines) + "\n\n"


@pytest.mark.asyncio
async def test_stream_yields_events_and_deltas_and_stops_at_closed() -> None:
    reply = {"id": "msg_r1", "author": {"type": "agent"}, "role": "company", "text": "Your order shipped."}

    def company(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept"] == "text/event-stream"
        return sse(
            ": keep-alive\n\n",
            frame({"message_id": "msg_r1", "text": "Your order"}, name="text-delta", with_id=False),
            frame(event("evt_1", type="message", message=reply)),
            frame(event("evt_2", type="state", status="closed", responder="agent")),
        )

    client, http = client_for(company)
    async with http:
        items = [item async for item in client.stream(ENDPOINT, "cnv_1", token=token(), **WHO)]
    assert isinstance(items[0], TextDelta) and items[0].actionable is False
    assert [getattr(item, "id", None) for item in items[1:]] == ["evt_1", "evt_2"]


@pytest.mark.asyncio
async def test_a_closed_stream_reopens_from_last_event_id_and_drops_partial_text() -> None:
    calls: list[str | None] = []

    def company(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("last-event-id"))
        if len(calls) == 1:
            return sse(
                frame(event("evt_1", type="state", status="working", responder="agent")),
                frame(
                    {"message_id": "msg_cut", "text": "Half a"}, name="text-delta", with_id=False
                ),
            )
        return sse(
            frame(event("evt_1", type="state", status="working", responder="agent")),
            frame(event("evt_2", type="state", status="closed", responder="agent")),
        )

    client, http = client_for(company)
    async with http:
        items = [item async for item in client.stream(ENDPOINT, "cnv_1", token=token(), **WHO)]
    assert calls == [None, "evt_1"]
    reconnects = [item for item in items if isinstance(item, StreamReconnected)]
    assert reconnects == [
        StreamReconnected(last_event_id="evt_1", discarded_message_ids=("msg_cut",))
    ]
    # The replayed evt_1 is not delivered twice.
    assert [item.id for item in items if hasattr(item, "type")] == ["evt_1", "evt_2"]


@pytest.mark.asyncio
async def test_a_company_that_does_not_stream_says_so() -> None:
    client, http = client_for(
        lambda _: httpx.Response(
            200,
            json={
                "conversation_id": "cnv_1",
                "events": [],
                "cursor": "c_1",
                "has_more": False,
                "status": "idle",
                "responder": "agent",
            },
        )
    )
    async with http:
        with pytest.raises(ConversationError) as raised:
            [item async for item in client.stream(ENDPOINT, "cnv_1", token=token(), **WHO)]
    assert raised.value.code == "sse_unsupported"


@pytest.mark.asyncio
async def test_a_stream_that_keeps_closing_empty_gives_up() -> None:
    client, http = client_for(lambda _: sse(": nothing\n\n"))
    async with http:
        with pytest.raises(ConversationError) as raised:
            [
                item
                async for item in client.stream(
                    ENDPOINT, "cnv_1", token=token(), max_reconnects=2, **WHO
                )
            ]
    assert raised.value.code == "stream_unavailable"


@pytest.mark.asyncio
async def test_handoff_and_close_post_empty_objects() -> None:
    seen: list[tuple[str, bytes]] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.content))
        if request.url.path.endswith("/handoff"):
            return httpx.Response(
                202, json={"conversation_id": "cnv_1", "status": "queued", "responder": "agent"}
            )
        return httpx.Response(
            200, json={"conversation_id": "cnv_1", "status": "closed", "responder": "human"}
        )

    client, http = client_for(company)
    async with http:
        queued = await client.handoff(ENDPOINT, "cnv_1", token=token(), **WHO)
        closed = await client.close(ENDPOINT, "cnv_1", token=token(), **WHO)
    assert queued.status == "queued"
    assert closed.status == "closed" and closed.responder == "human"
    assert seen == [("/conversations/cnv_1/handoff", b"{}"), ("/conversations/cnv_1/close", b"{}")]


@pytest.mark.asyncio
async def test_a_direct_conversation_names_its_parent_and_the_parent_points_to_it() -> None:
    seen: list[dict[str, object]] = []

    def company(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/messages"):
            return httpx.Response(
                409, json={"error": "direct_conversation_open", "conversation_id": "cnv_direct"}
            )
        seen.append(json.loads(request.content))
        return httpx.Response(
            201, json={"conversation_id": "cnv_direct", "status": "idle", "responder": "agent"}
        )

    client, http = client_for(company)
    async with http:
        opened = await client.start_direct(
            ENDPOINT,
            "cnv_1",
            Message(id="msg_d1", author=Author(type="human"), text="I'll take it from here"),
            token=token(),
            **WHO,
        )
        with pytest.raises(ConversationError) as raised:
            await client.send(
                ENDPOINT,
                "cnv_1",
                Message(id="msg_p2", author=Author(type="agent"), text="Still there?"),
                token=token(),
                **WHO,
            )
    assert seen[0]["parent_conversation_id"] == "cnv_1"
    assert opened.conversation_id == "cnv_direct"
    assert raised.value.code == "direct_conversation_open"
    assert raised.value.details == {"conversation_id": "cnv_direct"}


@pytest.mark.asyncio
async def test_signing_in_mid_conversation_keeps_its_id() -> None:
    """An `authorization` event is answered by a token change; the conversation goes on (§7.11)."""

    tokens: list[str] = []

    def company(request: httpx.Request) -> httpx.Response:
        tokens.append(request.headers["authorization"])
        return httpx.Response(
            202, json={"conversation_id": "cnv_1", "status": "working", "responder": "agent"}
        )

    client, http = client_for(company)
    signed_in = token(signed_in=True).model_copy(
        update={"access_token": SecretStr("signed-in-secret")}
    )
    async with http:
        first = await client.send(
            ENDPOINT,
            "cnv_1",
            Message(id="msg_1", author=Author(type="agent"), text="Show my order"),
            token=token(),
            **WHO,
        )
        second = await client.send(
            ENDPOINT,
            "cnv_1",
            Message(id="msg_2", author=Author(type="agent"), text="Signed in now"),
            token=signed_in,
            **WHO,
        )
    assert first.conversation_id == second.conversation_id == "cnv_1"
    assert tokens == ["DPoP session-secret", "DPoP signed-in-secret"]
