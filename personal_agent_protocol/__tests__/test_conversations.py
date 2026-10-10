from __future__ import annotations

import json

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    ConversationClient,
    ConversationError,
    DpopHttpClient,
    DpopProofRequest,
    Message,
    SessionToken,
    build_pap_reactor,
    generate_message_id,
)


class Proofs:
    async def create(self, request: DpopProofRequest) -> SecretStr:
        return SecretStr(f"proof-for-{request.method.lower()}")


class Plugin:
    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            DPOP_PROOF_PROVIDERS, Proofs(), contribution_id="proofs"
        )


def token() -> SessionToken:
    return SessionToken(
        access_token=SecretStr("session-secret"),
        token_type="DPoP",  # noqa: S106 - OAuth token type
        expires_in=300,
        session_id="ses_example",
        signed_in=False,
    )


@pytest.mark.asyncio
async def test_start_and_continue_preserve_message_ids_and_parse_waited_events() -> None:
    seen: list[dict[str, object]] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        if len(seen) == 1:
            assert str(request.url).endswith("?wait=10")
            return httpx.Response(
                201,
                json={
                    "conversation_id": "cnv_one",
                    "events": [],
                    "cursor": "evt_zero",
                    "has_more": False,
                    "status": "working",
                    "responder": "agent",
                },
            )
        assert str(request.url).endswith("/cnv_one/messages?cursor=evt_zero&wait=10")
        return httpx.Response(
            202,
            json={"conversation_id": "cnv_one", "status": "idle", "responder": "agent"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="conversations-test", version="1"), Plugin())
        client = ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http))
        first = Message(id=generate_message_id(reactor), sender="agent", text="Return the jacket")
        page = await client.start(
            "https://api.example/conversations",
            first,
            token=token(),
            tenant_id="tenant",
            pairwise_user_id="usr_example",
            issuer="https://auth.example",
            wait=10,
        )
        follow_up = Message(
            id=generate_message_id(reactor), sender="agent", context={"user_available": False}
        )
        receipt = await client.send(
            "https://api.example/conversations",
            "cnv_one",
            follow_up,
            token=token(),
            tenant_id="tenant",
            pairwise_user_id="usr_example",
            issuer="https://auth.example",
            cursor="evt_zero",
            wait=10,
        )
        reactor.stop()

    assert page.conversation_id == receipt.conversation_id == "cnv_one"
    assert seen[0]["message"]["id"] == first.id  # type: ignore[index]
    assert seen[1]["message"]["id"] == follow_up.id  # type: ignore[index]
    assert first.id != follow_up.id


@pytest.mark.asyncio
async def test_surfaces_message_id_conflict_without_response_body() -> None:
    def company(_: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"error": "message_id_conflict", "secret": "omit"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="conversations-test", version="1"), Plugin())
        client = ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http))
        with pytest.raises(ConversationError) as caught:
            await client.start(
                "https://api.example/conversations",
                Message(id="msg_same", sender="agent", text="different content"),
                token=token(),
                tenant_id="tenant",
                pairwise_user_id="usr_example",
                issuer="https://auth.example",
            )
        reactor.stop()

    assert caught.value.code == "message_id_conflict"
    assert "secret" not in str(caught.value)


@pytest.mark.asyncio
async def test_events_recover_cursor_drain_backlog_and_suppress_duplicates() -> None:
    urls: list[str] = []
    recovered = 0

    def event(event_id: str, text: str) -> dict[str, object]:
        return {
            "id": event_id,
            "type": "message",
            "created_at": "2026-10-10T12:00:00Z",
            "message": {
                "id": f"msg_{event_id}",
                "sender": "agent",
                "role": "company",
                "text": text,
            },
        }

    def company(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        if len(urls) == 1:
            return httpx.Response(410, json={"error": "cursor_expired"})
        if len(urls) == 2:
            return httpx.Response(
                200,
                json={
                    "conversation_id": "cnv_one",
                    "events": [event("evt_one", "one"), event("evt_two", "two")],
                    "cursor": "evt_two",
                    "has_more": True,
                    "status": "working",
                    "responder": "agent",
                },
            )
        return httpx.Response(
            200,
            json={
                "conversation_id": "cnv_one",
                "events": [event("evt_two", "two"), event("evt_three", "three")],
                "cursor": "evt_three",
                "has_more": False,
                "status": "closed",
                "responder": "agent",
            },
        )

    async def on_cursor_expired() -> None:
        nonlocal recovered
        recovered += 1

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(
            http_client=http,
            plugins=[
                (
                    PluginManifest(name="conversation-events-test", version="1"),
                    Plugin(),
                )
            ],
        )
        client = ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http))
        events = [
            item
            async for item in client.events(
                "https://api.example/conversations",
                "cnv_one",
                token=token(),
                tenant_id="tenant",
                pairwise_user_id="usr_example",
                issuer="https://auth.example",
                cursor="evt_saved",
                wait=30,
                on_cursor_expired=on_cursor_expired,
            )
        ]
        reactor.stop()

    assert [item.id for item in events] == ["evt_one", "evt_two", "evt_three"]
    assert recovered == 1
    assert urls[0].endswith("?cursor=evt_saved&wait=30")
    assert urls[1].endswith("/events?wait=30")
    assert urls[2].endswith("?cursor=evt_two&wait=0")


@pytest.mark.asyncio
async def test_read_events_rejects_conversation_mismatch() -> None:
    def company(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "conversation_id": "cnv_other",
                "events": [],
                "cursor": "evt_zero",
                "has_more": False,
                "status": "idle",
                "responder": "agent",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(
            http_client=http,
            plugins=[
                (
                    PluginManifest(name="conversation-mismatch-test", version="1"),
                    Plugin(),
                )
            ],
        )
        client = ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http))
        with pytest.raises(ConversationError, match="different conversation"):
            await client.read_events(
                "https://api.example/conversations",
                "cnv_one",
                token=token(),
                tenant_id="tenant",
                pairwise_user_id="usr_example",
                issuer="https://auth.example",
            )
        reactor.stop()
