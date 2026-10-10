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
