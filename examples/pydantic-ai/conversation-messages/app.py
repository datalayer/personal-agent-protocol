# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A Pydantic AI tool that starts and continues a PAP conversation safely."""

from __future__ import annotations

import httpx
from pydantic import SecretStr
from pydantic_ai import Agent
from reactor import PluginManifest

from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    Author,
    ConversationClient,
    DpopHttpClient,
    Message,
    SessionToken,
    build_pap_reactor,
    generate_message_id,
)


class Proofs:
    async def create(self, request: object) -> SecretStr:
        return SecretStr("host-only-proof")


class Plugin:
    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            DPOP_PROOF_PROVIDERS, Proofs(), contribution_id="protected-dpop"
        )


agent = Agent(
    instructions="Use demonstrate_conversation; never expose PAP credentials or identity."
)


@agent.tool_plain
async def demonstrate_conversation() -> dict[str, object]:
    """Start and continue one local PAP conversation."""

    calls = 0

    def company(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            201 if calls == 1 else 202,
            json={"conversation_id": "cnv_demo", "status": "working", "responder": "agent"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="conversation-example", version="1"), Plugin())
        client = ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http))
        token = SessionToken(
            access_token=SecretStr("host-only-token"),
            token_type="DPoP",  # noqa: S106 - OAuth token type
            expires_in=300,
            # The Session Key's JWK thumbprint names the Session; it stays in the host.
            session_key="NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
            signed_in=False,
        )
        # The personal agent writes this message itself: its `author` is `agent`.
        first = Message(
            id=generate_message_id(reactor),
            author=Author(type="agent"),
            text="Can this order be returned?",
        )
        started = await client.start(
            "https://api.shop.example/poppy/conversations",
            first,
            token=token,
            tenant_id="demo",
            issuer="https://auth.shop.example",
        )
        follow_up = Message(
            id=generate_message_id(reactor),
            author=Author(type="agent"),
            context={"user_available": False},
        )
        continued = await client.send(
            "https://api.shop.example/poppy/conversations",
            started.conversation_id,
            follow_up,
            token=token,
            tenant_id="demo",
            issuer="https://auth.shop.example",
        )
        reactor.stop()
    return {
        "conversation_id": continued.conversation_id,
        "unique_message_ids": first.id != follow_up.id,
        "retry_rule": "retain the same Message object and ID",
        "credentials_withheld": True,
    }
