# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent that demonstrates PAP Session start and renewal."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any
from urllib.parse import parse_qs

import httpx
from pydantic import SecretStr
from pydantic_ai import Agent
from reactor import PluginManifest

from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    SIGNERS,
    DpopProofRequest,
    InMemorySessionKeys,
    JoseDpopProofProvider,
    SessionClient,
    SessionError,
    build_pap_reactor,
)


class RecordingSigner:
    """Represent protected signing while recording only its purpose."""

    def __init__(self) -> None:
        self.purposes: list[str] = []

    async def sign(self, _: dict[str, object], *, purpose: str) -> SecretStr:
        self.purposes.append(purpose)
        return SecretStr(f"host-only-{purpose}-{len(self.purposes)}")


class RecordingDpopProvider:
    """Real Session Keys and proofs, recording which key each proof used.

    Each Session gets its own key; its JWK thumbprint, the Session Key, names the
    Session. The private halves stay in the host's key custody.
    """

    def __init__(self) -> None:
        self.proofs = JoseDpopProofProvider(InMemorySessionKeys())
        self.requests: list[DpopProofRequest] = []
        self.made: list[str] = []
        self.discarded: list[str] = []

    async def new_session_key(self, *, tenant_id: str, issuer: str) -> str:
        key = await self.proofs.new_session_key(tenant_id=tenant_id, issuer=issuer)
        self.made.append(key)
        return key

    async def discard_session_key(self, *, tenant_id: str, issuer: str, session_key: str) -> None:
        self.discarded.append(session_key)
        await self.proofs.discard_session_key(
            tenant_id=tenant_id, issuer=issuer, session_key=session_key
        )

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.requests.append(request)
        return await self.proofs.create(request)


class SessionSecurityPlugin:
    """Contribute host-owned Session security capabilities through Reactor."""

    def __init__(self, signer: RecordingSigner, dpop: RecordingDpopProvider) -> None:
        self.signer = signer
        self.dpop = dpop

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(SIGNERS, self.signer, contribution_id="example-signer")
        contribute(DPOP_PROOF_PROVIDERS, self.dpop, contribution_id="example-dpop")


agent = Agent(
    instructions=(
        "Use explain_session_lifecycle to explain signed-out PAP Session start "
        "and renewal. Never ask for or expose a subject, Session Key, assertion, "
        "proof, nonce, key, or token."
    ),
)


@agent.tool_plain
async def explain_session_lifecycle() -> dict[str, Any]:
    """Exercise SessionClient and return only lifecycle and safety evidence."""

    calls = 0
    forms: list[dict[str, list[str]]] = []

    def company(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        forms.append(parse_qs(request.content.decode()))
        if calls == 1:
            return httpx.Response(
                400,
                json={"error": "use_dpop_nonce"},
                headers={"DPoP-Nonce": "host-only-company-nonce"},
            )
        if calls == 4:
            # The company has ended the Session: its key is refused from now on.
            return httpx.Response(400, json={"error": "invalid_grant"})
        # No Session ID, no `signed_in`, no `scope`: the proof's key names the Session,
        # the grant (JWT bearer) makes it signed out, and a signed-out Session has none.
        return httpx.Response(
            200,
            json={
                "access_token": f"host-only-session-token-{calls}",
                "token_type": "DPoP",
                "expires_in": 300,
            },
        )

    signer = RecordingSigner()
    dpop = RecordingDpopProvider()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(
            PluginManifest(name="pap-session-example-security", version="1"),
            SessionSecurityPlugin(signer, dpop),
        )
        client = SessionClient(reactor=reactor, http_client=http)
        options = {
            "client_id": "https://assistant.example/agent.json",
            "pairwise_user_id": "usr_host_only_example",
            "issuer": "https://company.example",
            "token_endpoint": "https://company.example/oauth/token",
            "tenant_id": "example-tenant",
        }
        # Starting a Session makes a new Session Key; renewing proves the same key.
        started = await client.start(**options)
        renewed = await client.renew(**options, session_key=started.session_key)
        try:
            await client.renew(**options, session_key=started.session_key)
            ended = "renewed"
        except SessionError as error:
            ended = error.code
        # An ended Session's key is discarded, never reused: the next Session has a new one.
        restarted = await client.start(**options)
        reactor.stop()

    return {
        "start_status": "created",
        "renew_status": "renewed",
        "signed_in": renewed.signed_in,
        "token_type": renewed.token_type,
        "scopes": renewed.scopes,
        "same_session": started.session_key == renewed.session_key,
        "renewal_proved_with_the_session_key": dpop.requests[2].session_key == started.session_key,
        "no_session_id_on_the_wire": all("session_id" not in form for form in forms),
        "nonce_retry": [request.nonce for request in dpop.requests[:3]]
        == [None, "host-only-company-nonce", None],
        "fresh_assertions": len(signer.purposes) == 10,
        "fresh_proofs": len(dpop.requests) == 5,
        "ended_session": ended,
        "ended_session_key_discarded": dpop.discarded == [started.session_key],
        "new_session_new_key": restarted.session_key != started.session_key and len(dpop.made) == 2,
        "session_key_withheld": True,
        "assertions_withheld": True,
        "proofs_withheld": True,
        "tokens_withheld": True,
    }


async def main() -> None:
    """Run one didactic signed-out Session lifecycle conversation."""

    result = await agent.run(
        "Explain how a signed-out PAP Session starts, handles a DPoP nonce, "
        "and renews without exposing credentials.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
