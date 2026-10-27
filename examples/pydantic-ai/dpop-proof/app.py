# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent that demonstrates the PAP DPoP trust boundary."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from typing import Any

from pydantic import SecretStr
from pydantic_ai import Agent

from personal_agent_protocol import (
    DpopProofRequest,
    InMemorySessionKeys,
    JoseDpopProofProvider,
    ProofError,
    verify_dpop_proof,
)


class OneUseReplayCache:
    """Minimal in-memory replay cache for this single-process example."""

    def __init__(self) -> None:
        self._keys: set[str] = set()

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        del expires_at
        if key in self._keys:
            return False
        self._keys.add(key)
        return True


agent = Agent(
    instructions=(
        "Use explain_dpop_proof to explain proof-of-possession safety. Never "
        "ask for or expose a private key, access token, proof, JWK, jti, nonce, "
        "or Session Key."
    ),
)


@agent.tool_plain
async def explain_dpop_proof(method: str, url: str) -> dict[str, Any]:
    """Create and verify a real proof, then return only its safety properties."""

    # Each Session has its own Session Key, kept by the host's key custody. Starting a
    # Session makes one; its JWK thumbprint (RFC 7638) names the Session (§4.3).
    provider = JoseDpopProofProvider(InMemorySessionKeys())
    issuer = "https://company.example"
    session_key = await provider.new_session_key(tenant_id="example-tenant", issuer=issuer)
    other_session = await provider.new_session_key(tenant_id="example-tenant", issuer=issuer)
    access_token = SecretStr("host-only-example-token")
    request = DpopProofRequest(
        method=method,
        url=url,
        tenant_id="example-tenant",
        issuer=issuer,
        session_key=session_key,
        access_token=access_token,
        nonce="host-only-company-nonce",
    )
    proof = await provider.create(request)
    replay_cache = OneUseReplayCache()
    verified = await verify_dpop_proof(
        proof,
        method=method,
        url=url,
        access_token=access_token,
        nonce="host-only-company-nonce",
        replay_cache=replay_cache,
        now=datetime.now(timezone.utc),
    )
    replay_rejected = False
    try:
        await verify_dpop_proof(
            proof,
            method=method,
            url=url,
            access_token=access_token,
            nonce="host-only-company-nonce",
            replay_cache=replay_cache,
            now=datetime.now(timezone.utc),
        )
    except ProofError as error:
        replay_rejected = error.code == "invalid_dpop_proof"

    # A Session that has ended has its key discarded: it is never used again.
    await provider.discard_session_key(
        tenant_id="example-tenant", issuer=issuer, session_key=session_key
    )
    try:
        await provider.create(request)
        discarded_key_refused = False
    except ProofError as error:
        discarded_key_refused = error.code == "unknown_session_key"

    return {
        "algorithm": "ES256",
        "method_bound": True,
        "url_bound_without_query_or_fragment": True,
        "access_token_bound": True,
        "nonce_checked": True,
        "signature_verified": bool(verified.key_thumbprint),
        "proof_key_names_the_session": verified.key_thumbprint == session_key,
        "one_key_per_session": other_session != session_key,
        "replay_rejected": replay_rejected,
        "discarded_session_key_refused": discarded_key_refused,
        "proof_withheld": True,
        "access_token_withheld": True,
        "key_material_withheld": True,
    }


async def main() -> None:
    """Run one didactic DPoP conversation."""

    result = await agent.run(
        "Explain how PAP protects a POST to "
        "https://api.company.example/orders?draft=true with DPoP.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
