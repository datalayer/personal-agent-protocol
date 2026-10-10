# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent that demonstrates the PAP DPoP trust boundary."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from pydantic_ai import Agent

from personal_agent_protocol import (
    DpopKeyMaterial,
    DpopProofRequest,
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
        "or key thumbprint."
    ),
)


@agent.tool_plain
async def explain_dpop_proof(method: str, url: str) -> dict[str, Any]:
    """Create and verify a real proof, then return only its safety properties."""

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = jwt.algorithms.ECAlgorithm.to_jwk(
        private_key.public_key(), as_dict=True
    )

    async def resolve_key(_: DpopProofRequest) -> DpopKeyMaterial:
        return DpopKeyMaterial(private_key=private_key, public_jwk=public_jwk)

    provider = JoseDpopProofProvider(resolve_key)
    access_token = SecretStr("host-only-example-token")
    request = DpopProofRequest(
        method=method,
        url=url,
        tenant_id="example-tenant",
        subject="host-only-pairwise-subject",
        issuer="https://company.example",
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

    return {
        "algorithm": "ES256",
        "method_bound": True,
        "url_bound_without_query_or_fragment": True,
        "access_token_bound": True,
        "nonce_checked": True,
        "signature_verified": bool(verified.key_thumbprint),
        "replay_rejected": replay_rejected,
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
