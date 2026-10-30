# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A plain Pydantic AI agent that explains what a PAP delegation names."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from pydantic_ai import Agent
from reactor import PluginManifest, PluginPlatform

from personal_agent_protocol import (
    PAIRWISE_USER_ID_STORES,
    DelegatedSessionSigner,
    InMemoryDelegatedKeys,
    JoseSigner,
    SessionJwtRequest,
    SqlitePairwiseUserIdStore,
    new_session_id,
    resolve_pairwise_user_id,
)

PAIRWISE_DATABASE = Path(
    os.getenv(
        "PAP_PAIRWISE_DATABASE",
        "~/.local/state/pap-examples/pairwise-user-ids.sqlite3",
    )
).expanduser()
PAIRWISE_STORE = SqlitePairwiseUserIdStore(PAIRWISE_DATABASE)
TENANT_ID = os.getenv("PAP_TENANT_ID", "example-application")
LOCAL_USER_ID = os.getenv("PAP_LOCAL_USER_ID", "example-local-user")
COMPANY_ISSUER = os.getenv("PAP_COMPANY_ISSUER", "https://shop.example")
CLIENT_ID = os.getenv("PAP_CLIENT_ID", "https://assistant.example/agent.json")


class HostPairwiseStorePlugin:
    """Expose host storage through PAP's Reactor contribution point."""

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            PAIRWISE_USER_ID_STORES,
            PAIRWISE_STORE,
            contribution_id="example-sqlite",
        )


class RecordingSigner:
    """A key from the agent's `jwks_uri`, keeping what it signed host-side."""

    def __init__(self) -> None:
        self.key = JoseSigner(ec.generate_private_key(ec.SECP256R1()), key_id="agent-key")
        self.signed: list[tuple[str, dict[str, object]]] = []

    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        self.signed.append((purpose, claims))
        return await self.key.sign(claims, purpose=purpose)


PAIRWISE_REACTOR = PluginPlatform(extension_group="pap_example.plugins")
PAIRWISE_REACTOR.register_plugin(
    PluginManifest(
        name="pap-example-pairwise-store",
        version="1",
        contribution_points=[PAIRWISE_USER_ID_STORES.id],
    ),
    HostPairwiseStorePlugin(),
)

agent = Agent(
    instructions=(
        "Use explain_delegation to explain what a PAP delegation says. Never ask "
        "for or claim to expose a delegation, key, subject, jti, or token."
    ),
)


@agent.tool_plain
async def explain_delegation() -> dict[str, Any]:
    """Have a delegation signed internally and return its non-identifying policy."""

    PAIRWISE_DATABASE.parent.mkdir(parents=True, exist_ok=True)
    pairwise_user_id = await resolve_pairwise_user_id(
        PAIRWISE_REACTOR,
        tenant_id=TENANT_ID,
        local_user_id=LOCAL_USER_ID,
        company_issuer=COMPANY_ISSUER,
    )
    # The agent's key signs a delegation the first time a User ID sends a request, and
    # the delegated key then signs that User's Session JWTs.
    signer = RecordingSigner()
    session_signer = DelegatedSessionSigner(InMemoryDelegatedKeys(), signer=signer)
    await session_signer.sign(
        SessionJwtRequest(
            method="GET",
            url=f"{COMPANY_ISSUER}/orders",
            tenant_id=TENANT_ID,
            issuer=COMPANY_ISSUER,
            client_id=CLIENT_ID,
            sid=new_session_id(),
            sub=pairwise_user_id,
        )
    )
    purpose, claims = signer.signed[0]
    said = json.dumps(claims)
    return {
        "signed_for": purpose,
        "claims": sorted(claims),
        "issuer_bound_to_client_id": claims["iss"] == CLIENT_ID,
        "lifetime_seconds": int(claims["exp"]) - int(claims["iat"]),  # type: ignore[call-overload]
        "names_no_user": "sub" not in claims and pairwise_user_id not in said,
        "names_no_company": "aud" not in claims and COMPANY_ISSUER not in said,
        "pairwise_subject_withheld": True,
        "unique_request_id_withheld": True,
        "delegation_withheld": True,
        "delegated_key_withheld": True,
    }


async def main() -> None:
    """Run one didactic delegation conversation."""

    result = await agent.run(
        "Explain what a PAP delegation says, and what it never says.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
