# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A plain Pydantic AI agent that explains PAP Session assertion safety."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from pydantic_ai import Agent
from reactor import PluginManifest, PluginPlatform

from personal_agent_protocol import (
    PAIRWISE_USER_ID_STORES,
    SqlitePairwiseUserIdStore,
    build_session_assertion_claims,
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
        "Use explain_session_assertion to explain PAP Session safety. Never ask "
        "for or claim to expose an assertion, key, subject, jti, or token."
    ),
)


@agent.tool_plain
async def explain_session_assertion() -> dict[str, Any]:
    """Build claims internally and return their non-identifying policy."""

    PAIRWISE_DATABASE.parent.mkdir(parents=True, exist_ok=True)
    pairwise_user_id = await resolve_pairwise_user_id(
        PAIRWISE_REACTOR,
        tenant_id=TENANT_ID,
        local_user_id=LOCAL_USER_ID,
        company_issuer=COMPANY_ISSUER,
    )
    claims = build_session_assertion_claims(
        client_id=CLIENT_ID,
        pairwise_user_id=pairwise_user_id,
        issuer=COMPANY_ISSUER,
    )
    return {
        "issuer_bound_to_client_id": claims.iss == CLIENT_ID,
        "audience_bound_to_the_issuer": claims.aud == COMPANY_ISSUER,
        "lifetime_seconds": claims.exp - claims.iat,
        "stable_pairwise_subject": True,
        "pairwise_subject_withheld": True,
        "unique_request_id_withheld": True,
        "unsigned_assertion_withheld": True,
    }


async def main() -> None:
    """Run one didactic Session-boundary conversation."""

    result = await agent.run(
        "Explain how this host creates a safe PAP Session assertion.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
