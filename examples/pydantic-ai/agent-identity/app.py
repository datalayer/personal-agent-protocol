# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A plain Pydantic AI agent that verifies PAP personal-agent identity."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import AgentIdentityClient

agent = Agent(
    instructions=(
        "Use inspect_pap_agent before describing a personal-agent identity. "
        "Report only the verified public summary returned by the tool."
    ),
)


@agent.tool_plain
async def inspect_pap_agent(client_id: str) -> dict[str, Any]:
    """Return identity and signing policy without JWK coordinates."""

    async with AgentIdentityClient() as client:
        metadata = await client.fetch_metadata(client_id)
        keys = await client.fetch_jwks(client_id)
    algorithms = sorted({key.alg or ("ES256" if key.kty == "EC" else "RS256") for key in keys.keys})
    return {
        "client_id": metadata.client_id,
        "client_name": metadata.client_name,
        "redirect_count": len(metadata.redirect_uris),
        "signing_algorithms": algorithms,
        "extensions": {
            name: descriptor.version for name, descriptor in metadata.extensions.items()
        },
    }


async def main() -> None:
    """Ask the agent about a PAP client ID supplied on standard input."""

    client_id = input("PAP client ID: ").strip()
    result = await agent.run(
        f"Verify and explain the personal agent at {client_id}.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
