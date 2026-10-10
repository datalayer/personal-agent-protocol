# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A plain Pydantic AI agent that explains the Direct Sign-In boundary."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import build_direct_sign_in_request

agent = Agent(
    instructions=(
        "Use explain_direct_sign_in to explain the trusted browser boundary. "
        "Never request or expose an authorization URL, state, verifier, code, proof, or token."
    ),
)


@agent.tool_plain
def explain_direct_sign_in(
    authorization_endpoint: str,
    issuer: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str],
) -> dict[str, Any]:
    """Create protected authorization material and return safe policy only."""

    request = build_direct_sign_in_request(
        authorization_endpoint=authorization_endpoint,
        issuer=issuer,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=scopes,
    )
    return {
        "requested_scopes": request.scopes,
        "pkce_method": "S256",
        "random_state": True,
        "user_owned_browser_required": True,
        "authorization_url_withheld": True,
        "state_withheld": True,
        "code_verifier_withheld": True,
    }


async def main() -> None:
    """Run one didactic Direct Sign-In boundary conversation."""

    result = await agent.run(
        "Explain Direct Sign-In for https://assistant.example/agent.json against "
        "https://shop.example/oauth/authorize, redirecting to "
        "https://assistant.example/callback with poppy:read scope.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
