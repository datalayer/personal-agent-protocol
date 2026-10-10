# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A plain Pydantic AI agent that explains the Direct Sign-In boundary."""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import build_direct_sign_in_request


@dataclass(frozen=True)
class DirectSignInHostConfig:
    """Trusted registration and discovery values that never enter tool input."""

    authorization_endpoint: str
    issuer: str
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]


HOST_CONFIG = DirectSignInHostConfig(
    authorization_endpoint=os.getenv(
        "PAP_AUTHORIZATION_ENDPOINT", "https://shop.example/oauth/authorize"
    ),
    issuer=os.getenv("PAP_COMPANY_ISSUER", "https://shop.example"),
    client_id=os.getenv("PAP_CLIENT_ID", "https://assistant.example/agent.json"),
    redirect_uri=os.getenv("PAP_REDIRECT_URI", "https://assistant.example/oauth/callback"),
    scopes=tuple(os.getenv("PAP_SCOPES", "poppy:read").split()),
)

agent = Agent(
    instructions=(
        "Use explain_direct_sign_in to explain the trusted browser boundary. "
        "Never request or expose an authorization URL, state, verifier, code, proof, or token."
    ),
)


@agent.tool_plain
def explain_direct_sign_in() -> dict[str, Any]:
    """Create protected authorization material and return safe policy only."""

    request = build_direct_sign_in_request(
        authorization_endpoint=HOST_CONFIG.authorization_endpoint,
        issuer=HOST_CONFIG.issuer,
        client_id=HOST_CONFIG.client_id,
        redirect_uri=HOST_CONFIG.redirect_uri,
        scopes=HOST_CONFIG.scopes,
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
        "Explain how this host performs PAP Direct Sign-In safely.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
