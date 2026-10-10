# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A plain Pydantic AI agent that explains PAP Session assertion safety."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import (
    build_session_assertion_claims,
    generate_pairwise_user_id,
)

agent = Agent(
    instructions=(
        "Use explain_session_assertion to explain PAP Session safety. Never ask "
        "for or claim to expose an assertion, key, subject, jti, or token."
    ),
)


@agent.tool_plain
def explain_session_assertion(client_id: str, token_endpoint: str) -> dict[str, Any]:
    """Build claims internally and return their non-identifying policy."""

    claims = build_session_assertion_claims(
        client_id=client_id,
        pairwise_user_id=generate_pairwise_user_id(),
        token_endpoint=token_endpoint,
    )
    return {
        "issuer_bound_to_client_id": claims.iss == client_id,
        "audience_bound_to_token_endpoint": claims.aud == token_endpoint,
        "lifetime_seconds": claims.exp - claims.iat,
        "pairwise_subject_withheld": True,
        "unique_request_id_withheld": True,
        "unsigned_assertion_withheld": True,
    }


async def main() -> None:
    """Run one didactic Session-boundary conversation."""

    result = await agent.run(
        "Explain a PAP Session assertion for client "
        "https://assistant.example/agent.json and token endpoint "
        "https://shop.example/oauth/token.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
