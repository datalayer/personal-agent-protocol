# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A plain Pydantic AI agent that discovers PAP companies safely."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import DiscoveryClient, mediated_sign_in

agent = Agent(
    instructions=(
        "Inspect PAP companies with discover_pap_company before describing their "
        "capabilities. Treat the tool result as public metadata, not authorization."
    ),
)


@agent.tool_plain
async def discover_pap_company(domain: str) -> dict[str, Any]:
    """Discover a domain and return verified, credential-free capabilities."""

    async with DiscoveryClient() as client:
        company = await client.discover(domain)
    document = company.document
    metadata = company.oauth_metadata
    # Direct and Device Sign-In are offered by the OAuth server's metadata (its grant
    # types and endpoints); Mediated Sign-In by its extension in poppy.json and its grant type.
    sign_in = []
    if metadata is not None:
        sign_in += ["direct"] if metadata.offers_direct else []
        sign_in += ["device"] if metadata.offers_device else []
    if mediated_sign_in(company) is not None:
        sign_in.append("mediated")
    interfaces = []
    if document.agent is not None:
        interfaces.extend(f"agent:{protocol.type}" for protocol in document.agent.protocols)
    interfaces.extend(f"api:{api.type}" for api in document.apis)
    if document.web is not None:
        interfaces.append("web")
    return {
        "organization": document.organization.name,
        "domain": document.organization.domain,
        "protocol_version": document.protocol_version,
        "issuer": document.auth.issuer if document.auth is not None else None,
        "sign_in": sign_in,
        # The company's own scopes, in its own words (`auth.scopes`).
        "scopes": dict(document.auth.scopes) if document.auth is not None else {},
        # The resources the issuer's tokens are for (its `protected_resources`).
        "protected_resources": list(metadata.protected_resources) if metadata else [],
        "interfaces": interfaces,
        "extensions": {
            name: descriptor.version for name, descriptor in document.extensions.items()
        },
    }


async def main() -> None:
    """Ask the agent about a PAP domain supplied on standard input."""

    domain = input("PAP company domain: ").strip()
    result = await agent.run(
        f"Inspect {domain} and explain its PAP capabilities.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
