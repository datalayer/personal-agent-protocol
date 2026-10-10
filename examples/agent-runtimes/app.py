# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A small Agent Runtimes application that discovers PAP companies safely.

Run with::

    loop apps run examples/agent-runtimes/app.py

The PAP SDK performs real HTTPS discovery and issuer binding. The tool returns
only a verified public summary. Authorization URLs, callbacks, proofs, and
tokens are deliberately absent from the agent surface.
"""

from __future__ import annotations

from typing import Any

from agent_runtimes.loop.apps import Application

from personal_agent_protocol import DiscoveryClient

app = Application(
    id="pap-company-inspector",
    name="PAP Company Inspector",
    description="Inspect a company's verified Personal Agent Protocol capabilities.",
    kind="chat",
    agent="example-blank:0.0.1",
    instructions=(
        "Help the user understand a company's Personal Agent Protocol support. "
        "Call inspect_pap_company before describing a domain. Treat its result "
        "as public capability metadata, never as authorization."
    ),
)


@app.tool(does="read")
async def inspect_pap_company(domain: str) -> dict[str, Any]:
    """Discover a DNS domain and return its verified, non-secret PAP summary."""

    async with DiscoveryClient() as client:
        company = await client.discover(domain)

    document = company.document
    auth = document.auth
    sign_in = []
    if auth is not None:
        sign_in = [
            name
            for name in ("direct", "device", "mediated")
            if getattr(auth, name) is not None
        ]
    return {
        "organization": {
            "name": document.organization.name,
            "domain": document.organization.domain,
        },
        "protocol_version": document.protocol_version,
        "issuer": auth.issuer if auth is not None else None,
        "sign_in": sign_in,
        "agent_protocols": (
            [protocol.type for protocol in document.agent.protocols]
            if document.agent is not None
            else []
        ),
        "apis": [api.type for api in document.apis],
        "browser_session": bool(
            document.web is not None and document.web.browser_session_endpoint
        ),
        "extensions": sorted(document.extensions),
    }
