# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent reaching a company's OpenAPI API and its MCP server over PAP.

Atlas, Ada's personal agent, discovers Manzanita Outfitters, which lists two APIs
in its `poppy.json`: an OpenAPI API, called with the Session's DPoP-bound token,
and an MCP server, called with a Bearer token issued for that server's URL alone.
Signed out, the API names the scope signing in would give; once Ada signs in on
Manzanita's page, Atlas reads her orders through both and proposes the same
exchange through both — a `202` with an operation from the API, an `operation`
from the MCP tool, one record. Nothing is done until Ada confirms it.

The tool hands the model statuses, scopes, tool names, the orders, and the
company's summaries; the tokens, the device code, and every proof stay in the
host.
"""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import (
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    SessionClient,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.apis import ApiClient, ApiError, known_apis, openapi_url
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import DOMAIN, manzanita
from personal_agent_protocol.errors import TransportError
from personal_agent_protocol.mcp import McpClient, fetch_mcp_server_metadata, mcp_api

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"

agent = Agent(
    instructions=(
        "Use run_company_apis to show how Ada's personal agent reads and proposes "
        "through a company's OpenAPI API and its MCP server. A proposed operation is "
        "not done until Ada confirms it. Never expose tokens, codes, or proofs."
    ),
)


@agent.tool_plain
async def run_company_apis() -> dict[str, Any]:
    """Read and propose through Manzanita's API and MCP server; return safe evidence."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    shop, _ = manzanita(network, clock)
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    api = ApiClient(transport=DpopHttpClient(reactor=reactor, http_client=http))

    # Discovery: the APIs this SDK knows (`openapi`, `mcp`), unknown types skipped.
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    mcp_server = mcp_api(company.document)
    description = openapi_url(company.document)
    if not (
        metadata is not None
        and metadata.device_authorization_endpoint is not None
        and mcp_server is not None
        and description is not None
    ):
        raise RuntimeError("the example world is incomplete")
    who = {"tenant_id": TENANT, "pairwise_user_id": PAIRWISE, "issuer": metadata.issuer}
    base = description.removesuffix("/openapi.json")
    orders_url = f"{base}/orders"
    exchange_url = f"{base}/orders/ord_7Hk2/exchanges"

    # Signed out: the API refuses and says which scope signing in would give.
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=TENANT,
    )
    try:
        await api.call("GET", orders_url, token=session, **who)
        signed_out = {"status": "answered"}
    except ApiError as error:
        signed_out = {"error": error.code, **(error.details or {})}

    # Ada signs Atlas in on Manzanita's own page (Device Sign-In).
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
        organization=company.document.organization,
        poppy_domains=metadata.poppy_domains,
    )
    await shop.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    if not (done.token is not None and done.account_token_reference is not None):
        raise RuntimeError("the example world is incomplete")
    signed_in = done.token

    # The OpenAPI API, with the Session's DPoP-bound token: a read, then a proposal (202).
    read = await api.call("GET", orders_url, token=signed_in, **who)
    proposed = await api.call("POST", exchange_url, token=signed_in, body={}, **who)
    if proposed.operation is None:
        raise RuntimeError("the example world is incomplete")

    # The MCP server, with a token issued for its URL alone: DPoP when its protected
    # resource metadata says it supports DPoP, Bearer otherwise (the Account Token
    # rotated and stored in the host, never returned).
    served = await fetch_mcp_server_metadata(http, mcp_server.url, issuer=metadata.issuer)
    bearer = await AccountTokenClient(reactor=reactor, http_client=http).token_for_mcp(
        done.account_token_reference,
        context=AccountTokenContext(
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=atlas.client_id,
            tenant_id=TENANT,
            pairwise_user_id=PAIRWISE,
            revocation_endpoint=metadata.revocation_endpoint,
        ),
        session_id=signed_in.session_id,
        resource=mcp_server.url,
        dpop=served.supports_dpop,
    )
    if bearer.token is None:
        raise RuntimeError("the example world is incomplete")
    mcp = McpClient(
        http_client=http, token=bearer.token, url=mcp_server.url, reactor=reactor, who=who
    )
    tools = [tool["name"] for tool in await mcp.list_tools()]
    listed = await mcp.call_tool("list_orders")
    through_mcp = await mcp.call_tool("exchange_jacket")
    if through_mcp.operation is None:
        raise RuntimeError("the example world is incomplete")

    # The token is for the MCP server only: the SDK never sends a Bearer token to the API,
    # and the company refuses a DPoP one issued for the MCP server there (§4.3).
    try:
        await api.call("GET", orders_url, token=bearer.token, **who)
        bearer_at_the_api = "sent"
    except (TransportError, ApiError) as error:
        bearer_at_the_api = error.code
    await http.aclose()

    return {
        "apis": [
            {"type": entry.type, "description": entry.description}
            for entry in known_apis(company.document)
        ],
        "signed_out_read": signed_out,
        "granted_scopes": list(done.granted_scopes),
        "openapi": {
            "read_status": read.status,
            "orders": read.body["orders"] if isinstance(read.body, dict) else None,
            "proposal_status": proposed.status,
            "proposal": {
                "state": proposed.operation.state,
                "revision": proposed.operation.revision,
                "summary": proposed.operation.summary,
                "user_approval_required": proposed.operation.user_approval_required,
            },
        },
        "mcp": {
            "bearer_status": bearer.status,
            "bearer_token_type": bearer.token.token_type,
            "tools": tools,
            "list_orders": listed.text,
            "exchange_jacket": through_mcp.text,
            "proposal_state": through_mcp.operation.state,
        },
        "one_operation_across_channels": through_mcp.operation == proposed.operation,
        "bearer_refused_at_the_api": bearer_at_the_api,
        "tokens_codes_and_proofs_withheld": True,
    }


async def main() -> None:
    """Ask the agent to explain both channels."""

    result = await agent.run(
        "How does Atlas read Ada's orders and propose an exchange through Manzanita's "
        "API and its MCP server?",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
