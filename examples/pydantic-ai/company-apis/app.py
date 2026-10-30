# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent reaching a company's OpenAPI API and its MCP server over PAP.

Atlas, Ada's personal agent, discovers Manzanita Outfitters, which lists two APIs
in its `poppy.json`: an OpenAPI API, called with the account's access token, and an
MCP server, called with a token issued for that server's URL alone. Every request
carries the Session header. Signed out, the API answers `insufficient_scope` with
the scope it needs; once Ada signs in on Manzanita's page, Atlas reads her orders
through both and proposes the same exchange through both — a `202` with an
operation from the API, an `operation` from the MCP tool, one operation. Nothing is
done until Ada approves it.

The MCP token is a refresh with `resource` set to the server's URL (§4.5, §7): the
refresh token stays in the host, and the token is used at that server alone.

The tool hands the model statuses, scopes, tool names, the orders, and the
company's summaries; the tokens, the device code, and every Session JWT stay in the
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
    SessionClient,
    SessionHttpClient,
)
from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
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
        "through a company's OpenAPI API and its MCP server. An operation is "
        "not done until Ada approves it. Never expose tokens, codes, or Session JWTs."
    ),
)


@agent.tool_plain
async def run_company_apis() -> dict[str, Any]:
    """Read and propose through Manzanita's API and MCP server; return safe evidence."""

    return {**await _journey(), "tokens_codes_and_session_jwts_withheld": True}


async def _journey() -> dict[str, Any]:
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    shop, _ = manzanita(network, clock)
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    api = ApiClient(transport=SessionHttpClient(reactor=reactor, http_client=http))

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
    base = description.removesuffix("/openapi.json")
    orders_url = f"{base}/orders"
    exchange_url = f"{base}/orders/ord_7Hk2/exchanges"

    # A new, signed-out Session. Signed out, the API answers `insufficient_scope` and
    # names the scope it needs.
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        tenant_id=TENANT,
    )
    try:
        await api.call("GET", orders_url, session=session)
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
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await shop.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    if not (done.token is not None and done.refresh_token_reference is not None):
        raise RuntimeError("the example world is incomplete")
    signed_in = done.token

    # The OpenAPI API, with the access token: a read, then `approval_required` (403).
    read = await api.call("GET", orders_url, session=session, token=signed_in)
    proposed = await api.call("POST", exchange_url, session=session, token=signed_in, body={})
    if proposed.operation is None:
        raise RuntimeError("the example world is incomplete")

    # The MCP server, with a token issued for its URL alone (§4.5, §7): a refresh with
    # `resource`. Its protected resource metadata names that URL and the Company's issuer.
    served = await fetch_mcp_server_metadata(http, mcp_server.url, issuer=metadata.issuer)
    refreshed = await RefreshTokenClient(reactor=reactor, http_client=http).token_for_mcp(
        done.refresh_token_reference,
        context=RefreshTokenContext(
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=atlas.client_id,
            tenant_id=TENANT,
            revocation_endpoint=metadata.revocation_endpoint,
        ),
        server=served,
    )
    if refreshed.token is None:
        raise RuntimeError("the example world is incomplete")
    mcp_token = refreshed.token
    mcp = McpClient(
        http_client=http, url=mcp_server.url, session=session, reactor=reactor, token=mcp_token
    )
    tools = [tool["name"] for tool in await mcp.list_tools()]
    listed = await mcp.call_tool("list_orders")
    through_mcp = await mcp.call_tool("exchange_jacket")
    if through_mcp.operation is None:
        raise RuntimeError("the example world is incomplete")

    # The token is for the MCP server only: the company refuses it at the API (§4.5).
    try:
        await api.call("GET", orders_url, session=session, token=mcp_token)
        at_the_api = "sent"
    except (TransportError, ApiError) as error:
        at_the_api = error.code
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
            "approval_required_status": proposed.status,
            "operation": {
                "revision": proposed.operation.revision,
                "summary": proposed.operation.summary,
                "expires_at": proposed.operation.expires_at.isoformat(),
            },
        },
        "mcp": {
            "token_type": mcp_token.token_type,
            "token_is_for_the_server_alone": mcp_token.resource == mcp_server.url,
            "tools": tools,
            "list_orders": listed.text,
            "exchange_jacket": through_mcp.text,
            "exchange_is_an_error_result": through_mcp.is_error,
        },
        "one_operation_across_interfaces": (
            through_mcp.operation.operation_id == proposed.operation.operation_id
        ),
        "mcp_token_refused_at_the_api": at_the_api,
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
