# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A service of the company at a URL of its own: listed, issued for, verified (§4.5, §7)."""

from __future__ import annotations

import dataclasses

import pytest

from personal_agent_protocol.accounts import RefreshTokenClient
from personal_agent_protocol.company import CompanyConfig, resource_metadata_url
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.errors import PersonalAgentProtocolError
from personal_agent_protocol.models import ProtectedResourceMetadata

from .test_company_end_to_end import World
from .test_company_refusals import signed_in
from .test_mcp_and_web import MCP, context

#: The company's MCP server on a host of its own.
ELSEWHERE = "https://mcp.manzanita.example/mcp"


def world_with(*servers: str, **options: object) -> World:
    world = World()
    world.shop, world.plugin = manzanita(
        world.network,
        world.clock,
        config=dataclasses.replace(CONFIG, resource_servers=servers, **options),  # type: ignore[arg-type]
    )
    return world


async def token_for(world: World, resource: str):  # type: ignore[no-untyped-def]
    result = await RefreshTokenClient(reactor=world.reactor, http_client=world.http).token_for_mcp(
        world.refresh_reference,  # type: ignore[arg-type]
        context=context(world),
        server=ProtectedResourceMetadata(resource=resource),
    )
    assert result.status == "signed_in" and result.token is not None
    return result.token


def test_a_company_lists_none_unless_configured() -> None:
    assert CONFIG.resource_servers == ()


@pytest.mark.asyncio
async def test_without_any_the_issuer_lists_and_issues_as_before() -> None:
    world = World()
    await signed_in(world)
    listed = world.company.oauth_metadata.protected_resources  # type: ignore[union-attr]
    assert ELSEWHERE not in listed
    with pytest.raises(PersonalAgentProtocolError) as refused:
        await token_for(world, ELSEWHERE)
    assert refused.value.code == "invalid_target"


@pytest.mark.asyncio
async def test_the_issuer_lists_it_and_issues_a_bearer_token_for_it() -> None:
    """§3.2: `protected_resources` MAY list the company's MCP servers. §4.5: a token
    request names one `resource` and gets a token for that service; §7: the token's
    `resource` is the MCP server's `url`."""

    world = world_with(ELSEWHERE)
    default = await signed_in(world)
    listed = world.company.oauth_metadata.protected_resources  # type: ignore[union-attr]
    assert listed[0] == "https://manzanita.example" and ELSEWHERE in listed and MCP in listed

    token = await token_for(world, ELSEWHERE)
    assert (token.resource, token.token_type) == (ELSEWHERE, "Bearer")

    issued = await world.shop.access_token_for(token.access_token.get_secret_value(), ELSEWHERE)
    assert issued is not None
    assert (issued.account_id, issued.client_id) == ("acct_ada", world.atlas.client_id)
    assert set(issued.scopes) == {"orders:read", "orders:write"}

    # §4.5: the company accepts a token issued for a `resource` only at that service.
    assert (
        await world.shop.access_token_for(default.access_token.get_secret_value(), ELSEWHERE)
        is None
    )
    own = await token_for(world, MCP)
    assert await world.shop.access_token_for(own.access_token.get_secret_value(), ELSEWHERE) is None
    assert await world.shop.access_token_for("invented", ELSEWHERE) is None
    with pytest.raises(ValueError):
        await world.shop.access_token_for(
            token.access_token.get_secret_value(), "https://other.example/mcp"
        )


@pytest.mark.asyncio
async def test_a_token_stops_working_there_when_it_expires() -> None:
    world = world_with(ELSEWHERE)
    await signed_in(world)
    token = await token_for(world, ELSEWHERE)
    world.clock.advance(int(CONFIG.access_token_lifetime.total_seconds()) + 1)
    assert (
        await world.shop.access_token_for(token.access_token.get_secret_value(), ELSEWHERE) is None
    )


@pytest.mark.asyncio
async def test_it_gets_bearer_tokens_from_an_issuer_that_binds_its_own() -> None:
    """§7: a company whose MCP server doesn't accept DPoP returns Bearer tokens for it."""

    world = world_with(ELSEWHERE, dpop_binding="optional")
    await signed_in(world)
    assert (await token_for(world, ELSEWHERE)).token_type == "Bearer"


def test_its_metadata_is_where_rfc_9728_puts_it() -> None:
    assert resource_metadata_url(ELSEWHERE) == (
        "https://mcp.manzanita.example/.well-known/oauth-protected-resource/mcp"
    )
    assert resource_metadata_url("https://mcp.manzanita.example") == (
        "https://mcp.manzanita.example/.well-known/oauth-protected-resource"
    )


@pytest.mark.parametrize(
    "servers",
    [
        ("http://mcp.manzanita.example/mcp",),
        ("https://mcp.manzanita.example/mcp?x=1",),
        ("https://mcp.manzanita.example/mcp#x",),
        ("https://MCP.manzanita.example/mcp",),
        ("https://manzanita.example",),
        ("https://manzanita.example/mcp",),
        (ELSEWHERE, ELSEWHERE),
    ],
)
def test_each_is_an_https_url_of_its_own_named_once(servers: tuple[str, ...]) -> None:
    with pytest.raises(ValueError):
        dataclasses.replace(CONFIG, resource_servers=servers)


def test_a_company_with_no_issuer_has_none() -> None:
    with pytest.raises(ValueError):
        CompanyConfig(
            name="Open",
            domain="open.example",
            scopes=(),
            agent_description="Anything",
            oauth=False,
            device=False,
            direct=False,
            operations=False,
            resource_servers=(ELSEWHERE,),
        )
