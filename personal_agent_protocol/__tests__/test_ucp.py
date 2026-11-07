# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The UCP extension, version 1, both sides in one process: Manzanita is the test shop.

`src/__tests__/ucp.test.mjs` ports it.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import httpx
import pytest

from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.extensions import negotiate_extensions, parse_extensions_header
from personal_agent_protocol.models import DiscoveryDocument
from personal_agent_protocol.transport import session_headers
from personal_agent_protocol.ucp import (
    UCP_AGENT_HEADER,
    UcpClient,
    UcpError,
    UcpProfile,
    fetch_ucp_profile,
    speaks_ucp,
    ucp_agent_header,
    ucp_profile_url,
    ucp_scopes,
)

from .test_company_end_to_end import World
from .test_company_refusals import signed_in

PLATFORM = "https://atlas.example/ucp/profile.json"


async def _client(world: World) -> tuple[Any, UcpClient, str]:
    session = await world.signed_out_session()
    profile = await fetch_ucp_profile(world.http, world.company)
    endpoint = profile.endpoint()
    assert endpoint == "https://manzanita.example/ucp"
    return (
        session,
        UcpClient(transport=world.transport, platform_profile=PLATFORM, profile=profile),
        endpoint,
    )


@pytest.mark.asyncio
async def test_a_company_that_speaks_ucp_lists_it_and_serves_its_profile_on_its_domain() -> None:
    """`ucp` in `extensions`; the UCP profile at the validated domain's `/.well-known/ucp`;
    identity linking's scopes in `scopes_supported`, Direct Sign-In and `private_key_jwt`
    offered (UCP extension 2, 3, 4)."""

    world = World()
    await world.signed_out_session()
    document = world.company.document
    assert speaks_ucp(document)
    assert document.extensions["ucp"][0].version == "1"
    assert ucp_profile_url(world.company) == "https://manzanita.example/.well-known/ucp"
    profile = await fetch_ucp_profile(world.http, world.company)
    assert profile.offers("dev.ucp.shopping.catalog.search") and profile.offers(
        "dev.ucp.shopping.order"
    )
    metadata = world.company.oauth_metadata
    assert metadata is not None
    assert profile.identity_linking_scopes == ("orders:read",)
    assert set(profile.identity_linking_scopes) <= set(metadata.scopes_supported or [])
    assert metadata.offers_direct
    assert "private_key_jwt" in world.shop.oauth_metadata()["token_endpoint_auth_methods_supported"]
    assert ucp_scopes(profile, ("orders:read",)) == ()
    # A company that doesn't speak UCP lists nothing, and its profile isn't fetched.
    world = World()
    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, ucp=False)
    )
    await world.signed_out_session()
    assert not speaks_ucp(world.company.document)
    with pytest.raises(UcpError) as raised:
        await fetch_ucp_profile(world.http, world.company)
    assert raised.value.code == "ucp_not_offered"
    assert (await world.http.get("https://manzanita.example/.well-known/ucp")).status_code == 404
    # Sign-in and identity linking are one: Direct Sign-In (UCP extension 4).
    with pytest.raises(ValueError):
        replace(CONFIG, direct=False)


@pytest.mark.asyncio
async def test_a_ucp_profile_is_never_fetched_through_a_redirect_or_used_malformed() -> None:
    """The Personal Agent MUST NOT follow a redirect from the profile URL, nor use a profile
    from another host (UCP extension 3)."""

    world = World()
    await world.signed_out_session()
    answers = {
        "redirect": httpx.Response(302, headers={"location": "https://cdn.example.net/ucp"}),
        "malformed": httpx.Response(200, json={"ucp": {"services": {}}}),
        "missing": httpx.Response(404, json={"error": "not_found"}),
    }
    for name, answer in answers.items():
        http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _, a=answer: a))
        with pytest.raises(UcpError) as raised:
            await fetch_ucp_profile(http, world.company)
        expected = {
            "redirect": "redirect_refused",
            "malformed": "invalid_ucp_profile",
            "missing": "ucp_profile_unavailable",
        }[name]
        assert raised.value.code == expected


def test_the_ucp_agent_header_names_one_https_platform_profile() -> None:
    """The platform profile describes the Personal Agent, never a User: one HTTPS URL
    (UCP extension 3)."""

    assert ucp_agent_header(PLATFORM) == f'profile="{PLATFORM}"'
    for bad in ("http://atlas.example/p", 'https://atlas.example/"p"', "https://a.example/ p"):
        with pytest.raises(ValueError):
            ucp_agent_header(bad)
    profile = UcpProfile.model_validate(
        {
            "version": "2026-04-08",
            "services": {"dev.ucp.shopping": [{"transport": "mcp", "endpoint": "https://x"}]},
        }
    )
    assert profile.endpoint() is None and profile.identity_linking_scopes == ()


@pytest.mark.asyncio
async def test_a_signed_out_ucp_request_carries_the_session_header_and_the_platform_profile() -> (
    None
):
    """A UCP request in this extension carries `UCP-Agent` and the Session header, and is
    signed out without an access token; the Company verifies the header before using it
    (UCP extension 4, 8)."""

    world = World()
    session, client, endpoint = await _client(world)
    seen: list[httpx.Request] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return await original(request)

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    found = await client.call(
        "POST", f"{endpoint}/catalog/search", session=session, body={"query": "stormline"}
    )
    assert [product["id"] for product in found["products"]] == [
        "stormline-insulated-m",
        "stormline-insulated-l",
    ]
    sent = seen[-1]
    assert sent.headers[UCP_AGENT_HEADER] == f'profile="{PLATFORM}"'
    assert "poppy-session" in sent.headers and "authorization" not in sent.headers
    # The company knows the Session now: its header was verified.
    assert await world.shop.end_session(session.client_id, session.sid)


@pytest.mark.asyncio
async def test_ucp_without_this_extension_and_its_refusals() -> None:
    """A Company MUST NOT require a UCP platform to implement this protocol: a request
    without the Session header is UCP used independently, served signed out; one without a
    platform profile is UCP's `invalid_profile_url`; a token without the Session header is no
    token this protocol's sign-in gave for UCP (UCP extension 2, 4)."""

    world = World()
    await world.signed_out_session()
    url = "https://manzanita.example/ucp/catalog/search"
    agent = {UCP_AGENT_HEADER: ucp_agent_header(PLATFORM)}
    independent = await world.http.post(url, json={"query": "shell"}, headers=agent)
    assert independent.status_code == 200
    assert [p["id"] for p in independent.json()["products"]] == ["trailhead-shell-m"]
    anonymous = await world.http.post(url, json={"query": ""})
    assert (anonymous.status_code, anonymous.json()["code"]) == (400, "invalid_profile_url")
    token = await world.http.post(
        url, json={}, headers={**agent, "Authorization": "Bearer at_copied"}
    )
    assert (token.status_code, token.json()["code"]) == (401, "invalid_token")


@pytest.mark.asyncio
async def test_orders_need_identity_linking_through_this_protocols_sign_in() -> None:
    """Identity linking is this protocol's Direct or Device Sign-In at the selected issuer:
    signed out, `identity_required` with the scopes from the profile; a token without them,
    `insufficient_scope`; with them, the orders (UCP extension 4)."""

    world = World()
    session, client, endpoint = await _client(world)
    with pytest.raises(UcpError) as signed_out:
        await client.call("GET", f"{endpoint}/orders", session=session)
    assert signed_out.value.code == "identity_required"
    assert signed_out.value.details == {"scopes": ["orders:read"]}
    narrow = await signed_in(world, ("orders:write",))
    assert world.session is not None
    with pytest.raises(UcpError) as lacking:
        await client.call("GET", f"{endpoint}/orders", session=world.session, token=narrow)
    assert lacking.value.code == "insufficient_scope"
    assert lacking.value.details == {"scope": "orders:read"}
    token = await signed_in(world, ("orders:read",))
    assert token.token_type == "Bearer"
    orders = await client.call("GET", f"{endpoint}/orders", session=world.session, token=token)
    assert orders["orders"][0]["order_id"]


@pytest.mark.asyncio
async def test_session_errors_at_ucp_endpoints_are_ucp_responses() -> None:
    """`session_ended` and `invalid_session` come back as UCP responses, HTTP 400 with `code`
    naming them; the Personal Agent starts a new Session once for `session_ended`, and stops
    for `invalid_session` (UCP extension 9)."""

    world = World()
    session, client, endpoint = await _client(world)
    await client.call("POST", f"{endpoint}/catalog/search", session=session, body={})
    first = session.sid
    assert await world.shop.end_session(session.client_id, session.sid)
    await client.call("POST", f"{endpoint}/catalog/search", session=session, body={})
    assert session.sid != first
    url = f"{endpoint}/catalog/search"
    headers = await session_headers(
        world.reactor, "POST", "https://elsewhere.example/", session=session, token=None
    )
    refused = await world.http.post(
        url, json={}, headers={**headers, UCP_AGENT_HEADER: ucp_agent_header(PLATFORM)}
    )
    assert (refused.status_code, refused.json()["code"]) == (400, "invalid_session")


@pytest.mark.asyncio
async def test_a_personal_agent_declares_ucp_in_poppy_extensions() -> None:
    """A Personal Agent that supports this extension SHOULD declare `"ucp";v="1"` in
    `Poppy-Extensions` (UCP extension 2)."""

    world = World()
    await world.signed_out_session()
    declared = negotiate_extensions(
        world.company.document.extensions, supported={"ucp": "1", "operations": "2"}
    )
    assert declared["ucp"] == "1"
    session = await world.signed_out_session()
    session.extensions = declared
    headers = await session_headers(
        world.reactor, "GET", "https://manzanita.example/", session=session, token=None
    )
    assert parse_extensions_header(headers["Poppy-Extensions"])["ucp"] == "1"
    assert DiscoveryDocument.model_validate(world.shop.discovery_document()).extension("ucp", "1")
