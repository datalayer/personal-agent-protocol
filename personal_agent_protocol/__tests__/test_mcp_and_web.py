# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""One operation through MCP and the website; a token for the MCP server only there."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from personal_agent_protocol import BrowserSessionClient, PapSession
from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.demo.kit import ControlledBrowser, personal_agent_reactor
from personal_agent_protocol.errors import PersonalAgentProtocolError, TransportError
from personal_agent_protocol.mcp import (
    McpClient,
    McpError,
    McpSessionAuth,
    fetch_mcp_server_metadata,
    mcp_api,
)
from personal_agent_protocol.models import Approval, ProtectedResourceMetadata
from personal_agent_protocol.sessions import AccessToken
from personal_agent_protocol.transport import (
    SessionHttpClient,
    session_headers,
)

from .test_company_end_to_end import TENANT, World
from .test_company_refusals import signed_in

MCP = "https://manzanita.example/mcp"
BROWSER_SESSION = "https://manzanita.example/poppy/browser-session"
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def web_world() -> tuple[World, ControlledBrowser]:
    world = World()
    browser = ControlledBrowser(world.network.client())
    world.host.controlled_browser = browser
    world.reactor = personal_agent_reactor(
        world.host, network=world.network, http_client=world.http
    )
    world.transport = SessionHttpClient(reactor=world.reactor, http_client=world.http)
    return world, browser


def context(world: World) -> RefreshTokenContext:
    metadata = world.company.oauth_metadata
    return RefreshTokenContext(
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        revocation_endpoint=metadata.revocation_endpoint,  # type: ignore[union-attr]
    )


async def signed_in_with_reference(world: World):  # type: ignore[no-untyped-def]
    token = await signed_in(world)
    assert world.refresh_reference is not None
    return token, world.refresh_reference


async def mcp_token(world: World, reference: str, url: str = MCP) -> AccessToken:
    """A token for the MCP server: a refresh with `resource`, its `url` (§4.5, §7)."""

    result = await RefreshTokenClient(reactor=world.reactor, http_client=world.http).token_for_mcp(
        reference, context=context(world), server=ProtectedResourceMetadata(resource=url)
    )
    assert result.status == "signed_in" and result.token is not None
    return result.token


def mcp_client(world: World, session: PapSession, token: AccessToken | None = None) -> McpClient:
    return McpClient(
        http_client=world.http, url=MCP, session=session, reactor=world.reactor, token=token
    )


@pytest.mark.asyncio
async def test_the_company_advertises_its_mcp_server_and_its_issuer() -> None:
    world = World()
    session = await world.signed_out_session()
    api = mcp_api(world.company.document)
    assert api is not None and api.url == MCP
    served = await fetch_mcp_server_metadata(world.http, MCP, issuer=session.issuer)
    assert served.resource == MCP
    metadata = (
        await world.http.get("https://manzanita.example/.well-known/oauth-protected-resource/mcp")
    ).json()
    assert metadata["resource"] == MCP
    assert world.company.oauth_metadata.issuer in metadata["authorization_servers"]  # type: ignore[union-attr]
    # Tokens are Bearer tokens: nothing here speaks of DPoP (§4.5).
    assert "dpop_signing_alg_values_supported" not in metadata

    # A client with no Session header and no token gets where to read the metadata (§7).
    unauthenticated = await world.http.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert unauthenticated.status_code == 401
    assert "resource_metadata=" in unauthenticated.headers["www-authenticate"]
    assert "error=" not in unauthenticated.headers["www-authenticate"]

    # An invented token is `invalid_token`, whatever else the request lacks (§7).
    invented = await world.http.post(
        MCP,
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": "Bearer invented"},
    )
    assert invented.status_code == 401
    assert 'error="invalid_token"' in invented.headers["www-authenticate"]
    assert "resource_metadata=" in invented.headers["www-authenticate"]

    # A token not issued for the server: one Bearer challenge with `resource_metadata` (§7).
    token, _ = await signed_in_with_reference(world)
    assert world.session is not None
    refused = await world.http.post(
        MCP,
        headers=await session_headers(
            world.reactor, "POST", MCP, session=world.session, token=token
        ),
        json=LIST_TOOLS,
    )
    assert refused.status_code == 401
    challenge = refused.headers["www-authenticate"]
    assert re.findall(r"(?:^|, )(Bearer|DPoP) error=", challenge) == ["Bearer"]
    assert challenge.count("resource_metadata=") == 1

    with pytest.raises(McpError) as wrong:
        await fetch_mcp_server_metadata(world.http, MCP, issuer="https://other.example")
    assert wrong.value.code == "invalid_resource_metadata"


@pytest.mark.asyncio
async def test_a_signed_in_mcp_token_reads_and_proposes_the_same_operation() -> None:
    world = World()
    token, reference = await signed_in_with_reference(world)
    session = world.session
    assert session is not None
    before = world.host.vault.values[reference]
    for_mcp = await mcp_token(world, reference)
    # A Bearer token for the server's url, the refresh token rotated, stored, never returned.
    assert for_mcp.token_type == "Bearer" and for_mcp.resource == MCP
    assert world.host.vault.values[reference] != before

    mcp = mcp_client(world, session, for_mcp)
    names = [tool["name"] for tool in await mcp.list_tools()]
    assert names == ["list_orders", "exchange_jacket"]
    orders = await mcp.call_tool("list_orders")
    assert orders.structured_content == {
        "orders": [{"order_id": "ord_7Hk2", "item": "Ridge Jacket, size M", "status": "delivered"}]
    }

    # The default token still works: a Session can use both.
    api = ApiClient(transport=world.transport)
    proposed = await api.call(
        "POST",
        "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
        session=session,
        token=token,
        body={},
    )
    through_mcp = await mcp.call_tool("exchange_jacket")
    assert through_mcp.operation is not None and through_mcp.is_error
    assert "Not done yet" in through_mcp.text
    # One operation across interfaces, each with its own revision: its own request.
    assert proposed.operation is not None
    assert through_mcp.operation.operation_id == proposed.operation.operation_id
    assert through_mcp.operation.terms == proposed.operation.terms
    done = await mcp.call_tool(
        "exchange_jacket",
        approval=Approval(
            operation_id=through_mcp.operation.operation_id,
            revision=through_mcp.operation.revision,
        ),
    )
    assert not done.is_error and done.text.startswith("Exchanged")
    assert world.plugin.executor.performed == [through_mcp.operation.operation_id]


@pytest.mark.asyncio
async def test_an_mcp_token_is_refused_everywhere_but_its_mcp_server() -> None:
    world = World()
    token, reference = await signed_in_with_reference(world)
    session = world.session
    assert session is not None
    for_mcp = await mcp_token(world, reference)
    secret = for_mcp.access_token.get_secret_value()

    # The SDK never sends it elsewhere.
    auth = McpSessionAuth(MCP, session=session, token=for_mcp, reactor=world.reactor)
    for url in (
        "https://manzanita.example/api/orders",
        "https://manzanita.example/mcp/other",
        "https://evil.example/mcp",
        "http://manzanita.example/mcp",
    ):
        with pytest.raises(TransportError) as raised:
            await world.http.get(url, auth=auth)
        assert raised.value.code == "token_not_for_this_url"
    # And an MCP server takes only a token issued for its url.
    with pytest.raises(TransportError) as other:
        McpSessionAuth(MCP, session=session, token=token, reactor=world.reactor)
    assert other.value.code == "token_not_for_this_url"
    with pytest.raises(PersonalAgentProtocolError) as refused_api:
        await ApiClient(transport=world.transport).call(
            "GET", "https://manzanita.example/api/orders", session=session, token=for_mcp
        )
    assert refused_api.value.code == "invalid_token"

    # The company refuses it at every other endpoint, in a valid Session (§4.5).
    endpoints = [
        ("GET", "https://manzanita.example/api/orders"),
        ("POST", "https://manzanita.example/poppy/conversations"),
        ("POST", "https://manzanita.example/poppy/feedback"),
    ]
    for method, url in endpoints:
        response = await world.http.request(
            method,
            url,
            headers=await session_headers(
                world.reactor, method, url, session=session, token=for_mcp
            ),
            json={},
        )
        assert response.status_code == 401, (method, url)
        assert "invalid_token" in response.headers["www-authenticate"]
        assert "resource_metadata=" in response.headers["www-authenticate"]
        assert secret not in response.text
        # Copied without the Session header it is worth nothing at all (§5.3).
        copied = await world.http.request(
            method, url, headers={"Authorization": f"Bearer {secret}"}, json={}
        )
        assert copied.status_code == 400, (method, url)
        assert copied.json()["error"] == "invalid_session"
        assert secret not in copied.text

    # The MCP server refuses the default token: it was not issued for the server.
    refused = await world.http.post(
        MCP,
        headers=await session_headers(world.reactor, "POST", MCP, session=session, token=token),
        json=LIST_TOOLS,
    )
    assert refused.status_code == 401
    assert 'error="invalid_token"' in refused.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_a_token_for_the_mcp_server_comes_from_a_refresh_with_its_url() -> None:
    """A refresh with `resource`, the server's `url`, and nothing else: another `resource`
    is `invalid_target`. Signed out, the Session header alone (§4.5, §7)."""

    world = World()
    session = await world.signed_out_session()
    # Signed out: no token to ask for, the Session header alone.
    mcp = mcp_client(world, session)
    assert [tool["name"] for tool in await mcp.list_tools()] == ["list_orders", "exchange_jacket"]
    with pytest.raises(McpError) as refused:
        await mcp.call_tool("list_orders")
    assert (refused.value.code, refused.value.status_code) == ("insufficient_scope", 401)
    assert refused.value.details is not None and refused.value.details["scope"] == "orders:read"
    # A signed-out call for the account's action is refused the same way.
    with pytest.raises(McpError) as proposal:
        await mcp.call_tool("exchange_jacket")
    assert proposal.value.code == "insufficient_scope"

    _, reference = await signed_in_with_reference(world)
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    with pytest.raises(PersonalAgentProtocolError) as plain:
        await accounts.token_for_mcp(
            reference,
            context=context(world),
            server=ProtectedResourceMetadata.model_construct(
                resource="http://manzanita.example/mcp"
            ),
        )
    assert plain.value.code == "invalid_url"
    with pytest.raises(PersonalAgentProtocolError) as elsewhere:
        await accounts.token_for_mcp(
            reference,
            context=context(world),
            server=ProtectedResourceMetadata(resource="https://elsewhere.example/mcp"),
        )
    assert elsewhere.value.code == "invalid_target"
    token = await mcp_token(world, reference)
    assert token.resource == MCP
    assert (await mcp_client(world, session, token).call_tool("list_orders")).structured_content

    # The Session's own footing is untouched by the request for the MCP server.
    with pytest.raises(PersonalAgentProtocolError) as still:
        await ApiClient(transport=world.transport).call(
            "GET", "https://manzanita.example/api/orders", session=session
        )
    assert still.value.code == "insufficient_scope"


@pytest.mark.asyncio
async def test_an_mcp_server_that_ends_the_session_gets_a_new_one_once() -> None:
    """`invalid_session` starts a new Session once, then stops, wherever it comes from (§7)."""

    world = World()
    session = await world.signed_out_session()
    mcp = mcp_client(world, session)
    assert await mcp.list_tools()
    ended = session.sid
    assert await world.shop.end_session(session.client_id, ended)
    assert [tool["name"] for tool in await mcp.list_tools()] == ["list_orders", "exchange_jacket"]
    assert session.sid != ended


@pytest.mark.asyncio
async def test_signing_out_reaches_the_mcp_server_at_once() -> None:
    world = World()
    _, reference = await signed_in_with_reference(world)
    session = world.session
    assert session is not None
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    mcp = mcp_client(world, session, await mcp_token(world, reference))
    assert (await mcp.call_tool("list_orders")).structured_content is not None
    await accounts.revoke(reference, context=context(world))
    # The sign-in's access tokens are gone with it (§5.5).
    with pytest.raises(McpError) as raised:
        await mcp.call_tool("list_orders")
    assert raised.value.code == "invalid_token"
    # The Session goes on signed out, the Session header alone.
    with pytest.raises(McpError) as signed_out:
        await mcp_client(world, session).call_tool("list_orders")
    assert signed_out.value.code == "insufficient_scope"


@pytest.mark.asyncio
async def test_an_agent_without_operations_gets_a_tool_error_through_mcp() -> None:
    """A tool can't answer `extension_required`, which refuses the agent entirely (§6):
    a tool that needs the Operations extension returns an ordinary tool error."""

    world = World()
    world.atlas.extensions = ()
    world.network.add(world.atlas.domain, world.atlas.website())
    _, reference = await signed_in_with_reference(world)
    assert world.session is not None
    mcp = mcp_client(world, world.session, await mcp_token(world, reference))
    answer = await mcp.call_tool("exchange_jacket")
    assert answer.is_error and answer.operation is None
    assert "Operations extension" in answer.text
    assert (await mcp.call_tool("list_orders")).structured_content is not None


# The website (§6, Operations §4.4) -------------------------------------------------------


async def join(
    world: World,
    browser: ControlledBrowser,
    session: PapSession,
    token: AccessToken | None,
    page: str,
) -> None:
    """Join the agent's browser to the Session (§6), then open `page` in it."""

    await BrowserSessionClient(reactor=world.reactor, transport=world.transport).join(
        browser_session_endpoint=world.company.document.web.browser_session_endpoint,  # type: ignore[union-attr,arg-type]
        session=session,
        token=token,
    )
    await browser.get(page)


@pytest.mark.asyncio
async def test_a_joined_browser_follows_the_session() -> None:
    world, browser = web_world()
    token, reference = await signed_in_with_reference(world)
    session = world.session
    assert session is not None
    await join(world, browser, session, token, "https://manzanita.example/")
    cookie = browser.http.cookies.get("__Host-poppy_session")
    assert cookie is not None
    joined = await world.shop.web_session(cookie)
    assert joined is not None and joined.account_id == "acct_ada" and joined.sid == session.sid

    # Signing out reaches the website on its next request: the Session continues signed out.
    await RefreshTokenClient(reactor=world.reactor, http_client=world.http).revoke(
        reference, context=context(world)
    )
    signed_out = await world.shop.web_session(cookie)
    assert signed_out is not None and signed_out.account_id is None

    # Ending the Session ends the browser's cookie with it (§6).
    assert await world.shop.end_session(session.client_id, session.sid)
    assert await world.shop.web_session(cookie) is None


@pytest.mark.asyncio
async def test_the_join_page_is_one_time_tied_to_its_browser_and_never_framed() -> None:
    """Step 1 of §6: a form with a one-time code, a `__Host-` cookie that ties the code to
    this browser, no caching, no framing, no opener."""

    world, _ = web_world()
    browser = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    page = await browser.get(BROWSER_SESSION)
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert page.headers["cross-origin-opener-policy"] == "same-origin"
    cookie = page.headers["set-cookie"]
    for part in ("__Host-poppy_join=", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=60"):
        assert part in cookie
    code = re.search(r'name="code" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    # The code alone: the browser never holds anything of the Session's (§6).
    assert len(code) >= 22 and 'name="proof"' not in page.text
    await browser.aclose()


async def _join_form(world: World) -> tuple[httpx.AsyncClient, str]:
    browser = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    page = await browser.get(BROWSER_SESSION)
    code = re.search(r'name="code" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    return browser, code


async def _authorize(world: World, session: PapSession, code: str) -> httpx.Response:
    """Step 2 of §6, one request as it goes on the wire: no new Session on a refusal."""

    url = f"{BROWSER_SESSION}/authorize"
    return await world.http.post(
        url,
        headers=await session_headers(world.reactor, "POST", url, session=session, token=None),
        json={"code": code},
    )


@pytest.mark.asyncio
async def test_a_join_needs_its_own_browser_its_code_once_and_a_live_session() -> None:
    """Step 3 of §6 and both attacks of §10.6: a code submitted from another browser, a
    code used twice, a code the agent never authorized, a Session that has ended."""

    world, _ = web_world()
    session = await world.signed_out_session()

    browser, code = await _join_form(world)
    assert (await _authorize(world, session, code)).status_code == 204
    # Authorized once only.
    assert (await _authorize(world, session, code)).json()["error"] == "invalid_request"
    # Another browser (no join cookie): an attacker's code can't make it join (§10.6).
    victim = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    stolen = await victim.post(BROWSER_SESSION, data={"code": code})
    assert stolen.status_code == 400 and "__Host-poppy_session" not in stolen.headers.get(
        "set-cookie", ""
    )
    # The code was used by that first request, whatever the result: gone.
    used = await browser.post(BROWSER_SESSION, data={"code": code})
    assert used.status_code == 400
    assert (await _authorize(world, session, code)).json()["error"] == "invalid_request"

    # A code the agent never authorized sets no cookie, in the browser it was issued to.
    browser, code = await _join_form(world)
    unauthorized = await browser.post(BROWSER_SESSION, data={"code": code})
    assert unauthorized.status_code == 400
    assert "set-cookie" not in unauthorized.headers  # no cookie, not even a cleared one (§6)

    # A code that was never issued can't be authorized.
    assert (await _authorize(world, session, "bc_" + "x" * 22)).json()["error"] == (
        "invalid_request"
    )

    # Without the Session header, or with one for an ended Session, nothing is authorized.
    browser, code = await _join_form(world)
    bare = await world.http.post(f"{BROWSER_SESSION}/authorize", json={"code": code})
    assert (bare.status_code, bare.json()["error"]) == (400, "invalid_session")
    ended = await world.signed_out_session()
    assert (await _authorize(world, ended, "bc_" + "y" * 22)).status_code == 400
    assert await world.shop.end_session(ended.client_id, ended.sid)
    refused = await _authorize(world, ended, code)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_session")

    assert (await _authorize(world, session, code)).status_code == 204
    joined = await browser.post(BROWSER_SESSION, data={"code": code})
    assert joined.status_code == 303
    cookies = joined.headers.get_list("set-cookie")
    assert any(c.startswith("__Host-poppy_session=") and "SameSite=Strict" in c for c in cookies)
    assert any(c.startswith("__Host-poppy_join=;") and "Max-Age=0" in c for c in cookies)
    for client in (browser, victim):
        await client.aclose()


@pytest.mark.asyncio
async def test_an_mcp_429_is_rate_limited_with_its_retry_after() -> None:
    """A 429 is `rate_limited` with the `Retry-After` kept, as the API and conversation
    clients do, and says when to retry."""

    refusals: list[httpx.Response] = []

    def answer(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        if "id" not in message:
            return httpx.Response(202)
        if message["method"] == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": {}})
        return refusals.pop(0)

    world = World()
    session = await world.signed_out_session()
    bearer = AccessToken(
        access_token="sat_test",  # noqa: S106
        expires_in=60,
        scope="orders:read",
        resource=MCP,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        mcp = McpClient(
            http_client=http, url=MCP, session=session, reactor=world.reactor, token=bearer
        )
        refusals.append(httpx.Response(429, headers={"Retry-After": "30"}, json={"error": "slow"}))
        with pytest.raises(McpError) as raised:
            await mcp.call_tool("orders")
        assert raised.value.code == "rate_limited"
        assert raised.value.status_code == 429
        assert raised.value.details == {"retry_after": "30"}
        assert str(raised.value) == "rate_limited: the MCP server is rate limited, retry after 30 s"

        when = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=90), usegmt=True)
        refusals.append(httpx.Response(429, headers={"Retry-After": when}))
        with pytest.raises(McpError) as raised:
            await mcp.list_tools()
        assert raised.value.code == "rate_limited"
        assert raised.value.details == {"retry_after": when}
        assert re.fullmatch(
            r"rate_limited: the MCP server is rate limited, retry after (89|90) s",
            str(raised.value),
        )

        refusals.append(httpx.Response(429))
        with pytest.raises(McpError) as raised:
            await mcp.list_tools()
        assert (raised.value.code, raised.value.details) == ("rate_limited", {})
        assert str(raised.value) == "rate_limited: the MCP server is rate limited"

        refusals.append(httpx.Response(503, headers={"Retry-After": "30"}))
        with pytest.raises(McpError) as raised:
            await mcp.list_tools()
        assert (raised.value.code, raised.value.status_code) == ("temporarily_unavailable", 503)


@pytest.mark.asyncio
async def test_a_session_holds_a_token_for_the_mcp_server_and_its_default_token() -> None:
    """One account's tokens: one for each server that asks for its own, and the default
    one for its other APIs, each used only where it works (§4.5)."""

    world = World()
    _, reference = await signed_in_with_reference(world)
    session = world.session
    assert session is not None
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    for_mcp = await mcp_token(world, reference)
    own = await accounts.refresh(reference, context=context(world))
    assert own.status == "signed_in" and own.token is not None and own.token.resource is None
    await ApiClient(transport=world.transport).call(
        "GET", "https://manzanita.example/api/orders", session=session, token=own.token
    )
    # The token for the MCP server still works there.
    orders = await mcp_client(world, session, for_mcp).call_tool("list_orders")
    assert orders.structured_content is not None
