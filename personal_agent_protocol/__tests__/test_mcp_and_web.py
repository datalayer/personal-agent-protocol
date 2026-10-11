# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""One operation through MCP and the website; a Bearer token only at its MCP server."""

from __future__ import annotations

import httpx
import pytest

from personal_agent_protocol import (
    BrowserSessionClient,
    SessionClient,
    build_browser_assertion_claims,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.demo.kit import ControlledBrowser, personal_agent_reactor
from personal_agent_protocol.errors import PersonalAgentProtocolError, TransportError
from personal_agent_protocol.mcp import McpBearerAuth, McpClient, McpError, mcp_api
from personal_agent_protocol.operations import (
    OperationError,
    OperationsClient,
    approve,
    operation_from,
    operation_page,
)
from personal_agent_protocol.transport import DpopHttpClient

from .test_company_end_to_end import PAIRWISE, TENANT, World
from .test_company_refusals import signed_in

MCP = "https://manzanita.example/mcp"


def web_world() -> tuple[World, ControlledBrowser]:
    world = World()
    browser = ControlledBrowser(world.network.client())
    world.host.controlled_browser = browser
    world.reactor = personal_agent_reactor(
        world.host, network=world.network, http_client=world.http
    )
    world.transport = DpopHttpClient(reactor=world.reactor, http_client=world.http)
    return world, browser


def context(world: World) -> AccountTokenContext:
    metadata = world.company.oauth_metadata
    return AccountTokenContext(
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        revocation_endpoint=metadata.revocation_endpoint,  # type: ignore[union-attr]
    )


async def signed_in_with_reference(world: World):  # type: ignore[no-untyped-def]
    token = await signed_in(world)
    reference = next(iter(world.host.vault.values))
    return token, reference


@pytest.mark.asyncio
async def test_the_company_advertises_its_mcp_server_and_its_issuer() -> None:
    world = World()
    await world.signed_out_session()
    api = mcp_api(world.company.document)
    assert api is not None and api.url == MCP
    metadata = (
        await world.http.get("https://manzanita.example/.well-known/oauth-protected-resource/mcp")
    ).json()
    assert metadata["resource"] == MCP
    assert world.company.oauth_metadata.issuer in metadata["authorization_servers"]  # type: ignore[union-attr]
    unauthenticated = await world.http.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert unauthenticated.status_code == 401
    assert "resource_metadata=" in unauthenticated.headers["www-authenticate"]


@pytest.mark.asyncio
async def test_a_signed_in_bearer_reads_and_proposes_through_mcp_the_same_operation() -> None:
    world = World()
    token, reference = await signed_in_with_reference(world)
    before = world.host.vault.values[reference]
    bearer = await AccountTokenClient(reactor=world.reactor, http_client=world.http).bearer_for_mcp(
        reference, context=context(world), session_id=token.session_id, resource=MCP
    )
    assert bearer.status == "signed_in" and bearer.token is not None
    assert bearer.token.token_type == "Bearer" and bearer.token.signed_in
    assert world.host.vault.values[reference] != before  # rotated, stored, never returned

    mcp = McpClient(http_client=world.http, token=bearer.token, url=MCP)
    names = [tool["name"] for tool in await mcp.list_tools()]
    assert names == ["list_orders", "exchange_jacket"]
    orders = await mcp.call_tool("list_orders")
    assert orders.structured_content == {
        "orders": [{"order_id": "ord_7Hk2", "item": "Ridge Jacket, size M", "status": "delivered"}]
    }

    # The DPoP token of the same Session still works: a Session holds both.
    api = ApiClient(transport=world.transport)
    proposed = await api.call(
        "POST",
        "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
        token=token,
        body={},
        **world.who,
    )
    through_mcp = await mcp.call_tool("exchange_jacket")
    assert through_mcp.operation is not None and "Not done until confirmed" in through_mcp.text
    assert through_mcp.operation == proposed.operation  # one record across channels
    assert operation_from({"structuredContent": {"operation": through_mcp.operation}}) == (
        operation_from({"operation": proposed.operation})
    )
    done = await OperationsClient(transport=world.transport).confirm(
        world.shop.config.operations_endpoint,
        through_mcp.operation,
        approval=approve(through_mcp.operation),
        token=token,
        **world.who,
    )
    assert done.operation is not None and done.operation.state == "succeeded"
    assert world.plugin.executor.performed == [through_mcp.operation.operation_id]


@pytest.mark.asyncio
async def test_a_bearer_token_is_refused_everywhere_but_its_mcp_server() -> None:
    world = World()
    token, reference = await signed_in_with_reference(world)
    bearer = (
        await AccountTokenClient(reactor=world.reactor, http_client=world.http).bearer_for_mcp(
            reference, context=context(world), session_id=token.session_id, resource=MCP
        )
    ).token
    assert bearer is not None
    secret = bearer.access_token.get_secret_value()

    # The SDK never sends it elsewhere.
    auth = McpBearerAuth(bearer, MCP)
    for url in (
        "https://manzanita.example/api/orders",
        "https://manzanita.example/mcp/other",
        "https://evil.example/mcp",
        "http://manzanita.example/mcp",
    ):
        with pytest.raises(TransportError) as raised:
            await world.http.get(url, auth=auth)
        assert raised.value.code == "bearer_not_for_this_url"
    with pytest.raises(TransportError):
        await ApiClient(transport=world.transport).call(
            "GET", "https://manzanita.example/api/orders", token=bearer, **world.who
        )

    # The company refuses it at every non-MCP endpoint, as Bearer or as DPoP.
    endpoints = [
        ("GET", "https://manzanita.example/api/orders"),
        ("POST", "https://manzanita.example/poppy/conversations"),
        ("GET", "https://manzanita.example/poppy/operations/op_any"),
        ("POST", "https://manzanita.example/poppy/sign-in"),
    ]
    for method, url in endpoints:
        for scheme in ("Bearer", "DPoP"):
            response = await world.http.request(
                method, url, headers={"Authorization": f"{scheme} {secret}"}, json={}
            )
            assert response.status_code == 401, (method, url, scheme)
            assert secret not in response.text

    # And the MCP server refuses a DPoP token sent as Bearer.
    dpop_at_mcp = await world.http.post(
        MCP,
        headers={"Authorization": f"Bearer {token.access_token.get_secret_value()}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert dpop_at_mcp.status_code == 401


@pytest.mark.asyncio
async def test_a_bearer_is_issued_only_for_the_mcp_url_and_an_existing_session() -> None:
    world = World()
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    who = {
        "client_id": world.atlas.client_id,
        "pairwise_user_id": PAIRWISE,
        "issuer": metadata.issuer,  # type: ignore[union-attr]
        "token_endpoint": metadata.token_endpoint,  # type: ignore[union-attr]
        "tenant_id": TENANT,
    }
    with pytest.raises(PersonalAgentProtocolError) as raised:
        await sessions.bearer_for_mcp(
            **who, session_id=session.session_id, resource="https://manzanita.example/api"
        )
    assert raised.value.code == "invalid_dpop_proof"  # DPoP is required everywhere else
    with pytest.raises(ValueError):
        await sessions.bearer_for_mcp(
            **who, session_id=session.session_id, resource="http://manzanita.example/mcp"
        )

    signed_out = await sessions.bearer_for_mcp(**who, session_id=session.session_id, resource=MCP)
    assert signed_out.token_type == "Bearer" and not signed_out.signed_in
    mcp = McpClient(http_client=world.http, token=signed_out, url=MCP)
    with pytest.raises(McpError) as refused:
        await mcp.call_tool("list_orders")
    assert (refused.value.code, refused.value.status_code) == ("sign_in_required", 403)
    assert refused.value.details == {"scope": "orders:read"}
    # The DPoP token is untouched by the Bearer request.
    with pytest.raises(PersonalAgentProtocolError) as still:
        await ApiClient(transport=world.transport).call(
            "GET", "https://manzanita.example/api/orders", token=session, **world.who
        )
    assert still.value.code == "sign_in_required"


@pytest.mark.asyncio
async def test_signing_out_reaches_the_mcp_server_at_once() -> None:
    world = World()
    token, reference = await signed_in_with_reference(world)
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    bearer = (
        await accounts.bearer_for_mcp(
            reference, context=context(world), session_id=token.session_id, resource=MCP
        )
    ).token
    assert bearer is not None
    mcp = McpClient(http_client=world.http, token=bearer, url=MCP)
    assert (await mcp.call_tool("list_orders")).structured_content is not None
    await accounts.revoke(reference, context=context(world))
    with pytest.raises(McpError) as raised:
        await mcp.call_tool("list_orders")
    assert raised.value.code == "sign_in_required"


@pytest.mark.asyncio
async def test_an_agent_without_operations_gets_no_operation_through_mcp() -> None:
    world = World()
    world.atlas.extensions = ()
    world.network.add(world.atlas.domain, world.atlas.website())
    token, reference = await signed_in_with_reference(world)
    bearer = (
        await AccountTokenClient(reactor=world.reactor, http_client=world.http).bearer_for_mcp(
            reference, context=context(world), session_id=token.session_id, resource=MCP
        )
    ).token
    assert bearer is not None
    with pytest.raises(McpError) as raised:
        await McpClient(http_client=world.http, token=bearer, url=MCP).call_tool("exchange_jacket")
    assert raised.value.code == "extension_required"
    assert raised.value.details == {"extension": "operations"}


# The website (§5, Operations §4.4) -------------------------------------------------------


async def join(world: World, browser: ControlledBrowser, session_id: str, return_to: str) -> None:
    await BrowserSessionClient(reactor=world.reactor).join(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        browser_session_endpoint=world.company.document.web.browser_session_endpoint,  # type: ignore[union-attr,arg-type]
        session_id=session_id,
        return_to=return_to,
        company_domain="manzanita.example",
    )


@pytest.mark.asyncio
async def test_the_operation_confirmed_on_the_website_is_the_same_operation_once() -> None:
    world, browser = web_world()
    token = await signed_in(world)
    proposed = await ApiClient(transport=world.transport).call(
        "POST",
        "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
        token=token,
        body={},
        **world.who,
    )
    operation = proposed.operation
    assert operation is not None
    page_url = operation_page(operation, world.company.document.organization.domain)
    assert page_url == f"https://manzanita.example/operations/{operation.operation_id}"

    await join(world, browser, token.session_id, page_url)
    page = browser.page
    assert page is not None and page.status_code == 200 and str(page.url) == page_url
    assert operation.summary in page.text and 'data-state="proposed"' in page.text
    cookie = page.history[0].headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert "Max-Age" not in cookie and "Expires" not in cookie
    assert page.headers["x-frame-options"] == "DENY"

    confirmed = await browser.submit(
        page_url, {"action": "confirm", "revision": str(operation.revision), "approved_by": "user"}
    )
    assert 'data-state="succeeded"' in confirmed.text

    operations = OperationsClient(transport=world.transport)
    endpoint = world.shop.config.operations_endpoint
    read = await operations.read(endpoint, operation.operation_id, token=token, **world.who)
    assert read.operation_id == operation.operation_id and read.state == "succeeded"
    assert read.confirmation is not None and read.confirmation.approved_by == "user"
    again = await operations.confirm(
        endpoint, operation, approval=approve(operation), token=token, **world.who
    )
    assert again.operation == read  # confirming at the endpoint too changes nothing
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_the_website_follows_the_session_and_refuses_bad_assertions() -> None:
    world, browser = web_world()
    token, reference = await signed_in_with_reference(world)
    proposed = await ApiClient(transport=world.transport).call(
        "POST",
        "https://manzanita.example/api/orders/ord_7Hk2/gift-wrap",
        token=token,
        body={},
        **world.who,
    )
    operation = proposed.operation
    assert operation is not None and operation.url is not None
    await join(world, browser, token.session_id, operation.url)
    assert browser.page is not None and browser.page.status_code == 200

    # Signing out reaches the website on its next request: the account's operation is gone.
    await AccountTokenClient(reactor=world.reactor, http_client=world.http).revoke(
        reference, context=context(world)
    )
    assert (await browser.get(operation.url)).status_code == 404

    # A browser assertion is refused off the company's domain, replayed, or as a Session one.
    with pytest.raises(ValueError):
        await join(world, browser, token.session_id, "https://evil.example/")
    endpoint = "https://manzanita.example/poppy/browser-session"
    session = await world.signed_out_session()
    claims = build_browser_assertion_claims(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        browser_session_endpoint=endpoint,
        session_id=session.session_id,
        return_to="https://manzanita.example/",
        company_domain="manzanita.example",
        now=world.clock.now(),
    )
    signer = world.atlas.signer()
    assertion = (
        await signer.sign(claims.model_dump(), purpose="browser_assertion")
    ).get_secret_value()
    fresh = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    first = await fresh.post(endpoint, data={"assertion": assertion})
    assert first.status_code == 303 and "set-cookie" in first.headers
    replayed = await fresh.post(endpoint, data={"assertion": assertion})
    assert replayed.status_code == 400 and "set-cookie" not in replayed.headers
    session_assertion = await signer.sign(
        {
            "iss": world.atlas.client_id,
            "sub": PAIRWISE,
            "aud": endpoint,
            "session_id": session.session_id,
            "return_to": "https://manzanita.example/",
            "iat": int(world.clock.now().timestamp()),
            "exp": int(world.clock.now().timestamp()) + 60,
            "jti": "J" * 22,
        },
        purpose="session_assertion",
    )
    typed = await fresh.post(endpoint, data={"assertion": session_assertion.get_secret_value()})
    assert typed.status_code == 400 and "set-cookie" not in typed.headers
    await fresh.aclose()


def test_an_operation_page_off_the_company_domain_is_refused() -> None:
    operation = operation_from(
        {
            "operation": {
                "operation_id": "op_1",
                "revision": 1,
                "state": "proposed",
                "summary": "Gift wrap.",
                "expires_at": "2026-10-11T10:00:00Z",
                "url": "https://pay.elsewhere.example/op_1",
                "confirmation": None,
                "result": None,
            }
        }
    )
    with pytest.raises(OperationError) as raised:
        operation_page(operation, "manzanita.example")
    assert raised.value.code == "foreign_operation_page"
    shop = operation.model_copy(update={"url": "https://shop.manzanita.example/op_1"})
    assert operation_page(shop, "manzanita.example") == "https://shop.manzanita.example/op_1"
