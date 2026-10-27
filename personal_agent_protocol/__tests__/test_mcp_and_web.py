# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""One operation through MCP and the website; a token for the MCP server only there."""

from __future__ import annotations

import dataclasses
import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from personal_agent_protocol import (
    BrowserSessionClient,
    DpopProofRequest,
    SessionClient,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.demo.kit import ControlledBrowser, personal_agent_reactor
from personal_agent_protocol.errors import PersonalAgentProtocolError, TransportError
from personal_agent_protocol.mcp import (
    McpBearerAuth,
    McpClient,
    McpDpopAuth,
    McpError,
    fetch_mcp_server_metadata,
    mcp_api,
)
from personal_agent_protocol.operations import (
    OperationError,
    OperationsClient,
    approve,
    operation_from,
    operation_page,
)
from personal_agent_protocol.sessions import SessionToken
from personal_agent_protocol.reactor import DPOP_PROOF_PROVIDERS, first_contribution
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


def mcp_world(dpop: bool) -> World:
    """Manzanita with an MCP server that supports DPoP (the default) or doesn't (§4.3)."""

    world = World()
    world.shop.config = dataclasses.replace(world.shop.config, mcp_dpop=dpop)
    return world


async def mcp_token(world: World, token: SessionToken, reference: str, dpop: bool) -> SessionToken:
    """A signed-in token for the MCP server (§4.3).

    A server that supports DPoP: the Account Token request, with `resource`, gives a DPoP
    token. One that doesn't: the signed-in DPoP Session Token is exchanged for a Bearer
    one, for that server alone.
    """

    if dpop:
        result = await AccountTokenClient(reactor=world.reactor, http_client=world.http).refresh(
            reference, context=context(world), session_key=token.session_key, resource=MCP
        )
        assert result.status == "signed_in" and result.token is not None
        return result.token
    return await exchanged(world, token)


async def exchanged(world: World, token: SessionToken, resource: str = MCP) -> SessionToken:
    metadata = world.company.oauth_metadata
    return await SessionClient(reactor=world.reactor, http_client=world.http).token_for_mcp(
        client_id=world.atlas.client_id,
        issuer=metadata.issuer,  # type: ignore[union-attr]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        tenant_id=TENANT,
        session_key=token.session_key,
        subject_token=token.access_token,
        resource=resource,
    )


def session_who(world: World) -> dict[str, str]:
    metadata = world.company.oauth_metadata
    return {
        "client_id": world.atlas.client_id,
        "pairwise_user_id": PAIRWISE,
        "issuer": metadata.issuer,  # type: ignore[union-attr]
        "token_endpoint": metadata.token_endpoint,  # type: ignore[union-attr]
        "tenant_id": TENANT,
    }


def mcp_client(world: World, token: SessionToken) -> McpClient:
    return McpClient(
        http_client=world.http, token=token, url=MCP, reactor=world.reactor, who=world.who
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("dpop", [True, False])
async def test_the_company_advertises_its_mcp_server_and_its_issuer(dpop: bool) -> None:
    world = mcp_world(dpop)
    await world.signed_out_session()
    api = mcp_api(world.company.document)
    assert api is not None and api.url == MCP
    served = await fetch_mcp_server_metadata(world.http, MCP, issuer=world.who["issuer"])
    assert served.resource == MCP and served.supports_dpop is dpop
    metadata = (
        await world.http.get("https://manzanita.example/.well-known/oauth-protected-resource/mcp")
    ).json()
    assert metadata["resource"] == MCP
    assert world.company.oauth_metadata.issuer in metadata["authorization_servers"]  # type: ignore[union-attr]
    if dpop:
        # It supports DPoP, ES256 among its algorithms (§4.3, RFC 9728 §2).
        assert "ES256" in metadata["dpop_signing_alg_values_supported"]
    else:
        assert "dpop_signing_alg_values_supported" not in metadata
    unauthenticated = await world.http.post(MCP, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert unauthenticated.status_code == 401
    challenge = unauthenticated.headers["www-authenticate"]
    # One challenge per scheme it accepts, each with resource_metadata (§6).
    schemes = re.findall(r"(?:^|, )(Bearer|DPoP) error=", challenge)
    assert schemes == (["Bearer", "DPoP"] if dpop else ["Bearer"])
    assert challenge.count("resource_metadata=") == len(schemes)
    with pytest.raises(McpError) as wrong:
        await fetch_mcp_server_metadata(world.http, MCP, issuer="https://other.example")
    assert wrong.value.code == "invalid_resource_metadata"


@pytest.mark.asyncio
@pytest.mark.parametrize("dpop", [True, False])
async def test_a_signed_in_mcp_token_reads_and_proposes_the_same_operation(dpop: bool) -> None:
    world = mcp_world(dpop)
    token, reference = await signed_in_with_reference(world)
    before = world.host.vault.values[reference]
    mcp_session = await mcp_token(world, token, reference, dpop)
    # The scheme the server takes: DPoP with proofs, or a Bearer token for its url (§4.3).
    assert mcp_session.token_type == ("DPoP" if dpop else "Bearer") and mcp_session.signed_in
    if dpop:
        assert world.host.vault.values[reference] != before  # rotated, stored, never returned
    else:
        # Token Exchange uses the Session Token: the Account Token is not touched (§4.3).
        assert world.host.vault.values[reference] == before

    mcp = mcp_client(world, mcp_session)
    names = [tool["name"] for tool in await mcp.list_tools()]
    assert names == ["list_orders", "exchange_jacket"]
    orders = await mcp.call_tool("list_orders")
    assert orders.structured_content == {
        "orders": [{"order_id": "ord_7Hk2", "item": "Ridge Jacket, size M", "status": "delivered"}]
    }

    # The Session's own DPoP token still works: a Session holds both.
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
@pytest.mark.parametrize("dpop", [True, False])
async def test_an_mcp_token_is_refused_everywhere_but_its_mcp_server(dpop: bool) -> None:
    world = mcp_world(dpop)
    token, reference = await signed_in_with_reference(world)
    mcp_session = await mcp_token(world, token, reference, dpop)
    secret = mcp_session.access_token.get_secret_value()

    # The SDK never sends it elsewhere.
    auth: httpx.Auth = (
        McpDpopAuth(mcp_session, MCP, reactor=world.reactor, who=world.who)
        if dpop
        else McpBearerAuth(mcp_session, MCP)
    )
    for url in (
        "https://manzanita.example/api/orders",
        "https://manzanita.example/mcp/other",
        "https://evil.example/mcp",
        "http://manzanita.example/mcp",
    ):
        with pytest.raises(TransportError) as raised:
            await world.http.get(url, auth=auth)
        assert raised.value.code == (
            "token_not_for_this_url" if dpop else "bearer_not_for_this_url"
        )
    with pytest.raises(PersonalAgentProtocolError):
        await ApiClient(transport=world.transport).call(
            "GET", "https://manzanita.example/api/orders", token=mcp_session, **world.who
        )

    # The company refuses it at every other endpoint, as Bearer or as DPoP (§4.3).
    endpoints = [
        ("GET", "https://manzanita.example/api/orders"),
        ("POST", "https://manzanita.example/poppy/conversations"),
        ("GET", "https://manzanita.example/poppy/operations/op_any"),
        ("POST", "https://manzanita.example/poppy/sign-in"),
        ("POST", "https://manzanita.example/poppy/feedback"),
    ]
    for method, url in endpoints:
        for scheme in ("Bearer", "DPoP"):
            response = await world.http.request(
                method, url, headers={"Authorization": f"{scheme} {secret}"}, json={}
            )
            assert response.status_code == 401, (method, url, scheme)
            assert secret not in response.text

    # The MCP server refuses the Session's own DPoP token, in either scheme: it was not
    # issued for the server; and a DPoP token is never accepted as a Bearer token.
    own = token.access_token.get_secret_value()
    for value in (f"Bearer {own}", *([f"Bearer {secret}"] if dpop else [])):
        refused = await world.http.post(
            MCP,
            headers={"Authorization": value},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        assert refused.status_code == 401


@pytest.mark.asyncio
async def test_the_token_type_is_chosen_by_the_mcp_server() -> None:
    """A DPoP server: a DPoP token from the request that renews the Session, with
    `resource`. A server without DPoP: a Bearer token by Token Exchange alone. Each other
    way is `invalid_target` (§4.3)."""

    for dpop in (True, False):
        world = mcp_world(dpop)
        session = await world.signed_out_session()
        sessions = SessionClient(reactor=world.reactor, http_client=world.http)
        who = session_who(world)
        with pytest.raises(ValueError):
            await sessions.renew(
                **who, session_key=session.session_key, resource="http://manzanita.example/mcp"
            )
        # Token Exchange is only for an MCP server without DPoP.
        with pytest.raises(PersonalAgentProtocolError) as elsewhere:
            await exchanged(world, session, "https://manzanita.example/")
        assert elsewhere.value.code == "invalid_target"
        if dpop:
            with pytest.raises(PersonalAgentProtocolError) as wrong:
                await exchanged(world, session)
            assert wrong.value.code == "invalid_target"
            signed_out = await sessions.renew(**who, session_key=session.session_key, resource=MCP)
            assert signed_out.token_type == "DPoP"
        else:
            # Its tokens come from Token Exchange, never from another grant.
            with pytest.raises(PersonalAgentProtocolError) as wrong:
                await sessions.renew(**who, session_key=session.session_key, resource=MCP)
            assert wrong.value.code == "invalid_target"
            signed_out = await exchanged(world, session)
            assert signed_out.token_type == "Bearer"
        assert not signed_out.signed_in and signed_out.session_key == session.session_key
        with pytest.raises(McpError) as refused:
            await mcp_client(world, signed_out).call_tool("list_orders")
        assert (refused.value.code, refused.value.status_code) == ("insufficient_scope", 403)
        assert refused.value.details == {"scope": "orders:read"}
        # The Session's own token is untouched by the request for the MCP server.
        with pytest.raises(PersonalAgentProtocolError) as still:
            await ApiClient(transport=world.transport).call(
                "GET", "https://manzanita.example/api/orders", token=session, **world.who
            )
        assert still.value.code == "insufficient_scope"


@pytest.mark.asyncio
async def test_a_dpop_mcp_server_retries_once_with_its_nonce() -> None:
    world = mcp_world(True)
    world.shop.config = dataclasses.replace(world.shop.config, dpop_nonce=True)
    session = await world.signed_out_session()
    token = await SessionClient(reactor=world.reactor, http_client=world.http).renew(
        **session_who(world), session_key=session.session_key, resource=MCP
    )
    tools = await mcp_client(world, token).list_tools()
    assert [tool["name"] for tool in tools] == ["list_orders", "exchange_jacket"]


@pytest.mark.asyncio
@pytest.mark.parametrize("dpop", [True, False])
async def test_signing_out_reaches_the_mcp_server_at_once(dpop: bool) -> None:
    world = mcp_world(dpop)
    token, reference = await signed_in_with_reference(world)
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    mcp = mcp_client(world, await mcp_token(world, token, reference, dpop))
    assert (await mcp.call_tool("list_orders")).structured_content is not None
    await accounts.revoke(reference, context=context(world))
    with pytest.raises(McpError) as raised:
        await mcp.call_tool("list_orders")
    assert raised.value.code == "insufficient_scope"


@pytest.mark.asyncio
async def test_an_agent_without_operations_gets_a_tool_error_through_mcp() -> None:
    """A tool can't answer `extension_required`, which refuses the agent entirely (§6):
    a tool that needs the Operations extension returns an ordinary tool error."""

    world = World()
    world.atlas.extensions = ()
    world.network.add(world.atlas.domain, world.atlas.website())
    token, reference = await signed_in_with_reference(world)
    mcp = mcp_client(world, await mcp_token(world, token, reference, True))
    answer = await mcp.call_tool("exchange_jacket")
    assert answer.is_error and answer.operation is None
    assert "Operations extension" in answer.text
    assert (await mcp.call_tool("list_orders")).structured_content is not None


# The website (§5, Operations §4.4) -------------------------------------------------------


async def join(world: World, browser: ControlledBrowser, session_key: str, page: str) -> None:
    """Join the agent's browser to the Session (§5), then open `page` in it."""

    await BrowserSessionClient(reactor=world.reactor).join(
        browser_session_endpoint=world.company.document.web.browser_session_endpoint,  # type: ignore[union-attr,arg-type]
        tenant_id=TENANT,
        issuer=world.company.oauth_metadata.issuer,  # type: ignore[union-attr]
        session_key=session_key,
    )
    await browser.get(page)


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

    await join(world, browser, token.session_key, page_url)
    page = browser.page
    assert page is not None and page.status_code == 200 and str(page.url) == page_url
    assert operation.summary in page.text and 'data-state="proposed"' in page.text
    session_cookie = browser.http.cookies.get("__Host-poppy_session")
    assert session_cookie is not None
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
    await join(world, browser, token.session_key, operation.url)
    assert browser.page is not None and browser.page.status_code == 200

    # Signing out reaches the website on its next request: the account's operation is gone.
    await AccountTokenClient(reactor=world.reactor, http_client=world.http).revoke(
        reference, context=context(world)
    )
    assert (await browser.get(operation.url)).status_code == 404



@pytest.mark.asyncio
async def test_the_join_page_is_one_time_tied_to_its_browser_and_never_framed() -> None:
    """Step 1 of §5: a form with a one-time code, a `__Host-` cookie that ties the code to
    this browser, no caching, no framing, no opener."""

    world, _ = web_world()
    endpoint = "https://manzanita.example/poppy/browser-session"
    browser = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    page = await browser.get(endpoint)
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["content-security-policy"] == "frame-ancestors 'none'"
    assert page.headers["cross-origin-opener-policy"] == "same-origin"
    cookie = page.headers["set-cookie"]
    for part in ("__Host-poppy_join=", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=60"):
        assert part in cookie
    code = re.search(r'name="code" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    assert len(code) >= 22 and 'name="proof"' in page.text
    await browser.aclose()


async def _join_form(world: World) -> tuple[httpx.AsyncClient, str]:
    browser = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    page = await browser.get("https://manzanita.example/poppy/browser-session")
    code = re.search(r'name="code" value="([^"]+)"', page.text).group(1)  # type: ignore[union-attr]
    return browser, code


def _provider(world: World):  # type: ignore[no-untyped-def]
    return first_contribution(world.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider")


async def _proof(world: World, session_key: str, code: str) -> str:
    proof = await _provider(world).create(
        DpopProofRequest(
            method="POST",
            url="https://manzanita.example/poppy/browser-session",
            tenant_id=TENANT,
            issuer="https://manzanita.example",
            session_key=session_key,
            nonce=code,
        )
    )
    return proof.get_secret_value()


@pytest.mark.asyncio
async def test_a_join_needs_its_own_browser_its_code_once_and_a_live_sessions_key() -> None:
    """Step 3 of §5 and both attacks of §9.6: a code submitted from another browser, a
    code used twice, a proof over another code, a key that names no Session."""

    world, _ = web_world()
    session = await world.signed_out_session()
    endpoint = "https://manzanita.example/poppy/browser-session"

    browser, code = await _join_form(world)
    proof = await _proof(world, session.session_key, code)
    # Another browser (no join cookie): an attacker's code can't make it join (§9.6).
    victim = httpx.AsyncClient(transport=world.http._transport)  # type: ignore[attr-defined]
    stolen = await victim.post(endpoint, data={"code": code, "proof": proof})
    assert stolen.status_code == 400 and "__Host-poppy_session" not in stolen.headers.get(
        "set-cookie", ""
    )
    # The code was used by that first request, whatever the result: gone.
    used = await browser.post(endpoint, data={"code": code, "proof": proof})
    assert used.status_code == 400

    browser, code = await _join_form(world)
    other = await _proof(world, session.session_key, "bc_" + "x" * 22)
    assert (await browser.post(endpoint, data={"code": code, "proof": other})).status_code == 400

    browser, code = await _join_form(world)
    unknown = await _provider(world).new_session_key(
        tenant_id=TENANT, issuer="https://manzanita.example"
    )
    stray = await _proof(world, unknown, code)
    # A key the company doesn't know is an error here, never a new Session.
    assert (await browser.post(endpoint, data={"code": code, "proof": stray})).status_code == 400

    browser, code = await _join_form(world)
    joined = await browser.post(
        endpoint, data={"code": code, "proof": await _proof(world, session.session_key, code)}
    )
    assert joined.status_code == 303
    cookies = joined.headers.get_list("set-cookie")
    assert any(c.startswith("__Host-poppy_session=") and "SameSite=Strict" in c for c in cookies)
    assert any(c.startswith("__Host-poppy_join=;") and "Max-Age=0" in c for c in cookies)
    for client in (browser, victim):
        await client.aclose()


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


@pytest.mark.asyncio
async def test_an_mcp_429_is_rate_limited_with_its_retry_after() -> None:
    """A 429 is `rate_limited` with the `Retry-After` kept, as the API and conversation
    clients do (PAP_DATALAYER release gates, decided 2026-10-14), and says when to retry."""

    refusals: list[httpx.Response] = []

    def answer(request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        if "id" not in message:
            return httpx.Response(202)
        if message["method"] == "initialize":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": {}})
        return refusals.pop(0)

    bearer = SessionToken(
        access_token="sat_test",  # noqa: S106
        token_type="Bearer",  # noqa: S106
        expires_in=60,
        session_key="K" * 43,
        signed_in=True,
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        mcp = McpClient(http_client=http, token=bearer, url=MCP)
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
        assert (raised.value.code, raised.value.status_code) == ("http_error", 503)


@pytest.mark.asyncio
@pytest.mark.parametrize("dpop", [True, False])
async def test_a_session_started_for_the_mcp_server_gets_its_own_token_too(dpop: bool) -> None:
    """A Session can hold a token for each MCP server and one for its other APIs (§4.3)."""

    world = mcp_world(dpop)
    await world.signed_out_session()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    who = session_who(world)
    if dpop:
        # The request that starts a Session, for the MCP server alone.
        for_mcp = await sessions.start(**who, resource=MCP)
    else:
        for_mcp = await exchanged(world, await sessions.start(**who))
    own = await sessions.renew(**who, session_key=for_mcp.session_key)
    assert own.session_key == for_mcp.session_key and own.token_type == "DPoP"
    with pytest.raises(PersonalAgentProtocolError) as needs_sign_in:
        await ApiClient(transport=world.transport).call(
            "GET", "https://manzanita.example/api/orders", token=own, **world.who
        )
    assert needs_sign_in.value.code == "insufficient_scope"
    # The token for the MCP server still works there.
    with pytest.raises(McpError) as signed_out:
        await mcp_client(world, for_mcp).call_tool("list_orders")
    assert signed_out.value.code == "insufficient_scope"
