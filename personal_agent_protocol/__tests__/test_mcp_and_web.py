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
    SessionClient,
    build_browser_assertion_claims,
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
    result = await AccountTokenClient(reactor=world.reactor, http_client=world.http).token_for_mcp(
        reference, context=context(world), session_id=token.session_id, resource=MCP, dpop=dpop
    )
    assert result.status == "signed_in" and result.token is not None
    return result.token


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
    assert world.host.vault.values[reference] != before  # rotated, stored, never returned

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
    """DPoP server: a request without a proof is refused, never answered with Bearer. Server
    without DPoP: a Bearer token for its url even when the request has a proof (§4.3)."""

    for dpop in (True, False):
        world = mcp_world(dpop)
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
            await sessions.token_for_mcp(
                **who,
                session_id=session.session_id,
                resource="https://manzanita.example/api",
                dpop=False,
            )
        assert raised.value.code == "invalid_dpop_proof"  # DPoP is required everywhere else
        with pytest.raises(ValueError):
            await sessions.token_for_mcp(
                **who,
                session_id=session.session_id,
                resource="http://manzanita.example/mcp",
                dpop=dpop,
            )
        with_proof = await sessions.token_for_mcp(
            **who, session_id=session.session_id, resource=MCP, dpop=True
        )
        assert with_proof.token_type == ("DPoP" if dpop else "Bearer")
        if dpop:
            with pytest.raises(PersonalAgentProtocolError) as no_proof:
                await sessions.token_for_mcp(
                    **who, session_id=session.session_id, resource=MCP, dpop=False
                )
            assert no_proof.value.code == "invalid_dpop_proof"
        # A new Session can start for the MCP server alone (§4.3: the request that starts one).
        started = await sessions.token_for_mcp(**who, resource=MCP, dpop=dpop)
        assert started.session_id != session.session_id and not started.signed_in

        signed_out = await sessions.token_for_mcp(
            **who, session_id=session.session_id, resource=MCP, dpop=dpop
        )
        assert signed_out.token_type == ("DPoP" if dpop else "Bearer") and not signed_out.signed_in
        with pytest.raises(McpError) as refused:
            await mcp_client(world, signed_out).call_tool("list_orders")
        assert (refused.value.code, refused.value.status_code) == ("sign_in_required", 403)
        assert refused.value.details == {"scope": "orders:read"}
        # The Session's own token is untouched by the request for the MCP server.
        with pytest.raises(PersonalAgentProtocolError) as still:
            await ApiClient(transport=world.transport).call(
                "GET", "https://manzanita.example/api/orders", token=session, **world.who
            )
        assert still.value.code == "sign_in_required"


@pytest.mark.asyncio
async def test_a_dpop_mcp_server_retries_once_with_its_nonce() -> None:
    world = mcp_world(True)
    world.shop.config = dataclasses.replace(world.shop.config, dpop_nonce=True)
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    token = await SessionClient(reactor=world.reactor, http_client=world.http).token_for_mcp(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,  # type: ignore[union-attr]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        tenant_id=TENANT,
        session_id=session.session_id,
        resource=MCP,
        dpop=True,
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
    assert raised.value.code == "sign_in_required"


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
        session_id="ses_1",
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
    metadata = world.company.oauth_metadata
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    who = {
        "client_id": world.atlas.client_id,
        "pairwise_user_id": PAIRWISE,
        "issuer": metadata.issuer,  # type: ignore[union-attr]
        "token_endpoint": metadata.token_endpoint,  # type: ignore[union-attr]
        "tenant_id": TENANT,
    }
    for_mcp = await sessions.token_for_mcp(**who, resource=MCP, dpop=dpop)
    own = await sessions.renew(**who, session_id=for_mcp.session_id)
    assert own.session_id == for_mcp.session_id and own.token_type == "DPoP"
    with pytest.raises(PersonalAgentProtocolError) as needs_sign_in:
        await ApiClient(transport=world.transport).call(
            "GET", "https://manzanita.example/api/orders", token=own, **world.who
        )
    assert needs_sign_in.value.code == "sign_in_required"
    # The token for the MCP server still works there.
    with pytest.raises(McpError) as signed_out:
        await mcp_client(world, for_mcp).call_tool("list_orders")
    assert signed_out.value.code == "sign_in_required"
