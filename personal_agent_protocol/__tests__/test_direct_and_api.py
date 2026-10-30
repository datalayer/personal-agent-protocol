# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Signed out → Direct Sign-In → the company's OpenAPI API, against the reference company."""

from __future__ import annotations

import pytest

from personal_agent_protocol import Approval, AuthorizationError, DirectSignInClient
from personal_agent_protocol.apis import ApiClient, ApiError, openapi_url
from personal_agent_protocol.demo.kit import ScriptedBrowser, personal_agent_reactor
from personal_agent_protocol.transport import SessionHttpClient

from .test_company_end_to_end import TENANT, World


def direct_world() -> tuple[World, ScriptedBrowser]:
    world = World()
    browser = ScriptedBrowser(world.http)
    world.host.browser = browser
    # The host contributes its browser before the Reactor is built.
    world.reactor = personal_agent_reactor(
        world.host, network=world.network, http_client=world.http
    )
    world.transport = SessionHttpClient(reactor=world.reactor, http_client=world.http)
    return world, browser


async def begin(world: World, browser: ScriptedBrowser, session, scopes=("orders:read",)):  # type: ignore[no-untyped-def]
    metadata = world.company.oauth_metadata
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    await client.begin(
        authorization_endpoint=metadata.authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        redirect_uri=f"https://{world.atlas.domain}/oauth/callback",
        scopes=scopes,
        tenant_id=TENANT,
    )
    return client


@pytest.mark.asyncio
async def test_signed_out_then_direct_sign_in_then_a_read_and_a_proposed_exchange() -> None:
    world, browser = direct_world()
    session = await world.signed_out_session()
    api = ApiClient(transport=world.transport)
    description = openapi_url(world.company.document)
    assert description == "https://manzanita.example/api/openapi.json"
    orders = "https://manzanita.example/api/orders"

    # Signed out: the API says which scope signing in would give.
    with pytest.raises(ApiError) as raised:
        await api.call("GET", orders, session=session)
    assert (raised.value.code, raised.value.details) == (
        "insufficient_scope",
        {"scope": "orders:read"},
    )

    # Direct Sign-In: the company's own page, never framed, names the agent and the scopes.
    client = await begin(world, browser, session, ("orders:read", "orders:write"))
    page = browser.pages[-1]
    assert "Atlas" in page and "atlas.example" in page and "See your orders" in page
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    result = await client.complete(callback)
    assert result.token.scopes == ("orders:read", "orders:write")
    signed_in = result.token

    read = await api.call("GET", orders, session=session, token=signed_in)
    assert read.body == {
        "orders": [{"order_id": "ord_7Hk2", "item": "Ridge Jacket, size M", "status": "delivered"}]
    }

    # A consequential call is refused with an operation: nothing is done.
    proposed = await api.call(
        "POST", f"{orders}/ord_7Hk2/exchanges", session=session, token=signed_in, body={}
    )
    assert proposed.status == 403 and proposed.operation is not None
    assert world.plugin.executor.performed == []
    done = await api.call(
        "POST",
        f"{orders}/ord_7Hk2/exchanges",
        session=session,
        token=signed_in,
        body={},
        approval=Approval(
            operation_id=proposed.operation.operation_id, revision=proposed.operation.revision
        ),
    )
    assert done.status == 200 and done.body["summary"].startswith("Exchanged")
    assert world.plugin.executor.performed == [proposed.operation.operation_id]


@pytest.mark.asyncio
async def test_partial_consent_and_a_write_that_was_not_granted() -> None:
    world, browser = direct_world()
    session = await world.signed_out_session()
    client = await begin(world, browser, session, ("orders:read", "orders:write"))
    callback = await world.shop.approve_authorization(  # type: ignore[arg-type]
        browser.request_id, account_id="acct_ada", scopes=["orders:read"]
    )
    result = await client.complete(callback)
    assert result.missing_scopes == ("orders:write",)
    with pytest.raises(ApiError) as raised:
        await ApiClient(transport=world.transport).call(
            "POST",
            "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
            session=session,
            token=result.token,
            body={},
        )
    assert raised.value.code == "insufficient_scope"


@pytest.mark.asyncio
async def test_a_denial_reaches_the_agent_as_access_denied_only() -> None:
    world, browser = direct_world()
    session = await world.signed_out_session()
    client = await begin(world, browser, session)
    callback = await world.shop.deny_authorization(browser.request_id)  # type: ignore[arg-type]
    assert "error=access_denied" in callback
    with pytest.raises(AuthorizationError) as raised:
        await client.complete(callback)
    assert raised.value.code == "authorization_denied"


@pytest.mark.asyncio
async def test_the_consent_page_is_never_framed_and_bad_redirects_are_not_followed() -> None:
    world, _ = direct_world()
    await world.signed_out_session()
    base = "https://manzanita.example/oauth/authorize"
    good = (
        f"?response_type=code&client_id={world.atlas.client_id}&scope=orders:read"
        "&state=s1&code_challenge=c&code_challenge_method=S256"
        f"&redirect_uri=https://{world.atlas.domain}/oauth/callback"
    )
    page = await world.http.get(base + good)
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    elsewhere = await world.http.get(
        base
        + good.replace(
            f"https://{world.atlas.domain}/oauth/callback", "https://attacker.example/cb"
        )
    )
    assert elsewhere.status_code == 400 and "location" not in elsewhere.headers
    plain = await world.http.get(base + good.replace("S256", "plain"))
    assert plain.status_code == 303 and "error=invalid_request" in plain.headers["location"]


@pytest.mark.asyncio
async def test_a_code_works_once() -> None:
    world, browser = direct_world()
    session = await world.signed_out_session()
    client = await begin(world, browser, session)
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    await client.complete(callback)
    with pytest.raises(AuthorizationError):
        await client.complete(callback)
