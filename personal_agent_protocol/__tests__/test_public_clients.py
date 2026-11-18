# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Public clients: clients that are no personal agents (MCP clients) sign in with PKCE alone.

Off by default. On, a public client is verified by its domain (a client ID metadata
document that names no key) or registered itself (RFC 7591); it gets tokens for one
service, rotated at every refresh, and nothing of the protocol: no Session, no default
token, no operation approval.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from pydantic import SecretStr, ValidationError
from reactor import PluginManifest, hookimpl  # type: ignore[import-untyped]

from personal_agent_protocol.company import (
    CLIENT_POLICIES,
    CLIENT_RESOLVERS,
    COMPANY_RATE_LIMITS,
    CompanyConfig,
    CompanyRequest,
)
from personal_agent_protocol.company.store import (
    ACCOUNT_FAMILY,
    AccountFamily,
    AccountGrant,
    IssuedAccessToken,
    IssuedCode,
    PendingAuthorization,
)
from personal_agent_protocol.demo.kit import json_site
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.errors import PersonalAgentProtocolError
from personal_agent_protocol.identity import AgentIdentityClient
from personal_agent_protocol.models import (
    DEVICE_CODE_GRANT,
    PublicClientMetadata,
    is_public_loopback_redirect,
    public_client_name,
    public_redirect_uri,
    public_redirect_uri_matches,
)
from personal_agent_protocol.sessions import AccessToken, SessionClient

from .test_company_end_to_end import World
from .test_company_refusals import signed_in

SHOP = "https://manzanita.example"
MCP = f"{SHOP}/mcp"
#: The company's MCP server on a host of its own.
ELSEWHERE = "https://mcp.manzanita.example/mcp"
#: A public client verified by its domain: its client ID metadata document.
VERIFIED = "https://client.example/oauth/client.json"
VERIFIED_REDIRECT = "https://client.example/callback"
LOOPBACK = "http://127.0.0.1/callback"
LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def document(**changes: object) -> dict[str, object]:
    return {
        "client_id": VERIFIED,
        "client_name": "Deskmate",
        "redirect_uris": [VERIFIED_REDIRECT, LOOPBACK, "https://elsewhere.example/callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        **changes,
    }


def public_world(*, site: dict[str, object] | None = None, **options: object) -> World:
    """Manzanita with public clients and registration on, and a verified client's site."""

    world = World()
    settings: dict[str, object] = {
        "public_clients": True,
        "client_registration": True,
        "resource_servers": (ELSEWHERE,),
        **options,
    }
    world.shop, world.plugin = manzanita(
        world.network,
        world.clock,
        config=dataclasses.replace(CONFIG, **settings),  # type: ignore[arg-type]
    )
    world.network.add("client.example", json_site({"/oauth/client.json": site or document()}))
    return world


def pkce() -> tuple[str, str]:
    verifier = "v" * 43
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def register(world: World, **changes: object) -> httpx.Response:
    body = {
        "client_name": "Pocket MCP",
        "redirect_uris": [LOOPBACK, "https://pocket.example/callback"],
        "token_endpoint_auth_method": "none",
        **changes,
    }
    return await world.http.post(f"{SHOP}/oauth/register", json=body)


async def registered(world: World, **changes: object) -> str:
    response = await register(world, **changes)
    assert response.status_code == 201, response.text
    return str(response.json()["client_id"])


async def authorize(
    world: World, client_id: str, redirect_uri: str, **changes: str | None
) -> httpx.Response:
    query: dict[str, str | None] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "orders:read",
        "state": "st-1",
        "code_challenge": pkce()[1],
        "code_challenge_method": "S256",
        "resource": MCP,
        **changes,
    }
    asked = {name: value for name, value in query.items() if value is not None}
    return await world.http.get(f"{SHOP}/oauth/authorize?{urlencode(asked)}")


def request_id_of(page: httpx.Response) -> str:
    assert page.status_code == 200, page.text
    return page.text.split('data-request-id="', 1)[1].split('"', 1)[0]


async def token(world: World, **form: str) -> httpx.Response:
    return await world.http.post(f"{SHOP}/oauth/token", data=form)


async def code_for(world: World, client_id: str, redirect_uri: str, **changes: str | None) -> str:
    page = await authorize(world, client_id, redirect_uri, **changes)
    back = await world.shop.approve_authorization(request_id_of(page), account_id="acct_ada")
    return parse_qs(urlsplit(back).query)["code"][0]


async def sign_in(
    world: World,
    client_id: str,
    redirect_uri: str = LOOPBACK,
    *,
    resource: str = MCP,
    scope: str = "orders:read",
) -> dict[str, Any]:
    code = await code_for(world, client_id, redirect_uri, resource=resource, scope=scope)
    response = await token(
        world,
        grant_type="authorization_code",
        client_id=client_id,
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=pkce()[0],
        resource=resource,
    )
    assert response.status_code == 200, response.text
    return dict(response.json())


async def refresh(world: World, client_id: str, refresh_token: str, **more: str) -> httpx.Response:
    form = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "resource": MCP,
        **more,
    }
    return await token(world, **form)


async def mcp(world: World, access_token: str, message: dict[str, object]) -> httpx.Response:
    return await world.http.post(
        MCP, json=message, headers={"authorization": f"Bearer {access_token}"}
    )


# Off by default ------------------------------------------------------------------------


def test_nothing_is_on_unless_configured() -> None:
    assert CONFIG.public_clients is False
    assert CONFIG.client_registration is False
    assert CONFIG.public_client_refresh_lifetime.days == 30


@pytest.mark.asyncio
async def test_off_a_company_answers_as_before() -> None:
    world = World()
    world.network.add("client.example", json_site({"/oauth/client.json": document()}))
    metadata = (await world.http.get(f"{SHOP}/.well-known/oauth-authorization-server")).json()
    assert metadata["token_endpoint_auth_methods_supported"] == ["private_key_jwt"]
    assert "registration_endpoint" not in metadata
    assert "authorization_response_iss_parameter_supported" not in metadata
    assert (await register(world)).status_code == 404
    # A public client's document is no personal agent's: nothing verifies it.
    page = await authorize(world, VERIFIED, VERIFIED_REDIRECT)
    assert page.status_code == 400 and "location" not in page.headers
    # A token request with no assertion is `invalid_client`, as it always was.
    refused = await refresh(world, VERIFIED, "rt_x")
    assert (refused.status_code, refused.json()["error"]) == (401, "invalid_client")


def test_the_settings_are_checked() -> None:
    def config(**changes: object) -> CompanyConfig:
        return dataclasses.replace(CONFIG, **changes)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="direct"):
        config(public_clients=True, direct=False, ucp=False)
    with pytest.raises(ValueError, match="public_clients is on"):
        config(client_registration=True)
    with pytest.raises(ValueError, match="push"):
        config(public_clients=True, pushed_authorization_requests="required")
    with pytest.raises(ValueError, match="public_client_scopes"):
        config(public_clients=True, public_client_scopes=("poppy:browser-sign-in",))
    with pytest.raises(ValueError, match="public_client_scopes"):
        config(public_clients=True, public_client_scopes=())
    with pytest.raises(ValueError, match="positive"):
        dataclasses.replace(CONFIG, public_client_refresh_lifetime=timedelta(0))
    with pytest.raises(ValueError, match="at least 1"):
        dataclasses.replace(CONFIG, client_registrations_per_hour=0)


@pytest.mark.asyncio
async def test_on_the_issuer_says_so() -> None:
    world = public_world()
    metadata = (await world.http.get(f"{SHOP}/.well-known/oauth-authorization-server")).json()
    assert metadata["token_endpoint_auth_methods_supported"] == ["private_key_jwt", "none"]
    assert metadata["registration_endpoint"] == f"{SHOP}/oauth/register"
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    # Public clients without registration: `none`, and no endpoint to register at.
    without = public_world(client_registration=False)
    metadata = (await without.http.get(f"{SHOP}/.well-known/oauth-authorization-server")).json()
    assert "none" in metadata["token_endpoint_auth_methods_supported"]
    assert "registration_endpoint" not in metadata
    assert (await register(without)).status_code == 404


# The two ways to be a public client ---------------------------------------------------------


@pytest.mark.asyncio
async def test_a_client_verified_by_its_domain_signs_in_and_calls_the_mcp_server() -> None:
    world = public_world()
    page = await authorize(world, VERIFIED, VERIFIED_REDIRECT)
    request_id = request_id_of(page)
    # The page is never framed, and says where the browser goes back to.
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "<strong>client.example</strong>" in page.text
    assert "Unverified" not in page.text
    assert "Only continue if you asked Deskmate to do this just now." in page.text

    summary = await world.shop.authorization_request(request_id)
    assert summary["client_class"] == "public_client"
    assert summary["verified"] is True
    assert summary["client_name"] == "Deskmate"
    assert summary["client_domain"] == "client.example"
    assert summary["redirect_host"] == "client.example"
    assert summary["resource"] == MCP
    assert "state" not in summary and "code_challenge" not in summary

    back = await world.shop.approve_authorization(request_id, account_id="acct_ada")
    answer = parse_qs(urlsplit(back).query)
    # The answer names the issuer and gives the state back (RFC 9207, RFC 6749 §4.1.2).
    assert back.startswith(f"{VERIFIED_REDIRECT}?")
    assert answer["iss"] == [SHOP] and answer["state"] == ["st-1"]

    response = await token(
        world,
        grant_type="authorization_code",
        client_id=VERIFIED,
        code=answer["code"][0],
        redirect_uri=VERIFIED_REDIRECT,
        code_verifier=pkce()[0],
        resource=MCP,
    )
    assert response.status_code == 200, response.text
    tokens = response.json()
    assert tokens["token_type"] == "Bearer"
    assert tokens["refresh_token"] and tokens["access_token"]
    assert response.headers["cache-control"] == "no-store"

    # At the MCP server: its token alone, and no Session header.
    listed = await mcp(world, tokens["access_token"], LIST_TOOLS)
    assert listed.status_code == 200
    assert [tool["name"] for tool in listed.json()["result"]["tools"]]
    called = await mcp(
        world,
        tokens["access_token"],
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_orders"}},
    )
    assert called.status_code == 200 and "isError" not in called.json()["result"]


@pytest.mark.asyncio
async def test_a_client_that_registered_itself_is_shown_as_unverified() -> None:
    world = public_world()
    client_id = await registered(world)
    assert client_id.startswith("mcpc_") and "://" not in client_id
    page = await authorize(world, client_id, "http://127.0.0.1:49152/callback", resource=ELSEWHERE)
    assert "Unverified app." in page.text
    assert "<strong>127.0.0.1:49152</strong>" in page.text
    summary = await world.shop.authorization_request(request_id_of(page))
    assert summary["client_class"] == "public_client"
    assert summary["verified"] is False
    assert summary["client_domain"] == ""
    assert summary["redirect_host"] == "127.0.0.1:49152"
    assert summary["resource"] == ELSEWHERE

    tokens = await sign_in(world, client_id, "http://127.0.0.1:49152/callback", resource=ELSEWHERE)
    # The service at a URL of its own reads the token's record, which says whose it is.
    record = await world.shop.access_token_for(tokens["access_token"], ELSEWHERE)
    assert record is not None and record.public is True
    assert (record.client_id, record.account_id) == (client_id, "acct_ada")
    assert record.scopes == ("orders:read",) and record.dpop_jkt is None
    # Issued for that service, it is nothing at the company's own MCP server.
    assert (await mcp(world, tokens["access_token"], LIST_TOOLS)).status_code == 401


@pytest.mark.asyncio
async def test_a_personal_agents_request_says_its_class_too() -> None:
    """A hosted consent page tells the two classes apart for every request."""

    world = public_world()
    page = await authorize(
        world,
        world.atlas.client_id,
        "https://atlas.example/oauth/callback",
        resource=None,
    )
    summary = await world.shop.authorization_request(request_id_of(page))
    assert summary["client_class"] == "personal_agent"
    assert summary["verified"] is True
    assert summary["redirect_host"] == "atlas.example"
    assert "resource" not in summary


def _error(response: httpx.Response) -> str:
    """The refusal's code: the body's `error`, or UCP's own message code."""

    body = response.json()
    if "error" in body:
        return str(body["error"])
    return str(body["messages"][0]["code"])


# The protocol's boundaries --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_public_clients_token_is_refused_at_every_endpoint_of_the_protocol() -> None:
    world = public_world()
    session = await world.signed_out_session()
    client_id = await registered(world)
    tokens = await sign_in(world, client_id, scope="orders:read orders:write")
    bearer = {"authorization": f"Bearer {tokens['access_token']}"}
    as_json = {"content-type": "application/json"}
    endpoints = [
        ("POST", f"{SHOP}/poppy/conversations", b'{"message": {"text": "Hello"}}'),
        ("GET", f"{SHOP}/poppy/conversations/conv_1", None),
        ("POST", f"{SHOP}/poppy/operations", b"{}"),
        ("GET", f"{SHOP}/poppy/tasks", None),
        ("POST", f"{SHOP}/poppy/feedback", b'{"task": "Pay with a gift card"}'),
        ("POST", f"{SHOP}/poppy/browser-session/authorize", b"{}"),
        ("GET", f"{SHOP}/api/orders", None),
    ]
    for method, url, content in endpoints:
        # Alone, as a public client sends it: there is no Session, so nothing is served.
        alone = await world.http.request(
            method, url, content=content, headers={**bearer, **as_json}
        )
        assert alone.status_code in {400, 401}, (url, alone.status_code, alone.text)
        assert _error(alone) in {"invalid_session", "invalid_token"}, (url, alone.text)
        # In a personal agent's Session: a public client's token signs no Session in.
        borrowed = await world.transport.request(
            method,
            url,
            session=session,
            token=AccessToken(access_token=SecretStr(tokens["access_token"])),
            headers=as_json,
            content=content,
        )
        assert borrowed.status_code in {400, 401}, (url, borrowed.status_code)
        assert _error(borrowed) in {"invalid_session", "invalid_token"}, (url, borrowed.text)
    # The same at the MCP server once a Session header comes with it.
    with_session = await world.transport.request(
        "POST",
        MCP,
        session=session,
        token=AccessToken(access_token=SecretStr(tokens["access_token"])),
        headers=as_json,
        content=json.dumps(LIST_TOOLS).encode(),
    )
    assert with_session.status_code == 401
    # And no Session was started for the client, signed in or out.
    assert not [
        record
        for record in await world.shop.store.records("session")
        if record.value["client_id"] == client_id
    ]


@pytest.mark.asyncio
async def test_a_public_client_never_gets_the_default_token() -> None:
    world = public_world()
    client_id = await registered(world)
    for resource in (None, SHOP, f"{SHOP}/poppy/conversations", "https://other.example/mcp"):
        page = await authorize(world, client_id, LOOPBACK, resource=resource)
        assert page.status_code == 400, resource
    code = await code_for(world, client_id, LOOPBACK)
    form = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": LOOPBACK,
        "code_verifier": pkce()[0],
    }
    # No `resource`, the default token's, or a service it was not asked for: nothing,
    # and the code is still there for the request that names the right one.
    assert (await token(world, **form)).json()["error"] == "invalid_target"
    assert (await token(world, **form, resource=SHOP)).json()["error"] == "invalid_target"
    other = await token(world, **form, resource=ELSEWHERE)
    assert other.json()["error"] == "invalid_target"
    # The code named the MCP server: asked for another service, it is spent and gives nothing.
    assert (await token(world, **form, resource=MCP)).json()["error"] == "invalid_grant"

    tokens = await sign_in(world, client_id)
    assert (await refresh(world, client_id, tokens["refresh_token"], resource=SHOP)).json()[
        "error"
    ] == "invalid_target"
    assert (await refresh(world, client_id, tokens["refresh_token"], resource=ELSEWHERE)).json()[
        "error"
    ] == "invalid_target"
    # A token for the MCP server is nothing at the other service.
    assert await world.shop.access_token_for(tokens["access_token"], ELSEWHERE) is None


@pytest.mark.asyncio
async def test_a_public_client_gets_only_its_own_grants_and_scopes() -> None:
    world = public_world()
    client_id = await registered(world)
    # `poppy:browser-sign-in` is a personal agent's: never asked, never granted.
    page = await authorize(world, client_id, LOOPBACK, scope="orders:read poppy:browser-sign-in")
    assert page.status_code == 400
    # The device and mediated grants are a personal agent's.
    for grant in (DEVICE_CODE_GRANT, "urn:poppy:params:oauth:grant-type:mediated"):
        refused = await token(world, grant_type=grant, client_id=client_id, resource=MCP)
        assert refused.status_code == 400
        assert refused.json()["error"] in {"unauthorized_client", "unsupported_grant_type"}
    device = await world.http.post(
        f"{SHOP}/oauth/device", data={"client_id": client_id, "scope": "orders:read"}
    )
    assert (device.status_code, device.json()["error"]) == (401, "invalid_client")

    narrowed = public_world(public_client_scopes=("orders:read",))
    narrow_client = await registered(narrowed)
    page = await authorize(narrowed, narrow_client, LOOPBACK, scope="orders:read orders:write")
    assert page.status_code == 400
    assert (await authorize(narrowed, narrow_client, LOOPBACK)).status_code == 200


@pytest.mark.asyncio
async def test_a_public_client_approves_no_operation() -> None:
    world = public_world()
    client_id = await registered(world)
    tokens = await sign_in(world, client_id, scope="orders:read orders:write")
    called = await mcp(
        world,
        tokens["access_token"],
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "exchange_jacket",
                "arguments": {},
                # An approval a personal agent would send: read from no public client.
                "_meta": {"poppy/approval": {"operation_id": "op_1", "revision": 1}},
            },
        },
    )
    result = called.json()["result"]
    assert result["isError"] is True
    assert "structuredContent" not in result
    assert "personal agent" in result["content"][0]["text"]
    assert not await world.shop.store.records("operation")


@pytest.mark.asyncio
async def test_a_personal_agent_cannot_become_a_public_client() -> None:
    """Its assertion is never skipped: its sign-ins, codes and document stay its own."""

    world = public_world()
    await signed_in(world)
    assert world.refresh_reference is not None
    kept = await world.host.vault.get(world.refresh_reference)
    agent_refresh = kept.get_secret_value() if isinstance(kept, SecretStr) else str(kept)
    client_id = await registered(world)

    # Its own `client_id`, no assertion: its document names its keys, so it is no public client.
    bare = await refresh(world, world.atlas.client_id, agent_refresh)
    assert (bare.status_code, bare.json()["error"]) == (401, "invalid_client")
    # Its refresh token under a public client's `client_id`: not that class of sign-in.
    borrowed = await refresh(world, client_id, agent_refresh)
    assert (borrowed.status_code, borrowed.json()["error"]) == (400, "invalid_grant")
    # Neither attempt ended its sign-in: it refreshes as before.
    assert (await world.refreshed()).access_token

    # Its authorization code is exchanged with its assertion only.
    page = await authorize(
        world, world.atlas.client_id, "https://atlas.example/oauth/callback", resource=None
    )
    back = await world.shop.approve_authorization(request_id_of(page), account_id="acct_ada")
    agent_code = parse_qs(urlsplit(back).query)["code"][0]
    for claimed in (world.atlas.client_id, client_id):
        refused = await token(
            world,
            grant_type="authorization_code",
            client_id=claimed,
            code=agent_code,
            redirect_uri="https://atlas.example/oauth/callback",
            code_verifier=pkce()[0],
            resource=MCP,
        )
        assert refused.status_code in {400, 401}
        assert refused.json()["error"] in {"invalid_client", "invalid_grant"}

    # And a public client's code is nothing to a personal agent with a valid assertion.
    public_code = await code_for(world, client_id, LOOPBACK)
    assertion = await SessionClient(
        reactor=world.reactor, http_client=world.http
    ).client_authentication(client_id=world.atlas.client_id, issuer=SHOP)
    crossed = await token(
        world,
        grant_type="authorization_code",
        code=public_code,
        redirect_uri=LOOPBACK,
        code_verifier=pkce()[0],
        **assertion,
    )
    assert (crossed.status_code, crossed.json()["error"]) == (400, "invalid_grant")


@pytest.mark.asyncio
async def test_a_document_is_one_class_of_client_and_never_both() -> None:
    both = document(jwks_uri="https://client.example/jwks.json")
    with pytest.raises(ValidationError):
        PublicClientMetadata.model_validate(both)
    with pytest.raises(ValidationError):
        PublicClientMetadata.model_validate(
            document(**{"token_endpoint_auth_method": "private_key_jwt"})
        )
    with pytest.raises(ValidationError):
        # Said, never assumed: a document that leaves the method out is no public client's.
        PublicClientMetadata.model_validate(
            {k: v for k, v in document().items() if k != "token_endpoint_auth_method"}
        )
    with pytest.raises(ValidationError):
        PublicClientMetadata.model_validate(document(client_secret="s3cret"))  # noqa: S106
    world = public_world(site=both)
    page = await authorize(world, VERIFIED, VERIFIED_REDIRECT)
    assert page.status_code == 400 and "location" not in page.headers

    # A redirect on another host than the document's is never matched; loopback is.
    world = public_world()
    stray = await authorize(world, VERIFIED, "https://elsewhere.example/callback")
    assert stray.status_code == 400 and "location" not in stray.headers
    assert (await authorize(world, VERIFIED, "http://127.0.0.1:8123/callback")).status_code == 200


@pytest.mark.asyncio
async def test_a_document_at_a_private_address_is_never_fetched() -> None:
    fetched: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        return httpx.Response(200, json=document())

    async def private(_host: str) -> list[str]:
        return ["10.0.0.7"]

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        identity = AgentIdentityClient(http_client=http, address_resolver=private)
        with pytest.raises(PersonalAgentProtocolError):
            await identity.fetch_public_metadata(VERIFIED)
        for literal in (
            "https://127.0.0.1/client.json",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/client.json",
            "http://client.example/oauth/client.json",
        ):
            with pytest.raises(PersonalAgentProtocolError):
                await identity.fetch_public_metadata(literal)
    assert fetched == []


@pytest.mark.asyncio
async def test_a_document_that_redirects_or_names_another_url_is_refused() -> None:
    def redirecting(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://10.0.0.7/client.json"})

    def another(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=document(client_id="https://other.example/client.json"))

    async def public(_host: str) -> list[str]:
        return ["93.184.216.34"]

    for handler in (redirecting, another):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            identity = AgentIdentityClient(http_client=http, address_resolver=public)
            with pytest.raises(PersonalAgentProtocolError):
                await identity.fetch_public_metadata(VERIFIED)


# PKCE, codes, redirects -----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pkce_is_the_only_proof_and_is_never_skipped() -> None:
    world = public_world()
    client_id = await registered(world)
    for changes in (
        {"code_challenge": None},
        {"code_challenge_method": None},
        {"code_challenge_method": "plain"},
        {"code_challenge": "short"},
        {"response_type": "token"},
    ):
        page = await authorize(world, client_id, LOOPBACK, **changes)
        # An unverified client is answered a page, never a redirect.
        assert page.status_code == 400 and "location" not in page.headers, changes

    form = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "redirect_uri": LOOPBACK,
        "resource": MCP,
    }
    for verifier in (None, "", "w" * 43, "v" * 42, "v" * 129, "v" * 42 + "!"):
        code = await code_for(world, client_id, LOOPBACK)
        attempt = dict(form, code=code)
        if verifier is not None:
            attempt["code_verifier"] = verifier
        refused = await token(world, **attempt)
        assert (refused.status_code, refused.json()["error"]) == (400, "invalid_grant"), verifier
        # A refused exchange spent the code: the right verifier gets nothing after it.
        again = await token(world, **dict(form, code=code, code_verifier=pkce()[0]))
        assert again.json()["error"] == "invalid_grant"

    # A code is the client's it was issued to, for the redirect it was issued for, once.
    other = await registered(world, client_name="Another")
    code = await code_for(world, client_id, LOOPBACK)
    stolen = await token(world, **dict(form, client_id=other, code=code, code_verifier=pkce()[0]))
    assert stolen.json()["error"] == "invalid_grant"
    code = await code_for(world, client_id, LOOPBACK)
    moved = await token(
        world,
        **dict(
            form, code=code, code_verifier=pkce()[0], redirect_uri="http://127.0.0.1:1/callback"
        ),
    )
    assert moved.json()["error"] == "invalid_grant"
    code = await code_for(world, client_id, LOOPBACK)
    first = await token(world, **dict(form, code=code, code_verifier=pkce()[0]))
    assert first.status_code == 200
    second = await token(world, **dict(form, code=code, code_verifier=pkce()[0]))
    assert second.json()["error"] == "invalid_grant"


def test_a_redirect_uri_is_loopback_or_https_and_nothing_else() -> None:
    for accepted in (
        "https://client.example/callback",
        "https://client.example:8443/callback?tenant=1",
        "https://xn--bcher-kva.example/cb",
        "http://127.0.0.1/callback",
        "http://127.0.0.1:53211/callback",
        "http://[::1]:53211/callback",
        "http://localhost:53211/callback",
    ):
        assert public_redirect_uri(accepted) == accepted
    for refused in (
        "",
        "HTTPS://client.example/callback",
        "https:/client.example/callback",
        "https://client.example.:443/callback",
        "http://client.example/callback",
        "https://user@client.example/callback",
        "https://user:pw@client.example/callback",
        "https://client.example@evil.example/callback",
        "https://client.example/callback#fragment",
        "https://client.example/callback#",
        "https://Client.example/callback",
        "https://client.example\\@evil.example/callback",
        "https://client.example /callback",
        "https://client.example/call\tback",
        "https://client.example/call\nback",
        "https:///callback",
        "https://client.example:0/callback",
        "https://client.example:70000/callback",
        "https://[::1]/callback",
        "https://bücher.example/cb",
        "http://127.0.0.1.evil.example/callback",
        "http://127.0.0.1:80@evil.example/callback",
        "http://localhost.evil.example/callback",
        "http://127.1/callback",
        "http://2130706433/callback",
        "http://0.0.0.0/callback",
        "http://10.0.0.1/callback",
        "http://localhost:99999/callback",
        "cursor://callback",
        "javascript:alert(1)",
        "data:text/html,x",
        "//client.example/callback",
        "https://client.example/" + "a" * 2000,
    ):
        with pytest.raises(ValueError):
            public_redirect_uri(refused)
    assert is_public_loopback_redirect("http://localhost/cb")
    assert not is_public_loopback_redirect("https://localhost/cb")


def test_a_redirect_uri_matches_exactly_but_for_a_loopback_port() -> None:
    https = "https://client.example/callback"
    assert public_redirect_uri_matches(https, https)
    for other in (
        "https://client.example/callback/",
        "https://client.example/callback?next=https://evil.example",
        "https://client.example/callback/../evil",
        "https://client.example:8443/callback",
        "https://client.example/Callback",
        "https://client.example.evil.example/callback",
        "https://evil.example/callback",
        "https://client.example/callback#x",
        "https://client.example/callback%2f..",
    ):
        assert not public_redirect_uri_matches(https, other), other
    loopback = "http://127.0.0.1/callback"
    assert public_redirect_uri_matches(loopback, "http://127.0.0.1:53211/callback")
    for other in (
        "http://127.0.0.1:53211/other",
        "http://127.0.0.1:53211/callback?x=1",
        "http://localhost:53211/callback",
        "http://[::1]:53211/callback",
        "https://127.0.0.1:53211/callback",
        "http://127.0.0.1:53211@evil.example/callback",
        "http://127.0.0.1:99999/callback",
    ):
        assert not public_redirect_uri_matches(loopback, other), other


@pytest.mark.asyncio
async def test_a_request_with_another_redirect_is_never_redirected() -> None:
    world = public_world()
    client_id = await registered(world, redirect_uris=["https://pocket.example/callback"])
    for redirect_uri in (
        "https://pocket.example/callback?next=https://evil.example",
        "https://pocket.example/callback/..%2fevil",
        "https://user@pocket.example/callback",
        "https://pocket.example.evil.example/callback",
        "https://pocket.example/callback#x",
        "https://evil.example/callback",
        "http://127.0.0.1/callback",
        "",
    ):
        page = await authorize(world, client_id, redirect_uri)
        assert page.status_code == 400 and "location" not in page.headers, redirect_uri


@pytest.mark.asyncio
async def test_an_unverified_clients_errors_are_pages_and_a_verified_ones_redirects() -> None:
    """Anyone registers any HTTPS redirect: answered with no one's consent, an error
    would make the authorization endpoint an open redirector (RFC 9700 §4.11.2)."""

    world = public_world()
    client_id = await registered(world, redirect_uris=["https://pocket.example/callback"])
    for changes in ({"scope": "nothing:here"}, {"scope": ""}, {"resource": SHOP}):
        page = await authorize(world, client_id, "https://pocket.example/callback", **changes)
        assert page.status_code == 400 and "location" not in page.headers, changes
    # A client verified by its domain is answered at its own domain, with state and issuer.
    answered = await authorize(world, VERIFIED, VERIFIED_REDIRECT, scope="nothing:here")
    assert answered.status_code == 303
    query = parse_qs(urlsplit(answered.headers["location"]).query)
    assert answered.headers["location"].startswith(f"{VERIFIED_REDIRECT}?")
    assert query == {"error": ["invalid_scope"], "state": ["st-1"], "iss": [SHOP]}
    # A refusal by the person reaches either, after they decided.
    page = await authorize(world, client_id, "https://pocket.example/callback")
    denied = await world.shop.deny_authorization(request_id_of(page))
    assert parse_qs(urlsplit(denied).query) == {
        "error": ["access_denied"],
        "state": ["st-1"],
        "iss": [SHOP],
    }


@pytest.mark.asyncio
async def test_a_decision_counts_once_and_the_name_is_shown_as_text() -> None:
    world = public_world()
    client_id = await registered(world, client_name="<img src=x onerror=alert(1)>")
    page = await authorize(world, client_id, LOOPBACK)
    assert "<img" not in page.text and "&lt;img" in page.text
    request_id = request_id_of(page)
    await world.shop.approve_authorization(request_id, account_id="acct_ada")
    with pytest.raises(KeyError):
        await world.shop.approve_authorization(request_id, account_id="acct_ada")
    with pytest.raises(KeyError):
        await world.shop.deny_authorization(request_id)


# Refresh tokens -------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_refresh_token_is_rotated_and_one_used_twice_ends_the_sign_in() -> None:
    world = public_world()
    # Whatever the setting says for personal agents.
    assert world.shop.config.refresh_reuse_revokes is False
    client_id = await registered(world)
    tokens = await sign_in(world, client_id)
    first = await refresh(world, client_id, tokens["refresh_token"])
    assert first.status_code == 200, first.text
    rotated = first.json()
    assert rotated["refresh_token"] != tokens["refresh_token"]
    assert rotated["token_type"] == "Bearer"
    assert (await mcp(world, rotated["access_token"], LIST_TOOLS)).status_code == 200

    # The first one again: whoever holds a copy, the whole sign-in ends.
    replayed = await refresh(world, client_id, tokens["refresh_token"])
    assert (replayed.status_code, replayed.json()["error"]) == (400, "invalid_grant")
    after = await refresh(world, client_id, rotated["refresh_token"])
    assert after.json()["error"] == "invalid_grant"
    for access_token in (tokens["access_token"], rotated["access_token"]):
        assert (await mcp(world, access_token, LIST_TOOLS)).status_code == 401
    assert await world.shop.public_client_sign_ins() == ()


@pytest.mark.asyncio
async def test_a_refresh_token_is_its_clients_and_lasts_thirty_days() -> None:
    world = public_world()
    client_id = await registered(world)
    other = await registered(world, client_name="Another")
    tokens = await sign_in(world, client_id)
    stolen = await refresh(world, other, tokens["refresh_token"])
    assert stolen.json()["error"] == "invalid_grant"
    unknown = await refresh(world, "mcpc_AAAAAAAAAAAAAAAAAAAAAA", tokens["refresh_token"])
    assert (unknown.status_code, unknown.json()["error"]) == (401, "invalid_client")
    # Narrower scopes only.
    wider = await refresh(world, client_id, tokens["refresh_token"], scope="orders:write")
    assert wider.json()["error"] == "invalid_scope"

    world.clock.advance(29 * 24 * 3600)
    kept = await refresh(world, client_id, tokens["refresh_token"])
    assert kept.status_code == 200
    # Thirty days from the sign-in, not from the last refresh.
    world.clock.advance(2 * 24 * 3600)
    late = await refresh(world, client_id, kept.json()["refresh_token"])
    assert late.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_a_public_client_revokes_its_own_sign_in() -> None:
    world = public_world()
    client_id = await registered(world)
    other = await registered(world, client_name="Another")
    tokens = await sign_in(world, client_id)
    # Another client's request ends nothing.
    await world.http.post(
        f"{SHOP}/oauth/revoke", data={"client_id": other, "token": tokens["refresh_token"]}
    )
    assert (await mcp(world, tokens["access_token"], LIST_TOOLS)).status_code == 200
    done = await world.http.post(
        f"{SHOP}/oauth/revoke", data={"client_id": client_id, "token": tokens["refresh_token"]}
    )
    assert done.status_code == 200
    assert (await mcp(world, tokens["access_token"], LIST_TOOLS)).status_code == 401
    assert (await refresh(world, client_id, tokens["refresh_token"])).json()[
        "error"
    ] == "invalid_grant"


# Registration ---------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_only_a_public_client_registers() -> None:
    world = public_world(client_registrations_per_hour=1000)
    accepted = await register(world)
    body = accepted.json()
    assert accepted.status_code == 201 and accepted.headers["cache-control"] == "no-store"
    assert body["token_endpoint_auth_method"] == "none"
    assert body["grant_types"] == ["authorization_code", "refresh_token"]
    assert body["response_types"] == ["code"]
    assert "client_secret" not in body and "registration_access_token" not in body
    assert (await register(world, client_name=None)).status_code == 400

    refusals: list[tuple[dict[str, object], str]] = [
        ({"token_endpoint_auth_method": "client_secret_basic"}, "invalid_client_metadata"),
        ({"token_endpoint_auth_method": "private_key_jwt"}, "invalid_client_metadata"),
        ({"token_endpoint_auth_method": None}, "invalid_client_metadata"),
        ({"jwks_uri": "https://pocket.example/jwks.json"}, "invalid_client_metadata"),
        ({"jwks": {"keys": []}}, "invalid_client_metadata"),
        ({"client_secret": "s3cret"}, "invalid_client_metadata"),
        ({"grant_types": ["client_credentials"]}, "invalid_client_metadata"),
        ({"grant_types": ["refresh_token"]}, "invalid_client_metadata"),
        ({"grant_types": ["authorization_code", DEVICE_CODE_GRANT]}, "invalid_client_metadata"),
        ({"response_types": ["token"]}, "invalid_client_metadata"),
        ({"client_name": ""}, "invalid_client_metadata"),
        ({"client_name": "x" * 101}, "invalid_client_metadata"),
        ({"client_name": "Claude‮ (verified)"}, "invalid_client_metadata"),
        ({"client_name": "Claude\u0000"}, "invalid_client_metadata"),
        ({"client_name": 7}, "invalid_client_metadata"),
        ({"redirect_uris": []}, "invalid_redirect_uri"),
        ({"redirect_uris": "https://pocket.example/callback"}, "invalid_redirect_uri"),
        ({"redirect_uris": [LOOPBACK, LOOPBACK]}, "invalid_redirect_uri"),
        (
            {"redirect_uris": [f"https://pocket.example/{n}" for n in range(11)]},
            "invalid_redirect_uri",
        ),
        ({"redirect_uris": ["http://pocket.example/callback"]}, "invalid_redirect_uri"),
        ({"redirect_uris": ["cursor://callback"]}, "invalid_redirect_uri"),
        ({"redirect_uris": ["https://user@pocket.example/cb"]}, "invalid_redirect_uri"),
        ({"redirect_uris": ["https://pocket.example/cb#x"]}, "invalid_redirect_uri"),
        ({"redirect_uris": [LOOPBACK, 7]}, "invalid_redirect_uri"),
    ]
    for changes, error in refusals:
        refused = await register(world, **changes)
        assert (refused.status_code, refused.json()["error"]) == (400, error), changes
    for content in (b"[]", b"not json", b'{"a": 1, "a": 2}', b" " * (16 * 1024 + 1)):
        refused = await world.http.post(
            f"{SHOP}/oauth/register", content=content, headers={"content-type": "application/json"}
        )
        assert refused.status_code == 400, content[:10]


@pytest.mark.asyncio
async def test_registration_is_limited_by_address() -> None:
    world = public_world(client_registrations_per_hour=3)
    for _ in range(3):
        assert (await register(world)).status_code == 201
    limited = await register(world)
    assert limited.status_code == 429
    assert 0 < int(limited.headers["retry-after"]) <= 3600
    # A refused registration counts too: the limit is on asking, not on succeeding.
    assert (await register(world, redirect_uris=[])).status_code == 429
    world.clock.advance(3601)
    assert (await register(world)).status_code == 201

    # Another address has its own count; a request that names none shares one.
    direct = [
        await world.shop.handle(_registration(address))
        for address in ("203.0.113.5", "203.0.113.5", None, None)
    ]
    assert [response.status for response in direct] == [201, 201, 201, 201]


def _registration(address: str | None) -> CompanyRequest:
    return CompanyRequest(
        method="POST",
        url=f"{SHOP}/oauth/register",
        headers={"content-type": "application/json"},
        body=json.dumps(
            {"redirect_uris": [LOOPBACK], "token_endpoint_auth_method": "none"}
        ).encode(),
        client_address=address,
    )


@pytest.mark.asyncio
async def test_the_hosts_rate_limit_is_asked_by_address_before_anything_is_read() -> None:
    asked: list[tuple[str, str | None]] = []

    class Limited:
        async def admit(self, client_id: str, account_id: str | None) -> int | None:
            asked.append((client_id, account_id))
            return 120 if client_id.startswith("registration:") else None

    class Plugin:
        @hookimpl
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(COMPANY_RATE_LIMITS, Limited(), contribution_id="limit")  # type: ignore[attr-defined]

    world = public_world()
    world.shop.reactor.register_plugin(PluginManifest(name="limit", version="1"), Plugin())
    refused = await world.http.post(f"{SHOP}/oauth/register", content=b"not json")
    assert refused.status_code == 429 and refused.headers["retry-after"] == "120"
    assert asked == [("registration:127.0.0.1", None)]
    assert not await world.shop.store.records("public_client")


@pytest.mark.asyncio
async def test_a_registration_lasts_while_it_is_used() -> None:
    world = public_world()
    client_id = await registered(world)
    world.clock.advance(80 * 24 * 3600)
    tokens = await sign_in(world, client_id)
    # Signing in kept it ninety days more: it outlives the sign-in it gave.
    world.clock.advance(20 * 24 * 3600)
    assert (await refresh(world, client_id, tokens["refresh_token"])).status_code == 200
    world.clock.advance(71 * 24 * 3600)
    gone = await authorize(world, client_id, LOOPBACK)
    assert gone.status_code == 400
    forgotten = await registered(world, client_name="Short-lived")
    world.clock.advance(91 * 24 * 3600)
    assert (await authorize(world, forgotten, LOOPBACK)).status_code == 400


# The client policy, and what the company gives now -------------------------------------------


class Policy:
    """Blocks, refuses sign-in to, or leaves a service out for, the clients it is told."""

    def __init__(self) -> None:
        self.blocked: set[str] = set()
        self.no_sign_in: set[str] = set()
        self.no_resource: set[tuple[str, str]] = set()
        self.asked: list[str] = []

    async def allows(self, client_id: str) -> bool:
        self.asked.append(client_id)
        return client_id not in self.blocked

    async def allows_sign_in(self, client_id: str, grant_type: str) -> bool:
        return client_id not in self.no_sign_in

    async def allows_resource(self, client_id: str, resource: str) -> bool:
        return (client_id, resource) not in self.no_resource


def with_policy(world: World) -> Policy:
    policy = Policy()

    class Plugin:
        @hookimpl
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(CLIENT_POLICIES, policy, contribution_id="p", order=-10)  # type: ignore[attr-defined]

    world.shop.reactor.register_plugin(PluginManifest(name="policy", version="1"), Plugin())
    return policy


@pytest.mark.asyncio
async def test_the_client_policy_is_asked_each_time_and_before_anything_is_fetched() -> None:
    world = public_world()
    policy = with_policy(world)
    client_id = await registered(world)
    own = await sign_in(world, client_id)
    elsewhere = await sign_in(world, client_id, resource=ELSEWHERE)
    assert await world.shop.access_token_for(elsewhere["access_token"], ELSEWHERE) is not None

    # Left out of one service: its token for it stops at once, the other still works.
    policy.no_resource.add((client_id, ELSEWHERE))
    assert await world.shop.access_token_for(elsewhere["access_token"], ELSEWHERE) is None
    assert (await mcp(world, own["access_token"], LIST_TOOLS)).status_code == 200
    assert (await refresh(world, client_id, elsewhere["refresh_token"], resource=ELSEWHERE)).json()[
        "error"
    ] == "invalid_target"
    assert (await authorize(world, client_id, LOOPBACK, resource=ELSEWHERE)).status_code == 400
    policy.no_resource.clear()

    # Refused sign-in: nothing new, and a code already issued gives nothing.
    code = await code_for(world, client_id, LOOPBACK)
    policy.no_sign_in.add(client_id)
    assert (await authorize(world, client_id, LOOPBACK)).status_code == 400
    late = await token(
        world,
        grant_type="authorization_code",
        client_id=client_id,
        code=code,
        redirect_uri=LOOPBACK,
        code_verifier=pkce()[0],
        resource=MCP,
    )
    assert late.json()["error"] == "unauthorized_client"
    policy.no_sign_in.clear()

    # Blocked: every token stops at once, everywhere.
    policy.blocked.add(client_id)
    assert (await mcp(world, own["access_token"], LIST_TOOLS)).status_code == 401
    assert await world.shop.access_token_for(elsewhere["access_token"], ELSEWHERE) is None
    blocked = await refresh(world, client_id, own["refresh_token"])
    assert (blocked.status_code, blocked.json()["error"]) == (401, "invalid_client")
    assert (await authorize(world, client_id, LOOPBACK)).status_code == 400

    # A blocked URL is never fetched: the policy answers before the resolver is asked.
    fetched: list[str] = []
    site = json_site({"/oauth/client.json": document()})

    async def watched(scope: Any, receive: Any, send: Any) -> None:
        fetched.append(scope["path"])
        await site(scope, receive, send)

    fresh = public_world()
    fresh_policy = with_policy(fresh)
    fresh.network.add("client.example", watched)
    fresh_policy.blocked.add(VERIFIED)
    assert (await authorize(fresh, VERIFIED, VERIFIED_REDIRECT)).status_code == 400
    assert (await refresh(fresh, VERIFIED, "rt_x")).status_code == 401
    assert fetched == []


@pytest.mark.asyncio
async def test_a_verified_client_is_read_again_at_each_token_request() -> None:
    """A document that became a personal agent's, or went away, gets nothing more."""

    world = public_world()
    tokens = await sign_in(world, VERIFIED, VERIFIED_REDIRECT)
    assert (await refresh(world, VERIFIED, tokens["refresh_token"])).status_code == 200
    # A new company process reads the document again, which now names keys.
    restarted = World()
    restarted.network.add(
        "client.example",
        json_site({"/oauth/client.json": document(jwks_uri="https://client.example/jwks.json")}),
    )
    restarted.shop, restarted.plugin = manzanita(
        restarted.network,
        restarted.clock,
        store=world.shop.store,
        config=world.shop.config,
    )
    refused = await refresh(restarted, VERIFIED, "rt_anything")
    assert (refused.status_code, refused.json()["error"]) == (401, "invalid_client")


@pytest.mark.asyncio
async def test_turned_off_public_clients_tokens_stop() -> None:
    world = public_world()
    client_id = await registered(world)
    own = await sign_in(world, client_id)
    elsewhere = await sign_in(world, client_id, resource=ELSEWHERE)
    world.shop.config = dataclasses.replace(
        world.shop.config, public_client_scopes=("orders:write",)
    )
    # Outside what public clients are given now.
    assert await world.shop.access_token_for(elsewhere["access_token"], ELSEWHERE) is None
    assert (await mcp(world, own["access_token"], LIST_TOOLS)).status_code == 401
    assert (await refresh(world, client_id, own["refresh_token"])).json()[
        "error"
    ] == "invalid_scope"
    world.shop.config = dataclasses.replace(
        world.shop.config,
        public_clients=False,
        client_registration=False,
        public_client_scopes=None,
    )
    assert await world.shop.access_token_for(elsewhere["access_token"], ELSEWHERE) is None
    assert (await mcp(world, own["access_token"], LIST_TOOLS)).status_code in {400, 401}
    refused = await refresh(world, client_id, own["refresh_token"])
    assert (refused.status_code, refused.json()["error"]) == (401, "invalid_client")


@pytest.mark.asyncio
async def test_sign_in_turned_off_for_personal_agents_leaves_public_clients() -> None:
    world = public_world(sign_in_disabled=True, mediated_fields=(), ucp=False)
    client_id = await registered(world)
    tokens = await sign_in(world, client_id)
    assert (await mcp(world, tokens["access_token"], LIST_TOOLS)).status_code == 200
    # A personal agent is still refused there.
    page = await authorize(
        world, world.atlas.client_id, "https://atlas.example/oauth/callback", resource=None
    )
    assert page.status_code == 303
    assert parse_qs(urlsplit(page.headers["location"]).query)["error"] == ["unauthorized_client"]


# The owner's list -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_owner_lists_and_revokes_public_clients_sign_ins() -> None:
    world = public_world()
    await signed_in(world)  # A personal agent's sign-in is none of them.
    client_id = await registered(world)
    start = world.clock.now()
    registered_tokens = await sign_in(world, client_id, "http://127.0.0.1:5000/callback")
    verified_tokens = await sign_in(
        world, VERIFIED, VERIFIED_REDIRECT, resource=ELSEWHERE, scope="orders:read orders:write"
    )
    listed = {entry.client_id: entry for entry in await world.shop.public_client_sign_ins()}
    assert set(listed) == {client_id, VERIFIED}
    unverified = listed[client_id]
    assert (unverified.client_name, unverified.verified) == ("Pocket MCP", False)
    assert unverified.redirect_host == "127.0.0.1:5000"
    assert (unverified.resource, unverified.account_id) == (MCP, "acct_ada")
    assert unverified.scopes == ("orders:read",)
    assert unverified.signed_in_at == start and unverified.last_used_at == start
    assert (unverified.expires_at - start).days == 30
    verified = listed[VERIFIED]
    assert (verified.client_name, verified.verified) == ("Deskmate", True)
    assert verified.redirect_host == "client.example" and verified.resource == ELSEWHERE
    assert verified.scopes == ("orders:read", "orders:write")

    # A refresh is its last use.
    world.clock.advance(3600)
    rotated = (await refresh(world, client_id, registered_tokens["refresh_token"])).json()
    again = {entry.client_id: entry for entry in await world.shop.public_client_sign_ins()}
    assert (again[client_id].last_used_at - start).total_seconds() == 3600  # type: ignore[operator]
    assert again[client_id].sign_in_id == unverified.sign_in_id
    assert again[VERIFIED].last_used_at == start

    assert await world.shop.revoke_public_client_sign_in(unverified.sign_in_id) is True
    assert await world.shop.revoke_public_client_sign_in(unverified.sign_in_id) is False
    assert await world.shop.revoke_public_client_sign_in("nothing") is False
    assert (await mcp(world, rotated["access_token"], LIST_TOOLS)).status_code == 401
    assert (await refresh(world, client_id, rotated["refresh_token"])).json()[
        "error"
    ] == "invalid_grant"
    # The other one, and the personal agent's, go on.
    assert [entry.client_id for entry in await world.shop.public_client_sign_ins()] == [VERIFIED]
    fresh = await refresh(world, VERIFIED, verified_tokens["refresh_token"], resource=ELSEWHERE)
    assert await world.shop.access_token_for(fresh.json()["access_token"], ELSEWHERE)
    assert (await world.refreshed()).access_token
    # A personal agent's sign-in is never ended from this list.
    families = [
        AccountFamily.from_json(record.value)
        for record in await world.shop.store.records(ACCOUNT_FAMILY)
    ]
    personal = next(family for family in families if family.public is None)
    assert await world.shop.revoke_public_client_sign_in(personal.tokens[0]) is False
    assert (await world.refreshed()).access_token


# Records and names ----------------------------------------------------------------------------


def test_a_personal_agents_records_are_written_as_before() -> None:
    now = datetime(2026, 11, 18, tzinfo=timezone.utc)
    records = (
        IssuedAccessToken("c", "a", ("s",), now, "f"),
        AccountGrant("a", "c", ("s",), now),
        AccountFamily("c", "a"),
        PendingAuthorization("c", "https://c.example/cb", ("s",), "st", "ch", now),
        IssuedCode("c", "https://c.example/cb", "ch", ("s",), "a", ("s",), now),
    )
    for record in records:
        written = record.to_json()
        assert "public" not in written and "last_used_at" not in written
        assert type(record).from_json(written) == record


def test_a_name_holds_nothing_that_hides_or_reorders_text() -> None:
    assert public_client_name("  Pocket MCP ") == "Pocket MCP"
    for refused in ("", "   ", "x" * 101, "a‮b", "a⁦b", "a​b", "a\nb", "a\x7fb", None, 3):
        with pytest.raises(ValueError):
            public_client_name(refused)


@pytest.mark.asyncio
async def test_a_company_without_a_public_resolver_verifies_none_by_domain() -> None:
    """A host's own resolver without `resolve_public`: only registered clients sign in."""

    world = public_world()

    class Plain:
        async def resolve(self, client_id: str, *, kid: str | None = None) -> Any:
            raise PersonalAgentProtocolError("invalid_client_metadata", "none here")

    class Plugin:
        @hookimpl
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(CLIENT_RESOLVERS, Plain(), contribution_id="plain", order=-10)  # type: ignore[attr-defined]

    world.shop.reactor.register_plugin(PluginManifest(name="plain", version="1"), Plugin())
    assert (await authorize(world, VERIFIED, VERIFIED_REDIRECT)).status_code == 400
    client_id = await registered(world)
    assert (await authorize(world, client_id, LOOPBACK)).status_code == 200
