# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Hosted sign-in pages: a company's Device and consent pages served elsewhere."""

from __future__ import annotations

import dataclasses
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from pydantic import SecretStr

from personal_agent_protocol import DeviceSignInClient
from personal_agent_protocol.company import CompanyConfig
from personal_agent_protocol.company.store import AUTHORIZATION
from personal_agent_protocol.demo.kit import personal_agent_reactor

from .test_company_end_to_end import TENANT, World
from .test_direct_and_api import begin

DEVICE_PAGE = "https://pap.manzanita.example/device?slug=orders-helper"
CONSENT_PAGE = "https://datalayer.ai/pap/consent?slug=orders-helper&request={request_id}"


class HandoffBrowser:
    """The user's browser: records where the company sends it, follows nothing."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.http = http
        self.responses: list[httpx.Response] = []

    async def open(self, authorization_url: SecretStr) -> None:
        self.responses.append(await self.http.get(authorization_url.get_secret_value()))


def hosted_world(**pages: str) -> tuple[World, HandoffBrowser]:
    world = World()
    world.shop.config = dataclasses.replace(world.shop.config, **pages)
    browser = HandoffBrowser(world.http)
    world.host.browser = browser  # type: ignore[assignment]
    world.reactor = personal_agent_reactor(
        world.host, network=world.network, http_client=world.http
    )
    return world, browser


def test_hosted_page_templates_are_checked() -> None:
    base = {
        "name": "Shop",
        "domain": "shop.example",
        "scopes": ("orders:read",),
        "scope_descriptions": {"orders:read": "See orders"},
        "operations": False,
    }
    with pytest.raises(ValueError, match="consent_page"):
        CompanyConfig(**base, consent_page="https://datalayer.ai/pap/consent")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="HTTPS"):
        CompanyConfig(**base, device_page="http://pap.shop.example/device")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="company's domain"):
        # A device page off the company's domains is a link personal agents refuse (§4.3).
        CompanyConfig(**base, device_page="https://datalayer.ai/pap/device")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="HTTPS"):
        CompanyConfig(**base, consent_page="https://x.example/c?r={request_id}#frag")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_device_sign_in_points_at_the_hosted_device_page() -> None:
    world, _ = hosted_world(device_page=DEVICE_PAGE)
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None and metadata.device_authorization_endpoint is not None
    started = await DeviceSignInClient(reactor=world.reactor, http_client=world.http).begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read",),
        tenant_id=TENANT,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    assert started.verification_uri == DEVICE_PAGE
    assert started.verification_uri_complete == (
        f"{DEVICE_PAGE}&{urlencode({'code': started.user_code})}"
    )


@pytest.mark.asyncio
async def test_authorize_redirects_to_the_hosted_consent_page_which_reads_the_request() -> None:
    world, browser = hosted_world(consent_page=CONSENT_PAGE)
    session = await world.signed_out_session()
    client = await begin(world, browser, session, ("orders:read", "orders:write"))  # type: ignore[arg-type]

    handed = browser.responses[-1]
    assert handed.status_code == 303
    assert handed.headers["cache-control"] == "no-store"
    location = urlsplit(handed.headers["location"])
    assert (location.scheme, location.netloc, location.path) == (
        "https",
        "datalayer.ai",
        "/pap/consent",
    )
    query = parse_qs(location.query)
    assert query["slug"] == ["orders-helper"]
    (request_id,) = query["request"]

    # The consent page asks who wants what; reading never consumes the request.
    summary = await world.shop.authorization_request(request_id)
    assert summary == await world.shop.authorization_request(request_id)
    assert summary["client_name"] == "Atlas"
    assert summary["client_domain"] == "atlas.example"
    assert summary["scopes"] == [
        {"scope": "orders:read", "description": "See your orders, returns and exchanges"},
        {"scope": "orders:write", "description": "Exchange or return items in your orders"},
    ]
    assert summary["expires_at"].endswith("Z")
    assert set(summary) == {"request_id", "client_name", "client_domain", "scopes", "expires_at"}

    # The user allows on the hosted page; the sign-in completes as before.
    callback = await world.shop.approve_authorization(request_id, account_id="acct_ada")
    result = await client.complete(callback)
    assert result.token.scopes == ("orders:read", "orders:write")
    with pytest.raises(KeyError):
        await world.shop.authorization_request(request_id)
    with pytest.raises(KeyError):
        await world.shop.authorization_request("authz_unknown")


@pytest.mark.asyncio
async def test_an_unverified_redirect_is_never_sent_to_the_consent_page() -> None:
    world, _ = hosted_world(consent_page=CONSENT_PAGE)
    await world.signed_out_session()

    def authorize(redirect_uri: str, response_type: str = "code") -> str:
        return "https://manzanita.example/oauth/authorize?" + urlencode(
            {
                "response_type": response_type,
                "client_id": world.atlas.client_id,
                "redirect_uri": redirect_uri,
                "scope": "orders:read",
                "state": "s",
                "code_challenge": "c" * 43,
                "code_challenge_method": "S256",
            }
        )

    response = await world.http.get(authorize("https://attacker.example/callback"))
    assert response.status_code == 400
    assert "location" not in response.headers
    assert world.shop.store.keys(AUTHORIZATION) == []
    # A request failing a later check goes back to the agent's verified redirect, not the page.
    callback = f"https://{world.atlas.domain}/oauth/callback"
    response = await world.http.get(authorize(callback, response_type="token"))
    assert response.status_code == 303
    assert response.headers["location"].startswith(f"{callback}?")
    assert world.shop.store.keys(AUTHORIZATION) == []


@pytest.mark.asyncio
async def test_without_hosted_pages_the_company_serves_its_own() -> None:
    world, browser = hosted_world()
    session = await world.signed_out_session()
    await begin(world, browser, session)  # type: ignore[arg-type]
    page = browser.responses[-1]
    assert page.status_code == 200
    assert "Atlas" in page.text and 'name="request_id"' in page.text
