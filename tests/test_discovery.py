# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import json
from pathlib import Path

import httpx
import pytest
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from personal_agent_protocol import (
    DISCOVERY_TRANSPORTS,
    URL_SAFETY_POLICIES,
    DiscoveryClient,
    DiscoveryError,
)
from personal_agent_protocol.reactor import DiscoveryResponse

FIXTURES = Path(__file__).parents[1] / "protocol" / "fixtures"


async def public_resolver(_: str) -> list[str]:
    return ["93.184.216.34"]


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text())


@pytest.mark.asyncio
async def test_discovers_and_authenticates_company() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(200, json=fixture("discovery-valid.json"))
        if request.url.host == "auth.example.com":
            return httpx.Response(200, json=fixture("oauth-metadata-valid.json"))
        return httpx.Response(404)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        company = await client.discover("example.com")

    assert company.document.organization.name == "Example Company"
    assert company.oauth_metadata is not None
    assert company.oauth_metadata.token_endpoint == ("https://auth.example.com/oauth/token")


@pytest.mark.asyncio
async def test_rejects_issuer_that_does_not_authorize_domain() -> None:
    metadata = fixture("oauth-metadata-valid.json")
    metadata["poppy_domains"] = ["attacker.example"]

    def handler(request: httpx.Request) -> httpx.Response:
        body = fixture("discovery-valid.json") if request.url.host == "example.com" else metadata
        return httpx.Response(200, json=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(DiscoveryError, match="domain_not_authorized"):
            await client.discover("example.com")


@pytest.mark.asyncio
async def test_rejects_private_discovery_address() -> None:
    async def private_resolver(_: str) -> list[str]:
        return ["127.0.0.1"]

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as http:
        client = DiscoveryClient(http_client=http, address_resolver=private_resolver)
        with pytest.raises(DiscoveryError, match="unsafe_address"):
            await client.discover("example.com")


@pytest.mark.asyncio
async def test_discovers_through_reactor_contributions() -> None:
    class SafePolicy:
        async def assert_safe(self, _: str) -> None:
            return None

    class FixtureTransport:
        async def get(self, url: str) -> DiscoveryResponse:
            name = (
                "discovery-valid.json"
                if url.startswith("https://example.com/")
                else "oauth-metadata-valid.json"
            )
            return DiscoveryResponse(
                url=url,
                status_code=200,
                headers={"content-type": "application/json"},
                content=(FIXTURES / name).read_bytes(),
            )

    class TestPlugin:
        def provide_contributions(self, contributions: object) -> None:
            contribute = contributions.contribute  # type: ignore[attr-defined]
            contribute(DISCOVERY_TRANSPORTS, FixtureTransport())
            contribute(URL_SAFETY_POLICIES, SafePolicy())

    reactor = PluginPlatform(extension_group="pap.tests")
    reactor.register_plugin(PluginManifest(name="pap-test", version="1"), TestPlugin())

    company = await DiscoveryClient(reactor=reactor).discover("example.com")

    assert company.oauth_metadata is not None
    assert company.oauth_metadata.issuer == "https://auth.example.com"
