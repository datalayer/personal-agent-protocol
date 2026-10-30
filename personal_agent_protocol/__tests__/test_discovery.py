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
from personal_agent_protocol.reactor import (
    ApprovedUrl,
    DiscoveryResponse,
    MetadataFetch,
    build_pap_reactor,
)

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"


async def public_resolver(_: str) -> list[str]:
    return ["93.184.216.34"]


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text())


RESOURCE_METADATA = "/.well-known/oauth-protected-resource"


def company_site(
    *, resource_metadata: dict[str, object] | None = None, document: dict[str, object] | None = None
) -> httpx.MockTransport:
    """example.com's poppy.json and protected resource metadata, auth.example.com's metadata."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com" and request.url.path == RESOURCE_METADATA:
            return httpx.Response(
                200, json=resource_metadata or fixture("protected-resource-metadata-valid.json")
            )
        if request.url.host == "example.com":
            return httpx.Response(200, json=document or fixture("discovery-valid.json"))
        if request.url.host == "auth.example.com":
            return httpx.Response(200, json=fixture("oauth-metadata-valid.json"))
        return httpx.Response(404)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_discovers_and_authenticates_company() -> None:
    async with httpx.AsyncClient(transport=company_site()) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        company = await client.discover("example.com")

    assert company.document.organization.name == "Example Company"
    assert company.oauth_metadata is not None
    assert company.oauth_metadata.token_endpoint == ("https://auth.example.com/oauth/token")
    # The issuer is the one the domain's protected resource metadata names (§3.2).
    assert company.issuer == "https://auth.example.com"
    assert company.resource_metadata is not None
    assert company.resource_metadata.resource == company.resource == "https://example.com"


@pytest.mark.asyncio
async def test_the_issuer_comes_from_the_domains_protected_resource_metadata() -> None:
    """One authorization server is the issuer: poppy.json may leave `auth` out (§3.1, §3.2)."""

    document = fixture("discovery-valid.json")
    document.pop("auth")
    async with httpx.AsyncClient(transport=company_site(document=document)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        company = await client.discover("example.com")
    assert company.document.auth is None
    assert company.issuer == "https://auth.example.com"


@pytest.mark.asyncio
async def test_refuses_protected_resource_metadata_for_another_resource() -> None:
    """`resource` is exactly `https://{organization.domain}` (§3.2)."""

    for other in ("https://example.com/", "https://www.example.com", "https://example.com/api"):
        transport = company_site(
            resource_metadata={
                "resource": other,
                "authorization_servers": ["https://auth.example.com"],
            }
        )
        async with httpx.AsyncClient(transport=transport) as http:
            client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
            with pytest.raises(DiscoveryError, match="resource_mismatch"):
                await client.discover("example.com")


@pytest.mark.asyncio
async def test_several_authorization_servers_need_auth_issuer_among_them() -> None:
    """Several authorization servers: `auth.issuer` names the one to use, from the list (§3.1)."""

    several = {
        "resource": "https://example.com",
        "authorization_servers": ["https://staff.example.com", "https://auth.example.com"],
    }
    without = fixture("discovery-valid.json")
    without.pop("auth")
    async with httpx.AsyncClient(
        transport=company_site(resource_metadata=several, document=without)
    ) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(DiscoveryError, match="issuer_not_named"):
            await client.discover("example.com")
    async with httpx.AsyncClient(transport=company_site(resource_metadata=several)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        assert (await client.discover("example.com")).issuer == "https://auth.example.com"
    unlisted = fixture("discovery-valid.json")
    unlisted["auth"]["issuer"] = "https://login.example.com"  # type: ignore[index]
    async with httpx.AsyncClient(
        transport=company_site(resource_metadata=several, document=unlisted)
    ) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(DiscoveryError, match="issuer_mismatch"):
            await client.discover("example.com")


@pytest.mark.asyncio
async def test_one_authorization_server_and_another_auth_issuer_is_refused() -> None:
    document = fixture("discovery-valid.json")
    document["auth"]["issuer"] = "https://login.example.com"  # type: ignore[index]
    async with httpx.AsyncClient(transport=company_site(document=document)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(DiscoveryError, match="issuer_mismatch"):
            await client.discover("example.com")


@pytest.mark.asyncio
async def test_a_company_that_needs_an_issuer_and_publishes_none_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/poppy.json":
            return httpx.Response(200, json=fixture("discovery-valid.json"))
        return httpx.Response(404, json={"error": "not_found"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(DiscoveryError, match="issuer_not_found"):
            await client.discover("example.com")


@pytest.mark.asyncio
async def test_rejects_issuer_that_does_not_authorize_domain() -> None:
    metadata = fixture("oauth-metadata-valid.json")
    metadata["protected_resources"] = ["https://attacker.example"]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == RESOURCE_METADATA:
            return httpx.Response(200, json=fixture("protected-resource-metadata-valid.json"))
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
        async def assert_safe(self, url: str) -> ApprovedUrl:
            return ApprovedUrl(url=url, host=url.split("/")[2], addresses=("93.184.216.34",))

    class FixtureTransport:
        def __init__(self) -> None:
            self.fetches: list[MetadataFetch] = []

        async def get(self, url: str, *, fetch: MetadataFetch) -> DiscoveryResponse:
            self.fetches.append(fetch)
            name = (
                "protected-resource-metadata-valid.json"
                if url.endswith(RESOURCE_METADATA)
                else "discovery-valid.json"
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
            contribute(DISCOVERY_TRANSPORTS, transport)
            contribute(URL_SAFETY_POLICIES, SafePolicy())

    transport = FixtureTransport()
    reactor = PluginPlatform(extension_group="pap.tests")
    reactor.register_plugin(PluginManifest(name="pap-test", version="1"), TestPlugin())

    company = await DiscoveryClient(reactor=reactor, timeout=2.0).discover("example.com")

    assert company.oauth_metadata is not None
    assert company.oauth_metadata.issuer == "https://auth.example.com"
    # Each fetch carries the policy's approval and the client's bounds to the transport.
    assert [fetch.approved.host for fetch in transport.fetches] == [
        "example.com",
        "example.com",
        "auth.example.com",
    ]
    assert {(fetch.max_bytes, fetch.timeout) for fetch in transport.fetches} == {(100 * 1024, 2.0)}


@pytest.mark.asyncio
async def test_refuses_a_policy_that_approves_nothing() -> None:
    class OldPolicy:
        async def assert_safe(self, _: str) -> None:
            return None

    class TestPlugin:
        def provide_contributions(self, contributions: object) -> None:
            contribute = contributions.contribute  # type: ignore[attr-defined]
            contribute(URL_SAFETY_POLICIES, OldPolicy(), order=1)

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as http:
        reactor, _ = build_pap_reactor(
            http_client=http, plugins=[(PluginManifest(name="old", version="1"), TestPlugin())]
        )
        with pytest.raises(TypeError, match="ApprovedUrl"):
            await DiscoveryClient(reactor=reactor).discover("example.com")


@pytest.mark.asyncio
async def test_metadata_fetches_carry_no_cookie_or_credential() -> None:
    seen: list[httpx.Headers] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        if request.url.path == RESOURCE_METADATA:
            return httpx.Response(200, json=fixture("protected-resource-metadata-valid.json"))
        if request.url.host == "example.com":
            return httpx.Response(200, json=fixture("discovery-valid.json"))
        return httpx.Response(200, json=fixture("oauth-metadata-valid.json"))

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        cookies={"session": "host-cookie"},
        headers={"Authorization": "Bearer host-token"},
    ) as http:
        await DiscoveryClient(http_client=http, address_resolver=public_resolver).discover(
            "example.com"
        )

    assert len(seen) == 3
    for headers in seen:
        assert "cookie" not in headers
        assert "authorization" not in headers


@pytest.mark.asyncio
async def test_an_alias_publishes_the_companys_discovery_and_its_issuer_lists_it() -> None:
    """A company on a domain of its owner's (PAP_DATALAYER D-02): the alias names itself as the
    organization's domain, the issuer stays the company's own and lists it in `poppy_domains`,
    so a personal agent discovering the alias finds the same company; nothing else answers there."""
    from dataclasses import replace

    from personal_agent_protocol.company import build_company, company_app
    from personal_agent_protocol.demo.kit import InProcessNetwork
    from personal_agent_protocol.demo.manzanita import CONFIG

    with pytest.raises(ValueError, match="another domain"):
        replace(CONFIG, aliases=(CONFIG.domain,))
    with pytest.raises(ValueError, match="small letters"):
        replace(CONFIG, aliases=("Shop.Example",))
    config = replace(CONFIG, aliases=("shop.example",))
    network = InProcessNetwork()
    service = build_company(config, http_client=network.client(), address_resolver=network.resolve)
    network.add(config.domain, company_app(service))
    network.add("shop.example", company_app(service))
    client = DiscoveryClient(http_client=network.client(), address_resolver=network.resolve)
    company = await client.discover("shop.example")
    assert company.document.organization.domain == "shop.example"
    assert company.oauth_metadata is not None
    assert company.oauth_metadata.issuer == f"https://{config.domain}"
    assert company.oauth_metadata.protected_resources[:2] == [
        f"https://{config.domain}",
        "https://shop.example",
    ]
    # Every endpoint is the issuer's: the alias is the same company, never a second identity.
    assert (
        company.document.auth is not None
        and company.document.auth.issuer == f"https://{config.domain}"
    )
    own = await client.discover(config.domain)
    assert own.document.organization.domain == config.domain
    # Every document naming the issuer has the same auth, which describes it (§3.2).
    assert own.document.auth == company.document.auth
    assert (
        service.discovery_document("shop.example")["auth"] == service.discovery_document()["auth"]
    )
    async with network.client() as http:
        # The alias's own protected resource metadata names the company's issuer (§3.2).
        alias_resource = (
            await http.get("https://shop.example/.well-known/oauth-protected-resource")
        ).json()
        assert alias_resource == {
            **alias_resource,
            "resource": "https://shop.example",
            "authorization_servers": [f"https://{config.domain}"],
        }
        assert (
            await http.get("https://shop.example/.well-known/oauth-authorization-server")
        ).status_code == 404
        assert (await http.post("https://shop.example/oauth/token", data={})).status_code == 404
    with pytest.raises(ValueError, match="not one of this company's domains"):
        service.discovery_document("elsewhere.example")
