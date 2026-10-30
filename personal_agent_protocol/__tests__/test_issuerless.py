# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A Company with no OAuth issuer: its identifier is its HTTPS domain (§3.2, §5.1, §5.2)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from personal_agent_protocol import AuthorizationError, DiscoveryClient, DiscoveryError
from personal_agent_protocol.actions import discover_company
from personal_agent_protocol.company import CompanyRequest
from personal_agent_protocol.demo.conformance import ManzanitaConformance
from personal_agent_protocol.demo.manzanita import CONFIG
from personal_agent_protocol.errors import ProtocolValidationError
from personal_agent_protocol.pairwise import SqlitePairwiseUserIdStore
from personal_agent_protocol.reactor import build_pap_reactor

RESOURCE_METADATA = "/.well-known/oauth-protected-resource"
SIGNED_OUT: dict[str, Any] = {
    "protocol_version": "0.3",
    "organization": {"name": "Example", "domain": "Example.COM"},
    "apis": [{"type": "openapi", "url": "https://example.com/o.json", "description": "Catalog"}],
    "agent": {"protocols": [{"type": "poppy", "endpoint": "https://example.com/poppy"}]},
    "feedback": {"endpoint": "https://example.com/feedback"},
    "web": {"browser_session_endpoint": "https://example.com/join"},
}
ISSUER_METADATA: dict[str, Any] = {
    "issuer": "https://auth.example.com",
    "token_endpoint": "https://auth.example.com/token",
    "revocation_endpoint": "https://auth.example.com/revoke",
    "grant_types_supported": ["refresh_token"],
    "protected_resources": ["https://example.com"],
}


async def _public(_: str) -> list[str]:
    return ["93.184.216.34"]


def _site(
    *,
    resource: httpx.Response | Exception,
    document: dict[str, Any] | None = None,
    issuer: httpx.Response | None = None,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/poppy.json":
            return httpx.Response(200, json=document or SIGNED_OUT)
        if request.url.path == RESOURCE_METADATA:
            if isinstance(resource, Exception):
                raise resource
            return resource
        return issuer or httpx.Response(404)

    return httpx.MockTransport(handler)


async def _discover(transport: httpx.MockTransport, *, timeout: float = 5.0) -> Any:
    async with httpx.AsyncClient(transport=transport) as http:
        client = DiscoveryClient(http_client=http, address_resolver=_public, timeout=timeout)
        return await client.discover("example.com")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resource",
    [
        httpx.Response(404),
        httpx.Response(200, json={"resource": "https://example.com"}),
        httpx.Response(200, json={"resource": "https://example.com", "authorization_servers": []}),
    ],
    ids=["404", "absent", "empty"],
)
async def test_no_issuer_is_found_and_the_identifier_is_the_domain(
    resource: httpx.Response,
) -> None:
    company = await _discover(_site(resource=resource))
    assert company.issuer is None and company.oauth_metadata is None
    assert company.identifier == "https://example.com"


@pytest.mark.asyncio
async def test_with_an_issuer_the_identifier_is_the_issuer() -> None:
    company = await _discover(
        _site(
            resource=httpx.Response(
                200,
                json={
                    "resource": "https://example.com",
                    "authorization_servers": ["https://auth.example.com"],
                },
            ),
            issuer=httpx.Response(200, json=ISSUER_METADATA),
        )
    )
    assert company.identifier == company.issuer == "https://auth.example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "offers",
    [
        {"auth": {"issuer": "https://auth.example.com"}},
        {
            "agent": {
                "protocols": [
                    {"type": "poppy", "endpoint": "https://example.com/p", "access": "signed_in"}
                ]
            }
        },
        {"extensions": {"mediated-sign-in": {"version": "2"}}},
    ],
    ids=["auth.issuer", "access", "mediated"],
)
async def test_no_issuer_is_refused_for_a_company_that_offers_sign_in(
    offers: dict[str, Any],
) -> None:
    with pytest.raises(DiscoveryError, match="issuer_not_found"):
        await _discover(_site(resource=httpx.Response(404), document={**SIGNED_OUT, **offers}))


@pytest.mark.asyncio
async def test_an_ordinary_extension_needs_no_issuer() -> None:
    document = {**SIGNED_OUT, "extensions": {"example.com/gift-wrap": {"version": "1"}}}
    company = await _discover(_site(resource=httpx.Response(404), document=document))
    assert company.identifier == "https://example.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403, 500, 503])
async def test_another_status_is_never_the_domain_fallback(status: int) -> None:
    with pytest.raises(DiscoveryError, match="http_error"):
        await _discover(_site(resource=httpx.Response(status)))


@pytest.mark.asyncio
async def test_a_timeout_is_never_the_domain_fallback() -> None:
    with pytest.raises(DiscoveryError):
        await _discover(_site(resource=httpx.ConnectTimeout("timed out")))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resource, code",
    [
        (httpx.Response(200, json={"authorization_servers": []}), "invalid_resource_metadata"),
        (
            httpx.Response(
                200, json={"resource": "https://example.com", "authorization_servers": None}
            ),
            "invalid_resource_metadata",
        ),
        (
            httpx.Response(200, json={"resource": "https://other.example"}),
            "resource_mismatch",
        ),
        (httpx.Response(200, text="not json"), "invalid_content_type"),
    ],
    ids=["no-resource", "null-servers", "another-resource", "not-json"],
)
async def test_invalid_metadata_is_never_the_domain_fallback(
    resource: httpx.Response, code: str
) -> None:
    with pytest.raises((DiscoveryError, ProtocolValidationError), match=code):
        await _discover(_site(resource=resource))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "issuer, code",
    [
        (httpx.Response(404), "http_error"),
        (httpx.Response(200, json={**ISSUER_METADATA, "issuer": "https://x.example"}), "issuer_"),
        (
            httpx.Response(200, json={**ISSUER_METADATA, "protected_resources": ["https://x.ex"]}),
            "domain_not_authorized",
        ),
    ],
    ids=["unpublished", "another-issuer", "domain-not-listed"],
)
async def test_an_issuer_that_fails_to_verify_is_never_the_domain_fallback(
    issuer: httpx.Response, code: str
) -> None:
    resource = httpx.Response(
        200,
        json={
            "resource": "https://example.com",
            "authorization_servers": ["https://auth.example.com"],
        },
    )
    with pytest.raises(DiscoveryError, match=code):
        await _discover(_site(resource=resource, issuer=issuer))


@pytest.mark.asyncio
async def test_sign_in_is_refused_locally() -> None:
    company = await _discover(_site(resource=httpx.Response(404)))
    with pytest.raises(AuthorizationError, match="no_issuer") as refused:
        company.require_oauth()
    assert "no sign-in" in refused.value.message


@pytest.mark.asyncio
async def test_the_discovery_summary_names_the_identifier() -> None:
    async with httpx.AsyncClient(transport=_site(resource=httpx.Response(404))) as http:
        reactor, _ = build_pap_reactor(http_client=http, address_resolver=_public)
        summary = await discover_company("example.com", reactor=reactor)
    assert summary["verified"] and summary["issuer"] is None and summary["sign_in"] == []
    assert summary["identifier"] == "https://example.com"


@pytest.mark.asyncio
async def test_a_known_issuer_is_never_lost_to_an_error() -> None:
    """Only a discovery that succeeds says the issuer is gone: an error leaves no Company."""

    fresh = {"Cache-Control": "no-store"}
    answers = [
        httpx.Response(
            200,
            headers=fresh,
            json={"resource": "https://example.com", "authorization_servers": []},
        ),
        httpx.Response(503),
        httpx.Response(
            200,
            headers=fresh,
            json={
                "resource": "https://example.com",
                "authorization_servers": ["https://auth.example.com"],
            },
        ),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/poppy.json":
            return httpx.Response(200, json=SIGNED_OUT)
        if request.url.path == RESOURCE_METADATA:
            return answers.pop()
        return httpx.Response(200, json=ISSUER_METADATA)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=_public)
        assert (await client.discover("example.com")).issuer == "https://auth.example.com"
        with pytest.raises(DiscoveryError, match="http_error"):
            await client.discover("example.com")
        assert (await client.discover("example.com")).identifier == "https://example.com"


@pytest.mark.asyncio
async def test_user_ids_are_scoped_by_the_identifier(tmp_path: Path) -> None:
    """Without an issuer, each domain is a separate Company (§3.2, §5.1)."""

    store = SqlitePairwiseUserIdStore(tmp_path / "ids.sqlite")
    ids = [
        await store.get_or_create(tenant_id="t", local_user_id="u", company_issuer=identifier)
        for identifier in (
            "https://example.com",
            "https://example.org",
            "https://example.com",
        )
    ]
    assert ids[0] == ids[2] != ids[1]


@pytest.mark.parametrize(
    "offers",
    [
        {"mediated_fields": (("email", "Email", False),), "operations": False},
        {"mediated_fields": (), "operations": True},
        {"mediated_fields": (), "operations": False, "aliases": ("other.example",)},
        {"mediated_fields": (), "operations": False, "dpop_binding": "optional"},
    ],
    ids=["mediated", "operations", "aliases", "dpop"],
)
def test_a_company_with_no_issuer_refuses_what_needs_one(offers: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="no issuer"):
        replace(CONFIG, oauth=False, **offers)


def test_the_companys_identifier_is_its_lowercase_domain() -> None:
    config = replace(
        CONFIG, oauth=False, mediated_fields=(), operations=False, domain="Shop.Example"
    )
    assert config.identifier == "https://shop.example"
    assert replace(CONFIG, domain="Shop.Example").identifier == "https://Shop.Example"


@pytest.mark.asyncio
async def test_the_mcp_server_of_a_company_with_no_issuer_names_no_metadata() -> None:
    """Signed out it needs the Session header, and no challenge points at OAuth (§3.2, §7)."""

    world = ManzanitaConformance("no-issuer")
    answer = await world.service.handle(
        CompanyRequest(
            "POST",
            f"{world.service.config.base}/mcp",
            {"authorization": "Bearer invented"},
            b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        )
    )
    assert answer.status == 400 and answer.body == {"error": "invalid_session"}
    metadata = await world.service.handle(
        CompanyRequest(
            "GET", f"{world.service.config.base}/.well-known/oauth-protected-resource/mcp", {}
        )
    )
    assert metadata.status == 404
