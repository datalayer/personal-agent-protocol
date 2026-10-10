# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import json
from pathlib import Path

import httpx
import pytest

from personal_agent_protocol import (
    AgentIdentityClient,
    IdentityError,
    ProtocolValidationError,
)

FIXTURES = Path(__file__).parents[1] / "protocol" / "fixtures"
CLIENT_ID = "https://agent.example/agent.json"


async def public_resolver(_: str) -> list[str]:
    return ["93.184.216.34"]


def fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURES / name).read_text())


@pytest.mark.asyncio
async def test_fetches_metadata_and_public_jwks() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        name = (
            "client-metadata-valid.json"
            if request.url.path == "/agent.json"
            else "jwks-valid.json"
        )
        return httpx.Response(200, json=fixture(name), request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        async with AgentIdentityClient(
            http_client=http,
            address_resolver=public_resolver,
        ) as client:
            metadata = await client.fetch_metadata(CLIENT_ID)
            keys = await client.fetch_jwks(CLIENT_ID)

    assert metadata.client_name == "Example Agent"
    assert keys.keys[0].kid == "agent-signing-2026-10"
    assert keys.keys[0].alg == "ES256"


@pytest.mark.asyncio
async def test_client_metadata_does_not_follow_redirects() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "/moved.json"}, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = AgentIdentityClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(IdentityError, match="metadata_redirect"):
            await client.fetch_metadata(CLIENT_ID)


@pytest.mark.asyncio
async def test_rejects_substituted_client_id() -> None:
    document = fixture("client-metadata-valid.json")
    document["client_id"] = "https://agent.example/another-agent.json"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=document, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = AgentIdentityClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(IdentityError, match="client_id_mismatch"):
            await client.fetch_metadata(CLIENT_ID)


@pytest.mark.asyncio
async def test_rejects_private_key_material_in_jwks() -> None:
    private_jwks = fixture("jwks-valid.json")
    private_jwks["keys"][0]["d"] = "private-material"  # type: ignore[index]

    def handler(request: httpx.Request) -> httpx.Response:
        body = fixture("client-metadata-valid.json")
        if request.url.path == "/jwks.json":
            body = private_jwks
        return httpx.Response(200, json=body, request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = AgentIdentityClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(ProtocolValidationError, match="invalid_jwks"):
            await client.fetch_jwks(CLIENT_ID)


@pytest.mark.asyncio
async def test_rejects_cross_domain_jwks_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/agent.json":
            return httpx.Response(
                200,
                json=fixture("client-metadata-valid.json"),
                request=request,
            )
        return httpx.Response(
            302,
            headers={"location": "https://keys.example/jwks.json"},
            request=request,
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        client = AgentIdentityClient(http_client=http, address_resolver=public_resolver)
        with pytest.raises(IdentityError, match="jwks_domain_mismatch"):
            await client.fetch_jwks(CLIENT_ID)
