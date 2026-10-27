# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What draft 0.3 adds, both sides, over HTTP in one process.

Session Keys (§4.2, §4.3), codes bound to them (§4.5, §4.6), scopes and their hints
(§3.1, §4.4), excluded tasks and alternatives (§8), and the sign-in rules that changed.
"""

from __future__ import annotations

from datetime import timedelta
from urllib.parse import parse_qs, urlencode

import httpx
import pytest
from pydantic import ValidationError

from personal_agent_protocol import (
    DeviceSignInClient,
    DiscoveryClient,
    SessionClient,
    SessionError,
)
from personal_agent_protocol.models import (
    Alternative,
    DiscoveryDocument,
    OAuthServerMetadata,
    ScopeHint,
)
from personal_agent_protocol.reactor import DPOP_PROOF_PROVIDERS, first_contribution

from .test_company_end_to_end import PAIRWISE, TENANT, World

TOKEN = "https://manzanita.example/oauth/token"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


def _who(world: World) -> dict[str, str]:
    return {
        "client_id": world.atlas.client_id,
        "pairwise_user_id": PAIRWISE,
        "issuer": "https://manzanita.example",
        "token_endpoint": TOKEN,
        "tenant_id": TENANT,
    }


# Session Keys ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_new_key_starts_a_session_and_the_same_key_renews_it() -> None:
    world = World()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    first = await sessions.start(**_who(world))
    second = await sessions.start(**_who(world))
    # Each Session has its own key, which names it (§4.3).
    assert first.session_key != second.session_key
    renewed = await sessions.renew(**_who(world), session_key=first.session_key)
    assert renewed.session_key == first.session_key and not renewed.signed_in


@pytest.mark.asyncio
async def test_an_ended_sessions_key_is_refused_not_a_new_session() -> None:
    """A Company remembers the keys of Sessions it ended (§4.2, SHOULD)."""

    world = World()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    session = await sessions.start(**_who(world))
    # Long past the end of anything that could renew it.
    config = world.shop.config
    world.clock.advance(
        (
            config.session_lifetime + config.account_token_lifetime + timedelta(days=1)
        ).total_seconds()
    )
    with pytest.raises(SessionError) as ended:
        await sessions.renew(**_who(world), session_key=session.session_key)
    assert ended.value.code == "invalid_grant"
    # The agent never uses that key again: it is gone from its custody (§4.2).
    provider = first_contribution(world.reactor, DPOP_PROOF_PROVIDERS, "DPoP")
    keys = provider.keys  # type: ignore[attr-defined]
    assert (
        await keys.get(
            tenant_id=TENANT, issuer=_who(world)["issuer"], thumbprint=session.session_key
        )
        is None
    )


@pytest.mark.asyncio
async def test_a_session_keeps_the_agent_id_it_started_with() -> None:
    world = World()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    for other in ("agt_shopping", None):
        session = await sessions.start(**_who(world), agent_id="agt_travel")
        await sessions.renew(**_who(world), session_key=session.session_key, agent_id="agt_travel")
        with pytest.raises(SessionError) as changed:
            await sessions.renew(**_who(world), session_key=session.session_key, agent_id=other)
        assert changed.value.code == "invalid_grant"


@pytest.mark.asyncio
async def test_a_device_code_is_bound_to_the_key_of_its_first_poll() -> None:
    world = World()
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read",),
        tenant_id=TENANT,
        session_key=session.session_key,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    world.clock.advance(started.poll_interval)
    assert (await device.poll(started.reference)).status == "pending"
    # Opening the link approves nothing by itself (§4.6, 8300b10): still pending.
    page = await world.http.get(started.verification_uri_complete or started.verification_uri)
    assert page.status_code in {200, 404}
    world.clock.advance(started.poll_interval)
    assert (await device.poll(started.reference)).status == "pending"
    # A poll with another key: refused, the code being bound to the first poll's.
    other = await world.signed_out_session()
    # The device code is host state, never the model's: read it where the host keeps it.
    code = next(
        value.device_code.get_secret_value()
        for value in world.host.vault.values.values()
        if hasattr(value, "device_code")
    )
    provider = first_contribution(world.reactor, DPOP_PROOF_PROVIDERS, "DPoP")
    proof = await provider.create(
        __import__("personal_agent_protocol").DpopProofRequest(
            method="POST",
            url=TOKEN,
            tenant_id=TENANT,
            issuer=metadata.issuer,
            session_key=other.session_key,
        )
    )
    signer = world.atlas.signer()
    from personal_agent_protocol.sessions import build_client_assertion_claims

    assertion = await signer.sign(
        build_client_assertion_claims(
            client_id=world.atlas.client_id, issuer=metadata.issuer, now=world.clock.now()
        ).model_dump(),
        purpose="client_assertion",
    )
    world.clock.advance(started.poll_interval)
    stolen = await world.http.post(
        TOKEN,
        content=urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": code,
                "client_id": world.atlas.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion.get_secret_value(),
            }
        ).encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "DPoP": proof.get_secret_value(),
        },
    )
    assert stolen.status_code == 400 and stolen.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_an_authorization_code_needs_dpop_jkt_and_the_key_it_names() -> None:
    from .test_direct_and_api import direct_world

    world, _ = direct_world()
    await world.signed_out_session()
    base = (
        "https://manzanita.example/oauth/authorize?response_type=code"
        f"&client_id={world.atlas.client_id}&scope=orders:read&state=s1"
        "&code_challenge=c&code_challenge_method=S256"
        f"&redirect_uri=https://{world.atlas.domain}/oauth/callback"
    )
    # Without the Session Key's thumbprint the request is refused back to the agent (§4.5).
    refused = await world.http.get(base)
    assert refused.status_code in {302, 303}
    assert parse_qs(refused.headers["location"].split("?", 1)[1])["error"] == ["invalid_request"]


# Discovery and scopes ---------------------------------------------------------------------


def test_the_issuer_lists_the_grants_and_scopes_it_offers() -> None:
    base = {
        "issuer": "https://auth.example.com",
        "token_endpoint": "https://auth.example.com/oauth/token",
        "revocation_endpoint": "https://auth.example.com/oauth/revoke",
        "protected_resources": ["https://example.com"],
    }
    with pytest.raises(ValidationError, match="JWT bearer"):
        # grant_types_supported is required, with the JWT bearer and refresh grants (§3.2).
        OAuthServerMetadata.model_validate({**base, "grant_types_supported": ["refresh_token"]})
    with pytest.raises(ValidationError, match="authorization_endpoint"):
        OAuthServerMetadata.model_validate(
            {**base, "grant_types_supported": [JWT_BEARER, "refresh_token", "authorization_code"]}
        )
    plain = OAuthServerMetadata.model_validate(
        {**base, "grant_types_supported": [JWT_BEARER, "refresh_token"]}
    )
    # No sign-in grant: signed-out Sessions only (§4.4).
    assert not plain.offers_direct and not plain.offers_device and not plain.offers_token_exchange
    assert plain.lists_resource("EXAMPLE.com")
    assert not OAuthServerMetadata.model_validate(
        {
            **base,
            "grant_types_supported": [JWT_BEARER, "refresh_token"],
            "protected_resources": ["https://example.com/"],
        }
    ).lists_resource("example.com")


def test_scopes_are_the_companys_described_and_never_poppy() -> None:
    document = {
        "protocol_version": "0.3",
        "organization": {"name": "Example", "domain": "example.com"},
        "auth": {"issuer": "https://auth.example.com", "scopes": {"poppy:read": "Read"}},
        "web": {},
    }
    with pytest.raises(ValidationError, match="reserved"):
        DiscoveryDocument.model_validate(document)
    with pytest.raises(ValidationError, match="description"):
        DiscoveryDocument.model_validate(
            {**document, "auth": {"issuer": "https://auth.example.com", "scopes": {"a": ""}}}
        )


def test_an_unknown_changes_hint_is_read_as_irreversible() -> None:
    # Later versions may add values: until then, the most careful reading (§4.4).
    assert ScopeHint(changes="permanent", personal_data=False).effective_changes == "irreversible"
    assert ScopeHint(changes="none", personal_data=True).effective_changes == "none"
    with pytest.raises(ValidationError):
        ScopeHint.model_validate({"changes": "none"})  # both fields, always


@pytest.mark.asyncio
async def test_the_excluded_tasks_are_read_and_their_alternatives_filtered() -> None:
    world = World()
    await world.signed_out_session()
    excluded = await DiscoveryClient(reactor=world.reactor, http_client=world.http).excluded_tasks(
        world.company
    )
    assert excluded is not None
    assert [task.task for task in excluded.tasks] == [
        "Change the size of an item after it has shipped"
    ]
    alternative = Alternative.model_validate(
        {
            "instructions": "Use the API.",
            "references": [
                {
                    "type": "openapi",
                    "url": "https://manzanita.example/api/openapi.json",
                    "operation_id": "list",
                },
                {
                    "type": "openapi",
                    "url": "https://other.example/openapi.json",
                    "operation_id": "x",
                },
                {"type": "app", "url": "https://manzanita.example/app"},
                {"type": "web", "url": "https://manzanita.example/help"},
            ],
        }
    )
    usable = alternative.usable_references(world.company.document)
    # Only the company's own listed APIs, and only types the agent knows (§8.2).
    assert [(r.type, r.url) for r in usable] == [
        ("openapi", "https://manzanita.example/api/openapi.json"),
        ("web", "https://manzanita.example/help"),
    ]
    with pytest.raises(ValidationError):
        Alternative.model_validate({})


@pytest.mark.asyncio
async def test_a_signed_in_token_response_leaves_out_scope_only_when_exact() -> None:
    from .test_company_refusals import signed_in

    world = World()
    token = await signed_in(world)
    # Ada approved both scopes asked for: the response left `scope` out, and the SDK
    # read it as exactly those (§4.4, RFC 6749 §5.1).
    assert token.signed_in and set(token.scopes) == {"orders:read", "orders:write"}
    # The Account Token's lifetime is sent, so expired tells from revoked (guides).
    assert token.refresh_token_expires_in == 90 * 24 * 3600


@pytest.mark.asyncio
async def test_a_discovery_document_off_the_well_known_path_is_refused() -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.well-known/poppy.json":
            return httpx.Response(302, headers={"location": "https://example.com/uploads/p.json"})
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        client = DiscoveryClient(http_client=http, address_resolver=_public)
        with pytest.raises(Exception) as refused:
            await client.discover("example.com")
    assert getattr(refused.value, "code", None) == "invalid_discovery_location"


async def _public(host: str) -> list[str]:
    return ["93.184.216.34"]
