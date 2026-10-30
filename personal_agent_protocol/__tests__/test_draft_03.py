# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What draft 0.3 adds, both sides, over HTTP in one process.

Sessions kept by `sid` (§5.2, §5.3, §5.5), sign-in as plain OAuth (§4.2, §4.3), scopes and
their hints (§3.1, §4.7), excluded tasks and alternatives (§9.1, §9.2).
"""

from __future__ import annotations

from dataclasses import replace
from urllib.parse import parse_qs, urlencode

import httpx
import pytest
from pydantic import ValidationError

from personal_agent_protocol import (
    DeviceSignInClient,
    DiscoveryClient,
    FeedbackReport,
    PapSession,
    SessionClient,
)
from personal_agent_protocol.company.store import SESSION
from personal_agent_protocol.demo.kit import AgentIdentity
from personal_agent_protocol.models import (
    Alternative,
    DiscoveryDocument,
    OAuthServerMetadata,
    ScopeHint,
)
from personal_agent_protocol.sessions import build_client_assertion_claims
from personal_agent_protocol.transport import session_headers

from .test_company_end_to_end import PAIRWISE, TENANT, World

TOKEN = "https://manzanita.example/oauth/token"
FEEDBACK = "https://manzanita.example/poppy/feedback"


def _who(world: World) -> dict[str, str]:
    return {
        "client_id": world.atlas.client_id,
        "pairwise_user_id": PAIRWISE,
        "issuer": "https://manzanita.example",
        "tenant_id": TENANT,
    }


async def _report(world: World, session: PapSession, **headers: str) -> httpx.Response:
    """One request straight to the company, so `invalid_session` starts no new Session."""

    signed = await session_headers(world.reactor, "POST", FEEDBACK, session=session, token=None)
    report = FeedbackReport(task="Track a parcel", description="No tracking anywhere.")
    return await world.http.post(FEEDBACK, json=report.model_dump(), headers={**signed, **headers})


# Sessions -------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_new_sid_starts_a_session_and_the_same_sid_continues_it() -> None:
    world = World()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    first = await sessions.start(**_who(world))
    second = await sessions.start(**_who(world))
    # A Session is local: each has its own `sid`, and the company has heard of neither (§5.2).
    assert first.sid != second.sid
    assert world.shop.store.keys(SESSION) == []
    assert (await _report(world, first)).status_code == 202
    assert (await _report(world, first)).status_code == 202
    assert len(world.shop.store.keys(SESSION)) == 1
    assert (await _report(world, second)).status_code == 202
    assert len(world.shop.store.keys(SESSION)) == 2
    # One delegated key per User ID signs them all: a key doesn't name a Session (§5.2).
    assert len(world.host.delegated_keys) == 1


@pytest.mark.asyncio
async def test_an_ended_sessions_sid_is_refused_not_a_new_session() -> None:
    """A Company remembers the `sid`s of Sessions it ended, and may forget them (§5.5)."""

    world = World()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    session = await sessions.start(**_who(world))
    assert (await _report(world, session)).status_code == 202
    assert await world.shop.end_session(session.client_id, session.sid)
    assert not await world.shop.end_session(session.client_id, session.sid)
    ended = await _report(world, session)
    assert (ended.status_code, ended.json()) == (400, {"error": "invalid_session"})

    # A Session past the lifetime the company gives it has ended the same way.
    lapsing = await sessions.start(**_who(world))
    assert (await _report(world, lapsing)).status_code == 202
    config = world.shop.config
    world.clock.advance(config.session_lifetime.total_seconds())
    lapsed = await _report(world, lapsing)
    assert (lapsed.status_code, lapsed.json()) == (400, {"error": "invalid_session"})

    # Once forgotten, the same `sid` starts a new Session (§5.5: a Company can forget).
    world.clock.advance(config.ended_session_memory.total_seconds() + 1)
    assert (await _report(world, lapsing)).status_code == 202


@pytest.mark.asyncio
async def test_a_session_keeps_the_agent_id_it_started_with() -> None:
    world = World()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    for other in ("agt_shopping", None):
        session = await sessions.start(**_who(world), agent_id="agt_travel")
        assert (await _report(world, session)).status_code == 202
        changed = await _report(world, replace(session, agent_id=other))
        assert (changed.status_code, changed.json()) == (400, {"error": "invalid_session"})


@pytest.mark.asyncio
async def test_a_session_keeps_the_user_id_it_started_with() -> None:
    world = World()
    session = await SessionClient(reactor=world.reactor, http_client=world.http).start(
        **_who(world)
    )
    assert (await _report(world, session)).status_code == 202
    changed = await _report(world, replace(session, sub="usr_somebody_else_000000"))
    assert (changed.status_code, changed.json()) == (400, {"error": "invalid_session"})


@pytest.mark.asyncio
async def test_an_access_token_without_the_session_header_is_invalid_session() -> None:
    """A copied access token is useless without the agent's key (§5.3)."""

    from .test_company_refusals import signed_in

    world = World()
    token = await signed_in(world)
    bare = await world.http.post(
        FEEDBACK,
        json={"task": "x", "description": "y"},
        headers={"Authorization": f"Bearer {token.access_token.get_secret_value()}"},
    )
    assert (bare.status_code, bare.json()) == (400, {"error": "invalid_session"})


# Sign-in ----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_device_code_works_only_for_the_agent_it_was_issued_to() -> None:
    world = World()
    await world.signed_out_session()
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
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    world.clock.advance(started.poll_interval)
    assert (await device.poll(started.reference)).status == "pending"
    # Opening the link approves nothing by itself (§4.3): still pending.
    page = await world.http.get(started.verification_uri_complete or started.verification_uri)
    assert page.status_code in {200, 404}
    world.clock.advance(started.poll_interval)
    assert (await device.poll(started.reference)).status == "pending"
    # A poll from another agent, with its own good assertion: refused.
    other = AgentIdentity(domain="other.example", name="Other")
    world.network.add(other.domain, other.website())
    # The device code is host state, never the model's: read it where the host keeps it.
    code = next(
        value.device_code.get_secret_value()
        for value in world.host.vault.values.values()
        if hasattr(value, "device_code")
    )
    assertion = await other.signer().sign(
        build_client_assertion_claims(
            client_id=other.client_id, issuer=metadata.issuer, now=world.clock.now()
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
                "client_id": other.client_id,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion.get_secret_value(),
            }
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert stolen.status_code == 400 and stolen.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_an_authorization_request_needs_pkce() -> None:
    from .test_direct_and_api import direct_world

    world, _ = direct_world()
    await world.signed_out_session()
    base = (
        "https://manzanita.example/oauth/authorize?response_type=code"
        f"&client_id={world.atlas.client_id}&scope=orders:read&state=s1"
        f"&redirect_uri=https://{world.atlas.domain}/oauth/callback"
    )
    # Without an S256 code challenge the request is refused back to the agent (§4.2).
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
    with pytest.raises(ValidationError, match="refresh_token"):
        # grant_types_supported is required, with the refresh grant (§3.2).
        OAuthServerMetadata.model_validate(
            {**base, "grant_types_supported": ["authorization_code"]}
        )
    with pytest.raises(ValidationError, match="authorization_endpoint"):
        OAuthServerMetadata.model_validate(
            {**base, "grant_types_supported": ["refresh_token", "authorization_code"]}
        )
    plain = OAuthServerMetadata.model_validate({**base, "grant_types_supported": ["refresh_token"]})
    # No sign-in grant: signed-out Sessions only (§5.4).
    assert not plain.offers_direct and not plain.offers_device
    assert plain.lists_resource("EXAMPLE.com")
    assert not OAuthServerMetadata.model_validate(
        {
            **base,
            "grant_types_supported": ["refresh_token"],
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
    # `poppy:` is no longer reserved (3e9bada): a Company's scope like any other.
    accepted = DiscoveryDocument.model_validate(document)
    assert accepted.auth is not None and accepted.auth.scopes == {"poppy:read": "Read"}
    with pytest.raises(ValidationError, match="description"):
        DiscoveryDocument.model_validate(
            {**document, "auth": {"issuer": "https://auth.example.com", "scopes": {"a": ""}}}
        )


def test_an_unknown_changes_hint_is_read_as_irreversible() -> None:
    # Later versions may add values: until then, the most careful reading (§4.7).
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
    # Only the company's own listed APIs, and only types the agent knows (§9.2).
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
    # read it as exactly those (§4.7, RFC 6749 §5.1).
    assert set(token.scopes) == {"orders:read", "orders:write"}
    assert token.token_type == "Bearer"
    assert token.expires_in == 3600
    # The refresh token stays behind its reference, in the host's store.
    assert world.refresh_reference is not None


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
