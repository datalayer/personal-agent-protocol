# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What draft 0.4 adds, both sides, in one process: `src/__tests__/draft-04.test.mjs`
ports it.

Direct Sign-In preferred (§4, P4-01); several protocol versions (§3.4, P4-02); extensions
declared per request (§3.3, §3.4, P4-03); what a message took into account (§8.4, P4-08).
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest

from personal_agent_protocol import PROTOCOL_PROFILE, PapSession
from personal_agent_protocol.actions import discover_company
from personal_agent_protocol.company import CompanyConfig
from personal_agent_protocol.demo.kit import InProcessNetwork, MutableClock
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.errors import ConversationError
from personal_agent_protocol.extensions import (
    format_extensions_header,
    negotiate_extensions,
    parse_extensions_header,
)
from personal_agent_protocol.models import (
    DEVICE_CODE_GRANT,
    MEDIATED_GRANT,
    Author,
    ConversationEventPage,
    DiscoveredCompany,
    DiscoveryDocument,
    ExtensionDescriptor,
    Message,
    OAuthServerMetadata,
    choose_protocol_version,
    compatible_versions,
)
from personal_agent_protocol.transport import session_headers, version_unsupported
from personal_agent_protocol.ui import PapReplies

from .test_company_end_to_end import World

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"


def _company(grants: list[str], *, disabled: bool = False) -> DiscoveredCompany:
    document = json.loads((FIXTURES / "discovery-valid.json").read_text())
    if disabled:
        document["auth"]["disabled"] = True
    metadata = json.loads((FIXTURES / "oauth-metadata-valid.json").read_text())
    metadata["grant_types_supported"] = ["refresh_token", *grants]
    if "authorization_code" not in grants:
        del metadata["authorization_endpoint"]
    if DEVICE_CODE_GRANT not in grants:
        del metadata["device_authorization_endpoint"]
    return DiscoveredCompany(
        discovery_url="https://example.com/.well-known/poppy.json",
        document=DiscoveryDocument.model_validate(document),
        oauth_metadata=OAuthServerMetadata.model_validate(metadata),
    )


# Direct Sign-In preferred (§4) ---------------------------------------------------------


def test_direct_sign_in_is_preferred_when_offered() -> None:
    """The agent uses Direct Sign-In when the Company offers it, else Device, else
    Mediated (§4); a Company with sign-in off or no issuer offers none."""

    everything = _company(["authorization_code", DEVICE_CODE_GRANT, MEDIATED_GRANT])
    assert everything.sign_in_types == ("direct", "device", "mediated")
    assert everything.preferred_sign_in == "direct"
    # A Company guarding high-value resources offers Direct only (RFC 10027 §6.2.1.5).
    assert _company(["authorization_code"]).preferred_sign_in == "direct"
    device_only = _company([DEVICE_CODE_GRANT, MEDIATED_GRANT])
    assert device_only.sign_in_types == ("device", "mediated")
    assert device_only.preferred_sign_in == "device"
    assert _company([MEDIATED_GRANT]).preferred_sign_in == "mediated"
    assert _company([]).preferred_sign_in is None
    disabled = _company(["authorization_code", DEVICE_CODE_GRANT], disabled=True)
    assert disabled.sign_in_types == () and disabled.preferred_sign_in is None
    no_issuer = DiscoveredCompany(
        discovery_url=everything.discovery_url,
        document=everything.document.model_copy(update={"auth": None}),
    )
    assert no_issuer.preferred_sign_in is None


@pytest.mark.asyncio
async def test_the_discovery_summary_lists_sign_in_types_direct_first() -> None:
    world = World()
    summary = await discover_company(
        "manzanita.example", reactor=world.reactor, http_client=world.http
    )
    assert summary["sign_in"] == ["direct", "device", "mediated"]
    assert summary["preferred_sign_in"] == "direct"


def test_the_reference_company_offers_direct_sign_in() -> None:
    """A Company that offers sign-in SHOULD offer Direct Sign-In (§4): the reference
    company does by default, and one that offers Direct only lists no device grant."""

    assert CONFIG.direct and CONFIG.device
    service, _ = manzanita(InProcessNetwork(), MutableClock())
    grants = service.oauth_metadata()["grant_types_supported"]
    assert "authorization_code" in grants and DEVICE_CODE_GRANT in grants
    bank = CompanyConfig(
        name="Bank",
        domain="bank.example",
        scopes=("accounts:read",),
        scope_descriptions={"accounts:read": "See your accounts"},
        operations=False,
        device=False,
    )
    assert bank.direct and not bank.device


# Several protocol versions (§3.4) --------------------------------------------------------


def test_versions_are_compatible_by_major_and_before_1_0_by_minor() -> None:
    assert compatible_versions("0.4", "0.4") and not compatible_versions("0.4", "0.3")
    assert compatible_versions("1.2", "1.0") and not compatible_versions("2.0", "1.9")
    # The newest compatible version, its own or a linked one, else none (§3.4).
    assert choose_protocol_version("0.9", ["0.1", PROTOCOL_PROFILE]) == PROTOCOL_PROFILE
    assert choose_protocol_version(PROTOCOL_PROFILE, ["0.9"]) == PROTOCOL_PROFILE
    assert choose_protocol_version("0.9", ["0.8"]) is None
    assert choose_protocol_version("1.3", ["1.1", "1.5"], implemented=["1.0"]) == "1.5"
    assert choose_protocol_version("not-a-version", ["1.0"], implemented=["1.0"]) == "1.0"
    with pytest.raises(ValueError):
        DiscoveryDocument.model_validate(
            {
                "protocol_version": "0.9",
                "supported_versions": {PROTOCOL_PROFILE: "http://example.com/poppy.json"},
                "organization": {"name": "Example", "domain": "example.com"},
                "web": {},
            }
        )


@pytest.mark.asyncio
async def test_every_request_with_the_session_header_names_the_sessions_version() -> None:
    """`Poppy-Version` goes with `Poppy-Session`, the same for the Session's life (§3.4)."""

    world = World()
    session = await world.signed_out_session()
    assert session.protocol_version == PROTOCOL_PROFILE
    assert PapSession.from_json(session.to_json()).protocol_version == PROTOCOL_PROFILE
    headers = await session_headers(
        world.reactor, "GET", "https://manzanita.example/api/orders", session=session, token=None
    )
    assert headers["Poppy-Version"] == PROTOCOL_PROFILE
    with pytest.raises(ValueError):
        replace(session, protocol_version="0.9")


@pytest.mark.asyncio
async def test_a_request_without_poppy_version_or_in_an_unserved_one_is_refused() -> None:
    """The company checks `Poppy-Version` where it verifies the Session header: missing, or
    none it serves, is `version_unsupported` (HTTP 400, JSON), never another version (§3.4)."""

    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    headers = await session_headers(world.reactor, "POST", endpoint, session=session, token=None)
    body = {
        "id": "req_version_0000000000",
        "message": world.message("Hello").model_dump(mode="json", exclude_none=True),
    }
    without = {k: v for k, v in headers.items() if k != "Poppy-Version"}
    refused = await world.http.post(endpoint, headers=without, json=body)
    assert refused.status_code == 400 and refused.json() == {"error": "version_unsupported"}
    assert version_unsupported(refused)
    headers = await session_headers(world.reactor, "POST", endpoint, session=session, token=None)
    other = await world.http.post(endpoint, headers={**headers, "Poppy-Version": "9.0"}, json=body)
    assert other.status_code == 400 and other.json() == {"error": "version_unsupported"}
    # A company that stopped serving the Session's version: the transport returns the
    # refusal as it is, and choosing again is discovery's (`discover(fresh=True)`).
    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, protocol_versions=("0.0",))
    )
    with pytest.raises(ConversationError) as raised:
        await world.conversations.start(endpoint, world.message("Hello"), session=session)
    assert (raised.value.code, raised.value.status_code) == ("version_unsupported", 400)


@pytest.mark.asyncio
async def test_the_company_serves_its_other_versions_documents() -> None:
    """`poppy.json` is the preferred version's document and maps each other served version to
    its own document on the same host, with that version and no `supported_versions`; a
    deprecated version's responses carry `Deprecation` and `Sunset` (§3.4)."""

    world = World()
    since = datetime(2026, 11, 1, tzinfo=timezone.utc)
    until = datetime(2027, 1, 1, tzinfo=timezone.utc)
    config = replace(
        CONFIG,
        protocol_versions=(PROTOCOL_PROFILE, "0.0"),
        deprecated_versions={"0.0": (since, until)},
    )
    world.shop, world.plugin = manzanita(world.network, world.clock, config=config)
    session = await world.signed_out_session()
    document = world.company.document
    assert document.protocol_version == PROTOCOL_PROFILE
    assert document.supported_versions == {"0.0": "https://manzanita.example/poppy/0.0.json"}
    older = (await world.http.get("https://manzanita.example/poppy/0.0.json")).json()
    assert older["protocol_version"] == "0.0" and "supported_versions" not in older
    assert older["organization"] == document.organization.model_dump(exclude_none=True)
    assert older["auth"]["issuer"] == document.auth.issuer  # type: ignore[union-attr]
    assert (await world.http.get("https://manzanita.example/poppy/0.7.json")).status_code == 404
    summary = await discover_company(
        "manzanita.example", reactor=world.reactor, http_client=world.http
    )
    assert (summary["protocol_version"], summary["supported_versions"]) == (
        PROTOCOL_PROFILE,
        ["0.0"],
    )
    # A request in the older version is served, with the notice; the current one carries none.
    endpoint = document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    headers = await session_headers(world.reactor, "POST", endpoint, session=session, token=None)
    body = {
        "id": "req_versions_000000000",
        "message": world.message("Hello").model_dump(mode="json", exclude_none=True),
    }
    older_answer = await world.http.post(
        endpoint, headers={**headers, "Poppy-Version": "0.0"}, json=body
    )
    assert older_answer.status_code == 201
    assert older_answer.headers["Deprecation"] == f"@{int(since.timestamp())}"
    assert older_answer.headers["Sunset"] == "Fri, 01 Jan 2027 00:00:00 GMT"
    headers = await session_headers(world.reactor, "POST", endpoint, session=session, token=None)
    current = await world.http.post(
        endpoint, headers=headers, json={**body, "id": "req_current_000000000"}
    )
    assert current.status_code == 201 and "Sunset" not in current.headers
    with pytest.raises(ValueError):
        replace(CONFIG, protocol_versions=(PROTOCOL_PROFILE, PROTOCOL_PROFILE))
    with pytest.raises(ValueError):
        replace(CONFIG, deprecated_versions={"0.0": (since, until)})


# What a message took into account (§8.4) ------------------------------------------------


def test_only_an_ai_says_what_it_took_into_account() -> None:
    """`as_of_request` is the Company Agent's, `as_of_cursor` the Personal Agent's, and a
    person's message carries neither (§8.4)."""

    agent = Message(author=Author(type="agent"), text="Medium, please.", as_of_cursor="evt_c2")
    assert agent.as_of_cursor == "evt_c2"
    company = Message(
        id="msg_1", role="company", author=Author(type="agent"), text="Done.", as_of_request="req_1"
    )
    assert company.as_of_request == "req_1"
    for fields in (
        {"author": Author(type="human"), "as_of_cursor": "evt_c2"},
        {"author": Author(type="human"), "as_of_request": "req_1"},
        {"author": Author(type="agent"), "role": "user", "as_of_request": "req_1"},
        {"author": Author(type="agent"), "role": "company", "as_of_cursor": "evt_c2"},
        {"author": Author(type="agent"), "as_of_cursor": "not valid!"},
    ):
        with pytest.raises(ValueError):
            Message(text="Hello", **fields)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_the_company_agent_names_the_request_it_answered_and_people_do_not() -> None:
    """The reference company's agent replies carry `as_of_request`, the ID of the request
    they took into account; a person's reply carries none; `send(as_of_cursor=)` puts the
    agent's last cursor on its message (§8.4)."""

    world = World()
    world.shop.config = replace(world.shop.config, humans_available=True)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    first = world.message("Hello")
    page = await world.conversations.start(endpoint, first, session=session, wait=0)
    assert isinstance(page, ConversationEventPage)
    replies = [e.message for e in page.events if e.message and e.message.role == "company"]
    assert replies and all(reply.as_of_request == first.id for reply in replies)
    follow = Message(id="req_follow_00000000000", author=Author(type="agent"), text="And my order?")
    page = await world.conversations.send(
        endpoint, page.conversation_id, follow, session=session, as_of_cursor=page.cursor, wait=0
    )
    assert isinstance(page, ConversationEventPage)
    mine = [e.message for e in page.events if e.message and e.message.role == "user"]
    assert mine[-1].as_of_cursor is not None and mine[-1].as_of_cursor.startswith("evt")
    assert mine[-1].id == follow.id
    await world.conversations.handoff(endpoint, page.conversation_id, session=session)
    settled = await world.conversations.read_until_done(
        endpoint, page.conversation_id, session=session, wait=0
    )
    event = await world.shop.staff_reply(
        page.conversation_id, after=settled.events[-1].id, text="Marta here.", author_name="Marta"
    )
    assert event.message is not None and event.message.as_of_request is None
    shown = PapReplies.of("manzanita.example", page.conversation_id, replies)
    assert shown is not None and shown.replies[0].as_of_request == first.id


# Extensions declared per request (§3.3, §3.4) ---------------------------------------------


@pytest.mark.asyncio
async def test_a_session_declares_the_extensions_it_uses_with_the_company() -> None:
    """A company lists each extension with an entry per version; the Session declares the
    ones this agent implements in `Poppy-Extensions`, the same on every request; the company
    sends an extension's content only to a request that declares it (§3.3, §3.4, §8.4)."""

    world = World()
    session = await world.signed_out_session()
    document = world.company.document
    assert document.extensions["operations"] == [ExtensionDescriptor(version="2")]
    assert document.extension("operations", "2") is not None
    # Atlas implements Operations alone; the SDK as a whole implements four.
    assert session.extensions == {"operations": "2"}
    everything = negotiate_extensions(document.extensions)
    assert everything == {
        "operations": "2",
        "links": "1",
        "disclosures": "1",
        "mediated-sign-in": "1",
    }
    headers = await session_headers(
        world.reactor, "GET", "https://manzanita.example/api/orders", session=session, token=None
    )
    assert headers["Poppy-Extensions"] == '"operations";v="2"'
    # Mediated Sign-In is recognized from its grant: used, never declared (§3.3).
    assert (
        format_extensions_header(everything)
        == '"disclosures";v="1", "links";v="1", "operations";v="2"'
    )
    assert "extensions" not in world.atlas.metadata
    assert PapSession.from_json(session.to_json()).extensions == session.extensions
    # The company reads the declaration per request: a Session declaring nothing gets the
    # notice in `text` and no links, whatever the agent's other Sessions declare.
    endpoint = document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    plain = replace(session, extensions={})
    page = await world.conversations.start(
        endpoint, world.message("Where is my order?"), session=plain, wait=0
    )
    assert isinstance(page, ConversationEventPage)
    replies = [e.message for e in page.events if e.message and e.message.role == "company"]
    assert replies and all(reply.extensions is None for reply in replies)
    # Negotiation picks this SDK's version from the company's list, and nothing else.
    assert negotiate_extensions({"operations": [ExtensionDescriptor(version="1")]}) == {}
    assert negotiate_extensions(
        {"operations": [ExtensionDescriptor(version="1"), ExtensionDescriptor(version="2")]}
    ) == {"operations": "2"}
    assert parse_extensions_header('"operations";v="2", "links";v="1"') == {
        "operations": "2",
        "links": "1",
    }
    assert parse_extensions_header('"operations"') == {}
