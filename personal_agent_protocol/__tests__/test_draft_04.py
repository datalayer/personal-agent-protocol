# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What draft 0.4 adds, both sides, in one process: `src/__tests__/draft-04.test.mjs`
ports it.

Direct Sign-In preferred (§4, P4-01); several protocol versions (§3.4, P4-02); extensions
declared per request (§3.3, §3.4, P4-03); conversations across versions (§8.2, P4-04); the
browser join scope and website flags (§3.1, §4.7, §6, P4-05); what a message took into
account (§8.4, P4-08); sign-in's minor changes (§3.2, §4.5, §4.7, §5.2, P4-09).
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from personal_agent_protocol import (
    PROTOCOL_PROFILE,
    BrowserSessionClient,
    BrowserSessionError,
    PapSession,
)
from personal_agent_protocol.actions import discover_company
from personal_agent_protocol.company import CompanyConfig
from personal_agent_protocol.company.store import ACCOUNT_FAMILY, AccountFamily
from personal_agent_protocol.demo.kit import InProcessNetwork, MutableClock
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.discovery import DiscoveryClient
from personal_agent_protocol.errors import ConversationError
from personal_agent_protocol.extensions import (
    format_extensions_header,
    negotiate_extensions,
    parse_extensions_header,
)
from personal_agent_protocol.models import (
    BROWSER_SIGN_IN_SCOPE,
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
from .test_company_refusals import signed_in
from .test_mcp_and_web import web_world

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


# Conversations across versions (§8.2) -------------------------------------------------


@pytest.mark.asyncio
async def test_a_conversation_not_carried_over_to_other_versions_is_version_mismatch() -> None:
    """The reference company records the versions a conversation started in and carries it
    over by default; told not to, it refuses a POST from other versions with
    `version_mismatch` (409) naming the protocol version it started in, reads allowed; the
    client surfaces that version in the error's details (§8.2)."""

    world = World()
    config = replace(CONFIG, protocol_versions=(PROTOCOL_PROFILE, "0.0"))
    world.shop, world.plugin = manzanita(world.network, world.clock, config=config)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    # Started in "0.0", by hand; the client's Session is in this SDK's version.
    headers = await session_headers(world.reactor, "POST", endpoint, session=session, token=None)
    body = {"id": "req_started_in_0_0_0000", "message": {"author": {"type": "human"}, "text": "Hi"}}
    started = await world.http.post(
        endpoint, headers={**headers, "Poppy-Version": "0.0"}, json=body
    )
    assert started.status_code == 201
    conversation_id = started.json()["conversation_id"]
    record = await world.shop.conversation_record(conversation_id)
    assert (record.protocol_version, record.extensions) == ("0.0", {"operations": "2"})
    # Carried over by default: a message from this SDK's version is accepted.
    accepted = await world.conversations.send(
        endpoint, conversation_id, world.message("Still there?"), session=session
    )
    assert accepted.conversation_id == conversation_id
    # Not carried over: messages, handoffs and cancels are version_mismatch; reads are not.
    world.shop.config = replace(config, conversation_carry_over=False)
    with pytest.raises(ConversationError) as raised:
        await world.conversations.send(
            endpoint, conversation_id, world.message("And now?"), session=session
        )
    assert (raised.value.code, raised.value.status_code) == ("version_mismatch", 409)
    assert raised.value.details == {"protocol_version": "0.0"}
    with pytest.raises(ConversationError) as raised:
        await world.conversations.handoff(endpoint, conversation_id, session=session)
    assert raised.value.code == "version_mismatch"
    page = await world.conversations.read_events(endpoint, conversation_id, session=session)
    assert page.conversation_id == conversation_id and page.events
    # A Session in the versions it started in finishes it.
    close_url = f"{endpoint}/{conversation_id}/close"
    headers = await session_headers(world.reactor, "POST", close_url, session=session, token=None)
    again = await world.http.post(
        close_url,
        headers={**headers, "Poppy-Version": "0.0"},
        json={"id": "req_close_in_0_0_000000"},
    )
    assert again.status_code == 202


# Browser join scope and website flags (§3.1, §4.7, §6) -------------------------------------


@pytest.mark.asyncio
async def test_a_signed_in_browser_join_needs_the_browser_sign_in_scope() -> None:
    """A Company listing browser_session_endpoint with sign-in offers poppy:browser-sign-in
    and refuses a signed-in join without it with insufficient_scope naming the scope; the
    agent then joins signed out, or gets the scope and joins signed in (§4.7, §6)."""

    world, browser = web_world()
    without = await signed_in(world, ("orders:read",))
    document = world.company.document
    metadata = world.company.oauth_metadata
    assert metadata is not None and BROWSER_SIGN_IN_SCOPE in (metadata.scopes_supported or [])
    assert document.auth is not None and BROWSER_SIGN_IN_SCOPE in document.auth.scopes
    assert document.browser_sign_in_scopes == (BROWSER_SIGN_IN_SCOPE,)
    assert not document.browser_sign_in_unscoped and not document.browsing_disabled
    assert document.web is not None and document.web.browser_session_endpoint is not None
    endpoint = document.web.browser_session_endpoint
    client = BrowserSessionClient(reactor=world.reactor, transport=world.transport)

    session = world.session
    assert session is not None
    with pytest.raises(BrowserSessionError) as raised:
        await client.join(browser_session_endpoint=endpoint, session=session, token=without)
    assert raised.value.code == "insufficient_scope"
    assert raised.value.details == {"scope": BROWSER_SIGN_IN_SCOPE}
    # The refusal names the scope in its challenge.
    page = await world.http.get(endpoint)
    code = re.search(r'name="code" value="([^"]+)"', page.text)
    assert code is not None
    url = f"{endpoint}/authorize"
    headers = await session_headers(world.reactor, "POST", url, session=session, token=without)
    refused = await world.http.post(url, headers=headers, json={"code": code.group(1)})
    assert refused.status_code == 403
    assert f'scope="{BROWSER_SIGN_IN_SCOPE}"' in refused.headers["www-authenticate"]
    # The agent can join signed out instead.
    await client.join(browser_session_endpoint=endpoint, session=session, token=None)
    cookie = browser.http.cookies.get("__Host-poppy_session")
    assert cookie is not None
    joined = await world.shop.web_session(cookie)
    assert joined is not None and joined.account_id is None
    # With the scope, the join is signed in.
    with_scope = await signed_in(world, ("orders:read", BROWSER_SIGN_IN_SCOPE))
    session = world.session
    assert session is not None
    await client.join(browser_session_endpoint=endpoint, session=session, token=with_scope)
    cookie = browser.http.cookies.get("__Host-poppy_session")
    assert cookie is not None
    joined = await world.shop.web_session(cookie)
    assert joined is not None and joined.account_id == "acct_ada"
    # The protocol's scope is never one of the company's own.
    with pytest.raises(ValueError):
        replace(CONFIG, scopes=(*CONFIG.scopes, BROWSER_SIGN_IN_SCOPE))


@pytest.mark.asyncio
async def test_web_unscoped_and_web_disabled_are_published_and_read() -> None:
    """`web.unscoped` describes poppy:browser-sign-in as full access, hints it as
    irreversible and needs the endpoint; `web.disabled` lists no endpoint and asks agents not
    to browse; a document breaking either rule is refused (§3.1, §6)."""

    world = World()
    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, web=True, web_unscoped=True)
    )
    document = world.shop.discovery_document()
    assert document["web"] == {
        "browser_session_endpoint": "https://manzanita.example/poppy/browser-session",
        "unscoped": True,
    }
    assert document["auth"]["scopes"][BROWSER_SIGN_IN_SCOPE] == (
        "Use the website as you, with full access to your account"
    )
    assert document["auth"]["scope_hints"][BROWSER_SIGN_IN_SCOPE] == {
        "changes": "irreversible",
        "personal_data": True,
    }
    parsed = DiscoveryDocument.model_validate(document)
    assert parsed.browser_sign_in_unscoped
    assert parsed.browser_sign_in_scopes == (BROWSER_SIGN_IN_SCOPE,)
    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, web=False, web_disabled=True)
    )
    document = world.shop.discovery_document()
    assert document["web"] == {"disabled": True}
    assert BROWSER_SIGN_IN_SCOPE not in document["auth"]["scopes"]
    parsed = DiscoveryDocument.model_validate(document)
    assert parsed.browsing_disabled and parsed.browser_sign_in_scopes == ()
    for broken in (
        {"web": {"disabled": True, "browser_session_endpoint": "https://example.com/j"}},
        {"web": {"unscoped": True}},
    ):
        with pytest.raises(ValueError):
            DiscoveryDocument.model_validate({**document, **broken})
    with pytest.raises(ValueError):
        replace(CONFIG, web=True, web_disabled=True)
    with pytest.raises(ValueError):
        replace(CONFIG, web=False, web_unscoped=True)


# Sign-in's minor changes (§3.2, §4.5, §4.7, §5.2) -------------------------------------------


@pytest.mark.asyncio
async def test_a_company_that_never_issued_a_refresh_token_needs_no_assertion() -> None:
    """A Company that sets auth.disabled and has never issued a refresh token answers every
    refresh with invalid_grant and every revocation with success, without verifying the client
    assertion; once it has issued one, it verifies them as usual (§3.2)."""

    world = World()
    config = replace(CONFIG, sign_in_disabled=True, mediated_fields=())
    world.shop, world.plugin = manzanita(world.network, world.clock, config=config)
    unverified = {
        "client_id": world.atlas.client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": "not-a-jwt",
    }
    refresh = {"grant_type": "refresh_token", "refresh_token": "rt_unknown", **unverified}
    refused = await world.http.post("https://manzanita.example/oauth/token", data=refresh)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_grant")
    revoked = await world.http.post(
        "https://manzanita.example/oauth/revoke", data={"token": "rt_unknown", **unverified}
    )
    assert revoked.status_code == 200
    # Any sign-in it holds means a refresh token was issued: assertions are verified again.
    await world.shop.store.put(
        ACCOUNT_FAMILY,
        "family",
        AccountFamily(client_id=world.atlas.client_id, account_id="acct_ada", tokens=()).to_json(),
    )
    verified = await world.http.post("https://manzanita.example/oauth/token", data=refresh)
    assert (verified.status_code, verified.json()["error"]) == (401, "invalid_client")
    # Sign-in on: the assertion is verified whatever the store holds.
    world.shop, world.plugin = manzanita(world.network, world.clock)
    on = await world.http.post("https://manzanita.example/oauth/token", data=refresh)
    assert (on.status_code, on.json()["error"]) == (401, "invalid_client")


@pytest.mark.asyncio
async def test_service_metadata_for_another_resource_is_treated_as_absent() -> None:
    """The Personal Agent uses a service's protected resource metadata only if its `resource`
    is the URL it derived the metadata URL from, as RFC 9728 §3.3 requires, and otherwise
    treats it as absent: the default token works there (§4.5)."""

    world = World()
    company = await DiscoveryClient(reactor=world.reactor, http_client=world.http).discover(
        "manzanita.example"
    )
    service = "https://orders.example/api"
    metadata = {
        "resource": "https://orders.example/other",
        "authorization_servers": ["https://manzanita.example"],
    }

    async def published(scope: dict[str, Any], receive: Any, send: Any) -> None:
        # An ASGI app: the service's metadata, at the URL RFC 9728 §3.1 derives from `service`.
        assert scope["path"] == "/.well-known/oauth-protected-resource/api"
        body = json.dumps(metadata).encode()
        headers = [(b"content-type", b"application/json"), (b"cache-control", b"no-store")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    world.network.add("orders.example", published)
    discovery = DiscoveryClient(reactor=world.reactor, http_client=world.http)
    assert await discovery.resource_metadata(service) is None
    assert await discovery.service_resource(company, service) is None
    metadata["resource"] = service
    assert await discovery.service_resource(company, service, fresh=True) == service


def test_auth_scopes_win_over_an_openapi_description() -> None:
    """When an OpenAPI security scheme and auth.scopes both describe a scope, the Personal
    Agent uses the description in auth.scopes (§4.7)."""

    document = DiscoveryDocument.model_validate(
        json.loads((FIXTURES / "discovery-valid.json").read_text())
    )
    assert document.auth is not None
    openapi = {
        "components": {
            "securitySchemes": {
                "oauth": {
                    "type": "oauth2",
                    "flows": {
                        "authorizationCode": {
                            "scopes": {"orders:read": "Read orders (OpenAPI)", "returns": "Returns"}
                        }
                    },
                },
                "key": {"type": "apiKey", "name": "k", "in": "header"},
            }
        }
    }
    described = document.scope_descriptions(openapi)
    assert described["orders:read"] == document.auth.scopes["orders:read"]
    assert described["returns"] == "Returns"
    assert document.scope_descriptions() == document.auth.scopes


@pytest.mark.asyncio
async def test_a_delegated_key_signs_for_one_user_id() -> None:
    """A Company MAY reject, with invalid_session, a Session JWT whose delegated key has
    already signed for a different User ID while a delegation for the key lasts (§5.2)."""

    world = World()
    session = await world.signed_out_session()
    orders = "https://manzanita.example/api/orders"
    headers = await session_headers(world.reactor, "GET", orders, session=session, token=None)
    assert (await world.http.get(orders, headers=headers)).status_code in {200, 401}
    key = await world.host.delegated_keys.current(
        tenant_id=session.tenant_id, issuer=session.issuer, sub=session.sub
    )
    assert key is not None
    other = PapSession(
        sid="S" * 22,
        sub="usr_another_user_id_0000",
        issuer=session.issuer,
        client_id=session.client_id,
        tenant_id=session.tenant_id,
        extensions=dict(session.extensions),
    )
    # An agent that breaks §5.2: the same delegated key for another User ID.
    await world.host.delegated_keys.replace(
        tenant_id=other.tenant_id, issuer=other.issuer, sub=other.sub, key=key
    )
    headers = await session_headers(world.reactor, "GET", orders, session=other, token=None)
    refused = await world.http.get(orders, headers=headers)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_session")
    # The first User ID goes on with it.
    headers = await session_headers(world.reactor, "GET", orders, session=session, token=None)
    assert (await world.http.get(orders, headers=headers)).status_code in {200, 401}
