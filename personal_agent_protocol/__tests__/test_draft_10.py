# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What the 1.0 draft changes, both sides, in one process: `src/__tests__/draft-10.test.mjs`
ports it.

Protocol version `1.0` (§3.1, §3.4), which a Personal Agent and a Company use only when they
ask for it: a draft can still change in ways that aren't backward compatible, so the SDK
announces 0.4 unless told otherwise. Lookalike domains (§10.3; guides, *Finding a
company*): the name a `poppy.json` gives is unconfirmed, so the SDK shows the domain with it.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from personal_agent_protocol import (
    AVAILABLE_PROTOCOL_VERSIONS,
    DRAFT_PROTOCOL_REVISION,
    DRAFT_PROTOCOL_VERSION,
    PROTOCOL_PROFILE,
    SUPPORTED_PROTOCOL_VERSIONS,
    PapSession,
    SessionClient,
)
from personal_agent_protocol.cli_host import InputSource, TerminalInput
from personal_agent_protocol.conformance import run_conformance, select_cases
from personal_agent_protocol.demo.conformance import ManzanitaConformance
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.discovery import DiscoveryClient
from personal_agent_protocol.errors import ConversationError, DiscoveryError
from personal_agent_protocol.models import (
    PROTOCOL_VERSIONS_CONTEXT,
    DiscoveryDocument,
    Organization,
    implemented_protocol_versions,
    implemented_version_for,
)
from personal_agent_protocol.reactor import ProtectedInputField, ProtectedInputRequest
from personal_agent_protocol.transport import session_headers

from .test_company_end_to_end import PAIRWISE, TENANT, World

BOTH = (PROTOCOL_PROFILE, DRAFT_PROTOCOL_VERSION)


def _serving(world: World, *versions: str) -> None:
    """Manzanita, again, serving `versions`, the first the one `poppy.json` is."""

    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, protocol_versions=versions)
    )


async def _session(world: World, *versions: str) -> PapSession:
    """Discovery and a signed-out Session by a Personal Agent that implements `versions`
    (the SDK's default for none), the Session's version taken from the company."""

    client = DiscoveryClient(
        reactor=world.reactor,
        http_client=world.http,
        protocol_versions=versions or None,
    )
    company = await client.discover("manzanita.example")
    assert company.oauth_metadata is not None
    world.company = company
    return await SessionClient(reactor=world.reactor, http_client=world.http).start(
        client_id=world.atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=company.oauth_metadata.issuer,
        tenant_id=TENANT,
        company=company,
    )


# Protocol version 1.0, opt-in (§3.1, §3.4) ----------------------------------------------


def test_the_published_version_is_the_default_and_the_draft_is_available() -> None:
    assert (PROTOCOL_PROFILE, DRAFT_PROTOCOL_VERSION) == ("0.4", "1.0")
    assert DRAFT_PROTOCOL_REVISION == "2026-11-11"
    assert SUPPORTED_PROTOCOL_VERSIONS == {"0.4"}
    assert AVAILABLE_PROTOCOL_VERSIONS == {"0.4", "1.0"}
    assert implemented_protocol_versions() == {"0.4"}
    assert implemented_protocol_versions(["1.0"]) == {"1.0"}
    assert implemented_protocol_versions(BOTH) == {"0.4", "1.0"}
    for unknown in (["0.3"], ["2.0"], ["1.1"], []):
        with pytest.raises(ValueError):
            implemented_protocol_versions(unknown)
    with pytest.raises(ValueError):
        DiscoveryClient(protocol_versions=["1.1"])
    # The version a Session names: the one implemented compatible with the chosen one.
    assert implemented_version_for("1.0") == "1.0"
    assert implemented_version_for("1.4") == "1.0"
    assert implemented_version_for("0.4") == "0.4"
    with pytest.raises(ValueError):
        implemented_version_for("0.3")


def test_a_draft_document_is_used_only_by_an_agent_that_implements_the_draft() -> None:
    draft = {
        "protocol_version": "1.0",
        "organization": {"name": "Example", "domain": "example.com"},
        "web": {},
    }
    # A document's version is one the SDK implements; whether an agent uses it is its own.
    with pytest.raises(ValueError):
        DiscoveryDocument.model_validate(
            draft, context={PROTOCOL_VERSIONS_CONTEXT: SUPPORTED_PROTOCOL_VERSIONS}
        )
    with pytest.raises(ValueError):
        DiscoveryDocument.model_validate({**draft, "protocol_version": "2.0"})
    document = DiscoveryDocument.model_validate(draft)
    assert document.chosen_version is None  # the SDK's default implements no 1.0
    assert document.choose_version(BOTH) == "1.0"
    # A 1.0 document that links to 0.4: the default agent takes 0.4, the opted-in one 1.0.
    linked = {**draft, "supported_versions": {"0.4": "https://example.com/poppy/0.4.json"}}
    document = DiscoveryDocument.model_validate(linked)
    assert document.chosen_version == "0.4"
    assert document.choose_version(BOTH) == "1.0"
    assert document.choose_version(["1.0"]) == "1.0"


@pytest.mark.asyncio
async def test_the_reference_company_serves_the_published_version_only_by_default() -> None:
    """Nothing announces 1.0 unless asked: Manzanita's `poppy.json` says 0.4 and lists no
    other version, and a request in `1.0` is `version_unsupported` (§3.4)."""

    world = World()
    assert CONFIG.protocol_versions == (PROTOCOL_PROFILE,)
    session = await _session(world, *BOTH)  # an agent that implements both
    assert world.company.protocol_version == "0.4" and session.protocol_version == "0.4"
    assert world.company.document.supported_versions == {}
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    headers = await session_headers(world.reactor, "POST", endpoint, session=session, token=None)
    assert headers["Poppy-Version"] == "0.4"
    body = {"id": "req_draft_unserved_0000", "message": {"author": {"type": "human"}, "text": "Hi"}}
    draft = {**headers, "Poppy-Version": "1.0"}
    refused = await world.http.post(endpoint, headers=draft, json=body)
    assert refused.status_code == 400 and refused.json() == {"error": "version_unsupported"}


@pytest.mark.asyncio
async def test_an_agent_on_the_default_uses_no_company_that_serves_only_the_draft() -> None:
    world = World()
    _serving(world, DRAFT_PROTOCOL_VERSION)
    with pytest.raises(DiscoveryError) as raised:
        await _session(world)
    assert raised.value.code == "unsupported_protocol_version"
    # Asked for, the draft is used, and every request names it.
    session = await _session(world, DRAFT_PROTOCOL_VERSION)
    assert world.company.protocol_version == "1.0" and session.protocol_version == "1.0"
    assert PapSession.from_json(session.to_json()).protocol_version == "1.0"
    receipt = await world.conversations.start(
        world.company.document.agent.protocols[0].endpoint,  # type: ignore[union-attr]
        world.message("Hello"),
        session=session,
    )
    record = await world.shop.conversation_record(receipt.conversation_id)
    assert record.protocol_version == "1.0"


@pytest.mark.asyncio
async def test_a_company_that_serves_both_versions_is_used_at_the_newest_the_agent_implements() -> (
    None
):
    """A Company that opts in serves both: the agent chooses the newest version among
    `protocol_version` and `supported_versions` compatible with one it implements, and
    uses that version's document (§3.4). Either order of preference works."""

    for preferred in (BOTH, tuple(reversed(BOTH))):
        world = World()
        _serving(world, *preferred)
        other = preferred[1]
        assert world.shop.config.preferred_version == preferred[0]
        default = await _session(world)
        assert (world.company.protocol_version, default.protocol_version) == ("0.4", "0.4")
        # `poppy.json` itself when it is 0.4's, else 0.4's own document, which lists none.
        assert bool(world.company.document.supported_versions) is (preferred[0] == "0.4")
        opted_in = await _session(world, *BOTH)
        assert (world.company.protocol_version, opted_in.protocol_version) == ("1.0", "1.0")
        served = (await world.http.get("https://manzanita.example/.well-known/poppy.json")).json()
        assert served["protocol_version"] == preferred[0]
        assert served["supported_versions"] == {
            other: f"https://manzanita.example/poppy/{other}.json"
        }
        # Both Sessions are served, each in its own version.
        endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
        for session in (default, opted_in):
            receipt = await world.conversations.start(
                endpoint, world.message("Hello"), session=session
            )
            record = await world.shop.conversation_record(receipt.conversation_id)
            assert record.protocol_version == session.protocol_version


@pytest.mark.asyncio
async def test_a_conversation_started_in_the_draft_can_be_refused_in_the_published_version() -> (
    None
):
    """Versions don't always carry a conversation over: told not to, the company refuses a
    message from a 0.4 Session on a conversation started in 1.0 with `version_mismatch`,
    naming `1.0` (§8.2)."""

    world = World()
    _serving(world, *BOTH)
    draft = await _session(world, DRAFT_PROTOCOL_VERSION)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    receipt = await world.conversations.start(endpoint, world.message("Hello"), session=draft)
    world.shop.config = replace(world.shop.config, conversation_carry_over=False)
    published = await _session(world)
    with pytest.raises(ConversationError) as raised:
        await world.conversations.send(
            endpoint, receipt.conversation_id, world.message("Still there?"), session=published
        )
    assert (raised.value.code, raised.value.status_code) == ("version_mismatch", 409)
    assert raised.value.details == {"protocol_version": "1.0"}


@pytest.mark.asyncio
async def test_a_session_names_the_version_given_else_the_companys_else_the_published_one() -> None:
    world = World()
    sessions = SessionClient(reactor=world.reactor, http_client=world.http)
    who = {
        "client_id": world.atlas.client_id,
        "pairwise_user_id": PAIRWISE,
        "issuer": "https://manzanita.example",
        "tenant_id": TENANT,
    }
    assert (await sessions.start(**who)).protocol_version == "0.4"
    assert (await sessions.start(**who, protocol_version="1.0")).protocol_version == "1.0"
    with pytest.raises(ValueError):
        await sessions.start(**who, protocol_version="0.3")
    session = await sessions.start(**who)
    with pytest.raises(ValueError):
        replace(session, protocol_version="2.0")
    assert replace(session, protocol_version="1.0").protocol_version == "1.0"


@pytest.mark.asyncio
async def test_the_conformance_suite_passes_at_the_draft_over_tls() -> None:
    """Every case passes with Manzanita serving the 1.0 draft only and the suite's agent
    implementing it: the draft is wire-equal to 0.4 but its version string (§3.4)."""

    pytest.importorskip("uvicorn")
    from personal_agent_protocol.demo.sockets import served_over_tls

    world = ManzanitaConformance(protocol_versions=(DRAFT_PROTOCOL_VERSION,))
    async with served_over_tls(world.network):
        report = await run_conformance(world.context())
    failures = [f"{r.id}: {r.message}" for r in report.results if r.outcome == "failed"]
    assert failures == []
    assert report.profile == "1.0"
    assert {r.id for r in report.results} == {case.id for case in select_cases()}


# Lookalike domains (§10.3; guides, Finding a company) -------------------------------------


def test_the_name_is_shown_with_the_domain() -> None:
    """Nothing in `poppy.json` confirms that the domain belongs to the company it names:
    the domain is the Company's identity, so the SDK puts it beside the name."""

    assert Organization(name="Manzanita", domain="manzanita.example").label == (
        "Manzanita (manzanita.example)"
    )
    lookalike = Organization(name="Manzanita", domain="manzanita-orders.example")
    assert lookalike.label == "Manzanita (manzanita-orders.example)"
    assert Organization(name="manzanita.example", domain="manzanita.example").label == (
        "manzanita.example"
    )


@pytest.mark.asyncio
async def test_the_terminal_asks_for_credentials_with_the_domain_beside_the_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    asked: list[str] = []
    source = InputSource(stdin=True)
    source._lines = ["rosa@example.com", "246810"]
    original = source.read

    def read(label: str, *, secret: bool):  # type: ignore[no-untyped-def]
        asked.append(label)
        return original(label, secret=secret)

    monkeypatch.setattr(source, "read", read)
    request = ProtectedInputRequest(
        purpose="one_time_code",
        company_name="Manzanita",
        company_domain="manzanita-orders.example",
        issuer="https://manzanita-orders.example",
        fields=(ProtectedInputField(name="code", label="code", secret=True),),
        sent_to="r***@example.com",
    )
    await TerminalInput(source).collect(request)
    assert asked == ["Manzanita (manzanita-orders.example) code"]
    assert "Manzanita (manzanita-orders.example) sent a code" in capsys.readouterr().err
