# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Version 1.0 as published (upstream 8c02b42, frozen 2026-11-14): what changed after the
draft as of c71f515, both sides, in one process; `src/__tests__/published-10.test.mjs`
ports it.

Conversation protocol descriptions, Pushed Authorization Requests, minor versions, PS384,
consent for scopes granted before, the same DPoP key at refresh, UCP scope requests, ports
in `organization.domain`, client assertion lifetimes, one sign-in for every resource,
clearing context, room to extend conversations, what `working` means, unknown sign-in
errors, and the Mediated Sign-In retirement date. 0.4 as published is unchanged.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    KNOWN_CONVERSATION_ERRORS,
    MEDIATED_RETIREMENT_DATE,
    PROMPT_CONSENT,
    AuthorizationError,
    ConversationClient,
    ConversationError,
    DirectSignInClient,
    DiscoveryClient,
    DiscoveryDocument,
    PapSession,
    ProtocolValidationError,
    RefreshTokenClient,
    build_pap_reactor,
    clears_context,
    effective_context,
    known_conversation_error,
    page_carries_session,
    ucp_scopes,
    url_domain,
)
from personal_agent_protocol.auth import build_direct_sign_in_request
from personal_agent_protocol.company import CompanyConfig, CompanyRequest, MemoryReplayCache
from personal_agent_protocol.company.points import CLIENT_POLICIES, COMPANY_AGENTS
from personal_agent_protocol.company.verify import RSA_KEY_BITS, verify_assertion, verify_delegation
from personal_agent_protocol.conformance import ConformanceContext, SignedIn, _prover
from personal_agent_protocol.crypto import JoseSigner, delegation_claims
from personal_agent_protocol.demo.conformance import MANZANITA_SCENARIO, ManzanitaConformance
from personal_agent_protocol.demo.kit import ScriptedBrowser, personal_agent_reactor
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.device import verification_host_allowed
from personal_agent_protocol.errors import DiscoveryError, SessionError
from personal_agent_protocol.mcp import fetch_mcp_server_metadata
from personal_agent_protocol.models import (
    Author,
    ConversationEvent,
    JsonWebKeySet,
    Message,
    OAuthServerMetadata,
    Organization,
    split_domain,
)
from personal_agent_protocol.reactor import AUTHORIZATION_STATE_STORES, first_contribution
from personal_agent_protocol.sessions import build_client_assertion_claims
from personal_agent_protocol.transport import SessionHttpClient

from .test_company_end_to_end import TENANT, World
from .test_company_refusals import signed_in
from .test_conversations import Plugin
from .test_conversations import session as conversation_session
from .test_direct_and_api import begin, direct_world

SHOP = "https://manzanita.example"
DOCUMENT: dict[str, Any] = {
    "protocol_version": "1.0",
    "organization": {"name": "Example", "domain": "example.com"},
    "agent": {
        "protocols": [
            {
                "type": "poppy",
                "endpoint": "https://example.com/poppy/conversations",
                "description": "Anything about your orders",
            }
        ]
    },
}


def _without_description(version: str) -> dict[str, Any]:
    entry = {"type": "poppy", "endpoint": "https://example.com/poppy/conversations"}
    return {**DOCUMENT, "protocol_version": version, "agent": {"protocols": [entry]}}


def _binding(monkeypatch: pytest.MonkeyPatch, **changes: object) -> ManzanitaConformance:
    monkeypatch.setattr("personal_agent_protocol.demo.conformance.world_config", lambda _: changes)
    return ManzanitaConformance("a-test-world")


async def _signed_in(ctx: ConformanceContext) -> SignedIn:
    user = ctx.new_user()
    return await ctx.sign_in(user, await ctx.session(user))


class RecordingBrowser(ScriptedBrowser):
    """The user's browser: opens the company's pages, and records every URL handed to it,
    the agent's own pages unopened."""

    def __init__(self, http: httpx.AsyncClient) -> None:
        super().__init__(http)
        self.urls: list[str] = []

    async def open(self, authorization_url: SecretStr) -> None:
        url = authorization_url.get_secret_value()
        self.urls.append(url)
        if url.startswith(SHOP):
            await super().open(authorization_url)


def _recording_world(config: CompanyConfig | None = None) -> tuple[World, RecordingBrowser]:
    world, _ = direct_world()
    if config is not None:
        world.shop, world.plugin = manzanita(world.network, world.clock, config=config)
    browser = RecordingBrowser(world.http)
    world.host.browser = browser
    world.reactor = personal_agent_reactor(
        world.host, network=world.network, http_client=world.http
    )
    world.transport = SessionHttpClient(reactor=world.reactor, http_client=world.http)
    return world, browser


def _direct_arguments(world: World, **more: Any) -> dict[str, Any]:
    metadata = world.company.oauth_metadata
    assert metadata is not None
    return {
        "authorization_endpoint": metadata.authorization_endpoint,
        "token_endpoint": metadata.token_endpoint,
        "issuer": metadata.issuer,
        "client_id": world.atlas.client_id,
        "redirect_uri": f"https://{world.atlas.domain}/oauth/callback",
        "scopes": ("orders:read",),
        "tenant_id": TENANT,
        **more,
    }


# Conversation protocol descriptions (§3.1, §8.1) ------------------------------------------


def test_a_10_document_needs_a_description_for_each_conversation_protocol() -> None:
    entry = DiscoveryDocument.model_validate(DOCUMENT).agent.protocols[0]  # type: ignore[union-attr]
    assert entry.description == "Anything about your orders"
    with pytest.raises(ValueError, match="description"):
        DiscoveryDocument.model_validate(_without_description("1.0"))
    with pytest.raises(ValueError):
        DiscoveryDocument.model_validate(
            {**DOCUMENT, "agent": {"protocols": [{**_entry(), "description": ""}]}}
        )
    # 0.4 doesn't define it: a 0.4 document without one is valid, as published.
    published = DiscoveryDocument.model_validate(_without_description("0.4"))
    assert published.agent.protocols[0].description is None  # type: ignore[union-attr]


def _entry() -> dict[str, str]:
    return {"type": "poppy", "endpoint": "https://example.com/poppy/conversations"}


def test_the_reference_company_describes_its_agent_at_10_and_not_at_04() -> None:
    world = World()
    document = world.shop.discovery_document()
    (entry,) = document["agent"]["protocols"]
    assert entry["description"] == CONFIG.agent_description
    both = replace(CONFIG, protocol_versions=("1.0", "0.4"))
    world.shop, world.plugin = manzanita(world.network, world.clock, config=both)
    published = world.shop.discovery_document(version="0.4")
    assert "description" not in published["agent"]["protocols"][0]
    with pytest.raises(ValueError, match="agent_description"):
        replace(CONFIG, agent_description=" ")


# Pushed Authorization Requests (§3.2, §4.2, §4.8) ----------------------------------------


@pytest.mark.asyncio
async def test_a_company_offers_or_requires_par_and_the_agent_pushes() -> None:
    world, browser = _recording_world(replace(CONFIG, pushed_authorization_requests="offered"))
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    assert metadata.pushed_authorization_request_endpoint == f"{SHOP}/oauth/par"
    assert not metadata.require_pushed_authorization_requests
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    await client.begin(
        **_direct_arguments(
            world,
            pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
        )
    )
    # The browser gets only client_id and request_uri (RFC 9126 §4).
    query = parse_qs(urlsplit(browser.urls[-1]).query)
    assert set(query) == {"client_id", "request_uri"}
    assert query["request_uri"][0].startswith("urn:ietf:params:oauth:request_uri:")
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    done = await client.complete(callback)
    assert done.token.scopes == ("orders:read",)
    # A request_uri is used once.
    again = await world.http.get(browser.urls[-1])
    assert again.status_code == 400


@pytest.mark.asyncio
async def test_a_company_that_requires_par_takes_nothing_else() -> None:
    world, browser = _recording_world(replace(CONFIG, pushed_authorization_requests="required"))
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None and metadata.require_pushed_authorization_requests
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    # Not pushed: the company's page refuses the request.
    await client.begin(**_direct_arguments(world))
    assert "not valid" in browser.pages[-1] and 'name="request_id"' not in browser.pages[-1]
    # A required push needs the endpoint, refused before anything is sent.
    with pytest.raises(ValueError, match="PAR"):
        await client.begin(**_direct_arguments(world, require_pushed_authorization_requests=True))
    with pytest.raises(ValueError):
        OAuthServerMetadata.model_validate(
            {**metadata.model_dump(), "pushed_authorization_request_endpoint": None}
        )
    # Pushed, the sign-in completes.
    await client.begin(
        **_direct_arguments(
            world,
            pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests=True,
        )
    )
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    assert (await client.complete(callback)).token is not None
    # A push is checked as an authorization request: an unknown redirect is refused.
    form = {
        "response_type": "code",
        "client_id": world.atlas.client_id,
        "redirect_uri": "https://elsewhere.example/cb",
        "scope": "orders:read",
        "code_challenge": "x" * 43,
        "code_challenge_method": "S256",
        **await client.sessions.client_authentication(client_id=world.atlas.client_id, issuer=SHOP),
    }
    refused = await world.http.post(f"{SHOP}/oauth/par", data=form)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_request")
    with pytest.raises(ValueError, match="direct"):
        replace(CONFIG, pushed_authorization_requests="offered", direct=False)


@pytest.mark.asyncio
async def test_a_link_opened_later_goes_to_the_agents_page_which_pushes_then() -> None:
    world, browser = _recording_world(replace(CONFIG, pushed_authorization_requests="required"))
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    await client.begin(
        **_direct_arguments(
            world,
            pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests=True,
            cross_device=True,
            link_page="https://atlas.example/sign-in/{link}",
        )
    )
    # The handoff got the agent's own page: nothing was pushed yet.
    link_url = browser.urls[-1]
    assert link_url.startswith("https://atlas.example/sign-in/")
    link = link_url.rsplit("/", 1)[1]
    # Opened much later: the page pushes now, so the request_uri is fresh.
    world.clock.advance(120)
    authorization_url = await client.open_link(link)
    assert "request_uri=" in authorization_url.get_secret_value()
    await browser.open(authorization_url)
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    assert (await client.complete(callback)).token is not None
    with pytest.raises(AuthorizationError):
        await client.open_link(link)  # the sign-in is done
    with pytest.raises(AuthorizationError):
        await client.open_link("unknown")
    with pytest.raises(ValueError):
        await client.begin(**_direct_arguments(world, link_page="https://atlas.example/no-link"))


@pytest.mark.asyncio
async def test_a_push_with_a_dpop_proof_binds_the_code_to_its_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _binding(monkeypatch, dpop_binding="required", pushed_authorization_requests="required")
    ctx = world.context()
    metadata = await ctx.metadata()
    assert metadata.require_pushed_authorization_requests
    signed = await _signed_in(ctx)  # the conformance agent pushes, with a proof
    assert signed.token.token_type == "DPoP"
    # Pushed with one key, exchanged with another: the code is bound to the first.
    user = ctx.new_user()
    session = await ctx.session(user)
    client = DirectSignInClient(reactor=ctx.agent.reactor, http_client=ctx.http)
    await client.begin(
        authorization_endpoint=metadata.authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=ctx.agent.identity.client_id,
        redirect_uri=str(ctx.agent.identity.metadata["redirect_uris"][0]),
        scopes=MANZANITA_SCENARIO.scopes,
        tenant_id=ctx.tenant_id,
        dpop_signing_algs=metadata.dpop_signing_alg_values_supported,
        pairwise_user_id=session.sub,
        pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
        require_pushed_authorization_requests=True,
    )
    callback = await ctx.driver.approve_authorization(
        ctx.agent.user_browser.urls[-1], account=ctx.driver.accounts[0]
    )
    await _prover(ctx).keys.forget(tenant_id=ctx.tenant_id, issuer=metadata.issuer, sub=session.sub)
    with pytest.raises(AuthorizationError) as refused:
        await client.complete(callback)
    assert refused.value.code == "invalid_grant"


# Minor versions (§3.4) --------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nothing_of_10_goes_into_a_04_exchange() -> None:
    """A 0.4 document has no description, and a 0.4 Session sends no `null` context."""

    world = World()
    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, protocol_versions=("0.4",))
    )
    document = world.shop.discovery_document()
    assert document["protocol_version"] == "0.4"
    assert all("description" not in entry for entry in document["agent"]["protocols"])
    session = PapSession(
        sid="sid_" + "a" * 22,
        sub="u",
        issuer=SHOP,
        client_id="https://atlas.example/agent.json",
        tenant_id=TENANT,
        protocol_version="0.4",
    )
    clearing = Message(author=Author(type="agent"), context={"locale": None})
    assert clears_context(clearing)
    with pytest.raises(ProtocolValidationError) as refused:
        ConversationClient._outgoing_message(clearing, session)
    assert refused.value.code == "context_clear_unsupported"
    later = replace(session, protocol_version="1.0")
    assert ConversationClient._outgoing_message(clearing, later)["context"] == {"locale": None}


# PS384 required, RSA 2048 to 4096 bits (§4.1, §5.2, §10.7) --------------------------------


def _rsa_jwks(key: rsa.RSAPrivateKey, kid: str) -> JsonWebKeySet:
    public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    return JsonWebKeySet.model_validate({"keys": [{**public, "kid": kid, "alg": "PS384"}]})


async def _assertion(key: rsa.RSAPrivateKey, *, lifetime: int = 60) -> tuple[str, datetime]:
    now = datetime(2026, 11, 17, 9, tzinfo=timezone.utc)
    claims = build_client_assertion_claims(
        client_id="https://atlas.example/agent.json",
        issuer=SHOP,
        now=now,
        lifetime_seconds=min(lifetime, 300),
    )
    payload = {**claims.model_dump(), "exp": claims.iat + lifetime}
    signer = JoseSigner(key, algorithm="PS384", key_id="k")
    return (await signer.sign(payload, purpose="client_assertion")).get_secret_value(), now


@pytest.mark.asyncio
@pytest.mark.parametrize("bits", [2048, 3072, 4096])
async def test_companies_accept_ps384_assertions_and_delegations(bits: int) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    compact, now = await _assertion(key)
    claims = await verify_assertion(
        compact,
        keys=_rsa_jwks(key, "k"),
        issuer="https://atlas.example/agent.json",
        subject="https://atlas.example/agent.json",
        audience=SHOP,
        replay_cache=MemoryReplayCache(),
        now=now,
    )
    assert claims["aud"] == SHOP
    delegated = ec.generate_private_key(ec.SECP256R1())
    public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(delegated.public_key()))
    signer = JoseSigner(key, algorithm="PS384", key_id="k")
    delegation = await signer.sign(
        delegation_claims(
            client_id="https://atlas.example/agent.json",
            public=public,
            issued_at=now,
            lifetime=timedelta(hours=1),
        ),
        purpose="delegation",
    )

    async def resolve(_client: str, _kid: str | None) -> tuple[Any, JsonWebKeySet]:
        return None, _rsa_jwks(key, "k")

    verified = await verify_delegation(
        delegation.get_secret_value(),
        client_id="https://atlas.example/agent.json",
        resolve=resolve,
        now=now,
    )
    assert verified.client_id == "https://atlas.example/agent.json"


@pytest.mark.asyncio
@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")  # the test signs
async def test_an_rsa_key_outside_2048_to_4096_bits_is_refused() -> None:
    assert RSA_KEY_BITS == (2048, 4096)
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - refused, as it should be
    compact, now = await _assertion(weak)
    with pytest.raises(SessionError) as refused:
        await verify_assertion(
            compact,
            keys=_rsa_jwks(weak, "k"),
            issuer="https://atlas.example/agent.json",
            audience=SHOP,
            replay_cache=MemoryReplayCache(),
            now=now,
        )
    assert refused.value.code == "invalid_client"


# Client assertion lifetime (§4.1) ---------------------------------------------------------


@pytest.mark.asyncio
async def test_an_assertion_lasts_at_most_five_minutes_and_one_that_does_is_accepted() -> None:
    with pytest.raises(ValueError):
        build_client_assertion_claims(
            client_id="https://atlas.example/agent.json", issuer=SHOP, lifetime_seconds=301
        )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for lifetime, accepted in ((300, True), (301, False)):
        compact, now = await _assertion(key, lifetime=lifetime)
        verify = verify_assertion(
            compact,
            keys=_rsa_jwks(key, "k"),
            issuer="https://atlas.example/agent.json",
            audience=SHOP,
            replay_cache=MemoryReplayCache(),
            now=now,
        )
        if accepted:
            await verify
        else:
            with pytest.raises(SessionError):
                await verify


# Consent for scopes granted before (§4.2, §4.3, §10.8) ------------------------------------


def test_a_direct_sign_in_asks_for_consent_unless_the_redirect_stays_on_the_device() -> None:
    arguments = {
        "authorization_endpoint": f"{SHOP}/oauth/authorize?prompt=none",
        "issuer": SHOP,
        "client_id": "https://atlas.example/agent.json",
        "redirect_uri": "https://atlas.example/oauth/callback",
        "scopes": ("orders:read",),
    }
    request = build_direct_sign_in_request(**arguments)  # type: ignore[arg-type]
    query = parse_qs(urlsplit(request.authorization_url.get_secret_value()).query)
    assert query["prompt"] == [PROMPT_CONSENT] == ["consent"]
    assert "resource" not in query  # one sign-in for every resource (§4.5)
    same_device = build_direct_sign_in_request(**arguments, prompt_consent=False)  # type: ignore[arg-type]
    assert "prompt" not in parse_qs(
        urlsplit(same_device.authorization_url.get_secret_value()).query
    )


@pytest.mark.asyncio
async def test_the_consent_page_lists_every_scope_and_marks_the_earlier_ones() -> None:
    world, browser = direct_world()
    session = await world.signed_out_session()
    client = await begin(world, browser, session, ("orders:read",))
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    await client.complete(callback)
    # Every scope again, the earlier one included: the page is shown all the same.
    client = await begin(world, browser, session, ("orders:read", "orders:write"))
    page = browser.pages[-1]
    assert 'name="request_id"' in page and "See your orders" in page
    summary = await world.shop.authorization_request(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    assert summary["prompt"] == "consent"
    assert [(item["scope"], item["granted_before"]) for item in summary["scopes"]] == [
        ("orders:read", True),
        ("orders:write", False),
    ]
    unmarked = await world.shop.authorization_request(browser.request_id)  # type: ignore[arg-type]
    assert all("granted_before" not in item for item in unmarked["scopes"])
    # Another account granted nothing.
    other = await world.shop.authorization_request(browser.request_id, account_id="acct_bob")  # type: ignore[arg-type]
    assert not any(item["granted_before"] for item in other["scopes"])


@pytest.mark.asyncio
async def test_every_device_sign_in_shows_its_page_with_the_earlier_scopes_marked() -> None:
    world = World()
    await signed_in(world, ("orders:read",))
    from personal_agent_protocol.device import DeviceSignInClient

    metadata = world.company.oauth_metadata
    assert metadata is not None
    started = await DeviceSignInClient(reactor=world.reactor, http_client=world.http).begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=world.company.document.organization,
    )
    shown = await world.shop.device_request(started.user_code, account_id="acct_ada")
    assert [(item["scope"], item["granted_before"]) for item in shown["scopes"]] == [
        ("orders:read", True),
        ("orders:write", False),
    ]


# Same DPoP key at refresh (§4.4, §4.5, §10.7) ---------------------------------------------


@pytest.mark.asyncio
async def test_a_bound_refresh_token_refreshes_only_with_its_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="bind_refresh_tokens"):
        replace(CONFIG, bind_refresh_tokens=True)
    world = _binding(monkeypatch, dpop_binding="required", bind_refresh_tokens=True)
    ctx = world.context()
    signed = await _signed_in(ctx)
    context = await ctx.account_context(signed.session.sub)
    # The same key, twice: the rotated token stays bound to it.
    for _ in range(2):
        refreshed = await ctx.agent.accounts.refresh(signed.reference, context=context)
        assert refreshed.status == "signed_in" and refreshed.rotated
    metadata = await ctx.metadata()
    await _prover(ctx).keys.forget(
        tenant_id=ctx.tenant_id, issuer=metadata.issuer, sub=signed.session.sub
    )
    # Another key: invalid_grant, so the copy is useless and the agent signs in again.
    lost = await ctx.agent.accounts.refresh(signed.reference, context=context)
    assert lost.status == "signed_out"


@pytest.mark.asyncio
async def test_without_binding_a_refresh_with_a_new_key_still_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = _binding(monkeypatch, dpop_binding="required")
    ctx = world.context()
    signed = await _signed_in(ctx)
    metadata = await ctx.metadata()
    await _prover(ctx).keys.forget(
        tenant_id=ctx.tenant_id, issuer=metadata.issuer, sub=signed.session.sub
    )
    context = await ctx.account_context(signed.session.sub)
    assert (await ctx.agent.accounts.refresh(signed.reference, context=context)).status == (
        "signed_in"
    )
    url = ctx.url(MANZANITA_SCENARIO.read_path)
    assert url.startswith("https://")


# UCP scope requests name every scope (UCP 4, 11) ------------------------------------------


@pytest.mark.asyncio
async def test_a_ucp_sign_in_requests_every_scope_and_gets_only_those() -> None:
    held, needed = ("orders:write",), ("orders:read",)
    fake = type("Profile", (), {"identity_linking_scopes": ("orders:read",)})()
    assert ucp_scopes(fake, held, needed=needed) == ("orders:write", "orders:read")  # type: ignore[arg-type]
    assert ucp_scopes(fake, held) == ("orders:write", "orders:read")  # type: ignore[arg-type]
    # 0.4 kept UCP's incremental authorization: only the missing scopes.
    assert ucp_scopes(fake, held, needed=needed, protocol_version="0.4") == ("orders:read",)  # type: ignore[arg-type]
    # The company grants only the scopes a sign-in names, whatever was granted before.
    world = World()
    await signed_in(world, ("orders:read", "orders:write"))
    narrower = await signed_in(world, ("orders:read",))
    assert narrower.scopes == ("orders:read",)


# Ports in organization.domain (§3.1, §3.2) ------------------------------------------------


def test_a_domain_names_its_port_when_that_isnt_443_from_10_only() -> None:
    assert split_domain("shop.example:8443") == ("shop.example", 8443)
    assert Organization(name="Shop", domain="Shop.Example:8443").domain == "shop.example:8443"
    for invalid in ("shop.example:443", "shop.example:0", "shop.example:99999", "x.example:y"):
        with pytest.raises(ValueError):
            Organization(name="Shop", domain=invalid)
    on_a_port = {**DOCUMENT, "organization": {"name": "Shop", "domain": "shop.example:8443"}}
    assert DiscoveryDocument.model_validate(on_a_port).organization.domain == "shop.example:8443"
    with pytest.raises(ValueError, match="port"):
        DiscoveryDocument.model_validate({**on_a_port, "protocol_version": "0.4"})
    assert url_domain("https://shop.example:8443/x") == "shop.example:8443"
    assert url_domain("https://shop.example:443/x") == "shop.example"
    assert page_carries_session("https://shop.example:8443/page", "shop.example:8443")
    assert not page_carries_session("https://shop.example/page", "shop.example:8443")
    assert verification_host_allowed(
        "https://shop.example/device", issuer="https://auth.example", domain="shop.example:8443"
    )
    metadata = OAuthServerMetadata.model_validate(
        {
            "issuer": "https://shop.example:8443",
            "token_endpoint": "https://shop.example:8443/oauth/token",
            "revocation_endpoint": "https://shop.example:8443/oauth/revoke",
            "grant_types_supported": ["refresh_token"],
            "protected_resources": ["https://shop.example:8443"],
        }
    )
    assert metadata.lists_resource("shop.example:8443")
    assert not metadata.lists_resource("shop.example")
    # A company serves a domain with a port at 1.0 only.
    replace(CONFIG, domain="manzanita.example:8443")
    with pytest.raises(ValueError, match="port"):
        replace(CONFIG, domain="manzanita.example:8443", protocol_versions=("1.0", "0.4"))


def _port_network(organization: str) -> httpx.AsyncClient:
    base = "https://shop.example:8443"
    answers = {
        f"{base}/.well-known/poppy.json": {
            **DOCUMENT,
            "organization": {"name": "Shop", "domain": organization},
            "agent": {
                "protocols": [{**_entry(), "endpoint": f"{base}/poppy", "description": "All"}]
            },
        },
        f"{base}/.well-known/oauth-protected-resource": {
            "resource": base,
            "authorization_servers": [base],
        },
        f"{base}/.well-known/oauth-authorization-server": {
            "issuer": base,
            "token_endpoint": f"{base}/oauth/token",
            "revocation_endpoint": f"{base}/oauth/revoke",
            "grant_types_supported": ["refresh_token"],
            "protected_resources": [base],
        },
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        body = answers.get(str(request.url))
        return httpx.Response(200 if body else 404, json=body or {"error": "not_found"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _public(_: str) -> list[str]:
    return ["93.184.216.34"]


@pytest.mark.asyncio
async def test_an_agent_uses_a_company_on_another_port_only_when_configured_to() -> None:
    async with _port_network("shop.example:8443") as http:
        with pytest.raises(DiscoveryError) as refused:
            await DiscoveryClient(http_client=http, address_resolver=_public).discover(
                "shop.example:8443"
            )
        assert refused.value.code == "port_not_allowed"
        client = DiscoveryClient(http_client=http, address_resolver=_public, allow_ports=True)
        company = await client.discover("shop.example:8443")
        assert company.document.organization.domain == "shop.example:8443"
    # A document on shop.example:8443 speaks for shop.example:8443, not shop.example.
    async with _port_network("shop.example") as http:
        client = DiscoveryClient(http_client=http, address_resolver=_public, allow_ports=True)
        with pytest.raises(DiscoveryError) as mismatch:
            await client.discover("shop.example:8443")
        assert mismatch.value.code == "organization_domain_mismatch"


# One sign-in for every resource (§4.5, §4.7, §4.8, §7) ------------------------------------


@pytest.mark.asyncio
async def test_a_service_left_out_is_invalid_target_and_used_signed_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World()
    await signed_in(world)
    context = world.account_context()
    client = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    mcp = f"{SHOP}/mcp"
    # Signed in with no resource: a token for the MCP server, added or not.
    result = await client.refresh(world.refresh_reference, context=context, resource=mcp)  # type: ignore[arg-type]
    assert result.status == "signed_in" and result.token is not None
    assert result.token.resource == mcp

    # The client policy leaves the MCP server out for this agent (`allows_resource`).
    policy = first_contribution(world.shop.reactor, CLIENT_POLICIES, "policy")

    async def allows_resource(client_id: str, resource: str) -> bool:
        return resource != mcp

    monkeypatch.setattr(policy, "allows_resource", allows_resource, raising=False)
    with pytest.raises(AuthorizationError) as refused:
        await client.refresh(world.refresh_reference, context=context, resource=mcp)  # type: ignore[arg-type]
    assert refused.value.code == "invalid_target"
    # The default token still comes; the agent uses the server signed out.
    default = await client.refresh(world.refresh_reference, context=context)  # type: ignore[arg-type]
    assert default.status == "signed_in"


# Clearing context, room to extend conversations (§8.4, §8.6, §8.13) -----------------------


def test_null_clears_a_context_field_as_if_never_shared() -> None:
    messages = [
        Message(author=Author(type="agent"), context={"locale": "fr", "time_zone": "Europe/Paris"}),
        Message(author=Author(type="agent"), context={"user_available": True}),
        Message(author=Author(type="agent"), context={"locale": None}),
    ]
    assert effective_context(messages) == {"time_zone": "Europe/Paris", "user_available": True}


@pytest.mark.asyncio
async def test_the_company_agent_sees_the_context_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world = World()
    await signed_in(world)
    seen: list[dict[str, Any]] = []
    agent = first_contribution(world.shop.reactor, COMPANY_AGENTS, "company agent")
    original = agent.respond

    async def respond(turn: Any) -> Any:
        seen.append(dict(turn.context))
        return await original(turn)

    monkeypatch.setattr(agent, "respond", respond)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    started = await world.conversations.start(
        endpoint,
        Message(author=Author(type="agent"), text="Hello", context={"locale": "fr"}),
        session=world.session,  # type: ignore[arg-type]
        wait=5,
    )
    await world.conversations.send(
        endpoint,
        started.conversation_id,
        Message(author=Author(type="agent"), text="Again", context={"locale": None}),
        session=world.session,  # type: ignore[arg-type]
        wait=5,
    )
    assert seen == [{"locale": "fr"}, {}]


def test_unknown_roles_and_author_types_are_read_safely() -> None:
    message = Message.model_validate(
        {"author": {"type": "organization"}, "role": "system", "text": "Hi"}
    )
    assert (message.role, message.author.type) == ("company", "agent")


@pytest.mark.asyncio
async def test_the_company_ignores_author_fields_on_the_agents_messages() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    body = {
        "id": "req_" + "a" * 22,
        "message": {
            "author": {"type": "agent", "id": "pretend", "name": "Support", "image": f"{SHOP}/i"},
            "text": "Hello",
        },
    }
    transport = SessionHttpClient(reactor=world.reactor, http_client=world.http)
    response = await transport.request(
        "POST",
        endpoint,
        session=session,
        headers={"Content-Type": "application/json"},
        content=json.dumps(body).encode(),
    )
    assert response.status_code == 201
    page = await world.conversations.read_events(
        endpoint, response.json()["conversation_id"], session=session
    )
    first = page.events[0].message
    assert first is not None and first.author.model_dump(exclude_none=True) == {"type": "agent"}


@pytest.mark.asyncio
async def test_a_stream_skips_event_names_it_doesnt_know() -> None:
    lines = (
        'event: working\ndata: {"working":true}\n\n'
        'event: future-thing\ndata: {"anything":1}\n\n'
        "id: evt_1\ndata: "
        + json.dumps(
            {
                "id": "evt_1",
                "type": "state",
                "created_at": "2026-11-17T09:00:00Z",
                "handoff": "none",
                "responder": "agent",
                "closed": True,
            }
        )
        + "\n\n"
    )

    async def company(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=lines.encode()
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="stream-test", version="1"), Plugin())
        client = ConversationClient(transport=SessionHttpClient(reactor=reactor, http_client=http))
        items = [
            item
            async for item in client.stream(
                f"{SHOP}/poppy", "cnv_1", session=conversation_session()
            )
        ]
        reactor.stop()
    assert [type(item).__name__ for item in items] == ["WorkingChanged", "ConversationEvent"]


def test_an_unknown_error_code_is_handled_by_its_http_status() -> None:
    assert known_conversation_error("conversation_closed") == "conversation_closed"
    assert known_conversation_error("stronger_sign_in_needed") == "conversation_request_failed"
    assert "conversation_closed" in KNOWN_CONVERSATION_ERRORS
    refused = ConversationClient._rejected(
        httpx.Response(409, json={"error": "something_new"}), {"error": "something_new"}
    )
    assert (refused.code, refused.status_code, refused.details) == (
        "conversation_request_failed",
        409,
        {"error": "something_new"},
    )
    assert isinstance(refused, ConversationError)


# What working means, unknown sign-in errors (§8.7, §8.11) ---------------------------------


@pytest.mark.asyncio
async def test_working_is_false_once_the_reply_is_written() -> None:
    world = World()
    await signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        Message(author=Author(type="agent"), text="Exchange my jacket for a size L"),
        session=world.session,  # type: ignore[arg-type]
        wait=5,
    )
    # The reply proposes an exchange the User has yet to approve: not `working`.
    assert getattr(page, "working", False) is False


def test_an_unknown_authorization_error_signs_in_again_for_its_scopes() -> None:
    event = ConversationEvent.model_validate(
        {
            "id": "evt_1",
            "type": "authorization",
            "created_at": "2026-11-17T09:00:00Z",
            "error": "stronger_sign_in",
            "scope": "orders:read orders:write orders:read",
        }
    )
    assert event.error == "stronger_sign_in"
    assert event.sign_in_scopes == ("orders:read", "orders:write")


# Mediated Sign-In retirement date ---------------------------------------------------------


def test_mediated_sign_in_is_retired_on_17_march_2027() -> None:
    assert MEDIATED_RETIREMENT_DATE == "2027-03-17"
    assert CompanyRequest is not None


# 0.37.1 -----------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_bound_refresh_gets_a_bearer_token_for_a_bearer_only_mcp_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refresh proves with the refresh token's key whatever token it asks for (§4.4), and
    a server that takes only Bearer gets Bearer (§4.5): the sign-in is kept."""

    world = _binding(monkeypatch, dpop_binding="required", bind_refresh_tokens=True)
    ctx = world.context()
    signed = await _signed_in(ctx)
    plain = world.service.protected_resource_metadata()
    plain.pop("dpop_signing_alg_values_supported")
    monkeypatch.setattr(world.service, "protected_resource_metadata", lambda: plain)
    metadata = await ctx.metadata()
    server = await fetch_mcp_server_metadata(
        ctx.http, world.service.config.mcp_url, issuer=metadata.issuer
    )
    assert server.dpop_signing_alg_values_supported is None
    context = await ctx.account_context(signed.session.sub)
    result = await ctx.agent.accounts.token_for_mcp(
        signed.reference, context=context, server=server
    )
    assert result.status == "signed_in" and result.token is not None
    assert result.token.token_type == "Bearer"
    # The refresh token was kept: the next refresh, by the same key, works.
    assert (await ctx.agent.accounts.refresh(signed.reference, context=context)).status == (
        "signed_in"
    )


@pytest.mark.asyncio
async def test_opening_a_link_never_takes_the_callback_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    world, browser = _recording_world(replace(CONFIG, pushed_authorization_requests="required"))
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    await client.begin(
        **_direct_arguments(
            world,
            pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests=True,
            link_page="https://atlas.example/sign-in/{link}",
        )
    )
    link = browser.urls[-1].rsplit("/", 1)[1]
    store = first_contribution(world.reactor, AUTHORIZATION_STATE_STORES, "state store")
    taken: list[str] = []
    take = store.take

    async def recording(reference: str) -> object:
        taken.append(reference)
        return await take(reference)

    monkeypatch.setattr(store, "take", recording)
    await browser.open(await client.open_link(link))
    assert taken and all(not reference.startswith("direct:") for reference in taken)
    # Opened twice, then completed: complete() alone consumes the state, once.
    await client.open_link(link)
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    assert (await client.complete(callback)).token is not None
    with pytest.raises(AuthorizationError):
        await client.open_link(link)


def test_a_context_field_named_proto_is_a_field() -> None:
    messages = [Message(author=Author(type="agent"), context={"__proto__": {"x": 1}})]
    assert effective_context(messages) == {"__proto__": {"x": 1}}


@pytest.mark.asyncio
async def test_an_empty_event_name_is_the_default_message_event() -> None:
    state = {
        "id": "evt_1",
        "type": "state",
        "created_at": "2026-11-17T09:00:00Z",
        "handoff": "none",
        "responder": "agent",
        "closed": True,
    }
    lines = f"event:\nid: evt_1\ndata: {json.dumps(state)}\n\n"

    async def company(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content=lines.encode()
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(PluginManifest(name="stream-test", version="1"), Plugin())
        client = ConversationClient(transport=SessionHttpClient(reactor=reactor, http_client=http))
        session = conversation_session()
        items = [item async for item in client.stream(f"{SHOP}/poppy", "cnv_1", session=session)]
        reactor.stop()
    assert [type(item).__name__ for item in items] == ["ConversationEvent"]
