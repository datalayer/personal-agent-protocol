# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What draft 1.1 adds to 1.0 (upstream 589743a, 2026-11-18), both sides, in one process;
`src/__tests__/draft-11.test.mjs` ports it.

Draft 1.1 is the default version, and 1.0 stays available when named: from 1.0 each side
sends only what the other's version defines (§3.4). `offline_access` (§4.4, §4.7),
operator signatures at the authorization server (§5.3), replacing a User ID (§5.1), and
listed tasks in feedback (§9, §9.3).
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    OFFLINE_ACCESS_SCOPE,
    PAIRWISE_USER_ID_STORES,
    USER_ID_UNUSED_AFTER,
    AuthorizationError,
    DerivedPairwiseUserIds,
    DeviceSignInClient,
    DirectSignInClient,
    DiscoveryClient,
    FeedbackClient,
    FeedbackError,
    FeedbackReport,
    ListedTask,
    MediatedSignInClient,
    OperatorSignatureRequest,
    PapSession,
    ProtocolValidationError,
    RefreshTokenClient,
    SessionClient,
    SqlitePairwiseCounters,
    SqlitePairwiseUserIdStore,
    TasksClient,
    UserIdAtCompany,
    UserIdError,
    WebBotAuthSigner,
    content_digest,
    derive_pairwise_user_id,
    may_replace_unused,
    new_operator_key,
    operator_directory,
    replace_user_id,
    request_scope,
    sign_operator_request,
    verify_operator_signature,
)
from personal_agent_protocol.auth import build_direct_sign_in_request
from personal_agent_protocol.company import CompanyConfig, OperatorVerifiedAgents
from personal_agent_protocol.company.points import CLIENT_POLICIES
from personal_agent_protocol.company.store import FEEDBACK, USER_ID
from personal_agent_protocol.demo.conformance import ManzanitaConformance
from personal_agent_protocol.demo.kit import personal_agent_reactor
from personal_agent_protocol.demo.manzanita import ADA, CONFIG, manzanita
from personal_agent_protocol.models import (
    DiscoveryDocument,
    FeedbackDescriptor,
    OAuthServerMetadata,
    TasksResponse,
    version_defines,
)
from personal_agent_protocol.operator_signatures import accept_signature
from personal_agent_protocol.sessions import AccessToken, TokenResponse
from personal_agent_protocol.transport import SessionHttpClient, session_headers

from .test_company_end_to_end import PAIRWISE, TENANT, World
from .test_published_10 import _direct_arguments, _recording_world

SHOP = "https://manzanita.example"
FEEDBACK_URL = f"{SHOP}/poppy/feedback"
LISTED = (
    {"id": "installments", "task": "Pay in installments"},
    {"id": "split-payment", "task": "Split a payment across two cards"},
)


def _serving(world: World, config: CompanyConfig) -> None:
    world.shop, world.plugin = manzanita(world.network, world.clock, config=config)


def _spy(world: World) -> list[httpx.Request]:
    """Every request the agent sends from now on."""

    captured: list[httpx.Request] = []
    original = world.http._transport.handle_async_request  # type: ignore[attr-defined]

    async def spy(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return await original(request)

    world.http._transport.handle_async_request = spy  # type: ignore[attr-defined,method-assign]
    return captured


def _form(request: httpx.Request) -> dict[str, str]:
    return {name: values[0] for name, values in parse_qs(request.content.decode()).items()}


async def _session(world: World, *versions: str, sub: str = PAIRWISE) -> PapSession:
    """Discovery and a signed-out Session by an agent that implements `versions`."""

    company = await DiscoveryClient(
        reactor=world.reactor, http_client=world.http, protocol_versions=versions or None
    ).discover("manzanita.example", fresh=True)
    world.company = company
    return await SessionClient(reactor=world.reactor, http_client=world.http).start(
        client_id=world.atlas.client_id,
        pairwise_user_id=sub,
        issuer=company.identifier,
        tenant_id=TENANT,
        company=company,
    )


async def _device_sign_in(world: World, session: PapSession, **more: Any) -> Any:
    metadata = world.company.oauth_metadata
    assert metadata is not None
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=str(metadata.device_authorization_endpoint),
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=world.company.document.organization,
        **more,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    return await device.poll(started.reference)


# Draft 1.1, the default, and 1.0 when named (§3.4) ---------------------------------------


def test_a_version_defines_what_an_earlier_minor_added() -> None:
    assert version_defines("1.1", "1.1") and version_defines("1.4", "1.1")
    assert not version_defines("1.0", "1.1")
    assert not version_defines("0.4", "1.1") and not version_defines("2.1", "1.1")
    config = replace(CONFIG, protocol_versions=("1.1", "0.4"))
    assert config.defines("1.1", "1.1") and config.defines("1.3", "1.1")
    assert not config.defines("1.0", "1.1") and not config.defines("0.4", "1.1")
    assert not config.defines(None, "1.1") and not config.defines("one", "1.1")
    # A company that serves only 1.0 handles a 1.1 request as 1.0 defines.
    assert not replace(CONFIG, protocol_versions=("1.0",)).defines("1.1", "1.1")


@pytest.mark.asyncio
async def test_each_side_names_the_version_both_define() -> None:
    """The default agent (1.1) at a company whose document is 1.0 names 1.0, and an agent
    that names 1.0 stays at 1.0 with a 1.1 company: nothing of 1.1 goes to a 1.0 peer."""

    world = World()
    default = await _session(world)
    assert (world.company.protocol_version, default.protocol_version) == ("1.1", "1.1")
    published = await _session(world, "1.0")
    assert (world.company.protocol_version, published.protocol_version) == ("1.1", "1.0")
    headers = await session_headers(
        world.reactor, "GET", f"{SHOP}/poppy/tasks", session=published, token=None
    )
    assert headers["Poppy-Version"] == "1.0"
    # Both are served by the 1.1 company, each in its own version.
    for session in (default, published):
        answer = await world.transport.request("GET", f"{SHOP}/poppy/tasks", session=session)
        assert answer.status_code == 200
    _serving(world, replace(CONFIG, protocol_versions=("1.0",)))
    at_published = await _session(world)
    assert (world.company.protocol_version, at_published.protocol_version) == ("1.0", "1.0")
    # A 1.0 company accepts a request that names 1.1, compatible with what it serves.
    newer = replace(at_published, protocol_version="1.1")
    answer = await world.transport.request("GET", f"{SHOP}/poppy/tasks", session=newer)
    assert answer.status_code == 200


@pytest.mark.asyncio
async def test_the_conformance_suite_passes_at_10_over_tls() -> None:
    """Every case passes with Manzanita serving 1.0 as published only: the suite's agent
    names 1.0 there, and the cases 1.1 adds are skipped, never passed."""

    pytest.importorskip("uvicorn")
    from personal_agent_protocol.conformance import run_conformance, select_cases
    from personal_agent_protocol.demo.sockets import served_over_tls

    world = ManzanitaConformance(protocol_versions=("1.0",))
    async with served_over_tls(world.network):
        report = await run_conformance(world.context())
    failures = [f"{r.id}: {r.message}" for r in report.results if r.outcome == "failed"]
    assert failures == []
    assert report.profile == "1.0"
    assert {r.id for r in report.results} == {case.id for case in select_cases()}


# `offline_access` (§4.4, §4.7, §4.8) -------------------------------------------------------


def test_offline_access_is_requested_when_the_issuer_lists_it_and_never_granted() -> None:
    assert request_scope(("orders:read",), None) == "orders:read"
    assert request_scope(("orders:read",), ["orders:read"]) == "orders:read"
    listed = ["orders:read", OFFLINE_ACCESS_SCOPE]
    assert request_scope(("orders:read",), listed) == "orders:read offline_access"
    # Named by the caller, it is still sent once, and only when the issuer lists it.
    assert request_scope(("orders:read", "offline_access"), listed) == "orders:read offline_access"
    assert request_scope(("orders:read", "offline_access"), None) == "orders:read"
    with pytest.raises(AuthorizationError):
        request_scope(("offline_access",), listed)

    def built(scopes_supported: list[str] | None) -> Any:
        return build_direct_sign_in_request(
            authorization_endpoint=f"{SHOP}/oauth/authorize",
            issuer=SHOP,
            client_id="https://atlas.example/client.json",
            redirect_uri="https://atlas.example/oauth/callback",
            scopes=("orders:read",),
            scopes_supported=scopes_supported,
        )

    for scopes_supported, sent in ((listed, "orders:read offline_access"), (None, "orders:read")):
        request = built(scopes_supported)
        query = parse_qs(urlsplit(request.authorization_url.get_secret_value()).query)
        assert query["scope"] == [sent]
        assert parse_qs(request.parameters.get_secret_value())["scope"] == [sent]  # pushed too
        assert request.scopes == ("orders:read",)

    def response(scope: str | None) -> TokenResponse:
        return TokenResponse(access_token=SecretStr("at"), token_type="Bearer", scope=scope)  # noqa: S106

    # It is none of the scopes granted, and alone it is a decline (§4.7).
    token = AccessToken.from_response(response("orders:read offline_access"))
    assert token.scopes == ("orders:read",)
    for declined in ("offline_access", "", " "):
        with pytest.raises(ProtocolValidationError):
            AccessToken.from_response(response(declined))
    left_out = AccessToken.from_response(response(None), requested_scopes=("orders:read",))
    assert left_out.scopes == ("orders:read",)
    metadata = {
        "issuer": SHOP,
        "token_endpoint": f"{SHOP}/oauth/token",
        "revocation_endpoint": f"{SHOP}/oauth/revoke",
        "grant_types_supported": ["refresh_token"],
        "protected_resources": [SHOP],
    }
    assert not OAuthServerMetadata.model_validate(metadata).lists_offline_access
    assert OAuthServerMetadata.model_validate(
        {**metadata, "scopes_supported": listed}
    ).lists_offline_access


@pytest.mark.asyncio
async def test_a_company_whose_refresh_tokens_need_offline_access() -> None:
    """It lists the scope in its issuer's metadata and nowhere else; a sign-in that asks
    for it gets a refresh token, one that doesn't gets an access token alone."""

    world = World()
    _serving(world, replace(CONFIG, offline_access=True))
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None and metadata.lists_offline_access
    # Not a scope a Personal Agent requests for account access, nor one a resource lists.
    assert OFFLINE_ACCESS_SCOPE not in world.company.scopes_supported
    assert world.company.resource_metadata is not None
    assert OFFLINE_ACCESS_SCOPE not in world.company.resource_metadata.scopes_supported
    assert OFFLINE_ACCESS_SCOPE not in world.shop.protected_resource_metadata()["scopes_supported"]
    assert "offline_access" not in world.company.document.model_dump_json()

    sent = _spy(world)
    done = await _device_sign_in(world, session, scopes_supported=metadata.scopes_supported)
    assert _form(sent[0])["scope"] == "orders:read orders:write offline_access"
    assert done.status == "complete" and done.refresh_token_reference is not None
    assert done.granted_scopes == ("orders:read", "orders:write") and done.missing_scopes == ()
    assert done.token.scopes == ("orders:read", "orders:write")
    # The sign-in is kept with the account scopes only.
    grants = await world.shop.store.records("refresh_token")
    assert grants and all(OFFLINE_ACCESS_SCOPE not in grant.value["scopes"] for grant in grants)

    # A narrowed refresh names it too, and the scopes granted leave it out.
    context = replace(world.account_context(), scopes_supported=tuple(metadata.scopes_supported))
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    sent.clear()
    narrowed = await accounts.refresh(
        done.refresh_token_reference, context=context, scopes=("orders:read",)
    )
    assert _form(sent[0])["scope"] == "orders:read offline_access"
    assert narrowed.status == "signed_in" and narrowed.rotated
    assert narrowed.granted_scopes == ("orders:read",) and narrowed.missing_scopes == ()
    # A refresh that names no scope sends none.
    sent.clear()
    whole = await accounts.refresh(done.refresh_token_reference, context=context)
    assert "scope" not in _form(sent[0])
    assert whole.granted_scopes == ("orders:read", "orders:write")

    # An agent that leaves it out gets no refresh token: Device Sign-In fails for it.
    with pytest.raises(AuthorizationError) as raised:
        await _device_sign_in(world, session)
    assert raised.value.code == "missing_refresh_token"
    # `offline_access` alone asks for no account access: no sign-in starts (§4.7).
    form = {
        "scope": OFFLINE_ACCESS_SCOPE,
        **await SessionClient(reactor=world.reactor, http_client=world.http).client_authentication(
            client_id=world.atlas.client_id, issuer=SHOP
        ),
    }
    refused = await world.http.post(str(metadata.device_authorization_endpoint), data=form)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_scope")


@pytest.mark.asyncio
async def test_offline_access_in_a_pushed_request_a_mediated_sign_in_and_no_challenge() -> None:
    world, browser = _recording_world(
        replace(CONFIG, offline_access=True, pushed_authorization_requests="required")
    )
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    sent = _spy(world)
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    started = await client.begin(
        **_direct_arguments(
            world,
            pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
            require_pushed_authorization_requests=True,
            scopes_supported=metadata.scopes_supported,
        )
    )
    pushed = next(request for request in sent if request.url.path == "/oauth/par")
    assert _form(pushed)["scope"] == "orders:read offline_access"
    assert started.requested_scopes == ("orders:read",)
    # The consent page shows the account scope, and nothing about a refresh token.
    assert "offline_access" not in browser.pages[-1]
    shown = await world.shop.authorization_request(str(browser.request_id))
    assert [entry["scope"] for entry in shown["scopes"]] == ["orders:read"]
    callback = await world.shop.approve_authorization(
        str(browser.request_id), account_id="acct_ada"
    )
    done = await client.complete(callback)
    assert done.refresh_token_reference is not None
    assert done.granted_scopes == ("orders:read",) and done.missing_scopes == ()

    # Mediated Sign-In is a sign-in request too.
    mediated_world = World(dict(ADA))
    _serving(mediated_world, replace(CONFIG, offline_access=True))
    await mediated_world.signed_out_session()
    sent = _spy(mediated_world)
    await MediatedSignInClient(
        reactor=mediated_world.reactor, http_client=mediated_world.http
    ).sign_in(
        company=mediated_world.company,
        client_id=mediated_world.atlas.client_id,
        scopes=("orders:read",),
        tenant_id=TENANT,
    )
    grant = next(request for request in sent if request.url.path == "/oauth/token")
    assert _form(grant)["scope"] == "orders:read offline_access"

    # A resource never names it in a challenge, nor the Company Agent in an
    # `authorization` event: a refresh token isn't something a resource requires.
    challenged = await world.transport.request("GET", f"{SHOP}/api/orders", session=session)
    assert challenged.status_code == 401
    assert "offline_access" not in challenged.headers["www-authenticate"]
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), session=session, wait=0
    )
    asked = [event for event in page.events if event.type == "authorization"]
    assert asked and all(OFFLINE_ACCESS_SCOPE not in (event.scope or "") for event in asked)


@pytest.mark.asyncio
async def test_offline_access_is_an_unknown_scope_where_refresh_tokens_need_none() -> None:
    world = World()
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None and not metadata.lists_offline_access
    sent = _spy(world)
    # The agent reads the issuer's metadata: nothing listed, nothing added.
    done = await _device_sign_in(world, session, scopes_supported=metadata.scopes_supported)
    assert _form(sent[0])["scope"] == "orders:read orders:write"
    assert done.refresh_token_reference is not None
    form = {
        "scope": "orders:read offline_access",
        **await SessionClient(reactor=world.reactor, http_client=world.http).client_authentication(
            client_id=world.atlas.client_id, issuer=SHOP
        ),
    }
    refused = await world.http.post(str(metadata.device_authorization_endpoint), data=form)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_scope")


# Operator signatures at the authorization server (§5.3) -----------------------------------

AGENT = "https://atlas.example/operator-keys.json"


def test_an_operator_signature_covers_the_session_header_or_the_content_digest() -> None:
    digest = content_digest(b"grant_type=refresh_token")
    assert digest.startswith("sha-256=:") and digest.endswith(":")
    who = {"method": "POST", "url": f"{SHOP}/oauth/token", "tenant_id": TENANT}
    OperatorSignatureRequest(**who, content_digest=digest)
    OperatorSignatureRequest(**who, session_jwt=SecretStr("a.b.c"))
    for neither_or_both in ({}, {"content_digest": digest, "session_jwt": SecretStr("a.b.c")}):
        with pytest.raises(ValueError):
            OperatorSignatureRequest(**who, **neither_or_both)
    with pytest.raises(ValueError):
        OperatorSignatureRequest(**who, content_digest=digest, authorization=SecretStr("Bearer x"))
    assert '"content-digest"' in accept_signature({}, oauth=True)
    assert '"poppy-session"' not in accept_signature({"authorization": "x"}, oauth=True)
    assert '"poppy-session"' in accept_signature({})


@pytest.mark.asyncio
async def test_a_signature_over_the_content_digest_binds_the_body() -> None:
    world = World()
    now = world.clock.now()
    stamp = int(now.timestamp())
    key = new_operator_key()
    url = f"{SHOP}/oauth/token"
    body = b"grant_type=refresh_token&client_assertion=a.b.c"
    fetched: list[str] = []

    async def keys(agent: str, keyid: str) -> list[dict[str, Any]]:
        fetched.append(agent)
        return list(operator_directory([key])["keys"])

    async def signed(content: bytes, **options: Any) -> dict[str, str]:
        digest = content_digest(content)
        signature = await sign_operator_request(
            OperatorSignatureRequest(
                method="POST", url=url, tenant_id=TENANT, content_digest=digest
            ),
            key,
            signature_agent=AGENT,
            created=stamp,
            expires=stamp + 60,
            nonce="nonce",
            **options,
        )
        return {
            "content-digest": digest,
            "signature-agent": signature.signature_agent,
            "signature-input": signature.signature_input,
            "signature": signature.signature,
        }

    async def verdict(headers: dict[str, str], content: bytes | None = body, **more: Any) -> str:
        outcome = await verify_operator_signature(
            method="POST", url=url, headers=headers, keys=keys, now=now, content=content, **more
        )
        return outcome.outcome

    good = await signed(body)
    assert '"content-digest"' in good["signature-input"]
    assert await verdict(good) == "verified"
    # Another body than the one signed: the client assertion in it is not the one bound.
    assert await verdict(good, b"grant_type=refresh_token&client_assertion=x.y.z") == "invalid"
    # A digest of the new body under the old signature fails the signature.
    swapped = {**good, "content-digest": content_digest(b"other")}
    assert await verdict(swapped, b"other") == "invalid"
    # Without the digest covered, nothing binds the body.
    bare = await signed(body, components=("@authority", "signature-agent", "@method", "@path"))
    assert await verdict(bare) == "invalid"
    assert await verdict({**good, "content-digest": "md5=:AAAA:"}) == "invalid"
    assert (
        await verdict({name: value for name, value in good.items() if name != "content-digest"})
        == "invalid"
    )
    # At a resource it would have to cover the Session header instead.
    assert await verdict(good, None) == "invalid"
    assert await verdict({}) == "absent"

    # An operator the company doesn't know: `unverified`, and its directory is never read.
    fetched.clear()

    async def unknown(agent: str) -> bool:
        return False

    assert await verdict(good, trusts=unknown) == "unverified"
    assert fetched == []

    async def known(agent: str) -> bool:
        return agent == AGENT

    assert await verdict(good, trusts=known) == "verified" and fetched == [AGENT]


def _signing(world: World) -> None:
    """Atlas signs as its operator, with the key its website publishes."""

    world.host.operator_signer = WebBotAuthSigner(
        world.atlas.operator_key, signature_agent=world.atlas.operator_url, now=world.clock.now
    )
    world.reactor = personal_agent_reactor(
        world.host, network=world.network, http_client=world.http
    )
    world.transport = SessionHttpClient(reactor=world.reactor, http_client=world.http)


@pytest.mark.asyncio
async def test_the_agent_signs_its_requests_to_the_four_oauth_endpoints() -> None:
    world, browser = _recording_world(replace(CONFIG, pushed_authorization_requests="offered"))
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    sent = _spy(world)
    # No operator signer: nothing is signed, and no digest is added.
    await _device_sign_in(world, session)
    assert all("signature" not in request.headers for request in sent)
    assert all("content-digest" not in request.headers for request in sent)

    _signing(world)
    sent.clear()
    done = await _device_sign_in(world, session)
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    await client.begin(
        **_direct_arguments(
            world,
            pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
        )
    )
    callback = await world.shop.approve_authorization(
        str(browser.request_id), account_id="acct_ada"
    )
    await client.complete(callback)
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    await accounts.refresh(done.refresh_token_reference, context=world.account_context())
    await accounts.revoke(done.refresh_token_reference, context=world.account_context())
    paths = {"/oauth/device", "/oauth/token", "/oauth/par", "/oauth/revoke"}
    oauth = [request for request in sent if request.url.path in paths]
    assert {request.url.path for request in oauth} == paths
    for request in oauth:
        # Every one of them, each with its own signature over its own body.
        assert request.headers["content-digest"] == content_digest(request.content)
        assert '"content-digest"' in request.headers["signature-input"]
        assert '"poppy-session"' not in request.headers["signature-input"]
        assert "poppy-session" not in request.headers
        verdict = await verify_operator_signature(
            method="POST",
            url=str(request.url),
            headers={name.lower(): value for name, value in request.headers.items()},
            keys=_directory(world),
            now=world.clock.now(),
            content=request.content,
        )
        assert (verdict.outcome, verdict.operator) == ("verified", world.atlas.operator_url)
    assert len({request.headers["signature"] for request in oauth}) == len(oauth)


def _directory(world: World) -> Any:
    async def keys(agent: str, keyid: str) -> list[dict[str, Any]]:
        assert agent == world.atlas.operator_url
        return list(operator_directory([world.atlas.operator_key])["keys"])

    return keys


class _Policy:
    def __init__(self, policy: object) -> None:
        self.policy = policy

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(CLIENT_POLICIES, self.policy, contribution_id="test", order=1)


def _with_policy(world: World, policy: object) -> None:
    world.shop.reactor.register_plugin(
        PluginManifest(name="test-policy", version="1"), _Policy(policy)
    )


@pytest.mark.asyncio
async def test_the_policy_that_accepts_the_agents_a_verified_operator_speaks_for() -> None:
    operator = "https://atlas.example/operator-keys.json"
    atlas, other = "https://atlas.example/client.json", "https://other.example/client.json"
    policy = OperatorVerifiedAgents(
        agents=["https://known.example/client.json"],
        operators={operator: None, "https://edge.example/keys": [other]},
        blocked=["https://atlas.example/blocked.json"],
    )
    assert await policy.allows("https://known.example/client.json")
    assert not await policy.allows(atlas)
    # Every `client_id` on the host of the operator's directory, or the ones named.
    assert await policy.allows_operator(atlas, operator)
    assert not await policy.allows_operator(other, operator)
    assert not await policy.allows_operator("https://atlas.example.evil.example/c.json", operator)
    assert await policy.allows_operator(other, "https://edge.example/keys")
    assert not await policy.allows_operator(atlas, "https://edge.example/keys")
    assert not await policy.allows_operator(atlas, "https://unknown.example/keys")
    # A blocked `client_id` is refused whatever speaks for it.
    assert not await policy.allows_operator("https://atlas.example/blocked.json", operator)
    with pytest.raises(ValueError):
        OperatorVerifiedAgents(operators={"http://atlas.example/keys": None})


@pytest.mark.asyncio
async def test_a_company_accepts_an_agent_by_its_verified_operator_signature() -> None:
    """Beside its allowlist, with PAR required so it decides before its sign-in page is
    shown; the client assertion and the Session JWT are verified all the same."""

    world, browser = _recording_world(replace(CONFIG, pushed_authorization_requests="required"))
    _with_policy(world, OperatorVerifiedAgents(operators={world.atlas.operator_url: None}))
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    tasks = f"{SHOP}/poppy/tasks"
    arguments = _direct_arguments(
        world,
        pushed_authorization_request_endpoint=metadata.pushed_authorization_request_endpoint,
        require_pushed_authorization_requests=True,
    )

    # Not on the allowlist, and nothing signed: refused everywhere.
    with pytest.raises(AuthorizationError) as raised:
        await _device_sign_in(world, session)
    assert raised.value.code == "invalid_client"
    with pytest.raises(AuthorizationError) as raised:
        await DirectSignInClient(reactor=world.reactor, http_client=world.http).begin(**arguments)
    assert raised.value.code == "invalid_client"
    refused = await world.transport.request("GET", tasks, session=session)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_session")

    # Signed by the operator the company trusts: accepted at each endpoint.
    _signing(world)
    served = await world.transport.request("GET", tasks, session=session)
    assert served.status_code == 200
    done = await _device_sign_in(world, session)
    assert done.status == "complete" and done.refresh_token_reference is not None
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    await client.begin(**arguments)
    # The browser's request has no signature: the push was decided on, and its page shows.
    assert browser.request_id is not None and 'name="request_id"' in browser.pages[-1]
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")
    assert (await client.complete(callback)).refresh_token_reference is not None
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    refreshed = await accounts.refresh(
        done.refresh_token_reference, context=world.account_context()
    )
    assert refreshed.status == "signed_in" and refreshed.token is not None
    orders = await world.transport.request(
        "GET", f"{SHOP}/api/orders", session=session, token=refreshed.token
    )
    assert orders.status_code == 200

    # The signature doesn't replace the client assertion: a forged one is still refused.
    form = {
        "scope": "orders:read",
        "client_id": world.atlas.client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": "forged.assertion.value",
    }
    forged = world.http.build_request(
        "POST", str(metadata.device_authorization_endpoint), data=form
    )
    from personal_agent_protocol import sign_oauth_request

    await sign_oauth_request(world.reactor, forged, tenant_id=TENANT)
    answer = await world.http.send(forged)
    assert answer.status_code in {400, 401} and answer.json()["error"] == "invalid_client"

    # A body changed after signing: the signature no longer speaks for the request.
    genuine = {
        "scope": "orders:read",
        **await SessionClient(reactor=world.reactor, http_client=world.http).client_authentication(
            client_id=world.atlas.client_id, issuer=SHOP
        ),
    }
    request = world.http.build_request(
        "POST", str(metadata.device_authorization_endpoint), data=genuine
    )
    await sign_oauth_request(world.reactor, request, tenant_id=TENANT)
    tampered = world.http.build_request(
        "POST",
        str(metadata.device_authorization_endpoint),
        data={**genuine, "scope": "orders:read orders:write"},
        headers={
            name: request.headers[name]
            for name in ("content-digest", "signature", "signature-input", "signature-agent")
        },
    )
    answer = await world.http.send(tampered)
    assert (answer.status_code, answer.json()["error"]) == (401, "invalid_client")


@pytest.mark.asyncio
async def test_an_operator_the_company_does_not_trust_accepts_no_one() -> None:
    world, _ = _recording_world()
    fetched: list[str] = []
    original = world.network.client

    policy = OperatorVerifiedAgents(operators={"https://edge.example/keys": None})
    _with_policy(world, policy)
    asked: list[tuple[str, str]] = []
    decide = policy.allows_operator

    async def allows_operator(client_id: str, operator: str) -> bool:
        asked.append((client_id, operator))
        return await decide(client_id, operator)

    policy.allows_operator = allows_operator  # type: ignore[method-assign]
    del fetched, original
    _signing(world)
    session = await world.signed_out_session()
    refused = await world.transport.request("GET", f"{SHOP}/poppy/tasks", session=session)
    assert (refused.status_code, refused.json()["error"]) == (400, "invalid_session")
    # Asked once for the request, with the signature's own Signature-Agent.
    assert asked == [(world.atlas.client_id, world.atlas.operator_url)]
    # The allowlist stays beside it: an allowed agent needs no signature.
    world2, _ = _recording_world()
    _with_policy(world2, OperatorVerifiedAgents(agents=[world2.atlas.client_id]))
    served = await world2.transport.request(
        "GET", f"{SHOP}/poppy/tasks", session=await world2.signed_out_session()
    )
    assert served.status_code == 200


# Replacing a User ID (§5.1) ---------------------------------------------------------------

WHO = {
    "tenant_id": TENANT,
    "local_user_id": "user-ada",
    "company_issuer": SHOP,
}


@pytest.mark.asyncio
async def test_the_store_replaces_one_users_id_and_remembers_when_it_was_used(
    tmp_path: Path,
) -> None:
    store = SqlitePairwiseUserIdStore(tmp_path / "pairwise.sqlite3")
    first = await store.get_or_create(**WHO)
    other = await store.get_or_create(**{**WHO, "local_user_id": "user-bo"})
    assert await store.last_used(**WHO) is None
    world = World()
    now = world.clock.now()
    await store.mark_used(**WHO, at=now)
    await store.mark_used(**WHO, at=now - timedelta(days=3))  # never backwards
    assert await store.last_used(**WHO) == now
    with pytest.raises(ValueError):
        await store.mark_used(**WHO, at=now.replace(tzinfo=None))
    replaced = await store.replace(**WHO)
    assert replaced != first and replaced.startswith("usr_")
    assert await store.get_or_create(**WHO) == replaced
    assert await store.last_used(**WHO) is None
    # Only that User, only at that Company.
    assert await store.get_or_create(**{**WHO, "local_user_id": "user-bo"}) == other
    assert await store.last_used(**{**WHO, "local_user_id": "nobody"}) is None

    # A database made before 1.1.0 gains the column, its IDs kept.
    old = tmp_path / "old.sqlite3"
    with closing(sqlite3.connect(old)) as connection, connection as database:
        database.execute(
            "CREATE TABLE pap_pairwise_user_ids (tenant_id TEXT NOT NULL, local_user_id TEXT "
            "NOT NULL, company_issuer TEXT NOT NULL, pairwise_user_id TEXT NOT NULL UNIQUE, "
            "PRIMARY KEY (tenant_id, local_user_id, company_issuer))"
        )
        database.execute(
            "INSERT INTO pap_pairwise_user_ids VALUES (?, ?, ?, ?)", (*WHO.values(), "usr_old")
        )
    upgraded = SqlitePairwiseUserIdStore(old)
    assert await upgraded.get_or_create(**WHO) == "usr_old"
    await upgraded.mark_used(**WHO, at=now)
    assert await upgraded.last_used(**WHO) == now


@pytest.mark.asyncio
async def test_a_keyed_hash_replaces_one_users_id_with_a_counter(tmp_path: Path) -> None:
    key = bytes(range(32))
    first = derive_pairwise_user_id(key, **WHO)
    assert first == derive_pairwise_user_id(key, **WHO) and first.startswith("usr_")
    assert len(first) == 4 + 43
    different = [
        derive_pairwise_user_id(key, **WHO, counter=1),
        derive_pairwise_user_id(bytes(range(1, 33)), **WHO),
        derive_pairwise_user_id(key, **{**WHO, "local_user_id": "user-bo"}),
        derive_pairwise_user_id(key, **{**WHO, "company_issuer": "https://other.example"}),
        derive_pairwise_user_id(key, **{**WHO, "tenant_id": "another"}),
        # No two inputs share their bytes.
        derive_pairwise_user_id(
            key, **{**WHO, "tenant_id": TENANT + "u", "local_user_id": "ser-ada"}
        ),
    ]
    assert len({first, *different}) == 7
    for bad in ({"key": b"short"}, {"counter": -1}, {"counter": True}):
        with pytest.raises(ValueError):
            derive_pairwise_user_id(**{"key": key, **WHO, **bad})  # type: ignore[arg-type]

    counters = SqlitePairwiseCounters(tmp_path / "counters.sqlite3")
    ids = DerivedPairwiseUserIds(key, counters=counters)
    assert await ids.get_or_create(**WHO) == first
    replaced = await ids.replace(**WHO)
    assert replaced == derive_pairwise_user_id(key, **WHO, counter=1) != first
    # Durable: another process over the same counters derives the new ID.
    again = DerivedPairwiseUserIds(
        key, counters=SqlitePairwiseCounters(tmp_path / "counters.sqlite3")
    )
    assert await again.get_or_create(**WHO) == replaced
    assert await ids.get_or_create(**{**WHO, "local_user_id": "user-bo"}) == different[2]
    with pytest.raises(ValueError):
        DerivedPairwiseUserIds(b"short", counters=counters)
    with pytest.raises(ValueError):
        SqlitePairwiseCounters(":memory:")


def test_an_unused_id_ages_out_after_28_days_and_never_with_a_refresh_token() -> None:
    world = World()
    now = world.clock.now()
    assert USER_ID_UNUSED_AFTER == timedelta(days=28)

    def may(days: float, held: bool = False) -> bool:
        return may_replace_unused(
            last_used=now - timedelta(days=days), now=now, holds_refresh_token=held
        )

    assert may(28) and may(400)
    assert not may(27.99) and not may(0)
    assert not may(28, held=True) and not may(4000, held=True)


class _HostData:
    """The host's side of a replacement: what it held under the old ID."""

    def __init__(self, calls: list[str], *, busy: bool = False, fails: bool = False) -> None:
        self.calls, self.busy, self.fails = calls, busy, fails
        self.discarded: list[UserIdAtCompany] = []

    async def in_use(self, user: UserIdAtCompany) -> bool:
        self.calls.append("in_use")
        return self.busy

    async def discard(self, user: UserIdAtCompany) -> None:
        self.calls.append("discard")
        if self.fails:
            raise RuntimeError("the browser profile could not be cleared")
        self.discarded.append(user)


class _Store:
    def __init__(self, store: SqlitePairwiseUserIdStore, calls: list[str]) -> None:
        self.store, self.calls = store, calls

    async def get_or_create(self, **who: str) -> str:
        return await self.store.get_or_create(**who)

    async def replace(self, **who: str) -> str:
        self.calls.append("replace")
        return await self.store.replace(**who)


class _StorePlugin:
    def __init__(self, store: object) -> None:
        self.store = store

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(PAIRWISE_USER_ID_STORES, self.store, contribution_id="test")


async def _replaceable(world: World, tmp_path: Path, calls: list[str]) -> tuple[str, Any]:
    """Ada's ID at Manzanita in a store that can replace it, contributed to the agent."""

    store = _Store(SqlitePairwiseUserIdStore(tmp_path / "ids.sqlite3"), calls)
    world.reactor.register_plugin(PluginManifest(name="ids", version="1"), _StorePlugin(store))
    return await store.get_or_create(**WHO), store


@pytest.mark.asyncio
async def test_replacing_a_user_id_signs_out_first_and_discards_what_the_old_one_held(
    tmp_path: Path,
) -> None:
    world = World()
    calls: list[str] = []
    old, store = await _replaceable(world, tmp_path, calls)
    session = await _session(world, sub=old)
    done = await _device_sign_in(world, session, pairwise_user_id=old)
    reference = done.refresh_token_reference
    # Keys the old ID holds: its delegated key (made by the Session JWT) and its DPoP key.
    who = {"tenant_id": TENANT, "issuer": SHOP, "sub": old}
    await world.host.dpop_keys.key_for(**who)
    await world.transport.request("GET", f"{SHOP}/poppy/tasks", session=session)
    assert await world.host.delegated_keys.current(**who) is not None
    assert len(world.host.dpop_keys) == 1
    user = UserIdAtCompany(
        tenant_id=TENANT, local_user_id="user-ada", company=SHOP, pairwise_user_id=old
    )
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    sent = _spy(world)
    data = _HostData(calls)

    replaced = await replace_user_id(
        world.reactor,
        user=user,
        data=data,
        dpop_keys=world.host.dpop_keys,
        delegated_keys=world.host.delegated_keys,
        reason="user_request",
        refresh_token_references=[reference, reference],
        accounts=accounts,
        context=world.account_context(),
    )
    # Between tasks, the sign-out, then the old ID's things, and the new ID last.
    assert calls == ["in_use", "discard", "replace"]
    assert [request.url.path for request in sent] == ["/oauth/revoke"]
    assert (replaced.signed_out, replaced.revoked) == (True, 1)
    assert replaced.pairwise_user_id != old
    assert replaced.pairwise_user_id == await store.get_or_create(**WHO)
    assert await world.host.vault.get(reference) is None
    assert len(world.host.dpop_keys) == 0 and len(world.host.delegated_keys) == 0
    assert data.discarded == [user]
    # The Company signed the account out, and sees a new User: nothing links the two.
    after = await accounts.refresh(reference, context=world.account_context())
    assert after.status == "signed_out"
    fresh = await _session(world, sub=replaced.pairwise_user_id)
    served = await world.transport.request("GET", f"{SHOP}/poppy/tasks", session=fresh)
    assert served.status_code == 200
    assert fresh.sid != session.sid and fresh.sub != session.sub
    new_key = await world.host.delegated_keys.current(
        tenant_id=TENANT, issuer=SHOP, sub=replaced.pairwise_user_id
    )
    assert new_key is not None


@pytest.mark.asyncio
async def test_what_stops_a_replacement_leaves_the_old_id_in_place(tmp_path: Path) -> None:
    world = World()
    calls: list[str] = []
    old, store = await _replaceable(world, tmp_path, calls)
    session = await _session(world, sub=old)
    done = await _device_sign_in(world, session, pairwise_user_id=old)
    reference = str(done.refresh_token_reference)
    user = UserIdAtCompany(
        tenant_id=TENANT, local_user_id="user-ada", company=SHOP, pairwise_user_id=old
    )
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    now = world.clock.now()

    async def replace_it(**more: Any) -> Any:
        arguments: dict[str, Any] = {
            "user": user,
            "data": _HostData(calls),
            "dpop_keys": world.host.dpop_keys,
            "delegated_keys": world.host.delegated_keys,
            "reason": "user_request",
            "refresh_token_references": [reference],
            "accounts": accounts,
            "context": world.account_context(),
            **more,
        }
        return await replace_user_id(world.reactor, **arguments)

    async def unchanged() -> None:
        assert await store.get_or_create(**WHO) == old
        assert await world.host.vault.get(reference) is not None
        assert "replace" not in calls and "discard" not in calls

    # In the middle of a task.
    with pytest.raises(UserIdError) as raised:
        await replace_it(data=_HostData(calls, busy=True))
    assert raised.value.code == "user_id_in_use"
    await unchanged()
    # On its own, never while it holds a refresh token, however long the ID went unused.
    with pytest.raises(UserIdError) as raised:
        await replace_it(reason="unused", last_used=now - timedelta(days=4000))
    assert raised.value.code == "refresh_token_held"
    with pytest.raises(ValueError):
        await replace_it(reason="unused")
    with pytest.raises(ValueError):
        await replace_it(reason="whenever")
    # A refresh token is held: signing out needs the client and where to revoke.
    with pytest.raises(ValueError):
        await replace_it(accounts=None)
    await unchanged()
    # The Company doesn't acknowledge the sign-out: the account would link the two IDs.
    with pytest.raises(UserIdError) as raised:
        await replace_it(
            context=replace(world.account_context(), revocation_endpoint=f"{SHOP}/nowhere")
        )
    assert raised.value.code == "sign_out_failed"
    await unchanged()

    # Signed out, the 28 days apply.
    await accounts.sign_out([reference], context=world.account_context())
    with pytest.raises(UserIdError) as raised:
        await replace_it(reason="unused", last_used=now - timedelta(days=27))
    assert raised.value.code == "user_id_recently_used"
    assert await store.get_or_create(**WHO) == old
    # What the host can't discard stops it too, before the ID changes.
    with pytest.raises(RuntimeError):
        await replace_it(
            reason="unused", last_used=now - timedelta(days=28), data=_HostData(calls, fails=True)
        )
    assert await store.get_or_create(**WHO) == old
    calls.clear()
    aged = await replace_it(reason="unused", last_used=now - timedelta(days=28))
    assert (aged.signed_out, aged.revoked) == (False, 0) and aged.pairwise_user_id != old
    assert calls == ["in_use", "discard", "replace"]

    # A store that can't replace an ID is refused before anything is done.
    plain = World()

    class GetOnly:
        async def get_or_create(self, **who: str) -> str:
            return "usr_fixed"

    plain.reactor.register_plugin(PluginManifest(name="ids", version="1"), _StorePlugin(GetOnly()))
    with pytest.raises(TypeError):
        await replace_user_id(
            plain.reactor,
            user=user,
            data=_HostData([]),
            dpop_keys=plain.host.dpop_keys,
            delegated_keys=plain.host.delegated_keys,
            reason="user_request",
        )


@pytest.mark.asyncio
async def test_a_company_limits_new_user_ids_by_client_id_and_links_none_to_an_account() -> None:
    world = World()
    _serving(
        world,
        replace(CONFIG, new_user_ids_per_client=2, new_user_id_window=timedelta(minutes=10)),
    )
    tasks = f"{SHOP}/poppy/tasks"

    async def get(sub: str) -> httpx.Response:
        session = await _session(world, sub=sub)
        signed = await session_headers(world.reactor, "GET", tasks, session=session, token=None)
        return await world.http.get(tasks, headers=signed)

    assert (await get("usr_one_0000000000000000")).status_code == 200
    assert (await get("usr_two_0000000000000000")).status_code == 200
    limited = await get("usr_three_00000000000000")
    assert limited.status_code == 429 and limited.content == b""
    assert 0 < int(limited.headers["retry-after"]) <= 600
    # A User ID it has seen is served, in a new Session too: only new ones are counted.
    assert (await get("usr_one_0000000000000000")).status_code == 200
    assert len(world.shop.store.keys(USER_ID)) == 2  # type: ignore[attr-defined]
    # A forged Session JWT counts against no one.
    forged = await world.http.get(tasks, headers={"Poppy-Session": "a.b.c", "Poppy-Version": "1.1"})
    assert forged.status_code == 400
    world.clock.advance(601)
    assert (await get("usr_three_00000000000000")).status_code == 200
    with pytest.raises(ValueError):
        replace(CONFIG, new_user_ids_per_client=0)

    # One account under two User IDs: a replaced ID is a new User, signed in again.
    world = World()
    for sub in ("usr_before_0000000000000", "usr_after_00000000000000"):
        session = await _session(world, sub=sub)
        done = await _device_sign_in(world, session)
        orders = await world.transport.request(
            "GET", f"{SHOP}/api/orders", session=session, token=done.token
        )
        assert orders.status_code == 200


# Listed tasks in feedback (§9, §9.3) -------------------------------------------------------


def test_listed_tasks_as_a_personal_agent_reads_them() -> None:
    endpoint = {"endpoint": FEEDBACK_URL}
    assert FeedbackDescriptor.model_validate(endpoint).tasks == []
    listed = FeedbackDescriptor.model_validate({**endpoint, "tasks": list(LISTED)}).tasks
    assert listed == [ListedTask(**LISTED[0]), ListedTask(**LISTED[1])]
    # More than 50: the first 50. Two with one ID: the first.
    many = [{"id": f"task-{n}", "task": f"Task {n}"} for n in range(60)]
    assert [
        task.id for task in FeedbackDescriptor.model_validate({**endpoint, "tasks": many}).tasks
    ] == [f"task-{n}" for n in range(50)]
    twice = [*LISTED, {"id": "installments", "task": "Something else"}]
    again = FeedbackDescriptor.model_validate({**endpoint, "tasks": twice}).tasks
    assert [task.task for task in again] == ["Pay in installments", LISTED[1]["task"]]
    for bad in (
        {"id": "Installments", "task": "x"},
        {"id": "a b", "task": "x"},
        {"id": "x" * 65, "task": "x"},
        {"id": "", "task": "x"},
        {"id": "ok", "task": ""},
        {"id": "ok", "task": "x" * 201},
        {"id": "ok"},
    ):
        with pytest.raises(ValueError):
            FeedbackDescriptor.model_validate({**endpoint, "tasks": [bad]})
    assert TasksResponse.model_validate({"feedback": {**endpoint, "tasks": list(LISTED)}}).feedback

    # A report has one form or the other.
    assert FeedbackReport.listed("installments", "split-payment").body() == {
        "task_ids": ["installments", "split-payment"]
    }
    assert FeedbackReport(task="Pay", description="Why").body() == {
        "task": "Pay",
        "description": "Why",
    }
    for bad_report in (
        {},
        {"task": "Pay"},
        {"description": "Why"},
        {"task_ids": []},
        {"task_ids": ["installments", "installments"]},
        {"task_ids": ["Not An ID"]},
        {"task_ids": ["installments"], "task": "Pay", "description": "Why"},
        {"task_ids": ["installments"], "task": "Pay"},
    ):
        with pytest.raises(ValueError):
            FeedbackReport(**bad_report)  # type: ignore[arg-type]


def test_what_a_company_may_list() -> None:
    config = replace(CONFIG, feedback_tasks=LISTED)
    assert config.feedback_tasks == LISTED
    fifty = tuple({"id": f"task-{n}", "task": f"Task {n}"} for n in range(50))
    replace(CONFIG, feedback_tasks=fifty)
    for bad in (
        (*fifty, {"id": "one-more", "task": "One more"}),
        ({"id": "Installments", "task": "Pay in installments"},),
        ({"id": "x" * 65, "task": "Pay in installments"},),
        ({"id": "installments", "task": ""},),
        ({"id": "installments", "task": "x" * 201},),
        ({"id": "installments"},),
        ({"id": "installments", "task": "Pay in installments", "more": "x"},),
        (LISTED[0], {"id": "installments", "task": "Another"}),
        # Never also excluded (§9.1), nor answered with an alternative (§9.2).
        ({"id": "resize", "task": "change the size of an item after it has shipped"},),
        ({"id": "gift-card", "task": "Pay with a gift card"},),
    ):
        with pytest.raises(ValueError):
            replace(CONFIG, feedback_tasks=bad)
    with pytest.raises(ValueError):
        replace(CONFIG, feedback_tasks=LISTED, feedback=False)


@pytest.mark.asyncio
async def test_a_listed_task_is_reported_by_its_id() -> None:
    world = World()
    _serving(world, replace(CONFIG, feedback_tasks=LISTED))
    session = await _session(world)
    tasks = await TasksClient(transport=world.transport).get(world.company, session=session)
    assert [(task.id, task.task) for task in tasks.listed_tasks] == [
        (LISTED[0]["id"], LISTED[0]["task"]),
        (LISTED[1]["id"], LISTED[1]["task"]),
    ]
    # Never both listed and excluded.
    assert not {task.task for task in tasks.listed_tasks} & {
        task.task for task in tasks.excluded_tasks
    }
    feedback = FeedbackClient(transport=world.transport)
    endpoint = str(tasks.feedback_endpoint)
    # Several in one report, an ID the company no longer lists among them: 202.
    answered = await feedback.report(
        endpoint, FeedbackReport.listed("installments", "split-payment", "gone"), session=session
    )
    assert answered is None
    assert (
        await feedback.report(endpoint, FeedbackReport.listed("installments"), session=session)
        is None
    )
    assert (
        await feedback.report(endpoint, FeedbackReport.listed("only-unknown"), session=session)
        is None
    )
    assert await world.shop.feedback_task_counts() == {"installments": 2, "split-payment": 1}
    reports = await world.shop.feedback_reports()
    assert sorted(report.task_ids for report in reports) == [
        ("installments",),
        ("installments", "split-payment"),
    ]
    assert all(report.task is None and report.description is None for report in reports)
    # Free text still works beside it, and still gets its alternative.
    alternative = await feedback.report(
        endpoint,
        FeedbackReport(task="Pay with a gift card", description="No gift card field."),
        session=session,
    )
    assert alternative is not None
    assert len(world.shop.store.keys(FEEDBACK)) == 3  # type: ignore[attr-defined]

    async def raw(body: object, at: PapSession = session) -> httpx.Response:
        signed = await session_headers(world.reactor, "POST", endpoint, session=at, token=None)
        return await world.http.post(endpoint, json=body, headers=signed)

    for malformed in (
        {"task_ids": ["installments"], "task": "Pay", "description": "Why"},  # both forms
        {"task_ids": ["installments"], "task": "Pay"},
        {},  # neither
        {"task_ids": []},
        {"task_ids": "installments"},
        {"task_ids": [1]},
        {"task_ids": ["installments", "installments"]},
        {"task_ids": ["Not An ID"]},
        {"task_ids": None},
    ):
        refused = await raw(malformed)
        assert (refused.status_code, refused.json()) == (
            400,
            {"error": "invalid_request"},
        ), malformed
    assert (await raw({"task_ids": ["installments"]})).status_code == 202
    with pytest.raises(FeedbackError):
        await feedback.report(
            f"{SHOP}/poppy/nowhere", FeedbackReport.listed("installments"), session=session
        )


@pytest.mark.asyncio
async def test_nothing_of_listed_tasks_goes_to_a_peer_at_10() -> None:
    world = World()
    _serving(world, replace(CONFIG, feedback_tasks=LISTED))
    # A 1.0 agent at the 1.1 company: no `feedback.tasks`, and its reports are 1.0's.
    published = await _session(world, "1.0")
    answer = await world.transport.request("GET", f"{SHOP}/poppy/tasks", session=published)
    assert answer.json()["feedback"] == {"endpoint": FEEDBACK_URL}
    tasks = await TasksClient(transport=world.transport).get(world.company, session=published)
    assert tasks.listed_tasks == [] and tasks.feedback_endpoint == FEEDBACK_URL
    feedback = FeedbackClient(transport=world.transport)
    with pytest.raises(ValueError, match=r"1\.1"):
        await feedback.report(
            FEEDBACK_URL, FeedbackReport.listed("installments"), session=published
        )

    async def raw(body: object) -> httpx.Response:
        signed = await session_headers(
            world.reactor, "POST", FEEDBACK_URL, session=published, token=None
        )
        return await world.http.post(FEEDBACK_URL, json=body, headers=signed)

    # As 1.0 defines: a report needs `task` and `description`, and other members are ignored.
    assert (await raw({"task_ids": ["installments"]})).status_code == 400
    both = await raw({"task_ids": ["installments"], "task": "Pay", "description": "Why"})
    assert both.status_code == 202
    assert await world.shop.feedback_task_counts() == {"installments": 0, "split-payment": 0}
    assert world.shop.tasks_document("1.0")["feedback"] == {"endpoint": FEEDBACK_URL}
    assert world.shop.tasks_document()["feedback"]["tasks"] == list(LISTED)

    # A company that serves only 1.0 lists none, whatever the request names.
    _serving(world, replace(CONFIG, feedback_tasks=LISTED, protocol_versions=("1.0",)))
    session = await _session(world)
    assert session.protocol_version == "1.0"
    newer = replace(session, protocol_version="1.1")
    answer = await world.transport.request("GET", f"{SHOP}/poppy/tasks", session=newer)
    assert "tasks" not in answer.json()["feedback"]

    # A document at 1.0 whose tasks response lists tasks all the same: the agent reads it
    # as 1.0 defines, and reports nothing by ID.
    document = DiscoveryDocument.model_validate(
        {**world.company.document.model_dump(mode="json"), "protocol_version": "1.0"}
    )
    _serving(world, replace(CONFIG, feedback_tasks=LISTED))
    wrong = await TasksClient(transport=world.transport).get(document, session=newer)
    assert wrong.available and wrong.listed_tasks == []
    assert wrong.feedback_endpoint == FEEDBACK_URL
