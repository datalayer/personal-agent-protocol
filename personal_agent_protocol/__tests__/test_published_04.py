# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Version 0.4 as published (upstream 4803900): what changed after draft 0.4 as of 46beb21,
apart from Operations version 3 (`test_operations_v3.py`).

Task coverage per Session, the Session header on website pages fetched without a browser,
sign-ins someone else started, scopes in the protected resource metadata, the issuer's
client ID metadata document flag, and the tasks endpoint as a Session header destination.
"""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import httpx
import pytest

from personal_agent_protocol import (
    AuthorizationError,
    DirectSignInClient,
    DiscoveredCompany,
    DiscoveryDocument,
    FetchedPage,
    PageClient,
    SessionTasks,
    TasksClient,
    TasksError,
    TasksResponse,
    TransportError,
    page_carries_session,
    tasks_endpoint,
)
from personal_agent_protocol.auth import CROSS_DEVICE_LIFETIME_SECONDS
from personal_agent_protocol.company import CompanyRequest, CompanyResponse
from personal_agent_protocol.company.service import connect_caution, connect_heading
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.feedback import FeedbackClient, FeedbackReport
from personal_agent_protocol.transport import SessionHttpClient

from .test_company_end_to_end import TENANT, World
from .test_company_refusals import signed_in
from .test_direct_and_api import begin, direct_world

TASKS = "https://manzanita.example/poppy/tasks"
SKILL = "---\nname: exchange-a-jacket\n---\nAsk for the order, then POST an exchange.\n"


def _with_skills() -> World:
    world = World()
    world.shop, world.plugin = manzanita(
        world.network,
        world.clock,
        config=dataclasses.replace(
            CONFIG, skills=(("exchange-a-jacket", "Exchange a jacket for another size.", SKILL),)
        ),
    )
    return world


class Counting:
    """Counts the requests a transport sends, by URL."""

    def __init__(self, transport: SessionHttpClient) -> None:
        self.sent: list[tuple[str, str, bool]] = []
        inner = transport.request

        async def request(method: str, url: str, **kwargs: Any) -> httpx.Response:
            self.sent.append((method, url, kwargs.get("token") is not None))
            return await inner(method, url, **kwargs)

        transport.request = request  # type: ignore[method-assign]


# Task coverage per Session (§9) -----------------------------------------------------------


@pytest.mark.asyncio
async def test_poppy_json_names_a_tasks_endpoint_and_nothing_it_moved() -> None:
    world = _with_skills()
    await world.signed_out_session()
    document = world.shop.discovery_document()
    assert document["tasks"] == {"endpoint": TASKS}
    for moved in ("excluded_tasks", "skill_index", "feedback"):
        assert moved not in document
    assert tasks_endpoint(world.company.document) == TASKS
    # A company with nothing to say there lists no endpoint and serves none.
    quiet = World()
    quiet.shop.config = dataclasses.replace(CONFIG, excluded_tasks=(), feedback=False)
    assert "tasks" not in quiet.shop.discovery_document()
    answered = await quiet.http.get(TASKS)
    assert answered.status_code == 404


@pytest.mark.asyncio
async def test_the_tasks_response_is_fetched_with_the_session_header_and_no_token() -> None:
    """`GET {tasks.endpoint}` with the Session header, never an access token, also in a
    signed-in Session; the response lists excluded tasks, skills and the feedback endpoint,
    a skill's `url` resolved against `tasks.endpoint` (§9, §9.4)."""

    world = _with_skills()
    await signed_in(world)
    session = world.session
    counting = Counting(world.transport)
    tasks = await TasksClient(transport=world.transport).get(world.company, session=session)
    assert counting.sent == [("GET", TASKS, False)]
    assert tasks.available and tasks.session == session.sid and tasks.endpoint == TASKS
    assert [task.task for task in tasks.excluded_tasks] == [
        "Change the size of an item after it has shipped"
    ]
    (skill,) = tasks.skills
    assert skill.url == "https://manzanita.example/poppy/skills/exchange-a-jacket/SKILL.md"
    assert tasks.feedback_endpoint == "https://manzanita.example/poppy/feedback"
    # The feedback endpoint from the response is a Session header destination (§5.2).
    await FeedbackClient(transport=world.transport).report(
        tasks.feedback_endpoint,
        FeedbackReport(task="Track a parcel", description="No tracking anywhere."),
        session=session,
    )
    # The company marks it private: a shared cache never hands it to another Session.
    raw = await world.transport.request("GET", TASKS, session=session)
    assert raw.status_code == 200 and "private" in raw.headers["cache-control"]
    assert TasksResponse.model_validate(raw.json()).feedback is not None


@pytest.mark.asyncio
async def test_a_tasks_response_is_kept_for_its_session_and_never_used_in_another() -> None:
    world = World()
    first = await world.signed_out_session()
    second = await world.signed_out_session()
    assert first.sid != second.sid
    counting = Counting(world.transport)
    client = TasksClient(transport=world.transport)
    one = await client.get(world.company, session=first)
    assert await client.get(world.company, session=first) is one
    assert len(counting.sent) == 1  # reused in its Session, as its caching headers allow
    two = await client.get(world.company, session=second)
    assert two is not one and two.session == second.sid and len(counting.sent) == 2
    # `fresh` reads it again; so does the end of what `Cache-Control` allowed (max-age=300).
    await client.get(world.company, session=first, fresh=True)
    assert len(counting.sent) == 3
    world.clock.advance(301)
    await client.get(world.company, session=first)
    assert len(counting.sent) == 4
    # Another User ID with the same `sid` is another Session too.
    other = dataclasses.replace(first, sub="usr_somebody_else_000000")
    await client.get(world.company, session=other)
    assert len(counting.sent) == 5
    client.forget(first)
    await client.get(world.company, session=first)
    assert len(counting.sent) == 6


def _mock_transport(world: World, handler: Any) -> SessionHttpClient:
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return SessionHttpClient(reactor=world.reactor, http_client=http)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        httpx.Response(404, json={"error": "not_found"}),
        httpx.Response(500),
        httpx.Response(200, content=b"<html>not json</html>"),
        httpx.Response(200, json=["not", "an", "object"]),
        httpx.Response(200, json={"excluded_tasks": [{"task": ""}]}),
        httpx.Response(302, headers={"Location": "https://elsewhere.example/tasks"}),
        httpx.Response(429, headers={"Retry-After": "30"}),
    ],
)
async def test_with_no_response_the_agent_carries_on_as_if_nothing_were_listed(
    answer: httpx.Response,
) -> None:
    """No excluded tasks, no skills, no feedback (§9); a redirect is refused, never
    followed (§3): nothing is sent to the new URL."""

    world = World()
    session = await world.signed_out_session()
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return answer

    tasks = await TasksClient(transport=_mock_transport(world, handler)).get(
        world.company, session=session
    )
    assert tasks == SessionTasks(session=session.sid, endpoint=TASKS)
    assert not tasks.available
    assert (tasks.excluded_tasks, tasks.skills, tasks.feedback_endpoint) == ([], [], None)
    assert set(seen) == {TASKS}


@pytest.mark.asyncio
async def test_a_refused_session_header_at_the_tasks_endpoint_is_raised() -> None:
    world = World()
    session = await world.signed_out_session()
    for error in ("invalid_session", "version_unsupported"):
        client = TasksClient(
            transport=_mock_transport(world, lambda _: httpx.Response(400, json={"error": error}))  # noqa: B023
        )
        with pytest.raises(TasksError) as raised:
            await client.get(world.company, session=session)
        assert raised.value.code == error
    # The company's own: a header signed for another URL fails its checks.
    feedback = "https://manzanita.example/poppy/feedback"
    from personal_agent_protocol.transport import session_headers

    wrong = await session_headers(world.reactor, "GET", feedback, session=session, token=None)
    refused = await world.http.get(TASKS, headers=wrong)
    assert (refused.status_code, refused.json()) == (400, {"error": "invalid_session"})
    assert (await world.http.get(TASKS)).status_code == 400  # no header at all


def test_a_company_with_no_tasks_endpoint_gives_an_empty_answer_without_a_request() -> None:
    document = DiscoveryDocument.model_validate(
        {"protocol_version": "0.4", "organization": {"name": "X", "domain": "x.example"}, "web": {}}
    )
    assert tasks_endpoint(document) is None


# Website pages fetched without a browser (§5.2) -----------------------------------------


@pytest.mark.parametrize(
    ("url", "carries"),
    [
        ("https://manzanita.example/help/returns", True),
        ("https://MANZANITA.example/help", True),
        ("https://manzanita.example:443/help", True),
        ("https://www.manzanita.example/help", False),  # another host on its domain
        ("https://help.manzanita.example/", False),
        ("https://manzanita.example:8443/help", False),
        ("http://manzanita.example/help", False),
        ("https://manzanita.example.evil.example/help", False),
        ("https://user@manzanita.example/help", False),
    ],
)
def test_only_pages_on_the_host_that_served_poppy_json_carry_the_header(
    url: str, carries: bool
) -> None:
    assert page_carries_session(url, "manzanita.example") is carries


class Site:
    """Manzanita's website, with the company verifying the Session header when one is sent."""

    def __init__(self, world: World) -> None:
        self.world = world
        self.requests: list[httpx.Request] = []
        self.sessions: list[Any] = []

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if host == "manzanita.example":
            checked = await self.world.shop.page_session(
                CompanyRequest(
                    method=request.method,
                    url=str(request.url),
                    headers={name.lower(): value for name, value in request.headers.items()},
                )
            )
            if isinstance(checked, CompanyResponse):
                return httpx.Response(checked.status, json=checked.body)
            self.sessions.append(checked)
            if path == "/old-returns":
                return httpx.Response(301, headers={"Location": "/help/returns"})
            if path == "/blog":
                return httpx.Response(302, headers={"Location": "https://blog.example/returns"})
            return httpx.Response(200, text="<h1>Returns</h1>")
        if host == "blog.example":
            return httpx.Response(200, text="<h1>The blog</h1>")
        return httpx.Response(404)


def _pages(world: World, site: Any) -> PageClient:
    return PageClient(transport=_mock_transport(world, site))


@pytest.mark.asyncio
async def test_a_page_fetched_without_a_browser_carries_the_session_header_signed_out() -> None:
    """The header, `Poppy-Version` and no access token, even in a signed-in Session; the
    company verifies it and reads the request as signed out (§5.2, §5.3)."""

    world = World()
    await signed_in(world)
    session = world.session
    site = Site(world)
    page = await _pages(world, site).fetch(
        "https://manzanita.example/help/returns", session=session, company=world.company
    )
    assert isinstance(page, FetchedPage)
    assert (page.status_code, page.content, page.session_header_sent) == (
        200,
        b"<h1>Returns</h1>",
        True,
    )
    (request,) = site.requests
    assert "poppy-session" in request.headers and request.headers["poppy-version"] == "0.4"
    assert "authorization" not in request.headers and "dpop" not in request.headers
    (caller,) = site.sessions
    assert caller is not None and caller.sid == session.sid and caller.account_id is None
    # No header, no Session: an ordinary visitor.
    assert (
        await world.shop.page_session(
            CompanyRequest(method="GET", url="https://manzanita.example/help", headers={})
        )
        is None
    )


@pytest.mark.asyncio
async def test_documents_and_oauth_endpoints_on_the_same_host_never_carry_the_header() -> None:
    """ "…and not the documents above" (§5.2): discovery and description documents and OAuth
    endpoints don't carry the Session header, even on `organization.domain`."""

    world = World()
    session = await world.signed_out_session()
    site = Site(world)
    pages = _pages(world, site)
    metadata = world.company.oauth_metadata
    assert metadata is not None
    for url in (
        "https://manzanita.example/.well-known/poppy.json",
        "https://manzanita.example/.well-known/oauth-authorization-server",
        "https://manzanita.example/api/openapi.json",  # a description the company lists
        metadata.token_endpoint,
        metadata.authorization_endpoint,
    ):
        assert url is not None
        page = await pages.fetch(url, session=session, company=world.company)
        assert not page.session_header_sent, url
        assert "poppy-session" not in site.requests[-1].headers, url
    assert site.sessions == [None] * 5  # ordinary visitors, each of them
    page = await pages.fetch(
        "https://manzanita.example/help/returns", session=session, company=world.company
    )
    assert page.session_header_sent


@pytest.mark.asyncio
async def test_a_redirect_gets_a_new_session_jwt_only_on_the_same_host() -> None:
    world = World()
    session = await world.signed_out_session()
    site = Site(world)
    pages = _pages(world, site)

    async def blog(scope: Any, receive: Any, send: Any) -> None:  # the name only: Site answers
        raise AssertionError("reached through the mock transport instead")

    # Every hop passes the host's URL safety policy, so the other host must resolve.
    world.network.add("blog.example", blog)
    same = await pages.fetch(
        "https://manzanita.example/old-returns", session=session, company=world.company
    )
    assert same.url == "https://manzanita.example/help/returns" and same.session_header_sent
    first, second = site.requests
    # Each signed for its own URL: the second would fail the company's check otherwise.
    assert first.headers["poppy-session"] != second.headers["poppy-session"]
    assert len(site.sessions) == 2

    site.requests.clear()
    away = await pages.fetch(
        "https://manzanita.example/blog", session=session, company=world.company
    )
    assert (away.url, away.session_header_sent) == ("https://blog.example/returns", False)
    at_company, elsewhere = site.requests
    assert "poppy-session" in at_company.headers
    assert "poppy-session" not in elsewhere.headers and "poppy-version" not in elsewhere.headers

    # A page on another host is an ordinary fetch: no header from the start.
    site.requests.clear()
    other = await pages.fetch("https://blog.example/x", session=session, company=world.company)
    assert not other.session_header_sent and "poppy-session" not in site.requests[0].headers
    with pytest.raises(TransportError) as raised:
        await pages.fetch("http://manzanita.example/help", session=session, company=world.company)
    assert raised.value.code == "invalid_url"


@pytest.mark.asyncio
async def test_invalid_session_from_a_page_is_reported_and_the_page_fetched_again_on_request() -> (
    None
):
    """A page that verifies the header answers a failed check with `invalid_session`, so
    the agent learns of its mistake; it MAY then fetch the page again without the header
    (§5.2). The client never leaves the header out on its own."""

    world = World()
    session = await world.signed_out_session()
    seen: list[bool] = []

    def strict(request: httpx.Request) -> httpx.Response:
        seen.append("poppy-session" in request.headers)
        if "poppy-session" in request.headers:
            return httpx.Response(400, json={"error": "invalid_session"})
        return httpx.Response(200, text="<h1>Returns</h1>")

    pages = _pages(world, strict)
    url = "https://manzanita.example/help/returns"
    told = await pages.fetch(url, session=session, company=world.company)
    assert (told.status_code, told.invalid_session, told.session_header_sent) == (400, True, True)
    assert seen == [True]
    again = await pages.fetch(
        url, session=session, company=world.company, again_without_header=True
    )
    assert (again.status_code, again.invalid_session, again.session_header_sent) == (
        200,
        True,
        False,
    )
    assert seen == [True, True, False]


@pytest.mark.asyncio
async def test_the_company_answers_a_bad_page_header_with_invalid_session() -> None:
    world = World()
    await signed_in(world)
    session = world.session
    from personal_agent_protocol.transport import session_headers

    url = "https://manzanita.example/help/returns"
    other = await session_headers(
        world.reactor, "GET", "https://manzanita.example/x", session=session, token=None
    )
    refused = await world.shop.page_session(
        CompanyRequest(method="GET", url=url, headers={k.lower(): v for k, v in other.items()})
    )
    assert isinstance(refused, CompanyResponse)
    assert (refused.status, refused.body) == (400, {"error": "invalid_session"})
    # An access token never goes with a page: a Session JWT made with one carries `ath`,
    # and without the token the company can't match it.
    token = await world.refreshed()
    with_token = await session_headers(world.reactor, "GET", url, session=session, token=token)
    refused = await world.shop.page_session(
        CompanyRequest(method="GET", url=url, headers={k.lower(): v for k, v in with_token.items()})
    )
    assert isinstance(refused, CompanyResponse) and refused.body == {"error": "invalid_session"}


# Sign-ins someone else started (§4.2, §10.8) -------------------------------------------


@pytest.mark.asyncio
async def test_the_companys_page_names_the_agent_and_says_when_to_continue() -> None:
    """The sign-in and consent page starts with a heading that names the personal agent and
    says it wants to connect, never "Sign in with …", and tells the person to continue only
    if they just asked that agent (§10.8; guides, consent pages)."""

    world, browser = direct_world()
    session = await world.signed_out_session()
    await begin(world, browser, session)
    page = browser.pages[-1]
    assert "<h1>Atlas wants to connect to your Manzanita Outfitters account</h1>" in page
    assert "<p>Only continue if you asked Atlas to do this just now.</p>" in page
    assert "Sign in with" not in page and "<title>Connect</title>" in page
    assert page.index("<h1>") < page.index("asks to:")
    # A hosted consent page gets the same words to show.
    request = await world.shop.authorization_request(browser.request_id)  # type: ignore[arg-type]
    assert request["heading"] == connect_heading("Atlas", "Manzanita Outfitters")
    assert request["caution"] == connect_caution("Atlas")


@pytest.mark.asyncio
async def test_a_device_verification_page_can_name_the_agent_too() -> None:
    from personal_agent_protocol import DeviceSignInClient

    world = World()
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    started = await DeviceSignInClient(reactor=world.reactor, http_client=world.http).begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        scopes=("orders:read",),
        tenant_id=TENANT,
        organization=world.company.document.organization,
    )
    request = await world.shop.device_request(started.user_code)
    assert request["heading"] == "Atlas wants to connect to your Manzanita Outfitters account"
    assert request["caution"] == "Only continue if you asked Atlas to do this just now."
    assert request["client_domain"] == "atlas.example"
    assert [scope["scope"] for scope in request["scopes"]] == ["orders:read"]
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    with pytest.raises(KeyError):
        await world.shop.device_request(started.user_code)
    with pytest.raises(KeyError):
        await world.shop.device_request("NOPE-NOPE")


@pytest.mark.asyncio
async def test_a_redirect_that_arrives_for_another_user_gets_no_tokens() -> None:
    """A host that can tell which of its Users is in the browser at `redirect_uri` checks it
    is the one who started the sign-in: a forwarded link then fails (§4.2, §10.8)."""

    world, browser = direct_world()
    session = await world.signed_out_session()
    client = await begin(world, browser, session)
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    with pytest.raises(AuthorizationError) as raised:
        await client.complete(callback, completed_by="somebody-else")
    assert raised.value.code == "sign_in_started_by_another_user"
    # The state is used up: the same redirect can't be completed afterwards either.
    with pytest.raises(AuthorizationError) as again:
        await client.complete(callback, completed_by=TENANT)
    assert again.value.code == "invalid_or_expired_state"

    client = await begin(world, browser, session)
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    done = await client.complete(callback, completed_by=TENANT)
    assert done.token is not None


@pytest.mark.asyncio
async def test_a_direct_sign_in_opened_on_another_device_is_short_lived() -> None:
    """Opened on another device, Direct Sign-In is a cross-device flow (§4.2): its request
    lives at most `CROSS_DEVICE_LIFETIME_SECONDS` (RFC 10027 §2)."""

    world, browser = direct_world()
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    who: dict[str, Any] = {
        "authorization_endpoint": metadata.authorization_endpoint,  # type: ignore[union-attr]
        "token_endpoint": metadata.token_endpoint,  # type: ignore[union-attr]
        "issuer": metadata.issuer,  # type: ignore[union-attr]
        "client_id": world.atlas.client_id,
        "redirect_uri": f"https://{world.atlas.domain}/oauth/callback",
        "scopes": ("orders:read",),
        "tenant_id": TENANT,
    }
    started = await client.begin(**who, cross_device=True)
    assert started.cross_device
    lifetime = (started.expires_at - world.clock.now()).total_seconds()
    assert lifetime == CROSS_DEVICE_LIFETIME_SECONDS == 300
    with pytest.raises(ValueError):
        await client.begin(**who, cross_device=True, lifetime_seconds=600)
    same_device = await client.begin(**who)
    assert not same_device.cross_device
    assert (same_device.expires_at - world.clock.now()).total_seconds() == 600


# Scopes, and what the issuer says for other clients (§3.2, §4.7) ------------------------


def test_the_scopes_a_company_lists_come_from_either_metadata_or_both() -> None:
    """`scopes_supported` in the issuer's metadata, in the domain's protected resource
    metadata, or in both: the agent uses the scopes in either list (§4.7)."""

    world = World()
    company = DiscoveredCompany.model_validate(
        {
            "discovery_url": "https://example.com/.well-known/poppy.json",
            "document": json.loads(
                (
                    __import__("pathlib").Path(__file__).parents[2]
                    / "protocol"
                    / "fixtures"
                    / "discovery-valid.json"
                ).read_text()
            ),
            "oauth_metadata": {
                **world.shop.oauth_metadata(),
                "issuer": "https://auth.example.com",
                "scopes_supported": ["orders:read", "poppy:browser-sign-in"],
            },
            "resource_metadata": {
                "resource": "https://example.com",
                "authorization_servers": ["https://auth.example.com"],
                "scopes_supported": ["orders:read", "orders:write", "addresses"],
            },
        }
    )
    assert company.scopes_supported == (
        "orders:read",
        "poppy:browser-sign-in",
        "orders:write",
        "addresses",
    )
    only_resource = company.model_copy(
        update={
            "oauth_metadata": company.oauth_metadata.model_copy(update={"scopes_supported": None})  # type: ignore[union-attr]
        }
    )
    assert only_resource.scopes_supported == ("orders:read", "orders:write", "addresses")
    assert company.model_copy(update={"resource_metadata": None}).scopes_supported == (
        "orders:read",
        "poppy:browser-sign-in",
    )


@pytest.mark.asyncio
async def test_the_reference_company_lists_its_scopes_in_both_and_says_it_reads_cimd() -> None:
    world = World()
    await world.signed_out_session()
    issuer, resource = world.shop.oauth_metadata(), world.shop.domain_resource_metadata()
    assert issuer["scopes_supported"] == resource["scopes_supported"]
    assert set(world.company.scopes_supported) == set(issuer["scopes_supported"])
    # For other clients, such as MCP clients (guides; the CIMD draft's §8).
    assert issuer["client_id_metadata_document_supported"] is True
