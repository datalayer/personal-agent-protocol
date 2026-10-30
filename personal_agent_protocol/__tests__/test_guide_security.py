# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Guide-level behaviour at the reference company: overlapping JWKS, consent-page CSRF and framing.

What `docs/docs/guides/operational-limits.mdx` (Overlapping JWKS) and
`docs/docs/guides/company.mdx` (Consent pages and the website) say, tested
through the company's own endpoints with real keys.
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlencode

import pytest
from pydantic import SecretStr

from personal_agent_protocol import DirectSignInClient, SessionClient
from personal_agent_protocol.company import CompanyConfig, CompanyRequest, ConsentDecision
from personal_agent_protocol.company.service import CONSENT_COOKIE
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import CONFIG
from personal_agent_protocol.reactor import BROWSER_HANDOFFS
from personal_agent_protocol.transport import session_headers

from .test_company_end_to_end import PAIRWISE, TENANT, World

AUTHORIZE = "https://manzanita.example/oauth/authorize"
ORDERS = "https://manzanita.example/api/orders"
_HIDDEN = re.compile(r'<input type="hidden" name="([^"]+)" value="([^"]*)">')


# Overlapping JWKS (operational-limits.mdx) ------------------------------------------------


class RotatingSite:
    """Atlas's website, whose key set the test rotates; it counts JWKS fetches."""

    def __init__(self, identity: AgentIdentity, max_age: int) -> None:
        self.metadata = identity.metadata
        self.keys: list[dict[str, Any]] = list(identity.jwks["keys"])
        self.max_age = max_age
        self.jwks_fetches = 0

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["path"] == "/jwks.json":
            self.jwks_fetches += 1
            document: Any = {"keys": self.keys}
        else:
            document = self.metadata
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"cache-control", f"max-age={self.max_age}".encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": json.dumps(document).encode()})


def same_agent_with(world: World, kid: str) -> AgentIdentity:
    """Atlas after a rotation: the same `client_id`, another key."""

    return AgentIdentity(domain=world.atlas.domain, name=world.atlas.name, kid=kid)


async def session_accepted(world: World, identity: AgentIdentity) -> bool:
    """One signed-out request in a new Session, whose delegation `identity`'s key signed.

    Each call is a new host, so a new delegated key and delegation: a delegation is
    verified against the agent's keys when it is first seen (§5.2).
    """

    reactor = personal_agent_reactor(
        PersonalAgentHost(identity, world.clock), network=world.network, http_client=world.http
    )
    metadata = world.company.oauth_metadata
    session = await SessionClient(reactor=reactor, http_client=world.http).start(
        client_id=identity.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        tenant_id=TENANT,
    )
    answer = await world.http.get(
        ORDERS, headers=await session_headers(reactor, "GET", ORDERS, session=session, token=None)
    )
    if answer.status_code == 400:
        assert answer.json()["error"] == "invalid_session"
        return False
    # Signed out: the Session is good, and the account needs a sign-in (§7).
    assert answer.status_code == 401
    return True


@pytest.mark.asyncio
async def test_overlapping_jwks_verify_either_key_then_refuse_the_retired_one() -> None:
    world = World()
    site = RotatingSite(world.atlas, max_age=600)
    world.network.add(world.atlas.domain, site)
    await world.signed_out_session()
    assert await session_accepted(world, world.atlas)  # the company caches [key-1]
    assert site.jwks_fetches == 1
    newer = same_agent_with(world, "key-2")

    # The overlap: both keys are published; the agent signs delegations with the new one.
    site.keys = [*world.atlas.jwks["keys"], *newer.jwks["keys"]]
    assert await session_accepted(world, newer)
    assert site.jwks_fetches == 2  # the unknown kid fetched the set again, at once
    # Delegations signed with the old key still verify during the overlap, from the cache.
    assert await session_accepted(world, world.atlas)
    assert await session_accepted(world, newer)
    assert site.jwks_fetches == 2

    # The old key is retired. Until the cached set expires (its max-age) it still verifies…
    site.keys = list(newer.jwks["keys"])
    world.clock.advance(599)
    assert await session_accepted(world, world.atlas)
    # …and once it has, the retired key is refused and the new one still verifies.
    world.clock.advance(2)
    assert not await session_accepted(world, world.atlas)
    assert await session_accepted(world, newer)


@pytest.mark.asyncio
async def test_unknown_kids_refetch_the_set_at_most_once_a_minute() -> None:
    world = World()
    site = RotatingSite(world.atlas, max_age=3600)
    world.network.add(world.atlas.domain, site)
    await world.signed_out_session()
    assert await session_accepted(world, world.atlas)
    assert site.jwks_fetches == 1

    # Delegations naming keys that were never published: refused, one fetch for all of them.
    for index in range(20):
        assert not await session_accepted(world, same_agent_with(world, f"forged-{index}"))
    assert site.jwks_fetches == 2

    # A real rotation inside that minute waits for the next refetch: then it verifies.
    newer = same_agent_with(world, "key-2")
    site.keys = [*world.atlas.jwks["keys"], *newer.jwks["keys"]]
    assert not await session_accepted(world, newer)
    assert site.jwks_fetches == 2
    world.clock.advance(61)
    assert await session_accepted(world, newer)
    assert site.jwks_fetches == 3


# Consent pages (company.mdx) ---------------------------------------------------------------


class RecordingBrowser:
    """The user's browser handoff: it only remembers the authorization URL it was given."""

    def __init__(self) -> None:
        self.url: str | None = None

    async def open(self, authorization_url: SecretStr) -> None:
        self.url = authorization_url.get_secret_value()

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(BROWSER_HANDOFFS, self, contribution_id="recording")


async def consent_world() -> tuple[World, DirectSignInClient, str]:
    world = World()
    handoff = RecordingBrowser()
    world.host.browser = handoff  # type: ignore[assignment]
    world.reactor = personal_agent_reactor(
        world.host, network=world.network, http_client=world.http
    )
    await world.signed_out_session()
    metadata = world.company.oauth_metadata
    client = DirectSignInClient(reactor=world.reactor, http_client=world.http)
    await client.begin(
        authorization_endpoint=metadata.authorization_endpoint,  # type: ignore[union-attr,arg-type]
        token_endpoint=metadata.token_endpoint,  # type: ignore[union-attr]
        issuer=metadata.issuer,  # type: ignore[union-attr]
        client_id=world.atlas.client_id,
        redirect_uri=f"https://{world.atlas.domain}/oauth/callback",
        scopes=("orders:read",),
        tenant_id=TENANT,
    )
    assert handoff.url is not None
    return world, client, handoff.url


def post(
    form: dict[str, str], *, cookie: str | None, headers: dict[str, str] | None = None
) -> CompanyRequest:
    sent = {"origin": "https://manzanita.example", "sec-fetch-site": "same-origin"}
    sent.update(headers or {})
    if cookie is not None:
        sent["cookie"] = f"{CONSENT_COOKIE}={cookie}"
    return CompanyRequest(
        "POST",
        AUTHORIZE,
        {k: v for k, v in sent.items() if v},
        urlencode(form).encode(),
    )


@pytest.mark.asyncio
async def test_the_consent_form_is_bound_to_the_browser_that_was_shown_it() -> None:
    world, client, url = await consent_world()
    ours, theirs = world.network.client(), world.network.client()
    page = await ours.get(url)
    other = await theirs.get(url)  # the same link opened in another browser

    # Never framed, never cached; the cookie is the company's own, for this host only.
    for shown in (page, other):
        assert shown.status_code == 200
        assert shown.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in shown.headers["content-security-policy"]
        assert shown.headers["cache-control"] == "no-store"
        cookie = shown.headers["set-cookie"]
        assert cookie.startswith(f"{CONSENT_COOKIE}=")
        for attribute in ("Path=/", "Secure", "HttpOnly", "SameSite=Strict"):
            assert attribute in cookie
    form = dict(_HIDDEN.findall(page.text))
    other_form = dict(_HIDDEN.findall(other.text))
    assert set(form) == {"request_id", "csrf"} and form["request_id"] != other_form["request_id"]
    assert f'action="{AUTHORIZE}"' in page.text
    mine = ours.cookies[CONSENT_COOKIE]
    yours = theirs.cookies[CONSENT_COOKIE]
    assert mine != yours

    allow = {**form, "decision": "allow"}
    refused = {
        "a cross-site POST": post(allow, cookie=mine, headers={"sec-fetch-site": "cross-site"}),
        "a same-site but not same-origin POST": post(
            allow, cookie=mine, headers={"sec-fetch-site": "same-site"}
        ),
        "another origin": post(allow, cookie=mine, headers={"origin": "https://evil.example"}),
        "an opaque origin": post(allow, cookie=mine, headers={"origin": "null"}),
        "no consent cookie": post(allow, cookie=None),
        "no CSRF token": post({**allow, "csrf": ""}, cookie=mine),
        "a wrong CSRF token": post({**allow, "csrf": other_form["csrf"]}, cookie=mine),
        "the form replayed from another browser": post(allow, cookie=yours),
        "another browser's form for this request": post(
            {**other_form, "request_id": form["request_id"], "decision": "allow"}, cookie=yours
        ),
        "no decision": post(form, cookie=mine),
        "an unknown request": post({**allow, "request_id": "authz_unknown"}, cookie=mine),
    }
    for what, request in refused.items():
        try:
            await world.shop.consent_decision(request)
        except PermissionError:
            continue
        pytest.fail(f"{what} was taken for the user's decision")
    with pytest.raises(PermissionError):
        await world.shop.consent_decision(
            CompanyRequest("GET", AUTHORIZE, {"cookie": f"{CONSENT_COOKIE}={mine}"})
        )

    # The page's own form, in the browser it was shown to: the decision counts once.
    decision = await world.shop.consent_decision(post(allow, cookie=mine))
    assert decision == ConsentDecision(request_id=form["request_id"], allow=True)
    callback = await world.shop.approve_authorization(decision.request_id, account_id="acct_ada")
    assert (await client.complete(callback)).token.scopes == ("orders:read",)
    with pytest.raises(PermissionError):  # decided: the request is gone
        await world.shop.consent_decision(post(allow, cookie=mine))
    # A browser that already has the cookie keeps it for its next request.
    again = await ours.get(url)
    assert "set-cookie" in again.headers and ours.cookies[CONSENT_COOKIE] == mine
    denied = {**dict(_HIDDEN.findall(again.text)), "decision": "deny"}
    assert (await world.shop.consent_decision(post(denied, cookie=mine))).allow is False
    for browser in (ours, theirs):
        await browser.aclose()


@pytest.mark.asyncio
async def test_a_hosted_consent_page_gets_no_binding_and_no_built_in_decision() -> None:
    world, _, url = await consent_world()
    config = world.shop.config
    hosted = CompanyConfig(
        **{
            **{name: getattr(config, name) for name in config.__dataclass_fields__},
            "consent_page": "https://hosted.example/consent?request={request_id}",
        }
    )
    assert CONFIG.consent_page is None
    object.__setattr__(world.shop, "config", hosted)
    browser = world.network.client()
    answer = await browser.get(url)
    assert answer.status_code == 303 and "set-cookie" not in answer.headers
    request_id = answer.headers["location"].rsplit("=", 1)[1]
    with pytest.raises(PermissionError):
        await world.shop.consent_decision(
            post({"request_id": request_id, "csrf": "x", "decision": "allow"}, cookie="c")
        )
    await browser.aclose()
