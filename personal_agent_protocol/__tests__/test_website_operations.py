# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Operations on a website: `Poppy-Operation`, the operations endpoint (Operations 4, 6, 7)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from personal_agent_protocol import BrowserSessionClient
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.demo.kit import ControlledBrowser
from personal_agent_protocol.errors import PersonalAgentProtocolError
from personal_agent_protocol.models import Approval, ExtensionDescriptor
from personal_agent_protocol.operations import (
    OPERATION_HEADER,
    AgentInstruction,
    OperationError,
    OperationReference,
    OperationsClient,
    WebsiteOperations,
    operation_reference_header,
    operations_endpoint,
    parse_operation_header,
)
from personal_agent_protocol.sessions import AccessToken, PapSession

from .test_company_end_to_end import World
from .test_mcp_and_web import BROWSE, signed_in_with_reference, web_world

EXCHANGE_PAGE = "https://manzanita.example/orders/ord_7Hk2/exchange"
ENDPOINT = "https://manzanita.example/poppy/operations"


async def joined(
    world: World, browser: ControlledBrowser, *, signed_in: bool = True
) -> tuple[PapSession, AccessToken | None, BrowserSessionClient]:
    token, _ = await signed_in_with_reference(world, BROWSE)
    session = world.session
    assert session is not None
    joins = BrowserSessionClient(reactor=world.reactor, transport=world.transport)
    await joins.join(
        browser_session_endpoint=world.company.document.web.browser_session_endpoint,  # type: ignore[union-attr,arg-type]
        session=session,
        token=token if signed_in else None,
    )
    return session, token, joins


def website(world: World, operations: OperationsClient | None = None) -> WebsiteOperations:
    return WebsiteOperations(
        api=ApiClient(transport=world.transport),
        document=world.company.document,
        operations=operations,
    )


async def press_exchange(browser: ControlledBrowser):  # type: ignore[no-untyped-def]
    await browser.get(EXCHANGE_PAGE)
    return await browser.submit(EXCHANGE_PAGE, {})


def test_the_header_is_a_dictionary_of_two_strings() -> None:
    value = 'sid="ses_Hq3vT8nW2kLm9xRb", ref="exc_5Rt2.1791487200.k3Jd9Qx2mW8v"'
    assert parse_operation_header(value) == OperationReference(
        sid="ses_Hq3vT8nW2kLm9xRb", ref="exc_5Rt2.1791487200.k3Jd9Qx2mW8v"
    )
    reference = OperationReference(sid="s", ref="a.b")
    assert parse_operation_header(operation_reference_header(reference)) == reference
    # Other members are ignored; anything that isn't a Dictionary is ignored whole.
    assert parse_operation_header('sid="s", ref="r", x=1') == OperationReference("s", "r")
    for invalid in (
        None,
        "",
        'sid="s"',
        'ref="r"',
        "sid=s, ref=r",
        'sid="s", ref="has space"',
        'sid="s", ref="sl/ash"',
        f'sid="s", ref="{"a" * 2049}"',
        'sid="s", ref="r",',
    ):
        assert parse_operation_header(invalid) is None, invalid
    assert parse_operation_header(f'sid="s", ref="{"a" * 2048}"') is not None
    with pytest.raises(ValueError):
        operation_reference_header(OperationReference(sid="s", ref="no spaces"))


@pytest.mark.asyncio
async def test_the_company_lists_the_endpoint_with_its_browser_session_endpoint() -> None:
    world = World()
    await world.signed_out_session()
    document = world.company.document
    entry = document.extension("operations", "3")
    assert entry is not None and getattr(entry, "endpoint", None) == ENDPOINT
    assert operations_endpoint(document) == ENDPOINT
    # Without the browser-session endpoint the endpoint is not one to use (Operations 2).
    bare = document.model_copy(update={"web": None})
    assert operations_endpoint(bare) is None
    plain = document.model_copy(
        update={
            "extensions": {
                **document.extensions,
                "operations": [ExtensionDescriptor(version="3")],
            }
        }
    )
    assert operations_endpoint(plain) is None
    with pytest.raises(OperationError) as refused:
        WebsiteOperations(api=ApiClient(transport=world.transport), document=plain)
    assert refused.value.code == "no_operations_endpoint"


@pytest.mark.asyncio
async def test_a_website_operation_is_approved_at_the_endpoint_and_performed_once() -> None:
    world, browser = web_world()
    session, token, joins = await joined(world, browser)
    page = await press_exchange(browser)
    # The website performs nothing: 403, a page for the browser, the reference in the header.
    assert page.status_code == 403
    assert "waiting for your approval" in page.text
    assert page.headers["cache-control"] == "no-store"
    assert world.plugin.executor.performed == []
    sites = website(world)
    reference = sites.reference(
        page.headers,
        joined=joins.joined_sessions(world.company.document.web.browser_session_endpoint),  # type: ignore[union-attr,arg-type]
    )
    assert reference is not None and reference.sid == session.sid

    # The agent gets the operation at the endpoint, with the Session header and its token.
    operation = await sites.operation(reference, session=session, token=token)
    assert operation.terms["price_difference"] == {"amount": "70.00", "currency": "USD"}
    approval = await OperationsClient(reactor=world.reactor).ask_user(
        operation,
        organization=world.company.document.organization,
        tenant_id=session.tenant_id,
        input_type="tap",
    )
    recorded = await sites.record(reference, approval, session=session, token=token)
    assert recorded.status == 204 and recorded.operation is None
    # Recording performs nothing; a lookup says it is approved.
    assert world.plugin.executor.performed == []
    assert await sites.status(reference, session=session, token=token) == "approved"
    # The same approval again is answered the same way.
    again = await sites.record(reference, approval, session=session, token=token)
    assert again.status == 204

    # The browser makes the request again: performed once, with the approval recorded first.
    done = await browser.submit(EXCHANGE_PAGE, {"replacement": "ridge-insulated-m"})
    assert done.status_code == 200 and "Exchanged the Ridge Jacket" in done.text
    assert world.plugin.executor.performed == [operation.operation_id]
    assert await sites.status(reference, session=session, token=token) == "performed"
    stored = await world.shop.operation_record(operation.operation_id)
    assert stored.website and stored.approval == {
        "approver": "user",
        "approved_at": approval.approved_at,
        "input_type": "tap",
    }
    assert await sites.before_approving_again(reference, session=session, token=token) == (
        "performed"
    )

    # The next request for it is a new action: a new operation, nothing performed twice.
    after = await browser.submit(EXCHANGE_PAGE, {"replacement": "ridge-insulated-m"})
    assert after.status_code == 403
    fresh = sites.reference(after.headers, joined={session.sid})
    assert fresh is not None and fresh.ref != reference.ref
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_a_page_script_gets_json_and_the_reference() -> None:
    world, browser = web_world()
    session, _token, _joins = await joined(world, browser)
    await browser.get(EXCHANGE_PAGE)
    answer = await browser.http.post(
        EXCHANGE_PAGE,
        data={"replacement": "ridge-insulated-m"},
        headers={"Accept": "application/json", "Origin": "https://manzanita.example"},
    )
    assert answer.status_code == 403
    assert answer.json() == {"error": "approval_required"}
    assert parse_operation_header(answer.headers[OPERATION_HEADER]).sid == session.sid  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_a_reference_is_taken_only_from_a_joined_session() -> None:
    world, browser = web_world()
    session, _token, _joins = await joined(world, browser)
    page = await press_exchange(browser)
    # A header naming a Session the agent didn't join this browser to is ignored.
    assert WebsiteOperations.reference(page.headers, joined={"another-sid"}) is None
    assert WebsiteOperations.reference({}, joined={session.sid}) is None
    assert WebsiteOperations.reference(
        {"poppy-operation": page.headers[OPERATION_HEADER]}, joined={session.sid}
    ) == parse_operation_header(page.headers[OPERATION_HEADER])


@pytest.mark.asyncio
async def test_the_endpoint_refuses_what_the_session_cannot_use() -> None:
    world, browser = web_world()
    session, token, joins = await joined(world, browser)
    page = await press_exchange(browser)
    sites = website(world)
    reference = sites.reference(page.headers, joined={session.sid})
    assert reference is not None
    for ref in ("op_unknown.rev_unknown", reference.ref.split(".")[0] + ".rev_none"):
        with pytest.raises(OperationError) as unusable:
            await sites.operation(
                OperationReference(session.sid, ref), session=session, token=token
            )
        assert unusable.value.code == "invalid_reference"
    # An API's operation is never approved at the endpoint (Operations 6).
    api = ApiClient(transport=world.transport)
    asked = await api.call(
        "POST",
        "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
        session=session,
        token=token,
        body={},
    )
    assert asked.operation is not None
    api_ref = f"{asked.operation.operation_id}.{asked.operation.revision}"
    with pytest.raises(OperationError) as foreign:
        await sites.operation(
            OperationReference(session.sid, api_ref), session=session, token=token
        )
    assert foreign.value.code == "invalid_reference"
    # A signed-out Session of the same agent and User gets a challenge for the account.
    with pytest.raises(PersonalAgentProtocolError) as challenged:
        await sites.operation(reference, session=session, token=None)
    assert challenged.value.status_code == 401
    # Once its revision expired, the reference is unusable.
    world.clock.advance(16 * 60)
    with pytest.raises(OperationError) as expired:
        await sites.operation(reference, session=session, token=token)
    assert expired.value.code == "invalid_reference"
    assert joins.joined_sessions("https://manzanita.example/poppy/browser-session") == {session.sid}


@pytest.mark.asyncio
async def test_a_website_approval_is_never_accepted_at_the_api() -> None:
    world, browser = web_world()
    session, token, _joins = await joined(world, browser)
    page = await press_exchange(browser)
    sites = website(world)
    reference = sites.reference(page.headers, joined={session.sid})
    assert reference is not None
    operation = await sites.operation(reference, session=session, token=token)
    approval = Approval(
        operation_id=operation.operation_id,
        revision=operation.revision,
        approver="user",
    )
    answer = await ApiClient(transport=world.transport).call(
        "POST",
        "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
        session=session,
        token=token,
        body={},
        approval=approval,
    )
    # Handled as a request without an approval: a new operation, nothing performed.
    assert answer.operation is not None
    assert answer.operation.operation_id != operation.operation_id
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_an_approval_of_another_revision_gets_the_operation_and_a_decline_is_not_kept() -> (
    None
):
    world, browser = web_world()
    session, token, _joins = await joined(world, browser)
    page = await press_exchange(browser)
    sites = website(world)
    reference = sites.reference(page.headers, joined={session.sid})
    assert reference is not None
    operation = await sites.operation(reference, session=session, token=token)
    wrong = Approval(operation_id=operation.operation_id, revision="rev_never", approver="user")
    answered = await sites.record(reference, wrong, session=session, token=token)
    assert answered.operation is not None and answered.operation.revision == operation.revision
    assert await sites.status(reference, session=session, token=token) is None

    # The browser's request without a recorded approval asks again: nothing performed.
    retried = await browser.submit(EXCHANGE_PAGE, {"replacement": "ridge-insulated-m"})
    assert retried.status_code == 403
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_an_agent_approval_makes_the_next_revision_the_users() -> None:
    world, browser = web_world()
    session, token, _joins = await joined(world, browser)
    page = await press_exchange(browser)
    operations = OperationsClient(reactor=world.reactor)
    sites = website(world, operations)
    reference = sites.reference(page.headers, joined={session.sid})
    assert reference is not None
    operation = await sites.operation(reference, session=session, token=token)
    instruction = AgentInstruction("Go ahead with exchanges under $100", lambda _: True)
    approval = await operations.approve_as_agent(operation, instruction=instruction)
    sent = await operations.send(
        lambda approved: sites.record(reference, approved, session=session, token=token), approval
    )
    assert sent.status == "answered" and sent.answer.status == 204  # type: ignore[union-attr]
    assert operation.operation_id in operations.user_only
    with pytest.raises(OperationError) as refused:
        await operations.approve_as_agent(operation, instruction=instruction)
    assert refused.value.code == "ask_user"


@pytest.mark.asyncio
async def test_a_browser_without_operations_gets_the_websites_own_flow() -> None:
    world, browser = web_world()
    token, _ = await signed_in_with_reference(world, BROWSE)
    session = world.session
    assert session is not None
    # A join whose Session declares no Operations extension.
    plain = replace(session, extensions={})
    await BrowserSessionClient(reactor=world.reactor, transport=world.transport).join(
        browser_session_endpoint=world.company.document.web.browser_session_endpoint,  # type: ignore[union-attr,arg-type]
        session=plain,
        token=token,
    )
    page = await press_exchange(browser)
    assert page.status_code == 403
    assert OPERATION_HEADER.lower() not in {name.lower() for name in page.headers}
    assert "Confirm the exchange on manzanita.example" in page.text
    # A visitor that never joined is sent to sign in.
    visitor = ControlledBrowser(world.network.client())
    await visitor.get(EXCHANGE_PAGE)
    refused = await visitor.submit(EXCHANGE_PAGE, {})
    assert refused.status_code == 401
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_the_endpoint_needs_the_operations_declaration() -> None:
    world, browser = web_world()
    session, token, _joins = await joined(world, browser)
    page = await press_exchange(browser)
    reference = parse_operation_header(page.headers[OPERATION_HEADER])
    assert reference is not None
    plain = replace(session, extensions={})
    with pytest.raises(OperationError) as refused:
        await website(world).operation(reference, session=plain, token=token)
    assert refused.value.code == "operations_not_declared"
    raw = await world.transport.request(
        "POST",
        ENDPOINT,
        session=plain,
        token=token,
        headers={"Content-Type": "application/json"},
        content=b'{"ref": "%s"}' % reference.ref.encode(),
    )
    assert raw.status_code == 403 and raw.json()["error"] == "extension_required"
