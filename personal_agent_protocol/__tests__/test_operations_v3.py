# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Operations version 3: who approved, agent approvals on the user's instruction, required
terms, declined approvals, and no version 2 on either side."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

import pytest
from pydantic import ValidationError

from personal_agent_protocol import (
    APPROVAL_DECLINED,
    APPROVAL_HEADER,
    OPERATIONS_VERSION,
    AgentInstruction,
    Approval,
    ApprovalDeclined,
    Message,
    Operation,
    OperationError,
    approval_header,
    declined_from,
    new_approval_reference,
    parse_approval_header,
)
from personal_agent_protocol.apis import ApiClient, ApiError, ApiResponse
from personal_agent_protocol.company import Decline, DeclineRequest, ProposedOperation
from personal_agent_protocol.demo.kit import ScriptedApprovals
from personal_agent_protocol.demo.manzanita import CONFIG, PROPOSALS, manzanita
from personal_agent_protocol.models import Author, OperationsContent, operations_content
from personal_agent_protocol.operations import approval_from_meta

from .test_company_end_to_end import World
from .test_company_refusals import signed_in
from .test_operations import (
    EXCHANGE,
    NOW,
    RETURNS,
    SHOP,
    Script,
    _exchange_in_a_conversation,
    _mcp,
    _said,
    client_for,
    returned,
)

GIFT_WRAP = "https://manzanita.example/api/orders/ord_7Hk2/gift-wrap"

#: "Go ahead with gift wrap up to USD 10": the user's instruction, and the host's own check
#: of a revision's terms against it. `None` when it can't tell.
UNDER_TEN = AgentInstruction(
    text="Go ahead with gift wrap up to USD 10.",
    covers=lambda operation: (
        None
        if "price" not in operation.terms
        else operation.terms["price"].get("currency") == "USD"
        and float(operation.terms["price"]["amount"]) <= 10
    ),
)
ANYTHING = AgentInstruction(text="Do whatever this shop asks.", covers=lambda _: True)


def test_the_sdk_implements_version_3_and_no_other() -> None:
    assert OPERATIONS_VERSION == "3"


# The approval: who approved --------------------------------------------------------------


def test_an_approval_names_its_approver_and_the_header_carries_every_member() -> None:
    """`approver` is required; `Poppy-Approval` carries it with `approved_at`, `input_type`
    (a user approval only) and `reference` (Operations 6)."""

    by_user = Approval(
        operation_id="exc_5Rt2",
        revision="1791487200-k3Jd9Qx2mW8v",
        approver="user",
        approved_at=1791487260,
        input_type="tap",
        reference="apr_01JD8ZK3Q9",
    )
    assert approval_header(by_user) == (
        'operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v", approver="user", '
        'approved_at=1791487260, input_type="tap", reference="apr_01JD8ZK3Q9"'
    )
    assert parse_approval_header(approval_header(by_user)) == by_user
    by_agent = Approval(
        operation_id="exc_5Rt2",
        revision="1791487200-k3Jd9Qx2mW8v",
        approver="agent",
        approved_at=1791487255,
        reference="apr_01JD8ZK3R4",
    )
    assert approval_header(by_agent) == (
        'operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v", approver="agent", '
        'approved_at=1791487255, reference="apr_01JD8ZK3R4"'
    )
    assert parse_approval_header(approval_header(by_agent)) == by_agent
    with pytest.raises(ValidationError):
        Approval(operation_id="exc_5Rt2", revision="r1")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Approval(operation_id="exc_5Rt2", revision="r1", approver="rule")  # type: ignore[arg-type]


def test_an_agent_approval_never_carries_an_input_type() -> None:
    """Never sent with `agent`, and ignored by a company that receives one (Operations 6)."""

    stated = Approval(operation_id="a", revision="b", approver="agent", input_type="tap")
    assert stated.input_type is None
    assert "input_type" not in approval_header(stated)
    received = parse_approval_header(
        'operation_id="a", revision="b", approver="agent", input_type="tap"'
    )
    assert received is not None and received.approver == "agent" and received.input_type is None
    meta = {
        "personalagentprotocol.org/approval": {
            "operation_id": "a",
            "revision": "b",
            "approver": "agent",
            "input_type": "voice",
        }
    }
    from_meta = approval_from_meta(meta)
    assert from_meta is not None and from_meta.input_type is None


@pytest.mark.parametrize(
    "value",
    [
        # What version 2 sent: no approver. Not an approval in version 3.
        'operation_id="a", revision="b"',
        'operation_id="a", revision="b", approved_at=1791487260, input_type="tap"',
        'operation_id="a", revision="b", approver="rule"',
        'operation_id="a", revision="b", approver=user',
        'operation_id="a", revision="b", approver=1',
    ],
)
def test_an_approval_without_a_valid_approver_is_no_approval(value: str) -> None:
    assert parse_approval_header(value) is None
    assert approval_from_meta({"personalagentprotocol.org/approval": {"operation_id": "a"}}) is None


def test_a_malformed_optional_member_is_left_out_never_a_reason_to_refuse() -> None:
    parsed = parse_approval_header(
        'operation_id="a", revision="b", approver="user", reference="not an id!", '
        'approved_at="soon", input_type=tap, later=1'
    )
    assert parsed == Approval(operation_id="a", revision="b", approver="user")


def test_a_reference_is_opaque_random_and_never_the_same_twice() -> None:
    """`reference` names the agent's own record: the IDs' characters, no personal data, and a
    new one per approval, so two Companies never see the same (Operations 6)."""

    references = {new_approval_reference() for _ in range(64)}
    assert len(references) == 64
    for reference in references:
        assert reference.startswith("apr_") and len(reference) == 36
        assert (
            Approval(operation_id="a", revision="b", approver="user", reference=reference).reference
            == reference
        )
    fixed = new_approval_reference(lambda length: bytes(range(length)))
    assert fixed == "apr_000102030405060708090a0b0c0d0e0f"
    assert client_for().new_reference().startswith("apr_")


def test_extensions_operations_carries_an_operation_an_approval_or_a_decline() -> None:
    declined = ApprovalDeclined(operation_id="cls_2Wq8", revision="r1", reason="No.")
    content = operations_content(declined=declined)
    assert content == {
        "operations": {"declined": {"operation_id": "cls_2Wq8", "revision": "r1", "reason": "No."}}
    }
    message = Message(author=Author(type="agent"), role="company", text="No.", extensions=content)
    assert message.declined == declined and message.operation is None and message.approval is None
    with pytest.raises(ValidationError):
        OperationsContent(operation=returned(), declined=declined)
    with pytest.raises(ValidationError):
        OperationsContent()


def test_a_decline_is_read_from_each_interface() -> None:
    members = {
        "operation_id": "cls_2Wq8",
        "revision": "1791487200-p9Lm3Rt6Vx1c",
        "reason": "Only the account holder can close this account.",
        "alternative": {
            "instructions": "The account holder can close the account in the Example app.",
            "references": [{"type": "web", "url": "https://example.com/account/close"}],
        },
    }
    api = declined_from({"error": APPROVAL_DECLINED, **members})
    tool = declined_from(
        {"isError": True, "structuredContent": {"error": APPROVAL_DECLINED, **members}}
    )
    message = declined_from({"extensions": {"operations": {"declined": members}}})
    assert api == tool == message and api is not None
    assert api.reason == members["reason"] and api.alternative is not None
    assert api.alternative.references[0].url == "https://example.com/account/close"
    assert declined_from({"error": "approval_required", **members}) is None
    assert declined_from({"structuredContent": {"operation": {}}}) is None
    with pytest.raises(ValidationError):
        declined_from({"error": APPROVAL_DECLINED, "reason": "names no operation"})
    # The vendored schema says the same.
    schema = json.loads(
        (
            __import__("pathlib").Path(__file__).parents[2]
            / "protocol"
            / "schemas"
            / "approval-declined.schema.json"
        ).read_text()
    )
    assert schema["required"] == ["operation_id", "revision"]


# Approving: the user, or the agent on the user's instruction -----------------------------


@pytest.mark.asyncio
async def test_a_user_approval_says_user_how_and_under_which_reference() -> None:
    surface = ScriptedApprovals(True)
    approval = await client_for(surface).ask_user(
        returned(), organization=SHOP, tenant_id="t", input_type="tap", reference="apr_ledger_1"
    )
    assert approval == Approval(
        operation_id="exc_5Rt2",
        revision="1791487200-k3Jd9Qx2mW8v",
        approver="user",
        approved_at=int(NOW.timestamp()),
        input_type="tap",
        reference="apr_ledger_1",
    )


@pytest.mark.asyncio
async def test_the_user_is_shown_the_terms_values_when_there_is_no_summary() -> None:
    surface = ScriptedApprovals(True)
    await client_for(surface).ask_user(returned(summary=None), organization=SHOP, tenant_id="t")
    (request,) = surface.asked
    assert request.summary == (
        "order_id: ord_7Hk2\nprice_difference.amount: 70.00\nprice_difference.currency: USD"
    )
    assert request.terms == returned().terms and request.differences == ()


def _gift_wrap(**changes: Any) -> Operation:
    wrap: dict[str, Any] = {
        "summary": "Gift-wrap order ord_7Hk2 before it ships again, USD 5.00.",
        "terms": {"order_id": "ord_7Hk2", "price": {"amount": "5.00", "currency": "USD"}},
    }
    return returned(**{**wrap, **changes})


@pytest.mark.asyncio
async def test_the_agent_approves_only_what_the_users_instruction_covers() -> None:
    """An agent approval rests on an instruction the user gave, checked against the
    revision's terms; nobody is asked, and anything short of a clear yes is the user's
    (Operations 5)."""

    surface = ScriptedApprovals(True)
    client = client_for(surface)
    approval = await client.approve_as_agent(
        _gift_wrap(), instruction=UNDER_TEN, reference="apr_ledger_2"
    )
    assert approval == Approval(
        operation_id="exc_5Rt2",
        revision="1791487200-k3Jd9Qx2mW8v",
        approver="agent",
        approved_at=int(NOW.timestamp()),
        reference="apr_ledger_2",
    )
    assert surface.asked == []  # the surface is the user's: an agent approval never uses it

    async def refused(operation: Operation, instruction: AgentInstruction, **more: Any) -> str:
        with pytest.raises(OperationError) as raised:
            await client.approve_as_agent(operation, instruction=instruction, **more)
        return raised.value.code

    # The instruction says no: USD 50.
    dear = _gift_wrap(
        summary="Gift-wrap order ord_7Hk2, USD 50.00.",
        terms={"order_id": "ord_7Hk2", "price": {"amount": "50.00", "currency": "USD"}},
    )
    assert await refused(dear, UNDER_TEN) == "ask_user"
    # It can't tell: the exchange has no `price`.
    assert await refused(returned(), UNDER_TEN) == "ask_user"
    # Its check failed.
    broken = AgentInstruction(text="x", covers=lambda _: 1 / 0)  # type: ignore[arg-type,return-value]
    assert await refused(_gift_wrap(), broken) == "ask_user"
    # A truthy answer that is not `True` approves nothing.
    assert (
        await refused(_gift_wrap(), AgentInstruction(text="x", covers=lambda _: "yes"))
        == "ask_user"
    )  # type: ignore[arg-type,return-value]
    # The terms differ from what the agent asked for, or from the summary: the user is told.
    assert await refused(_gift_wrap(), ANYTHING, asked={"order_id": "ord_other"}) == "ask_user"
    lying = _gift_wrap(summary="Gift-wrap the order, USD 1.00.")
    assert await refused(lying, ANYTHING) == "ask_user"
    # Past its expiry there is nothing to approve.
    past = _gift_wrap(expires_at="2026-10-10T11:59:59Z")
    assert await refused(past, ANYTHING) == "revision_expired"
    assert surface.asked == []
    with pytest.raises(ValueError):
        AgentInstruction(text="  ", covers=lambda _: True)


@pytest.mark.asyncio
async def test_new_terms_after_an_agent_approval_are_the_users_to_approve() -> None:
    """A new revision in answer to an agent approval is never approved on the same
    instruction (Operations 5); after a user approval it may be."""

    client = client_for(ScriptedApprovals(True))
    first = _gift_wrap()
    newer = _gift_wrap(revision="rev_2")
    approval = await client.approve_as_agent(first, instruction=ANYTHING)
    sent = await client.send(Script(ApiResponse(status=403, operation=newer)), approval)
    assert (sent.status, sent.ask_user) == ("new_revision", True)
    assert client.user_only == {first.operation_id}
    with pytest.raises(OperationError) as raised:
        await client.approve_as_agent(newer, instruction=ANYTHING)
    assert raised.value.code == "ask_user"
    # A host that outlives the client says so itself.
    with pytest.raises(OperationError):
        await client_for().approve_as_agent(newer, instruction=ANYTHING, user_only=True)
    # The user can approve it.
    asked = await client.ask_user(newer, organization=SHOP, tenant_id="t", replaces=first)
    assert asked.approver == "user"
    by_user = Approval(operation_id="exc_9", revision="r1", approver="user")
    after_user = await client.send(
        Script(ApiResponse(status=403, operation=returned(operation_id="exc_9", revision="r2"))),
        by_user,
    )
    assert (after_user.status, after_user.ask_user) == ("new_revision", False)


@pytest.mark.asyncio
async def test_a_declined_approval_is_final_and_never_sent_again() -> None:
    """`approval_declined`: nothing was performed, the approval is not retried, and no new
    revision of the action is approved without the user (Operations 6, 7)."""

    client = client_for()
    operation = _gift_wrap()
    approval = await client.approve_as_agent(operation, instruction=ANYTHING)
    declined = ApprovalDeclined(
        operation_id=operation.operation_id, revision=operation.revision, reason="Not this way."
    )
    request = Script(ApiResponse(status=403, declined=declined), ApiResponse(status=200))
    sent = await client.send(request, approval)
    assert (sent.status, sent.declined, sent.ask_user) == ("declined", declined, True)
    assert len(request.sent) == 1  # a decline is not a failure: no retry
    with pytest.raises(OperationError) as raised:
        await client.approve_as_agent(_gift_wrap(revision="rev_2"), instruction=ANYTHING)
    assert raised.value.code == "ask_user"
    # A decline after a failure is still a decline: it says the operation wasn't performed.
    again = Script(ApiError("x", "x", status_code=503), ApiResponse(status=403, declined=declined))
    assert (await client_for().send(again, approval)).status == "declined"


# The company ------------------------------------------------------------------------------


async def _world(config: Any = None) -> tuple[World, Any, Any, ApiClient]:
    world = World()
    if config is not None:
        world.shop, world.plugin = manzanita(world.network, world.clock, config=config)
    token = await signed_in(world)
    return world, world.session, token, ApiClient(transport=world.transport)


async def _asked(api: ApiClient, session: Any, token: Any, url: str) -> Operation:
    answered = await api.call("POST", url, session=session, token=token, body={})
    assert answered.status == 403 and answered.operation is not None
    return answered.operation


def _stated(operation: Operation, approver: str = "agent", **more: Any) -> Approval:
    return Approval(
        operation_id=operation.operation_id, revision=operation.revision, approver=approver, **more
    )


@pytest.mark.asyncio
async def test_the_company_performs_an_agent_approval_and_records_who_approved() -> None:
    world, session, token, api = await _world()
    operation = await _asked(api, session, token, GIFT_WRAP)
    approval = _stated(operation, approved_at=1791487255, reference="apr_ledger_7")
    done = await api.call(
        "POST", GIFT_WRAP, session=session, token=token, body={}, approval=approval
    )
    assert done.status == 200 and done.declined is None
    record = await world.shop.operation_record(operation.operation_id)
    assert record.status == "performed" and record.approved == operation.revision
    assert record.approval == {
        "approver": "agent",
        "approved_at": 1791487255,
        "reference": "apr_ledger_7",
    }


@pytest.mark.asyncio
async def test_an_approval_with_only_its_approver_is_acted_on() -> None:
    """A Company MUST NOT reject or decline an approval because an optional member is
    missing or its `input_type` is unknown (Operations 6)."""

    world, session, token, api = await _world()
    operation = await _asked(api, session, token, EXCHANGE)
    bare = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_stated(operation, "user")
    )
    assert bare.status == 200
    record = await world.shop.operation_record(operation.operation_id)
    assert record.approval == {"approver": "user"}
    odd = await _asked(api, session, token, GIFT_WRAP)
    done = await api.call(
        "POST",
        GIFT_WRAP,
        session=session,
        token=token,
        body={},
        approval=_stated(odd, "user", input_type="a gesture nobody defined"),
    )
    assert done.status == 200


@pytest.mark.asyncio
async def test_a_version_2_approval_approves_nothing() -> None:
    """Without `approver` the header is no approval: the request is one without an approval,
    answered with the operation and performing nothing."""

    world, session, token, api = await _world()
    operation = await _asked(api, session, token, EXCHANGE)
    raw = await world.transport.request(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        headers={
            "Content-Type": "application/json",
            APPROVAL_HEADER: f'operation_id="{operation.operation_id}", '
            f'revision="{operation.revision}", approved_at=1791487260, input_type="tap"',
        },
        content=b"{}",
    )
    assert raw.status_code == 403 and raw.json()["error"] == "approval_required"
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_a_request_that_declares_operations_2_gets_no_operation() -> None:
    """Version 2 is another major version (Operations 2): the company returns no operation
    to a request that declares it, and says which extension the request needs, in a JSON
    body (§3.3)."""

    world, session, token, api = await _world()
    session.extensions = {"operations": "2"}
    raw = await world.transport.request(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        headers={"Content-Type": "application/json"},
        content=b"{}",
    )
    assert raw.status_code == 403
    assert raw.json() == {"error": "extension_required", "extension": "operations"}
    assert "www-authenticate" not in raw.headers
    with pytest.raises(ApiError) as raised:
        await api.call("POST", EXCHANGE, session=session, token=token, body={})
    assert raised.value.code == "extension_required"
    assert raised.value.details == {"extension": "operations"}
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_manzanita_declines_an_agent_approval_of_a_return_and_takes_the_users() -> None:
    """A decline at an API: HTTP 403, `approval_declined` with the members, a JSON body;
    nothing performed, nothing recorded, no new operation (Operations 6)."""

    world, session, token, api = await _world()
    operation = await _asked(api, session, token, RETURNS)
    by_agent = _stated(operation, reference="apr_ledger_8")
    raw = await world.transport.request(
        "POST",
        RETURNS,
        session=session,
        token=token,
        headers={"Content-Type": "application/json", APPROVAL_HEADER: approval_header(by_agent)},
        content=b"{}",
    )
    assert raw.status_code == 403 and "www-authenticate" not in raw.headers
    assert raw.json() == {
        "error": "approval_declined",
        "operation_id": operation.operation_id,
        "revision": operation.revision,
        "reason": "A return is refunded only when you approve it yourself.",
        "alternative": {
            "instructions": "Approve the return when your personal agent asks you.",
            "references": [{"type": "web", "url": "https://manzanita.example/returns"}],
        },
    }
    answered = await api.call(
        "POST", RETURNS, session=session, token=token, body={}, approval=by_agent
    )
    assert answered.declined is not None and answered.operation is None
    assert answered.declined.alternative is not None
    record = await world.shop.operation_record(operation.operation_id)
    assert (record.status, record.approved, record.approval) == ("open", None, None)
    assert len(record.revisions) == 1  # no new operation, no new revision
    assert world.plugin.returns.performed == []

    # The whole of it through the client: declined, then the user is asked, and theirs works.
    client = client_for(ScriptedApprovals(True))
    sent = await client.send(
        lambda approval: api.call(
            "POST", RETURNS, session=session, token=token, body={}, approval=approval
        ),
        by_agent,
    )
    assert sent.status == "declined" and sent.ask_user
    by_user = _stated(operation, "user", input_type="tap")
    # Manzanita's return fails partway, which is its own story (Operations 7): what matters
    # here is that the company acted on the user's approval of the revision it had declined
    # from the agent.
    with pytest.raises(ApiError) as failed:
        await api.call("POST", RETURNS, session=session, token=token, body={}, approval=by_user)
    assert failed.value.code == "action_failed"
    record = await world.shop.operation_record(operation.operation_id)
    assert record.status == "performed" and record.approval == {
        "approver": "user",
        "input_type": "tap",
    }


def _no_agents(request: DeclineRequest) -> Decline | None:
    assert isinstance(request.operation, Operation) and request.action
    return Decline(reason="Ask the person.") if request.approval.approver == "agent" else None


@pytest.mark.asyncio
async def test_a_tool_declines_with_an_error_result() -> None:
    world, session, _, _ = await _world(dataclasses.replace(CONFIG, decline=_no_agents))
    client = await _mcp(world, session)
    asked = await client.call_tool("exchange_jacket")
    assert asked.operation is not None
    declined = await client.call_tool("exchange_jacket", approval=_stated(asked.operation))
    assert declined.is_error and declined.text == "Ask the person."
    assert declined.structured_content == {
        "error": "approval_declined",
        "operation_id": asked.operation.operation_id,
        "revision": asked.operation.revision,
        "reason": "Ask the person.",
    }
    assert declined.declined is not None and declined.operation is None
    assert world.plugin.executor.performed == []
    done = await client.call_tool("exchange_jacket", approval=_stated(asked.operation, "user"))
    assert not done.is_error and world.plugin.executor.performed == [asked.operation.operation_id]


@pytest.mark.asyncio
async def test_a_conversation_declines_in_a_later_message_without_error() -> None:
    world, session, token, _ = await _world(dataclasses.replace(CONFIG, decline=_no_agents))
    conversation, operation = await _exchange_in_a_conversation(world, session, token)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    def approving(approver: str) -> Message:
        return Message(
            id=world.message("x").id,
            author=Author(type="agent"),
            extensions=operations_content(approval=_stated(operation, approver)),
        )

    page = await world.conversations.send(
        endpoint, conversation, approving("agent"), session=session, token=token, wait=0
    )
    told = _said(page)[-1]
    assert told.declined == ApprovalDeclined(
        operation_id=operation.operation_id, revision=operation.revision, reason="Ask the person."
    )
    assert told.text == "Ask the person." and told.operation is None
    assert "error" not in told.extensions["operations"]["declined"]
    assert world.plugin.executor.performed == []
    page = await world.conversations.send(
        endpoint, conversation, approving("user"), session=session, token=token, wait=0
    )
    assert _said(page)[-1].text.startswith("Exchanged the Ridge Jacket")
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_a_company_sends_terms_always_and_a_summary_when_it_has_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`terms` are required of the company's actions; an operation without a summary goes
    out without one, and a tool's text then says the values (Operations 3, 4)."""

    with pytest.raises(TypeError):
        ProposedOperation(action="orders.note", summary="Add a note.")  # type: ignore[call-arg]
    bare = dataclasses.replace(PROPOSALS["exchanges"], summary=None)
    world, session, token, api = await _world()
    monkeypatch.setitem(PROPOSALS, "exchanges", bare)
    raw = await world.transport.request(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        headers={"Content-Type": "application/json"},
        content=b"{}",
    )
    operation = raw.json()["operation"]
    assert set(operation) == {"operation_id", "revision", "terms", "expires_at"}
    assert operation["terms"] == bare.terms
