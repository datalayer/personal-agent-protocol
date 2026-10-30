# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Operations v2: the operation, the user's approval, the company's checks, at most once."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from reactor import PluginManifest

from personal_agent_protocol import (
    APPROVAL_META_KEY,
    APPROVAL_SURFACES,
    CLOCKS,
    Approval,
    ClientMetadata,
    DiscoveryDocument,
    Message,
    Operation,
    OperationError,
    OperationsClient,
    Organization,
    TransportError,
    approval_header,
    build_pap_reactor,
    operation_from,
    operations_negotiated,
    parse_approval_header,
    terms_differences,
)
from personal_agent_protocol.apis import ApiClient, ApiError, ApiResponse
from personal_agent_protocol.company import (
    ActionResult,
    ProposedOperation,
)
from personal_agent_protocol.company.points import COMPANY_MCP, OPERATION_EXECUTORS
from personal_agent_protocol.demo.kit import ScriptedApprovals
from personal_agent_protocol.mcp import McpClient
from personal_agent_protocol.models import Author
from personal_agent_protocol.reactor import RATE_LIMIT_BUDGETS, first_contribution

from .test_company_end_to_end import World
from .test_company_refusals import signed_in

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"
NOW = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)
EXCHANGE = "https://manzanita.example/api/orders/ord_7Hk2/exchanges"
RETURNS = "https://manzanita.example/api/orders/ord_7Hk2/returns"
REPAIRS = "https://manzanita.example/api/orders/ord_7Hk2/repairs"
SHOP = Organization(name="Shop", domain="shop.example")


def returned(**changes: object) -> Operation:
    data = json.loads((FIXTURES / "operation-valid.json").read_text())
    data.update(changes)
    return Operation.model_validate(data)


class Clock:
    def now(self) -> datetime:
        return NOW


class Host:
    def __init__(self, surface: object | None) -> None:
        self.surface = surface

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(CLOCKS, Clock(), contribution_id="fixed", order=10)
        if self.surface is not None:
            contribute(APPROVAL_SURFACES, self.surface, contribution_id="the-user")


def client_for(surface: object | None = None, **options: Any) -> OperationsClient:
    reactor, _ = build_pap_reactor()
    reactor.register_plugin(PluginManifest(name="host", version="1"), Host(surface))
    return OperationsClient(reactor=reactor, **options)


# The operation ---------------------------------------------------------------------------


def test_the_fixture_is_an_operation_and_a_revision_is_opaque() -> None:
    operation = returned()
    assert operation.revision == "1791487200-k3Jd9Qx2mW8v"
    assert set(operation.model_dump(mode="json")) == {
        "operation_id",
        "revision",
        "summary",
        "terms",
        "expires_at",
    }
    assert "terms" not in returned(terms=None).model_dump(mode="json")


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": 1},
        {"revision": "not an id"},
        {"operation_id": "a/b"},
        {"summary": ""},
        {"expires_at": None},
        {"expires_at": "2026-10-10T18:00:00"},
    ],
)
def test_an_operation_with_another_shape_is_refused(changes: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        returned(**changes)


def test_fields_of_the_old_shape_mean_nothing() -> None:
    old = returned(state="proposed", url="https://shop.example/op", confirmation=None, result=None)
    for name in ("state", "url", "confirmation", "result"):
        assert name not in type(old).model_fields


def test_operation_from_each_interface() -> None:
    operation = returned()
    wire = operation.model_dump(mode="json")
    message = Message(id="msg_1", author=Author(type="agent"), role="company", operation=operation)
    for payload in (
        {"error": "approval_required", "operation": wire},
        {"isError": True, "structuredContent": {"operation": wire}},
        message,
        operation,
    ):
        assert operation_from(payload) == operation
    with pytest.raises(ValueError):
        operation_from({})


def test_a_message_with_only_an_approval_is_a_message_and_a_text_alone_approves_nothing() -> None:
    approval = Approval(operation_id="exc_5Rt2", revision="r1")
    message = Message(id="msg_1", author=Author(type="agent"), approval=approval)
    assert message.model_dump(mode="json", exclude_none=True)["approval"] == {
        "operation_id": "exc_5Rt2",
        "revision": "r1",
    }
    with pytest.raises(ValidationError):
        Message(id="msg_2", author=Author(type="agent"))


def test_operations_are_used_only_when_both_sides_list_version_2() -> None:
    def document(version: str) -> DiscoveryDocument:
        return DiscoveryDocument.model_validate(
            {
                **json.loads((FIXTURES / "discovery-valid.json").read_text()),
                "extensions": {"operations": {"version": version}},
            }
        )

    metadata = json.loads((FIXTURES / "client-metadata-valid.json").read_text())

    def agent(extensions: dict[str, object]) -> ClientMetadata:
        return ClientMetadata.model_validate({**metadata, "extensions": extensions})

    both = agent({"operations": {"version": "2"}})
    assert operations_negotiated(document("2"), both)
    assert not operations_negotiated(document("2"), agent({}))
    assert not operations_negotiated(document("1"), both)
    assert not operations_negotiated(document("2"), agent({"operations": {"version": "1"}}))


# The Poppy-Approval header ------------------------------------------------------------------


def test_the_header_is_a_dictionary_with_two_strings() -> None:
    approval = Approval(operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v")
    value = approval_header(approval)
    assert value == 'operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v"'
    assert parse_approval_header(value) == approval


@pytest.mark.parametrize(
    "value",
    [
        'operation_id="a", revision="b"',
        'revision="b",operation_id="a"',
        'operation_id="a",   revision="b"  ',
        'later=1, operation_id="a", revision="b"',
        'operation_id="a", revision="b", flag',
        'operation_id="a", revision="b", flag=?0, n=1.5, t=tok/en, d=:aGk=:, at=@1659578233',
        'operation_id="a";note="x", revision="b";a;b=2',
        'operation_id="a", revision="b", list=(1 "two" tok);p=1, empty=()',
        'operation_id="a", revision="b", display=%"caf%c3%a9"',
        'operation_id="old", operation_id="a", revision="b"',  # the last one wins
    ],
)
def test_the_header_parses_as_a_dictionary_ignoring_unknown_members(value: str) -> None:
    assert parse_approval_header(value) == Approval(operation_id="a", revision="b")


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "operation_id=a, revision=b",  # Tokens, not Strings
        'operation_id="a"',
        'revision="b"',
        'operation_id="a", revision=1',
        'operation_id="a", revision="not an id"',
        'operation_id="a", revision="b",',  # a trailing comma
        'operation_id="a" revision="b"',
        'operation_id="a", revision="b',  # unterminated
        'Operation_id="a", revision="b"',  # keys are lower case
        'operation_id="a", revision="b", x=(1',
        'operation_id="a", revision="b\\n"',
    ],
)
def test_a_value_that_is_not_such_a_dictionary_is_no_approval(value: str | None) -> None:
    assert parse_approval_header(value) is None


# The terms check ----------------------------------------------------------------------------


def test_the_terms_check_agrees_with_a_summary_that_says_the_same() -> None:
    assert terms_differences(returned()) == ()
    # The spec's own example: identifiers aren't in a summary, written for people.
    spec = returned(
        summary=(
            "Exchange the Stormline Jacket (M) on order ord_7Hk2 for the Stormline Insulated "
            "Jacket (M), for $70.00 more, charged to the card used for the order."
        ),
        terms={
            "order_id": "ord_7Hk2",
            "item_id": "itm_4Qa",
            "replacement_sku": "stormline-insulated-m",
            "price_difference": {"amount": "70.00", "currency": "USD"},
        },
    )
    assert terms_differences(spec) == ()
    assert terms_differences(returned(terms=None)) == ()


def test_the_terms_check_points_out_a_summary_that_says_otherwise() -> None:
    cheaper = returned(summary="Exchange the jacket for USD 7.00 more.")
    differences = terms_differences(cheaper)
    assert differences == (
        "The terms say price_difference.amount 70.00; the summary doesn't.",
        "The summary says 7.00; the terms don't.",
    )


def test_the_terms_check_compares_what_was_asked_for() -> None:
    asked = {"order_id": "ord_7Hk2", "price_difference.currency": "EUR", "gift": "yes"}
    assert terms_differences(returned(), asked) == (
        "You asked for price_difference.currency EUR; the terms say USD.",
        "You asked for gift yes; the terms don't say.",
    )


# Asking the user ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_the_user_is_asked_with_the_company_the_summary_and_any_difference() -> None:
    surface = ScriptedApprovals(True)
    operation = returned(summary="Exchange the jacket for USD 7.00 more.")
    older = returned(summary="Exchange the jacket.", terms={"order_id": "ord_7Hk2"})
    approval = await client_for(surface).ask_user(
        operation, organization=SHOP, tenant_id="tenant", replaces=older
    )
    assert approval == Approval(operation_id=operation.operation_id, revision=operation.revision)
    asked = surface.asked[0]
    assert (asked.company_name, asked.company_domain) == ("Shop", "shop.example")
    assert asked.summary == operation.summary
    assert asked.expires_at == operation.expires_at
    assert asked.terms == operation.terms
    assert len(asked.differences) == 2
    assert asked.changed == (
        "summary",
        "price_difference.amount",
        "price_difference.currency",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", [False, None, "yes", 1])
async def test_only_true_from_the_users_surface_approves(answer: object) -> None:
    class Surface:
        async def approve(self, request: object) -> object:
            return answer

    with pytest.raises(OperationError) as raised:
        await client_for(Surface()).ask_user(returned(), organization=SHOP, tenant_id="t")
    assert raised.value.code == "not_approved"


@pytest.mark.asyncio
async def test_every_operation_is_asked_about_never_approved_on_the_users_behalf() -> None:
    """An approval says nothing of the next one, however like it (Operations 5)."""

    surface = ScriptedApprovals(True, False)
    client = client_for(surface)
    await client.ask_user(returned(), organization=SHOP, tenant_id="t")
    with pytest.raises(OperationError):
        await client.ask_user(returned(revision="r2"), organization=SHOP, tenant_id="t")
    assert len(surface.asked) == 2


@pytest.mark.asyncio
async def test_without_a_surface_nothing_is_approved() -> None:
    with pytest.raises(OperationError) as raised:
        await client_for().ask_user(returned(), organization=SHOP, tenant_id="t")
    assert raised.value.code == "no_approval_surface"


@pytest.mark.asyncio
async def test_a_failing_surface_approves_nothing() -> None:
    class Surface:
        async def approve(self, request: object) -> bool:
            raise RuntimeError("the dialog crashed")

    with pytest.raises(OperationError) as raised:
        await client_for(Surface()).ask_user(returned(), organization=SHOP, tenant_id="t")
    assert raised.value.code == "approval_failed"


@pytest.mark.asyncio
async def test_a_revision_past_its_expiry_is_not_put_to_the_user() -> None:
    surface = ScriptedApprovals(True)
    past = returned(expires_at=(NOW - timedelta(seconds=1)).isoformat())
    with pytest.raises(OperationError) as raised:
        await client_for(surface).ask_user(past, organization=SHOP, tenant_id="t")
    assert raised.value.code == "revision_expired" and surface.asked == []


# Sending the approval -----------------------------------------------------------------------

APPROVAL = Approval(operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v")


def answer(body: object = None, operation: Operation | None = None) -> ApiResponse:
    return ApiResponse(status=403 if operation else 200, body=body, operation=operation)


class Script:
    """A request's answers, in order; an exception is raised."""

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.sent: list[Approval] = []

    async def __call__(self, approval: Approval) -> object:
        self.sent.append(approval)
        next_answer = self.answers.pop(0)
        if isinstance(next_answer, Exception):
            raise next_answer
        return next_answer


@pytest.mark.asyncio
async def test_a_failure_or_timeout_keeps_the_same_approval() -> None:
    waits: list[float] = []

    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    request = Script(
        TransportError("request_failed", "the answer was lost"),
        ApiError("temporarily_unavailable", "x", status_code=503, details={"retry_after": "5"}),
        answer({"summary": "Exchanged."}),
    )
    sent = await client_for(sleep=sleep).send(request, APPROVAL)
    assert sent.status == "answered" and sent.answer.body == {"summary": "Exchanged."}  # type: ignore[union-attr]
    assert request.sent == [APPROVAL] * 3
    assert waits == [5.0]


@pytest.mark.asyncio
async def test_a_new_revision_for_a_first_send_is_for_the_user() -> None:
    newer = returned(revision="r2")
    sent = await client_for().send(Script(answer(operation=newer)), APPROVAL)
    assert sent.status == "new_revision" and sent.operation == newer


@pytest.mark.asyncio
async def test_a_new_operation_in_answer_to_a_retry_says_nothing_of_the_first() -> None:
    """Don't ask the user again until it's known whether the first was performed (Operations 7)."""

    newer = returned(revision="r2")
    request = Script(TransportError("request_failed", "lost"), answer(operation=newer))
    sent = await client_for().send(request, APPROVAL)
    assert sent.status == "unknown" and sent.operation == newer


@pytest.mark.asyncio
async def test_an_answer_with_the_revision_named_is_refused() -> None:
    same = returned()
    with pytest.raises(OperationError) as raised:
        await client_for().send(Script(answer(operation=same)), APPROVAL)
    assert raised.value.code == "invalid_operation"


@pytest.mark.asyncio
async def test_still_unknown_after_every_attempt() -> None:
    unavailable = ApiError("temporarily_unavailable", "x", status_code=503)
    request = Script(unavailable, unavailable, unavailable)
    sent = await client_for().send(request, APPROVAL, attempts=3)
    assert sent.status == "unknown" and sent.operation is None and len(request.sent) == 3


@pytest.mark.asyncio
async def test_a_wait_longer_than_the_client_waits_ends_it() -> None:
    long = ApiError(
        "temporarily_unavailable", "x", status_code=503, details={"retry_after": "3600"}
    )
    request = Script(long, answer())
    sent = await client_for(max_wait=30).send(request, APPROVAL)
    assert sent.status == "unknown" and sent.retry_after == "3600" and len(request.sent) == 1


@pytest.mark.asyncio
async def test_another_refusal_is_raised_and_not_retried() -> None:
    request = Script(ApiError("invalid_token", "x", status_code=401))
    with pytest.raises(ApiError):
        await client_for().send(request, APPROVAL)
    assert len(request.sent) == 1


# The company: asking and performing ----------------------------------------------------------


async def _world(*answers: dict[str, str]) -> tuple[World, Any, Any, ApiClient]:
    world = World(*answers)
    token = await signed_in(world)
    session = world.session
    return world, session, token, ApiClient(transport=world.transport)


async def _ask(api: ApiClient, session: Any, token: Any, url: str = EXCHANGE) -> Operation:
    answered = await api.call("POST", url, session=session, token=token, body={})
    assert answered.status == 403 and answered.operation is not None
    return answered.operation


def _approval(operation: Operation) -> Approval:
    return Approval(operation_id=operation.operation_id, revision=operation.revision)


@pytest.mark.asyncio
async def test_a_request_is_refused_with_the_operation_and_nothing_is_done() -> None:
    world, session, token, _ = await _world()
    raw = await world.transport.request(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        headers={"Content-Type": "application/json"},
        content=b"{}",
    )
    assert raw.status_code == 403
    assert raw.json()["error"] == "approval_required"
    assert set(raw.json()["operation"]) == {
        "operation_id",
        "revision",
        "summary",
        "terms",
        "expires_at",
    }
    assert "www-authenticate" not in raw.headers  # not an authorization error
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_the_same_request_with_the_approval_is_performed_once() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    done = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert done.status == 200 and done.body["summary"].startswith("Exchanged the Ridge Jacket")
    again = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert again.body == done.body
    assert world.plugin.executor.performed == [operation.operation_id]
    record = await world.shop.operation_record(operation.operation_id)
    assert (record.status, record.approved) == ("performed", operation.revision)
    assert record.approved_at == world.clock.now()


@pytest.mark.asyncio
async def test_the_executor_gets_the_revision_approved_with_its_account() -> None:
    world, session, token, api = await _world()
    seen: list[tuple[Operation, str | None]] = []
    perform = world.plugin.executor.perform

    async def spy(operation: Operation, account_id: str | None) -> ActionResult:
        seen.append((operation, account_id))
        return await perform(operation, account_id)

    world.plugin.executor.perform = spy  # type: ignore[method-assign]
    operation = await _ask(api, session, token)
    await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert seen == [(operation, "acct_ada")]


@pytest.mark.asyncio
async def test_a_failed_check_3_answers_a_new_revision_never_the_one_named() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    # A revision the company never returned; then one that expired.
    forged = Approval(operation_id=operation.operation_id, revision="never_returned")
    first = await api.call("POST", EXCHANGE, session=session, token=token, body={}, approval=forged)
    assert first.operation == operation  # still the latest: not the one named
    world.clock.advance(16 * 60)
    token = await world.refreshed()
    second = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert second.status == 403 and second.operation is not None
    assert second.operation.operation_id == operation.operation_id
    assert second.operation.revision != operation.revision
    assert second.operation.expires_at > operation.expires_at
    assert world.plugin.executor.performed == []
    done = await api.call(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        body={},
        approval=_approval(second.operation),
    )
    assert done.status == 200


@pytest.mark.asyncio
async def test_expires_at_is_the_last_time_an_approval_is_accepted() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    world.clock.value = operation.expires_at
    token = await world.refreshed()
    done = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert done.status == 200


@pytest.mark.asyncio
async def test_an_approval_with_another_request_is_refused_with_a_new_revision() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    other = await api.call(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        body={"size": "L"},
        approval=_approval(operation),
    )
    assert other.operation is not None
    assert other.operation.operation_id == operation.operation_id
    assert other.operation.revision != operation.revision
    assert world.plugin.executor.performed == []
    # Whichever revision is approved, once: the first is still good for its own request.
    done = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert done.status == 200
    late = await api.call(
        "POST",
        EXCHANGE,
        session=session,
        token=token,
        body={"size": "L"},
        approval=_approval(other.operation),
    )
    assert late.body == done.body
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_new_terms_from_the_action_are_a_new_revision_of_the_same_operation() -> None:
    world, session, token, api = await _world()
    original = world.plugin  # the demo's API proposes a constant; replace it for the new terms
    operation = await _ask(api, session, token)
    from personal_agent_protocol.demo import manzanita as demo

    dearer = dataclasses.replace(
        demo.EXCHANGE,
        summary="Exchange the Ridge Jacket (M) for USD 90.00 more.",
        terms={"order_id": "ord_7Hk2", "price_difference": {"amount": "90.00", "currency": "USD"}},
    )
    demo.PROPOSALS["exchanges"], kept = dearer, demo.PROPOSALS["exchanges"]
    try:
        answered = await api.call(
            "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
        )
    finally:
        demo.PROPOSALS["exchanges"] = kept
    assert answered.operation is not None and answered.operation.terms == dearer.terms
    assert answered.operation.operation_id == operation.operation_id
    assert answered.operation.revision != operation.revision
    assert original.executor.performed == []


@pytest.mark.asyncio
async def test_the_companys_revision_withdraws_the_earlier_ones() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    current = await world.shop.revise(
        operation.operation_id, summary="Exchange it, in 5 days.", terms={"ships_in_days": 5}
    )
    answered = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert answered.operation == current
    assert world.plugin.executor.performed == []
    done = await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(current)
    )
    assert done.status == 200
    assert (await world.shop.operation_record(operation.operation_id)).approved == current.revision
    with pytest.raises(ValueError):
        await world.shop.revise(operation.operation_id, summary="Too late.", terms={})


@pytest.mark.asyncio
async def test_a_new_request_after_the_action_is_a_new_operation() -> None:
    _, session, token, api = await _world()
    first = await _ask(api, session, token)
    await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(first)
    )
    second = await _ask(api, session, token)
    assert second.operation_id != first.operation_id


@pytest.mark.asyncio
async def test_a_call_says_whether_it_carries_an_approval() -> None:
    """A company's API and tools tell a retry from a first ask, without reading the header."""

    world, session, token, api = await _world()
    company_api = world.shop._api()  # type: ignore[attr-defined]
    answer_api = company_api.handle
    seen: list[bool] = []

    async def handle(call: Any) -> Any:
        seen.append(call.carries_approval)
        return await answer_api(call)

    company_api.handle = handle
    operation = await _ask(api, session, token)
    await api.call(
        "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert seen == [False, True]

    company_mcp = first_contribution(world.shop.reactor, COMPANY_MCP, "MCP server")
    answer_tool = company_mcp.call
    tools: list[bool] = []

    async def call(name: str, arguments: dict[str, Any], details: Any) -> Any:
        tools.append(details.carries_approval)
        return await answer_tool(name, arguments, details)

    company_mcp.call = call
    client = await _mcp(world, session)
    asked = await client.call_tool("exchange_jacket", {"order_id": "ord_other"})
    assert asked.operation is not None
    await client.call_tool(
        "exchange_jacket", {"order_id": "ord_other"}, approval=_approval(asked.operation)
    )
    assert tools == [False, True]


@pytest.mark.asyncio
async def test_a_failed_action_says_what_changed_and_a_retry_gets_the_same_answer() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token, RETURNS)
    errors = []
    for _ in range(2):
        with pytest.raises(ApiError) as raised:
            await api.call(
                "POST",
                RETURNS,
                session=session,
                token=token,
                body={},
                approval=_approval(operation),
            )
        errors.append((raised.value.code, raised.value.status_code))
    assert errors == [("action_failed", 422)] * 2
    # The company's own words, for the host to show; never in the error's text.
    told = raised.value.body
    assert told is not None and told["error"] == "action_failed"
    assert told["data"]["return_label"] and told["summary"] not in str(raised.value)
    assert world.plugin.returns.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_while_it_is_performed_a_retry_gets_503_and_retry_after_never_a_failure() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token, REPAIRS)

    async def no_pause(key: str, seconds: float) -> None:
        """The shared budget would hold each retry for the 503's `Retry-After`."""

    budget = first_contribution(world.reactor, RATE_LIMIT_BUDGETS, "budget")
    budget.defer = no_pause  # type: ignore[attr-defined]
    for _ in range(2):
        with pytest.raises(ApiError) as raised:
            await api.call(
                "POST",
                REPAIRS,
                session=session,
                token=token,
                body={},
                approval=_approval(operation),
            )
        assert raised.value.status_code == 503
        assert raised.value.details == {"retry_after": "5"}
    assert world.plugin.repairs.performed == [operation.operation_id]
    await world.shop.settle(
        operation.operation_id, ActionResult(summary="The repair is booked."), succeeded=True
    )
    done = await api.call(
        "POST", REPAIRS, session=session, token=token, body={}, approval=_approval(operation)
    )
    assert done.body == {"summary": "The repair is booked."}
    with pytest.raises(ValueError):
        await world.shop.settle(operation.operation_id, ActionResult(summary="x"), succeeded=True)


@pytest.mark.asyncio
async def test_two_requests_at_once_perform_it_once() -> None:
    import asyncio

    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    gate = asyncio.Event()
    perform = world.plugin.executor.perform

    async def slow(given: Operation, account_id: str | None) -> ActionResult:
        await gate.wait()
        return await perform(given, account_id)

    world.plugin.executor.perform = slow  # type: ignore[method-assign]
    first = asyncio.create_task(
        api.call(
            "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
        )
    )
    await asyncio.sleep(0.01)
    with pytest.raises(ApiError) as raised:
        await api.call(
            "POST", EXCHANGE, session=session, token=token, body={}, approval=_approval(operation)
        )
    assert raised.value.status_code == 503
    gate.set()
    assert (await first).status == 200
    assert world.plugin.executor.performed == [operation.operation_id]


# The company: who can approve ----------------------------------------------------------------


@pytest.mark.asyncio
async def test_an_operation_returned_signed_out_is_approved_only_in_that_session() -> None:
    world = World()
    session = await world.signed_out_session()
    other = await world.signed_out_session()
    assert session.sid != other.sid
    performed: list[str] = []

    class Everyone:
        action = "orders.note"

        async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
            assert account_id is None
            performed.append(operation.operation_id)
            return ActionResult(summary="Noted.")

    class SignedOutApi:
        description = "Notes"

        def openapi(self) -> dict[str, object]:
            return {}

        async def handle(self, call: Any) -> Any:
            from personal_agent_protocol.company import ApiResult

            return ApiResult(
                operation=ProposedOperation(action="orders.note", summary="Add a note.")
            )

    world.shop.reactor.register_plugin(
        PluginManifest(name="notes", version="1"), _Contribute(Everyone())
    )
    api_of = world.shop._api  # type: ignore[attr-defined]
    world.shop._api = SignedOutApi  # type: ignore[attr-defined,method-assign,assignment]
    try:
        api = ApiClient(transport=world.transport)
        url = "https://manzanita.example/api/notes"
        answered = await api.call("POST", url, session=session, body={})
        assert answered.status == 403 and answered.operation is not None
        operation = answered.operation
        # Another Session of the same agent and user: as if it had no approval.
        elsewhere = await api.call(
            "POST", url, session=other, body={}, approval=_approval(operation)
        )
        assert elsewhere.operation is not None
        assert elsewhere.operation.operation_id != operation.operation_id
        assert performed == []
        # Signing in changes nothing: it can still be approved in that Session (Operations 3).
        token = await signed_in_to(world, session)
        done = await api.call(
            "POST", url, session=session, token=token, body={}, approval=_approval(operation)
        )
        assert done.status == 200 and performed == [operation.operation_id]
    finally:
        world.shop._api = api_of  # type: ignore[attr-defined,method-assign]


async def signed_in_to(world: World, session: Any) -> Any:
    """An access token, for a Session that started signed out (no Session is named, §5.4)."""

    kept = world.session
    token = await signed_in(world)
    world.session = kept or session
    return token


class _Contribute:
    def __init__(self, executor: object) -> None:
        self.executor = executor

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            OPERATION_EXECUTORS, self.executor, contribution_id="notes"
        )


@pytest.mark.asyncio
async def test_any_session_of_the_account_approves_and_a_signed_out_one_gets_a_challenge() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    another = await world.signed_out_session()
    with pytest.raises(ApiError) as raised:
        await api.call("POST", EXCHANGE, session=another, body={}, approval=_approval(operation))
    assert (raised.value.code, raised.value.status_code) == ("insufficient_scope", 401)
    done = await api.call(
        "POST", EXCHANGE, session=another, token=token, body={}, approval=_approval(operation)
    )
    assert done.status == 200
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_a_session_without_the_operations_scopes_is_refused() -> None:
    world, session, token, api = await _world()
    operation = await _ask(api, session, token)
    narrower = await world.refreshed(scopes=("orders:read",))
    with pytest.raises(ApiError) as raised:
        await api.call(
            "POST",
            EXCHANGE,
            session=session,
            token=narrower,
            body={},
            approval=_approval(operation),
        )
    assert (raised.value.code, raised.value.status_code) == ("insufficient_scope", 403)
    assert raised.value.details == {"scope": "orders:write"}


# The company: through MCP and conversations ----------------------------------------------------


async def _mcp(world: World, session: Any) -> McpClient:
    from personal_agent_protocol.accounts import RefreshTokenClient

    result = await RefreshTokenClient(reactor=world.reactor, http_client=world.http).token_for_mcp(
        world.refresh_reference,  # type: ignore[arg-type]
        context=world.account_context(),
        url="https://manzanita.example/mcp",
    )
    return McpClient(
        http_client=world.http,
        url="https://manzanita.example/mcp",
        session=session,
        reactor=world.reactor,
        token=result.token,
    )


@pytest.mark.asyncio
async def test_a_tool_returns_an_error_result_and_the_same_call_with_the_approval_performs() -> (
    None
):
    world, session, _, _ = await _world()
    client = await _mcp(world, session)
    asked = await client.call_tool("exchange_jacket")
    assert asked.is_error and asked.operation is not None
    assert asked.text.startswith("Not done yet. This needs the user's approval:")
    assert asked.structured_content == {"operation": asked.operation.model_dump(mode="json")}
    done = await client.call_tool("exchange_jacket", approval=_approval(asked.operation))
    assert not done.is_error and done.text.startswith("Exchanged the Ridge Jacket")
    again = await client.call_tool("exchange_jacket", approval=_approval(asked.operation))
    assert again.text == done.text
    assert world.plugin.executor.performed == [asked.operation.operation_id]


@pytest.mark.asyncio
async def test_the_mcp_approval_is_read_from_meta_ignoring_unknown_members() -> None:
    world, session, _, _ = await _world()
    client = await _mcp(world, session)
    asked = await client.call_tool("exchange_jacket")
    assert asked.operation is not None
    raw = await client._call(
        "tools/call",
        {
            "name": "exchange_jacket",
            "arguments": {},
            "_meta": {
                APPROVAL_META_KEY: {**_approval(asked.operation).model_dump(), "later": 1},
                "another.example/thing": True,
            },
        },
    )
    assert raw.get("isError") is not True
    assert world.plugin.executor.performed == [asked.operation.operation_id]


@pytest.mark.asyncio
async def test_a_signed_out_call_with_an_approval_gets_the_mcp_challenge() -> None:
    from personal_agent_protocol.mcp import McpError

    world, session, _, _ = await _world()
    asked = await (await _mcp(world, session)).call_tool("exchange_jacket")
    assert asked.operation is not None
    signed_out = McpClient(
        http_client=world.http,
        url="https://manzanita.example/mcp",
        session=await world.signed_out_session(),
        reactor=world.reactor,
    )
    with pytest.raises(McpError) as raised:
        await signed_out.call_tool("exchange_jacket", approval=_approval(asked.operation))
    assert (raised.value.code, raised.value.status_code) == ("insufficient_scope", 401)
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_a_tool_still_being_performed_answers_503() -> None:
    from personal_agent_protocol.mcp import McpError

    world, session, _, _ = await _world()
    client = await _mcp(world, session)
    asked = await client.call_tool("exchange_jacket")
    assert asked.operation is not None

    class Unknown:
        action = "orders.exchange"

        async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
            from personal_agent_protocol.company import OperationOutcomeUnknown

            raise OperationOutcomeUnknown("no answer")

    world.plugin.executor.perform = Unknown().perform  # type: ignore[method-assign,assignment]
    with pytest.raises(McpError) as raised:
        await client.call_tool("exchange_jacket", approval=_approval(asked.operation))
    assert raised.value.status_code == 503 and raised.value.details == {"retry_after": "5"}


async def _exchange_in_a_conversation(world: World, session: Any, token: Any) -> tuple[str, Any]:
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Exchange it for something warmer"),
        session=session,
        token=token,
        wait=0,
    )
    operation = next(
        event.message.operation
        for event in page.events  # type: ignore[union-attr]
        if event.message is not None and event.message.operation is not None
    )
    return page.conversation_id, operation


def _approving(world: World, operation: Operation, **fields: Any) -> Message:
    return Message(
        id=world.message("x").id,
        author=Author(type="agent"),
        approval=_approval(operation),
        **fields,
    )


def _said(page: Any) -> list[Any]:
    return [
        event.message
        for event in page.events
        if event.message is not None and event.message.role == "company"
    ]


@pytest.mark.asyncio
async def test_a_message_with_the_approval_performs_and_a_later_message_says_how_it_went() -> None:
    world, session, token, _ = await _world()
    conversation, operation = await _exchange_in_a_conversation(world, session, token)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    message = _approving(world, operation, text="The user approved the exchange.")
    page = await world.conversations.send(
        endpoint, conversation, message, session=session, token=token, wait=0
    )
    told = _said(page)[-1]
    assert told.text.startswith("Exchanged the Ridge Jacket") and told.operation is None
    assert world.plugin.executor.performed == [operation.operation_id]
    # The same message again gets the original response; a new one adds nothing.
    await world.conversations.send(
        endpoint, conversation, message, session=session, token=token, wait=0
    )
    before = len((await world.shop.conversation_record(conversation)).events)
    await world.conversations.send(
        endpoint,
        conversation,
        _approving(world, operation),
        session=session,
        token=token,
        wait=0,
    )
    after = (await world.shop.conversation_record(conversation)).events[before:]
    assert all(event.payload.get("message", {}).get("role") != "company" for event in after)
    assert world.plugin.executor.performed == [operation.operation_id]


@pytest.mark.asyncio
async def test_a_messages_text_approves_nothing_whatever_it_says() -> None:
    world, session, token, _ = await _world()
    conversation, operation = await _exchange_in_a_conversation(world, session, token)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    await world.conversations.send(
        endpoint,
        conversation,
        world.message(f"I approve {operation.operation_id} revision {operation.revision}"),
        session=session,
        token=token,
        wait=0,
    )
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_a_failed_check_in_a_conversation_is_a_message_with_a_new_revision() -> None:
    world, session, token, _ = await _world()
    conversation, operation = await _exchange_in_a_conversation(world, session, token)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    forged = Message(
        id=world.message("x").id,
        author=Author(type="agent"),
        approval=Approval(operation_id=operation.operation_id, revision="never_returned"),
    )
    page = await world.conversations.send(
        endpoint, conversation, forged, session=session, token=token, wait=0
    )
    told = _said(page)[-1]
    assert told.operation is not None
    assert told.operation.operation_id == operation.operation_id
    assert told.operation.revision != "never_returned"
    assert world.plugin.executor.performed == []


@pytest.mark.asyncio
async def test_an_operation_is_the_conversations_own() -> None:
    world, session, token, _ = await _world()
    conversation, operation = await _exchange_in_a_conversation(world, session, token)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    other = await world.conversations.start(
        endpoint, world.message("Hello"), session=session, token=token, wait=0
    )
    page = await world.conversations.send(
        endpoint,
        other.conversation_id,
        _approving(world, operation),
        session=session,
        token=token,
        wait=0,
    )
    told = _said(page)[-1]
    assert told.operation is not None and told.operation.revision != operation.revision
    assert world.plugin.executor.performed == []
    del conversation


@pytest.mark.asyncio
async def test_a_signed_out_session_approving_in_a_conversation_gets_the_challenge() -> None:
    world, session, token, _ = await _world()
    conversation, operation = await _exchange_in_a_conversation(world, session, token)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    answer_ = await world.transport.request(
        "POST",
        f"{endpoint}/{conversation}/messages",
        session=session,
        headers={"Content-Type": "application/json"},
        content=json.dumps(
            {
                "message": _approving(world, operation).model_dump(mode="json", exclude_none=True),
            }
        ).encode(),
    )
    assert answer_.status_code == 401
    assert world.plugin.executor.performed == []


# Withdrawn --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    ["/poppy/operations/op_1", "/poppy/operations/op_1/confirm", "/poppy/operations/op_1/cancel"],
)
@pytest.mark.asyncio
async def test_the_operations_endpoint_is_gone(path: str) -> None:
    world, session, token, _ = await _world()
    for method in ("GET", "POST"):
        answer_ = await world.transport.request(
            method, f"https://manzanita.example{path}", session=session, token=token
        )
        assert answer_.status_code == 404


def test_the_default_expiry_leaves_the_user_fifteen_minutes() -> None:
    assert World().shop.config.operation_lifetime == timedelta(minutes=15)


def test_the_discovery_entry_has_a_version_and_no_endpoint() -> None:
    world = World()
    assert world.shop.discovery_document()["extensions"]["operations"] == {"version": "2"}


def test_an_old_extension_entry_is_not_this_version() -> None:
    from personal_agent_protocol.demo.kit import AgentIdentity

    assert AgentIdentity(domain="a.example", name="A").metadata["extensions"] == {
        "operations": {"version": "2"}
    }


@pytest.mark.asyncio
async def test_an_agent_listing_version_1_is_not_sent_an_operation() -> None:
    world, session, token, api = await _world()
    from personal_agent_protocol.company.store import CLIENT, KnownClient

    await world.shop.store.put(
        CLIENT, world.atlas.client_id, KnownClient({"operations": "1"}).to_json()
    )
    world.shop._remember_client = _keep  # type: ignore[attr-defined,method-assign,assignment]
    with pytest.raises(ApiError) as raised:
        await api.call("POST", EXCHANGE, session=session, token=token, body={})
    assert raised.value.code == "extension_required"
    assert raised.value.details == {"extension": "operations"}


async def _keep(*_: object) -> None:
    return None
