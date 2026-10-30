# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Feedback (§8): a task the protocol can't do, reported once, as data."""

from __future__ import annotations

import dataclasses
import json

import httpx
import pytest
from pydantic import ValidationError
from reactor import PluginManifest

from personal_agent_protocol import (
    FeedbackClient,
    FeedbackError,
    FeedbackReport,
    feedback_endpoint,
)
from personal_agent_protocol.company import COMPANY_RATE_LIMITS

from .test_company_end_to_end import PAIRWISE, World
from .test_company_refusals import signed_in

FEEDBACK = "https://manzanita.example/poppy/feedback"
GIFT_CARD = FeedbackReport(
    task="Pay with a gift card",
    description=(
        "The User wanted to pay for a new order with a gift card they were given. Neither the "
        "API nor the Company Agent can apply a gift card."
    ),
)


def test_a_report_is_task_and_description_only() -> None:
    assert GIFT_CARD.model_dump() == {
        "task": "Pay with a gift card",
        "description": GIFT_CARD.description,
    }
    # No `kind` (3e9bada), and nothing else rides along (§9.3).
    with pytest.raises(ValidationError):
        FeedbackReport(kind="missing", task="x", description="y")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        FeedbackReport(task="x", description="y", user="Ada")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        FeedbackReport(task="x" * 201, description="y")
    with pytest.raises(ValidationError):
        FeedbackReport(task="x", description="y" * 2001)
    with pytest.raises(ValidationError):
        FeedbackReport(task="", description="y")
    assert FeedbackReport(task="x" * 200, description="y" * 2000).task == "x" * 200


@pytest.mark.asyncio
async def test_a_signed_out_and_a_signed_in_session_report_with_no_scope() -> None:
    world = World()
    session = await world.signed_out_session()
    endpoint = feedback_endpoint(world.company.document)
    assert endpoint == FEEDBACK
    client = FeedbackClient(transport=world.transport)
    # The task can be done after all: 200 and an alternative, content from the company (§9.3).
    alternative = await client.report(endpoint, GIFT_CARD, session=session)
    assert alternative is not None and alternative.instructions
    assert [r.type for r in alternative.usable_references(world.company.document)] == ["web"]
    token = await signed_in(world)
    await client.report(
        endpoint,
        FeedbackReport(task="Return a jacket", description="No return option in any channel."),
        session=world.session,
        token=token,
    )
    reports = await world.shop.feedback_reports()
    assert [report.task for report in reports] == ["Pay with a gift card", "Return a jacket"]
    # The Session says which personal agent and which user sent it; the report doesn't.
    assert {report.client_id for report in reports} == {world.atlas.client_id}
    assert {report.pairwise_user_id for report in reports} == {PAIRWISE}


@pytest.mark.asyncio
async def test_the_company_ignores_unknown_members_and_refuses_a_malformed_report() -> None:
    world = World()
    session = await world.signed_out_session()

    async def post(body: object) -> httpx.Response:
        return await world.transport.request(
            "POST",
            FEEDBACK,
            session=session,
            headers={"Content-Type": "application/json"},
            content=json.dumps(body).encode(),
        )

    # A member it doesn't recognize, such as the withdrawn `kind`, is ignored (§9.3).
    accepted = await post({"kind": "slow", "task": "Track a parcel", "description": "Took ages."})
    assert accepted.status_code == 202 and accepted.content == b""
    assert (await world.shop.feedback_reports())[0].task == "Track a parcel"
    for body in (
        {"task": "x" * 201, "description": "too long a task"},
        {"task": "x", "description": "y" * 2001},
        {"task": "x"},
        {"description": "y"},
        ["not", "an", "object"],
    ):
        refused = await post(body)
        assert refused.status_code == 400 and refused.json() == {"error": "invalid_request"}
    # Only with the Session header.
    bare = await world.http.post(FEEDBACK, json=GIFT_CARD.model_dump())
    assert (bare.status_code, bare.json()) == (400, {"error": "invalid_session"})
    assert len(await world.shop.feedback_reports()) == 1


@pytest.mark.asyncio
async def test_feedback_refusals_carry_their_code_and_retry_after() -> None:
    class Limited:
        async def admit(self, client_id: str, account_id: str | None) -> int | None:
            return 30

    class Limit:
        def provide_contributions(self, contributions: object) -> None:
            contributions.contribute(COMPANY_RATE_LIMITS, Limited(), contribution_id="limit")  # type: ignore[attr-defined]

    world = World()
    session = await world.signed_out_session()
    world.shop.reactor.register_plugin(PluginManifest(name="limit", version="1"), Limit())
    with pytest.raises(FeedbackError) as raised:
        await FeedbackClient(transport=world.transport).report(FEEDBACK, GIFT_CARD, session=session)
    assert (raised.value.code, raised.value.status_code) == ("rate_limited", 429)
    assert raised.value.details == {"retry_after": "30"}


@pytest.mark.asyncio
async def test_a_company_without_feedback_neither_lists_nor_accepts_it() -> None:
    world = World()
    world.shop.config = dataclasses.replace(world.shop.config, feedback=False)
    session = await world.signed_out_session()
    assert feedback_endpoint(world.company.document) is None
    with pytest.raises(FeedbackError) as raised:
        await FeedbackClient(transport=world.transport).report(FEEDBACK, GIFT_CARD, session=session)
    assert raised.value.status_code == 404
