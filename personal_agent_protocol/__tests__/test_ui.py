# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A sign-in, an operation to confirm and what it came to, as reactor.ui displays."""

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from personal_agent_protocol import build_pap_reactor
from personal_agent_protocol.models import Operation
from personal_agent_protocol.ui import (
    PAP_CONFIRM_TYPE,
    PAP_OUTCOME_TYPE,
    PAP_REPLIES_TYPE,
    PAP_SIGN_IN_TYPE,
    PapConfirm,
    PapOutcome,
    PapReplies,
    PapSessionShown,
    PapSignIn,
)

DEVICE = {
    "status": "waiting_for_the_person",
    "mode": "device",
    "open": "https://manzanita.example/device?user_code=WDJB-MJHT",
    "code": "WDJB-MJHT",
    "expires_at": "2026-10-11T12:15:00+00:00",
    "organization_name": "Manzanita",
    "organization_domain": "manzanita.example",
}


def test_a_device_answer_is_a_display_whose_code_only_the_page_sees() -> None:
    display = PapSignIn.from_answer(DEVICE)
    assert display is not None
    wire = display.wire()
    assert wire.type == PAP_SIGN_IN_TYPE
    assert wire.version == 1
    assert wire.data["code"] == "WDJB-MJHT"
    assert wire.data["expires_at"] == "2026-10-11T12:15:00Z"
    assert wire.data["open"] == DEVICE["open"]
    # Neither the code nor the verification URL carrying it reaches a model:
    # checked against everything the model is given, not the text alone.
    view = display.model_view()
    assert "code" not in view["data"] and "open" not in view["data"]
    seen = json.dumps(view)
    assert "WDJB-MJHT" not in seen and "user_code" not in seen
    # The company that asks, by its name and domain (§4.6).
    assert view["text"].startswith("Sign in to Manzanita (manzanita.example) at manzanita.example")


def test_direct_and_mediated_answers() -> None:
    direct = PapSignIn.from_answer(
        {
            "status": "waiting_for_the_person",
            "mode": "direct",
            "open": "https://a.example/authorize",
        }
    )
    assert direct is not None and direct.code is None
    mediated = PapSignIn.from_answer(
        {
            "status": "waiting_for_the_person",
            "mode": "mediated",
            "open": "https://studio.example/pap/sign-in?ticket=t",
            "sent_to": "a•••@example.com",
            "organization_name": "Example",
            "organization_domain": "example.com",
        }
    )
    assert mediated is not None
    assert "never in this conversation" in mediated.text()
    # Asked for credentials or a code, the person sees which company asks (§4.7).
    assert "Example (example.com)" in mediated.text()
    assert "a•••@example.com" in mediated.text()
    # The page's address, with its ticket, is the page's alone.
    for display in (direct, mediated):
        assert display.open not in json.dumps(display.model_view())


def test_a_bound_direct_sign_in_names_the_company_not_the_hosts_link() -> None:
    """A host that binds Direct Sign-In (Datalayer's one-use start link, PAP_DATALAYER P-04) opens
    its own page, which sends the person on to the company: the display names the company where
    they sign in, and the page they open is the host's — said so, never the link itself."""
    bound = PapSignIn.from_answer(
        {
            "status": "waiting_for_the_person",
            "mode": "direct",
            "open": "https://iam.example/pap/start?ticket=t",
            "company": "Manzanita.Example",
        }
    )
    assert bound is not None and (bound.company, bound.at, bound.host) == (
        "manzanita.example",
        "manzanita.example",
        "iam.example",
    )
    assert bound.text().startswith(
        "Sign in at manzanita.example: open its sign-in page, shown here (through iam.example"
    )
    assert "ticket" not in json.dumps(bound.model_view())
    # Unbound, the page's own domain is the company's.
    plain = PapSignIn(mode="direct", open="https://a.example/authorize")
    assert (plain.company, plain.at) == (None, "a.example")
    with pytest.raises(ValidationError):
        PapSignIn(mode="direct", open="https://iam.example/pap/start", company="not a domain")


def test_a_sign_in_names_what_the_company_said_it_needs() -> None:
    """Signed out first (PAP_DATALAYER P-02): the sign-in is asked for once the company's
    `authorization` event says what it needs, and the person and the model are told that scope."""
    asked = PapSignIn.from_answer(
        {
            "status": "waiting_for_the_person",
            "mode": "direct",
            "open": "https://iam.example/pap/start?ticket=t",
            "company": "manzanita.example",
            "needs": ["orders:read", "orders:write"],
        }
    )
    assert asked is not None and asked.needs == ["orders:read", "orders:write"]
    assert asked.text().endswith(" It needs: orders:read, orders:write.")
    assert asked.model_view()["data"]["needs"] == ["orders:read", "orders:write"]
    assert PapSignIn(mode="direct", open="https://a.example/authorize").needs == []
    with pytest.raises(ValidationError):
        PapSignIn(
            mode="direct", open="https://a.example/authorize", needs=["orders:read orders:write"]
        )


def test_another_status_is_no_display() -> None:
    assert PapSignIn.from_answer({"status": "unavailable", "reason": "no"}) is None


@pytest.mark.parametrize(
    "open_", ["http://a.example/x", "javascript:alert(1)", "https://user:pw@a.example/", ""]
)
def test_only_an_https_page_is_offered(open_: str) -> None:
    with pytest.raises(ValidationError):
        PapSignIn(mode="direct", open=open_)


def test_a_device_sign_in_needs_its_code() -> None:
    with pytest.raises(ValidationError):
        PapSignIn(mode="device", open="https://a.example/device")


def test_the_tool_meta_carries_the_wire_display() -> None:
    display = PapSignIn(id="s1", mode="direct", open="https://a.example/authorize")
    meta = display.tool_meta()
    assert meta["reactor.ui/display"]["type"] == PAP_SIGN_IN_TYPE
    assert meta["reactor.ui/display"]["id"] == "s1"
    assert meta["reactor.ui/display"]["text"] == display.text()


async def test_the_core_plugin_declares_the_type() -> None:
    platform, http = build_pap_reactor()
    try:
        assert platform.display_types().get(PAP_SIGN_IN_TYPE, 1) is PapSignIn
    finally:
        if http is not None:
            await http.aclose()


# An operation waiting for the person to confirm it (PapConfirm).

FIXTURE = Path(__file__).parents[2] / "protocol" / "fixtures" / "pap-confirm-display.json"
SESSION_ID = "ses_8c1f0e6a2b4d4f0e9a7c3d5b1e2f4a6c"


def _confirm(**overrides: Any) -> PapConfirm:
    fields: dict[str, Any] = {
        "id": "confirm-op_7Hq2",
        "company": "manzanita.example",
        "summary": (
            "Exchange the Ridge Jacket (M) for the Alpine Parka (M). You pay USD 70.00 more."
        ),
        "terms": {
            "price_difference": {"amount": "70.00", "currency": "USD"},
            "ships_in_days": 5,
        },
        "operation_ref": "op_7Hq2",
        "revision": 2,
        "does": "buy",
        "session": PapSessionShown.of(SESSION_ID, signed_in=True),
        "expires_at": "2026-10-12T18:00:00+00:00",
        "was": {
            "revision": 1,
            "terms": {
                "price_difference": {"amount": "70.00", "currency": "USD"},
                "ships_in_days": 2,
            },
        },
        "only_the_person": True,
    }
    fields.update(overrides)
    return PapConfirm.model_validate(fields)


def test_an_operation_to_confirm_is_the_committed_display_both_sdks_read() -> None:
    # The TypeScript SDK reads the same file (src/__tests__/ui.test.mjs): one shape on both tiers.
    wire = _confirm().wire().model_dump(mode="json")
    assert wire == json.loads(FIXTURE.read_text())
    assert wire["type"] == PAP_CONFIRM_TYPE and wire["version"] == 1
    assert wire["data"]["session"] == {
        "ref": hashlib.sha256(SESSION_ID.encode()).hexdigest()[:12],
        "signed_in": True,
    }
    assert wire["text"] == (
        "manzanita.example asks you to confirm: "
        "Exchange the Ridge Jacket (M) for the Alpine Parka (M). "
        "You pay USD 70.00 more. (version 2) Changed since version 1."
    )


def test_a_model_is_told_what_is_asked_never_the_session() -> None:
    display = _confirm()
    view = display.model_view()
    # The company's words, the terms, what it does and which revision: what a model needs to
    # confirm it.
    assert view["data"]["summary"] == display.summary and view["data"]["does"] == "buy"
    assert (view["data"]["operation_ref"], view["data"]["revision"]) == ("op_7Hq2", 2)
    # Whether the person is signed in there, never which Session: not its ID, not even the
    # reference.
    assert view["data"]["session"] == {"signed_in": True}
    seen = json.dumps(view)
    assert (
        SESSION_ID not in seen and display.session is not None and display.session.ref not in seen
    )


def test_the_session_is_shown_by_a_one_way_reference_only() -> None:
    with pytest.raises(ValidationError):
        PapSessionShown(ref=SESSION_ID, signed_in=True)
    with pytest.raises(ValueError):
        PapSessionShown.of("", signed_in=False)


@pytest.mark.parametrize(
    "overrides",
    [
        {"company": "  "},
        {"summary": ""},
        {"operation_ref": ""},
        {"revision": 0},
        {"does": "spend"},
        {"was": {"revision": 2, "terms": {}}},
        {"token": "secret"},
    ],
)
def test_an_operation_to_confirm_is_refused_when_it_says_less_or_other(
    overrides: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError):
        _confirm(**overrides)


def test_the_confirm_tool_meta_carries_the_wire_display() -> None:
    display = _confirm(session=None, was=None, does=None, only_the_person=False)
    meta = display.tool_meta()["reactor.ui/display"]
    assert meta["type"] == PAP_CONFIRM_TYPE and meta["text"] == display.text()
    assert meta["data"]["session"] is None and meta["data"]["was"] is None


async def test_the_core_plugin_declares_the_confirm_type() -> None:
    platform, http = build_pap_reactor()
    try:
        registry = platform.display_types()
        assert registry.get(PAP_CONFIRM_TYPE, 1) is PapConfirm
        assert registry.parse(json.loads(FIXTURE.read_text())) == _confirm()
    finally:
        if http is not None:
            await http.aclose()


# What a confirmed operation came to (PapOutcome).

OUTCOME_FIXTURE = Path(__file__).parents[2] / "protocol" / "fixtures" / "pap-outcome-display.json"
EXCHANGE = "Exchange the Ridge Jacket (M) for the Alpine Parka (M). You pay USD 70.00 more."
PARTIAL = (
    "The Alpine Parka (M) is reserved for you, but the refund of the Ridge Jacket failed: "
    "USD 70.00 was charged and nothing was refunded yet."
)


def _operation(state: str, result: str | None) -> Operation:
    return Operation.model_validate(
        {
            "operation_id": "op_7Hq2",
            "revision": 2,
            "state": state,
            "summary": EXCHANGE,
            "confirmation": None
            if state == "proposed"
            else {
                "revision": 2,
                "approved_by": "user",
                "confirmed_at": "2026-10-12T17:00:00+00:00",
            },
            "result": None if result is None else {"summary": result},
            **({"expires_at": "2026-10-12T18:00:00+00:00"} if state == "proposed" else {}),
        }
    )


def test_a_failed_operation_is_the_committed_display_its_partial_effects_verbatim() -> None:
    # The TypeScript SDK reads the same file (src/__tests__/ui.test.mjs).
    display = PapOutcome.of("manzanita.example", _operation("failed", PARTIAL), approved_by="user")
    wire = display.wire().model_dump(mode="json")
    assert wire == json.loads(OUTCOME_FIXTURE.read_text())
    assert wire["type"] == PAP_OUTCOME_TYPE and wire["version"] == 1
    assert wire["id"] == "op_7Hq2-2-outcome"
    assert wire["data"]["result"] == PARTIAL
    assert wire["text"] == f"Failed at manzanita.example: {PARTIAL} (version 2)"


def test_each_outcome_says_the_companys_words() -> None:
    done = PapOutcome.of(
        "manzanita.example", _operation("succeeded", "Exchange placed: order 1043.")
    )
    assert done.text() == "Done at manzanita.example: Exchange placed: order 1043. (version 2)"
    # Sent, its answer lost: read back as proposed, said as in progress until the outcome is known.
    sent = PapOutcome.of("manzanita.example", _operation("proposed", None))
    assert sent.state == "in_progress" and sent.result is None
    assert sent.text() == (
        f"Still in progress at manzanita.example: {EXCHANGE} (version 2) "
        "The outcome is not known yet."
    )
    cancelled = PapOutcome.of(
        "manzanita.example", _operation("cancelled", "Cancelled at your request.")
    )
    assert (
        cancelled.text() == "Cancelled at manzanita.example: Cancelled at your request. (version 2)"
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"company": " "},
        {"summary": ""},
        {"operation_ref": ""},
        {"revision": 0},
        {"state": "proposed"},
        {"result": " "},
        {"state": "in_progress", "result": "done"},
        {"state": "failed", "result": None},
        {"approved_by": "rule"},
        {"token": "secret"},
    ],
)
def test_an_outcome_is_refused_when_it_says_less_or_other(overrides: dict[str, Any]) -> None:
    fields = PapOutcome.of("manzanita.example", _operation("succeeded", "Done.")).model_dump()
    fields.update(overrides)
    with pytest.raises(ValidationError):
        PapOutcome.model_validate(fields)


async def test_the_core_plugin_declares_the_outcome_type() -> None:
    platform, http = build_pap_reactor()
    try:
        registry = platform.display_types()
        assert registry.get(PAP_OUTCOME_TYPE, 1) is PapOutcome
        shown = registry.parse(json.loads(OUTCOME_FIXTURE.read_text()))
        assert shown.tool_meta()["reactor.ui/display"]["data"]["result"] == PARTIAL
    finally:
        if http is not None:
            await http.aclose()


REPLIES_FIXTURE = Path(__file__).parents[2] / "protocol" / "fixtures" / "pap-replies-display.json"


def _message(
    id_: str, author: str, text: str | None, role: str = "company", name: str | None = None
) -> Any:
    from personal_agent_protocol.models import Author, Message

    data = None if text else {"order": "1043"}
    return Message(id=id_, author=Author(type=author, name=name), role=role, text=text, data=data)


def _replies() -> PapReplies:
    replies = PapReplies.of(
        "manzanita.example",
        "conv_4Kp9",
        [
            _message("msg_1", "agent", "Your Ridge Jacket shipped on Tuesday."),
            _message("msg_2", "human", "I can exchange it for you.", name="Rosa"),
        ],
        status="idle",
        responder="human",
    )
    assert replies is not None
    return replies


def test_replies_are_the_committed_display_each_with_who_wrote_it() -> None:
    # The TypeScript SDK reads the same file (src/__tests__/ui.test.mjs).
    wire = _replies().wire().model_dump(mode="json")
    assert wire == json.loads(REPLIES_FIXTURE.read_text())
    assert wire["type"] == PAP_REPLIES_TYPE and wire["version"] == 3
    assert wire["id"] == "conv_4Kp9-msg_1-replies"
    # The conversation the replies are in: where the person's own words open a Direct Conversation.
    assert wire["data"]["conversation"] == "conv_4Kp9"
    assert [reply["author"] for reply in wire["data"]["replies"]] == ["agent", "human"]
    # A person the company names is named on the page (§7.4).
    assert wire["data"]["replies"][1]["name"] == "Rosa"
    assert wire["text"] == (
        "manzanita.example, its agent: Your Ridge Jacket shipped on Tuesday.\n"
        "manzanita.example, one of its people (Rosa): I can exchange it for you."
    )


def test_only_the_companys_own_words_are_replies() -> None:
    # The personal agent's own message, and a company message carrying only data, are not drawn.
    assert (
        PapReplies.of(
            "manzanita.example",
            "conv_4Kp9",
            [
                _message("msg_0", "agent", "Where is my order?", role="user"),
                _message("msg_1", "agent", None),
            ],
        )
        is None
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"company": " "},
        {"conversation": ""},
        {"conversation": "has space"},
        {"replies": []},
        {"replies": [{"author": "model", "text": "Hello"}]},
        {"replies": [{"author": {"type": "agent"}, "text": " "}]},
        {"replies": [{"author": {"type": "agent"}, "text": "Hello", "token": "secret"}]},
        {"token": "secret"},
    ],
)
def test_replies_are_refused_when_they_say_less_or_other(overrides: dict[str, Any]) -> None:
    fields = _replies().model_dump()
    fields.update(overrides)
    with pytest.raises(ValidationError):
        PapReplies.model_validate(fields)


def test_an_unknown_status_reads_as_working_and_an_unknown_responder_as_human() -> None:
    """Later versions may add values (§8.7): read as the most careful known one."""

    fields = _replies().model_dump()
    shown = PapReplies.model_validate({**fields, "status": "paused", "responder": "robot"})
    assert (shown.status, shown.responder) == ("working", "human")
    built = PapReplies.of(
        "manzanita.example",
        "conv_4Kp9",
        [_message("msg_1", "agent", "Hello", role="company")],
        status="paused",
        responder="robot",
    )
    assert built is not None and (built.status, built.responder) == ("working", "human")


async def test_the_core_plugin_declares_the_replies_type() -> None:
    platform, http = build_pap_reactor()
    try:
        registry = platform.display_types()
        assert registry.get(PAP_REPLIES_TYPE, 3) is PapReplies
        shown = registry.parse(json.loads(REPLIES_FIXTURE.read_text()))
        assert shown.tool_meta()["reactor.ui/display"]["data"]["responder"] == "human"
    finally:
        if http is not None:
            await http.aclose()


def test_a_device_or_mediated_sign_in_names_its_company() -> None:
    """Whenever a person is asked for a code or credentials, the company is named (§4.6, §4.7)."""
    for mode, extra in (("device", {"code": "ABCD-EFGH"}), ("mediated", {})):
        with pytest.raises(ValidationError, match="names the company"):
            PapSignIn(mode=mode, open="https://a.example/sign-in", **extra)  # type: ignore[arg-type]
        named = PapSignIn(
            mode=mode,  # type: ignore[arg-type]
            open="https://a.example/sign-in",
            organization_name="A Company",
            organization_domain="A.Example",
            **extra,
        )
        assert named.organization == "A Company (a.example)"
        assert "A Company (a.example)" in named.text()
