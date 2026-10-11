# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A sign-in waiting for the person, as a reactor.ui display."""

import json

import pytest
from pydantic import ValidationError

from personal_agent_protocol import build_pap_reactor
from personal_agent_protocol.ui import PAP_SIGN_IN_TYPE, PapSignIn

DEVICE = {
    "status": "waiting_for_the_person",
    "mode": "device",
    "open": "https://manzanita.example/device?user_code=WDJB-MJHT",
    "code": "WDJB-MJHT",
    "expires_at": "2026-10-11T12:15:00+00:00",
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
    assert view["text"].startswith("Sign in at manzanita.example")


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
        }
    )
    assert mediated is not None
    assert "never in this conversation" in mediated.text()
    assert "a•••@example.com" in mediated.text()
    # The page's address, with its ticket, is the page's alone.
    for display in (direct, mediated):
        assert display.open not in json.dumps(display.model_view())


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
