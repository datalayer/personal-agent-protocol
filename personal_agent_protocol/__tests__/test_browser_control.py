# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The Browser Control extension, version 1: marks, control, the controller value."""

from __future__ import annotations

import pytest

from personal_agent_protocol import BrowserSessionClient
from personal_agent_protocol.browser_control import (
    BROWSER_CONTROL_EXTENSION,
    BROWSER_CONTROL_VERSION,
    BrowserControl,
    BrowserControlError,
    browser_control_negotiated,
    controller_script,
    controller_update_script,
    on_company_host,
    page_marks,
    user_step_kind,
)
from personal_agent_protocol.demo.kit import AgentIdentity, ControlledBrowser

from .test_company_end_to_end import World
from .test_mcp_and_web import BROWSE, signed_in_with_reference, web_world

PICKUP_PAGE = "https://manzanita.example/orders/ord_7Hk2/pickup"

CHECK_IN = """
<form id="checkin" action="/bookings/bkg_4Rt9/check-in" method="post"
      data-poppy-user-step="submission">
  <label>Seat <select name="seat"><option>12C</option></select></label>
  <label>Passport <input name="passport_number" data-poppy-user-step="interaction"></label>
  <button type="submit">Check in</button>
  <button type="button" name="help">Help</button>
</form>
<input name="newsletter" type="checkbox" form="checkin">
<input name="orphan" form="missing">
<form action="/search"><input name="q"><button>Search</button></form>
<form action="/account" data-poppy-user-step="interaction">
  <input name="email"><input type="submit" value="Save">
</form>
<button data-poppy-user-step="submission" name="pay">Pay</button>
<a href="/x" data-poppy-user-step="interaction">not a control</a>
"""


def test_a_value_other_than_the_two_or_submission_off_a_form_is_interaction() -> None:
    assert user_step_kind(None, on_form=True) is None
    assert user_step_kind("submission", on_form=True) == "submission"
    assert user_step_kind("submission", on_form=False) == "interaction"
    assert user_step_kind("interaction", on_form=True) == "interaction"
    for value in ("", "later", "SUBMISSIONS"):
        assert user_step_kind(value, on_form=True) == "interaction"


def test_marks_add_up_and_cover_what_section_4_says() -> None:
    marks = page_marks(CHECK_IN)
    checkin, search, account = marks.forms
    assert (checkin.mark, search.mark, account.mark) == ("submission", None, "interaction")
    assert marks.marked

    def control(name: str):  # type: ignore[no-untyped-def]
        found = marks.control(name=name)
        assert found is not None, name
        return found

    # A submission form: its controls can be filled in, submitting it is the User's.
    assert marks.may_change(control("seat"))
    assert not marks.may_submit(checkin)
    submit = next(c for c in marks.controls if c.form == checkin.index and c.submits)
    assert not marks.may_change(submit)
    assert marks.may_change(control("help"))  # a plain button submits nothing
    # A marked control inside it is the User's too: marks add up.
    assert not marks.may_change(control("passport_number"))
    # A control outside the form that names it in `form` is the form's own.
    assert control("newsletter").form == checkin.index and marks.may_change(control("newsletter"))
    # A `form` attribute naming no form leaves the control without an owner.
    assert control("orphan").form is None
    # An unmarked form is the agent's.
    assert marks.may_change(control("q")) and marks.may_submit(search)
    # An interaction form: neither its controls nor submitting it.
    assert not marks.may_change(control("email")) and not marks.may_submit(account)
    # `submission` on anything but a form counts as interaction.
    assert control("pay").mark == "interaction" and not marks.may_change(control("pay"))
    assert marks.user_steps()[0] == "submitting the form to /bookings/bkg_4Rt9/check-in"
    assert not page_marks("<form><input name=a></form>").marked


def test_only_the_user_ends_their_control_and_the_model_waits_for_nothing() -> None:
    changes: list[str] = []
    control = BrowserControl(on_change=changes.append)
    marks = page_marks(CHECK_IN)
    checkin = marks.forms[0]
    assert control.controller == "agent"
    control.check_change(marks, marks.control(name="seat"))  # type: ignore[arg-type]
    with pytest.raises(BrowserControlError) as marked:
        control.check_submit(marks, checkin)
    assert marked.value.code == "user_step"
    with pytest.raises(BrowserControlError):
        control.check_change(marks, marks.control(name="passport_number"))  # type: ignore[arg-type]

    assert control.offer(marks)
    control.hand_to_user()
    assert control.controller == "user" and changes == ["user"]
    # While the User holds control nothing the model asks for is done, marked or not.
    with pytest.raises(BrowserControlError) as held:
        control.check_change(marks, marks.control(name="q"))  # type: ignore[arg-type]
    assert held.value.code == "user_has_control"
    with pytest.raises(BrowserControlError):
        control.check_model_action()
    control.hand_back()
    assert control.controller == "agent" and changes == ["user", "agent"]
    control.hand_to_user()
    control.cancel()
    assert changes == ["user", "agent", "user", "agent"]


def test_navigator_poppy_is_only_on_the_companys_hosts() -> None:
    assert on_company_host("manzanita.example", "manzanita.example")
    assert on_company_host("shop.manzanita.example", "Manzanita.Example")
    assert not on_company_host("evilmanzanita.example", "manzanita.example")
    assert not on_company_host("manzanita.example.evil", "manzanita.example")
    script = controller_script("Manzanita.Example", "chan_1")
    assert '"manzanita.example"' in script and 'Symbol.for("chan_1")' in script
    assert 'let controller = "agent"' in script
    assert 'set("user")' in controller_update_script("chan_1", "user")
    with pytest.raises(ValueError):
        controller_update_script("chan_1", "model")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_the_company_lists_browser_control_and_the_join_carries_the_declaration() -> None:
    world, browser = web_world()
    world.atlas = AgentIdentity(
        domain=world.atlas.domain,
        name=world.atlas.name,
        extensions=("operations", BROWSER_CONTROL_EXTENSION),
        private_key=world.atlas.private_key,
        operator_key=world.atlas.operator_key,
    )
    token, _ = await signed_in_with_reference(world, BROWSE)
    session = world.session
    assert session is not None
    document = world.company.document
    assert document.extension(BROWSER_CONTROL_EXTENSION, BROWSER_CONTROL_VERSION) is not None
    assert session.extensions[BROWSER_CONTROL_EXTENSION] == "1"
    assert browser_control_negotiated(document, session)
    await BrowserSessionClient(reactor=world.reactor, transport=world.transport).join(
        browser_session_endpoint=document.web.browser_session_endpoint,  # type: ignore[union-attr,arg-type]
        session=session,
        token=token,
    )
    joined = await world.shop.web_session(browser.http.cookies.get("__Host-poppy_session"))
    assert joined is not None and joined.extensions[BROWSER_CONTROL_EXTENSION] == "1"

    # Manzanita's pickup form is the User's step: the agent fills in the store and stops.
    page = await browser.get(PICKUP_PAGE)
    marks = page_marks(page.text)
    form = marks.forms[0]
    control = BrowserControl()
    control.check_change(marks, marks.control(name="store"))  # type: ignore[arg-type]
    with pytest.raises(BrowserControlError):
        control.check_submit(marks, form)
    with pytest.raises(BrowserControlError):
        control.check_change(marks, marks.control(name="id_last4"))  # type: ignore[arg-type]
    # The User takes control and submits; the page sends navigator.poppy.controller.
    control.hand_to_user()
    done = await browser.submit(
        PICKUP_PAGE, {"store": "Bend", "id_last4": "1234", "controller": control.controller}
    )
    assert done.status_code == 200 and "ready in Bend" in done.text
    assert world.plugin.website.pickups == [{"store": "Bend", "controller": "user"}]
    control.hand_back()


@pytest.mark.asyncio
async def test_a_company_without_the_extension_is_not_negotiated() -> None:
    world = World()
    session = await world.signed_out_session()
    plain = world.company.document.model_copy(
        update={
            "extensions": {
                name: entries
                for name, entries in world.company.document.extensions.items()
                if name != BROWSER_CONTROL_EXTENSION
            }
        }
    )
    assert not browser_control_negotiated(plain, session)
    visitor = ControlledBrowser(world.network.client())
    page = await visitor.get(PICKUP_PAGE)
    assert 'data-poppy-user-step="submission"' in page.text
