# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Browser Control extension, version 1: steps the Company leaves to the User.

A Company marks the steps it wants the User to take themselves with the
`data-poppy-user-step` attribute (Browser Control 4). A personal agent that declares
the extension, in a browser joined to a Session:

- leaves a marked step to the User: it doesn't change or activate a control a mark
  covers, or submit a form a mark covers, and doesn't remove or change marks
  (`PageMarks`, read from the page's HTML with `page_marks`);
- tells the User the step is theirs and offers them control of the browser; while the
  User holds control its model's browser actions are refused, only the User ends it,
  and nothing waits on the User (`BrowserControl`);
- provides `navigator.poppy.controller`, `"user"` or `"agent"`, on the Company's own
  hosts only (`controller_script`, `controller_update_script`).

The SDK drives no browser: the host's browser runs the scripts and asks `PageMarks`
and `BrowserControl` before each action its model takes. Marks are signals and the
controller value is not a guarantee (Browser Control 8): the Company's servers still
decide.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Literal

from .errors import PersonalAgentProtocolError
from .models import DiscoveryDocument
from .sessions import PapSession

BROWSER_CONTROL_EXTENSION = "browser-control"
#: The version this SDK implements (Browser Control 3).
BROWSER_CONTROL_VERSION = "1"
#: The attribute that marks a step for the User (Browser Control 4).
USER_STEP_ATTRIBUTE = "data-poppy-user-step"

#: Who controls the browser, as `navigator.poppy.controller` says (Browser Control 6).
Controller = Literal["user", "agent"]
#: What a mark asks: the User changes or activates (`interaction`), or submits.
UserStepKind = Literal["interaction", "submission"]

#: The HTML elements a form owns, its listed elements (HTML Standard, *form owner*).
_LISTED = frozenset({"button", "fieldset", "input", "object", "output", "select", "textarea"})
#: The input types that submit their form when activated.
_SUBMIT_INPUTS = frozenset({"submit", "image"})


class BrowserControlError(PersonalAgentProtocolError):
    """A browser action the extension asks the personal agent not to take."""


def browser_control_negotiated(document: DiscoveryDocument, session: PapSession) -> bool:
    """Whether the Company lists `browser-control` version 1 with a browser-session
    endpoint, and the Session declares it (Browser Control 3)."""

    return (
        document.extension(BROWSER_CONTROL_EXTENSION, BROWSER_CONTROL_VERSION) is not None
        and document.web is not None
        and document.web.browser_session_endpoint is not None
        and session.extensions.get(BROWSER_CONTROL_EXTENSION) == BROWSER_CONTROL_VERSION
    )


def user_step_kind(value: str | None, *, on_form: bool) -> UserStepKind | None:
    """What a `data-poppy-user-step` value asks, or `None` without one (Browser Control 4).

    A value other than `interaction` or `submission`, or `submission` on anything but a
    form, counts as `interaction`.
    """

    if value is None:
        return None
    if value.strip().lower() == "submission" and on_form:
        return "submission"
    return "interaction"


@dataclass(frozen=True)
class PageForm:
    """A form on the page: its position, `id`, `action`, `method`, and its mark."""

    index: int
    id: str | None
    action: str | None
    method: str
    mark: UserStepKind | None


@dataclass(frozen=True)
class PageControl:
    """A listed element (`input`, `select`, `button`, …) and the form that owns it.

    `form` is the owner's index: the form it is in, or the one its `form` attribute names
    (HTML Standard, *form owner*); `None` for a control no form owns.
    """

    index: int
    tag: str
    name: str | None
    id: str | None
    type: str | None
    form: int | None
    mark: UserStepKind | None

    @property
    def submits(self) -> bool:
        """Whether activating it submits its form: a submit button or a submit input."""

        if self.tag == "button":
            return (self.type or "submit").lower() == "submit"
        return self.tag == "input" and (self.type or "").lower() in _SUBMIT_INPUTS


@dataclass(frozen=True)
class PageMarks:
    """The marked steps of one page, read from its HTML (Browser Control 4).

    Marks add up: a control inside a `submission` form can be marked `interaction` too,
    and a marked control doesn't mark the rest of its form.
    """

    forms: tuple[PageForm, ...] = ()
    controls: tuple[PageControl, ...] = ()

    @property
    def marked(self) -> bool:
        """Whether the page marks any step for the User."""

        return any(form.mark for form in self.forms) or any(c.mark for c in self.controls)

    def form(self, index: int | None) -> PageForm | None:
        return None if index is None else next((f for f in self.forms if f.index == index), None)

    def may_change(self, control: PageControl) -> bool:
        """Whether the agent may change or activate this control (Browser Control 4, 5).

        Not when it is marked, when its form is marked `interaction`, or when activating it
        submits a form a mark covers. A `submission` form's other controls it may fill in.
        """

        if control.mark is not None:
            return False
        owner = self.form(control.form)
        if owner is not None and owner.mark == "interaction":
            return False
        return not (control.submits and owner is not None and owner.mark is not None)

    def may_submit(self, form: PageForm) -> bool:
        """Whether the agent may submit this form: not when a mark covers it."""

        return form.mark is None

    def control(
        self, *, name: str | None = None, element_id: str | None = None, form: int | None = None
    ) -> PageControl | None:
        """The first control with this `name` or `id` (`element_id`), in `form` when given."""

        for control in self.controls:
            if form is not None and control.form != form:
                continue
            if (name is not None and control.name == name) or (
                element_id is not None and control.id == element_id
            ):
                return control
        return None

    def user_steps(self) -> tuple[str, ...]:
        """The marked steps in words for the User: which step is theirs (Browser Control 5).

        Names and actions come from the page, content from the Company (spec 10.1).
        """

        steps: list[str] = []
        for form in self.forms:
            if form.mark == "submission":
                steps.append(f"submitting the form to {form.action or 'this page'}")
            elif form.mark == "interaction":
                steps.append(f"filling in and submitting the form to {form.action or 'this page'}")
        for control in self.controls:
            if control.mark is not None:
                label = control.name or control.id or control.tag
                steps.append(f"the {control.tag} {label}")
        return tuple(steps)


def _mark_value(values: dict[str, str | None]) -> str | None:
    """The mark's value; an attribute without one is an empty value, still a mark."""

    if USER_STEP_ATTRIBUTE not in values:
        return None
    return values[USER_STEP_ATTRIBUTE] or ""


class _MarksParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[PageForm] = []
        self.controls: list[tuple[int, str, dict[str, str | None], int | None]] = []
        self._open_form: int | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): value for name, value in attrs}
        if tag == "form":
            if self._open_form is not None:
                return  # a form inside a form is ignored by HTML's parser
            index = len(self.forms)
            self.forms.append(
                PageForm(
                    index=index,
                    id=values.get("id"),
                    action=values.get("action"),
                    method=(values.get("method") or "get").lower(),
                    mark=user_step_kind(_mark_value(values), on_form=True),
                )
            )
            self._open_form = index
        elif tag in _LISTED:
            self.controls.append((len(self.controls), tag, values, self._open_form))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._open_form = None


def page_marks(html: str) -> PageMarks:
    """The forms, controls and marks of a page's HTML (Browser Control 4).

    A form's controls are the ones it owns: those inside it, and those outside it whose
    `form` attribute names its `id`; a control whose `form` attribute names no form on
    the page has no owner. The host's browser reads the live page; this reads the HTML
    it was given, so marks a script adds later are the host's to read again.
    """

    parser = _MarksParser()
    parser.feed(html)
    parser.close()
    by_id = {form.id: form.index for form in parser.forms if form.id}
    controls = []
    for index, tag, values, inside in parser.controls:
        owner = inside
        if "form" in values:
            named = values.get("form")
            owner = by_id.get(named) if named else None
        controls.append(
            PageControl(
                index=index,
                tag=tag,
                name=values.get("name"),
                id=values.get("id"),
                type=values.get("type"),
                form=owner,
                mark=user_step_kind(_mark_value(values), on_form=False),
            )
        )
    return PageMarks(forms=tuple(parser.forms), controls=tuple(controls))


def on_company_host(host: str, organization_domain: str) -> bool:
    """Whether `host` is `organization.domain` or one of its subdomains: the only pages
    that get `navigator.poppy` (Browser Control 6)."""

    host, domain = host.lower().rstrip("."), organization_domain.lower().rstrip(".")
    return host == domain or host.endswith(f".{domain}")


def controller_script(organization_domain: str, channel: str) -> str:
    """The script that provides `navigator.poppy.controller` (Browser Control 6).

    The host's browser runs it in every document before the page's own scripts. It
    defines `navigator.poppy` only on the hosts of `organization_domain` and its
    subdomains, so other websites can't tell the browser is a personal agent's; the
    value is read-only for the page, and starts as `"agent"`. `channel` is a random
    name the host keeps, never shown to the model: the host's software, not its model,
    changes the value with `controller_update_script(channel, …)`.
    """

    domain = json.dumps(organization_domain.lower().rstrip("."))
    key = json.dumps(channel)
    return (
        "(() => {"
        f"const domain = {domain};"
        "const host = location.hostname.toLowerCase();"
        'if (host !== domain && !host.endsWith("." + domain)) return;'
        'if ("poppy" in navigator) return;'
        'let controller = "agent";'
        "const poppy = Object.freeze(Object.create(Object.prototype, {"
        "controller: { get: () => controller, enumerable: true },"
        "}));"
        'Object.defineProperty(navigator, "poppy", { value: poppy, enumerable: true });'
        f"Object.defineProperty(window, Symbol.for({key}), {{"
        'value: (value) => { if (value === "user" || value === "agent") controller = value; },'
        "});"
        "})();"
    )


def controller_update_script(channel: str, controller: Controller) -> str:
    """The script the host runs in the page as soon as control changes (Browser Control 6)."""

    if controller not in ("user", "agent"):
        raise ValueError("the controller is user or agent")
    return (
        f"(() => {{ const set = window[Symbol.for({json.dumps(channel)})];"
        f" if (typeof set === 'function') set({json.dumps(controller)}); }})();"
    )


@dataclass
class BrowserControl:
    """Who controls the personal agent's browser, and what its model may do there.

    `controller` starts as `agent`. `hand_to_user` gives the User control, when the host
    offers it and the User takes it; while they hold it `check_model_action` refuses
    every browser action from the model (the website's own scripts keep running), and only
    `hand_back` or `cancel`, which the host calls from the User's own interface, ends it:
    no timeout, page change or Company message does (Browser Control 5). Each change is
    passed to `on_change`, for the host to run `controller_update_script` in its pages.
    Nothing here waits for the User: the host's conversation and requests go on.
    """

    on_change: Callable[[Controller], None] | None = None
    controller: Controller = "agent"
    #: The steps the agent told the User are theirs, for the host's own record.
    offered: list[str] = field(default_factory=list)

    def offer(self, marks: PageMarks) -> tuple[str, ...]:
        """The page's marked steps, to tell the User they are theirs and offer control.

        The host may instead leave the step undone and go on with other work.
        """

        steps = marks.user_steps()
        self.offered.extend(steps)
        return steps

    def hand_to_user(self) -> None:
        """The User takes control: `navigator.poppy.controller` is `"user"` at once."""

        self._set("user")

    def hand_back(self) -> None:
        """The User hands control back; the agent looks at the page again before going on."""

        self._set("agent")

    def cancel(self) -> None:
        """The User cancels their control: the same as handing it back."""

        self._set("agent")

    def check_model_action(self) -> None:
        """Refuse a browser action from the model while the User holds control."""

        if self.controller == "user":
            raise BrowserControlError("user_has_control", "The User holds control of the browser")

    def check_change(self, marks: PageMarks, control: PageControl) -> None:
        """Refuse changing or activating a control a mark covers, or any action while the
        User holds control (Browser Control 5)."""

        self.check_model_action()
        if not marks.may_change(control):
            raise BrowserControlError(
                "user_step", "The Company marked this step for the User to take"
            )

    def check_submit(self, marks: PageMarks, form: PageForm) -> None:
        """Refuse submitting a form a mark covers, by any means (Browser Control 5)."""

        self.check_model_action()
        if not marks.may_submit(form):
            raise BrowserControlError(
                "user_step", "The Company marked submitting this form for the User"
            )

    def _set(self, controller: Controller) -> None:
        if controller == self.controller:
            return
        self.controller = controller
        if self.on_change is not None:
            self.on_change(controller)


__all__ = [
    "BROWSER_CONTROL_EXTENSION",
    "BROWSER_CONTROL_VERSION",
    "USER_STEP_ATTRIBUTE",
    "BrowserControl",
    "BrowserControlError",
    "Controller",
    "PageControl",
    "PageForm",
    "PageMarks",
    "UserStepKind",
    "browser_control_negotiated",
    "controller_script",
    "controller_update_script",
    "on_company_host",
    "page_marks",
    "user_step_kind",
]
