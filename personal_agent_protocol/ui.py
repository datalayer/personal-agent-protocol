# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP's displays for ``reactor.ui``: what a page draws for a PAP answer.

Two displays: :class:`PapSignIn`, a sign-in waiting for the person, and
:class:`PapConfirm`, an operation a company proposed, waiting for the person to
confirm it.

A tool that starts a sign-in answers with a :class:`PapSignIn` beside its
result — in an MCP result's ``_meta["reactor.ui/display"]`` — and any page with
a renderer for ``application/vnd.datalayer.pap.sign-in+json`` draws *Sign in
at a company*; a page without one shows the display's text.

The display type lives here, in the package both tiers already depend on for
PAP, not in a host. It needs ``datalayer_reactor`` 1.1 (``reactor.ui``), the
``ui`` extra; importing this module is the only thing that does, so the rest
of the SDK keeps working on an older reactor.

What the person types never travels in a display, and the page to open and
the code to enter are for the page only: a device's verification URL may
carry the code, so :meth:`~reactor.ui.Display.model_view` leaves both out and
the text names only the company's domain. Nor does a Session's ID or token:
a :class:`PapConfirm` names the Session by a one-way reference, and only the
page sees even that.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from reactor.ui import (  # type: ignore[import-untyped]
    DISPLAY_META_KEY,
    Display,
    audience,
    display_type,
)

#: The display type of a sign-in waiting for the person.
PAP_SIGN_IN_TYPE = "application/vnd.datalayer.pap.sign-in+json"

#: The display type of an operation waiting for the person to confirm it.
PAP_CONFIRM_TYPE = "application/vnd.datalayer.pap.confirm+json"

#: What confirming an operation does, as an application's Rules class it.
PapActionClass = Literal["read", "write", "send", "buy", "delete", "publish"]

#: The status a sign-in tool answers while the person has something to do.
WAITING_FOR_THE_PERSON = "waiting_for_the_person"


@display_type(PAP_SIGN_IN_TYPE, version=1)
class PapSignIn(Display):
    """A sign-in waiting for the person (PAP_DATALAYER P-03).

    ``direct``: the company's page, then back. ``device``: the company's page
    and a code to enter there. ``mediated``: Datalayer's own page, where the
    person types what the company asks — never in the conversation; ``sent_to``
    says where the company sent a code, when it did.
    """

    mode: Literal["direct", "device", "mediated"]
    #: The page to open, ``https`` only. For the page alone: a device's
    #: verification URL may carry the code.
    open: Annotated[str, audience("page")]
    #: The code to enter, for ``device``. The page shows it; a model is not told.
    code: Annotated[str | None, audience("page")] = None
    #: Until when the sign-in can be finished.
    expires_at: datetime | None = None
    #: Where the company sent a code, for ``mediated``.
    sent_to: str | None = None

    @field_validator("open")
    @classmethod
    def _https(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("a sign-in page must be an HTTPS URL")
        return value

    @model_validator(mode="after")
    def _code_for_device(self) -> PapSignIn:
        if self.mode == "device" and not self.code:
            raise ValueError("a device sign-in needs its code")
        return self

    @property
    def host(self) -> str:
        """The page's domain: what the person can check before signing in."""
        return urlsplit(self.open).hostname or ""

    def text(self) -> str:
        # Neither the page nor the code: the text is also what a model and a
        # transcript read, and a verification URL may carry the code.
        if self.mode == "direct":
            return (
                f"Sign in at {self.host}: open its sign-in page, shown here, "
                "sign in there, and come back."
            )
        if self.mode == "device":
            return (
                f"Sign in at {self.host}: open its sign-in page, shown here, "
                "and enter the code shown with it."
            )
        sent = f" A code was sent to {self.sent_to}." if self.sent_to else ""
        return (
            f"Sign in at {self.host}: open the page shown here and type what the company "
            f"asks there, never in this conversation.{sent}"
        )

    @classmethod
    def from_answer(cls, answer: dict[str, Any]) -> PapSignIn | None:
        """The display for a ``pap_sign_in`` answer, or ``None`` for any other status."""
        if answer.get("status") != WAITING_FOR_THE_PERSON:
            return None
        fields = ("mode", "open", "code", "expires_at", "sent_to")
        return cls.model_validate({key: answer[key] for key in fields if answer.get(key)})

    def tool_meta(self) -> dict[str, Any]:
        """The ``_meta`` an MCP tool result carries this display in."""
        return {DISPLAY_META_KEY: self.wire().model_dump(mode="json")}


class PapSessionShown(BaseModel):
    """The Session an operation is confirmed in, as the person's card names it.

    ``ref`` is one-way — the first 12 hex digits of the SHA-256 of the
    Session's ID: enough to tell two Sessions apart, never the ID, and never
    the Session Token. Make one with :meth:`of`. Only the page sees the
    reference; a model is told whether the person is signed in there.
    """

    model_config = ConfigDict(extra="forbid")

    ref: Annotated[str, audience("page"), Field(pattern=r"^[0-9a-f]{12}$")]
    signed_in: bool

    @classmethod
    def of(cls, session_id: str, *, signed_in: bool) -> PapSessionShown:
        """The reference of a Session's ID, and whether the person is signed in there."""
        if not session_id:
            raise ValueError("a Session is shown by the reference of its ID, and this one has none")
        return cls(ref=hashlib.sha256(session_id.encode()).hexdigest()[:12], signed_in=signed_in)


class PapTermsWas(BaseModel):
    """The revision a revised operation replaced, and its terms."""

    model_config = ConfigDict(extra="forbid")

    revision: int = Field(ge=1)
    terms: dict[str, Any] = Field(default_factory=dict)


@display_type(PAP_CONFIRM_TYPE, version=1)
class PapConfirm(Display):
    """An operation a company proposed, waiting for the person to confirm it (Operations).

    What the person approves is exactly this revision: the company's own
    ``summary``, verbatim, and its ``terms``. ``does`` is what confirming it
    does, as an application's Rules class it (``buy`` when a term moves money);
    ``session`` the Session it is confirmed in, by a one-way reference;
    ``was`` the revision it replaced, when the company changed its terms;
    ``only_the_person`` that the company (or the application's Rule) wants the
    person's own decision, so no approval given in advance covers it.

    The buttons are the host's own: a display says what is asked, and the
    person answers where the host asks them.
    """

    #: The company, as the person knows it (its domain or its name).
    company: str = Field(min_length=1)
    #: The company's own words, shown verbatim, never rephrased.
    summary: str = Field(min_length=1)
    terms: dict[str, Any] = Field(default_factory=dict)
    #: The operation's reference at the company; with ``revision``, what is confirmed.
    operation_ref: str = Field(min_length=1)
    revision: int = Field(ge=1)
    does: PapActionClass | None = None
    session: PapSessionShown | None = None
    #: Until when the company holds these terms.
    expires_at: datetime | None = None
    was: PapTermsWas | None = None
    only_the_person: bool = False

    @field_validator("company")
    @classmethod
    def _company(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("an operation to confirm names its company")
        return value.strip()

    @field_validator("summary")
    @classmethod
    def _summary(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("an operation to confirm says what it is, in the company's words")
        return value

    @model_validator(mode="after")
    def _was_earlier(self) -> PapConfirm:
        if self.was is not None and self.was.revision >= self.revision:
            raise ValueError("the revision an operation replaced comes before it")
        return self

    def text(self) -> str:
        # Neither the Session's reference nor anything of the page's alone:
        # the text is also what a model and a transcript read.
        said = f"{self.company} asks you to confirm: {self.summary} (version {self.revision})"
        if self.was is not None:
            said += f" Changed since version {self.was.revision}."
        return said

    def tool_meta(self) -> dict[str, Any]:
        """The ``_meta`` an MCP tool result carries this display in."""
        return {DISPLAY_META_KEY: self.wire().model_dump(mode="json")}


__all__ = [
    "PAP_CONFIRM_TYPE",
    "PAP_SIGN_IN_TYPE",
    "WAITING_FOR_THE_PERSON",
    "PapActionClass",
    "PapConfirm",
    "PapSessionShown",
    "PapSignIn",
    "PapTermsWas",
]
