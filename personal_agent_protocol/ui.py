# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP's displays for ``reactor.ui``: what a page draws for a PAP answer.

A tool that starts a sign-in answers with a :class:`PapSignIn` beside its
result — in an MCP result's ``_meta["reactor.ui/display"]`` — and any page with
a renderer for ``application/vnd.datalayer.pap.sign-in+json`` draws *Sign in
at a company*; a page without one shows the display's text.

The display type lives here, in the package both tiers already depend on for
PAP, not in a host. It needs ``datalayer_reactor`` 1.1 (``reactor.ui``), the
``ui`` extra; importing this module is the only thing that does, so the rest
of the SDK keeps working on an older reactor.

What the person types never travels in a display, and the code to enter is
for the page only: :meth:`~reactor.ui.Display.model_view` leaves it out.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

from pydantic import field_validator, model_validator
from reactor.ui import (  # type: ignore[import-untyped]
    DISPLAY_META_KEY,
    Display,
    audience,
    display_type,
)

#: The display type of a sign-in waiting for the person.
PAP_SIGN_IN_TYPE = "application/vnd.datalayer.pap.sign-in+json"

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
    #: The page to open, ``https`` only.
    open: str
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
        # No code here: the text is also what a model and a transcript read.
        if self.mode == "direct":
            return f"Sign in at {self.host}: open {self.open}, sign in there, and come back."
        if self.mode == "device":
            return f"Sign in at {self.host}: open {self.open} and enter the code shown there."
        sent = f" A code was sent to {self.sent_to}." if self.sent_to else ""
        return (
            f"Sign in at {self.host}: open {self.open} and type what the company asks there, "
            f"never in this conversation.{sent}"
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


__all__ = ["PAP_SIGN_IN_TYPE", "WAITING_FOR_THE_PERSON", "PapSignIn"]
