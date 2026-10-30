# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP's displays for ``reactor.ui``: what a page draws for a PAP answer.

Three displays: :class:`PapSignIn`, a sign-in waiting for the person;
:class:`PapConfirm`, an operation a company returned, waiting for the person's
approval; and :class:`PapReplies`, what a company answered in a conversation,
each reply with who wrote it there.

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
import re
from datetime import datetime
from typing import Annotated, Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)
from reactor.ui import (  # type: ignore[import-untyped]
    DISPLAY_META_KEY,
    Display,
    audience,
    display_type,
)

from .models import _domain, known_responder, known_status

#: The display type of a sign-in waiting for the person.
PAP_SIGN_IN_TYPE = "application/vnd.datalayer.pap.sign-in+json"

#: The display type of an operation waiting for the person's approval.
PAP_CONFIRM_TYPE = "application/vnd.datalayer.pap.confirm+json"

#: The display type of what a company answered in a conversation.
PAP_REPLIES_TYPE = "application/vnd.datalayer.pap.replies+json"

#: What confirming an operation does, as an application's Rules class it.
PapActionClass = Literal["read", "write", "send", "buy", "delete", "publish"]

#: An operation ID or revision (Operations 3).
_IDENTIFIER = r"^[A-Za-z0-9_-]{1,256}$"

#: What makes a link, an image or HTML of a summary, in CommonMark and its autolinks.
_ACTIVE = re.compile(r"[\\\[\]<>@]|://|www\.")


def inert_summary(summary: str) -> str:
    """A summary whose links, images and HTML show as text, wherever it is rendered.

    A summary can't send the User elsewhere or load content while they decide
    (Operations 3): their markup is escaped, in the Markdown a chat renders.
    Emphasis, paragraphs and lists stay. Text a host shows as text needs none of
    this: it shows the summary as it is.
    """

    return _ACTIVE.sub(lambda found: _escaped(found.group()), summary)


def _escaped(active: str) -> str:
    if active == "://":
        return r"\://"
    if active == "www.":
        return r"www\."
    return f"\\{active}"


#: The status a sign-in tool answers while the person has something to do.
WAITING_FOR_THE_PERSON = "waiting_for_the_person"


@display_type(PAP_SIGN_IN_TYPE, version=1)
class PapSignIn(Display):
    """A sign-in waiting for the person.

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
    #: The company's domain, when the page opened is the host's own link that sends the person on
    #: to it and takes them back only from it (a bound Direct Sign-In); otherwise the page's host
    #: is the company's.
    company: str | None = None
    #: What the company said it needs before it answers: the scope its ``authorization``
    #: event named (§7.11), when one did. The person sees what they are asked to allow.
    needs: list[str] = Field(default_factory=list)
    #: The company's ``organization.name`` and ``organization.domain`` from its poppy.json:
    #: shown whenever the person is asked for a code or credentials (§4.6, §4.7), so
    #: required for ``device`` and ``mediated``.
    organization_name: str | None = None
    organization_domain: str | None = None

    @field_validator("company", "organization_domain")
    @classmethod
    def _company(cls, value: str | None) -> str | None:
        return _domain(value) if value is not None else None

    @field_validator("organization_name")
    @classmethod
    def _organization_name(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("a company's name is not blank")
        return value.strip() if value is not None else None

    @field_validator("needs")
    @classmethod
    def _needs(cls, value: list[str]) -> list[str]:
        if any(not scope or any(ch.isspace() for ch in scope) for scope in value):
            raise ValueError("each scope a company needs is one token")
        return value

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
        if self.mode != "direct" and (not self.organization_name or not self.organization_domain):
            # Asking for a code or credentials names the company that asks (§4.6, §4.7).
            raise ValueError("a device or mediated sign-in names the company: name and domain")
        return self

    @property
    def host(self) -> str:
        """The page's domain: what the person can check before signing in."""
        return urlsplit(self.open).hostname or ""

    @property
    def at(self) -> str:
        """Where the person signs in: the company named, or the page's own domain."""
        return self.company or self.host

    @property
    def organization(self) -> str:
        """The company as poppy.json names it, ``name (domain)``, when the display has it."""
        if self.organization_name and self.organization_domain:
            return f"{self.organization_name} ({self.organization_domain})"
        return ""

    def text(self) -> str:
        # Neither the page nor the code: the text is also what a model and a
        # transcript read, and a verification URL may carry the code.
        needs = f" It needs: {', '.join(self.needs)}." if self.needs else ""
        return self._how() + needs

    def _how(self) -> str:
        if self.mode == "direct":
            through = f" (through {self.host}, which brings you back)" if self.company else ""
            return (
                f"Sign in at {self.at}: open its sign-in page, shown here{through}, "
                "sign in there, and come back."
            )
        if self.mode == "device":
            return (
                f"Sign in to {self.organization} at {self.host}: open its sign-in page, "
                "shown here, and enter the code shown with it."
            )
        sent = f" A code was sent to {self.sent_to}." if self.sent_to else ""
        return (
            f"Sign in to {self.organization} at {self.host}: open the page shown here and type "
            f"what the company asks there, never in this conversation.{sent}"
        )

    @classmethod
    def from_answer(cls, answer: dict[str, Any]) -> PapSignIn | None:
        """The display for a ``pap_sign_in`` answer, or ``None`` for any other status."""
        if answer.get("status") != WAITING_FOR_THE_PERSON:
            return None
        fields = (
            "mode",
            "open",
            "code",
            "expires_at",
            "sent_to",
            "company",
            "needs",
            "organization_name",
            "organization_domain",
        )
        return cls.model_validate({key: answer[key] for key in fields if answer.get(key)})

    def tool_meta(self) -> dict[str, Any]:
        """The ``_meta`` an MCP tool result carries this display in."""
        return {DISPLAY_META_KEY: self.wire().model_dump(mode="json")}


class PapSessionShown(BaseModel):
    """The Session an operation is approved in, as the person's card names it.

    ``ref`` is one-way — the first 12 hex digits of the SHA-256 of the
    Session's ID: enough to tell two Sessions apart, never the ID, and never
    the Session Token. Make one with :meth:`of`. Only the page sees the
    reference; a model is told whether the person is signed in there.
    """

    model_config = ConfigDict(extra="forbid")

    ref: Annotated[str, audience("page"), Field(pattern=r"^[0-9a-f]{12}$")]
    signed_in: bool

    @classmethod
    def of(cls, session_key: str, *, signed_in: bool) -> PapSessionShown:
        """The reference of a Session's key, and whether the person is signed in there."""
        if not session_key:
            raise ValueError(
                "a Session is shown by the reference of its key, and this one has none"
            )
        return cls(ref=hashlib.sha256(session_key.encode()).hexdigest()[:12], signed_in=signed_in)


class PapTermsWas(BaseModel):
    """The revision a new one replaced, and its terms: to show what changed."""

    model_config = ConfigDict(extra="forbid")

    revision: str = Field(pattern=_IDENTIFIER)
    terms: dict[str, Any] = Field(default_factory=dict)


@display_type(PAP_CONFIRM_TYPE, version=2)
class PapConfirm(Display):
    """An operation a company returned, waiting for the person's approval (Operations 5).

    What the person approves is exactly this revision: ``company``, the Company's
    name; its ``summary``, verbatim and shown as text, so links, images and HTML in
    it don't work (:func:`inert_summary`, which :meth:`text` applies); ``revision``
    and ``expires_at``. ``terms`` are the company's own, for values worth showing;
    ``differences`` what the personal agent's terms check found, to point out.
    ``does`` is what approving it does, as an application's Rules class it (``buy``
    when a term moves money); ``session`` the Session it is approved in, by a
    one-way reference; ``was`` the revision it replaced, when the terms changed.

    The buttons are the host's own: a display says what is asked, and the
    person answers where the host asks them. Every operation is asked about.
    """

    #: The Company's name (`organization.name`), or its domain.
    company: str = Field(min_length=1)
    #: The company's own words, shown verbatim as text, never rephrased.
    summary: str = Field(min_length=1)
    terms: dict[str, Any] = Field(default_factory=dict)
    #: The operation's ID at the company; with ``revision``, what is approved.
    operation_ref: str = Field(min_length=1)
    revision: str = Field(pattern=_IDENTIFIER)
    #: The last time an approval of this revision is accepted.
    expires_at: datetime
    #: Where the terms disagree with the summary or with what was asked for.
    differences: list[str] = Field(default_factory=list)
    does: PapActionClass | None = None
    session: PapSessionShown | None = None
    was: PapTermsWas | None = None

    @field_validator("company")
    @classmethod
    def _company(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("an operation to approve names its company")
        return value.strip()

    @field_validator("summary")
    @classmethod
    def _summary(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("an operation to approve says what it is, in the company's words")
        return value

    @model_validator(mode="after")
    def _was_earlier(self) -> PapConfirm:
        if self.was is not None and self.was.revision == self.revision:
            raise ValueError("the revision an operation replaced is another one")
        return self

    def text(self) -> str:
        # Neither the Session's reference nor anything of the page's alone:
        # the text is also what a model and a transcript read.
        said = (
            f"{self.company} asks you to approve: {inert_summary(self.summary)} "
            f"(revision {self.revision}, until {self.expires_at.isoformat()})"
        )
        if self.was is not None:
            said += " The terms changed since you saw them."
        for difference in self.differences:
            said += f" Check: {difference}"
        return said

    def tool_meta(self) -> dict[str, Any]:
        """The ``_meta`` an MCP tool result carries this display in."""
        return {DISPLAY_META_KEY: self.wire().model_dump(mode="json")}


#: Where a conversation stands (§7.8), apart from who answers in it.
PapConversationStatus = Literal["working", "idle", "queued", "closed"]

_WROTE: dict[str, str] = {"agent": "its agent", "human": "one of its people"}


class PapReply(BaseModel):
    """One message a company wrote, and who wrote it there: its agent or one of its people."""

    model_config = ConfigDict(extra="forbid")

    #: Its agent or one of its people (`author.type`, §7.4, §7.8).
    author: Literal["agent", "human"]
    #: The writer's display name, when the company gives one (`author.name`, §7.4).
    name: str | None = Field(default=None, min_length=1)
    #: The company's words, verbatim.
    text: str = Field(min_length=1)

    @field_validator("text")
    @classmethod
    def _text(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a reply says something, in the company's words")
        return value


@display_type(PAP_REPLIES_TYPE, version=3)
class PapReplies(Display):
    """What a company answered in a conversation, each reply with who wrote it (§7.8).

    A company's message is written by its agent or by one of its people
    (``author``, with the writer's ``name`` when the company gives one,
    version 3), whoever answers the conversation now (``responder``) and
    wherever it stands (``status``: ``working``, ``idle``, ``queued`` while a
    person is found, ``closed``); the page tells them apart, as PAP-7.8-01
    asks of the personal agent's own words. Each reply is the company's text,
    verbatim; a message carrying only data is the model's to read, not the
    page's to draw. It names the conversation (``conversation``, version 2):
    where the person's own words open a Direct Conversation under it (§7.10),
    typed on the page, never through the model. Make one from the company's
    messages with :meth:`of`.
    """

    #: The company, as the person knows it (its domain or its name).
    company: str = Field(min_length=1)
    #: The conversation the replies are in, by the company's id for it.
    conversation: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    replies: list[PapReply] = Field(min_length=1)
    status: PapConversationStatus | None = None
    responder: Literal["agent", "human"] | None = None

    @field_validator("status", mode="before")
    @classmethod
    def _status(cls, value: object) -> object:
        # A status this version doesn't define reads as `working` (§8.7).
        return known_status(value)

    @field_validator("responder", mode="before")
    @classmethod
    def _responder(cls, value: object) -> object:
        # A responder this version doesn't define reads as `human` (§8.7).
        return known_responder(value)

    @field_validator("company")
    @classmethod
    def _company(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("replies name their company")
        return value.strip()

    @classmethod
    def of(
        cls,
        company: str,
        conversation_id: str,
        messages: Any,
        *,
        status: str | None = None,
        responder: str | None = None,
    ) -> PapReplies | None:
        """The company's :class:`~personal_agent_protocol.models.Message` s with text, or ``None``.

        Only the company's own messages (``role: company``) are replies; the
        display's ``id`` is the conversation's and its first reply's.
        """
        written = [
            message
            for message in messages
            if message.role == "company" and message.text and message.text.strip()
        ]
        if not written:
            return None
        return cls(
            id=f"{conversation_id}-{written[0].id}-replies",
            company=company,
            conversation=conversation_id,
            replies=[
                PapReply(author=message.author.type, name=message.author.name, text=message.text)
                for message in written
            ],
            status=cast(Any, status),
            responder=cast(Any, responder),
        )

    def text(self) -> str:
        return "\n".join(
            f"{self.company}, {_WROTE[reply.author]}"
            f"{f' ({reply.name})' if reply.name else ''}: {reply.text}"
            for reply in self.replies
        )

    def tool_meta(self) -> dict[str, Any]:
        """The ``_meta`` an MCP tool result carries this display in."""
        return {DISPLAY_META_KEY: self.wire().model_dump(mode="json")}


__all__ = [
    "PAP_CONFIRM_TYPE",
    "PAP_REPLIES_TYPE",
    "PAP_SIGN_IN_TYPE",
    "WAITING_FOR_THE_PERSON",
    "PapActionClass",
    "PapConfirm",
    "PapConversationStatus",
    "PapReplies",
    "PapReply",
    "PapSessionShown",
    "PapSignIn",
    "PapTermsWas",
    "inert_summary",
]
