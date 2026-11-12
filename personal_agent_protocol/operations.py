# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Operations extension, version 3: exact approval, at most once.

A company that wants approval for an action refuses the request and returns the
operation: the terms as JSON, and usually in plain language too. The terms are approved,
by the user or by the personal agent on an instruction the user gave it, and the agent
makes the same request again with the approval, through the interface that returned
the operation:

- an API's `403` with `error: approval_required` and `operation`, answered by the
  same request with the `Poppy-Approval` header (`ApiClient.call(approval=...)`);
- an MCP tool's error result with `structuredContent.operation`, answered by the
  same call with `_meta["personalagentprotocol.org/approval"]`
  (`McpClient.call_tool(approval=...)`);
- a company message's `operation`, answered by a message with `approval`;
- a website's `403` to the agent's own joined browser, with only a reference in the
  `Poppy-Operation` header: the agent gets the operation by posting the reference to the
  extension's `endpoint`, records the approval there (`204`), and has its browser make
  the request again (`WebsiteOperations`).

What this client guarantees on the personal agent's side:

- **Negotiation.** Operations are used only when the company's `poppy.json` lists
  `operations` version 3 and the Session declares it. Version 2 is another major
  version: it does not count, and nothing here speaks it.
- **Who approved.** Every approval says `approver`. `OperationsClient.ask_user` asks
  the host's own approval surface (`pap.approvalSurface`), naming the company and the
  revision's terms: only the surface's `True` makes a `user` approval, and nothing here
  reads conversation text as approval. `OperationsClient.approve_as_agent` makes an
  `agent` approval only on an `AgentInstruction` the host holds from the user, and only
  when the instruction's own check says it covers the revision's terms; when it can't
  tell, when the terms differ from what was asked, or when the company answered an
  earlier agent approval of the action with new terms or declined one, it is `ask_user`.
- **Exact terms.** `terms_differences` checks `terms` against what the agent asked for
  and against the `summary` when there is one. An approval covers one revision.
- **Declines.** A company may decline an approval that passes its checks
  (`approval_declined`): `send` reports `declined`, the approval is never sent again,
  and no new revision of that action is approved without the user.
- **At most once.** After a failure or a timeout, `OperationsClient.send` sends
  the same approval again, waiting for `Retry-After`. A new operation in answer
  to such a retry doesn't say whether the first was performed: it is `unknown`,
  and the host finds out another way before asking the user again.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from collections.abc import Awaitable, Callable, Collection, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, cast
from urllib.parse import urlsplit

from pydantic import ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import PersonalAgentProtocolError, TransportError
from .models import (
    Approval,
    ApprovalDeclined,
    DiscoveryDocument,
    Message,
    Operation,
    Organization,
    terms_leaves,
)
from .reactor import (
    APPROVAL_SURFACES,
    CLOCKS,
    RANDOM_SOURCES,
    ApprovalRequest,
    ApprovalSurface,
    Clock,
    RandomSource,
    first_contribution,
    optional_contribution,
)
from .sessions import AccessToken, PapSession
from .telemetry import operation_result, traced

if TYPE_CHECKING:
    from .apis import ApiClient, ApiResponse

OPERATIONS_EXTENSION = "operations"
#: The version this SDK implements, and the only one: version 2 is incompatible with it
#: (another major version, Operations 2), so a Company that lists only 2 gets no
#: `operations` declaration, and a request that declares 2 gets no operations here.
OPERATIONS_VERSION = "3"
#: A Company's refusal to act on an approval that passed its checks (Operations 6).
APPROVAL_DECLINED = "approval_declined"
#: An approved action that didn't finish: an API error saying every change made (Operations 7).
ACTION_FAILED = "action_failed"
#: The header that carries an approval to an API (Operations 6).
APPROVAL_HEADER = "Poppy-Approval"
#: The `_meta` key that carries an approval to an MCP tool (Operations 6).
APPROVAL_META_KEY = "personalagentprotocol.org/approval"
#: The header that carries a website's reference to an operation (Operations 4).
OPERATION_HEADER = "Poppy-Operation"
#: A website's reference: at most 2048 characters of `A-Z a-z 0-9 - _ .` (Operations 4).
OPERATION_REFERENCE = re.compile(r"[A-Za-z0-9._-]{1,2048}")
#: How many times `send` sends an approval, unless told otherwise.
SEND_ATTEMPTS = 3

_T = TypeVar("_T")


class OperationError(PersonalAgentProtocolError):
    """An operation could not be approved, or its approval could not be sent."""


def operations_negotiated(document: DiscoveryDocument, session: PapSession) -> bool:
    """Whether the Company lists `operations` at this version and the Session declares it
    (Operations 2): another major version doesn't count."""

    return (
        document.extension(OPERATIONS_EXTENSION, OPERATIONS_VERSION) is not None
        and session.extensions.get(OPERATIONS_EXTENSION) == OPERATIONS_VERSION
    )


def operation_from(payload: object) -> Operation:
    """The one operation object, from whichever interface carried it (Operations 4).

    Accepts an API's `403` body (`{"operation": …}`), an MCP tool result
    (`{"structuredContent": {"operation": …}}`), a conversation message
    (`{"extensions": {"operations": {"operation": …}}}`, or a `Message`), or the
    operation itself.
    """

    candidate: object = payload
    if isinstance(payload, Message):
        candidate = payload.operation
    elif isinstance(payload, dict):
        structured = payload.get("structuredContent")
        extensions = payload.get("extensions")
        operations = extensions.get("operations") if isinstance(extensions, dict) else None
        if isinstance(structured, dict) and "operation" in structured:
            candidate = structured["operation"]
        elif "operation" in payload:
            candidate = payload["operation"]
        elif isinstance(operations, dict):
            candidate = operations.get("operation")
    if isinstance(candidate, Operation):
        return candidate
    if candidate is None:
        raise ValueError("the payload carries no operation")
    return Operation.model_validate(candidate)


def declined_from(payload: object) -> ApprovalDeclined | None:
    """The decline a Company answered an approval with, or `None` (Operations 6).

    Accepts an API's `403` body (`error: approval_declined` with the members), an MCP
    tool result (the same in `structuredContent`), a conversation message
    (`extensions.operations.declined`, or a `Message`).
    """

    if isinstance(payload, Message):
        return payload.declined
    if not isinstance(payload, dict):
        return None
    structured = payload.get("structuredContent")
    extensions = payload.get("extensions")
    operations = extensions.get("operations") if isinstance(extensions, dict) else None
    candidate: object = None
    if isinstance(structured, dict) and structured.get("error") == APPROVAL_DECLINED:
        candidate = structured
    elif payload.get("error") == APPROVAL_DECLINED:
        candidate = payload
    elif isinstance(operations, dict):
        candidate = operations.get("declined")
    if not isinstance(candidate, dict):
        return None
    # `error` marks the body at an API and a tool; it is not a member of the decline.
    return ApprovalDeclined.model_validate(
        {name: value for name, value in candidate.items() if name != "error"}
    )


# The `Poppy-Approval` header: an RFC 9651 Dictionary ---------------------------------------


def _sf_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def approval_header(approval: Approval) -> str:
    """The value of `Poppy-Approval` (Operations 6): `operation_id`, `revision`, `approver`
    and any `input_type` and `reference` as Strings, any `approved_at` as an Integer. An
    agent approval never carries `input_type`."""

    value = (
        f'operation_id="{approval.operation_id}", revision="{approval.revision}", '
        f'approver="{approval.approver}"'
    )
    if approval.approved_at is not None:
        value += f", approved_at={approval.approved_at}"
    if approval.input_type is not None and approval.approver == "user":
        value += f", input_type={_sf_string(approval.input_type)}"
    if approval.reference is not None:
        value += f', reference="{approval.reference}"'
    return value


def new_approval_reference(random_bytes: Callable[[int], bytes] = secrets.token_bytes) -> str:
    """A `reference` for one approval (Operations 6): `apr_` and 16 random bytes, so it is
    opaque, identifies nobody, and is never the same at two Companies. The host keeps its
    own record of the approval under it."""

    return f"apr_{random_bytes(16).hex()}"


class _DictionaryError(ValueError):
    """The value is not an RFC 9651 Dictionary: the whole field is ignored."""


_KEY = re.compile(r"[a-z*][a-z0-9_.*-]*")
_TOKEN = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*")
_NUMBER = re.compile(r"-?\d{1,15}(\.\d{1,3})?")
_BYTES = re.compile(r":[A-Za-z0-9+/=]*:")
_DISPLAY = re.compile(r'%"[^"]*"')
_WHITESPACE = " \t"


class _Dictionary:
    """A strict parser of an RFC 9651 Dictionary, keeping the Strings a caller reads."""

    def __init__(self, text: str) -> None:
        self.text = text.strip(" ")
        self.at = 0

    def _peek(self) -> str:
        return self.text[self.at] if self.at < len(self.text) else ""

    def _match(self, pattern: re.Pattern[str]) -> str:
        found = pattern.match(self.text, self.at)
        if found is None:
            raise _DictionaryError(self.text)
        self.at = found.end()
        return found.group()

    def members(self) -> dict[str, object]:
        members: dict[str, object] = {}
        while self.at < len(self.text):
            key = self._match(_KEY)
            value: object = True
            if self._peek() == "=":
                self.at += 1
                value = self._inner_list() if self._peek() == "(" else self._bare_item()
            self._parameters()
            members[key] = value  # the last one wins, in the first one's place
            while self._peek() and self._peek() in _WHITESPACE:
                self.at += 1
            if self.at == len(self.text):
                break
            if self._peek() != ",":
                raise _DictionaryError(self.text)
            self.at += 1
            while self._peek() and self._peek() in _WHITESPACE:
                self.at += 1
            if self.at == len(self.text):
                raise _DictionaryError(self.text)  # a trailing comma
        return members

    def _parameters(self) -> None:
        while self._peek() == ";":
            self.at += 1
            while self._peek() == " ":
                self.at += 1
            self._match(_KEY)
            if self._peek() == "=":
                self.at += 1
                self._bare_item()

    def _inner_list(self) -> list[object]:
        self.at += 1
        items: list[object] = []
        while True:
            while self._peek() == " ":
                self.at += 1
            if self._peek() == ")":
                self.at += 1
                return items
            items.append(self._bare_item())
            self._parameters()
            if self._peek() not in (" ", ")"):
                raise _DictionaryError(self.text)

    def _bare_item(self) -> object:
        first = self._peek()
        if first == '"':
            return self._string()
        if first == "?":
            self.at += 1
            if self._peek() not in ("0", "1"):
                raise _DictionaryError(self.text)
            self.at += 1
            return self.text[self.at - 1] == "1"
        # Only a String is a `str` here: nothing else names an operation or a revision. An
        # Integer is an `int` (`approved_at`); any other item is opaque.
        if first == ":":
            return (self._match(_BYTES),)
        if first == "@":
            self.at += 1
            return (self._match(_NUMBER),)
        if first == "%":
            return (self._match(_DISPLAY),)
        if first == "-" or first.isdigit():
            number = self._match(_NUMBER)
            return (number,) if "." in number else int(number)
        return (self._match(_TOKEN),)

    def _string(self) -> str:
        self.at += 1
        value: list[str] = []
        while self.at < len(self.text):
            char = self.text[self.at]
            self.at += 1
            if char == "\\":
                escaped = self._peek()
                if escaped not in ('"', "\\") or not escaped:
                    raise _DictionaryError(self.text)
                self.at += 1
                value.append(escaped)
            elif char == '"':
                return "".join(value)
            elif not " " <= char <= "~":
                raise _DictionaryError(self.text)
            else:
                value.append(char)
        raise _DictionaryError(self.text)


def parse_approval_header(value: str | None) -> Approval | None:
    """The approval a `Poppy-Approval` value states, or `None`.

    A value that isn't a Dictionary is ignored whole (RFC 9651), and so is one without
    `operation_id` and `revision` as Strings of the IDs' characters or without `approver`
    as `user` or `agent`: a version 2 approval, which names no approver, is not an
    approval. `approved_at` (an Integer), `input_type` and `reference` (Strings) are kept
    when they are such, and left out otherwise; `input_type` is dropped with `agent`.
    Members this version doesn't recognize are ignored, so later versions can add them
    (Operations 6).
    """

    if not value:
        return None
    try:
        members = _Dictionary(value).members()
        return Approval.model_validate(
            {
                "operation_id": members.get("operation_id"),
                "revision": members.get("revision"),
                "approver": members.get("approver"),
                "approved_at": members.get("approved_at"),
                "input_type": members.get("input_type"),
                "reference": members.get("reference"),
            }
        )
    except (_DictionaryError, ValidationError):
        return None


def approval_from_meta(meta: object) -> Approval | None:
    """The approval in an MCP tool call's `_meta`, or `None` (unknown members are ignored)."""

    if not isinstance(meta, Mapping):
        return None
    try:
        return Approval.model_validate(meta.get(APPROVAL_META_KEY))
    except ValidationError:
        return None


# Operations on websites: the `Poppy-Operation` header and the extension's `endpoint` -----


@dataclass(frozen=True)
class OperationReference:
    """A website's reference to an operation (Operations 4): the `sid` of the Session the
    website handled the browser's request as, and the opaque `ref` the Company chose."""

    sid: str
    ref: str


def operation_reference_header(reference: OperationReference) -> str:
    """The value of `Poppy-Operation`: a Dictionary with `sid` and `ref` as Strings."""

    if not OPERATION_REFERENCE.fullmatch(reference.ref):
        raise ValueError("a reference is 1 to 2048 characters of A-Z a-z 0-9 - _ .")
    return f"sid={_sf_string(reference.sid)}, ref={_sf_string(reference.ref)}"


def parse_operation_header(value: str | None) -> OperationReference | None:
    """The reference a `Poppy-Operation` value states, or `None`.

    A value that isn't a Dictionary is ignored whole (RFC 9651), and so is one without
    `sid` and `ref` as Strings, or whose `ref` has characters or a length the extension
    doesn't allow. Other members are ignored.
    """

    if not value:
        return None
    try:
        members = _Dictionary(value).members()
    except _DictionaryError:
        return None
    sid, ref = members.get("sid"), members.get("ref")
    if not isinstance(sid, str) or not sid or not isinstance(ref, str):
        return None
    if not OPERATION_REFERENCE.fullmatch(ref):
        return None
    return OperationReference(sid=sid, ref=ref)


def operations_endpoint(document: DiscoveryDocument) -> str | None:
    """The `endpoint` of the Company's `operations` entry at this version, or `None`.

    Only an HTTPS URL counts, and only beside `web.browser_session_endpoint`: a Company
    lists both, because only a browser joined to a Session gets operations (Operations 2).
    """

    entry = document.extension(OPERATIONS_EXTENSION, OPERATIONS_VERSION)
    endpoint = None if entry is None else getattr(entry, "endpoint", None)
    if not isinstance(endpoint, str) or document.web is None:
        return None
    if document.web.browser_session_endpoint is None:
        return None
    parsed = urlsplit(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return endpoint


#: What a lookup of an approved reference says (Operations 6).
WebsiteOperationStatus = Literal["approved", "performing", "performed"]


class WebsiteOperations:
    """Operations a Company's website returns to the personal agent's own browser.

    The approval never passes through the browser (Operations 6, 8.2):

    1. `reference(headers, joined=...)` takes the reference from the `Poppy-Operation`
       header of a response the agent's own browser received, and only when its `sid`
       names a Session the agent joined that browser to, at this Company. Page content,
       a message, or a header naming any other Session is never a reference.
    2. `operation(reference, session=...)` posts `{"ref": …}` to this Company's
       `endpoint`, with the Session header and any access token: the operation, to
       approve as at an API (`OperationsClient.ask_user` or `approve_as_agent`).
    3. `record(reference, approval, session=...)` posts the same body with
       `Poppy-Approval`: `204` records it, nothing performed yet. Use it as the request
       of `OperationsClient.send`: a decline and a new revision come back as from an API.
    4. The host has its browser make the request again (the page's Continue button, the
       same form): the website performs it once, using the approval recorded first.
    5. When the browser's request fails, or answers a new reference after an approval was
       recorded, `before_approving_again(earlier, ...)` looks the earlier reference up:
       `performing` waits, `performed` is never approved again (Operations 7).

    `endpoint` is the one `operations_endpoint` reads from this Company's `poppy.json`,
    so a header from anywhere else can't send the Session header to a new destination.
    """

    def __init__(
        self,
        *,
        api: ApiClient,
        document: DiscoveryDocument,
        operations: OperationsClient | None = None,
    ) -> None:
        endpoint = operations_endpoint(document)
        if endpoint is None:
            raise OperationError(
                "no_operations_endpoint",
                "This Company returns no operations on its website",
            )
        self.api = api
        self.endpoint = endpoint
        #: Told of every agent approval recorded here: a new operation the website returns
        #: for the action afterwards is the User's to approve (Operations 5).
        self.operations = operations

    @staticmethod
    def reference(
        headers: Mapping[str, str], *, joined: Collection[str]
    ) -> OperationReference | None:
        """The reference in a response the agent's own browser received, or `None`.

        `headers` are that response's; `joined` the `sid`s of the Sessions the agent
        joined that browser to at this Company (`BrowserSessionClient.joined`). A header
        whose `sid` names none of them is ignored (Operations 4).
        """

        value = next(
            (item for name, item in headers.items() if name.lower() == OPERATION_HEADER.lower()),
            None,
        )
        found = parse_operation_header(value)
        if found is None or found.sid not in joined:
            return None
        return found

    async def operation(
        self,
        reference: OperationReference,
        *,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> Operation:
        """The operation a reference names, from `endpoint` (Operations 4).

        `session` is the Session the reference names, or another Session of the same
        agent and User that can approve it; signed in, `token` is its access token. A
        reference the Session can't use is `invalid_reference` (have the browser make
        the request again for a new one); one already approved is `already_approved`,
        its `status` in the details.
        """

        answer = await self._post(reference, session=session, token=token, approval=None)
        if answer.operation is not None:
            return cast(Operation, answer.operation)
        status = answer.body.get("status") if isinstance(answer.body, dict) else None
        raise OperationError(
            "already_approved",
            "This operation is already approved",
            details={"status": status} if isinstance(status, str) else None,
        )

    async def record(
        self,
        reference: OperationReference,
        approval: Approval,
        *,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> ApiResponse:
        """Send the approval to `endpoint` (Operations 6): an API answer, for `send`.

        `204` is recorded (its `status`); `approval_declined` and a new revision come back
        as the answer's `declined` and `operation`. Nothing is performed until the
        browser makes the request again. An agent approval recorded here makes the next
        revision of the action the User's to approve (`OperationsClient.user_only`).
        """

        answer = await self._post(reference, session=session, token=token, approval=approval)
        if (
            approval.approver == "agent"
            and self.operations is not None
            and answer.operation is None
            and answer.declined is None
        ):
            self.operations.user_only.add(approval.operation_id)
        return answer

    async def status(
        self,
        reference: OperationReference,
        *,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> WebsiteOperationStatus | None:
        """What became of an approved reference: `approved`, `performing` or `performed`;
        `None` when it has no recorded approval, or the Company no longer knows it."""

        try:
            answer = await self._post(reference, session=session, token=token, approval=None)
        except OperationError as error:
            if error.code == "invalid_reference":
                return None
            raise
        if answer.operation is not None or not isinstance(answer.body, dict):
            return None
        status = answer.body.get("status")
        if status in ("approved", "performing", "performed"):
            return cast(WebsiteOperationStatus, status)
        return None

    async def before_approving_again(
        self, earlier: OperationReference, *, session: PapSession, token: AccessToken | None = None
    ) -> Literal["approve", "wait", "performed"]:
        """After an approval was recorded, the browser's request failed or answered a new
        reference: may the agent approve the new one? (Operations 7)

        `wait` while the earlier one is `performing`; `performed` once it was, so the new
        one is never approved; `approve` otherwise (the approval was not used, or no
        longer matches). The agent still never approves a new revision after its own
        agent approval was answered with new terms without asking the User (Operations 5).
        """

        status = await self.status(earlier, session=session, token=token)
        if status == "performing":
            return "wait"
        if status == "performed":
            return "performed"
        return "approve"

    async def _post(
        self,
        reference: OperationReference,
        *,
        session: PapSession,
        token: AccessToken | None,
        approval: Approval | None,
    ) -> ApiResponse:
        if not OPERATION_REFERENCE.fullmatch(reference.ref):
            raise OperationError("invalid_reference", "Not a reference the extension allows")
        if session.extensions.get(OPERATIONS_EXTENSION) != OPERATIONS_VERSION:
            raise OperationError(
                "operations_not_declared",
                "The Session does not declare the Operations extension, version 3",
            )
        try:
            return await self.api.call(
                "POST",
                self.endpoint,
                session=session,
                token=token,
                body={"ref": reference.ref},
                approval=approval,
            )
        except PersonalAgentProtocolError as error:
            if error.code == "invalid_request" and error.status_code == 400:
                raise OperationError(
                    "invalid_reference",
                    "The Company can't use this reference in this Session",
                    status_code=400,
                ) from error
            raise


# The terms check ---------------------------------------------------------------------------

#: A value a `summary` states with decimals, such as an amount.
_DECIMAL = re.compile(r"(?<![\w.])\d[\d,]*\.\d+(?![\w])")
_NUMERIC = re.compile(r"^\d+(\.\d+)?$")


_leaves = terms_leaves


def terms_differences(
    operation: Operation, asked: Mapping[str, object] | None = None
) -> tuple[str, ...]:
    """Where `terms` disagree with what the agent asked for, or with the `summary`.

    `asked` gives the values the agent asked for, keyed by their dotted paths in
    `terms`: a different or missing value is a difference. When the operation has a
    `summary`, the company wrote both, so the summary alone could describe something
    other than the terms (Operations 5): amounts are compared both ways, every decimal
    in the summary is in the terms and every number in the terms is in the summary.
    Identifiers aren't, since a summary is written for people. Without a `summary`
    only `asked` is compared.
    """

    leaves = _leaves(operation.terms)
    differences: list[str] = []
    for path, wanted in (asked or {}).items():
        if path not in leaves:
            differences.append(f"You asked for {path} {wanted}; the terms don't say.")
        elif str(leaves[path]) != str(wanted):
            differences.append(f"You asked for {path} {wanted}; the terms say {leaves[path]}.")
    if operation.summary is None:
        return tuple(differences)
    stated = {match.replace(",", "") for match in _DECIMAL.findall(operation.summary)}
    numbers = {
        path: str(value)
        for path, value in leaves.items()
        if not isinstance(value, bool)
        and isinstance(value, str | int | float)
        and _NUMERIC.fullmatch(str(value))
    }
    for path, value in numbers.items():
        if value not in operation.summary.replace(",", ""):
            differences.append(f"The terms say {path} {value}; the summary doesn't.")
    for value in sorted(stated - set(numbers.values())):
        differences.append(f"The summary says {value}; the terms don't.")
    return tuple(differences)


def _changed(before: Operation, after: Operation) -> tuple[str, ...]:
    """What a new revision changed: `summary`, `expires_at`, and the terms' paths."""

    old, new = _leaves(before.terms), _leaves(after.terms)
    changed = sorted(path for path in old.keys() | new.keys() if old.get(path) != new.get(path))
    if before.expires_at != after.expires_at:
        changed.insert(0, "expires_at")
    if before.summary != after.summary:
        changed.insert(0, "summary")
    return tuple(changed)


# Asking the user, and sending the approval ---------------------------------------------------


class ApprovalSent(Generic[_T]):
    """What came of sending an approval.

    `answered`: the company answered as it would without operations; `answer` is
    that answer, the same on every retry. `new_revision`: it returned an operation
    to approve, `operation`, for a first send: show what changed and ask again.
    `declined`: the company will not act on this approval (`declined` carries its
    `reason` and `alternative`, company content): nothing was performed, the approval
    is never sent again, and the user is told. `ask_user` is `True` when a new revision
    of the action may only be approved by the user: after a decline, and when the
    approval sent was the agent's (Operations 5). `unknown`: a send failed or timed out
    and nothing since says whether the action
    was performed, with `operation` when the company answered a retry with one, or
    the company is still performing it: find out another way, such as from the
    order in the company's API, before asking the user about the same action again.
    """

    def __init__(
        self,
        status: Literal["answered", "new_revision", "declined", "unknown"],
        *,
        answer: _T | None = None,
        operation: Operation | None = None,
        declined: ApprovalDeclined | None = None,
        ask_user: bool = False,
        retry_after: str | None = None,
    ) -> None:
        self.status = status
        self.answer = answer
        self.operation = operation
        self.declined = declined
        self.ask_user = ask_user
        self.retry_after = retry_after


@dataclass(frozen=True)
class AgentInstruction:
    """An instruction the User gave the Personal Agent, which an agent approval rests on
    (Operations 5), such as "go ahead with any exchange under $20".

    The host holds it: `text` is the User's instruction as the host recorded it, taken
    through the host's own interface, never content from a Company, a website or anything
    else the agent read, even when that says it comes from the User. `covers` is the
    host's check of a revision's terms against it: `True` only when the instruction covers
    them, `False` when it does not, `None` when it can't tell. The extension doesn't say
    how to check; the SDK never guesses, and only `True` approves.
    """

    text: str
    covers: Callable[[Operation], bool | None]

    def __post_init__(self) -> None:
        if not self.text.strip():
            raise ValueError("an agent approval rests on an instruction the User gave")


def _retry_after(error: PersonalAgentProtocolError) -> str | None:
    details = error.details if isinstance(error.details, Mapping) else {}
    value = details.get("retry_after")
    return value if isinstance(value, str) else None


class OperationsClient:
    """Approve an operation, as the user or on the user's instruction, and send the
    approval at most once.

    `sleep` waits for `Retry-After` between sends; `max_wait` is the longest wait
    it will do. The client remembers, for its own life, the operations whose next
    revision only the user may approve (`user_only`): a host that outlives it keeps
    that itself and passes `user_only=True` to `approve_as_agent`.
    """

    def __init__(
        self,
        *,
        reactor: PluginPlatform,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        max_wait: float = 30.0,
    ) -> None:
        self.reactor = reactor
        self.sleep = sleep
        self.max_wait = max_wait
        #: The operations declined, or answered with new terms after an agent approval:
        #: no agent approval of a new revision of the same action (Operations 5, 6).
        self.user_only: set[str] = set()

    @traced("pap.operation.ask_user", after=operation_result)
    async def ask_user(
        self,
        operation: Operation,
        *,
        organization: Organization,
        tenant_id: str,
        asked: Mapping[str, object] | None = None,
        replaces: Operation | None = None,
        surface: ApprovalSurface | None = None,
        input_type: str | None = None,
        reference: str | None = None,
    ) -> Approval:
        """Ask the user about this revision, through the host's own surface: a `user`
        approval.

        The approval says when the user approved (`approved_at`, the host's clock when the
        surface answered) and, with `input_type`, how: `tap`, `typed`, `voice`, or another
        short string the host's surface stands for, never personal data (Operations 6).
        `reference` names the host's own record of the approval (`new_approval_reference`).

        Shows the company's name and the revision's terms, as the `summary` when the
        company wrote one and else as the values in `terms`, with any difference
        the terms check finds, and with what changed from `replaces`, the revision
        this one replaces. Only `True` from the surface approves; anything else is
        `not_approved`, a revision past its expiry is `revision_expired` (make the
        request again for new terms), and a host with no surface is
        `no_approval_surface`. `surface` overrides the contribution, for a host
        whose interface is the caller's own.
        """

        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        if clock.now() > operation.expires_at:
            raise OperationError("revision_expired", "This revision has expired")
        request = ApprovalRequest(
            action_id="pap.operations.approve",
            action_name="Approve an operation",
            summary=operation.shown,
            arguments={"operation_id": operation.operation_id, "revision": operation.revision},
            tenant_id=tenant_id,
            company_name=organization.name,
            company_domain=organization.domain,
            terms=operation.terms,
            expires_at=operation.expires_at,
            differences=terms_differences(operation, asked),
            changed=() if replaces is None else _changed(replaces, operation),
        )
        if await self._approved(request, surface) is not True:
            raise OperationError("not_approved", "The user did not approve")
        return Approval(
            operation_id=operation.operation_id,
            revision=operation.revision,
            approver="user",
            approved_at=int(clock.now().timestamp()),
            input_type=input_type,
            reference=reference,
        )

    @traced("pap.operation.approve_as_agent", after=operation_result)
    async def approve_as_agent(
        self,
        operation: Operation,
        *,
        instruction: AgentInstruction,
        asked: Mapping[str, object] | None = None,
        user_only: bool = False,
        reference: str | None = None,
    ) -> Approval:
        """Approve this revision on an instruction the user gave: an `agent` approval.

        Nobody is asked, so every doubt goes to the user instead: `ask_user` (an
        `OperationError`) when the operation was declined before, or the company
        answered an earlier agent approval of it with new terms (`user_only`, or this
        client's own memory); when the terms differ from what the agent asked for or
        from the summary; and when `instruction.covers` says anything but `True`. The
        caller then asks with `ask_user`. A revision past its expiry is
        `revision_expired`. The approval says `approver: agent` and when, never an
        `input_type`.
        """

        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        if clock.now() > operation.expires_at:
            raise OperationError("revision_expired", "This revision has expired")
        if user_only or operation.operation_id in self.user_only:
            raise OperationError(
                "ask_user",
                "New terms after an agent approval, or after a decline, are the user's to approve",
            )
        if terms_differences(operation, asked):
            raise OperationError("ask_user", "The terms differ from what was asked: ask the user")
        try:
            covered = instruction.covers(operation)
        except Exception as error:
            raise OperationError(
                "ask_user", "The instruction's check failed: ask the user"
            ) from error
        if covered is not True:
            raise OperationError(
                "ask_user", "The user's instruction does not clearly cover these terms"
            )
        return Approval(
            operation_id=operation.operation_id,
            revision=operation.revision,
            approver="agent",
            approved_at=int(clock.now().timestamp()),
            reference=reference,
        )

    def new_reference(self) -> str:
        """A `reference` for one approval, from the host's random source."""

        source = cast(RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random"))
        return new_approval_reference(source.bytes)

    async def _approved(self, request: ApprovalRequest, surface: ApprovalSurface | None) -> object:
        chosen = surface
        if chosen is None:
            try:
                contributed = optional_contribution(
                    self.reactor, APPROVAL_SURFACES, "approval surface"
                )
            except RuntimeError as error:
                raise OperationError(
                    "approval_surface_ambiguous", "Two approval surfaces at one order"
                ) from error
            if contributed is None:
                raise OperationError(
                    "no_approval_surface", "This host has no surface to ask the user through"
                )
            chosen = cast(ApprovalSurface, contributed)
        try:
            return await chosen.approve(request)
        except Exception as error:
            raise OperationError(
                "approval_failed", "The approval surface failed: nothing was approved"
            ) from error

    @traced("pap.operation.send", after=operation_result)
    async def send(
        self,
        request: Callable[[Approval], Awaitable[_T]],
        approval: Approval,
        *,
        attempts: int = SEND_ATTEMPTS,
    ) -> ApprovalSent[_T]:
        """Send one approval: the saved request, the same every time.

        `request(approval)` makes the request that returned the operation, with
        the approval: `api.call(..., approval=approval)`, or the tool call, or the
        same message with the same ID. A failure, a timeout, or a `503` sends it
        again with the same approval, waiting for `Retry-After`. After `attempts`,
        or a longer wait than `max_wait`, the outcome is `unknown`. A decline is
        final: `declined`, never sent again (Operations 6, 7).
        """

        if attempts < 1:
            raise ValueError("attempts must be positive")
        uncertain = False
        retry_after: str | None = None
        for attempt in range(attempts):
            try:
                answer = await request(approval)
            except TransportError:
                uncertain, retry_after = True, None
            except PersonalAgentProtocolError as error:
                if error.status_code != 503:
                    raise
                uncertain, retry_after = True, _retry_after(error)
            else:
                sent = self._sent(answer, approval, uncertain=uncertain)
                if sent.ask_user:
                    self.user_only.add(approval.operation_id)
                return sent
            if attempt + 1 < attempts and not await self._waited(retry_after):
                break
        return ApprovalSent("unknown", retry_after=retry_after)

    @staticmethod
    def _sent(answer: Any, approval: Approval, *, uncertain: bool) -> ApprovalSent[Any]:
        declined = getattr(answer, "declined", None)
        if isinstance(declined, ApprovalDeclined):
            return ApprovalSent("declined", declined=declined, ask_user=True)
        operation = getattr(answer, "operation", None)
        if not isinstance(operation, Operation):
            return ApprovalSent("answered", answer=answer)
        if operation.revision == approval.revision:
            # Answering an approval with the revision it names would loop for ever.
            raise OperationError(
                "invalid_operation", "The company answered an approval with the same revision"
            )
        return ApprovalSent(
            "unknown" if uncertain else "new_revision",
            operation=operation,
            ask_user=approval.approver == "agent",
        )

    async def _waited(self, retry_after: str | None) -> bool:
        """Wait for `Retry-After`: `False` when it asks for longer than this client waits."""

        seconds = int(retry_after) if retry_after is not None and retry_after.isdigit() else 0
        if seconds > self.max_wait:
            return False
        if seconds:
            await self.sleep(float(seconds))
        return True


__all__ = [
    "ACTION_FAILED",
    "APPROVAL_DECLINED",
    "APPROVAL_HEADER",
    "APPROVAL_META_KEY",
    "OPERATIONS_EXTENSION",
    "OPERATIONS_VERSION",
    "OPERATION_HEADER",
    "OPERATION_REFERENCE",
    "AgentInstruction",
    "ApprovalSent",
    "OperationError",
    "OperationReference",
    "OperationsClient",
    "WebsiteOperationStatus",
    "WebsiteOperations",
    "approval_from_meta",
    "approval_header",
    "declined_from",
    "new_approval_reference",
    "operation_from",
    "operation_reference_header",
    "operations_endpoint",
    "operations_negotiated",
    "parse_approval_header",
    "parse_operation_header",
    "terms_differences",
]
