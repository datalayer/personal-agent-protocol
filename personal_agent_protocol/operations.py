# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""PAP Operations extension v2: exact approval, at most once, no endpoints of its own.

A company that wants the user's approval for an action refuses the request and
returns the operation: the terms, in plain language and as JSON. The personal
agent gets the user's approval and makes the same request again with it, through
the interface that returned the operation:

- an API's `403` with `error: approval_required` and `operation`, answered by the
  same request with the `Poppy-Approval` header (`ApiClient.call(approval=...)`);
- an MCP tool's error result with `structuredContent.operation`, answered by the
  same call with `_meta["personalagentprotocol.org/approval"]`
  (`McpClient.call_tool(approval=...)`);
- a company message's `operation`, answered by a message with `approval`.

What this client guarantees on the personal agent's side:

- **Negotiation.** Operations are used only when the company's `poppy.json`
  and the agent's client metadata both list `operations` version 2.
- **The user decides.** `OperationsClient.ask_user` asks the host's own approval
  surface (`pap.approvalSurface`) about every operation, naming the company and
  the revision's summary: only the surface's `True` makes an `Approval`. Nothing
  here reads conversation text as approval, approves in advance, or approves on
  the user's behalf; without a surface, nothing is approved.
- **Exact terms.** `terms_differences` checks `terms` against the `summary` and
  against what the agent asked for, and the surface is told any difference. An
  approval covers one revision: a new one needs a new approval.
- **At most once.** After a failure or a timeout, `OperationsClient.send` sends
  the same approval again, waiting for `Retry-After`. A new operation in answer
  to such a retry doesn't say whether the first was performed: it is `unknown`,
  and the host finds out another way before asking the user again.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Generic, Literal, TypeVar, cast

from pydantic import ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import PersonalAgentProtocolError, TransportError
from .models import (
    Approval,
    ClientMetadata,
    DiscoveryDocument,
    Message,
    Operation,
    Organization,
)
from .reactor import (
    APPROVAL_SURFACES,
    CLOCKS,
    ApprovalRequest,
    ApprovalSurface,
    Clock,
    first_contribution,
    optional_contribution,
)
from .telemetry import operation_result, traced

OPERATIONS_EXTENSION = "operations"
OPERATIONS_VERSION = "2"
#: An approved action that didn't finish: an API error saying every change made (Operations 7).
ACTION_FAILED = "action_failed"
#: The header that carries an approval to an API (Operations 6).
APPROVAL_HEADER = "Poppy-Approval"
#: The `_meta` key that carries an approval to an MCP tool (Operations 6).
APPROVAL_META_KEY = "personalagentprotocol.org/approval"
#: How many times `send` sends an approval, unless told otherwise.
SEND_ATTEMPTS = 3

_T = TypeVar("_T")


class OperationError(PersonalAgentProtocolError):
    """An operation could not be approved, or its approval could not be sent."""


def operations_negotiated(document: DiscoveryDocument, metadata: ClientMetadata) -> bool:
    """Whether both sides list `operations` with this version (another major doesn't count)."""

    company = document.extensions.get(OPERATIONS_EXTENSION)
    agent = metadata.extensions.get(OPERATIONS_EXTENSION)
    return (
        company is not None
        and agent is not None
        and company.version == OPERATIONS_VERSION
        and agent.version == OPERATIONS_VERSION
    )


def operation_from(payload: object) -> Operation:
    """The one operation object, from whichever interface carried it (Operations 4).

    Accepts an API's `403` body (`{"operation": …}`), an MCP tool result
    (`{"structuredContent": {"operation": …}}`), a conversation message
    (`{"operation": …}`, or a `Message`), or the operation itself.
    """

    candidate: object = payload
    if isinstance(payload, Message):
        candidate = payload.operation
    elif isinstance(payload, dict):
        structured = payload.get("structuredContent")
        if isinstance(structured, dict) and "operation" in structured:
            candidate = structured["operation"]
        elif "operation" in payload:
            candidate = payload["operation"]
    if isinstance(candidate, Operation):
        return candidate
    if candidate is None:
        raise ValueError("the payload carries no operation")
    return Operation.model_validate(candidate)


# The `Poppy-Approval` header: an RFC 9651 Dictionary ---------------------------------------


def approval_header(approval: Approval) -> str:
    """The value of `Poppy-Approval`: the two members, as Strings."""

    return f'operation_id="{approval.operation_id}", revision="{approval.revision}"'


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
        # Only a String is a `str` here: nothing else names an operation or a revision.
        if first == ":":
            return (self._match(_BYTES),)
        if first == "@":
            self.at += 1
            return (self._match(_NUMBER),)
        if first == "%":
            return (self._match(_DISPLAY),)
        if first == "-" or first.isdigit():
            return (self._match(_NUMBER),)
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

    A value that isn't a Dictionary is ignored whole (RFC 9651), and so is one
    without both members as Strings of the IDs' characters. Members this version
    doesn't recognize are ignored, so later versions can add them (Operations 6).
    """

    if not value:
        return None
    try:
        members = _Dictionary(value).members()
        return Approval.model_validate(
            {"operation_id": members.get("operation_id"), "revision": members.get("revision")}
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


# The terms check ---------------------------------------------------------------------------

#: A value a `summary` states with decimals, such as an amount.
_DECIMAL = re.compile(r"(?<![\w.])\d[\d,]*\.\d+(?![\w])")
_NUMERIC = re.compile(r"^\d+(\.\d+)?$")


def _leaves(value: object, path: str = "") -> dict[str, object]:
    if isinstance(value, Mapping):
        leaves: dict[str, object] = {}
        for key, item in value.items():
            leaves.update(_leaves(item, f"{path}.{key}" if path else str(key)))
        return leaves
    return {path: value}


def terms_differences(
    operation: Operation, asked: Mapping[str, object] | None = None
) -> tuple[str, ...]:
    """Where `terms` disagree with the `summary`, or with what the agent asked for.

    The company writes both, so the summary alone could describe something other
    than the terms (Operations 5). `asked` gives the values the agent asked for,
    keyed by their dotted paths in `terms`: a different or missing value is a
    difference. Amounts are compared with the summary both ways: every decimal in
    the summary is in the terms, and every number in the terms is in the summary.
    Identifiers aren't, since a summary is written for people. Without `terms`
    there is nothing to compare with.
    """

    leaves = _leaves(operation.terms or {})
    differences: list[str] = []
    for path, wanted in (asked or {}).items():
        if path not in leaves:
            differences.append(f"You asked for {path} {wanted}; the terms don't say.")
        elif str(leaves[path]) != str(wanted):
            differences.append(f"You asked for {path} {wanted}; the terms say {leaves[path]}.")
    if operation.terms is None:
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

    old, new = _leaves(before.terms or {}), _leaves(after.terms or {})
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
    `unknown`: a send failed or timed out and nothing since says whether the action
    was performed, with `operation` when the company answered a retry with one, or
    the company is still performing it: find out another way, such as from the
    order in the company's API, before asking the user about the same action again.
    """

    def __init__(
        self,
        status: Literal["answered", "new_revision", "unknown"],
        *,
        answer: _T | None = None,
        operation: Operation | None = None,
        retry_after: str | None = None,
    ) -> None:
        self.status = status
        self.answer = answer
        self.operation = operation
        self.retry_after = retry_after


def _retry_after(error: PersonalAgentProtocolError) -> str | None:
    details = error.details if isinstance(error.details, Mapping) else {}
    value = details.get("retry_after")
    return value if isinstance(value, str) else None


class OperationsClient:
    """Get the user's approval of an operation, and send it at most once.

    `sleep` waits for `Retry-After` between sends; `max_wait` is the longest wait
    it will do.
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
    ) -> Approval:
        """Ask the user about this revision, through the host's own surface.

        Shows the company's name and the revision's `summary`, with any difference
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
            summary=operation.summary,
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
        return Approval(operation_id=operation.operation_id, revision=operation.revision)

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
        or a longer wait than `max_wait`, the outcome is `unknown`.
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
                return self._sent(answer, approval, uncertain=uncertain)
            if attempt + 1 < attempts and not await self._waited(retry_after):
                break
        return ApprovalSent("unknown", retry_after=retry_after)

    @staticmethod
    def _sent(answer: Any, approval: Approval, *, uncertain: bool) -> ApprovalSent[Any]:
        operation = getattr(answer, "operation", None)
        if not isinstance(operation, Operation):
            return ApprovalSent("answered", answer=answer)
        if operation.revision == approval.revision:
            # Answering an approval with the revision it names would loop for ever.
            raise OperationError(
                "invalid_operation", "The company answered an approval with the same revision"
            )
        return ApprovalSent("unknown" if uncertain else "new_revision", operation=operation)

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
    "APPROVAL_HEADER",
    "APPROVAL_META_KEY",
    "OPERATIONS_EXTENSION",
    "OPERATIONS_VERSION",
    "ApprovalSent",
    "OperationError",
    "OperationsClient",
    "approval_from_meta",
    "approval_header",
    "operation_from",
    "operations_negotiated",
    "parse_approval_header",
    "terms_differences",
]
