# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""PAP 0.2 conversation creation and message continuation."""

from __future__ import annotations

import base64
import inspect
import json
import re
from collections.abc import AsyncGenerator, AsyncIterator, Awaitable, Callable
from typing import Literal, cast
from urllib.parse import urlencode, urlsplit, urlunsplit

import httpx
from pydantic import Field, field_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import ConversationError, ProtocolValidationError
from .json import loads_strict
from .models import (
    ConversationEvent,
    ConversationEventPage,
    ConversationState,
    Message,
    ProtocolModel,
    known_handoff,
    known_responder,
)
from .reactor import RANDOM_SOURCES, RandomSource, first_contribution
from .refusals import refusal_code, refusal_details
from .sessions import AccessToken, PapSession
from .telemetry import by_endpoint, conversation_result, traced
from .transport import SessionHttpClient


class ConversationReceipt(ProtocolModel):
    """What a `POST` without `wait` returns: the conversation and its state (§8.3, §8.7)."""

    conversation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    working: bool
    handoff: Literal["none", "pending"]
    responder: Literal["agent", "human"]
    closed: bool

    _handoff = field_validator("handoff", mode="before")(
        classmethod(lambda cls, value: known_handoff(value))
    )
    _responder = field_validator("responder", mode="before")(
        classmethod(lambda cls, value: known_responder(value))
    )

    @property
    def state(self) -> ConversationState:
        return ConversationState(
            working=self.working,
            handoff=self.handoff,
            responder=self.responder,
            closed=self.closed,
        )


class WorkingChanged(ProtocolModel):
    """A stream's `working` event (§8.6): `working` is no recorded event, so the Company
    sends it with no SSE `id`, when the stream opens and each time it changes."""

    working: bool


class TextDelta(ProtocolModel):
    """A piece of a message still being written (SSE `text-delta`, §7.6).

    For display only: the complete `message` event replaces the pieces, and a
    personal agent MUST NOT act on a delta's text. `actionable` is always
    `False` so a host can route it away from anything that acts.
    """

    message_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    text: str
    actionable: Literal[False] = False


class StreamReconnected(ProtocolModel):
    """The stream was reopened from `Last-Event-ID`.

    `discarded_message_ids` are messages whose pieces arrived but whose
    complete `message` did not: a display drops their partial text (§7.6).
    """

    last_event_id: str | None
    discarded_message_ids: tuple[str, ...] = ()


ConversationResponse = ConversationReceipt | ConversationEventPage
StreamItem = ConversationEvent | TextDelta | StreamReconnected | WorkingChanged
CursorExpiredHandler = Callable[[], Awaitable[None] | None]
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def generate_message_id(reactor: PluginPlatform) -> str:
    """Generate a user-global message ID with at least 128 random bits."""

    random = cast(RandomSource, first_contribution(reactor, RANDOM_SOURCES, "random source"))
    entropy = random.bytes(16)
    if len(entropy) < 16:
        raise ConversationError("insufficient_entropy", "message IDs require 128 random bits")
    return "msg_" + base64.urlsafe_b64encode(entropy).decode().rstrip("=")


class ConversationClient:
    """Start and continue PAP conversations through a proof-bound transport."""

    def __init__(
        self, *, transport: SessionHttpClient, max_response_bytes: int = 1024 * 1024
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.transport = transport
        self.max_response_bytes = max_response_bytes

    @traced("pap.conversation.start", before=by_endpoint, after=conversation_result)
    async def start(
        self,
        endpoint: str,
        message: Message | None,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        parent_conversation_id: str | None = None,
        user_requested_event_id: str | None = None,
        cursor: str | None = None,
        wait: int | None = None,
    ) -> ConversationResponse:
        """Start a conversation; retry the same Message object to preserve its ID.

        `message` may be None only when accepting a `user_requested` event, with
        `parent_conversation_id` and `user_requested_event_id` both given: the company
        then speaks first (§8.10, `accept_user_request`).
        """

        body: dict[str, object] = {}
        if message is not None:
            body["message"] = self._outgoing_message(message)
        if parent_conversation_id is not None:
            self._identifier(parent_conversation_id, "parent conversation ID")
            body["parent_conversation_id"] = parent_conversation_id
        if user_requested_event_id is not None:
            if parent_conversation_id is None:
                raise ValueError("a user_requested event is accepted under its parent")
            self._identifier(user_requested_event_id, "user_requested event ID")
            body["user_requested_event_id"] = user_requested_event_id
        if message is None and user_requested_event_id is None:
            raise ValueError("a conversation starts with a message, or by accepting an invitation")
        return await self._send(
            endpoint,
            body,
            expected_status=201,
            session=session,
            token=token,
            cursor=cursor,
            wait=wait,
        )

    @traced("pap.conversation.send", before=by_endpoint, after=conversation_result)
    async def send(
        self,
        endpoint: str,
        conversation_id: str,
        message: Message,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        cursor: str | None = None,
        wait: int | None = None,
    ) -> ConversationResponse:
        """Continue a conversation with an idempotent, caller-retained message ID."""

        self._identifier(conversation_id, "conversation ID")
        url = f"{endpoint.rstrip('/')}/{conversation_id}/messages"
        return await self._send(
            url,
            {"message": self._outgoing_message(message)},
            expected_status=202,
            session=session,
            token=token,
            cursor=cursor,
            wait=wait,
        )

    @traced("pap.conversation.read_events", before=by_endpoint, after=conversation_result)
    async def read_events(
        self,
        endpoint: str,
        conversation_id: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        cursor: str | None = None,
        wait: int | None = None,
    ) -> ConversationEventPage:
        """Read one ordered page of events after an opaque cursor."""

        self._identifier(conversation_id, "conversation ID")
        target = self._query(
            f"{endpoint.rstrip('/')}/{conversation_id}/events",
            cursor=cursor,
            wait=wait,
        )
        response = await self.transport.request(
            "GET",
            target,
            session=session,
            token=token,
            headers={"Accept": "application/json"},
        )
        page = self._parse_page(response, expected_status=200)
        if page.conversation_id != conversation_id:
            raise ConversationError(
                "conversation_mismatch",
                "conversation event page belongs to a different conversation",
            )
        return page

    async def events(  # noqa: C901 - protocol recovery is one ordered state machine
        self,
        endpoint: str,
        conversation_id: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        cursor: str | None = None,
        wait: int = 30,
        on_cursor_expired: CursorExpiredHandler | None = None,
        max_seen_event_ids: int = 10_000,
    ) -> AsyncGenerator[ConversationEvent, None]:
        """Yield ordered, de-duplicated events until the conversation closes.

        ``has_more`` pages are drained immediately. Long polls use ``wait``.
        If a saved cursor expired, the iterator notifies the host, restarts
        from the beginning once, and retains seen IDs so replayed events are
        not delivered twice.
        """

        if max_seen_event_ids <= 0:
            raise ValueError("max_seen_event_ids must be positive")
        current_cursor = cursor
        seen: set[str] = set()
        recovered_cursor = False
        drain_backlog = False
        while True:
            try:
                page = await self.read_events(
                    endpoint,
                    conversation_id,
                    session=session,
                    token=token,
                    cursor=current_cursor,
                    wait=0 if drain_backlog else wait,
                )
            except ConversationError as exc:
                if exc.code != "cursor_expired" or current_cursor is None or recovered_cursor:
                    raise
                recovered_cursor = True
                current_cursor = None
                if on_cursor_expired is not None:
                    result = on_cursor_expired()
                    if inspect.isawaitable(result):
                        await result
                continue

            for event in page.events:
                if event.id in seen:
                    continue
                if len(seen) >= max_seen_event_ids:
                    raise ConversationError(
                        "event_history_too_large",
                        "conversation event de-duplication limit was exceeded",
                    )
                seen.add(event.id)
                yield event
            current_cursor = page.cursor
            if page.closed and not page.has_more:
                return
            # A backlog must be drained immediately rather than held by a new
            # long poll. Once drained, return to the caller's requested wait.
            drain_backlog = page.has_more

    @traced("pap.conversation.read_until_done", before=by_endpoint, after=conversation_result)
    async def read_until_done(
        self,
        endpoint: str,
        conversation_id: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        cursor: str | None = None,
        wait: int = 30,
        max_reads: int = 100,
    ) -> ConversationEventPage:
        """Read until the Company has no work in progress: `working` false and no backlog
        (§8.7). A successful `POST` only means the Company accepted the request; this is
        how a Personal Agent gets the whole reply, or makes sure everything it sent was acted
        on before closing (§8.12). One page with every event read, in order, and the state
        when the last read answered; `max_reads` bounds a Company that never settles."""

        events: list[ConversationEvent] = []
        seen: set[str] = set()
        current = cursor
        for _ in range(max_reads):
            page = await self.read_events(
                endpoint, conversation_id, session=session, token=token, cursor=current, wait=wait
            )
            for event in page.events:
                if event.id not in seen:
                    seen.add(event.id)
                    events.append(event)
            current = page.cursor
            if not page.has_more and not page.working:
                return page.model_copy(update={"events": events})
        raise ConversationError("still_working", "the company kept working past max_reads")

    @traced("pap.conversation.start_direct", before=by_endpoint, after=conversation_result)
    async def start_direct(
        self,
        endpoint: str,
        parent_conversation_id: str,
        message: Message,
        *,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> ConversationResponse:
        """Open a Direct Conversation under an open parent (§7.10).

        Only the personal agent starts one, for the user to talk with the
        company through the agent's interface. While it is open the parent
        refuses messages and handoff with `direct_conversation_open`, whose
        `details["conversation_id"]` names it.
        """

        return await self.start(
            endpoint,
            message,
            session=session,
            token=token,
            parent_conversation_id=parent_conversation_id,
        )

    @traced("pap.conversation.accept_user_request", before=by_endpoint, after=conversation_result)
    async def accept_user_request(
        self,
        endpoint: str,
        parent_conversation_id: str,
        event_id: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        wait: int | None = None,
    ) -> ConversationResponse:
        """Accept the company's `user_requested` invitation: a Direct Conversation under
        the parent, named by the event, in which the company speaks first (§8.10).

        No message goes: the company records its first message, read with `wait` here
        or by reading or streaming events. Sent again with the same parent and event,
        the company returns the same Direct Conversation, even once it closed. When the
        user returns control to the agent, close it before continuing in the parent.
        """

        return await self.start(
            endpoint,
            None,
            session=session,
            token=token,
            parent_conversation_id=parent_conversation_id,
            user_requested_event_id=event_id,
            wait=wait,
        )

    @traced("pap.conversation.handoff", before=by_endpoint, after=conversation_result)
    async def handoff(
        self,
        endpoint: str,
        conversation_id: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> ConversationReceipt:
        """Ask for a person at the company (§8.9): `handoff` is `pending` while one is
        found, and `responder` becomes `human` when one joins."""

        return await self._control(endpoint, conversation_id, "handoff", 202, session, token)

    @traced("pap.conversation.close", before=by_endpoint, after=conversation_result)
    async def close(
        self,
        endpoint: str,
        conversation_id: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> ConversationReceipt:
        """Close the conversation (§7.12); what it started is not cancelled."""

        return await self._control(endpoint, conversation_id, "close", 200, session, token)

    async def stream(  # noqa: C901 - one SSE reader with its reconnect rules
        self,
        endpoint: str,
        conversation_id: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        last_event_id: str | None = None,
        max_reconnects: int = 5,
        max_seen_event_ids: int = 10_000,
    ) -> AsyncGenerator[StreamItem, None]:
        """Yield events from the company's SSE stream until the conversation closes.

        Reconnects with `Last-Event-ID` set to the last event handled when the
        company ends the stream (§7.6), at most `max_reconnects` times in a
        row without a new event. A company that does not stream answers
        `sse_unsupported`; read with `events()` instead.
        """

        self._identifier(conversation_id, "conversation ID")
        if last_event_id is not None:
            self._identifier(last_event_id, "last event ID")
        url = f"{endpoint.rstrip('/')}/{conversation_id}/events"
        seen: set[str] = set()
        idle_reconnects = 0
        while True:
            progressed = False
            partial: list[str] = []
            headers = {"Accept": "text/event-stream"}
            if last_event_id is not None:
                headers["Last-Event-ID"] = last_event_id
            async with self.transport.stream(
                "GET",
                url,
                session=session,
                token=token,
                headers=headers,
            ) as response:
                content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
                if response.status_code != 200:
                    payload = self._parse_payload(
                        httpx.Response(200, content=await response.aread())
                    )
                    code = payload.get("error") if isinstance(payload, dict) else None
                    raise ConversationError(
                        code if isinstance(code, str) else "conversation_request_failed",
                        "conversation stream was rejected",
                        status_code=response.status_code,
                    )
                if content_type != "text/event-stream":
                    raise ConversationError(
                        "sse_unsupported", "the company does not stream this conversation"
                    )
                async for name, data, event_id in _sse_frames(
                    response.aiter_lines(), self.max_response_bytes
                ):
                    if name == "working":
                        # No recorded event: `working` as the company sends it (§8.6).
                        try:
                            yield WorkingChanged.model_validate(loads_strict(data))
                        except (ValueError, ProtocolValidationError) as exc:
                            raise ConversationError(
                                "invalid_response", "working event was malformed"
                            ) from exc
                        continue
                    if name == "text-delta":
                        try:
                            delta = TextDelta.model_validate(loads_strict(data))
                        except (ValueError, ProtocolValidationError) as exc:
                            raise ConversationError(
                                "invalid_response", "text-delta was malformed"
                            ) from exc
                        if delta.message_id not in partial:
                            partial.append(delta.message_id)
                        yield delta
                        continue
                    try:
                        event = ConversationEvent.model_validate(loads_strict(data))
                    except (ValueError, ProtocolValidationError) as exc:
                        raise ConversationError(
                            "invalid_response", "conversation event was malformed"
                        ) from exc
                    if event_id is not None and event_id != event.id:
                        raise ConversationError("invalid_response", "SSE id and event id disagree")
                    last_event_id = event.id
                    if event.id in seen:
                        continue
                    if len(seen) >= max_seen_event_ids:
                        raise ConversationError(
                            "event_history_too_large",
                            "conversation event de-duplication limit was exceeded",
                        )
                    seen.add(event.id)
                    progressed = True
                    if event.message is not None and event.message.id in partial:
                        partial.remove(event.message.id)
                    yield event
                    if event.type == "state" and event.closed:
                        return
            idle_reconnects = 0 if progressed else idle_reconnects + 1
            if idle_reconnects > max_reconnects:
                raise ConversationError(
                    "stream_unavailable", "the conversation stream kept closing without events"
                )
            yield StreamReconnected(
                last_event_id=last_event_id, discarded_message_ids=tuple(partial)
            )

    async def _control(
        self,
        endpoint: str,
        conversation_id: str,
        action: str,
        expected_status: int,
        session: PapSession,
        token: AccessToken | None = None,
    ) -> ConversationReceipt:
        self._identifier(conversation_id, "conversation ID")
        response = await self.transport.request(
            "POST",
            f"{endpoint.rstrip('/')}/{conversation_id}/{action}",
            session=session,
            token=token,
            headers={"Content-Type": "application/json"},
            content=b"{}",
        )
        payload = self._parse_payload(response)
        if response.status_code != expected_status:
            raise self._rejected(response, payload)
        try:
            return ConversationReceipt.model_validate(payload)
        except ValueError as exc:
            raise ConversationError(
                "invalid_response", "conversation response was malformed"
            ) from exc

    @staticmethod
    def _rejected(response: httpx.Response, payload: object) -> ConversationError:
        # In the JSON body, or a token error in WWW-Authenticate (§3.3, §7).
        code = refusal_code(response, payload, "conversation_request_failed")
        # `extension` of `extension_required` (§3.3), `scope`, and on a 429 `retry_after`,
        # never retried here: the caller waits at least this long (§4.3).
        details = refusal_details(response, payload)
        if code == "direct_conversation_open" and isinstance(payload, dict):
            open_id = payload.get("conversation_id")
            if isinstance(open_id, str) and _IDENTIFIER.fullmatch(open_id):
                details["conversation_id"] = open_id
        return ConversationError(
            code if isinstance(code, str) else "conversation_request_failed",
            "conversation request was rejected",
            status_code=response.status_code,
            details=details or None,
        )

    async def _send(
        self,
        url: str,
        body: dict[str, object],
        *,
        expected_status: int,
        session: PapSession,
        token: AccessToken | None = None,
        cursor: str | None,
        wait: int | None,
    ) -> ConversationResponse:
        target = self._query(url, cursor=cursor, wait=wait)
        response = await self.transport.request(
            "POST",
            target,
            session=session,
            token=token,
            headers={"Content-Type": "application/json"},
            content=json.dumps(body, separators=(",", ":")).encode(),
        )
        payload = self._parse_payload(response)
        if response.status_code != expected_status:
            raise self._rejected(response, payload)
        try:
            if isinstance(payload, dict) and "events" in payload:
                return ConversationEventPage.model_validate(payload)
            return ConversationReceipt.model_validate(payload)
        except ValueError as exc:
            raise ConversationError(
                "invalid_response", "conversation response was malformed"
            ) from exc

    def _parse_payload(self, response: httpx.Response) -> object:
        content = response.content
        if len(content) > self.max_response_bytes:
            raise ConversationError("response_too_large", "conversation response exceeded limit")
        if not content and not response.is_success:
            # A challenge alone: its error is in WWW-Authenticate (§7), a 429 has no body (§5.6).
            return None
        try:
            return loads_strict(content)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ConversationError(
                "invalid_response", "conversation returned invalid JSON"
            ) from exc

    def _parse_page(
        self, response: httpx.Response, *, expected_status: int
    ) -> ConversationEventPage:
        payload = self._parse_payload(response)
        if response.status_code != expected_status:
            raise self._rejected(response, payload)
        try:
            return ConversationEventPage.model_validate(payload)
        except ValueError as exc:
            raise ConversationError(
                "invalid_response", "conversation response was malformed"
            ) from exc

    @staticmethod
    def _outgoing_message(message: Message) -> dict[str, object]:
        if message.role is not None:
            raise ProtocolValidationError("invalid_message", "outgoing messages cannot set role")
        return message.model_dump(mode="json", exclude_none=True)

    @staticmethod
    def _identifier(value: str, label: str) -> None:
        if not _IDENTIFIER.fullmatch(value):
            raise ProtocolValidationError("invalid_identifier", f"{label} is invalid")

    @classmethod
    def _query(cls, value: str, *, cursor: str | None, wait: int | None) -> str:
        parsed = urlsplit(value)
        if parsed.query or parsed.fragment:
            raise ProtocolValidationError(
                "invalid_endpoint", "conversation endpoint cannot have query or fragment"
            )
        query: dict[str, str] = {}
        if cursor is not None:
            cls._identifier(cursor, "cursor")
            query["cursor"] = cursor
        if wait is not None:
            if not isinstance(wait, int) or isinstance(wait, bool) or wait < 0:
                raise ProtocolValidationError("invalid_wait", "wait must be a non-negative integer")
            query["wait"] = str(wait)
        return urlunsplit((*parsed[:3], urlencode(query), ""))


async def _sse_frames(
    lines: AsyncIterator[str], max_event_bytes: int
) -> AsyncIterator[tuple[str, str, str | None]]:
    """Parse SSE into `(event name, data, id)`; comments (keep-alives) are skipped."""

    name, event_id, size = "message", None, 0
    data: list[str] = []
    async for line in lines:
        if line == "":
            if data:
                yield name, "\n".join(data), event_id
            name, event_id, size = "message", None, 0
            data = []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value[1:] if value.startswith(" ") else value
        size += len(value)
        if size > max_event_bytes:
            raise ConversationError("response_too_large", "conversation event exceeded limit")
        if field == "event":
            name = value
        elif field == "data":
            data.append(value)
        elif field == "id":
            event_id = value or None
    if data:
        yield name, "\n".join(data), event_id
