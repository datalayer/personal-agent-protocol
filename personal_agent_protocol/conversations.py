# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""PAP 0.1 conversation creation and message continuation."""

from __future__ import annotations

import base64
import json
import re
from typing import Literal, cast
from urllib.parse import urlencode, urlsplit, urlunsplit

from pydantic import Field
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import ConversationError, ProtocolValidationError
from .json import loads_strict
from .models import ConversationEventPage, Message, ProtocolModel
from .reactor import RANDOM_SOURCES, RandomSource, first_contribution
from .sessions import SessionToken
from .transport import DpopHttpClient


class ConversationReceipt(ProtocolModel):
    """State returned after a message when the caller does not wait for events."""

    conversation_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    status: Literal["working", "idle", "queued", "closed"]
    responder: Literal["agent", "human"]


ConversationResponse = ConversationReceipt | ConversationEventPage
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

    def __init__(self, *, transport: DpopHttpClient, max_response_bytes: int = 1024 * 1024) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.transport = transport
        self.max_response_bytes = max_response_bytes

    async def start(
        self,
        endpoint: str,
        message: Message,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
        parent_conversation_id: str | None = None,
        cursor: str | None = None,
        wait: int | None = None,
    ) -> ConversationResponse:
        """Start a conversation; retry the same Message object to preserve its ID."""

        body: dict[str, object] = {"message": self._outgoing_message(message)}
        if parent_conversation_id is not None:
            self._identifier(parent_conversation_id, "parent conversation ID")
            body["parent_conversation_id"] = parent_conversation_id
        return await self._send(
            endpoint,
            body,
            expected_status=201,
            token=token,
            tenant_id=tenant_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            cursor=cursor,
            wait=wait,
        )

    async def send(
        self,
        endpoint: str,
        conversation_id: str,
        message: Message,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
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
            token=token,
            tenant_id=tenant_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            cursor=cursor,
            wait=wait,
        )

    async def _send(
        self,
        url: str,
        body: dict[str, object],
        *,
        expected_status: int,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
        cursor: str | None,
        wait: int | None,
    ) -> ConversationResponse:
        target = self._query(url, cursor=cursor, wait=wait)
        response = await self.transport.request(
            "POST",
            target,
            token=token,
            tenant_id=tenant_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            headers={"Content-Type": "application/json"},
            content=json.dumps(body, separators=(",", ":")).encode(),
        )
        if len(response.content) > self.max_response_bytes:
            raise ConversationError("response_too_large", "conversation response exceeded limit")
        try:
            payload = loads_strict(response.content)
        except (UnicodeDecodeError, ValueError) as exc:
            raise ConversationError(
                "invalid_response", "conversation returned invalid JSON"
            ) from exc
        if response.status_code != expected_status:
            code = payload.get("error") if isinstance(payload, dict) else None
            raise ConversationError(
                code if isinstance(code, str) else "conversation_request_failed",
                "conversation request was rejected",
                status_code=response.status_code,
            )
        try:
            if isinstance(payload, dict) and "events" in payload:
                return ConversationEventPage.model_validate(payload)
            return ConversationReceipt.model_validate(payload)
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
