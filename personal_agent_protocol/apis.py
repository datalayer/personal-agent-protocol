# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Call a company's OpenAPI API with the Session's DPoP token (§6, Operations §4.1).

A read answers its JSON body. A consequential call answers `202` with an
operation: proposed, not performed, until it is confirmed at the operations
endpoint (`OperationsClient`). The same operation object arrives through a
conversation, so one approval flow serves both channels.

Every write (POST, PUT, PATCH, DELETE) carries an `Idempotency-Key` (guides,
*Retries*): a random UUID (version 4), or the caller's own key when it
retries the same request. The key used comes back on the response and on
the `ApiError`, so a retry can send it again; the company answers a repeated
key with its original response.
"""

from __future__ import annotations

import json
import re
import uuid
from typing import Any

import httpx

from .errors import PersonalAgentProtocolError, ProtocolValidationError
from .json import loads_strict
from .models import ApiDescriptor, DiscoveryDocument, Operation, ProtocolModel
from .refusals import challenge_parameters, refusal_details
from .sessions import SessionToken
from .transport import DpopHttpClient


class ApiError(PersonalAgentProtocolError):
    """The company refused an API call; `code` is its error, never its body.

    `idempotency_key` is the key a write was sent with, to send again on a retry.
    """

    idempotency_key: str | None = None


class ApiResponse(ProtocolModel):
    """A successful API answer: the body, or the operation it proposes."""

    status: int
    body: Any = None
    operation: Operation | None = None
    #: The `Idempotency-Key` a write was sent with; `None` for a read.
    idempotency_key: str | None = None


#: The methods that change something: each carries an `Idempotency-Key` (guides, *Retries*).
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

#: What a company accepts as an `Idempotency-Key`: 1 to 255 visible ASCII characters.
IDEMPOTENCY_KEY = re.compile(r"[\x21-\x7e]{1,255}")


def new_idempotency_key() -> str:
    """A fresh key for a write: a random UUID (version 4)."""

    return str(uuid.uuid4())


#: API types draft 0.2 defines (§6); any other type is skipped.
KNOWN_API_TYPES = frozenset({"openapi", "mcp"})


def known_apis(document: DiscoveryDocument) -> list[ApiDescriptor]:
    """The APIs whose type this SDK knows, skipping the rest so later versions can add types."""

    return [api for api in document.apis if api.type in KNOWN_API_TYPES]


def conversation_endpoint(document: DiscoveryDocument) -> str | None:
    """The `poppy` conversation endpoint, skipping protocol types this SDK does not speak."""

    if document.agent is None:
        return None
    for protocol in document.agent.protocols:
        if protocol.type == "poppy":
            return protocol.endpoint
    return None


def openapi_url(document: DiscoveryDocument) -> str | None:
    """The company's OpenAPI description, when it advertises one."""

    for api in document.apis:
        if api.type == "openapi":
            return api.url
    return None


class ApiClient:
    """Read and change through a company's API, the credentials host-owned."""

    def __init__(self, *, transport: DpopHttpClient, max_response_bytes: int = 1024 * 1024) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.transport = transport
        self.max_response_bytes = max_response_bytes

    async def call(
        self,
        method: str,
        url: str,
        *,
        token: SessionToken,
        tenant_id: str,
        pairwise_user_id: str,
        issuer: str,
        body: Any = None,
        idempotency_key: str | None = None,
    ) -> ApiResponse:
        """One call; `sign_in_required` and `insufficient_scope` carry the scope asked for.

        A write sends `idempotency_key`, or a new random one; pass the key of an
        earlier attempt to retry the same request. A read takes none.
        """

        method = method.upper()
        headers = {"Accept": "application/json"}
        key: str | None = None
        if method in WRITE_METHODS:
            key = new_idempotency_key() if idempotency_key is None else idempotency_key
            if not IDEMPOTENCY_KEY.fullmatch(key):
                raise ValueError("an Idempotency-Key is 1 to 255 visible ASCII characters")
            headers["Idempotency-Key"] = key
        elif idempotency_key is not None:
            raise ValueError("only a write (POST, PUT, PATCH, DELETE) takes an Idempotency-Key")
        content = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            content = json.dumps(body, separators=(",", ":")).encode()
        response = await self.transport.request(
            method,
            url,
            token=token,
            tenant_id=tenant_id,
            pairwise_user_id=pairwise_user_id,
            issuer=issuer,
            headers=headers,
            content=content,
        )
        try:
            return self._answer(response, key)
        except ApiError as error:
            error.idempotency_key = key
            raise

    def _answer(self, response: httpx.Response, key: str | None) -> ApiResponse:
        payload = self._payload(response)
        if response.status_code == 202:
            operation = payload.get("operation") if isinstance(payload, dict) else None
            try:
                return ApiResponse(
                    status=202,
                    operation=Operation.model_validate(operation),
                    idempotency_key=key,
                )
            except ValueError as exc:
                raise ApiError(
                    "invalid_operation", "202 answer carries no valid operation", status_code=202
                ) from exc
        if response.is_success:
            return ApiResponse(status=response.status_code, body=payload, idempotency_key=key)
        error = payload.get("error") if isinstance(payload, dict) else None
        if not isinstance(error, str):
            # Token errors, and `extension_required` with its `extension` attribute,
            # come in WWW-Authenticate at an API (§3.3, §6).
            error = challenge_parameters(response.headers.get("www-authenticate", "")).get("error")
        # `scope`, `extension`, and on a 429 `retry_after`: never retried here (§4.3).
        details = refusal_details(response, payload)
        raise ApiError(
            error if isinstance(error, str) else "api_request_failed",
            "the company refused the API call",
            status_code=response.status_code,
            details=details or None,
        )

    def _payload(self, response: httpx.Response) -> object:
        if len(response.content) > self.max_response_bytes:
            raise ApiError("response_too_large", "API response exceeded limit")
        if not response.content:
            return None
        try:
            return loads_strict(response.content)
        except (ValueError, ProtocolValidationError) as exc:
            raise ApiError("invalid_json", "API response was not JSON") from exc
