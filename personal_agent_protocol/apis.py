# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Call a company's OpenAPI API with the Session's DPoP token (§6, Operations §4.1).

A read answers its JSON body. A consequential call answers `202` with an
operation: proposed, not performed, until it is confirmed at the operations
endpoint (`OperationsClient`). The same operation object arrives through a
conversation, so one approval flow serves both channels.
"""

from __future__ import annotations

import json
import re
from typing import Any

import httpx

from .errors import PersonalAgentProtocolError, ProtocolValidationError
from .json import loads_strict
from .models import ApiDescriptor, DiscoveryDocument, Operation, ProtocolModel
from .sessions import SessionToken
from .transport import DpopHttpClient


class ApiError(PersonalAgentProtocolError):
    """The company refused an API call; `code` is its error, never its body."""


class ApiResponse(ProtocolModel):
    """A successful API answer: the body, or the operation it proposes."""

    status: int
    body: Any = None
    operation: Operation | None = None


#: API types draft 0.1 defines (§6); any other type is skipped.
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


_CHALLENGE = re.compile(r'(\w+)="([^"]*)"')


def _challenge(header: str) -> tuple[str | None, str | None]:
    """`error` and `scope` from a `DPoP`/`Bearer` WWW-Authenticate challenge."""

    values = dict(_CHALLENGE.findall(header))
    return values.get("error"), values.get("scope")


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
    ) -> ApiResponse:
        """One call; `sign_in_required` and `insufficient_scope` carry the scope asked for."""

        headers = {"Accept": "application/json"}
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
        payload = self._payload(response)
        if response.status_code == 202:
            operation = payload.get("operation") if isinstance(payload, dict) else None
            try:
                return ApiResponse(status=202, operation=Operation.model_validate(operation))
            except ValueError as exc:
                raise ApiError(
                    "invalid_operation", "202 answer carries no valid operation", status_code=202
                ) from exc
        if response.is_success:
            return ApiResponse(status=response.status_code, body=payload)
        error = payload.get("error") if isinstance(payload, dict) else None
        scope = payload.get("scope") if isinstance(payload, dict) else None
        if not isinstance(error, str):
            # Token errors may come only in WWW-Authenticate (§6).
            error, scope = _challenge(response.headers.get("www-authenticate", ""))
        raise ApiError(
            error if isinstance(error, str) else "api_request_failed",
            "the company refused the API call",
            status_code=response.status_code,
            details={"scope": scope} if isinstance(scope, str) else None,
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
