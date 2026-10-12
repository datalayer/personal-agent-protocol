# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A company's MCP server with a resource-bound Bearer Session Token (§4.3, §6).

MCP authorization uses Bearer tokens, so for MCP the personal agent asks for
a Session Token without a DPoP proof and with `resource` set to the MCP
server's `url` from poppy.json (`SessionClient.bearer_for_mcp`, or
`AccountTokenClient.bearer_for_mcp` signed in). Anyone holding a Bearer token
can use it, so this module sends it only to that exact URL:

- `McpBearerAuth` is an `httpx.Auth` that adds the token to requests for the
  MCP server's URL and refuses every other request, before it is sent. Use it
  with any MCP client built on httpx (for example the MCP SDK's Streamable
  HTTP client, `auth=McpBearerAuth(...)`).
- `McpClient` is a minimal Streamable HTTP client (initialize, tools/list,
  tools/call) over that auth, with no MCP SDK dependency.
- `McpToolResult.operation` is the operation a consequential tool proposes in
  `structuredContent.operation` (Operations §4.2): the same `Operation` as an
  API's `202` or a conversation message, confirmed at the operations endpoint.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Generator
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import Field

from .errors import PersonalAgentProtocolError, ProtocolValidationError, TransportError
from .json import loads_strict
from .models import ApiDescriptor, DiscoveryDocument, Operation, ProtocolModel
from .operations import operation_from
from .reactor import send_bounded
from .sessions import SessionToken

MCP_PROTOCOL_VERSION = "2025-06-18"


class McpError(PersonalAgentProtocolError):
    """The MCP server refused a request; `code` is its token or JSON-RPC error."""


def mcp_api(document: DiscoveryDocument) -> ApiDescriptor | None:
    """The company's MCP server, when it lists one."""

    for api in document.apis:
        if api.type == "mcp":
            return api
    return None


def _target(url: str | httpx.URL) -> tuple[str, str, int, str]:
    parsed = urlsplit(str(url))
    return (
        parsed.scheme,
        (parsed.hostname or "").lower(),
        parsed.port or 443,
        parsed.path or "/",
    )


class McpBearerAuth(httpx.Auth):
    """Send a Bearer Session Token to one MCP server's URL, and nowhere else."""

    requires_response_body = False

    def __init__(self, token: SessionToken, resource: str) -> None:
        if token.token_type != "Bearer":  # noqa: S105 - OAuth token type
            raise TransportError(
                "unexpected_token_type", "MCP uses a Bearer token issued for its url"
            )
        if urlsplit(resource).scheme != "https":
            raise TransportError("invalid_url", "an MCP server's url must use HTTPS")
        self._token = token
        self.resource = resource

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        if _target(request.url) != _target(self.resource):
            # A copied Bearer token works for anyone: it never leaves its MCP server.
            raise TransportError(
                "bearer_not_for_this_url",
                "A Bearer Session Token is sent only to the MCP server it was issued for",
            )
        request.headers["Authorization"] = f"Bearer {self._token.access_token.get_secret_value()}"
        yield request


class McpToolResult(ProtocolModel):
    """A tool's answer; `operation` is set when it proposed one (Operations §4.2)."""

    content: list[dict[str, Any]] = Field(default_factory=list)
    structured_content: dict[str, Any] | None = None
    is_error: bool = False
    operation: Operation | None = None

    @property
    def text(self) -> str:
        return "\n".join(
            str(item.get("text", "")) for item in self.content if item.get("type") == "text"
        )


class McpClient:
    """Initialize, list, and call tools on one MCP server with a resource-bound Bearer token."""

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient,
        token: SessionToken,
        url: str,
        max_response_bytes: int = 1024 * 1024,
    ) -> None:
        self.http = http_client
        self.url = url
        self.auth = McpBearerAuth(token, url)
        self.max_response_bytes = max_response_bytes
        self._next_id = 0
        self._session_id: str | None = None
        self._initialized = False

    async def initialize(self) -> dict[str, Any]:
        result = await self._call(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "personal-agent-protocol", "version": "1"},
            },
        )
        self._initialized = True
        await self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    async def list_tools(self) -> list[dict[str, Any]]:
        await self._ensure_initialized()
        tools = (await self._call("tools/list", {})).get("tools")
        if not isinstance(tools, list):
            raise McpError("invalid_response", "tools/list did not return tools")
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> McpToolResult:
        await self._ensure_initialized()
        result = await self._call("tools/call", {"name": name, "arguments": arguments or {}})
        structured = result.get("structuredContent")
        operation = None
        if isinstance(structured, dict) and "operation" in structured:
            try:
                operation = operation_from(result)
            except ValueError as exc:
                raise McpError(
                    "invalid_operation", "the tool proposed a malformed operation"
                ) from exc
        content = result.get("content")
        return McpToolResult(
            content=content if isinstance(content, list) else [],
            structured_content=structured if isinstance(structured, dict) else None,
            is_error=result.get("isError") is True,
            operation=operation,
        )

    async def _ensure_initialized(self) -> None:
        if not self._initialized:
            await self.initialize()

    async def _call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        message = await self._post(
            {"jsonrpc": "2.0", "id": self._next_id, "method": method, "params": params}
        )
        if not isinstance(message, dict):
            raise McpError("invalid_response", "MCP answered no JSON-RPC message")
        error = message.get("error")
        if isinstance(error, dict):
            raise McpError("jsonrpc_error", f"MCP error {error.get('code')}")
        result = message.get("result")
        if not isinstance(result, dict):
            raise McpError("invalid_response", "MCP answered no result")
        return result

    async def _post(self, message: dict[str, Any]) -> object:  # noqa: C901 - JSON or SSE
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if self._initialized:
            headers["MCP-Protocol-Version"] = MCP_PROTOCOL_VERSION
        if self._session_id is not None:
            headers["Mcp-Session-Id"] = self._session_id
        try:
            response = await send_bounded(
                self.http,
                self.http.build_request(
                    "POST",
                    self.url,
                    content=json.dumps(message, separators=(",", ":")).encode(),
                    headers=headers,
                ),
                max_bytes=self.max_response_bytes,
                auth=self.auth,
            )
        except httpx.HTTPError as exc:
            raise TransportError("request_failed", "MCP request failed") from exc
        session_id = response.headers.get("mcp-session-id")
        if session_id:
            self._session_id = session_id
        if response.status_code in {401, 403}:
            raise _refusal(response)
        if response.status_code == 202 or "id" not in message:
            return None
        if response.status_code != 200:
            raise McpError("http_error", "MCP request failed", status_code=response.status_code)
        if len(response.content) > self.max_response_bytes:
            raise McpError("response_too_large", "MCP response exceeded limit")
        kind = response.headers.get("content-type", "").split(";", 1)[0].strip()
        try:
            if kind == "text/event-stream":
                async for data in _sse_data(response.text):
                    parsed = loads_strict(data)
                    if isinstance(parsed, dict) and parsed.get("id") == message["id"]:
                        return parsed
                raise McpError("invalid_response", "the MCP stream ended without an answer")
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise McpError("invalid_json", "MCP answered invalid JSON") from exc


def _refusal(response: httpx.Response) -> McpError:
    """A token refusal, from the Bearer challenge (RFC 6750) or the body."""

    challenge = response.headers.get("www-authenticate", "")
    values: dict[str, str] = {}
    for part in challenge.removeprefix("Bearer").split(","):
        name, _, value = part.strip().partition("=")
        if name:
            values[name] = value.strip('"')
    code = values.get("error")
    if code is None:
        try:
            payload = response.json()
        except ValueError:
            payload = None
        error = payload.get("error") if isinstance(payload, dict) else None
        code = error if isinstance(error, str) else "unauthorized"
    details: dict[str, object] = {}
    if "scope" in values:
        details["scope"] = values["scope"]
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict) and isinstance(payload.get("extension"), str):
        details["extension"] = payload["extension"]
    return McpError(
        code,
        "the MCP server refused the token",
        status_code=response.status_code,
        details=details or None,
    )


async def _sse_data(text: str) -> AsyncIterator[str]:
    data: list[str] = []
    for line in [*text.splitlines(), ""]:
        if not line:
            if data:
                yield "\n".join(data)
            data = []
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
