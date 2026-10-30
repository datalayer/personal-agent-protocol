# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A company's MCP server, with an access token issued for its url (§4.5, §7).

The server's protected resource metadata (RFC 9728) has its `url` from
poppy.json as `resource` and the Company's issuer among its
`authorization_servers`; `fetch_mcp_server_metadata` reads and checks it.
Signed in, the personal agent asks for an access token with `resource` set to
that `url` (`RefreshTokenClient.token_for_mcp`, a refresh with `resource`) and
uses it there only. Every request carries the Session header; signed out, the
Session header alone, which a server that accepts it may allow.

`McpSessionAuth` is an `httpx.Auth` that refuses any other URL before a request
is sent, usable with any MCP client built on httpx. `McpClient` is a minimal
Streamable HTTP client (initialize, tools/list, tools/call) over it, with no MCP
SDK dependency. `McpToolResult.operation` is the operation a tool returns for the
user's approval, in `structuredContent.operation` of an error result, and
`call_tool(approval=...)` calls it again with the approval (Operations 4, 6).
"""

from __future__ import annotations

import json
import math
from collections.abc import AsyncGenerator, AsyncIterator, Generator
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import Field, ValidationError
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import PersonalAgentProtocolError, ProtocolValidationError, TransportError
from .json import loads_strict
from .models import (
    ApiDescriptor,
    Approval,
    DiscoveryDocument,
    Operation,
    ProtectedResourceMetadata,
    ProtocolModel,
    protected_resource_metadata_url,
)
from .operations import APPROVAL_META_KEY, operation_from
from .reactor import SystemClock, parse_retry_after, send_bounded
from .refusals import challenge_parameters, dpop_nonce_asked, refuse_redirect
from .sessions import DPOP_NONCE_HEADER, AccessToken, PapSession
from .transport import invalid_session, session_headers

MCP_PROTOCOL_VERSION = "2025-06-18"


class McpError(PersonalAgentProtocolError):
    """The MCP server refused a request; `code` is its token or JSON-RPC error."""


def mcp_api(document: DiscoveryDocument) -> ApiDescriptor | None:
    """The company's MCP server, when it lists one."""

    for api in document.apis:
        if api.type == "mcp":
            return api
    return None


#: An MCP server's protected resource metadata (RFC 9728, §7).
McpServerMetadata = ProtectedResourceMetadata


async def fetch_mcp_server_metadata(
    http_client: httpx.AsyncClient,
    url: str,
    *,
    issuer: str,
    max_response_bytes: int = 64 * 1024,
) -> McpServerMetadata:
    """The MCP server's protected resource metadata, checked against poppy.json (§7).

    Its `resource` is the server's `url`, and its `authorization_servers`
    include the company's issuer; anything else is `McpError`
    (`invalid_resource_metadata`). No redirect is followed.
    """

    try:
        response = await send_bounded(
            http_client,
            http_client.build_request(
                "GET", protected_resource_metadata_url(url), headers={"Accept": "application/json"}
            ),
            max_bytes=max_response_bytes,
        )
    except httpx.HTTPError as exc:
        raise McpError("request_failed", "MCP resource metadata request failed") from exc
    refuse_redirect(response, McpError)
    if response.status_code != 200 or len(response.content) > max_response_bytes:
        raise McpError(
            "invalid_resource_metadata",
            "MCP resource metadata is unavailable",
            status_code=response.status_code,
        )
    try:
        metadata = McpServerMetadata.model_validate(loads_strict(response.content))
    except (ValidationError, ProtocolValidationError) as exc:
        raise McpError("invalid_resource_metadata", "MCP resource metadata is malformed") from exc
    if metadata.resource != url or issuer not in metadata.authorization_servers:
        raise McpError(
            "invalid_resource_metadata",
            "MCP resource metadata names another resource or authorization server",
        )
    return metadata


def _target(url: str | httpx.URL) -> tuple[str, str, int, str]:
    parsed = urlsplit(str(url))
    return (
        parsed.scheme,
        (parsed.hostname or "").lower(),
        parsed.port or 443,
        parsed.path or "/",
    )


class McpSessionAuth(httpx.Auth):
    """The Session header, and signed in a token, to one MCP server's URL only (§7).

    The token was issued for that server's `url` and works nowhere else; the
    Session JWT is signed for each request by the host's `pap.sessionSigner`, and with
    a `DPoP` token a proof by `pap.dpopProver`. A `use_dpop_nonce` challenge is
    retried once, and the server's latest nonce kept for its later requests (§4.5).
    """

    requires_response_body = False

    def __init__(
        self,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None,
        reactor: PluginPlatform,
    ) -> None:
        if urlsplit(url).scheme != "https":
            raise TransportError("invalid_url", "an MCP server's url must use HTTPS")
        if token is not None and token.resource != url:
            raise TransportError(
                "token_not_for_this_url", "An MCP server takes a token issued for its url"
            )
        self.url = url
        self.session = session
        self.token = token
        self.reactor = reactor
        self.dpop_nonce: str | None = None

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        raise TransportError("sync_unsupported", "Session JWTs are signed asynchronously")
        yield request  # pragma: no cover - a generator for httpx

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        if _target(request.url) != _target(self.url):
            # A token for an MCP server never leaves it (§7).
            raise TransportError(
                "token_not_for_this_url",
                "A token for an MCP server is sent only to that server",
            )
        request.headers.update(await self._signed(request))
        response = yield request
        bound = self.token is not None and self.token.token_type == "DPoP"  # noqa: S105
        if not bound:
            return
        asked = dpop_nonce_asked(response)
        self.dpop_nonce = response.headers.get(DPOP_NONCE_HEADER, self.dpop_nonce)
        if asked is not None:
            request.headers.update(await self._signed(request))
            response = yield request
            self.dpop_nonce = response.headers.get(DPOP_NONCE_HEADER, self.dpop_nonce)

    async def _signed(self, request: httpx.Request) -> dict[str, str]:
        return await session_headers(
            self.reactor,
            request.method,
            str(request.url),
            session=self.session,
            token=self.token,
            dpop_nonce=self.dpop_nonce,
        )


class McpToolResult(ProtocolModel):
    """A tool's answer; `operation` is set when it needs the user's approval (Operations 4)."""

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
    """Initialize, list, and call tools on one MCP server, in a Session (§7).

    Signed in with `token`, an access token issued for `url`; signed out without.
    """

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient,
        url: str,
        session: PapSession,
        reactor: PluginPlatform,
        token: AccessToken | None = None,
        max_response_bytes: int = 1024 * 1024,
    ) -> None:
        self.http = http_client
        self.url = url
        self.session = session
        self.auth: httpx.Auth = McpSessionAuth(url, session=session, token=token, reactor=reactor)
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

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        approval: Approval | None = None,
    ) -> McpToolResult:
        """Call a tool; `approval` goes with the same call as the one that returned it."""

        await self._ensure_initialized()
        params: dict[str, Any] = {"name": name, "arguments": arguments or {}}
        if approval is not None:
            params["_meta"] = {
                APPROVAL_META_KEY: {
                    "operation_id": approval.operation_id,
                    "revision": approval.revision,
                }
            }
        result = await self._call("tools/call", params)
        structured = result.get("structuredContent")
        operation = None
        if isinstance(structured, dict) and "operation" in structured:
            try:
                operation = operation_from(result)
            except ValueError as exc:
                raise McpError(
                    "invalid_operation", "the tool returned a malformed operation"
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
        for restarted in (False, True):
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
            refuse_redirect(response, McpError)
            if not invalid_session(response):
                break
            if restarted:
                raise McpError(
                    "invalid_session", "MCP refused the Session", status_code=response.status_code
                )
            # The Session failed a check or has ended: a new one, once (§5.5, §7).
            self.session.restart()
        session_id = response.headers.get("mcp-session-id")
        if session_id:
            self._session_id = session_id
        if response.status_code in {401, 403}:
            raise _refusal(response)
        if response.status_code == 202 or "id" not in message:
            return None
        if response.status_code == 429:
            raise _rate_limited(response)
        if response.status_code == 503:
            # Being performed, or not known yet: send it again (Operations 7).
            retry_after = response.headers.get("retry-after")
            raise McpError(
                "temporarily_unavailable",
                "the MCP server can't answer yet",
                status_code=503,
                details={"retry_after": retry_after} if retry_after else None,
            )
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


def _rate_limited(response: httpx.Response) -> McpError:
    """A `429`: `rate_limited`, its `Retry-After` kept as the other clients keep it (§5.6).

    Never retried here: the caller waits at least this long. The message says
    when, in seconds, for the model reading the error.
    """

    retry_after = response.headers.get("retry-after")
    seconds = parse_retry_after(retry_after, SystemClock().now())
    return McpError(
        "rate_limited",
        "the MCP server is rate limited"
        + ("" if seconds is None else f", retry after {math.ceil(seconds)} s"),
        status_code=response.status_code,
        details={"retry_after": retry_after} if retry_after else None,
    )


def _refusal(response: httpx.Response) -> McpError:
    """A token refusal, from the `WWW-Authenticate` challenge (§7) or the body.

    A challenge with no error code (signed out) is `insufficient_scope` (§7); its
    `resource_metadata` is kept, so a stale view of the server is read again.
    """

    values = challenge_parameters(response.headers.get("www-authenticate", ""))
    code = values.get("error")
    if code is None and response.status_code == 401 and "scope" in values:
        code = "insufficient_scope"
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
    if "resource_metadata" in values:
        details["resource_metadata"] = values["resource_metadata"]
    try:
        payload = response.json()
    except ValueError:
        payload = None
    extension = payload.get("extension") if isinstance(payload, dict) else None
    extension = extension if isinstance(extension, str) else values.get("extension")
    if extension:
        # The server refuses the personal agent entirely, never one tool (§6).
        details["extension"] = extension
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
