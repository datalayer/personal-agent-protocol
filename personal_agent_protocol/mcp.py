# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A company's MCP server, with a Session Token issued for its url (§4.3, §6).

An MCP server supports DPoP when its protected resource metadata (RFC 9728)
lists `dpop_signing_alg_values_supported`; `fetch_mcp_server_metadata` reads
it (`McpServerMetadata.supports_dpop`). The personal agent then asks for a
Session Token with `resource` set to the server's `url` from poppy.json
(`SessionClient.token_for_mcp`, or `AccountTokenClient.token_for_mcp`
signed in), with a DPoP proof for a DPoP server and without one otherwise,
and uses the scheme `token_type` names:

- `McpDpopAuth` sends a DPoP token with a fresh proof on each request, and
  retries once with the server's nonce on `use_dpop_nonce`.
- `McpBearerAuth` sends a Bearer token. Anyone holding one can use it, so
  it goes only to that exact URL.

Both are `httpx.Auth`s that refuse any other URL before a request is sent,
usable with any MCP client built on httpx. `McpClient` is a minimal
Streamable HTTP client (initialize, tools/list, tools/call) over them, with
no MCP SDK dependency. `McpToolResult.operation` is the operation a
consequential tool proposes in `structuredContent.operation` (Operations
§4.2): the same `Operation` as an API's `202` or a conversation message,
confirmed at the operations endpoint.
"""

from __future__ import annotations

import json
import math
from collections.abc import AsyncGenerator, AsyncIterator, Generator
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import Field, ValidationError, field_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import PersonalAgentProtocolError, ProtocolValidationError, TransportError
from .json import loads_strict
from .models import (
    DPOP_REQUIRED_ALGORITHM,
    ApiDescriptor,
    DiscoveryDocument,
    Operation,
    ProtocolModel,
    _https_url,
)
from .operations import operation_from
from .reactor import (
    DPOP_PROOF_PROVIDERS,
    DpopProofProvider,
    DpopProofRequest,
    SystemClock,
    first_contribution,
    parse_retry_after,
    send_bounded,
)
from .refusals import challenge_parameters, refuse_redirect
from .sessions import SessionToken, Who

MCP_PROTOCOL_VERSION = "2025-06-18"


class McpError(PersonalAgentProtocolError):
    """The MCP server refused a request; `code` is its token or JSON-RPC error."""


def mcp_api(document: DiscoveryDocument) -> ApiDescriptor | None:
    """The company's MCP server, when it lists one."""

    for api in document.apis:
        if api.type == "mcp":
            return api
    return None


class McpServerMetadata(ProtocolModel):
    """An MCP server's protected resource metadata (RFC 9728, §6).

    `dpop_signing_alg_values_supported`, when listed, says the server supports
    DPoP, and then includes ES256 (§4.3).
    """

    resource: str
    authorization_servers: list[str] = Field(min_length=1)
    scopes_supported: list[str] = Field(default_factory=list)
    bearer_methods_supported: list[str] = Field(default_factory=list)
    dpop_signing_alg_values_supported: list[str] | None = None

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        return _https_url(value, "resource")

    @field_validator("authorization_servers")
    @classmethod
    def validate_servers(cls, value: list[str]) -> list[str]:
        return [_https_url(item, "authorization server") for item in value]

    @field_validator("dpop_signing_alg_values_supported")
    @classmethod
    def validate_algorithms(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and DPOP_REQUIRED_ALGORITHM not in value:
            raise ValueError("an MCP server that supports DPoP lists ES256")
        return value

    @property
    def supports_dpop(self) -> bool:
        """Whether the server takes DPoP Session Tokens with proofs (§4.3)."""

        return self.dpop_signing_alg_values_supported is not None


def protected_resource_metadata_url(url: str) -> str:
    """Where an MCP server's RFC 9728 metadata is: the well-known path before its own."""

    parsed = urlsplit(url)
    path = parsed.path.rstrip("/")
    return urlunsplit(
        (parsed.scheme, parsed.netloc, "/.well-known/oauth-protected-resource" + path, "", "")
    )


async def fetch_mcp_server_metadata(
    http_client: httpx.AsyncClient,
    url: str,
    *,
    issuer: str,
    max_response_bytes: int = 64 * 1024,
) -> McpServerMetadata:
    """The MCP server's protected resource metadata, checked against poppy.json (§6).

    Its `resource` is the server's `url`, and its `authorization_servers`
    include the company's `auth.issuer`; anything else is `McpError`
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


class McpDpopAuth(httpx.Auth):
    """Send a DPoP Session Token with a fresh proof to one MCP server's URL (§4.3).

    The proof is signed by the host's `pap.dpopProofProvider` for the user and
    company in `who`. A `use_dpop_nonce` refusal is retried once, with a new
    proof carrying the server's `DPoP-Nonce`.
    """

    requires_response_body = False

    def __init__(
        self, token: SessionToken, resource: str, *, reactor: PluginPlatform, who: Who
    ) -> None:
        if token.token_type != "DPoP":  # noqa: S105 - OAuth token type
            raise TransportError(
                "unexpected_token_type", "A DPoP MCP server takes a DPoP token issued for its url"
            )
        if urlsplit(resource).scheme != "https":
            raise TransportError("invalid_url", "an MCP server's url must use HTTPS")
        self._token = token
        self.resource = resource
        self.reactor = reactor
        self.who = who

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        raise TransportError("sync_unsupported", "DPoP proofs for MCP are signed asynchronously")
        yield request  # pragma: no cover - a generator for httpx

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        if _target(request.url) != _target(self.resource):
            raise TransportError(
                "token_not_for_this_url",
                "A Session Token for an MCP server is sent only to that server",
            )
        nonce: str | None = None
        for attempt in range(2):
            await self._sign(request, nonce)
            response = yield request
            challenge = challenge_parameters(response.headers.get("www-authenticate", ""))
            if response.status_code != 401 or challenge.get("error") != "use_dpop_nonce":
                return
            nonce = response.headers.get("dpop-nonce")
            if attempt or not nonce:
                return

    async def _sign(self, request: httpx.Request, nonce: str | None) -> None:
        provider = cast(
            DpopProofProvider,
            first_contribution(self.reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"),
        )
        proof = await provider.create(
            DpopProofRequest(
                method=request.method,
                url=str(request.url),
                tenant_id=self.who["tenant_id"],
                issuer=self.who["issuer"],
                session_key=self._token.session_key,
                access_token=self._token.access_token,
                nonce=nonce,
            )
        )
        request.headers["Authorization"] = f"DPoP {self._token.access_token.get_secret_value()}"
        request.headers["DPoP"] = proof.get_secret_value()


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
    """Initialize, list, and call tools on one MCP server with a token issued for its url.

    A DPoP token (from a server that supports DPoP) is sent with proofs and
    needs the host's `reactor` and `who` the Session is for; a Bearer token
    needs neither.
    """

    def __init__(
        self,
        *,
        http_client: httpx.AsyncClient,
        token: SessionToken,
        url: str,
        reactor: PluginPlatform | None = None,
        who: Who | None = None,
        max_response_bytes: int = 1024 * 1024,
    ) -> None:
        self.http = http_client
        self.url = url
        self.auth: httpx.Auth
        if token.token_type == "DPoP":  # noqa: S105 - OAuth token type
            if reactor is None or who is None:
                raise TransportError(
                    "dpop_unavailable", "A DPoP token for MCP needs the host's reactor and who"
                )
            self.auth = McpDpopAuth(token, url, reactor=reactor, who=who)
        else:
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
        refuse_redirect(response, McpError)
        session_id = response.headers.get("mcp-session-id")
        if session_id:
            self._session_id = session_id
        if response.status_code in {401, 403}:
            raise _refusal(response)
        if response.status_code == 202 or "id" not in message:
            return None
        if response.status_code == 429:
            raise _rate_limited(response)
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
    """A `429`: `rate_limited`, its `Retry-After` kept as the other clients keep it (§4.3).

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
    """A token refusal, from the `Bearer` or `DPoP` challenges (§6) or the body."""

    values = challenge_parameters(response.headers.get("www-authenticate", ""))
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
