# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Serve a `CompanyService` over plain ASGI (no web framework needed)."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from typing import Any

from .service import CompanyRequest, CompanyService

#: The largest request body the company reads; larger is `413`, as in the
#: TypeScript company's Node adapter.
MAX_BODY_BYTES = 1 << 20

#: Headers a repeat of which is joined, so the joined value fails its check (§5.3, RFC 9449 §4.3).
_JOINED_HEADERS = ("poppy-session", "dpop")
#: Headers a request carries at most once: a second is refused (`400`).
#: One credential per request: a repeated one is never merged or picked from (RFC 6750 §2).
#: A repeated `Poppy-Session` header is joined, so it fails as `invalid_session` (§5.3).
_SINGLE_HEADERS = ("authorization",)

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


async def _send_json(send: Send, status: int, payload: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json"), (b"cache-control", b"no-store")],
        }
    )
    await send({"type": "http.response.body", "body": payload})


def _encoded(headers: Mapping[str, str]) -> list[tuple[bytes, bytes]]:
    """Response headers; a `Set-Cookie` holding several cookies, one per line, is one each."""

    return [
        (name.encode(), line.encode())
        for name, value in headers.items()
        for line in (value.split("\n") if name.lower() == "set-cookie" else (value,))
    ]


def _headers(raw: list[tuple[bytes, bytes]]) -> dict[str, str]:
    """Lower-case names; a repeated `Poppy-Session` or `DPoP` header is joined, so it fails."""

    headers: dict[str, str] = {}
    for raw_name, raw_value in raw:
        name, value = raw_name.decode().lower(), raw_value.decode()
        joined = name in _JOINED_HEADERS and name in headers
        headers[name] = f"{headers[name]}, {value}" if joined else value
    return headers


def company_app(service: CompanyService) -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    """An ASGI application answering at the company's own HTTPS origin.

    The request URL is rebuilt on `service.config.base`, the origin the
    company publishes, so Session JWT `htu` checks compare against what the
    personal agent signed whatever proxy or test transport is in front.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if len(body) > MAX_BODY_BYTES:
                await _send_json(send, 413, b'{"error":"request_too_large"}')
                return
            if not message.get("more_body"):
                break
        query = scope.get("query_string", b"").decode()
        url = f"{service.config.base}{scope['path']}" + (f"?{query}" if query else "")
        names = [name.decode().lower() for name, _ in scope["headers"]]
        if any(names.count(name) > 1 for name in _SINGLE_HEADERS):
            # One credential per request: a repeated one is never merged or picked
            # from (RFC 6750 §2).
            await _send_json(send, 400, b'{"error":"invalid_request"}')
            return
        headers = _headers(scope["headers"])
        response = await service.handle(
            CompanyRequest(method=scope["method"], url=url, headers=headers, body=body)
        )
        if response.stream is not None:
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status,
                    "headers": _encoded(response.headers),
                }
            )
            async for chunk in response.stream:
                await send({"type": "http.response.body", "body": chunk, "more_body": True})
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        if isinstance(response.body, str):
            # A page (the consent page): its own Content-Type is in its headers.
            payload = response.body.encode()
            headers_out = dict(response.headers)
        else:
            payload = b"" if response.body is None else json.dumps(response.body).encode()
            headers_out = {"Content-Type": "application/json", **response.headers}
        await send(
            {
                "type": "http.response.start",
                "status": response.status,
                "headers": _encoded(headers_out),
            }
        )
        await send({"type": "http.response.body", "body": payload})

    return app
