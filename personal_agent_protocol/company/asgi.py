# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Serve a `CompanyService` over plain ASGI (no web framework needed)."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from .service import CompanyRequest, CompanyService

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]


def company_app(service: CompanyService) -> Callable[[Scope, Receive, Send], Awaitable[None]]:
    """An ASGI application answering at the company's own HTTPS origin.

    The request URL is rebuilt on `service.config.base`, the origin the
    company publishes, so DPoP `htu` checks compare against what the
    personal agent signed whatever proxy or test transport is in front.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        query = scope.get("query_string", b"").decode()
        url = f"{service.config.base}{scope['path']}" + (f"?{query}" if query else "")
        headers = {name.decode().lower(): value.decode() for name, value in scope["headers"]}
        response = await service.handle(
            CompanyRequest(method=scope["method"], url=url, headers=headers, body=body)
        )
        if response.stream is not None:
            await send(
                {
                    "type": "http.response.start",
                    "status": response.status,
                    "headers": [(k.encode(), v.encode()) for k, v in response.headers.items()],
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
                "headers": [(k.encode(), v.encode()) for k, v in headers_out.items()],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    return app
