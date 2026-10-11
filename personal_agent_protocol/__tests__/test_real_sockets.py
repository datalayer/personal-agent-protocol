# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The user-with-a-company journey over real TCP and TLS (Python agent ↔ Python company)."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpcore
import httpx
import pytest

from personal_agent_protocol import DiscoveryClient
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.demo.sockets import _certificates, served_over_tls
from personal_agent_protocol.operations import OperationsClient, approve

from .test_direct_and_api import begin, direct_world

pytest.importorskip("uvicorn")


@pytest.mark.asyncio
async def test_discovery_sign_in_read_and_operation_over_tls() -> None:
    world, browser = direct_world()
    async with served_over_tls(world.network) as network:
        assert network.socket_transport is not None
        session = await world.signed_out_session()
        client = await begin(world, browser, session, ("orders:read", "orders:write"))
        signed_in = (
            await client.complete(
                world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
            )
        ).token
        api = ApiClient(transport=world.transport)
        orders = await api.call(
            "GET", "https://manzanita.example/api/orders", token=signed_in, **world.who
        )
        assert orders.body["orders"][0]["order_id"] == "ord_7Hk2"
        proposed = await api.call(
            "POST",
            "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
            token=signed_in,
            body={},
            **world.who,
        )
        done = await OperationsClient(transport=world.transport).confirm(
            world.shop.config.operations_endpoint,
            proposed.operation,  # type: ignore[arg-type]
            approval=approve(proposed.operation),
            token=signed_in,
            **world.who,  # type: ignore[arg-type]
        )
        assert done.operation.state == "succeeded"  # type: ignore[union-attr]
        # The company verified the agent by fetching its metadata over TLS too.
        page = await world.http.get(f"https://{world.atlas.domain}/agent.json")
        assert page.json()["client_id"] == world.atlas.client_id


class _ToLocalPort(httpcore.AsyncNetworkBackend):
    """Dial a loopback address on the test server's port; refuse any host name."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.dialed: list[str] = []
        self.backend = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.dialed.append(host)
        ipaddress.ip_address(host)  # a name here would mean the host was resolved again
        return await self.backend.connect_tcp(
            host, self.port, timeout=timeout, socket_options=socket_options
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("no unix sockets")

    async def sleep(self, seconds: float) -> None:
        await self.backend.sleep(seconds)


@pytest.mark.asyncio
async def test_metadata_connects_to_the_approved_address() -> None:
    """Discovery over TLS dials the address the policy approved, verifying the name.

    `pinned.example` resolves nowhere: only the address the policy approved
    (loopback, allowed on purpose here) can reach the server, and its
    certificate is still checked against the name.
    """

    import uvicorn

    document = {
        "protocol_version": "0.1",
        "organization": {"name": "Pinned", "domain": "pinned.example"},
        "web": {},
    }

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while (message := await receive())["type"] != "lifespan.shutdown":
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
            await send({"type": "lifespan.shutdown.complete"})
            return
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": json.dumps(document).encode()})

    resolutions: list[str] = []

    async def approve_loopback(host: str) -> list[str]:
        resolutions.append(host)
        return ["127.0.0.1"]

    with tempfile.TemporaryDirectory() as directory:
        ca, cert, key = _certificates(["pinned.example"], Path(directory))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        server = uvicorn.Server(
            uvicorn.Config(
                app, ssl_certfile=str(cert), ssl_keyfile=str(key), log_level="warning"
            )
        )
        task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            while not server.started:
                if task.done():
                    task.result()
                await asyncio.sleep(0.01)
            transport = httpx.AsyncHTTPTransport(verify=ssl.create_default_context(cafile=ca))
            dial = _ToLocalPort(listener.getsockname()[1])
            transport._pool._network_backend = dial
            async with httpx.AsyncClient(transport=transport) as http:
                client = DiscoveryClient(
                    http_client=http,
                    address_resolver=approve_loopback,
                    allow_private_networks=True,
                )
                company = await client.discover("pinned.example")
        finally:
            server.should_exit = True
            await task
            listener.close()

    assert company.document.organization.domain == "pinned.example"
    assert resolutions == ["pinned.example"]
    assert dial.dialed == ["127.0.0.1"]
