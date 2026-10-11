# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The user-with-a-company journey over real TCP and TLS (Python agent ↔ Python company)."""

from __future__ import annotations

import pytest

pytest.importorskip("uvicorn")

from personal_agent_protocol.apis import ApiClient  # noqa: E402
from personal_agent_protocol.demo.sockets import served_over_tls  # noqa: E402
from personal_agent_protocol.operations import OperationsClient, approve  # noqa: E402

from .test_direct_and_api import begin, direct_world  # noqa: E402


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
