# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A company taken down by its owner: what is under way is settled and ended first."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from personal_agent_protocol.accounts import RefreshTokenClient, RefreshTokenContext
from personal_agent_protocol.company.store import OPERATION, OperationOutcome, StoredOperation
from personal_agent_protocol.device import DeviceSignInClient

from .test_company_end_to_end import TENANT, World

TAKEN_DOWN = "The company was taken down."


async def _signed_in(world: World):  # type: ignore[no-untyped-def]
    session = await world.signed_out_session()
    metadata = world.company.oauth_metadata
    assert metadata is not None
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        organization=world.company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.token is not None and done.refresh_token_reference is not None
    return session, done


async def _copy(world: World, stored: StoredOperation, operation_id: str, **update: object) -> None:
    assert world.store is not None
    await world.store.put(
        OPERATION,
        operation_id,
        replace(stored, operation_id=operation_id, **update).to_json(),  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_taking_a_company_down_settles_its_operations_and_ends_its_sign_ins() -> None:
    """Open operations settled, saying so; performed ones
    untouched; every sign-in ended whole; nothing open after, and doing it again is nothing."""

    world = World(durable=True)
    session, done = await _signed_in(world)
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await world.conversations.start(
        endpoint,
        world.message("Where is my jacket order?"),
        session=session,
        token=done.token,
        wait=0,
    )
    page = await world.conversations.send(
        endpoint,
        page.conversation_id,
        world.message("Exchange it for something warmer"),
        session=session,
        token=done.token,  # type: ignore[arg-type]
        cursor=page.cursor,
        wait=0,
    )
    proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    assert proposal is not None
    stored = await world.shop.operation_record(proposal.operation_id)
    # One being performed when the company stopped, one finished, one past its expiry.
    await _copy(world, stored, "op_performing", status="performing")
    finished = OperationOutcome(summary="Exchanged.")
    await _copy(world, stored, "op_finished", status="performed", outcome=finished)
    gone = replace(stored.latest, expires_at=world.clock.now() - timedelta(seconds=1))
    await _copy(world, stored, "op_stale", revisions=(gone,))

    work = await world.shop.open_work()
    assert [operation.operation_id for operation in work.operations] == sorted(
        [proposal.operation_id, "op_performing"]
    )
    assert work.sign_ins == ((world.atlas.client_id, "acct_ada"),)
    assert not work.empty

    with pytest.raises(ValueError, match="say why"):
        await world.shop.settle_open_operations("  ")
    assert await world.shop.settle_open_operations(TAKEN_DOWN) == 2
    assert (await world.shop.operation_record(proposal.operation_id)).status == "withdrawn"
    performing = await world.shop.operation_record("op_performing")
    assert performing.status == "performed" and performing.outcome is not None
    assert not performing.outcome.succeeded
    assert performing.outcome.summary.startswith("It was stopped before it finished")
    assert "whatever it changed until then stands" in performing.outcome.summary
    assert performing.outcome.summary.endswith(TAKEN_DOWN)
    assert (await world.shop.operation_record("op_finished")).outcome == finished
    assert (await world.shop.operation_record("op_stale")).status == "open"

    assert await world.shop.end_sign_ins() == 1
    assert (await world.shop.open_work()).empty
    # The personal agent's sign-in is over: its refresh token is refused.
    metadata = world.company.oauth_metadata
    assert metadata is not None
    accounts = RefreshTokenClient(reactor=world.reactor, http_client=world.http)
    context = RefreshTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
    )
    refreshed = await accounts.refresh(done.refresh_token_reference, context=context)
    assert refreshed.status == "signed_out"

    # Again: nothing left to settle or end.
    assert await world.shop.settle_open_operations(TAKEN_DOWN) == 0
    assert await world.shop.end_sign_ins() == 0
