# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The company store contract: the conformance kit, and a company restarted over its store."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import SecretStr

from personal_agent_protocol import DeviceSignInClient
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.company import MemoryCompanyStore
from personal_agent_protocol.company.store import ACCOUNT_TOKEN, AccountGrant, JsonObject
from personal_agent_protocol.company.testing import StoreConformanceError, check_store
from personal_agent_protocol.operations import OperationsClient, approve
from personal_agent_protocol.reactor import TOKEN_STORES, TokenStore, first_contribution

from .test_company_end_to_end import PAIRWISE, TENANT, World


@pytest.mark.asyncio
async def test_the_memory_store_keeps_the_contract() -> None:
    await check_store(MemoryCompanyStore)


class _TakeTwice(MemoryCompanyStore):
    """A store whose `take` reads without deleting: two callers would both get it."""

    async def take(self, kind: str, key: str) -> JsonObject | None:
        entry = await self.get(kind, key)
        return None if entry is None else entry.value


class _BlindReplace(MemoryCompanyStore):
    """A store whose compare-and-set ignores the version."""

    async def replace(
        self, kind: str, key: str, version: str, value: JsonObject, **kw: Any
    ) -> bool:
        if await self.get(kind, key) is None:
            return False
        await self.put(kind, key, value, **kw)
        return True


class _Shared(MemoryCompanyStore):
    """A store that hands back the very object it was given."""

    async def put(self, kind: str, key: str, value: JsonObject, **kw: Any) -> None:
        await super().put(kind, key, value, **kw)
        self.last = value

    async def get(self, kind: str, key: str):  # type: ignore[no-untyped-def]
        entry = await super().get(kind, key)
        if entry is not None and getattr(self, "last", None) is not None:
            return type(entry)(self.last, entry.version, entry.expires_at)
        return entry


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("store", "broken"),
    [
        (_TakeTwice, "take returned the record"),
        (_BlindReplace, "replace"),
        (_Shared, "copy"),
    ],
)
async def test_the_kit_names_what_a_broken_store_breaks(store: type, broken: str) -> None:
    with pytest.raises(StoreConformanceError, match=broken):
        await check_store(store)


@pytest.mark.asyncio
async def test_a_company_restarted_over_its_store_continues_every_flow() -> None:
    world = World(durable=True)
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    metadata = world.company.oauth_metadata
    assert metadata is not None

    # Before: a conversation with events, and a Device Sign-In the user has not approved.
    page = await world.conversations.start(
        endpoint, world.message("Where is my jacket order?"), token=session, wait=0, **world.who
    )
    device = DeviceSignInClient(reactor=world.reactor, http_client=world.http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        scopes=("orders:read", "orders:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    world.clock.advance(started.poll_interval)
    assert (await device.poll(started.reference)).status == "pending"

    world.restart()

    # The pending sign-in survived: approved and completed on the restarted company.
    await world.shop.approve_device(started.user_code, account_id="acct_ada")
    world.clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.token is not None
    assert done.token.session_id == session.session_id
    reference = done.account_token_reference
    assert reference is not None

    # The Account Token rotates before the next restart.
    accounts = AccountTokenClient(reactor=world.reactor, http_client=world.http)
    context = AccountTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=world.atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )
    tokens = first_contribution(world.reactor, TOKEN_STORES, "token store")
    assert isinstance(tokens, TokenStore)
    before = await tokens.get(reference)
    assert before is not None
    refreshed = await accounts.refresh(reference, context=context, session_id=session.session_id)
    assert refreshed.status == "signed_in" and refreshed.rotated
    rotated = await tokens.get(reference)
    assert rotated is not None and rotated.get_secret_value() != before.get_secret_value()

    # The conversation continues from its cursor; the company proposes an operation.
    page = await world.conversations.send(
        endpoint,
        page.conversation_id,
        world.message("Exchange it for something warmer"),
        token=refreshed.token,  # type: ignore[arg-type]
        cursor=page.cursor,
        wait=0,
        **world.who,
    )
    proposal = page.events[-1].message.operation  # type: ignore[union-attr]
    assert proposal is not None and proposal.state == "proposed"
    cursor = page.cursor

    world.restart()

    # The rotated-away token stays refused after the restart; the new one works.
    old = await world.store.get(ACCOUNT_TOKEN, _sha256(before))  # type: ignore[union-attr]
    assert old is not None and AccountGrant.from_json(old.value).revoked
    await tokens.put(reference, before)
    assert (
        await accounts.refresh(reference, context=context, session_id=session.session_id)
    ).status == "signed_out"
    await tokens.put(reference, rotated)
    again = await accounts.refresh(reference, context=context, session_id=session.session_id)
    assert again.status == "signed_in" and again.token is not None

    # The operation proposed before the restart is confirmed once after it.
    operations = OperationsClient(transport=world.transport)
    ops = world.shop.config.operations_endpoint
    outcome = await operations.confirm(
        ops, proposal, approval=approve(proposal), token=again.token, **world.who
    )
    assert outcome.status == "confirmed"
    assert outcome.operation.state == "succeeded"  # type: ignore[union-attr]
    retried = await operations.confirm(
        ops, proposal, approval=approve(proposal), token=again.token, **world.who
    )
    assert retried.operation.state == "succeeded"  # type: ignore[union-attr]
    assert world.plugin.executor.performed == [proposal.operation_id]

    # The event cursor taken before the restart resumes after it: nothing is lost or repeated.
    resumed = await world.conversations.read_events(
        endpoint, page.conversation_id, token=again.token, cursor=cursor, **world.who
    )
    assert all(event.id != cursor for event in resumed.events)
    assert resumed.cursor == (resumed.events[-1].id if resumed.events else cursor)


def _sha256(token: SecretStr) -> str:
    import hashlib

    return hashlib.sha256(token.get_secret_value().encode()).hexdigest()
