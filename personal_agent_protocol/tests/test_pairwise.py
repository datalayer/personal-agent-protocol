# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import asyncio
from pathlib import Path

import pytest
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    PAIRWISE_USER_ID_STORES,
    SqlitePairwiseUserIdStore,
    resolve_pairwise_user_id,
)
from personal_agent_protocol.reactor import build_pap_reactor


class DistinctRandom:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, length: int) -> bytes:
        self.calls += 1
        return bytes([self.calls]) * length


@pytest.mark.asyncio
async def test_persists_stable_pairwise_ids_by_exact_tenant_user_and_issuer(
    tmp_path: Path,
) -> None:
    random = DistinctRandom()
    database = tmp_path / "pairwise.sqlite3"
    store = SqlitePairwiseUserIdStore(database, random_bytes=random)
    key = {
        "tenant_id": "app-one",
        "local_user_id": "user-one",
        "company_issuer": "https://auth.example.com",
    }

    first = await store.get_or_create(**key)
    same = await SqlitePairwiseUserIdStore(database).get_or_create(**key)
    other_user = await store.get_or_create(**{**key, "local_user_id": "user-two"})
    other_tenant = await store.get_or_create(**{**key, "tenant_id": "app-two"})
    other_issuer = await store.get_or_create(
        **{**key, "company_issuer": "https://auth.other.example"}
    )

    assert first == same
    assert len({first, other_user, other_tenant, other_issuer}) == 4
    assert first.startswith("usr_")


@pytest.mark.asyncio
async def test_get_or_create_is_atomic_across_concurrent_store_instances(
    tmp_path: Path,
) -> None:
    database = tmp_path / "pairwise.sqlite3"
    stores = [SqlitePairwiseUserIdStore(database) for _ in range(8)]

    identifiers = await asyncio.gather(
        *(
            store.get_or_create(
                tenant_id="app-one",
                local_user_id="user-one",
                company_issuer="https://auth.example.com",
            )
            for store in stores
        )
    )

    assert len(set(identifiers)) == 1


class PairwisePlugin:
    def __init__(self, store: SqlitePairwiseUserIdStore) -> None:
        self.store = store

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            PAIRWISE_USER_ID_STORES,
            self.store,
            contribution_id="sqlite",
        )


@pytest.mark.asyncio
async def test_resolves_pairwise_store_through_reactor(tmp_path: Path) -> None:
    reactor, http = build_pap_reactor()
    assert http is not None
    reactor.register_plugin(
        PluginManifest(name="pap-test-pairwise", version="1"),
        PairwisePlugin(SqlitePairwiseUserIdStore(tmp_path / "pairwise.sqlite3")),
    )
    try:
        identifier = await resolve_pairwise_user_id(
            reactor,
            tenant_id="app-one",
            local_user_id="user-one",
            company_issuer="https://auth.example.com",
        )
    finally:
        reactor.stop()
        await http.aclose()

    assert identifier.startswith("usr_")


@pytest.mark.asyncio
async def test_rejects_non_durable_or_unverified_store_keys(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="file-backed"):
        SqlitePairwiseUserIdStore(":memory:")

    store = SqlitePairwiseUserIdStore(tmp_path / "pairwise.sqlite3")
    with pytest.raises(ValueError, match="HTTPS issuer"):
        await store.get_or_create(
            tenant_id="app-one",
            local_user_id="user-one",
            company_issuer="http://auth.example.com",
        )
