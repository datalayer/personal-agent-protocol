# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Every Reactor contribution point, held to `protocol/reactor-points.json`.

The TypeScript SDK is held to the same file by `src/__tests__/reactor-points.test.mjs`,
so both SDKs define the same points with the same ids and contracts. For each point:
the SDK's own default (or none); the lifecycle (a contribution is used, a lower `order`
replaces it, it goes when its plugin is unregistered, and an equal order fails closed);
and, where the point is tenant-scoped, a tenant test.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]
from reactor.contributions import ContributionPoint  # type: ignore[import-untyped]

import personal_agent_protocol
import personal_agent_protocol.company as company
from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    PAIRWISE_USER_ID_STORES,
    DpopHttpClient,
    SessionToken,
    SqlitePairwiseUserIdStore,
    build_pap_reactor,
    resolve_pairwise_user_id,
)
from personal_agent_protocol import operations as operations_module
from personal_agent_protocol import reactor as reactor_module
from personal_agent_protocol.company import CompanyConfig, build_company
from personal_agent_protocol.company import points as company_points
from personal_agent_protocol.company import store as company_store
from personal_agent_protocol.reactor import first_contribution, optional_contribution

ROOT = Path(__file__).parents[2]
INVENTORY = json.loads((ROOT / "protocol" / "reactor-points.json").read_text())
POINTS: list[dict[str, Any]] = INVENTORY["points"]
CONTRACT_MODULES = (reactor_module, operations_module, company_points, company_store)


def _ids(entry: dict[str, Any]) -> str:
    return str(entry["id"])


def _point(entry: dict[str, Any]) -> ContributionPoint:
    module = company if entry["role"] == "company" else personal_agent_protocol
    return getattr(module, entry["python"])


def _exported_points() -> Iterator[tuple[str, ContributionPoint]]:
    for module in (personal_agent_protocol, company):
        for name in module.__all__:
            value = getattr(module, name)
            if isinstance(value, ContributionPoint):
                yield name, value


class _Contributor:
    def __init__(self, point: ContributionPoint, value: object, order: int) -> None:
        self.point, self.value, self.order = point, value, order

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            self.point, self.value, contribution_id=f"host-{self.order}", order=self.order
        )


class _Executor:
    """A stand-in value; an executor also names its action."""

    action = "tests.act"


def _reactor(entry: dict[str, Any]) -> PluginPlatform:
    if entry["role"] == "company":
        config = CompanyConfig(name="Points", domain="points.example", scopes=("a:read",))
        return build_company(config, http_client=httpx.AsyncClient()).reactor
    platform, _ = build_pap_reactor(http_client=httpx.AsyncClient())
    return platform


def _resolve(platform: PluginPlatform, entry: dict[str, Any]) -> object | None:
    """What the SDK uses for the point, the way the SDK reads it."""

    point = _point(entry)
    if entry["resolution"] == "optional":
        return optional_contribution(platform, point, entry["id"])
    if entry["resolution"] == "by-action":
        winners = [c for c in platform.get_contributions(point) if c.value.action == "tests.act"]
        if not winners:
            raise RuntimeError("no active executor")
        if len(winners) > 1 and winners[0].order == winners[1].order:
            raise RuntimeError("ambiguous executors")
        return winners[0].value
    return first_contribution(platform, point, entry["id"])


def test_the_inventory_names_each_point_once() -> None:
    ids = [entry["id"] for entry in POINTS]
    assert len(ids) == len(set(ids))
    assert all(entry["role"] in {"personal-agent", "company"} for entry in POINTS)
    assert all(
        entry["id"].startswith("pap.company.") == (entry["role"] == "company") for entry in POINTS
    )
    assert all(entry["resolution"] in {"single", "optional", "by-action"} for entry in POINTS)


def test_the_python_sdk_exports_exactly_the_inventorys_points() -> None:
    exported = {(name, point.id) for name, point in _exported_points()}
    assert exported == {(entry["python"], entry["id"]) for entry in POINTS}


@pytest.mark.parametrize("entry", POINTS, ids=_ids)
def test_each_contract_has_the_inventorys_members(entry: dict[str, Any]) -> None:
    contracts = [
        getattr(module, entry["contract"])
        for module in CONTRACT_MODULES
        if hasattr(module, entry["contract"])
    ]
    assert contracts, f"no Python contract {entry['contract']}"
    contract = contracts[0]
    members = set(dir(contract)) | set(getattr(contract, "__annotations__", {}))
    assert set(entry["members"]) <= members


@pytest.mark.parametrize("entry", POINTS, ids=_ids)
def test_each_default_is_the_inventorys(entry: dict[str, Any]) -> None:
    platform = _reactor(entry)
    try:
        defaults = [c.id for c in platform.get_contributions(_point(entry)) if c.order == 100]
        expected = entry["default"]
        assert defaults == ([] if expected is None else [expected["python"]])
    finally:
        platform.stop()


@pytest.mark.parametrize("entry", POINTS, ids=_ids)
def test_each_point_follows_its_plugins_lifecycle(entry: dict[str, Any]) -> None:
    point = _point(entry)
    platform = _reactor(entry)
    try:
        default = None if entry["default"] is None else _resolve(platform, entry)
        first, second = _Executor(), _Executor()
        # Contributed: the host's contribution is the one used.
        platform.register_plugin(
            PluginManifest(name="host-first", version="1"), _Contributor(point, first, 50)
        )
        assert _resolve(platform, entry) is first
        # Replaced: a lower order wins.
        platform.register_plugin(
            PluginManifest(name="host-second", version="1"), _Contributor(point, second, 10)
        )
        assert _resolve(platform, entry) is second
        # Removed: unregistering a plugin takes its contribution away.
        platform.unregister_plugin("host-second")
        assert _resolve(platform, entry) is first
        platform.unregister_plugin("host-first")
        if entry["default"] is not None:
            assert _resolve(platform, entry) is default
        elif entry["resolution"] == "optional":
            assert _resolve(platform, entry) is None
        else:
            with pytest.raises(RuntimeError, match="no active"):
                _resolve(platform, entry)
        # Ambiguous: two contributions at the winning order fail closed.
        platform.register_plugin(
            PluginManifest(name="host-a", version="1"), _Contributor(point, first, 5)
        )
        platform.register_plugin(
            PluginManifest(name="host-b", version="1"), _Contributor(point, second, 5)
        )
        with pytest.raises(RuntimeError, match="ambiguous"):
            _resolve(platform, entry)
    finally:
        platform.stop()


def test_the_tenant_scoped_points_are_the_inventorys() -> None:
    scoped = {entry["id"] for entry in POINTS if entry["tenant"] is not None}
    assert scoped == {PAIRWISE_USER_ID_STORES.id, DPOP_PROOF_PROVIDERS.id}


@pytest.mark.asyncio
async def test_pairwise_ids_are_resolved_per_tenant_and_never_cross(tmp_path: Path) -> None:
    store = SqlitePairwiseUserIdStore(tmp_path / "pairwise.sqlite3")
    asked: list[str] = []

    class Spy:
        async def get_or_create(
            self, *, tenant_id: str, local_user_id: str, company_issuer: str
        ) -> str:
            asked.append(tenant_id)
            return await store.get_or_create(
                tenant_id=tenant_id, local_user_id=local_user_id, company_issuer=company_issuer
            )

    platform, owned = build_pap_reactor(
        plugins=[
            (
                PluginManifest(name="pairwise", version="1"),
                _Contributor(PAIRWISE_USER_ID_STORES, Spy(), 10),
            )
        ]
    )
    try:
        who = {"local_user_id": "ada", "company_issuer": "https://shop.example"}
        one = await resolve_pairwise_user_id(platform, tenant_id="tenant-one", **who)
        two = await resolve_pairwise_user_id(platform, tenant_id="tenant-two", **who)
        again = await resolve_pairwise_user_id(platform, tenant_id="tenant-one", **who)
    finally:
        platform.stop()
        if owned is not None:
            await owned.aclose()
    assert asked == ["tenant-one", "tenant-two", "tenant-one"]
    assert one == again and one != two


@pytest.mark.asyncio
async def test_each_dpop_proof_is_asked_for_the_requests_own_tenant() -> None:
    asked: list[tuple[str, str]] = []

    class Proofs:
        async def create(self, request: Any) -> SecretStr:
            asked.append((request.tenant_id, request.subject))
            return SecretStr(f"proof-for-{request.tenant_id}")

    seen: list[str] = []

    def answer(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["dpop"])
        return httpx.Response(200, json={})

    async with httpx.AsyncClient(transport=httpx.MockTransport(answer)) as http:
        platform, _ = build_pap_reactor(
            http_client=http,
            plugins=[
                (
                    PluginManifest(name="proofs", version="1"),
                    _Contributor(DPOP_PROOF_PROVIDERS, Proofs(), 10),
                )
            ],
        )
        try:
            client = DpopHttpClient(reactor=platform, http_client=http)
            token = SessionToken(
                access_token=SecretStr("sat"),
                token_type="DPoP",  # noqa: S106 - OAuth token type
                expires_in=60,
                session_id="ses_1",
                signed_in=False,
            )
            for tenant, user in (("tenant-one", "usr_one"), ("tenant-two", "usr_two")):
                await client.request(
                    "GET",
                    "https://shop.example/api/orders",
                    token=token,
                    tenant_id=tenant,
                    pairwise_user_id=user,
                    issuer="https://shop.example",
                )
        finally:
            platform.stop()
    assert asked == [("tenant-one", "usr_one"), ("tenant-two", "usr_two")]
    assert seen == ["proof-for-tenant-one", "proof-for-tenant-two"]


def test_the_docs_list_every_point() -> None:
    page = (ROOT / "docs" / "docs" / "concepts" / "contribution-points.mdx").read_text()
    rows = {
        line.split("|")[1].strip().strip("`")
        for line in page.splitlines()
        if line.startswith("| `pap.")
    }
    assert rows == {entry["id"] for entry in POINTS}
