# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import httpx
import pytest
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from personal_agent_protocol import (
    AUTHORIZATION_STATE_STORES,
    BROWSER_HANDOFFS,
    CACHES,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    PAIRWISE_USER_ID_STORES,
    RANDOM_SOURCES,
    SIGNERS,
    TOKEN_STORES,
    build_pap_reactor,
)
from personal_agent_protocol.reactor import first_contribution

SECURITY_POINTS = [
    AUTHORIZATION_STATE_STORES,
    SIGNERS,
    TOKEN_STORES,
    PAIRWISE_USER_ID_STORES,
    CACHES,
    BROWSER_HANDOFFS,
    DPOP_PROOF_PROVIDERS,
]


class ContributionPlugin:
    def __init__(self, point: object, value: object, contribution_id: str) -> None:
        self.point = point
        self.value = value
        self.contribution_id = contribution_id

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(
            self.point,
            self.value,
            contribution_id=self.contribution_id,
            order=10,
        )


def platform_with(point: object, *values: object) -> PluginPlatform:
    platform = PluginPlatform(extension_group="pap.tests")
    for index, value in enumerate(values):
        platform.register_plugin(
            PluginManifest(name=f"pap-test-{index}", version="1"),
            ContributionPlugin(point, value, f"test-{index}"),
        )
    return platform


def test_cross_language_infrastructure_point_ids_are_stable() -> None:
    assert AUTHORIZATION_STATE_STORES.id == "pap.authorizationStateStore"
    assert CLOCKS.id == "pap.clock"
    assert RANDOM_SOURCES.id == "pap.randomSource"
    assert SIGNERS.id == "pap.signer"
    assert TOKEN_STORES.id == "pap.tokenStore"
    assert PAIRWISE_USER_ID_STORES.id == "pap.pairwiseUserIdStore"
    assert CACHES.id == "pap.cache"
    assert BROWSER_HANDOFFS.id == "pap.browserHandoff"
    assert DPOP_PROOF_PROVIDERS.id == "pap.dpopProofProvider"


@pytest.mark.parametrize("point", SECURITY_POINTS, ids=lambda point: point.id)
def test_required_security_contribution_fails_closed_when_missing(point: object) -> None:
    platform = platform_with(point)

    with pytest.raises(RuntimeError, match="no active"):
        first_contribution(platform, point, point.id)  # type: ignore[attr-defined]


@pytest.mark.parametrize("point", SECURITY_POINTS, ids=lambda point: point.id)
def test_required_security_contribution_fails_closed_when_ambiguous(point: object) -> None:
    platform = platform_with(point, object(), object())

    with pytest.raises(RuntimeError, match="ambiguous"):
        first_contribution(platform, point, point.id)  # type: ignore[attr-defined]


@pytest.mark.parametrize("point", SECURITY_POINTS, ids=lambda point: point.id)
def test_required_security_contribution_tracks_plugin_lifecycle(point: object) -> None:
    value = object()
    platform = platform_with(point, value)

    assert first_contribution(platform, point, point.id) is value  # type: ignore[attr-defined]
    platform.disable_plugin("pap-test-0")
    with pytest.raises(RuntimeError, match="no active"):
        first_contribution(platform, point, point.id)  # type: ignore[attr-defined]
    platform.enable_plugin("pap-test-0")
    assert first_contribution(platform, point, point.id) is value  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_build_pap_reactor_registers_plugin_inputs_before_use() -> None:
    signer = object()
    manifest = PluginManifest(name="pap-test-host-security", version="1")

    async with httpx.AsyncClient() as http:
        platform, owned_http = build_pap_reactor(
            http_client=http,
            plugins=[
                (
                    manifest,
                    ContributionPlugin(SIGNERS, signer, "host-signer"),
                )
            ],
        )
        try:
            assert owned_http is None
            assert first_contribution(platform, SIGNERS, "signer") is signer
        finally:
            platform.stop()


@pytest.mark.asyncio
async def test_build_pap_reactor_consumes_plugin_iterables_once() -> None:
    values = [object(), object()]

    def plugins():
        for index, value in enumerate(values):
            yield (
                PluginManifest(name=f"pap-test-plugin-{index}", version="1"),
                ContributionPlugin(
                    TOKEN_STORES,
                    value,
                    f"host-token-store-{index}",
                ),
            )

    async with httpx.AsyncClient() as http:
        platform, _ = build_pap_reactor(http_client=http, plugins=plugins())
        try:
            with pytest.raises(RuntimeError, match="ambiguous"):
                first_contribution(platform, TOKEN_STORES, "token store")
        finally:
            platform.stop()
