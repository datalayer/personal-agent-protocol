# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Python personal agent ↔ Python company: the conformance suite over real TCP and TLS."""

from __future__ import annotations

import json
import os
from pathlib import Path
from xml.etree import ElementTree

import pytest

from personal_agent_protocol.conformance import (
    CASES,
    ConformanceReport,
    run_conformance,
    select_cases,
)
from personal_agent_protocol.demo.conformance import ManzanitaConformance


def _failures(report: ConformanceReport) -> list[str]:
    return [f"{r.id}: {r.message}" for r in report.results if r.outcome != "passed"]


@pytest.mark.asyncio
async def test_python_agent_python_company_over_tls() -> None:
    """Every positive, negative, and recovery case passes against Manzanita over TLS."""

    pytest.importorskip("uvicorn")
    from personal_agent_protocol.demo.sockets import served_over_tls

    world = ManzanitaConformance()
    async with served_over_tls(world.network) as network:
        assert network.socket_transport is not None
        report = await run_conformance(world.context())
    reports = os.environ.get("PAP_CONFORMANCE_REPORTS")
    if reports:  # kept for the compatibility report (scripts/conformance_report.py)
        Path(reports).mkdir(parents=True, exist_ok=True)
        target = Path(reports) / "python-agent-python-company.json"
        target.write_text(json.dumps(report.to_json(), indent=2) + "\n")
    assert _failures(report) == []
    assert {r.id for r in report.results} == set(CASES)
    kinds = {r.kind for r in report.results}
    assert kinds == {"positive", "negative", "recovery"}


@pytest.mark.asyncio
async def test_reports_as_json_and_junit_and_a_failure_does_not_stop_the_suite() -> None:
    world = ManzanitaConformance()
    selected = select_cases(
        suites=["lifecycle"], requirements=["GUIDE-co-account-01", "GUIDE-co-lifetimes-02"]
    )
    assert {case.id for case in selected} == {
        "lifecycle.disconnect-from-account-settings",
        "lifecycle.sign-out-takes-effect",
        "lifecycle.sign-out-session-continues",
        "lifecycle.sign-out-revokes-every-refresh-token",
        "lifecycle.mcp-sign-out-takes-effect",
    }

    # A driver whose disconnect does nothing: that case cannot pass.
    async def no_disconnect(client_id: str, account: str) -> None:
        return None

    world.driver.disconnect = no_disconnect  # type: ignore[method-assign]
    report = await run_conformance(world.context(), cases=selected)
    outcomes = {r.id: r.outcome for r in report.results}
    assert outcomes["lifecycle.disconnect-from-account-settings"] == "failed"
    assert outcomes["lifecycle.sign-out-takes-effect"] == "passed"

    payload = report.to_json()
    assert payload["schema_version"] == 1 and payload["profile"] == "0.3"
    assert payload["extensions"] == {"operations": "2"}
    assert payload["summary"] == {"passed": 4, "failed": 1, "skipped": 0}
    text = json.dumps(payload)
    assert "rt_" not in text  # no refresh token in the report
    junit = ElementTree.fromstring(report.to_junit())  # noqa: S314 - our own report
    suite = junit.find("testsuite")
    assert suite is not None and suite.get("failures") == "1"
    names = [case.get("name") for case in junit.iter("testcase")]
    assert "lifecycle.disconnect-from-account-settings" in names
    requirements = [p.get("value") for p in junit.iter("property")]
    assert "GUIDE-co-lifetimes-02" in requirements


@pytest.mark.asyncio
async def test_a_driver_without_a_capability_skips_rather_than_passes() -> None:
    world = ManzanitaConformance()
    world.driver.capabilities = frozenset()  # type: ignore[misc]
    report = await run_conformance(
        world.context(), cases=select_cases(ids=["operations.new-revision-on-changed-terms"])
    )
    assert [(r.outcome, r.message) for r in report.results] == [
        ("skipped", "the driver cannot revise")
    ]


@pytest.mark.asyncio
async def test_the_mcp_cases_pass_with_a_token_for_the_servers_url() -> None:
    """The MCP cases on their own: tokens by `resource`, the server's `url` (§4.5, §7)."""

    world = ManzanitaConformance()
    mcp = [case for case in CASES if ".mcp-" in case or case == "operations.cross-channel-mcp"]
    report = await run_conformance(world.context(), cases=select_cases(ids=mcp))
    assert sorted(result.id for result in report.results) == sorted(mcp)
    assert sorted(mcp) == [
        "lifecycle.mcp-protected-resource-metadata",
        "lifecycle.mcp-sign-out-takes-effect",
        "lifecycle.mcp-token-for-its-url",
        "lifecycle.mcp-token-only-at-mcp",
        "operations.cross-channel-mcp",
        "operations.mcp-approval",
    ]
    assert _failures(report) == []
