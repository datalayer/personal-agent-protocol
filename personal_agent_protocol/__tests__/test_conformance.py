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
    selected = select_cases(suites=["lifecycle"], requirements=["PAP-4.8-04", "PAP-4.9-01"])
    assert {case.id for case in selected} == {
        "lifecycle.account-mismatch",
        "lifecycle.account-mismatch-after-sign-out",
        "lifecycle.sign-out-takes-effect",
        "lifecycle.sign-out-session-continues",
        "lifecycle.sign-out-every-session",
        "lifecycle.mcp-sign-out-takes-effect",
    }
    # A driver with one account twice: the account-mismatch case cannot pass.
    world.driver.accounts = ("acct_ada", "acct_ada")
    report = await run_conformance(world.context(), cases=selected)
    outcomes = {r.id: r.outcome for r in report.results}
    assert outcomes["lifecycle.account-mismatch"] == "failed"
    assert outcomes["lifecycle.account-mismatch-after-sign-out"] == "failed"
    assert outcomes["lifecycle.sign-out-takes-effect"] == "passed"

    payload = report.to_json()
    assert payload["schema_version"] == 1 and payload["profile"] == "0.2"
    assert payload["summary"] == {"passed": 4, "failed": 2, "skipped": 0}
    text = json.dumps(payload)
    assert "acct_" not in text.replace("acct_ada", "")  # no Account Token in the report
    junit = ElementTree.fromstring(report.to_junit())  # noqa: S314 - our own report
    suite = junit.find("testsuite")
    assert suite is not None and suite.get("failures") == "2"
    names = [case.get("name") for case in junit.iter("testcase")]
    assert "lifecycle.account-mismatch" in names
    requirements = [p.get("value") for p in junit.iter("property")]
    assert "PAP-4.8-04" in requirements


@pytest.mark.asyncio
async def test_a_driver_without_a_capability_skips_rather_than_passes() -> None:
    world = ManzanitaConformance()
    world.driver.capabilities = frozenset()  # type: ignore[misc]
    report = await run_conformance(
        world.context(), cases=select_cases(ids=["operations.terms-changed"])
    )
    assert [(r.outcome, r.message) for r in report.results] == [
        ("skipped", "the driver cannot revise")
    ]


@pytest.mark.asyncio
async def test_the_mcp_cases_pass_against_an_mcp_server_without_dpop() -> None:
    """The same MCP cases against Manzanita with a non-DPoP MCP server: Bearer tokens (§4.3)."""

    import dataclasses

    world = ManzanitaConformance()
    world.service.config = dataclasses.replace(world.service.config, mcp_dpop=False)
    mcp = [case for case in CASES if ".mcp-" in case or case == "operations.cross-channel-mcp"]
    report = await run_conformance(world.context(), cases=select_cases(ids=mcp))
    assert len(report.results) == len(mcp) >= 6
    assert _failures(report) == []
