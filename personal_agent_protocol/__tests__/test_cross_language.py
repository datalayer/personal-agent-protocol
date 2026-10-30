# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The conformance suite across languages, over real TCP and TLS (PAP plan §5).

- Python agent ↔ TypeScript company: the Python conformance runner, every
  positive, negative and recovery case, against the TypeScript Manzanita on
  node:https, with a driver (`NodeDriver`) that plays the user and the demo
  company's operator over JSON lines.
- TypeScript agent ↔ Python company: the TypeScript conformance cases
  (`src/__tests__/support/conformance.mjs`) against the Python Manzanita
  served with `served_over_tls`, the Python side playing the user and operator.

Each writes its report (schema 1, the runner's JSON) where
`PAP_CONFORMANCE_REPORTS` names, for the compatibility report.
"""

from __future__ import annotations

import json
import os
import shutil
import ssl
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest

from personal_agent_protocol.conformance import ConformanceReport, run_conformance
from personal_agent_protocol.demo.conformance import (
    MANZANITA_SCENARIO,
    DemoDriver,
    ManzanitaConformance,
)
from personal_agent_protocol.demo.kit import AgentIdentity, InProcessNetwork, MutableClock
from personal_agent_protocol.demo.sockets import _certificates, _DialLocal, served_over_tls

from .test_pairings import NodeProcess, _served

pytest.importorskip("uvicorn")

ROOT = Path(__file__).parents[2]

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None
    or not (ROOT / "lib" / "server.js").exists()
    or not (ROOT / "lib" / "demo" / "manzanita.js").exists(),
    reason="needs node and the TypeScript lib/",
)

#: Cases the TypeScript company cannot pass yet, with why (kept exact: a fix shows here).
TYPESCRIPT_COMPANY_GAPS: dict[str, str] = {}

#: Cases the TypeScript agent's suite does not pass against the Python company.
TYPESCRIPT_AGENT_GAPS: dict[str, str] = {}


def _save(name: str, report: dict[str, Any]) -> None:
    directory = os.environ.get("PAP_CONFORMANCE_REPORTS")
    if directory:
        Path(directory).mkdir(parents=True, exist_ok=True)
        (Path(directory) / f"{name}.json").write_text(json.dumps(report, indent=2) + "\n")


class NodeDriver:
    """The user and the TypeScript demo company's operator, over the node process."""

    capabilities = frozenset(
        {"revise", "forget_events", "disconnect", "performed", "clock", "second_identity"}
    )

    def __init__(self, node: NodeProcess, clock: MutableClock, other: AgentIdentity) -> None:
        self.node = node
        self.clock = clock
        self.other_identity: AgentIdentity | None = other
        self.accounts = ("acct_ada", "acct_ada_business")

    async def _ask(self, message: dict[str, Any]) -> dict[str, Any]:
        answer = await self.node.ask(message)
        if "error" in answer:
            raise RuntimeError(f"the TypeScript company refused {message['op']}: {answer['error']}")
        return answer

    async def approve_device(
        self, user_code: str, *, account: str, scopes: Sequence[str] | None = None
    ) -> None:
        await self._ask(
            {
                "op": "approve_device",
                "user_code": user_code,
                "account_id": account,
                "scopes": list(scopes) if scopes else None,
            }
        )

    async def wait(self, seconds: float) -> None:
        self.clock.advance(seconds)
        await self._ask({"op": "advance", "seconds": seconds})

    async def revise(self, operation_id: str) -> None:
        await self._ask({"op": "revise", "operation_id": operation_id})

    async def forget_events(self, conversation_id: str) -> None:
        await self._ask({"op": "forget_events", "conversation_id": conversation_id})

    async def disconnect(self, client_id: str, account: str) -> None:
        await self._ask({"op": "disconnect", "client_id": client_id, "account_id": account})

    async def performed(self, operation_id: str) -> int:
        return int((await self._ask({"op": "performed", "operation_id": operation_id}))["count"])


def _outcomes(report: ConformanceReport) -> dict[str, str]:
    return {result.id: result.outcome for result in report.results}


def _print(title: str, report: ConformanceReport) -> None:
    print(f"\n{title}: {report.counts()}")  # noqa: T201 - the per-case results, with -s
    for result in report.results:
        print(f"  {result.outcome:7} {result.id} {result.message or ''}")  # noqa: T201


@pytest.mark.xfail(reason="TypeScript port pending", strict=True)
@pytest.mark.asyncio
async def test_python_runner_against_the_typescript_company(tmp_path: Path) -> None:
    from reactor import PluginManifest  # noqa: F401 - the runner's host needs Reactor

    from personal_agent_protocol.conformance import ConformanceContext

    clock = MutableClock()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    plain = AgentIdentity(domain="plain.example", name="Plain", extensions=())
    company = "manzanita.example"
    ca, cert, key = _certificates([company, atlas.domain, plain.domain], tmp_path)
    config = tmp_path / "company.json"
    config.write_text(
        json.dumps(
            {
                "cert": str(cert),
                "key": str(key),
                "ca": str(ca),
                "clock": clock.now().isoformat().replace("+00:00", "Z"),
                "agents": {
                    identity.domain: {"/agent.json": identity.metadata, "/jwks.json": identity.jwks}
                    for identity in (atlas, plain)
                },
            }
        )
    )
    node = await NodeProcess.start("serve-company.mjs", config)
    try:
        port = (await node.receive())["ready"]["port"]

        async def nowhere(scope: Any, receive: Any, send: Any) -> None:  # never called
            raise AssertionError("the network is served over TLS")

        network = InProcessNetwork()
        for domain in (company, atlas.domain, plain.domain):
            network.add(domain, nowhere)
        transport = httpx.AsyncHTTPTransport(verify=ssl.create_default_context(cafile=str(ca)))
        transport._pool._network_backend = _DialLocal(frozenset(network.apps), port)  # type: ignore[attr-defined]
        network.socket_transport = transport
        http, browser = network.client(), network.client()
        context = ConformanceContext(
            f"https://{company}",
            identity=atlas,
            http=http,
            driver=NodeDriver(node, clock, plain),
            scenario=MANZANITA_SCENARIO,
            clock=clock,
            address_resolver=network.resolve,
            browser_http=browser,
        )
        try:
            report = await run_conformance(context)
        finally:
            await http.aclose()
            await browser.aclose()
            await transport.aclose()
        await node.send({"op": "close"})
    finally:
        await node.stop()
    _save("python-agent-typescript-company", report.to_json())
    _print("Python agent ↔ TypeScript company", report)
    failed = {r.id: r.message for r in report.results if r.outcome == "failed"}
    assert failed.keys() == TYPESCRIPT_COMPANY_GAPS.keys(), failed


def _scenario_json() -> dict[str, Any]:
    """MANZANITA_SCENARIO for the TypeScript runner (decimals as strings, as on the wire)."""

    scenario = MANZANITA_SCENARIO

    def limits(values: Any) -> list[dict[str, Any]]:
        return [
            {
                "path": limit.path,
                **({"maximum": str(limit.maximum)} if limit.maximum is not None else {}),
                **({"allowed": sorted(limit.allowed)} if limit.allowed is not None else {}),
            }
            for limit in values
        ]

    return {
        "read_path": scenario.read_path,
        "read_scope": scenario.read_scope,
        "scopes": list(scenario.scopes),
        "proposals": {
            kind: {
                "method": proposal.method,
                "path": proposal.path,
                "body": proposal.body,
                "documented_as": proposal.documented_as,
            }
            for kind, proposal in scenario.proposals.items()
        },
        "standing_action": scenario.standing_action,
        "standing_limits": limits(scenario.standing_limits),
        "standing_too_low": limits(scenario.standing_too_low),
        "operation_prompt": scenario.operation_prompt,
        "account_prompt": scenario.account_prompt,
        "greeting": scenario.greeting,
        "mcp_read_tool": scenario.mcp_read_tool,
        "mcp_propose_tool": scenario.mcp_propose_tool,
        "web_confirm_form": scenario.web_confirm_form,
    }


def test_the_typescript_runners_scenario_is_manzanitas() -> None:
    shared = json.loads(
        (ROOT / "protocol" / "scenarios" / "manzanita-conformance.json").read_text()
    )
    shared.pop("description")
    assert shared == _scenario_json()


async def _answer(driver: DemoDriver, line: dict[str, Any]) -> dict[str, Any]:
    """Play the user, or Manzanita's operator, for the TypeScript runner."""

    ask = line.get("ask")
    if ask == "approve_device":
        await driver.approve_device(
            line["user_code"], account=line["account"], scopes=line["scopes"]
        )
    elif ask == "wait":
        await driver.wait(line["seconds"])
    elif ask == "revise":
        await driver.revise(line["operation_id"])
    elif ask == "forget_events":
        await driver.forget_events(line["conversation_id"])
    elif ask == "disconnect":
        await driver.disconnect(line["client_id"], line["account"])
    elif ask == "performed":
        return {"count": await driver.performed(line["operation_id"])}
    else:
        raise ValueError(f"unexpected line from node: {line}")
    return {"ok": True}


@pytest.mark.xfail(reason="TypeScript port pending", strict=True)
@pytest.mark.asyncio
async def test_typescript_runner_against_the_python_company(tmp_path: Path) -> None:
    world = ManzanitaConformance()
    driver = world.driver

    def agent(identity: AgentIdentity, name: str) -> dict[str, Any]:
        key = tmp_path / f"{name}-key.json"
        key.write_text(jwt.algorithms.ECAlgorithm.to_jwk(identity.private_key))
        key.chmod(0o600)
        return {
            "domain": identity.domain,
            "name": identity.name,
            "key": str(key),
            "extensions": list(identity.extensions),
        }

    async with served_over_tls(world.network):
        port, ca = _served(world.network)
        (tmp_path / "ca.pem").write_text(ca)
        config = tmp_path / "conformance.json"
        config.write_text(
            json.dumps(
                {
                    "port": port,
                    "ca": str(tmp_path / "ca.pem"),
                    "base_url": "https://manzanita.example",
                    "scenario": _scenario_json(),
                    "accounts": list(driver.accounts),
                    "capabilities": sorted(driver.capabilities),
                    "clock": world.clock.now().isoformat().replace("+00:00", "Z"),
                    "agent": agent(world.atlas, "atlas"),
                    "other": agent(world.plain, "plain"),
                }
            )
        )
        node = await NodeProcess.start("run-conformance.mjs", config)
        try:
            while True:
                line = await node.receive()
                if "report" in line:
                    document = line["report"]
                    break
                if "failed" in line:
                    pytest.fail(f"the TypeScript runner failed: {line['failed']}")
                try:
                    await node.send(await _answer(driver, line))
                except (KeyError, ValueError) as error:
                    await node.send({"error": f"{type(error).__name__}: {error}"})
        finally:
            await node.stop()
    _save("typescript-agent-python-company", document)
    report = ConformanceReport.from_json(document)
    _print("TypeScript agent ↔ Python company", report)
    failed = {r.id: r.message for r in report.results if r.outcome == "failed"}
    assert failed.keys() == TYPESCRIPT_AGENT_GAPS.keys(), failed
