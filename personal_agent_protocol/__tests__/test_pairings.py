# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The language pairings over real TCP and TLS (PAP plan §5), one shared scenario.

- TypeScript agent ↔ Python company: the Python Manzanita is served with
  `served_over_tls`; the TypeScript agent runs in node and asks this test to play
  the user's actions at the company.
- Python agent ↔ TypeScript company: the TypeScript Manzanita runs on node:https
  with a throwaway CA; this test is the personal agent.

Both run `protocol/scenarios/user-with-a-company.json`, the journey the
TypeScript ↔ TypeScript pairing (`src/__tests__/pairing.test.mjs`) and the
Python ↔ Python one run too. They need node and the TypeScript `lib/` built (by
the watcher or `npm run build:lib`); they skip otherwise.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import ssl
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest

from personal_agent_protocol import (
    ConversationClient,
    DirectSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.apis import ApiClient
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    PersonalAgentHost,
    ScriptedBrowser,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import manzanita
from personal_agent_protocol.demo.sockets import (
    _certificates,
    _DialLocal,
    served_over_tls,
)
from personal_agent_protocol.models import ClientMetadata
from personal_agent_protocol.operations import (
    OperationsClient,
    approve,
    operations_endpoint,
)

pytest.importorskip("uvicorn")

ROOT = Path(__file__).parents[2]
SCENARIO = json.loads((ROOT / "protocol" / "scenarios" / "user-with-a-company.json").read_text())
SUPPORT = ROOT / "src" / "__tests__" / "support"
NODE = shutil.which("node")
#: Resolves extensionless ESM imports for local runs, when present (PAP_NODE_IMPORT overrides).
NODE_IMPORT = os.environ.get(
    "PAP_NODE_IMPORT", str(Path.home() / ".cache" / "pap-node-test" / "register.mjs")
)

pytestmark = pytest.mark.skipif(
    NODE is None
    or not (ROOT / "lib" / "server.js").exists()
    or not (ROOT / "lib" / "demo" / "manzanita.js").exists(),
    reason="needs node and the TypeScript lib/",
)


class SystemClock:
    """The wall clock: the two parties live in different processes."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)


def _node(script: str, config: Path) -> list[str]:
    command = [str(NODE)]
    if NODE_IMPORT and Path(NODE_IMPORT).exists():
        command += ["--import", NODE_IMPORT]
    return [*command, str(SUPPORT / script), str(config)]


class NodeProcess:
    """A node process speaking JSON lines on stdin and stdout."""

    def __init__(self, process: asyncio.subprocess.Process) -> None:
        self.process = process

    @classmethod
    async def start(cls, script: str, config: Path) -> NodeProcess:
        process = await asyncio.create_subprocess_exec(
            *_node(script, config),
            cwd=ROOT,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=1024 * 1024,
        )
        return cls(process)

    async def receive(self) -> dict[str, Any]:
        assert self.process.stdout is not None
        line = await asyncio.wait_for(self.process.stdout.readline(), timeout=60)
        if not line:
            assert self.process.stderr is not None
            error = (await self.process.stderr.read()).decode(errors="replace")
            pytest.fail(f"node ended without answering: {error[-2000:]}")
        return json.loads(line)

    async def send(self, message: dict[str, Any]) -> None:
        assert self.process.stdin is not None
        self.process.stdin.write(json.dumps(message).encode() + b"\n")
        await self.process.stdin.drain()

    async def ask(self, message: dict[str, Any]) -> dict[str, Any]:
        await self.send(message)
        return await self.receive()

    async def stop(self) -> None:
        if self.process.returncode is None:
            self.process.kill()
        await self.process.wait()


# The Python agent's journey ---------------------------------------------------------------


class _Journey:
    """The Python personal agent's state through the shared scenario, one method per step."""

    def __init__(
        self,
        *,
        reactor: Any,
        http: httpx.AsyncClient,
        browser: ScriptedBrowser,
        identity: AgentIdentity,
        approve_authorization: Callable[[str, str], Awaitable[str]],
        performed: Callable[[str], Awaitable[list[str]]],
    ) -> None:
        self.reactor = reactor
        self.http = http
        self.browser = browser
        self.identity = identity
        self.approve_authorization = approve_authorization
        self.performed = performed
        self.agent = SCENARIO["agent"]
        self.domain = SCENARIO["company"]["domain"]
        self.transport = DpopHttpClient(reactor=reactor, http_client=http)
        self.conversations = ConversationClient(transport=self.transport)
        self.company: Any = None
        self.who: dict[str, str] = {}
        self.session: Any = None
        self.signed_in: Any = None
        self.page: Any = None
        self.proposal: Any = None
        self.seen: dict[str, Any] = {}

    def message(self, text: str) -> Message:
        return Message(id=generate_message_id(self.reactor), sender="human", text=text)

    async def discover(self, step: dict[str, Any], expect: dict[str, Any]) -> None:
        agent = self.agent
        self.company = await DiscoveryClient(reactor=self.reactor, http_client=self.http).discover(
            self.domain
        )
        assert self.company.document.organization.name == expect["organization"]
        assert ("operations" in self.company.document.extensions) is expect["operations"]
        self.who = {
            "tenant_id": agent["tenant_id"],
            "pairwise_user_id": agent["pairwise_user_id"],
            "issuer": self.company.oauth_metadata.issuer,
        }

    async def session_step(self, step: dict[str, Any], expect: dict[str, Any]) -> None:
        agent = self.agent
        self.session = await SessionClient(reactor=self.reactor, http_client=self.http).start(
            client_id=self.identity.client_id,
            pairwise_user_id=agent["pairwise_user_id"],
            issuer=self.who["issuer"],
            token_endpoint=self.company.oauth_metadata.token_endpoint,
            tenant_id=agent["tenant_id"],
        )
        assert self.session.signed_in is expect["signed_in"]

    async def ask(self, step: dict[str, Any], expect: dict[str, Any]) -> None:
        endpoint = self.company.document.agent.protocols[0].endpoint
        self.page = await self.conversations.start(
            endpoint, self.message(step["text"]), token=self.session, wait=0, **self.who
        )
        assert [event.type for event in self.page.events] == expect["events"]
        assert [e for e in self.page.events if e.type != "state"][-1].error == expect["error"]
        self.seen["authorization"] = [e for e in self.page.events if e.type != "state"][-1].error

    async def sign_in(self, step: dict[str, Any], expect: dict[str, Any]) -> None:
        assert step["method"] == "direct"
        agent = self.agent
        metadata = self.company.oauth_metadata
        client = DirectSignInClient(reactor=self.reactor, http_client=self.http)
        await client.begin(
            authorization_endpoint=metadata.authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=self.identity.client_id,
            redirect_uri=f"https://{agent['domain']}{agent['redirect_path']}",
            scopes=tuple(step["scopes"]),
            tenant_id=agent["tenant_id"],
            pairwise_user_id=agent["pairwise_user_id"],
            session_id=self.session.session_id,
        )
        for text in expect["consent_page"]:
            assert text in self.browser.pages[-1]
        assert self.browser.request_id is not None
        callback = await self.approve_authorization(
            self.browser.request_id, SCENARIO["company"]["account_id"]
        )
        result = await client.complete(callback)
        self.signed_in = result.token
        assert self.signed_in.signed_in is expect["signed_in"]
        assert self.signed_in.session_id == self.session.session_id
        assert list(result.granted_scopes) == expect["granted"]

    async def api_read(self, step: dict[str, Any], expect: dict[str, Any]) -> None:
        answer = await ApiClient(transport=self.transport).call(
            step["method"],
            f"https://{self.domain}{step['path']}",
            token=self.signed_in,
            **self.who,
        )
        assert answer.status == expect["status"]
        assert answer.body == expect["body"]
        self.seen["read"] = True

    async def continue_step(self, step: dict[str, Any], expect: dict[str, Any]) -> None:
        endpoint = self.company.document.agent.protocols[0].endpoint
        self.page = await self.conversations.send(
            endpoint,
            self.page.conversation_id,
            self.message(step["text"]),
            token=self.signed_in,
            cursor=self.page.cursor,
            wait=0,
            **self.who,
        )
        self.proposal = [e for e in self.page.events if e.type != "state"][-1].message.operation
        assert self.proposal.state == expect["operation_state"]
        assert self.proposal.user_approval_required is expect["user_approval_required"]

    async def confirm(self, step: dict[str, Any], expect: dict[str, Any]) -> None:
        proposal = self.proposal
        target = operations_endpoint(
            self.company.document, ClientMetadata.model_validate(self.identity.metadata)
        )
        assert target is not None
        operations = OperationsClient(transport=self.transport)
        outcome: Any = None
        for _ in range(step["times"]):
            outcome = await operations.confirm(
                target, proposal, approval=approve(proposal), token=self.signed_in, **self.who
            )
            assert outcome.status == "confirmed"
            assert outcome.operation.state == expect["state"]
            assert outcome.operation.confirmation.approved_by == step["approved_by"]
        assert outcome.operation.result.summary.startswith(expect["summary_starts_with"])
        done = await self.performed("orders.exchange")
        assert done == [proposal.operation_id]
        assert len(done) == expect["performed"]
        self.seen["operation"] = {"operation_id": proposal.operation_id, "performed": len(done)}


_STEPS = {
    "discover": _Journey.discover,
    "session": _Journey.session_step,
    "ask": _Journey.ask,
    "sign_in": _Journey.sign_in,
    "api_read": _Journey.api_read,
    "continue": _Journey.continue_step,
    "confirm": _Journey.confirm,
}


async def run_journey(
    *,
    reactor: Any,
    http: httpx.AsyncClient,
    browser: ScriptedBrowser,
    identity: AgentIdentity,
    approve_authorization: Callable[[str, str], Awaitable[str]],
    performed: Callable[[str], Awaitable[list[str]]],
) -> dict[str, Any]:
    """Every step of the shared scenario, as the Python personal agent."""

    journey = _Journey(
        reactor=reactor,
        http=http,
        browser=browser,
        identity=identity,
        approve_authorization=approve_authorization,
        performed=performed,
    )
    for step in SCENARIO["steps"]:
        run = _STEPS.get(step["step"])
        if run is None:
            raise AssertionError(f"unknown step {step['step']}")
        await run(journey, step, step["expect"])
    return {"steps": [step["step"] for step in SCENARIO["steps"]], **journey.seen}


# TypeScript agent ↔ Python company ------------------------------------------------------


def _served(network: InProcessNetwork) -> tuple[int, str]:
    """The port and CA of a network `served_over_tls` serves (it does not expose them)."""

    transport: Any = network.socket_transport
    pool = transport._pool
    port = pool._network_backend.port
    der = pool._ssl_context.get_ca_certs(binary_form=True)
    return port, "".join(ssl.DER_cert_to_PEM_cert(cert) for cert in der)


@pytest.mark.asyncio
async def test_typescript_agent_with_the_python_company(tmp_path: Path) -> None:
    clock = SystemClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain=SCENARIO["agent"]["domain"], name=SCENARIO["agent"]["name"])
    network.add(atlas.domain, atlas.website())
    shop, plugin = manzanita(network, clock)  # type: ignore[arg-type]
    async with served_over_tls(network):
        port, ca = _served(network)
        (tmp_path / "ca.pem").write_text(ca)
        key = tmp_path / "agent-key.json"
        key.write_text(jwt.algorithms.ECAlgorithm.to_jwk(atlas.private_key))
        key.chmod(0o600)
        config = tmp_path / "agent.json"
        config.write_text(
            json.dumps({"port": port, "ca": str(tmp_path / "ca.pem"), "agent_key": str(key)})
        )
        node = await NodeProcess.start("run-agent.mjs", config)
        try:
            while True:
                line = await node.receive()
                if "done" in line:
                    result = line["done"]
                    break
                if "failed" in line:
                    pytest.fail(f"TypeScript agent failed: {line['failed']}")
                if line.get("ask") == "approve_authorization":
                    callback = await shop.approve_authorization(
                        line["request_id"], account_id=line["account_id"]
                    )
                    await node.send({"callback": callback})
                elif line.get("ask") == "performed":
                    await node.send({"performed": list(plugin.executor.performed)})
                else:
                    pytest.fail(f"unexpected line from node: {line}")
        finally:
            await node.stop()
    assert result["steps"] == [step["step"] for step in SCENARIO["steps"]]
    assert result["authorization"] == "sign_in_required"
    assert plugin.executor.performed == [result["operation"]["operation_id"]]


# Python agent ↔ TypeScript company ------------------------------------------------------


@pytest.mark.asyncio
async def test_python_agent_with_the_typescript_company(tmp_path: Path) -> None:
    company_domain = SCENARIO["company"]["domain"]
    atlas = AgentIdentity(domain=SCENARIO["agent"]["domain"], name=SCENARIO["agent"]["name"])
    ca, cert, key = _certificates([company_domain, atlas.domain], tmp_path)
    config = tmp_path / "company.json"
    config.write_text(
        json.dumps(
            {
                "cert": str(cert),
                "key": str(key),
                "ca": str(ca),
                "agents": {atlas.domain: {"/agent.json": atlas.metadata, "/jwks.json": atlas.jwks}},
            }
        )
    )
    node = await NodeProcess.start("serve-company.mjs", config)
    try:
        ready = await node.receive()
        port = ready["ready"]["port"]

        async def nowhere(scope: Any, receive: Any, send: Any) -> None:  # never called
            raise AssertionError("the network is served over TLS")

        network = InProcessNetwork()
        for domain in (company_domain, atlas.domain):
            network.add(domain, nowhere)  # names it for DNS; requests dial the node server
        transport = httpx.AsyncHTTPTransport(verify=ssl.create_default_context(cafile=str(ca)))
        transport._pool._network_backend = _DialLocal(frozenset(network.apps), port)  # type: ignore[attr-defined]
        network.socket_transport = transport
        http = network.client()
        host = PersonalAgentHost(atlas, SystemClock())  # type: ignore[arg-type]
        browser = ScriptedBrowser(http)
        host.browser = browser
        reactor = personal_agent_reactor(host, network=network, http_client=http)

        async def approve_authorization(request_id: str, account_id: str) -> str:
            answer = await node.ask(
                {"op": "approve_authorization", "request_id": request_id, "account_id": account_id}
            )
            assert "callback" in answer, answer
            return str(answer["callback"])

        async def performed(action: str) -> list[str]:
            return list((await node.ask({"op": "performed", "action": action}))["performed"])

        try:
            result = await run_journey(
                reactor=reactor,
                http=http,
                browser=browser,
                identity=atlas,
                approve_authorization=approve_authorization,
                performed=performed,
            )
        finally:
            reactor.stop()
            await http.aclose()
            await transport.aclose()
        assert result["steps"] == [step["step"] for step in SCENARIO["steps"]]
        assert result["operation"]["performed"] == 1
        await node.send({"op": "close"})
        await asyncio.wait_for(node.process.wait(), timeout=10)
    finally:
        await node.stop()


@pytest.mark.asyncio
async def test_python_agent_with_the_python_company_runs_the_same_scenario() -> None:
    """The Python ↔ Python pairing over TLS, from the same scenario definition."""

    clock = SystemClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain=SCENARIO["agent"]["domain"], name=SCENARIO["agent"]["name"])
    network.add(atlas.domain, atlas.website())
    shop, plugin = manzanita(network, clock)  # type: ignore[arg-type]
    async with served_over_tls(network):
        http = network.client()
        host = PersonalAgentHost(atlas, clock)  # type: ignore[arg-type]
        browser = ScriptedBrowser(http)
        host.browser = browser
        reactor = personal_agent_reactor(host, network=network, http_client=http)

        async def approve_authorization(request_id: str, account_id: str) -> str:
            return await shop.approve_authorization(request_id, account_id=account_id)

        async def performed(action: str) -> list[str]:
            return list(plugin.executor.performed)

        try:
            result = await run_journey(
                reactor=reactor,
                http=http,
                browser=browser,
                identity=atlas,
                approve_authorization=approve_authorization,
                performed=performed,
            )
        finally:
            reactor.stop()
            await http.aclose()
    assert result["operation"]["performed"] == 1
