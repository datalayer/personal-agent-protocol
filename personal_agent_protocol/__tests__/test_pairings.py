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

pytest.importorskip("uvicorn")

from personal_agent_protocol import (  # noqa: E402
    ConversationClient,
    DirectSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.apis import ApiClient  # noqa: E402
from personal_agent_protocol.demo.kit import (  # noqa: E402
    AgentIdentity,
    InProcessNetwork,
    PersonalAgentHost,
    ScriptedBrowser,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import manzanita  # noqa: E402
from personal_agent_protocol.demo.sockets import (  # noqa: E402
    _certificates,
    _DialLocal,
    served_over_tls,
)
from personal_agent_protocol.models import ClientMetadata  # noqa: E402
from personal_agent_protocol.operations import (  # noqa: E402
    OperationsClient,
    approve,
    operations_endpoint,
)

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

    agent = SCENARIO["agent"]
    domain = SCENARIO["company"]["domain"]
    transport = DpopHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)
    company: Any = None
    who: dict[str, str] = {}
    session: Any = None
    signed_in: Any = None
    page: Any = None
    proposal: Any = None
    seen: dict[str, Any] = {}

    def message(text: str) -> Message:
        return Message(id=generate_message_id(reactor), sender="human", text=text)

    for step in SCENARIO["steps"]:
        expect = step["expect"]
        if step["step"] == "discover":
            company = await DiscoveryClient(reactor=reactor, http_client=http).discover(domain)
            assert company.document.organization.name == expect["organization"]
            assert ("operations" in company.document.extensions) is expect["operations"]
            who = {
                "tenant_id": agent["tenant_id"],
                "pairwise_user_id": agent["pairwise_user_id"],
                "issuer": company.oauth_metadata.issuer,
            }
        elif step["step"] == "session":
            session = await SessionClient(reactor=reactor, http_client=http).start(
                client_id=identity.client_id,
                pairwise_user_id=agent["pairwise_user_id"],
                issuer=who["issuer"],
                token_endpoint=company.oauth_metadata.token_endpoint,
                tenant_id=agent["tenant_id"],
            )
            assert session.signed_in is expect["signed_in"]
        elif step["step"] == "ask":
            endpoint = company.document.agent.protocols[0].endpoint
            page = await conversations.start(
                endpoint, message(step["text"]), token=session, wait=0, **who
            )
            assert [event.type for event in page.events] == expect["events"]
            assert page.events[-1].error == expect["error"]
            seen["authorization"] = page.events[-1].error
        elif step["step"] == "sign_in":
            assert step["method"] == "direct"
            metadata = company.oauth_metadata
            client = DirectSignInClient(reactor=reactor, http_client=http)
            await client.begin(
                authorization_endpoint=metadata.authorization_endpoint,
                token_endpoint=metadata.token_endpoint,
                issuer=metadata.issuer,
                client_id=identity.client_id,
                redirect_uri=f"https://{agent['domain']}{agent['redirect_path']}",
                scopes=tuple(step["scopes"]),
                tenant_id=agent["tenant_id"],
                pairwise_user_id=agent["pairwise_user_id"],
                session_id=session.session_id,
            )
            for text in expect["consent_page"]:
                assert text in browser.pages[-1]
            assert browser.request_id is not None
            callback = await approve_authorization(
                browser.request_id, SCENARIO["company"]["account_id"]
            )
            result = await client.complete(callback)
            signed_in = result.token
            assert signed_in.signed_in is expect["signed_in"]
            assert signed_in.session_id == session.session_id
            assert list(result.granted_scopes) == expect["granted"]
        elif step["step"] == "api_read":
            answer = await ApiClient(transport=transport).call(
                step["method"], f"https://{domain}{step['path']}", token=signed_in, **who
            )
            assert answer.status == expect["status"]
            assert answer.body == expect["body"]
            seen["read"] = True
        elif step["step"] == "continue":
            endpoint = company.document.agent.protocols[0].endpoint
            page = await conversations.send(
                endpoint,
                page.conversation_id,
                message(step["text"]),
                token=signed_in,
                cursor=page.cursor,
                wait=0,
                **who,
            )
            proposal = page.events[-1].message.operation
            assert proposal.state == expect["operation_state"]
            assert proposal.user_approval_required is expect["user_approval_required"]
        elif step["step"] == "confirm":
            target = operations_endpoint(
                company.document, ClientMetadata.model_validate(identity.metadata)
            )
            assert target is not None
            operations = OperationsClient(transport=transport)
            outcome: Any = None
            for _ in range(step["times"]):
                outcome = await operations.confirm(
                    target, proposal, approval=approve(proposal), token=signed_in, **who
                )
                assert outcome.status == "confirmed"
                assert outcome.operation.state == expect["state"]
                assert outcome.operation.confirmation.approved_by == step["approved_by"]
            assert outcome.operation.result.summary.startswith(expect["summary_starts_with"])
            done = await performed("orders.exchange")
            assert done == [proposal.operation_id]
            assert len(done) == expect["performed"]
            seen["operation"] = {"operation_id": proposal.operation_id, "performed": len(done)}
        else:
            raise AssertionError(f"unknown step {step['step']}")
    return {"steps": [step["step"] for step in SCENARIO["steps"]], **seen}


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
                    callback = shop.approve_authorization(
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
            return shop.approve_authorization(request_id, account_id=account_id)

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

