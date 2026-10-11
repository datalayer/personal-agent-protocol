# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The `pap` protocol commands against Manzanita, in process, as a user would run them."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click
import typer
from cryptography.hazmat.primitives import serialization
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]
from typer.testing import CliRunner

from personal_agent_protocol.cli import create_app
from personal_agent_protocol.cli_commands import EXIT_CODES, ExitCode
from personal_agent_protocol.cli_host import local_host
from personal_agent_protocol.cli_plugin import MANIFEST, PapCliPlugin
from personal_agent_protocol.config import ConfigStore
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    ClockPlugin,
    InProcessNetwork,
    MutableClock,
    ScriptedBrowser,
)
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE, manzanita
from personal_agent_protocol.reactor import BROWSER_HANDOFFS

GROUPS = ("sessions", "auth", "api", "conversations", "operations", "requirements", "conformance")


class UsersBrowser:
    """The user's own browser, opening Manzanita's sign-in page (pap.browserHandoff)."""

    def __init__(self, network: InProcessNetwork) -> None:
        self.browser = ScriptedBrowser(network.client())

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(
            BROWSER_HANDOFFS, self.browser, contribution_id="users-browser", order=50
        )


class Pap:
    """A user's terminal: one Manzanita world, one `pap` with its own state directory."""

    def __init__(self, tmp_path: Path, *, approve_on_wait: bool = True) -> None:
        self.clock = MutableClock()
        self.network = InProcessNetwork()
        self.atlas = AgentIdentity(domain="atlas.example", name="Atlas")
        self.network.add(self.atlas.domain, self.atlas.website())
        self.shop, self.plugin = manzanita(self.network, self.clock)
        self.state = tmp_path / "state"
        self.approve_on_wait = approve_on_wait
        self.outputs: list[str] = []

        async def wait(seconds: float) -> None:
            # The user approves on Manzanita's page while the CLI waits.
            if self.approve_on_wait:
                for pending in self.shop.store.devices.values():
                    if pending.account_id is None:
                        self.shop.approve_device(pending.user_code, account_id="acct_ada")
            self.clock.advance(seconds)

        host = local_host(
            self.state,
            open_browser=False,
            address_resolver=self.network.resolve,
            http_factory=self.network.client,
            discover_plugins=False,
            plugins=[
                (PluginManifest(name="demo-clock", version="1"), ClockPlugin(self.clock)),
                (PluginManifest(name="users-browser", version="1"), UsersBrowser(self.network)),
            ],
            sleep=wait,
        )
        platform = PluginPlatform()
        platform.register_plugin(
            MANIFEST, PapCliPlugin(ConfigStore(tmp_path / "config.json"), host)
        )
        self.app = create_app(platform)
        self.runner = CliRunner()

    def __call__(self, *arguments: str, input: str | None = None, code: int = 0) -> Any:  # noqa: A002
        result = self.runner.invoke(self.app, list(arguments), input=input)
        self.outputs.append(result.output)
        assert result.exit_code == code, (arguments, result.exit_code, result.output)
        if "--json" in arguments and result.exit_code == 0:
            payload = json.loads(result.stdout)
            assert payload["schema_version"] == 1
            return payload
        return result

    def pem(self) -> str:
        return self.atlas.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()

    def set_up(self) -> None:
        self("config", "set", "client_id", self.atlas.client_id)
        self("config", "set", "domain", "manzanita.example")
        self("agent", "key", "import", "--stdin", "--json", input=self.pem())

    def secrets(self) -> list[str]:
        values = json.loads((self.state / "secrets.json").read_text())
        return [*values.values(), self.pem().splitlines()[1]]


def test_every_group_and_command_has_help_and_completion(tmp_path: Path) -> None:
    pap = Pap(tmp_path)
    command = typer.main.get_command(pap.app)
    assert isinstance(command, click.Group)
    for group in (*GROUPS, "agent"):
        sub = command.commands[group]
        assert isinstance(sub, click.Group)
        pap(group, "--help")
        for name in sub.commands:
            assert "Usage" in pap(group, name, "--help").output
    completion = pap("--show-completion", "bash")
    assert "_PAP_COMPLETE" in completion.output


def test_no_protected_value_is_ever_a_command_line_option(tmp_path: Path) -> None:
    forbidden = ("token", "password", "secret", "credential", "assertion", "pem", "private")
    command = typer.main.get_command(Pap(tmp_path).app)
    assert isinstance(command, click.Group)
    for group in (*GROUPS, "agent"):
        sub = command.commands[group]
        assert isinstance(sub, click.Group)
        commands = [
            leaf
            for leaf in sub.commands.values()
            for leaf in (leaf.commands.values() if isinstance(leaf, click.Group) else [leaf])
        ]
        for leaf in commands:
            for parameter in leaf.params:
                names = " ".join([parameter.name or "", *getattr(parameter, "opts", [])]).lower()
                assert not any(word in names for word in forbidden), (leaf.name, names)
                assert "code" not in names.replace("exit-codes", ""), (leaf.name, names)


def test_a_user_with_manzanita_from_the_command_line(tmp_path: Path) -> None:
    pap = Pap(tmp_path)
    pap.set_up()
    key = pap("agent", "key", "show", "--json")["key"]
    assert key["key_reference"] == "key:key-1" and key["alg"] == "ES256"

    started = pap("sessions", "start", "--json")["session"]
    session = started["session_id"]
    assert started["signed_in"] is False and started["token_reference"] == f"session:{session}"
    assert "pairwise_user_id" not in started

    # Mediated Sign-In: credentials and the one-time code from stdin, never as options.
    lines = f"{ADA['email']}\n{ADA['password']}\n{ADA_CODE}\n"
    signed = pap("auth", "mediated", session, "--stdin", "--json", input=lines)["session"]
    assert signed["signed_in"] and signed["scope"] == "orders:read orders:write"
    assert signed["account_reference"].startswith("account")

    orders = pap("api", "openapi", session, "GET", "/api/orders", "--json")
    assert orders["body"]["orders"][0]["order_id"] == "ord_7Hk2"
    proposed = pap("api", "openapi", session, "POST", "/api/orders/ord_7Hk2/exchanges", "--json")[
        "operation"
    ]
    operation = proposed["operation_id"]
    assert proposed["state"] == "proposed"

    # The same operation through MCP, with a Bearer for the MCP url only.
    tools = pap("api", "mcp", session, "--json")["tools"]
    assert [tool["name"] for tool in tools] == ["list_orders", "exchange_jacket"]
    through_mcp = pap("api", "mcp", session, "exchange_jacket", "--json")["operation"]
    assert through_mcp["operation_id"] == operation

    # Approval names the exact ID and revision; confirming needs that approval.
    pap("operations", "confirm", session, operation, "--revision", "1", code=6)
    pap("operations", "approve", session, operation, "--revision", "2", code=6)
    pap("operations", "approve", session, operation, "--revision", "1", input="no\n", code=6)
    pap("operations", "approve", session, operation, "--revision", "1", "--no-input", code=4)
    approved = pap(
        "operations", "approve", session, operation, "--revision", "1", "--json",
        input=f"{operation}\n",
    )  # fmt: skip
    assert approved["approved"] == {"operation_id": operation, "revision": 1}
    pap("operations", "confirm", session, operation, "--revision", "2", code=6)
    done = pap("operations", "confirm", session, operation, "--revision", "1", "--json")
    assert done["operation"]["state"] == "succeeded" and done["status"] == "confirmed"
    shown = pap("operations", "show", session, operation, "--json")["operation"]
    assert shown["confirmation"]["approved_by"] == "user"
    assert pap.plugin.executor.performed == [operation]

    # Conversations.
    receipt = pap("conversations", "start", session, "Hello.", "--json")
    conversation = receipt["conversation_id"]
    page = pap(
        "conversations", "send", session, conversation, "Where is my order?", "--human",
        "--wait", "0", "--json",
    )  # fmt: skip
    assert any(e["message"]["sender"] == "human" for e in page["events"] if "message" in e)
    events = pap("conversations", "events", session, conversation, "--json")
    assert events["status"] == "idle" and events["has_more"] is False
    followed = pap("conversations", "follow", session, conversation, "--max-events", "2", "--json")
    assert len(followed["events"]) == 2
    assert pap("conversations", "handoff", session, conversation, "--json")["status"] == "idle"
    direct = pap("conversations", "direct", session, conversation, "I'll ask myself.", "--json")[
        "conversation_id"
    ]
    pap("conversations", "send", session, conversation, "Meanwhile?", code=1)
    pap("conversations", "close", session, direct, "--json")
    assert pap("conversations", "close", session, conversation, "--json")["status"] == "closed"

    # Sign out: the Session continues signed out; renewal is signed out.
    assert pap("auth", "disconnect", session, "--json")["session"]["signed_in"] is False
    assert pap("sessions", "renew", session, "--json")["session"]["signed_in"] is False
    pap("api", "openapi", session, "GET", "/api/orders", code=1)
    listed = pap("sessions", "show", "--json")["sessions"]
    assert [item["session_id"] for item in listed] == [session]
    pap("sessions", "end", session, "--json")
    pap("sessions", "show", session, code=3)

    # No secret ever reached the terminal, and the state file holds none.
    state = (pap.state / "state.json").read_text()
    for secret in pap.secrets():
        assert all(secret not in output for output in pap.outputs)
        assert secret not in state
    assert oct((pap.state / "secrets.json").stat().st_mode & 0o777) == "0o600"
    assert oct((pap.state / "keys.json").stat().st_mode & 0o777) == "0o600"


def test_device_sign_in_waits_for_the_user_and_times_out(tmp_path: Path) -> None:
    pap = Pap(tmp_path)
    pap.set_up()
    session = pap("sessions", "start", "--json")["session"]["session_id"]
    signed = pap("auth", "device", session, "--scope", "orders:read", "--json")["session"]
    assert signed["signed_in"] and signed["scope"] == "orders:read"
    assert pap("sessions", "renew", session, "--json")["session"]["signed_in"] is True

    waiting = Pap(tmp_path / "other", approve_on_wait=False)
    waiting.set_up()
    other = waiting("sessions", "start", "--json")["session"]["session_id"]
    result = waiting("auth", "device", other, "--timeout", "12", code=5)
    assert "authorization_pending" in result.output


def test_exit_codes_for_setup_input_refusals_and_usage(tmp_path: Path) -> None:
    pap = Pap(tmp_path)
    pap("sessions", "start", "manzanita.example", code=3)  # no client_id
    pap("config", "set", "client_id", pap.atlas.client_id)
    missing_key = pap("sessions", "start", "manzanita.example", code=3)
    assert "pap agent key import" in missing_key.output
    pap("agent", "key", "import", code=4)  # the PEM is never prompted for or an option
    pap("agent", "key", "import", "--stdin", input="not a key\n", code=1)
    pap("agent", "key", "import", "--stdin", input=pap.pem())
    session = pap("sessions", "start", "manzanita.example", "--json")["session"]["session_id"]
    pap("auth", "mediated", session, "--no-input", code=4)
    pap("auth", "direct", session, "--no-input", code=4)
    wrong = f"{ADA['email']}\nnot the password\n"
    assert (
        "sign_in_failed" in pap("auth", "mediated", session, "--stdin", input=wrong, code=1).output
    )
    pap("api", "openapi", session, "GET", "/api/nothing-here", code=1)
    pap("sessions", "renew", "ses_unknown", code=3)
    pap("sessions", "start", "--no-such-option", code=2)
    listed = pap("exit-codes", "--json")["exit_codes"]
    assert set(listed) == {str(int(code)) for code in ExitCode} == {str(c) for c in EXIT_CODES}


def test_direct_sign_in_reads_the_callback_from_a_file_descriptor(tmp_path: Path) -> None:
    import os

    pap = Pap(tmp_path)
    pap.set_up()
    session = pap("sessions", "start", "--json")["session"]["session_id"]
    shop = pap.shop

    # The user signs in on Manzanita's page in their own browser; their browser
    # then lands on the agent's callback, which they hand to the CLI.
    original = shop.approve_authorization
    callbacks: list[str] = []

    def approve_when_asked() -> str:
        request_id = next(iter(shop.store.authorizations))
        callbacks.append(original(request_id, account_id="acct_ada"))
        return callbacks[-1]

    read, write = os.pipe()
    import threading

    def answer() -> None:
        import time

        for _ in range(200):
            if shop.store.authorizations:
                break
            time.sleep(0.01)
        try:
            os.write(write, (approve_when_asked() + "\n").encode())
        finally:
            os.close(write)

    thread = threading.Thread(target=answer)
    thread.start()
    try:
        signed = pap(
            "auth", "direct", session, "--scope", "orders:read", "--input-fd", str(read), "--json"
        )["session"]
    finally:
        thread.join()
        os.close(read)
    assert signed["signed_in"] and signed["scope"] == "orders:read"
    assert all(callbacks[0] not in output for output in pap.outputs)


def test_a_broken_extension_does_not_take_the_command_line_down(tmp_path: Path) -> None:
    class Broken:
        def provide_cli(self, cli: typer.Typer) -> None:
            raise RuntimeError("this extension is broken")

    platform = PluginPlatform()
    platform.register_plugin(MANIFEST, PapCliPlugin(ConfigStore(tmp_path / "c.json")))
    platform.register_plugin(PluginManifest(name="example.broken", version="1"), Broken())
    result = CliRunner().invoke(create_app(platform), ["--help"])
    assert result.exit_code == 0
    for group in GROUPS:
        assert group in result.output


def test_requirements_and_conformance_commands(tmp_path: Path) -> None:
    pap = Pap(tmp_path)
    listed = pap("requirements", "list", "--role", "company", "--level", "MUST NOT", "--json")
    assert listed["requirements"] and all(
        item["level"] == "MUST NOT" and item["role"] in {"company", "both"}
        for item in listed["requirements"]
    )
    shown = pap("requirements", "show", "OPS-6-02", "--json")["requirement"]
    assert shown["source"] == "operations" and shown["conformance"]
    pap("requirements", "show", "PAP-0-00", code=2)

    report = tmp_path / "report.json"
    pap(
        "conformance", "run", "--demo", "--suite", "operations", "--format", "json",
        "--output", str(report),
    )  # fmt: skip
    payload = json.loads(report.read_text())
    assert payload["summary"]["failed"] == 0 and payload["summary"]["passed"] > 10
    junit = pap("conformance", "report", str(report), "--format", "junit")
    assert "<testsuite" in junit.output and 'name="pap.operations"' in junit.output
    text = pap("conformance", "run", "--demo", "--case", "lifecycle.rotated-token")
    assert "passed   lifecycle.rotated-token" in text.output
    pap("conformance", "run", code=3)  # a real company needs its own driver and scenario
