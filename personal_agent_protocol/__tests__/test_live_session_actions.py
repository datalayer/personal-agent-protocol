# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Live-session actions: one implementation each, from Studio, a REPL, and `pap commands run`.

Against Manzanita, in process: a user signs in from `pap`, an operation is
proposed and a conversation started. Then every action is invoked from each
surface — Reactor's command registry as Studio's palette calls it, a Reactor REPL
whose slash commands the same plugin registered, and `pap commands run <id>` —
and answers what the `pap` command of the same name answers with `--json`.
Destructive actions refuse on every surface unless the host contributes an
approval surface, and do what was approved only when it says yes.
"""

from __future__ import annotations

import asyncio
import json
import shlex
from pathlib import Path
from typing import Any

import pytest
from reactor import PluginManifest  # type: ignore[import-untyped]
from reactor.repl import ReactorRepl  # type: ignore[import-untyped]
from reactor.slash import SlashCommandRegistry  # type: ignore[import-untyped]

from personal_agent_protocol import APPROVAL_SURFACES, ApprovalRequest
from personal_agent_protocol.actions import (
    ACTIONS,
    ActionUsageError,
    ApprovalRequiredError,
    parse_arguments,
)
from personal_agent_protocol.cli_commands import ExitCode
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE

from .test_cli_protocol import Pap

SCOPES = ("--scope", "orders:read", "--scope", "orders:write")
SAFE = {
    "pap.company.discover",
    "pap.sessions.show",
    "pap.conversations.events",
    "pap.conversations.follow",
    "pap.operations.show",
    "pap.requirements.list",
    "pap.requirements.show",
}
NEEDS_APPROVAL = {"pap.operations.cancel", "pap.sessions.end", "pap.auth.disconnect"}


class Approvals:
    """The host's approval surface: the user's answers, in order; what it was shown."""

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.asked: list[ApprovalRequest] = []

    async def approve(self, request: ApprovalRequest) -> bool:
        self.asked.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer  # type: ignore[return-value]

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(APPROVAL_SURFACES, self, contribution_id="host-approval", order=50)


class World:
    """A user with Manzanita: signed in, an operation proposed, a conversation going."""

    def __init__(self, tmp_path: Path, *plugins: tuple[PluginManifest, object]) -> None:
        self.pap = Pap(tmp_path, plugins=plugins)
        pap = self.pap
        pap.set_up()
        self.session = pap("sessions", "start", "--json")["session"]["id"]
        lines = f"{ADA['email']}\n{ADA['password']}\n{ADA_CODE}\n"
        pap("auth", "mediated", self.session, *SCOPES, "--stdin", "--json", input=lines)
        self.operation = pap(
            "api", "openapi", self.session, "POST", "/api/orders/ord_7Hk2/exchanges", "--json"
        )["operation"]["operation_id"]
        self.conversation = pap("conversations", "start", self.session, "Hello.", "--json")[
            "conversation_id"
        ]

    def studio(self, action_id: str, argument: object = None) -> Any:
        """Studio's palette: the Reactor command registry, with a mapping."""

        return asyncio.run(self.pap.platform.execute_command(action_id, argument))

    def repl(self, line: str) -> dict[str, Any] | str:
        """A Reactor REPL whose slash commands the PAP plugin registered."""

        registry = SlashCommandRegistry()
        self.pap.pap.provide_slash_commands(registry)
        before = len(self.pap.printed)
        assert asyncio.run(ReactorRepl(registry).dispatch(line))
        (printed,) = self.pap.printed[before:]
        return json.loads(printed) if printed.startswith("{") else printed

    def run(self, action_id: str, *words: str, code: int = 0) -> Any:
        """`pap commands run <id> [words]`."""

        result = self.pap("commands", "run", action_id, *words, code=code)
        return json.loads(result.stdout) if code == 0 else result.output


def _same_everywhere(world: World, action_id: str, cli: list[str], **values: str) -> dict:
    """The action from Studio, a REPL and `pap commands run`, and the `pap` command."""

    words = [f"{name}={value}" for name, value in values.items()]
    studio = world.studio(action_id, values)
    repl = world.repl(f"/{action_id} {shlex.join(words)}")
    terminal = world.run(action_id, *words)
    assert studio == repl == terminal, action_id
    assert studio["schema_version"] == 1
    if cli:
        assert world.pap(*cli, "--json") == studio, action_id
    return studio


def test_each_safe_action_is_one_implementation_on_every_surface(tmp_path: Path) -> None:
    world = World(tmp_path)
    session, operation, conversation = world.session, world.operation, world.conversation

    shown = _same_everywhere(world, "pap.sessions.show", ["sessions", "show"])
    assert [item["id"] for item in shown["sessions"]] == [session]
    one = _same_everywhere(
        world, "pap.sessions.show", ["sessions", "show", session], session=session
    )
    assert one["session"]["signed_in"] is True and "pairwise_user_id" not in one["session"]
    proposed = _same_everywhere(
        world,
        "pap.operations.show",
        ["operations", "show", session, operation],
        session=session,
        operation_id=operation,
    )
    assert proposed["operation"]["state"] == "proposed"
    page = _same_everywhere(
        world,
        "pap.conversations.events",
        ["conversations", "events", session, conversation],
        session=session,
        conversation_id=conversation,
    )
    assert page["conversation_id"] == conversation and page["events"]
    followed = _same_everywhere(
        world,
        "pap.conversations.follow",
        ["conversations", "follow", session, conversation, "--max-events", "2"],
        session=session,
        conversation_id=conversation,
        max_events="2",
    )
    assert len(followed["events"]) == 2
    listed = _same_everywhere(
        world,
        "pap.requirements.list",
        ["requirements", "list", "--role", "company", "--level", "MUST NOT"],
        role="company",
        level="MUST NOT",
    )
    assert listed["requirements"]
    shown_requirement = _same_everywhere(
        world,
        "pap.requirements.show",
        ["requirements", "show", "OPS-6-02"],
        requirement_id="OPS-6-02",
    )
    assert shown_requirement["requirement"]["id"] == "OPS-6-02"
    # Discovery through the agent's own Reactor (the host's network and safety policy).
    company = _same_everywhere(world, "pap.company.discover", [], domain="manzanita.example")
    assert company["verified"] and company["organization"] == "Manzanita Outfitters"
    # Nothing an action answered holds a secret the agent keeps.
    answered = "\n".join(world.pap.outputs + world.pap.printed)
    for secret in world.pap.secrets():
        assert secret not in answered


def test_arguments_by_position_name_json_or_mapping_are_the_same(tmp_path: Path) -> None:
    world = World(tmp_path)
    session, operation = world.session, world.operation
    expected = world.studio("pap.operations.show", {"session": session, "operation_id": operation})
    assert world.run("pap.operations.show", session, operation) == expected
    assert world.run("pap.operations.show", f"operation_id={operation}", session) == expected
    text = json.dumps({"session": session, "operation_id": operation})
    assert world.studio("pap.operations.show", text) == expected
    assert world.repl(f"/pap.operations.show {session} {operation}") == expected


def test_unknown_actions_and_arguments_are_usage_errors(tmp_path: Path) -> None:
    world = World(tmp_path)
    world.run("pap.nothing.here", code=ExitCode.USAGE)
    out = world.run("pap.sessions.show", "token=abc", "x", "y", code=ExitCode.USAGE)
    assert "takes session" in out
    world.run("pap.operations.show", world.session, code=ExitCode.USAGE)  # operation_id missing
    with pytest.raises(ActionUsageError, match="needs requirement_id"):
        world.studio("pap.requirements.show", {})
    with pytest.raises(ActionUsageError, match="is text"):
        world.studio("pap.sessions.show", {"session": ["a"]})
    assert world.repl("/pap.requirements.show PAP-0-00") == (
        "unknown_requirement: No requirement PAP-0-00"
    )
    # An unknown Session is not configured, on every surface.
    world.run("pap.sessions.show", "ses_unknown_0000000000", code=ExitCode.NOT_CONFIGURED)
    assert str(world.repl("/pap.sessions.show ses_unknown_0000000000")).startswith(
        "unknown_session:"
    )


def test_destructive_actions_are_refused_without_an_approval_surface(tmp_path: Path) -> None:
    world = World(tmp_path)
    session, operation = world.session, world.operation
    arguments = {
        "pap.operations.cancel": {"session": session, "operation_id": operation},
        "pap.sessions.end": {"session": session},
        "pap.auth.disconnect": {"session": session},
    }
    for action_id, values in arguments.items():
        with pytest.raises(ApprovalRequiredError) as refused:
            world.studio(action_id, values)
        assert refused.value.code == "approval_required"
        words = [f"{name}={value}" for name, value in values.items()]
        assert world.repl(" ".join([f"/{action_id}", *words])).startswith(  # type: ignore[union-attr]
            "approval_required:"
        )
        out = world.run(action_id, *words, code=ExitCode.NOT_APPROVED)
        assert "approval_required" in out
    # Nothing was done: the Session is held and signed in, the operation still proposed.
    held = world.pap("sessions", "show", session, "--json")["session"]
    assert held["signed_in"] is True and held["account_reference"]
    shown = world.pap("operations", "show", session, operation, "--json")["operation"]
    assert shown["state"] == "proposed"
    # The same actions stay available as CLI-only commands.
    assert world.pap("auth", "disconnect", session, "--json")["session"]["signed_in"] is False


def test_the_approval_surface_is_shown_the_action_and_only_yes_does_it(tmp_path: Path) -> None:
    approvals = Approvals(False, RuntimeError("the dialog crashed"), True, True)
    world = World(tmp_path, (PluginManifest(name="host-approval", version="1"), approvals))
    session, operation = world.session, world.operation

    with pytest.raises(ApprovalRequiredError) as declined:
        world.studio("pap.operations.cancel", {"session": session, "operation_id": operation})
    assert declined.value.code == "not_approved"
    out = world.run("pap.operations.cancel", session, operation, code=ExitCode.NOT_APPROVED)
    assert "approval_failed" in out and "crashed" not in out
    assert (
        world.pap("operations", "show", session, operation, "--json")["operation"]["state"]
        == "proposed"
    )

    cancelled = world.studio(
        "pap.operations.cancel", {"session": session, "operation_id": operation}
    )
    assert cancelled["operation"]["state"] == "cancelled"
    ended = world.repl(f"/pap.sessions.end {session}")
    assert isinstance(ended, dict) and ended["ended"] == session
    world.pap("sessions", "show", session, code=ExitCode.NOT_CONFIGURED)

    request = approvals.asked[0]
    assert request.action_id == "pap.operations.cancel"
    assert request.summary == f"Cancel operation {operation} at the company."
    assert dict(request.arguments) == {"session": session, "operation_id": operation}
    assert request.tenant_id == "pap-cli"
    assert [r.action_id for r in approvals.asked] == [
        "pap.operations.cancel",
        "pap.operations.cancel",
        "pap.operations.cancel",
        "pap.sessions.end",
    ]


def test_two_approval_surfaces_at_one_order_fail_closed(tmp_path: Path) -> None:
    world = World(
        tmp_path,
        (PluginManifest(name="approval-a", version="1"), Approvals(True)),
        (PluginManifest(name="approval-b", version="1"), Approvals(True)),
    )
    with pytest.raises(ApprovalRequiredError) as refused:
        world.studio("pap.sessions.end", {"session": world.session})
    assert refused.value.code == "approval_surface_ambiguous"
    world.pap("sessions", "show", world.session, "--json")


def test_actions_see_only_their_tenants_sessions(tmp_path: Path, monkeypatch: Any) -> None:
    world = World(tmp_path)
    monkeypatch.setenv("PAP_TENANT", "shop-b")
    assert world.studio("pap.sessions.show") == {"schema_version": 1, "sessions": []}
    world.run("pap.sessions.show", world.session, code=ExitCode.NOT_CONFIGURED)
    monkeypatch.setenv("PAP_TENANT", "pap-cli")
    shown = world.studio("pap.sessions.show")
    assert [item["id"] for item in shown["sessions"]] == [world.session]


def test_only_safe_and_approval_gated_actions_are_registered(tmp_path: Path) -> None:
    assert set(ACTIONS) == SAFE | NEEDS_APPROVAL
    assert {a.id for a in ACTIONS.values() if a.needs_approval} == NEEDS_APPROVAL
    forbidden = ("token", "password", "secret", "credential", "assertion", "key", "code", "pem")
    for action in ACTIONS.values():
        for argument in action.arguments:
            assert not any(word in argument.name for word in forbidden), argument.name
        if action.needs_approval:
            assert action.summary, action.id
    # Configuration, credential entry, sign-in, messages, APIs and approvals stay CLI-only.
    for cli_only in (
        "pap.config.set",
        "pap.agent.key.import",
        "pap.auth.direct",
        "pap.auth.device",
        "pap.auth.mediated",
        "pap.sessions.start",
        "pap.conversations.send",
        "pap.operations.approve",
        "pap.operations.confirm",
        "pap.api.openapi",
    ):
        assert cli_only not in ACTIONS
    listed = Pap(tmp_path)("commands", "list", "--json")["commands"]
    assert [entry["id"] for entry in listed] == list(ACTIONS)
    assert {entry["plugin"] for entry in listed} == {"personal-agent-protocol.cli"}


def test_parse_arguments_refuses_what_an_action_does_not_take() -> None:
    show = ACTIONS["pap.operations.show"]
    assert parse_arguments(show, "a b") == {"session": "a", "operation_id": "b"}
    assert parse_arguments(show, ["operation_id=b", "a"]) == {
        "session": "a",
        "operation_id": "b",
    }
    for bad in ("a b c", "{not json", "[1]", 42, {"session": True, "operation_id": "b"}):
        with pytest.raises(ActionUsageError):
            parse_arguments(show, bad)
