# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent invoking PAP's live-session actions, as Studio and a REPL do.

The actions are registered by the `pap` plugin in a Reactor command registry; the
tool runs them by ID through that registry — the same implementation `pap commands
run <id>`, a REPL's slash commands and Studio's palette invoke. Read-only actions
answer; a destructive one is refused here, because this host supplies no approval
surface: the model can never end a Session or sign Ada out.
"""

from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from pydantic_ai import Agent
from reactor import PluginManifest, PluginPlatform

from personal_agent_protocol.actions import ACTIONS
from personal_agent_protocol.cli_host import local_host
from personal_agent_protocol.cli_plugin import MANIFEST, PapCliPlugin
from personal_agent_protocol.config import ConfigStore
from personal_agent_protocol.demo.kit import ClockPlugin, InProcessNetwork, MutableClock
from personal_agent_protocol.demo.manzanita import DOMAIN, manzanita
from personal_agent_protocol.errors import PersonalAgentProtocolError

agent = Agent(
    instructions=(
        "Use run_live_session_actions to show which PAP live-session actions a personal "
        "agent's tools may run and which need the user's own approval. Report what each "
        "returned or why it was refused. Never ask for tokens, codes, or passwords."
    ),
)


def _pap(state: Path, network: InProcessNetwork, clock: MutableClock) -> PluginPlatform:
    """A Reactor with the `pap` plugin, its personal agent reaching Manzanita in process."""

    host = local_host(
        state,
        open_browser=False,
        address_resolver=network.resolve,
        http_factory=network.client,
        discover_plugins=False,
        plugins=[(PluginManifest(name="demo-clock", version="1"), ClockPlugin(clock))],
    )
    platform = PluginPlatform()
    platform.register_plugin(MANIFEST, PapCliPlugin(ConfigStore(state / "config.json"), host))
    return platform


@agent.tool_plain
async def run_live_session_actions() -> dict[str, Any]:
    """Run the safe actions, then try a destructive one; return answers and refusals."""

    clock = MutableClock()
    network = InProcessNetwork()
    manzanita(network, clock)
    with tempfile.TemporaryDirectory() as state:
        platform = _pap(Path(state), network, clock)
        company = await platform.execute_command("pap.company.discover", {"domain": DOMAIN})
        sessions = await platform.execute_command("pap.sessions.show")
        requirement = await platform.execute_command(
            "pap.requirements.show", {"requirement_id": "OPS-6-02"}
        )
        try:
            await platform.execute_command("pap.sessions.end", {"session_id": "ses_example"})
            refusal = "none"
        except PersonalAgentProtocolError as refused:
            refusal = refused.code
    return {
        "actions": {
            action.id: "needs the user's approval" if action.needs_approval else "read-only"
            for action in ACTIONS.values()
        },
        "company": {
            "organization": company["organization"],
            "verified": company["verified"],
            "sign_in": company["sign_in"],
        },
        "sessions_held": len(sessions["sessions"]),
        "requirement": {
            "id": requirement["requirement"]["id"],
            "level": requirement["requirement"]["level"],
        },
        "ending_a_session_without_approval": refusal,
    }


async def main() -> None:
    """Ask the agent what it may do in a live session."""

    result = await agent.run(
        "Which PAP actions can you run for Ada without asking her, and which need her approval?",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
