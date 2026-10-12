# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The ``pap`` command: a thin Typer host extended by Reactor plugins.

Besides what plugins add, the host has one group of its own, ``pap commands``:
the live-session commands plugins registered in its Reactor (PAP's are the
`actions.ACTIONS`), listed and run by ID, as Studio's palette and a REPL run them.
"""

from __future__ import annotations

import asyncio
import json
import logging

import typer
from reactor import PluginPlatform  # type: ignore[import-untyped]
from reactor.cli import extend, load_platform  # type: ignore[import-untyped]

from .cli_commands import ExitCode, exit_code_for
from .errors import PersonalAgentProtocolError

ARGUMENTS = typer.Argument(None, help="Its arguments: values in order, or name=value.")


def commands_app(platform: PluginPlatform) -> typer.Typer:
    """`pap commands list|run`: the platform's registered commands, from a terminal."""

    app = typer.Typer(
        name="commands",
        help="List and run live-session commands (as Studio and a REPL run them).",
        no_args_is_help=True,
    )

    @app.command("list")
    def list_commands(
        json_output: bool = typer.Option(False, "--json", help="Print versioned JSON."),
    ) -> None:
        """Every registered command, with its plugin."""

        entries = platform.describe_commands()
        if json_output:
            typer.echo(json.dumps({"schema_version": 1, "commands": entries}, indent=2))
            return
        for entry in entries:
            typer.echo(f"{entry['id']:<28} {entry['name']}  ({entry['plugin']})")

    @app.command("run")
    def run_command(
        command_id: str = typer.Argument(..., help="The command's ID, e.g. pap.sessions.show."),
        arguments: list[str] | None = ARGUMENTS,
    ) -> None:
        """Run one command by ID and print its JSON answer.

        The same implementation Studio and a REPL invoke. A command that changes or
        ends what the user holds runs only where the host supplies an approval
        surface: here, use its own `pap` command instead (exit code 6).
        """

        try:
            result = asyncio.run(platform.execute_command(command_id, arguments or None))
        except KeyError as error:
            typer.secho(f"No command {command_id} is registered.", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=int(ExitCode.USAGE)) from error
        except PersonalAgentProtocolError as error:
            typer.secho(str(error), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=int(exit_code_for(error))) from error
        except RuntimeError as error:  # the command is unavailable right now
            typer.secho(str(error), fg=typer.colors.RED, err=True)
            raise typer.Exit(code=int(ExitCode.REFUSED)) from error
        if isinstance(result, dict):
            typer.echo(json.dumps(result, indent=2, sort_keys=True, default=str))
        elif result is not None:
            typer.echo(str(result))

    return app


def create_app(platform: PluginPlatform | None = None) -> typer.Typer:
    """Create a host and let installed Reactor extensions add every command."""

    if platform is None:
        platform = load_platform()
    app = typer.Typer(
        name="pap",
        help="Manage and inspect Personal Agent Protocol integrations.",
        no_args_is_help=True,
        add_completion=True,
    )
    extend(app, platform)
    app.add_typer(commands_app(platform))
    return app


def main() -> None:
    """Run the extensible PAP command line."""

    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    create_app()()


if __name__ == "__main__":
    main()
