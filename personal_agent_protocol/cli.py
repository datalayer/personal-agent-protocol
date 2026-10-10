# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The ``pap`` command: a thin Typer host extended by Reactor plugins."""

from __future__ import annotations

import logging

import typer
from reactor import PluginPlatform  # type: ignore[import-untyped]
from reactor.cli import extend  # type: ignore[import-untyped]


def create_app(platform: PluginPlatform | None = None) -> typer.Typer:
    """Create a host and let installed Reactor extensions add every command."""

    app = typer.Typer(
        name="pap",
        help="Manage and inspect Personal Agent Protocol integrations.",
        no_args_is_help=True,
        add_completion=True,
    )
    extend(app, platform)
    return app


def main() -> None:
    """Run the extensible PAP command line."""

    logging.basicConfig(level=logging.WARNING, format="%(message)s")
    create_app()()


if __name__ == "__main__":
    main()
