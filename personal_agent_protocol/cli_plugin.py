# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Reactor extension contributing PAP command-line and session commands."""

from __future__ import annotations

import asyncio
import json
import math
from typing import Any

import typer
from reactor import PluginManifest  # type: ignore[import-untyped]

from .__version__ import __version__
from .config import CONFIG_KEYS, ConfigStore
from .discovery import DiscoveryClient
from .errors import PersonalAgentProtocolError

MANIFEST = PluginManifest(
    name="personal-agent-protocol.cli",
    version=__version__,
    description="Personal Agent Protocol command-line tools.",
    author="Datalayer",
    tags=["pap", "cli"],
)


def _json(value: object) -> None:
    typer.echo(json.dumps(value, indent=2, sort_keys=True, default=str))


def _extension_versions(payload: dict[str, object]) -> dict[str, object]:
    extensions = payload.get("extensions")
    if not isinstance(extensions, dict):
        raise ValueError("discovery summary has invalid extensions")
    return extensions


async def discover_company(domain: str) -> dict[str, object]:
    """Return a stable, non-secret discovery summary."""

    async with DiscoveryClient() as client:
        company = await client.discover(domain)
    document = company.document
    metadata = company.oauth_metadata
    return {
        "schema_version": 1,
        "verified": metadata is not None,
        "domain": document.organization.domain,
        "organization": document.organization.name,
        "protocol_version": document.protocol_version,
        "issuer": metadata.issuer if metadata else None,
        "sign_in": [
            name
            for name in ("direct", "device", "mediated")
            if document.auth is not None and getattr(document.auth, name) is not None
        ],
        "apis": [item.type for item in document.apis],
        "conversation_protocols": (
            [item.type for item in document.agent.protocols] if document.agent else []
        ),
        "web": document.web is not None,
        "extensions": {
            name: item.version for name, item in sorted(document.extensions.items())
        },
    }


def _run_discovery(domain: str) -> dict[str, object]:
    """Run discovery behind the CLI's redacted error boundary."""

    try:
        return asyncio.run(discover_company(domain))
    except PersonalAgentProtocolError as error:
        typer.secho(str(error), fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from error


class PapCliPlugin:
    """Add PAP-owned groups to a CLI and safe actions to live sessions."""

    def __init__(self, config: ConfigStore | None = None) -> None:
        self.config = config or ConfigStore()

    def provide_cli(self, cli: typer.Typer) -> None:
        cli.add_typer(self._config_app())
        cli.add_typer(self._company_app())
        cli.add_typer(self._extensions_app())

    def provide_slash_commands(self, commands: Any) -> None:
        commands.add(
            "pap.company.discover",
            "Discover PAP company",
            discover_company,
            description="Discover and verify one PAP company domain.",
            emoji="🔎",
            category="Personal Agent Protocol",
        )

    def _config_app(self) -> typer.Typer:  # noqa: C901 - Typer handlers stay with their group
        app = typer.Typer(name="config", help="Manage non-secret PAP CLI profiles.")

        @app.command("show")
        def show(
            profile: str | None = typer.Option(None, "--profile"),
            json_output: bool = typer.Option(False, "--json"),
        ) -> None:
            """Show effective settings and their provenance."""

            selected = profile or self.config.default_profile()
            values = self.config.resolve(selected)
            payload = {
                "schema_version": 1,
                "profile": selected,
                "values": {
                    key: {"value": item.value, "source": item.source}
                    for key, item in values.items()
                },
            }
            if json_output:
                _json(payload)
                return
            typer.echo(f"Profile: {selected}")
            for key, item in values.items():
                typer.echo(f"{key}={item.value}  ({item.source})")

        @app.command("get")
        def get(
            key: str = typer.Argument(...),
            profile: str | None = typer.Option(None, "--profile"),
        ) -> None:
            """Read one effective setting."""

            if key not in CONFIG_KEYS:
                raise typer.BadParameter("unknown or secret configuration key")
            value = self.config.resolve(profile).get(key)
            if value is None:
                raise typer.Exit(code=1)
            typer.echo(value.value)

        @app.command("set")
        def set_value(
            key: str = typer.Argument(...),
            value: str = typer.Argument(...),
            profile: str = typer.Option("default", "--profile"),
        ) -> None:
            """Set one non-secret profile value."""

            try:
                if key == "timeout":
                    timeout = float(value)
                    if not math.isfinite(timeout) or timeout <= 0:
                        raise ValueError("timeout must be a positive finite number")
                    parsed: object = timeout
                else:
                    parsed = value
                self.config.set(profile, key, parsed)
            except ValueError as error:
                raise typer.BadParameter(str(error)) from error
            typer.echo(f"Set {key} in profile {profile}.")

        @app.command("unset")
        def unset(
            key: str = typer.Argument(...),
            profile: str = typer.Option("default", "--profile"),
        ) -> None:
            """Remove one profile value."""

            try:
                removed = self.config.unset(profile, key)
            except ValueError as error:
                raise typer.BadParameter(str(error)) from error
            if not removed:
                raise typer.Exit(code=1)
            typer.echo(f"Unset {key} in profile {profile}.")

        @app.command("profiles")
        def profiles() -> None:
            """List configured profiles."""

            for name in self.config.profiles():
                typer.echo(name)

        return app

    def _company_app(self) -> typer.Typer:
        app = typer.Typer(name="company", help="Discover and verify PAP companies.")

        def run(domain: str | None, profile: str | None, json_output: bool) -> None:
            configured = self.config.resolve(profile)
            selected = domain or (
                str(configured["domain"].value) if "domain" in configured else None
            )
            if not selected:
                raise typer.BadParameter("provide DOMAIN or configure domain")
            payload = _run_discovery(selected)
            if json_output:
                _json(payload)
                return
            mark = "verified" if payload["verified"] else "signed-out website only"
            typer.echo(f"{payload['organization']} ({payload['domain']}): {mark}")
            typer.echo(f"PAP {payload['protocol_version']} · issuer {payload['issuer'] or 'none'}")

        @app.command("discover")
        def discover(
            domain: str | None = typer.Argument(None),
            profile: str | None = typer.Option(None, "--profile"),
            json_output: bool = typer.Option(False, "--json"),
        ) -> None:
            """Discover one company's PAP declaration."""

            run(domain, profile, json_output)

        @app.command("verify")
        def verify(
            domain: str | None = typer.Argument(None),
            profile: str | None = typer.Option(None, "--profile"),
            json_output: bool = typer.Option(False, "--json"),
        ) -> None:
            """Verify discovery, organization domain, and OAuth issuer binding."""

            run(domain, profile, json_output)

        return app

    def _extensions_app(self) -> typer.Typer:
        app = typer.Typer(name="extensions", help="Inspect PAP extension negotiation.")

        @app.command("list")
        def list_extensions(
            domain: str | None = typer.Argument(None),
            profile: str | None = typer.Option(None, "--profile"),
            json_output: bool = typer.Option(False, "--json"),
        ) -> None:
            """List extensions advertised by a verified company."""

            configured = self.config.resolve(profile)
            selected = domain or (
                str(configured["domain"].value) if "domain" in configured else None
            )
            if not selected:
                raise typer.BadParameter("provide DOMAIN or configure domain")
            payload = _run_discovery(selected)
            extensions = _extension_versions(payload)
            if json_output:
                _json({"schema_version": 1, "domain": selected, "extensions": extensions})
                return
            for name, version in extensions.items():
                typer.echo(f"{name} v{version}")

        @app.command("check")
        def check_extension(
            name: str = typer.Argument(...),
            version: str = typer.Option(..., "--version"),
            domain: str | None = typer.Argument(None),
            profile: str | None = typer.Option(None, "--profile"),
        ) -> None:
            """Require one advertised extension major version."""

            configured = self.config.resolve(profile)
            selected = domain or (
                str(configured["domain"].value) if "domain" in configured else None
            )
            if not selected:
                raise typer.BadParameter("provide DOMAIN or configure domain")
            payload = _run_discovery(selected)
            extensions = _extension_versions(payload)
            if extensions.get(name) != version:
                raise typer.Exit(code=1)
            typer.echo(f"{name} v{version} is supported by {selected}.")

        return app


def plugin() -> tuple[PluginManifest, PapCliPlugin]:
    """Entry-point factory used by Reactor discovery."""

    return MANIFEST, PapCliPlugin()
