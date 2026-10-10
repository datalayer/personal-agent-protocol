# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import typer
from reactor import PluginPlatform  # type: ignore[import-untyped]
from typer.testing import CliRunner

from personal_agent_protocol.cli import create_app
from personal_agent_protocol.cli_plugin import MANIFEST, PapCliPlugin
from personal_agent_protocol.config import ConfigStore
from personal_agent_protocol.errors import DiscoveryError


def cli(tmp_path: Path) -> tuple[CliRunner, typer.Typer, ConfigStore, PluginPlatform]:
    store = ConfigStore(tmp_path / "pap" / "config.json")
    platform = PluginPlatform()
    platform.register_plugin(MANIFEST, PapCliPlugin(store))
    return CliRunner(), create_app(platform), store, platform


def test_reactor_extension_adds_groups_to_thin_host(tmp_path: Path) -> None:
    runner, app, _, _ = cli(tmp_path)

    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "company" in result.stdout
    assert "agent" in result.stdout
    assert "config" in result.stdout
    assert "extensions" in result.stdout


def test_plugin_command_groups_are_independently_testable(tmp_path: Path) -> None:
    app = typer.Typer(no_args_is_help=True)
    PapCliPlugin(ConfigStore(tmp_path / "pap" / "config.json")).provide_cli(app)

    result = CliRunner().invoke(app, ["config", "profiles"])

    assert result.exit_code == 0


def test_config_profiles_are_atomic_non_secret_and_show_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner, app, store, _ = cli(tmp_path)

    assert runner.invoke(app, ["config", "set", "domain", "example.com"]).exit_code == 0
    assert runner.invoke(app, ["config", "set", "timeout", "4.5"]).exit_code == 0
    monkeypatch.setenv("PAP_OUTPUT", "json")
    result = runner.invoke(app, ["config", "show", "--json"])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["values"]["domain"] == {
        "source": "profile:default",
        "value": "example.com",
    }
    assert payload["values"]["output"] == {"source": "env:PAP_OUTPUT", "value": "json"}
    assert store.path.stat().st_mode & 0o777 == 0o600
    assert runner.invoke(app, ["config", "set", "password", "secret"]).exit_code == 2
    assert "secret" not in store.path.read_text()


def test_config_profiles_list_and_unset(tmp_path: Path) -> None:
    runner, app, _, _ = cli(tmp_path)

    assert (
        runner.invoke(
            app,
            ["config", "set", "domain", "example.com", "--profile", "work"],
        ).exit_code
        == 0
    )
    listed = runner.invoke(app, ["config", "profiles"])
    removed = runner.invoke(
        app,
        ["config", "unset", "domain", "--profile", "work"],
    )

    assert listed.stdout.strip() == "work"
    assert removed.exit_code == 0
    assert runner.invoke(app, ["config", "get", "domain", "--profile", "work"]).exit_code == 1


def test_company_commands_emit_stable_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_discover(domain: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "verified": True,
            "domain": domain,
            "organization": "Example Company",
            "protocol_version": "0.1",
            "issuer": "https://auth.example.com",
            "sign_in": ["direct"],
            "apis": ["openapi"],
            "conversation_protocols": ["poppy"],
            "web": False,
            "extensions": {"operations": "1"},
        }

    monkeypatch.setattr(
        "personal_agent_protocol.cli_plugin.discover_company",
        fake_discover,
    )
    runner, app, _, _ = cli(tmp_path)

    result = runner.invoke(app, ["company", "verify", "example.com", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["schema_version"] == 1
    assert json.loads(result.stdout)["issuer"] == "https://auth.example.com"


def test_agent_commands_use_profile_and_emit_stable_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_metadata(client_id: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "client_id": client_id,
            "client_name": "Example Agent",
            "jwks_uri": "https://agent.example/jwks.json",
            "redirect_uris": [],
        }

    async def fake_jwks(client_id: str) -> dict[str, object]:
        return {
            "schema_version": 1,
            "client_id": client_id,
            "keys": [{"kid": "key-1", "kty": "EC", "alg": "ES256"}],
        }

    monkeypatch.setattr("personal_agent_protocol.cli_plugin.inspect_agent_metadata", fake_metadata)
    monkeypatch.setattr("personal_agent_protocol.cli_plugin.inspect_agent_jwks", fake_jwks)
    runner, app, _, _ = cli(tmp_path)
    assert (
        runner.invoke(
            app,
            ["config", "set", "client_id", "https://agent.example/agent.json"],
        ).exit_code
        == 0
    )

    metadata = runner.invoke(app, ["agent", "metadata", "--json"])
    jwks = runner.invoke(app, ["agent", "jwks", "--json"])

    assert metadata.exit_code == 0
    assert json.loads(metadata.stdout)["client_name"] == "Example Agent"
    assert jwks.exit_code == 0
    assert json.loads(jwks.stdout)["keys"][0]["kid"] == "key-1"


@pytest.mark.parametrize(
    "arguments",
    [
        ["company", "discover", "example.com"],
        ["extensions", "list", "example.com"],
        ["extensions", "check", "operations", "--version", "1", "example.com"],
    ],
)
def test_network_commands_redact_discovery_error_details(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arguments: list[str],
) -> None:
    async def fail_discovery(domain: str) -> dict[str, object]:
        del domain
        raise DiscoveryError(
            "discovery_failed",
            "The company could not be verified.",
            details={"response_body": "account-token-secret"},
        )

    monkeypatch.setattr(
        "personal_agent_protocol.cli_plugin.discover_company",
        fail_discovery,
    )
    runner, app, _, _ = cli(tmp_path)

    result = runner.invoke(app, arguments)

    assert result.exit_code == 1
    assert "discovery_failed: The company could not be verified." in result.output
    assert "account-token-secret" not in result.output


def test_namespaced_session_command_follows_plugin_lifecycle(tmp_path: Path) -> None:
    _, _, _, platform = cli(tmp_path)

    assert [command.id for command in platform.list_commands()] == ["pap.company.discover"]
    platform.disable_plugin(MANIFEST.name)
    assert platform.list_commands() == []
    platform.enable_plugin(MANIFEST.name)
    assert [command.id for command in platform.list_commands()] == ["pap.company.discover"]
    platform.unregister_plugin(MANIFEST.name)
    assert platform.list_commands() == []


def test_distribution_declares_console_script_and_reactor_entry_point() -> None:
    project = (Path(__file__).parents[2] / "pyproject.toml").read_text()

    assert '[project.scripts]\npap = "personal_agent_protocol.cli:main"' in project
    assert '[project.entry-points."datalayer.reactor.cli"]' in project
    assert 'pap = "personal_agent_protocol.cli_plugin:plugin"' in project


def test_command_collision_keeps_original_owner(tmp_path: Path) -> None:
    class ClashingPlugin:
        def provide_slash_commands(self, commands: Any) -> None:
            commands.add(
                "pap.company.discover",
                "Unsafe duplicate",
                lambda: None,
            )

    _, _, _, platform = cli(tmp_path)
    platform.register_plugin(
        type(MANIFEST)(name="example.clash", version="1.0.0"),
        ClashingPlugin(),
    )

    described = platform.describe_commands()
    assert len(described) == 1
    assert described[0]["id"] == "pap.company.discover"
    assert described[0]["plugin"] == MANIFEST.name
