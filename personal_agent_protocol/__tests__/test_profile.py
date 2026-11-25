# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Both SDKs, and what the repository says, name the same PAP draft and Operations version.

The TypeScript SDK's constants are read from its source here, and
`src/__tests__/profile.test.mjs` reads Python's, so either side changing alone fails.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from personal_agent_protocol import OPERATIONS_VERSION, PROTOCOL_PROFILE, PROTOCOL_REVISION

ROOT = Path(__file__).parents[2]
STATEMENT = (
    f"{PROTOCOL_PROFILE} ({PROTOCOL_REVISION}) and its Operations extension v{OPERATIONS_VERSION}"
)


def _typescript(path: str, name: str) -> str:
    match = re.search(rf'export const {name} = "([^"]+)";', (ROOT / path).read_text())
    assert match is not None, f"{path} exports no {name}"
    return match[1]


def test_the_typescript_sdk_declares_the_same_profile_and_operations_version() -> None:
    assert _typescript("src/profile.ts", "PROTOCOL_PROFILE") == PROTOCOL_PROFILE == "0.4"
    assert _typescript("src/profile.ts", "PROTOCOL_REVISION") == PROTOCOL_REVISION
    assert _typescript("src/operations.ts", "OPERATIONS_VERSION") == OPERATIONS_VERSION == "3"


def test_the_requirement_ledger_and_the_upstream_snapshot_say_the_same() -> None:
    ledger = yaml.safe_load((ROOT / "protocol" / "requirements.yaml").read_text())
    assert (ledger["profile"], ledger["upstream_revision"]) == (PROTOCOL_PROFILE, PROTOCOL_REVISION)
    upstream = (ROOT / "protocol" / "UPSTREAM.md").read_text()
    assert f"- Profile implemented: {PROTOCOL_PROFILE} as published\n" in upstream
    assert f"- Upstream page revision: {PROTOCOL_REVISION}\n" in upstream
    assert f"- Operations extension: version {OPERATIONS_VERSION}\n" in upstream


def test_the_packages_and_the_docs_state_it() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text()
    package = json.loads((ROOT / "package.json").read_text())
    assert f'description = "Python SDK for Personal Agent Protocol {STATEMENT}"\n' in pyproject
    assert package["description"] == f"TypeScript SDK for Personal Agent Protocol {STATEMENT}"
    readme = " ".join((ROOT / "README.md").read_text().split())
    # Published: frozen at /docs/{version}/spec (/docs/spec is the next draft).
    spec = f"https://personalagentprotocol.org/docs/{PROTOCOL_PROFILE}/spec"
    assert f"version {PROTOCOL_PROFILE}]({spec}) ({PROTOCOL_REVISION})" in readme
    assert f"Operations extension v{OPERATIONS_VERSION}" in readme
    docs = ROOT / "docs" / "docs"
    compatibility = (docs / "releases" / "compatibility.mdx").read_text()
    for python, typescript in (
        (
            f"`PROTOCOL_PROFILE` = `{PROTOCOL_PROFILE}`",
            f'`PROTOCOL_PROFILE` = `"{PROTOCOL_PROFILE}"`',
        ),
        (
            f"`PROTOCOL_REVISION` = `{PROTOCOL_REVISION}`",
            f'`PROTOCOL_REVISION` = `"{PROTOCOL_REVISION}"`',
        ),
        (
            f"`OPERATIONS_VERSION` = `{OPERATIONS_VERSION}`",
            f'`OPERATIONS_VERSION` = `"{OPERATIONS_VERSION}"`',
        ),
    ):
        assert python in compatibility and typescript in compatibility
    report = (docs / "protocol" / "conformance-report.mdx").read_text()
    assert (
        f"PAP profile **{PROTOCOL_PROFILE}** (as published {PROTOCOL_REVISION}), "
        f"Operations extension **v{OPERATIONS_VERSION}**"
    ) in report


def _npm_version(version: str) -> str:
    """A Python version as npm writes it: `1.1.0a1` is `1.1.0-alpha.1` (PEP 440, semver)."""

    match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:(a|b|rc)(\d+))?", version)
    assert match is not None, f"{version} is no release or pre-release version"
    if match[2] is None:
        return match[1]
    return f"{match[1]}-{ {'a': 'alpha', 'b': 'beta', 'rc': 'rc'}[match[2]] }.{match[3]}"


def test_the_docs_are_versioned_with_the_release() -> None:
    from personal_agent_protocol.__version__ import __version__

    docs = ROOT / "docs" / "docs"
    npm = _npm_version(__version__)
    assert json.loads((ROOT / "package.json").read_text())["version"] == npm
    compatibility = (docs / "releases" / "compatibility.mdx").read_text()
    assert f"| `{__version__}` | `{PROTOCOL_PROFILE}` | {PROTOCOL_REVISION} |" in compatibility
    if npm == __version__:
        assert f"it describes **SDK {__version__}**." in compatibility
        minor = ".".join(__version__.split(".")[:2])
        assert f"| `{minor}.x` | Yes" in (docs / "releases" / "support.mdx").read_text()
    else:
        # A pre-release: the page keeps describing the stable release, and says what the
        # pre-release is, by both registries' names for it.
        assert f"pre-release **{__version__}** (npm `{npm}`)" in compatibility
        assert "it describes **SDK " in compatibility
        assert f"it describes **SDK {__version__}**." not in compatibility
    for manifest, version in (
        ("personal_agent_protocol/reactor.py", __version__),
        ("personal_agent_protocol/company/__init__.py", __version__),
        ("src/reactor.ts", npm),
        ("src/company/index.ts", npm),
    ):
        assert re.search(rf'version[=:] ?"{re.escape(version)}"', (ROOT / manifest).read_text())
    changelog = (ROOT / "CHANGELOG.md").read_text()
    assert f"## {__version__} (" in changelog
    assert (
        f"SDK version **{__version__}**"
        in (docs / "protocol" / "conformance-report.mdx").read_text()
    )
