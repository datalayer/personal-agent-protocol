# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The normative requirement ledger (`protocol/requirements.yaml`) and shared fixtures.

Every MUST, MUST NOT, SHOULD, and SHOULD NOT of draft 0.3 and its extensions
has one entry: its section, level, role, exact text, where it is implemented
(`module:symbol`), and the test that shows it (`file::name`), or an `open`
status with the reason. Recommendations from the upstream guides are kept
apart (`source: guide`).

The ledger and the conformance fixtures ship inside the wheel
(`personal_agent_protocol/protocol/`); in a source checkout they are read from
the repository's `protocol/` directory.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any, Literal

import yaml  # type: ignore[import-untyped]

Level = Literal["MUST", "MUST NOT", "SHOULD", "SHOULD NOT"]
Source = Literal["spec", "operations", "mediated", "guide"]
Status = Literal["implemented", "partial", "open", "not-applicable"]

LEVELS: tuple[Level, ...] = ("MUST", "MUST NOT", "SHOULD", "SHOULD NOT")
STATUSES: tuple[Status, ...] = ("implemented", "partial", "open", "not-applicable")


def protocol_path(*parts: str) -> Path:
    """A file under the protocol assets: in the wheel, or in the source checkout."""

    package = Path(__file__).resolve().parent
    for root in (package / "protocol", package.parent / "protocol"):
        if root.is_dir():
            return root.joinpath(*parts)
    raise FileNotFoundError("the PAP protocol assets (requirements, fixtures) are not installed")


@dataclass(frozen=True)
class Requirement:
    """One normative statement and how this SDK meets it."""

    id: str
    source: Source
    section: str
    level: Level
    role: str
    text: str
    status: Status
    implementation: tuple[str, ...] = ()
    tests: tuple[str, ...] = ()
    conformance: tuple[str, ...] = ()
    reason: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "id": self.id,
            "source": self.source,
            "section": self.section,
            "level": self.level,
            "role": self.role,
            "text": self.text,
            "status": self.status,
            "implementation": list(self.implementation),
            "tests": list(self.tests),
            "conformance": list(self.conformance),
        }
        if self.reason:
            value["reason"] = self.reason
        return value


@dataclass(frozen=True)
class Ledger:
    """The ledger's header and its entries, normative and guide."""

    protocol: str
    profile: str
    upstream_revision: str
    requirements: tuple[Requirement, ...]
    guide: tuple[Requirement, ...]

    def all(self) -> tuple[Requirement, ...]:
        return self.requirements + self.guide

    def get(self, requirement_id: str) -> Requirement:
        for item in self.all():
            if item.id == requirement_id:
                return item
        raise KeyError(requirement_id)

    def select(
        self,
        *,
        role: str | None = None,
        level: str | None = None,
        status: str | None = None,
        source: str | None = None,
        ids: Iterable[str] = (),
    ) -> tuple[Requirement, ...]:
        wanted = frozenset(ids)
        return tuple(
            item
            for item in self.all()
            if (role is None or item.role in {role, "both"})
            and (level is None or item.level == level)
            and (status is None or item.status == status)
            and (source is None or item.source == source)
            and (not wanted or item.id in wanted)
        )


def _strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return tuple(value)
    raise ValueError("expected a string or a list of strings")


def _entry(raw: object, default_source: Source) -> Requirement:
    if not isinstance(raw, dict):
        raise ValueError("a ledger entry must be a mapping")
    known = {
        "id",
        "source",
        "section",
        "level",
        "role",
        "text",
        "status",
        "implementation",
        "test",
        "tests",
        "conformance",
        "reason",
    }
    level = raw.get("level")
    status = raw.get("status")
    if level not in LEVELS:
        raise ValueError(f"{raw.get('id')}: level must be one of {LEVELS}")
    if status not in STATUSES:
        raise ValueError(f"{raw.get('id')}: status must be one of {STATUSES}")
    return Requirement(
        id=str(raw["id"]),
        source=raw.get("source", default_source),
        section=str(raw["section"]),
        level=level,
        role=str(raw["role"]),
        text=str(raw["text"]),
        status=status,
        implementation=_strings(raw.get("implementation")),
        tests=_strings(raw.get("tests", raw.get("test"))),
        conformance=_strings(raw.get("conformance")),
        reason=raw.get("reason"),
        extra={key: value for key, value in raw.items() if key not in known},
    )


def parse_ledger(document: object) -> Ledger:
    if not isinstance(document, dict):
        raise ValueError("the ledger must be a mapping")
    return Ledger(
        protocol=str(document["protocol"]),
        profile=str(document["profile"]),
        upstream_revision=str(document["upstream_revision"]),
        requirements=tuple(_entry(item, "spec") for item in document.get("requirements", [])),
        guide=tuple(_entry(item, "guide") for item in document.get("guide", [])),
    )


@cache
def load_ledger(path: Path | None = None) -> Ledger:
    """Read the ledger shipped with this SDK (or one at `path`)."""

    source = path or protocol_path("requirements.yaml")
    return parse_ledger(yaml.safe_load(source.read_text(encoding="utf-8")))
