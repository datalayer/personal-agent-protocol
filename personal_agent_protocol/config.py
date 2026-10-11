# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Non-secret, profile-aware configuration for the PAP CLI."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .json import loads_strict

CONFIG_KEYS: Final = frozenset(
    {"domain", "client_id", "issuer", "output", "store_provider", "tenant", "timeout"}
)
ENVIRONMENT_KEYS: Final = {key: f"PAP_{key.upper()}" for key in CONFIG_KEYS}


def default_config_path() -> Path:
    """Return the XDG configuration path without creating it."""

    root = os.environ.get("XDG_CONFIG_HOME")
    base = Path(root).expanduser() if root else Path.home() / ".config"
    return base / "pap" / "config.json"


@dataclass(frozen=True)
class EffectiveValue:
    """One resolved setting and where it came from."""

    value: object
    source: str


class ConfigStore:
    """Read and atomically update non-secret named profiles."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_config_path()

    def read(self) -> dict[str, object]:
        if not self.path.exists():
            return {"default_profile": "default", "profiles": {}}
        value = loads_strict(self.path.read_bytes())
        if not isinstance(value, dict):
            raise ValueError("PAP configuration must be a JSON object")
        profiles = value.get("profiles", {})
        if not isinstance(profiles, dict):
            raise ValueError("PAP configuration profiles must be an object")
        return value

    def profiles(self) -> tuple[str, ...]:
        profiles = self._profiles(self.read())
        return tuple(sorted(str(name) for name in profiles))

    def default_profile(self) -> str:
        configured = self.read().get("default_profile", "default")
        return os.environ.get("PAP_PROFILE", str(configured))

    def resolve(self, profile: str | None = None) -> dict[str, EffectiveValue]:
        selected = profile or self.default_profile()
        document = self.read()
        profiles = self._profiles(document)
        stored = profiles.get(selected, {})
        if not isinstance(stored, dict):
            raise ValueError(f"PAP profile {selected!r} must be an object")
        result: dict[str, EffectiveValue] = {}
        for key in sorted(CONFIG_KEYS):
            environment = ENVIRONMENT_KEYS[key]
            if environment in os.environ:
                result[key] = EffectiveValue(os.environ[environment], f"env:{environment}")
            elif key in stored:
                result[key] = EffectiveValue(stored[key], f"profile:{selected}")
        return result

    def set(self, profile: str, key: str, value: object) -> None:
        self._validate_key(key)
        document = self.read()
        profiles = self._profiles(document)
        current = profiles.setdefault(profile, {})
        if not isinstance(current, dict):
            raise ValueError(f"PAP profile {profile!r} must be an object")
        current[key] = value
        self._write(document)

    def unset(self, profile: str, key: str) -> bool:
        self._validate_key(key)
        document = self.read()
        profiles = self._profiles(document)
        current = profiles.get(profile, {})
        if not isinstance(current, dict) or key not in current:
            return False
        del current[key]
        self._write(document)
        return True

    @staticmethod
    def _validate_key(key: str) -> None:
        if key not in CONFIG_KEYS:
            allowed = ", ".join(sorted(CONFIG_KEYS))
            raise ValueError(f"Unknown configuration key {key!r}; choose one of: {allowed}")

    @staticmethod
    def _profiles(document: dict[str, object]) -> dict[str, object]:
        profiles = document.setdefault("profiles", {})
        if not isinstance(profiles, dict):
            raise ValueError("PAP configuration profiles must be an object")
        return profiles

    def _write(self, document: dict[str, object]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=".config-",
            suffix=".json",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(document, stream, indent=2, sort_keys=True)
                stream.write("\n")
            os.chmod(temporary, 0o600)
            temporary.replace(self.path)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
