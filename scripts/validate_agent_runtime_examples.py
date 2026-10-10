# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""Build every Agent Runtimes PAP example and reject duplicate app/tool IDs."""

from __future__ import annotations

from pathlib import Path

from agent_runtimes.loop.apps.build import build

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples" / "agent-runtimes"


def main() -> int:
    app_ids: set[str] = set()
    tool_names: set[tuple[str, str]] = set()
    paths = sorted(EXAMPLES.glob("*/app.py"))
    if not paths:
        raise RuntimeError("No Agent Runtimes PAP examples were found")
    for path in paths:
        built = build(str(path))
        app_id = built.application.spec.id
        if app_id in app_ids:
            raise RuntimeError(f"Duplicate example application id: {app_id}")
        app_ids.add(app_id)
        for tool in built.application.spec.tools:
            key = (app_id, tool.name)
            if key in tool_names:
                raise RuntimeError(f"Duplicate example tool: {app_id}/{tool.name}")
            tool_names.add(key)
        print(f"{path.relative_to(ROOT)}: {app_id} ({len(built.application.spec.tools)} tool)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
