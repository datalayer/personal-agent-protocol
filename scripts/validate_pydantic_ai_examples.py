# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""Import every Pydantic AI example without invoking a model."""

from __future__ import annotations

import runpy
import sys
from pathlib import Path

from pydantic_ai import Agent

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples" / "pydantic-ai"


def main() -> int:
    """Require every example to expose one Pydantic AI agent."""

    paths = sorted(EXAMPLES.glob("*/app.py"))
    if not paths:
        raise RuntimeError("No Pydantic AI examples were found")
    for path in paths:
        namespace = runpy.run_path(str(path), run_name="pap_example_validation")
        if not isinstance(namespace.get("agent"), Agent):
            raise RuntimeError(f"{path.relative_to(ROOT)} does not expose an Agent")
        sys.stdout.write(f"{path.relative_to(ROOT)}: Pydantic AI agent\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
