#!/usr/bin/env python3
"""Generate Docusaurus API inventories from the packages' public exports."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs" / "docs" / "sdk"
GITHUB = "https://github.com/datalayer/personal-agent-protocol/blob/main"


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    source: Path
    summary: str
    entry: str = "."


def first_line(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    return " ".join(value.strip().splitlines()[0].split())


def python_symbols() -> list[Symbol]:
    package = ROOT / "personal_agent_protocol"
    init = ast.parse((package / "__init__.py").read_text())
    imports: dict[str, Path] = {}
    exports: list[str] = []
    for node in init.body:
        if isinstance(node, ast.ImportFrom) and node.module:
            source = package / f"{node.module}.py"
            for alias in node.names:
                imports[alias.asname or alias.name] = source
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets
        ):
            exports = [item.value for item in node.value.elts if isinstance(item, ast.Constant)]  # type: ignore[union-attr]

    parsed: dict[Path, ast.Module] = {}
    symbols: list[Symbol] = []
    for name in exports:
        source = imports.get(name, package / "__init__.py")
        module = parsed.setdefault(source, ast.parse(source.read_text()))
        definition = next(
            (
                node
                for node in module.body
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == name
            ),
            None,
        )
        if isinstance(definition, ast.ClassDef):
            kind = "Class"
            summary = first_line(ast.get_docstring(definition), f"Public `{name}` class.")
        elif isinstance(definition, (ast.FunctionDef, ast.AsyncFunctionDef)):
            kind = "Function"
            summary = first_line(ast.get_docstring(definition), f"Public `{name}` function.")
        else:
            kind = "Constant"
            summary = f"Public `{name}` constant."
        symbols.append(Symbol(name, kind, source.relative_to(ROOT), summary))
    return sorted(symbols, key=lambda symbol: symbol.name.lower())


EXPORT_BLOCK = re.compile(r'export\s*\{(?P<body>.*?)\}\s*from\s*"(?P<module>.+?)";', re.S)


def typescript_symbols() -> list[Symbol]:
    source_root = ROOT / "packages" / "typescript" / "src"
    exported: list[tuple[str, str, Path, str]] = []

    def add_reexports(entry_file: Path, entry: str) -> str:
        text = entry_file.read_text()
        for match in EXPORT_BLOCK.finditer(text):
            source = source_root / match.group("module").removeprefix("./").replace(
                ".js", ".ts"
            )
            for raw in match.group("body").split(","):
                value = raw.strip()
                if not value:
                    continue
                is_type = value.startswith("type ")
                name = value.removeprefix("type ").split(" as ")[-1].strip()
                exported.append((name, "Type" if is_type else "Value", source, entry))
        return text

    add_reexports(source_root / "index.ts", ".")

    server = source_root / "server.ts"
    server_text = add_reexports(server, "./server")
    for match in re.finditer(
        r"^export\s+(?:declare\s+)?(class|function|interface|type|const)\s+([A-Za-z0-9_]+)",
        server_text,
        re.M,
    ):
        exported.append((match.group(2), match.group(1).title(), server, "./server"))

    parsed_sources = {source: source.read_text() for _, _, source, _ in exported}
    symbols: list[Symbol] = []
    for name, declared_kind, source, entry in exported:
        text = parsed_sources[source]
        definition = re.search(
            rf"^export\s+(?:declare\s+)?(class|function|interface|type|const)\s+{re.escape(name)}\b",
            text,
            re.M,
        )
        kind = definition.group(1).title() if definition else declared_kind
        summary = f"Public TypeScript {kind.lower()} `{name}`."
        if definition:
            prefix = text[: definition.start()]
            doc_start = prefix.rfind("/**")
            candidate = prefix[doc_start:] if doc_start >= 0 else ""
            doc = re.fullmatch(r"/\*\*(.*?)\*/\s*", candidate, re.S)
            if doc:
                cleaned = re.sub(r"^\s*\*\s?", "", doc.group(1), flags=re.M).strip()
                summary = first_line(cleaned, summary)
        symbols.append(Symbol(name, kind, source.relative_to(ROOT), summary, entry))
    return sorted(symbols, key=lambda symbol: (symbol.entry, symbol.name.lower()))


def render(title: str, symbols: list[Symbol], *, include_entry: bool = False) -> str:
    rows: list[str] = []
    for symbol in symbols:
        source = symbol.source.as_posix()
        details = symbol.kind
        if include_entry:
            details += f"; entry `{symbol.entry}`"
        rows.append(
            f"- [`{symbol.name}`]({GITHUB}/{source}) — {details}. {symbol.summary}"
        )
    return "\n".join(
        [
            "---",
            f"title: {title}",
            "---",
            "",
            "<!-- Generated by scripts/generate_api_reference.py; do not edit. -->",
            "",
            f"# {title}",
            "",
            "This inventory is generated from the package's public export surface.",
            "Unknown or internal symbols are deliberately excluded.",
            "",
            *rows,
            "",
        ]
    )


def write_or_check(path: Path, content: str, check: bool) -> bool:
    current = path.read_text() if path.exists() else None
    if current == content:
        return True
    if check:
        sys.stderr.write(f"stale generated API reference: {path.relative_to(ROOT)}\n")
        return False
    path.write_text(content)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    results = [
        write_or_check(
            DOCS / "python-api.mdx",
            render("Python API reference", python_symbols()),
            args.check,
        ),
        write_or_check(
            DOCS / "typescript-api.mdx",
            render("TypeScript API reference", typescript_symbols(), include_entry=True),
            args.check,
        ),
    ]
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
