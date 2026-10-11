# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The requirement ledger points only at code, tests, and cases that exist."""

from __future__ import annotations

import ast
import importlib
from functools import cache
from pathlib import Path

import pytest

from personal_agent_protocol.conformance import load_fixture_cases
from personal_agent_protocol.requirements import LEVELS, STATUSES, load_ledger

REPOSITORY = Path(__file__).parents[2]
LEDGER = load_ledger()


@cache
def _functions(path: Path) -> frozenset[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return frozenset(
        node.name for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def _resolves(reference: str) -> bool:
    module_name, _, qualified = reference.partition(":")
    value: object = importlib.import_module(module_name)
    for part in qualified.split("."):
        fields = getattr(value, "model_fields", None)
        if isinstance(fields, dict) and part in fields:
            return True  # a pydantic field: not a class attribute
        if not hasattr(value, part):
            return False
        value = getattr(value, part)
    return True


def test_the_ledger_is_well_formed() -> None:
    ids = [item.id for item in LEDGER.all()]
    assert len(ids) == len(set(ids)), "ledger IDs are unique"
    assert LEDGER.profile == "0.1"
    for item in LEDGER.all():
        assert item.level in LEVELS and item.status in STATUSES, item.id
        assert item.text.strip() and item.role in {"personal-agent", "company", "both"}, item.id
        if item.status == "implemented":
            assert item.tests, f"{item.id} is implemented but names no test"
        else:
            assert item.reason, f"{item.id} is {item.status} without a reason"
    assert {item.source for item in LEDGER.requirements} == {"spec", "operations"}
    assert {item.source for item in LEDGER.guide} == {"guide"}


def test_every_normative_keyword_of_the_text_is_its_level() -> None:
    for item in LEDGER.requirements:
        assert item.level in item.text, f"{item.id}: {item.level} is not in its own text"


@pytest.mark.parametrize("item", LEDGER.all(), ids=[item.id for item in LEDGER.all()])
def test_every_test_and_implementation_exists(item: object) -> None:
    for test in item.tests:  # type: ignore[attr-defined]
        path, _, name = test.partition("::")
        file = REPOSITORY / path
        assert file.is_file(), f"{test}: no such test file"
        assert name in _functions(file), f"{test}: no such test"
    for reference in item.implementation:  # type: ignore[attr-defined]
        assert _resolves(reference), f"{reference}: no such symbol"


def test_conformance_cases_and_requirements_point_at_each_other() -> None:
    cases = {case.id: case for case in load_fixture_cases()}
    known = {item.id for item in LEDGER.all()}
    for item in LEDGER.all():
        for case_id in item.conformance:
            assert case_id in cases, f"{item.id}: no fixture case {case_id}"
            assert item.id in cases[case_id].requirements, f"{case_id} does not name {item.id}"
    for case in cases.values():
        for requirement in case.requirements:
            assert requirement in known, f"{case.id} names unknown requirement {requirement}"


def test_selection_by_role_level_and_status() -> None:
    company_musts = LEDGER.select(role="company", level="MUST")
    assert company_musts and all(item.role in {"company", "both"} for item in company_musts)
    assert LEDGER.get("OPS-6-02").source == "operations"
    open_items = LEDGER.select(status="open")
    assert all(item.reason for item in open_items)
