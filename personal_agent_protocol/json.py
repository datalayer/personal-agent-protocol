# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Strict JSON helpers used at protocol trust boundaries."""

from __future__ import annotations

import json
from typing import Any

from .errors import ProtocolValidationError


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolValidationError(
                "duplicate_json_member",
                f"JSON object contains duplicate member {key!r}",
            )
        result[key] = value
    return result


def loads_strict(value: str | bytes) -> Any:
    """Decode JSON while rejecting duplicate object member names."""

    try:
        return json.loads(value, object_pairs_hook=_unique_object)
    except ProtocolValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolValidationError("invalid_json", "Response is not valid JSON") from exc
