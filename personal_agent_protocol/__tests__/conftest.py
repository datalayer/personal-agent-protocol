# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Pytest configuration for personal-agent-protocol tests."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator

import pytest


@pytest.fixture(scope="session", autouse=True)
def _a_closed_current_loop() -> Iterator[None]:
    """Own the loop pytest-asyncio finds current, and close it at the end.

    pytest-asyncio asks for the current loop around each async test and, when
    there is none, the policy creates one that nothing closes. A later
    `asyncio.run` (the CLI surface) replaces it and the orphan is collected
    unclosed in whichever test runs then: a ResourceWarning, an error under
    `filterwarnings = error`, that depended on test order.
    """

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        yield
    finally:
        asyncio.set_event_loop(None)
        loop.close()
