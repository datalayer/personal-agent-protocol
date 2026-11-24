# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A URL the SDK accepts is one a browser reads the same way (reported on 1.0.1)."""

from __future__ import annotations

from pathlib import Path

import pytest

from personal_agent_protocol.urls import browser_safe

PACKAGE = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "url",
    [
        "https://company.example/device",
        "https://login.company.example:8443/device?code=WDJB-MJHT#top",
        "https://company.example/a%20b/c",  # percent-encoding in the path is read alike
        "https://[2001:db8::1]/device",
        "http://127.0.0.1:8765/callback",
        # Non-ASCII in a query: a browser percent-encodes it, on the same host.
        "https://company.example/events?wait=\u0661",
    ],
)
def test_a_uri_is_read_alike(url: str) -> None:
    assert browser_safe(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://v.example\\.m.example/../device",
        "https://v.example\\@m.example/device",
        "https://v.example/\\device",
        "https://v.example\t.m.example/device",
        "https://v.example\n.m.example/device",
        "https://v.example\r.m.example/device",
        " https://m.example/device",
        "https://m.example/device ",
        "https://m.example/device\x00",
        "https://v.example%2e.m.example/device",
        "https://v.example%2fm.example/device",
        "https://v.example\uff0em.example/device",
        "https://v.example\u00a0.m.example/device",
        "https://user%40m.example@v.example/",
        "",
    ],
)
def test_a_url_a_browser_reads_otherwise_is_not(url: str) -> None:
    assert not browser_safe(url)


def test_every_https_check_of_the_sdk_asks_it_first() -> None:
    """Each place that accepts an HTTPS URL checks it is read alike before reading its host."""

    places = {
        "auth.py": "not browser_safe(value)",
        "browser.py": "not browser_safe(value)",
        "transport.py": "not browser_safe(value)",
        "crypto.py": "not browser_safe(value)",
        "models.py": "not browser_safe(value)",
        "sessions.py": "not browser_safe(value)",
        "pages.py": "not browser_safe(url)",
        "reactor.py": "not browser_safe(url)",
        "operations.py": "not browser_safe(endpoint)",
        "mcp.py": "not browser_safe(url)",
        "pairwise.py": "not browser_safe(value)",
        "ui.py": "not browser_safe(value)",
        "conformance.py": "not browser_safe(base_url)",
        "company/service.py": "not browser_safe(",
    }
    for name, check in places.items():
        assert check in (PACKAGE / name).read_text(), name
