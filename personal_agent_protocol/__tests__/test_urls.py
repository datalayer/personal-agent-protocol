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


# --- the review of 1.0.2 -------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://0x7f.1/device",  # hexadecimal and abbreviated: 127.0.0.1 to a browser
        "https://0177.0.0.1/device",  # octal: 127.0.0.1
        "https://127.1/device",  # abbreviated: 127.0.0.1
        "https://3.1.2/device",  # abbreviated: 3.1.0.2
        "https://2130706433/device",  # one number: 127.0.0.1
        "https://1.2.3.04/device",  # a leading zero: octal to a browser
        "https://1.2.3.256/device",  # out of range: refused by a browser
        "https://v.example.0x1/device",  # a name that ends in a hexadecimal number
        "https://v.example.42/device",  # a name that ends in a number
        "https://1.2.3.4./device",  # a trailing dot
    ],
)
def test_a_host_a_browser_reads_as_another_ipv4_address_is_refused(url: str) -> None:
    assert not browser_safe(url)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/device",
        "https://10.0.0.1:8443/device",
        "https://0.0.0.0/",
        "https://v.example42/device",  # a name whose last label is not all digits
        "https://0xv.example/device",  # not hexadecimal
    ],
)
def test_a_canonical_ipv4_address_or_a_name_is_read_alike(url: str) -> None:
    assert browser_safe(url)


def test_an_ip_address_has_no_subdomains() -> None:
    from personal_agent_protocol.urls import host_within

    assert host_within("login.m.example", "m.example")
    assert host_within("m.example", "m.example")
    assert not host_within("evilm.example", "m.example")
    # `3.1.2` read as a subdomain of `1.2` (a browser opens 3.1.0.2), and an address within another.
    assert not host_within("3.1.2", "1.2")
    assert not host_within("10.1.2.3", "1.2.3")
    assert host_within("10.1.2.3", "10.1.2.3")
    assert not host_within("a.2001:db8::1", "2001:db8::1")
    assert not host_within("", "m.example")


def test_a_company_logo_is_checked_as_every_https_url() -> None:
    from personal_agent_protocol.ui import PapSignIn

    def sign_in(logo: str) -> PapSignIn:
        return PapSignIn(
            mode="device",
            open="https://login.m.example/device",
            code="WDJB-MJHT",
            organization_name="M",
            organization_domain="m.example",
            organization_logo=logo,
        )

    assert sign_in("https://m.example/logo.svg").organization_logo == "https://m.example/logo.svg"
    for logo in ("https://v.example\\.m.example/../logo.svg", "https://0x7f.1/logo.svg"):
        with pytest.raises(ValueError):
            sign_in(logo)


def test_a_ucp_endpoint_is_checked_as_every_https_url() -> None:
    from personal_agent_protocol.ucp import UcpProfile

    def endpoint(url: str) -> str | None:
        return UcpProfile.model_validate(
            {
                "version": "2026-04-08",
                "services": {"dev.ucp.shopping": [{"transport": "rest", "endpoint": url}]},
            }
        ).endpoint()

    assert endpoint("https://shop.m.example/ucp") == "https://shop.m.example/ucp"
    assert endpoint("https://v.example\\.m.example/../ucp") is None
    assert endpoint("https://0177.0.0.1/ucp") is None


def test_every_https_prefix_check_also_asks_it() -> None:
    """Where a URL is accepted on its `https://` prefix alone, `browser_safe` is asked too."""

    places = {
        "ucp.py": ["and browser_safe(endpoint)", "not browser_safe(platform_profile)"],
        "operator_signatures.py": [
            "not browser_safe(signature_agent)",
            "if not browser_safe(agent):",
        ],
        "company/verify.py": ["not browser_safe(issuer)"],
        "models.py": ["not browser_safe(entry)"],
        "ui.py": ["not browser_safe(value) or urlsplit(value).scheme"],
        "device.py": ["return host_within(host, domain)"],
        "browser_control.py": ["return host_within(host, domain)"],
        "company/service.py": ["if not host_within(host, own):"],
    }
    for name, checks in places.items():
        text = (PACKAGE / name).read_text()
        for check in checks:
            assert check in text, (name, check)
