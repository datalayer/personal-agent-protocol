# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""URLs read the way a browser reads them.

The SDK reads a URL with :func:`urllib.parse.urlsplit` (RFC 3986); a browser
reads it with the WHATWG URL parser. The two agree on a URL made only of the
characters RFC 3986 allows, and disagree on others. In an ``https`` URL a
browser takes a backslash for a slash, drops tabs and newlines, strips
leading and trailing spaces and control characters, and decodes a
percent-encoded host. So ``https://v.example\\.m.example/../device`` is on
``v.example\\.m.example`` (a subdomain of ``m.example``) for the SDK, and on
``v.example`` for the browser that opens it: a Company could show the User
another Company's sign-in page as its own (§4.3).

Every URL the SDK accepts as an HTTPS URL is first checked here: one with no
backslash, whitespace or control character, and an authority of plain RFC 3986
ASCII characters, is read on the same host by both, so the host the SDK checks
is the host the browser opens. A host a browser reads as an IPv4 address must be
written in its canonical form, and an IP address has no subdomains
(`host_within`).
"""

from __future__ import annotations

import string
from ipaddress import ip_address
from urllib.parse import urlsplit

#: The characters of an authority (RFC 3986 §3.2): unreserved, sub-delims, `:`, `@`, `[`, `]`.
_AUTHORITY_CHARACTERS = frozenset(string.ascii_letters + string.digits + "-._~!$&'()*+,;=:@[]")


def _read_otherwise(character: str) -> bool:
    """A character a browser drops or reads as another anywhere in an `https` URL:
    a backslash (a slash to it), whitespace, a control character."""

    return (
        character == "\\" or character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
    )


def browser_safe(value: str) -> bool:
    """Whether a browser reads `value` on the host the SDK reads it on: no
    backslash, whitespace or control character anywhere, and an authority of
    RFC 3986 ASCII characters only — no percent-encoding (a browser decodes a
    host, the SDK doesn't) and no other character (a browser maps a host
    through IDNA first). A path or a query may hold any other character: a
    browser percent-encodes it, on the same host. A URL with no host for the SDK is
    refused (a browser finds one in `https:///0x7f.1/`); a host a browser reads as an
    IPv4 address must be a canonical dotted quad; an IPv6 literal is read alike."""

    if (
        not isinstance(value, str)
        or not value
        or any(_read_otherwise(character) for character in value)
    ):
        return False
    try:
        netloc = urlsplit(value).netloc
    except ValueError:
        return False
    if not all(character in _AUTHORITY_CHARACTERS for character in netloc):
        return False
    try:
        host = urlsplit(value).hostname or ""
    except ValueError:
        return False
    if not host:
        # No host for the SDK, one for a browser: in `https:///0x7f.1/`, `https:/0x7f.1/` and
        # `https:0x7f.1/` a browser takes `0x7f.1` for the host (the review of 1.0.3).
        return False
    if ":" in host:
        # An IPv6 literal (`[::ffff:93.184.216.34]`), read alike by both. Only a valid one:
        # `urlsplit` also takes an IPvFuture host (`[v1.a:1.2.3.4]`), which a browser refuses.
        return is_ip_address(host)
    # A host a browser reads as an IPv4 address is one only in its canonical form: a
    # browser reads `0x7f.1`, `0177.0.0.1` and `3.1.2` as 127.0.0.1, 127.0.0.1 and
    # 3.1.0.2, the SDK as the names they are written (the review of 1.0.2).
    return not ends_in_a_number(host) or canonical_ipv4(host)


def ends_in_a_number(host: str) -> bool:
    """Whether a browser reads `host` as an IPv4 address (WHATWG's "ends in a number"):
    its last label, a trailing dot aside, is all digits, or `0x` and hexadecimal digits."""

    labels = host.split(".")
    if labels[-1] == "" and len(labels) > 1:
        labels.pop()
    last = labels[-1]
    if last and all(character in string.digits for character in last):
        return True
    return last[:2].lower() == "0x" and all(character in string.hexdigits for character in last[2:])


def canonical_ipv4(host: str) -> bool:
    """Whether `host` is an IPv4 address written as a browser writes it back: four decimal
    parts, 0 to 255, with no leading zero, no trailing dot."""

    parts = host.split(".")
    return len(parts) == 4 and all(
        part.isascii()
        and part.isdigit()
        and (part == "0" or not part.startswith("0"))
        # Three digits at most before `int`: a part of thousands of digits would raise.
        and len(part) <= 3
        and int(part) <= 255
        for part in parts
    )


def is_ip_address(host: str) -> bool:
    """Whether `host` (as `urlsplit` gives it: lowercase, without brackets) is an IP address."""

    try:
        ip_address(host)
    except ValueError:
        return False
    return True


def host_within(host: str, domain: str) -> bool:
    """Whether `host` is `domain` or one of its subdomains. An IP address has no
    subdomains: it is within only itself (`3.1.2` is not within `1.2`; a browser opens
    3.1.0.2)."""

    if not host or not domain:
        return False
    if (
        is_ip_address(host)
        or is_ip_address(domain)
        or ends_in_a_number(host)
        or ends_in_a_number(domain)
    ):
        return host == domain
    return host == domain or host.endswith(f".{domain}")


__all__ = ["browser_safe", "canonical_ipv4", "ends_in_a_number", "host_within", "is_ip_address"]
