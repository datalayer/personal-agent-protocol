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
is the host the browser opens.
"""

from __future__ import annotations

import string
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
    browser percent-encodes it, on the same host."""

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
    return all(character in _AUTHORITY_CHARACTERS for character in netloc)


__all__ = ["browser_safe"]
