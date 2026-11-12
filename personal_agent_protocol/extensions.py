# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Extension names, declaration, and `extension_required` (§3.3, §3.4).

- Extensions defined with the protocol have plain names (`operations`);
  anyone else names theirs under a domain they control
  (`example.com/gift-wrap`). `extension_name_kind` says which a name is, and
  an invalid name is ignored like any extension the agent does not support.
- A Company lists each extension with an entry per version it supports.
  `negotiate_extensions` picks, for each, the version this SDK implements when
  the Company lists it: what the agent uses with that Company. It declares
  them, one version each, in the `Poppy-Extensions` header on every request
  with the Session header (`format_extensions_header`, an RFC 9651 List of
  Strings with a `v` parameter), the same throughout a Session. An extension
  the company recognizes from the request itself, such as one with its own
  grant type, is never declared (`RECOGNIZED_FROM_THE_REQUEST`), and is never
  refused with `extension_required`.
- A Company reads the request's declaration (`parse_extensions_header`; a
  header that fails to parse declares none), and `extension_required` reads
  the `403` a company returns when a request needs an extension it doesn't
  declare.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Literal

from .models import ExtensionDescriptor

#: The header the Personal Agent declares the extensions it uses in (§3.4).
EXTENSIONS_HEADER = "Poppy-Extensions"

#: Extensions this SDK implements, by name and major version.
SUPPORTED_EXTENSIONS: Mapping[str, str] = {
    "operations": "3",
    "mediated-sign-in": "1",
    "links": "1",
    "disclosures": "1",
}

#: Extensions a company recognizes from the request: the agent doesn't list them (§3.3).
RECOGNIZED_FROM_THE_REQUEST: frozenset[str] = frozenset({"mediated-sign-in"})

_PLAIN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_THIRD_PARTY = re.compile(
    rf"^(?P<domain>(?:{_LABEL}\.)+{_LABEL})/(?P<name>[a-z0-9][a-z0-9._-]{{0,127}})$"
)


def extension_name_kind(name: str) -> Literal["plain", "third-party", "invalid"]:
    """`plain` for a protocol-defined name, `third-party` for `domain/name`, else `invalid`."""

    if _PLAIN.fullmatch(name):
        return "plain"
    if _THIRD_PARTY.fullmatch(name):
        return "third-party"
    return "invalid"


def extension_domain(name: str) -> str | None:
    """The domain a third-party extension name is under, else `None`."""

    match = _THIRD_PARTY.fullmatch(name)
    return match.group("domain") if match else None


def negotiate_extensions(
    company: Mapping[str, Sequence[ExtensionDescriptor]],
    *,
    supported: Mapping[str, str] = SUPPORTED_EXTENSIONS,
) -> dict[str, str]:
    """The extensions this agent uses with a Company, one version each (§3.3, §3.4).

    For each extension the Company lists, with an entry per version it supports, the
    version this host implements, when the Company lists it; everything else is
    ignored, so either side works with the other under the specification alone.
    """

    negotiated: dict[str, str] = {}
    for name, entries in company.items():
        if extension_name_kind(name) == "invalid":
            continue
        mine = supported.get(name)
        if mine is not None and any(entry.version == mine for entry in entries):
            negotiated[name] = mine
    return negotiated


def format_extensions_header(extensions: Mapping[str, str]) -> str | None:
    """`Poppy-Extensions` (§3.4): an RFC 9651 List of Strings, each an extension's name with
    its version in the `v` parameter; `None` when nothing is declared. An extension the
    company recognizes from the request itself is not declared."""

    items = [
        f'"{name}";v="{version}"'
        for name, version in sorted(extensions.items())
        if name not in RECOGNIZED_FROM_THE_REQUEST and extension_name_kind(name) != "invalid"
    ]
    return ", ".join(items) if items else None


_SF_STRING = re.compile(r'"((?:[\x20\x21\x23-\x5B\x5D-\x7E]|\\["\\])*)"')
_SF_KEY = re.compile(r"[a-z*][a-z0-9_.*-]*")


def parse_extensions_header(  # noqa: C901 - one branch per RFC 9651 production
    value: str | None,
) -> dict[str, str]:
    """The extensions a request declares (§3.4): the `Poppy-Extensions` List of Strings, each
    with its `v` parameter. Without the header, or when it fails to parse (RFC 9651 §4.2),
    the request declares no extensions; an item without a version, with an invalid name
    or an invalid version, is ignored."""

    if value is None or not value.strip():
        return {}
    declared: dict[str, str] = {}
    text = value.strip()
    position = 0
    while True:
        match = _SF_STRING.match(text, position)
        if match is None:
            return {}
        name = match.group(1).replace('\\"', '"').replace("\\\\", "\\")
        position = match.end()
        version: str | None = None
        while position < len(text) and text[position] == ";":
            position += 1
            key = _SF_KEY.match(text, position)
            if key is None:
                return {}
            position = key.end()
            parameter: str | None = None
            if position < len(text) and text[position] == "=":
                parameter_match = _SF_STRING.match(text, position + 1)
                if parameter_match is None:
                    return {}
                parameter = parameter_match.group(1)
                position = parameter_match.end()
            if key.group(0) == "v":
                version = parameter
        if (
            version is not None
            and re.fullmatch(r"(0|[1-9][0-9]*)", version)
            and extension_name_kind(name) != "invalid"
        ):
            declared[name] = version
        if position >= len(text):
            return declared
        comma = re.compile(r"[ \t]*,[ \t]*").match(text, position)
        if comma is None or comma.end() >= len(text):
            return {}
        position = comma.end()


def extension_required(status_code: int, payload: object) -> str | None:
    """The extension a `403 extension_required` names, else `None` (§3.3).

    In the JSON body, at APIs as at the endpoints the protocol or an extension defines:
    it is not an access token error, so a `WWW-Authenticate` challenge never carries it
    and none is read for it (§7). The token endpoint returns none: extensions are
    declared per request, and one with its own grant type is recognized from the request.
    """

    if status_code != 403:
        return None
    values: dict[str, object] = dict(payload) if isinstance(payload, dict) else {}
    if values.get("error") != "extension_required":
        return None
    name = values.get("extension")
    if not isinstance(name, str) or name in RECOGNIZED_FROM_THE_REQUEST:
        # A company can't refuse a request that uses the extension itself (§3.3).
        return None
    return name if extension_name_kind(name) != "invalid" else None
