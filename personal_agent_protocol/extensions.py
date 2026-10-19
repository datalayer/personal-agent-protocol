# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Extension names, negotiation, and `extension_required` (§3.3).

- Extensions defined with the protocol have plain names (`operations`);
  anyone else names theirs under a domain they control
  (`example.com/gift-wrap`). `extension_name_kind` says which a name is, and
  an invalid name is ignored like any extension the agent does not support.
- `negotiate_extensions` keeps only what both sides list with the same major
  version: everything else is ignored, so either side works with the other
  under the specification alone.
- `extension_required` reads the `403` a company returns when a request needs
  an extension the personal agent does not list.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Literal

from .models import ExtensionDescriptor
from .refusals import challenge_parameters

#: Extensions this SDK implements, by name and major version.
SUPPORTED_EXTENSIONS: Mapping[str, str] = {"operations": "1"}

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
    company: Mapping[str, ExtensionDescriptor],
    agent: Mapping[str, ExtensionDescriptor],
    *,
    supported: Mapping[str, str] = SUPPORTED_EXTENSIONS,
) -> dict[str, str]:
    """The extensions both sides list, at the same major version, that this host supports."""

    negotiated: dict[str, str] = {}
    for name, descriptor in company.items():
        if extension_name_kind(name) == "invalid":
            continue
        mine = agent.get(name)
        if mine is None or supported.get(name) != descriptor.version:
            continue
        if mine.version == descriptor.version:
            negotiated[name] = descriptor.version
    return negotiated


def extension_required(
    status_code: int, payload: object, www_authenticate: str | None = None
) -> str | None:
    """The extension a `403 extension_required` names, else `None` (§3.3).

    In the JSON body at the token endpoint and the endpoints the protocol or
    an extension defines; in the `WWW-Authenticate` challenge's `extension`
    attribute at an API.
    """

    if status_code != 403:
        return None
    values: dict[str, object] = dict(payload) if isinstance(payload, dict) else {}
    if values.get("error") != "extension_required" and www_authenticate:
        values = dict(challenge_parameters(www_authenticate))
    if values.get("error") != "extension_required":
        return None
    name = values.get("extension")
    return name if isinstance(name, str) and extension_name_kind(name) != "invalid" else None
