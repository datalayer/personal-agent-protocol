# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""How a company's refusals read, whichever endpoint answered (§3, §3.3, §4.3, §6).

Shared by every client: the parameters of a `WWW-Authenticate` challenge,
the details a refusal carries besides its code (`extension`, `scope`,
`retry_after`), and the one rule for redirects outside discovery.
"""

from __future__ import annotations

import re

import httpx

from .errors import PersonalAgentProtocolError, TransportError

#: The statuses of an HTTP redirect.
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

_CODE_REQUIRED = ("sign_in_id", "sent_to", "expires_in")

_CHALLENGE_PARAMETER = re.compile(r'([A-Za-z_][A-Za-z0-9_-]*)="([^"]*)"')


def challenge_parameters(header: str) -> dict[str, str]:
    """The quoted parameters of a `WWW-Authenticate` header: `error`, `scope`, `extension`...

    An MCP server sends one challenge per scheme it accepts (`Bearer` and
    `DPoP`, §6), each with the same `error`; the first value of each name is kept.
    """

    values: dict[str, str] = {}
    for name, value in _CHALLENGE_PARAMETER.findall(header):
        values.setdefault(name, value)
    return values


def refusal_details(response: httpx.Response, payload: object) -> dict[str, object]:
    """What a refusal says besides its code: `extension`, `scope`, `retry_after`...

    `extension_required` names its extension in the JSON body at the token
    endpoint and the endpoints the protocol or an extension defines, and in
    the `WWW-Authenticate` challenge at APIs (§3.3); either shape is read.
    `retry_after` is kept as sent on a 429 or 503 (§5.6), never acted on here.
    """

    challenge = challenge_parameters(response.headers.get("www-authenticate", ""))
    body = payload if isinstance(payload, dict) else {}
    details: dict[str, object] = {}
    extension = body.get("extension", challenge.get("extension"))
    if isinstance(extension, str) and extension:
        details["extension"] = extension
    scope = body.get("scope", challenge.get("scope"))
    if isinstance(scope, str) and scope:
        details["scope"] = scope
    metadata = challenge.get("resource_metadata")
    if metadata:
        # A token not issued for this service: its metadata, to read again (§4.5).
        details["resource_metadata"] = metadata
    retry_after = response.headers.get("retry-after")
    if response.status_code in {429, 503} and retry_after:
        details["retry_after"] = retry_after
    if body.get("error") == "code_required":
        # What continues a Mediated Sign-In (Mediated Sign-In 4).
        details.update({name: body[name] for name in _CODE_REQUIRED if name in body})
    return details


def refusal_code(response: httpx.Response, payload: object, default: str) -> str:
    """The error a refusal names: in its JSON body, else its `WWW-Authenticate` challenge.

    A 401 challenge with no error code and a `scope` is a signed-out request for
    something that needs the account: read as `insufficient_scope` (§7). A 429
    has no body: `rate_limited` (§5.6).
    """

    body = payload if isinstance(payload, dict) else {}
    error = body.get("error")
    if isinstance(error, str):
        return error
    challenge = challenge_parameters(response.headers.get("www-authenticate", ""))
    if "error" in challenge:
        return challenge["error"]
    if response.status_code == 401 and challenge.get("scope"):
        return "insufficient_scope"
    if response.status_code == 429:
        return "rate_limited"
    return default


def dpop_nonce_asked(response: httpx.Response) -> str | None:
    """The nonce a resource's `use_dpop_nonce` challenge gives, to retry with (RFC 9449 §9)."""

    if response.status_code != 401:
        return None
    challenge = challenge_parameters(response.headers.get("www-authenticate", ""))
    return (
        response.headers.get("dpop-nonce") if challenge.get("error") == "use_dpop_nonce" else None
    )


def refused_without_body(response: httpx.Response) -> bool:
    """A refusal with nothing to parse, such as a 429 (§5.6) or a challenge alone (§7)."""

    return not response.is_success and not response.content


def refuse_redirect(
    response: httpx.Response, error: type[PersonalAgentProtocolError] = TransportError
) -> None:
    """Outside discovery a redirect never carries the protocol's secrets (§3).

    A token, revocation or device authorization endpoint, an API, or a conversation,
    feedback or extension endpoint answering with a redirect is refused: nothing is sent
    to the new URL.
    """

    if response.status_code in REDIRECT_STATUSES:
        raise error(
            "redirect_refused",
            "A protocol endpoint answered with a redirect: nothing is sent to the new URL",
            status_code=response.status_code,
        )


__all__ = [
    "REDIRECT_STATUSES",
    "challenge_parameters",
    "dpop_nonce_asked",
    "refusal_code",
    "refusal_details",
    "refuse_redirect",
    "refused_without_body",
]
