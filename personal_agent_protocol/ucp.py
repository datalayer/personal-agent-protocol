# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The UCP extension, version 1: a Company that speaks the Universal Commerce Protocol.

This protocol finds the Company, identifies the Personal Agent and a pseudonymous User,
and signs the User in; UCP is how the Personal Agent shops once it is there (UCP
extension 1). A Company lists `ucp` in `extensions` (2); its UCP profile is at
`https://{organization.domain}/.well-known/ucp`, fetched without redirects (3); a UCP
request carries the platform profile in `UCP-Agent`, the Session header, an operator
signature when the host contributes one, and a Bearer access token when signed in (4).
UCP's own negotiation, capabilities and commerce stay UCP's: this module is the
connection, and `UcpClient` sends one UCP REST request at a time.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

import httpx
from pydantic import Field, ValidationError

from .errors import PersonalAgentProtocolError, SessionError
from .json import loads_strict
from .models import DiscoveredCompany, DiscoveryDocument, ProtocolModel
from .reactor import send_bounded
from .refusals import challenge_parameters
from .sessions import AccessToken, PapSession
from .transport import SessionHttpClient, session_error

#: The extension's name and version in `extensions` and `Poppy-Extensions` (UCP extension 2).
UCP_EXTENSION = "ucp"
UCP_VERSION = "1"
#: Where a Company's UCP profile is, on `organization.domain` (UCP extension 3).
UCP_PROFILE_PATH = "/.well-known/ucp"
#: The header a UCP REST request names the platform profile in (UCP extension 3, 4).
UCP_AGENT_HEADER = "UCP-Agent"
#: UCP's service for shopping, and its REST transport.
UCP_SHOPPING = "dev.ucp.shopping"
UCP_IDENTITY_LINKING = "dev.ucp.common.identity_linking"
#: The UCP version the reference companies speak, in their profile (UCP's own versioning).
UCP_PROFILE_VERSION = "2026-04-08"


class UcpError(PersonalAgentProtocolError):
    """A UCP profile or request refused: its code, and `details` such as the scopes to get.

    `identity_required` (sign in, `details["scopes"]` from the profile's identity linking),
    `insufficient_scope` (`details["scope"]`), `invalid_token` (refresh, else signed out),
    `ucp_not_offered`, `redirect_refused`, `ucp_profile_unavailable`,
    `invalid_ucp_profile`, or the code a UCP error body names.
    """


class UcpProfile(ProtocolModel):
    """A Company's UCP profile, as far as this extension reads it (UCP extension 3).

    `version` is the business's UCP version; `services` and `capabilities` are UCP's,
    by name, each a list of entries. Negotiation is UCP's: the profile is data from the
    Company, never instructions (§10.1).
    """

    version: str = Field(min_length=1)
    services: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    capabilities: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)

    def endpoint(self, service: str = UCP_SHOPPING, transport: str = "rest") -> str | None:
        """The HTTPS endpoint of `service` for `transport`, or `None` when it offers none."""

        for entry in self.services.get(service, []):
            endpoint = entry.get("endpoint")
            if (
                entry.get("transport") == transport
                and isinstance(endpoint, str)
                and endpoint.startswith("https://")
            ):
                return endpoint
        return None

    def offers(self, capability: str) -> bool:
        """Whether the profile lists `capability` (UCP's name, such as `dev.ucp.shopping.order`)."""

        return bool(self.capabilities.get(capability))

    @property
    def identity_linking_scopes(self) -> tuple[str, ...]:
        """The scopes identity linking gates (`config.scopes`): what a sign-in asks for when a
        UCP request answers `identity_required` (UCP extension 4)."""

        scopes: list[str] = []
        for entry in self.capabilities.get(UCP_IDENTITY_LINKING, []):
            config = entry.get("config")
            named = config.get("scopes") if isinstance(config, Mapping) else None
            if isinstance(named, Mapping):
                scopes.extend(
                    name for name in named if isinstance(name, str) and name not in scopes
                )
        return tuple(scopes)


def speaks_ucp(document: DiscoveryDocument) -> bool:
    """Whether the Company lists the UCP extension at this version (UCP extension 2)."""

    return document.extension(UCP_EXTENSION, UCP_VERSION) is not None


def ucp_profile_url(company: DiscoveredCompany) -> str:
    """`https://{organization.domain}/.well-known/ucp`: on the validated domain, so the
    `poppy.json` and the UCP profile speak for the same host (UCP extension 3)."""

    return f"https://{company.document.organization.domain}{UCP_PROFILE_PATH}"


def ucp_agent_header(platform_profile: str) -> str:
    """The `UCP-Agent` value naming the platform profile, an RFC 9651 Dictionary.

    The profile describes the Personal Agent, never a User: one URL for every User, or its
    URL would let Companies match a User across Companies (UCP extension 3, 10).
    """

    if not platform_profile.startswith("https://") or any(
        char in platform_profile for char in '"\\ \t\r\n'
    ):
        raise ValueError("The platform profile is an HTTPS URL")
    return f'profile="{platform_profile}"'


async def fetch_ucp_profile(
    http_client: httpx.AsyncClient,
    company: DiscoveredCompany,
    *,
    max_response_bytes: int = 256 * 1024,
) -> UcpProfile:
    """The Company's UCP profile, from its validated domain, with no redirect followed.

    `ucp_not_offered` when `poppy.json` doesn't list the extension; a redirect is
    `redirect_refused`, never followed, as UCP requires (UCP extension 3).
    """

    if not speaks_ucp(company.document):
        raise UcpError("ucp_not_offered", "The company doesn't list the UCP extension")
    try:
        response = await send_bounded(
            http_client,
            http_client.build_request(
                "GET", ucp_profile_url(company), headers={"Accept": "application/json"}
            ),
            max_bytes=max_response_bytes,
        )
    except httpx.HTTPError as exc:
        raise UcpError("ucp_profile_unavailable", "The UCP profile request failed") from exc
    if response.is_redirect:
        raise UcpError("redirect_refused", "A UCP profile is never fetched through a redirect")
    if response.status_code != 200:
        raise UcpError(
            "ucp_profile_unavailable",
            "The UCP profile is unavailable",
            status_code=response.status_code,
        )
    try:
        payload = loads_strict(response.content)
        body = payload.get("ucp") if isinstance(payload, dict) else None
        return UcpProfile.model_validate(body)
    except (ValidationError, ValueError) as exc:
        raise UcpError("invalid_ucp_profile", "The UCP profile is malformed") from exc


class UcpClient:
    """Send UCP REST requests through this extension (UCP extension 4).

    Each request carries the platform profile in `UCP-Agent`, the Session header (and, when
    contributed, the operator signature) through `transport`, and the access token when
    signed in. The token is one from this protocol's sign-in, never one got independently
    of this extension. `session_ended` starts a new Session once, in the transport; the
    other answers are UCP's, and challenges are `UcpError`s as the specification's API
    challenges (§7).
    """

    def __init__(
        self,
        *,
        transport: SessionHttpClient,
        platform_profile: str,
        profile: UcpProfile,
    ) -> None:
        self.transport = transport
        self.agent = ucp_agent_header(platform_profile)
        self.profile = profile

    async def call(
        self,
        method: str,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        body: Mapping[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> Any:
        """One UCP request: its JSON answer, or a `UcpError` for a challenge or an error."""

        headers = {UCP_AGENT_HEADER: self.agent, "Accept": "application/json"}
        content = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            content = json.dumps(dict(body), separators=(",", ":")).encode()
        if idempotency_key is not None:
            headers["Idempotency-Key"] = idempotency_key
        response = await self.transport.request(
            method, url, session=session, token=token, headers=headers, content=content
        )
        if response.is_success:
            return loads_strict(response.content) if response.content else None
        error = session_error(response)
        if error is not None:
            raise SessionError(error, "The company refused the Session", status_code=400)
        raise self._refusal(response)

    def _refusal(self, response: httpx.Response) -> UcpError:
        challenge = challenge_parameters(response.headers.get("www-authenticate", ""))
        try:
            payload = loads_strict(response.content)
        except Exception:
            payload = None
        code = payload.get("code") if isinstance(payload, dict) else None
        if response.status_code == 401 and challenge.get("error") == "invalid_token":
            return UcpError("invalid_token", "Refresh the access token", status_code=401)
        if response.status_code == 401:
            # The scopes come from the profile, never from where the challenge points: the
            # issuer stays the one this protocol selected (UCP extension 4, 10).
            return UcpError(
                "identity_required",
                "Sign in for this UCP request",
                status_code=401,
                details={"scopes": list(self.profile.identity_linking_scopes)},
            )
        if response.status_code == 403 and challenge.get("error") == "insufficient_scope":
            return UcpError(
                "insufficient_scope",
                "The access token lacks a scope this UCP request needs",
                status_code=403,
                details={"scope": challenge.get("scope", "")},
            )
        return UcpError(
            code if isinstance(code, str) and code else "http_error",
            "The company refused the UCP request",
            status_code=response.status_code,
        )


def ucp_scopes(profile: UcpProfile, held: Sequence[str] = ()) -> tuple[str, ...]:
    """The identity linking scopes not in `held`: for `insufficient_scope`, UCP asks only
    for the missing ones, by incremental authorization (UCP extension 4)."""

    return tuple(scope for scope in profile.identity_linking_scopes if scope not in held)


__all__ = [
    "UCP_AGENT_HEADER",
    "UCP_EXTENSION",
    "UCP_IDENTITY_LINKING",
    "UCP_PROFILE_PATH",
    "UCP_PROFILE_VERSION",
    "UCP_SHOPPING",
    "UCP_VERSION",
    "UcpClient",
    "UcpError",
    "UcpProfile",
    "fetch_ucp_profile",
    "speaks_ucp",
    "ucp_agent_header",
    "ucp_profile_url",
    "ucp_scopes",
]
