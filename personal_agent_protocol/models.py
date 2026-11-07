# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Wire models for Personal Agent Protocol draft 0.3."""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal, cast
from urllib.parse import urljoin, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidationError,
    field_validator,
    model_serializer,
    model_validator,
)

from .errors import AuthorizationError
from .profile import PROTOCOL_PROFILE

_VERSION = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)$")
#: The protocol versions this SDK implements (§3.4): a Company's document is used at a
#: version compatible with one of them, the same major and, before 1.0, the same minor.
SUPPORTED_PROTOCOL_VERSIONS = frozenset({PROTOCOL_PROFILE})


def parse_version(value: str) -> tuple[int, int]:
    """`major.minor` as numbers, or `ValueError`."""

    match = _VERSION.fullmatch(value)
    if match is None:
        raise ValueError("a protocol version is major.minor")
    return int(match["major"]), int(match["minor"])


def compatible_versions(one: str, other: str) -> bool:
    """Whether two protocol versions are compatible (§3.4): the same major version and,
    before 1.0, the same minor version."""

    first, second = parse_version(one), parse_version(other)
    if first[0] != second[0]:
        return False
    return first[0] >= 1 or first[1] == second[1]


def choose_protocol_version(
    protocol_version: str,
    supported_versions: Iterable[str] = (),
    *,
    implemented: Iterable[str] = SUPPORTED_PROTOCOL_VERSIONS,
) -> str | None:
    """The newest version, among `protocol_version` and `supported_versions`, that is
    compatible with one this SDK implements (§3.4); `None` when none is, and the Personal
    Agent then uses none of the documents."""

    mine = tuple(implemented)
    usable = [
        version
        for version in (protocol_version, *supported_versions)
        if _VERSION.fullmatch(version) and any(compatible_versions(version, v) for v in mine)
    ]
    return max(usable, key=parse_version) if usable else None


_EXTENSION_VERSION = re.compile(r"^(0|[1-9][0-9]*)$")
#: OAuth scope syntax (RFC 6749 §3.3): one scope token.
_SCOPE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")
#: The grant a Company's token endpoint MUST accept (§3.2, §4.4).
REFRESH_TOKEN_GRANT = "refresh_token"
#: The grants that say the Company offers Direct and Device Sign-In (§3.2, §4.4).
AUTHORIZATION_CODE_GRANT = "authorization_code"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
#: The sign-in extension, listed in `extensions` (Mediated Sign-In 2), and its grant type.
MEDIATED_EXTENSION = "mediated-sign-in"
MEDIATED_GRANT = "https://personalagentprotocol.org/grant/mediated-sign-in"
#: The one scope the protocol defines (§4.7, §6): a signed-in browser join needs an access
#: token with it; the website applies the cookie's other scopes, or treats it as everything
#: the account can do there and says so with `web.unscoped`.
BROWSER_SIGN_IN_SCOPE = "poppy:browser-sign-in"
#: The sign-in types, in the order a Personal Agent prefers them (§4): Direct Sign-In is
#: the preferred type, Device Sign-In stays, and Mediated Sign-In is transitional.
SIGN_IN_TYPES = ("direct", "device", "mediated")
#: `changes` values a scope hint may give (§4.4); any other is read as `irreversible`.
SCOPE_CHANGES = ("none", "reversible", "irreversible")
_DOMAIN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_LOCALE = re.compile(r"^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$")


def _iana_zone(value: object) -> bool:
    if not isinstance(value, str) or not value or len(value) > 64 or ".." in value:
        return False
    try:
        ZoneInfo(value)
    except (ValueError, ZoneInfoNotFoundError):
        return False
    return True


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{label} must be an HTTPS URL without user information")
    return value


def _identifier(value: str, label: str) -> str:
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must use the URL-safe base64 alphabet")
    return value


def _scope(value: str) -> str:
    if not _SCOPE.fullmatch(value):
        raise ValueError("a scope must follow OAuth scope syntax")
    return value


def is_loopback_redirect(value: str) -> bool:
    """A loopback redirect URI (RFC 8252 §7.3): `http` to a loopback IP literal, any port.

    An app on the User's computer receives Direct Sign-In's answer there (§4.1).
    """

    parsed = urlsplit(value)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        return False
    if parsed.fragment:
        return False
    try:
        return ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


def redirect_uri_matches(registered: str, given: str) -> bool:
    """Whether `given` is the redirect URI `registered` names (§4.1, §4.5).

    Exactly, except that a loopback redirect URI matches with any port (RFC 8252 §7.3).
    """

    if registered == given:
        return True
    if not (is_loopback_redirect(registered) and is_loopback_redirect(given)):
        return False
    one, other = urlsplit(registered), urlsplit(given)
    return (one.hostname, one.path, one.query) == (other.hostname, other.path, other.query)


def _domain(value: str) -> str:
    normalized = value.rstrip(".").lower()
    if not _DOMAIN.fullmatch(normalized):
        raise ValueError("must be a DNS domain name")
    return normalized


class ProtocolModel(BaseModel):
    """Base wire model that retains additions from compatible minor versions."""

    model_config = ConfigDict(extra="allow", frozen=True)


class Organization(ProtocolModel):
    name: str = Field(min_length=1)
    domain: str
    #: An HTTPS URL of the Company's logo (§3.1), named as in client metadata (§4.1). An
    #: agent shows it next to the Company's name and domain, never in place of the domain,
    #: and serves its own copy (guides, *Finding a company*).
    logo_uri: str | None = None

    _normalize_domain = field_validator("domain")(_domain)

    @field_validator("logo_uri")
    @classmethod
    def validate_logo_uri(cls, value: str | None) -> str | None:
        return None if value is None else _https_url(value, "organization.logo_uri")


#: The Agent Skills discovery draft revision `skill_index` pins (§9.4): the `$schema` an
#: index names. An index with another, or none, is ignored; the rest of poppy.json is used.
SKILL_INDEX_SCHEMA = "https://schemas.agentskills.io/discovery/0.2.0/schema.json"
#: The artifact types the SDK recognizes (§9.4): a single `SKILL.md`, or an archive with
#: supporting files. An entry of another type is skipped.
SKILL_TYPES = frozenset({"skill-md", "archive"})


class SkillEntry(ProtocolModel):
    """A skill a Company publishes for Personal Agents acting for the User there (§9.4).

    `url` is resolved against poppy.json's final URL (RFC 3986 §5) and is HTTPS; `digest` is
    the SHA-256 of the artifact's raw bytes, `sha256:` and 64 lowercase hex characters,
    which `DiscoveryClient.fetch_skill` verifies. A skill is Company content (§10.1): it
    grants no account access, changes no scopes, and supplies no User approval.
    """

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    type: str = Field(min_length=1)
    url: str
    digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _https_url(value, "skill url")


class MediatedField(ProtocolModel):
    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    secret: bool


#: What a Mediated Sign-In field can't be called: the grant's own parameters and OAuth's
#: (Mediated Sign-In 2).
MEDIATED_RESERVED_FIELDS = frozenset(
    {
        "grant_type",
        "scope",
        "resource",
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "sign_in_id",
        "one_time_code",
    }
)


class MediatedSignIn(ProtocolModel):
    """`extensions["mediated-sign-in"]`, version 1: the credentials to collect, its scopes."""

    version: Literal["1"]
    fields: list[MediatedField] = Field(min_length=1)
    scopes: list[str] = Field(min_length=1)

    _scopes = field_validator("scopes")(lambda value: [_scope(item) for item in value])

    @field_validator("fields")
    @classmethod
    def validate_fields(cls, value: list[MediatedField]) -> list[MediatedField]:
        if any(field.name in MEDIATED_RESERVED_FIELDS for field in value):
            raise ValueError("a Mediated Sign-In field can't use a reserved parameter name")
        return value


class ScopeHint(ProtocolModel):
    """What a scope allows, its most consequential operation (§4.4): a Company's claim."""

    changes: str = Field(min_length=1)
    personal_data: bool

    @property
    def effective_changes(self) -> Literal["none", "reversible", "irreversible"]:
        """`changes`, with a value this SDK doesn't know read as `irreversible` (§4.4)."""

        if self.changes == "none":
            return "none"
        if self.changes == "reversible":
            return "reversible"
        return "irreversible"


class AuthCapabilities(ProtocolModel):
    """`auth` (§3.1): optional; the issuer it names, the Company's scopes.

    `issuer` is needed only when the domain's protected resource metadata lists more
    than one authorization server, and then names one of them; with one, it may be
    left out, and if present names that one (§3.1, §3.2). Direct and Device Sign-In are
    not here: the issuer's `grant_types_supported` says whether the Company offers them.
    Mediated Sign-In is an extension (`extensions["mediated-sign-in"]`).
    """

    issuer: str | None = None
    #: `true` when the Company offers Personal Agents no sign-in, though it has an issuer
    #: (§3.2): its identifier stays the issuer, and no sign-in is started with it.
    disabled: bool = False
    scopes: dict[str, str] = Field(default_factory=dict)
    scope_hints: dict[str, ScopeHint] = Field(default_factory=dict)

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, value: str | None) -> str | None:
        # Kept exactly as written: the issuer is compared character for character (§3.2).
        return None if value is None else _https_url(value, "auth issuer")

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: dict[str, str]) -> dict[str, str]:
        for name, description in value.items():
            _scope(name)
            if not description:
                raise ValueError("each scope needs a description")
        return value

    @field_validator("scope_hints")
    @classmethod
    def validate_hint_names(cls, value: dict[str, ScopeHint]) -> dict[str, ScopeHint]:
        for name in value:
            _scope(name)
        return value


class AgentProtocol(ProtocolModel):
    """A conversation protocol the Company Agent speaks (§3.1, §8).

    `access` is kept as written, whatever it says; read `account_access`.
    """

    type: str = Field(min_length=1)
    endpoint: str
    access: str | None = None

    @property
    def account_access(self) -> Literal["session", "signed_in"]:
        """Whether a `poppy` entry needs account access before useful work can begin (§3.2).

        `signed_in` lets the agent arrange sign-in before its first request; a value this
        SDK doesn't know is an absent hint. A hint only: it grants nothing, and challenges
        and authorization events still decide.
        """

        return "signed_in" if self.type == "poppy" and self.access == "signed_in" else "session"

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return _https_url(value, "endpoint")


class AgentDescriptor(ProtocolModel):
    protocols: list[AgentProtocol] = Field(min_length=1)


class ApiDescriptor(ProtocolModel):
    type: str = Field(min_length=1)
    url: str
    description: str = Field(min_length=1)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _https_url(value, "API url")


class WebDescriptor(ProtocolModel):
    """The Company's website (§3.1, §6): where the agent's browser joins a Session, whether
    the Company asks Personal Agents not to browse (`disabled`), and whether
    `poppy:browser-sign-in` gives the account's full access there (`unscoped`)."""

    browser_session_endpoint: str | None = None
    disabled: bool = False
    unscoped: bool = False

    @field_validator("browser_session_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str | None) -> str | None:
        return _https_url(value, "browser session endpoint") if value is not None else None

    @model_validator(mode="after")
    def validate_flags(self) -> WebDescriptor:
        if self.disabled and self.browser_session_endpoint is not None:
            # A Company that asks agents not to browse lists no join endpoint (§6).
            raise ValueError("web.disabled lists no browser_session_endpoint")
        if self.unscoped and self.browser_session_endpoint is None:
            # The scope's meaning is said for a website agents can sign in to (§6).
            raise ValueError("web.unscoped needs a browser_session_endpoint")
        return self


class FeedbackDescriptor(ProtocolModel):
    """Where personal agents report a task the protocol can't do at this company (§8)."""

    endpoint: str

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return _https_url(value, "feedback endpoint")


class ExcludedTasksDescriptor(ProtocolModel):
    """Where the tasks the Company chose not to offer through the protocol are listed (§8.1)."""

    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _https_url(value, "excluded tasks URL")


class ExtensionDescriptor(ProtocolModel):
    version: str

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: str) -> str:
        if not _EXTENSION_VERSION.fullmatch(value):
            raise ValueError("extension version must be a non-negative major version")
        return value


class DiscoveryDocument(ProtocolModel):
    protocol_version: str
    #: The other protocol versions the Company serves, each mapped to the HTTPS URL of
    #: that version's document, on the host that served `poppy.json` (§3.4). A version's
    #: own document lists none.
    supported_versions: dict[str, str] = Field(default_factory=dict)
    organization: Organization
    auth: AuthCapabilities | None = None
    agent: AgentDescriptor | None = None
    web: WebDescriptor | None = None
    apis: list[ApiDescriptor] = Field(default_factory=list)
    feedback: FeedbackDescriptor | None = None
    excluded_tasks: ExcludedTasksDescriptor | None = None
    #: The extensions the Company supports, keyed by name, each a list with an entry per
    #: major version it supports (§3.3); each extension defines the entry's other fields.
    extensions: dict[str, list[ExtensionDescriptor]] = Field(default_factory=dict)
    #: The Company's Agent Skills discovery index, as published (§3.1, §9.4); read it
    #: through `usable_skills`, which skips what this SDK does not recognize.
    skill_index: dict[str, Any] | None = None

    @field_validator("protocol_version")
    @classmethod
    def validate_protocol_version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("protocol_version must use major.minor")
        return value

    @field_validator("supported_versions")
    @classmethod
    def validate_supported_versions(cls, value: dict[str, str]) -> dict[str, str]:
        for version, url in value.items():
            if not _VERSION.fullmatch(version):
                raise ValueError("supported_versions are keyed by major.minor")
            _https_url(url, f"supported_versions[{version}]")
        return value

    @field_validator("extensions")
    @classmethod
    def validate_extensions(
        cls, value: dict[str, list[ExtensionDescriptor]]
    ) -> dict[str, list[ExtensionDescriptor]]:
        for name, entries in value.items():
            if not entries:
                raise ValueError(f"extensions.{name} lists at least one version")
        return value

    def extension(self, name: str, version: str) -> ExtensionDescriptor | None:
        """The Company's entry for `name` at `version` (§3.3), or `None`."""

        return next(
            (entry for entry in self.extensions.get(name, []) if entry.version == version), None
        )

    @model_validator(mode="after")
    def validate_interfaces(self) -> DiscoveryDocument:
        if self.agent is None and not self.apis and self.web is None:
            # At least one of the three, not exactly one (§3.1).
            raise ValueError("at least one of agent, apis, or web is required")
        if self.web is not None and self.web.disabled and self.agent is None and not self.apis:
            # Asking agents not to browse means offering them the Company Agent or APIs (§6).
            raise ValueError("web.disabled needs agent or apis")
        if self.chosen_version is None:
            # A document is used only at a version compatible with one this SDK
            # implements, its own or one it links to (§3.1, §3.4).
            raise ValueError("unsupported Personal Agent Protocol version")
        return self

    @property
    def chosen_version(self) -> str | None:
        """The version the Personal Agent uses this Company at (§3.4): the newest, among
        `protocol_version` and `supported_versions`, compatible with one it implements.
        When it is not `protocol_version`, the version's own document is fetched and used."""

        return choose_protocol_version(self.protocol_version, self.supported_versions)

    @property
    def browsing_disabled(self) -> bool:
        """Whether the Company asks Personal Agents not to browse its website (`web.disabled`,
        §6): use its Company Agent and APIs instead. Not enforceable, a preference."""

        return self.web is not None and self.web.disabled

    @property
    def browser_sign_in_scopes(self) -> tuple[str, ...]:
        """The scope a signed-in browser join needs (§6): `poppy:browser-sign-in`, requested
        only from a Company that lists `browser_session_endpoint`; nothing otherwise."""

        if self.web is None or self.web.browser_session_endpoint is None:
            return ()
        return (BROWSER_SIGN_IN_SCOPE,)

    @property
    def browser_sign_in_unscoped(self) -> bool:
        """Whether `poppy:browser-sign-in` gives the account's full access on the website
        (`web.unscoped`, §6): treat it like a scope that allows changes that can't be undone,
        and ask the User when you would for one."""

        return self.web is not None and self.web.unscoped

    def usable_skills(self, base_url: str) -> list[SkillEntry]:
        """The skills of `skill_index` this SDK can use (§9.4), each `url` resolved.

        Nothing when there is no index or its `$schema` is not `SKILL_INDEX_SCHEMA`; an
        entry whose `type` is unknown, which lacks a field, whose `digest` is malformed, or
        whose `url`, resolved against `base_url` (the final poppy.json URL), is not HTTPS is
        skipped. The guides suggest telling the User when that mattered for the task.
        """

        index = self.skill_index
        if not isinstance(index, dict) or index.get("$schema") != SKILL_INDEX_SCHEMA:
            return []
        skills = index.get("skills")
        if not isinstance(skills, list):
            return []
        usable: list[SkillEntry] = []
        for raw in skills:
            if not isinstance(raw, dict) or raw.get("type") not in SKILL_TYPES:
                continue
            url = raw.get("url")
            if not isinstance(url, str) or not url:
                continue
            try:
                usable.append(SkillEntry.model_validate({**raw, "url": urljoin(base_url, url)}))
            except ValidationError:
                continue
        return usable

    @property
    def sign_in_disabled(self) -> bool:
        """Whether the Company turned sign-in off (`auth.disabled`, §3.2).

        A Personal Agent starts no Direct, Device or Mediated Sign-In with it, whatever
        its issuer's grants say; a Mediated Sign-In entry or `signed_in` access it lists
        anyway is not used.
        """

        return self.auth is not None and self.auth.disabled

    @property
    def needs_issuer(self) -> bool:
        """Whether the Company offers sign-in, which needs an OAuth issuer (§3.2).

        `auth.issuer`, an `access: signed_in` conversation entry, or Mediated Sign-In.
        Anything else works signed out: APIs, conversations, feedback and browser join.
        """

        return (
            (self.auth is not None and self.auth.issuer is not None)
            or (
                self.agent is not None
                and any(item.account_access == "signed_in" for item in self.agent.protocols)
            )
            or MEDIATED_EXTENSION in self.extensions
        )


class OAuthServerMetadata(ProtocolModel):
    """The issuer's RFC 8414 metadata, with the fields this protocol requires (§3.2)."""

    issuer: str
    token_endpoint: str
    revocation_endpoint: str
    grant_types_supported: list[str]
    #: RFC 9728 §4: `https://{domain}` for every domain whose `poppy.json` names the issuer,
    #: exactly as written, compared as a string (§3.2).
    protected_resources: list[str] = Field(min_length=1)
    authorization_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    pushed_authorization_request_endpoint: str | None = None
    scopes_supported: list[str] | None = None
    dpop_signing_alg_values_supported: list[str] | None = None

    @field_validator("grant_types_supported")
    @classmethod
    def validate_grants(cls, value: list[str]) -> list[str]:
        if REFRESH_TOKEN_GRANT not in value:
            raise ValueError("grant_types_supported must include refresh_token")
        return value

    @field_validator("scopes_supported")
    @classmethod
    def validate_scopes(cls, value: list[str] | None) -> list[str] | None:
        return [_scope(item) for item in value] if value is not None else None

    @field_validator("protected_resources")
    @classmethod
    def validate_resources(cls, value: list[str]) -> list[str]:
        return [_https_url(item, "protected resource") for item in value]

    @model_validator(mode="after")
    def validate_sign_in_endpoints(self) -> OAuthServerMetadata:
        if self.offers_direct and self.authorization_endpoint is None:
            raise ValueError("authorization_code needs authorization_endpoint")
        if self.offers_device and self.device_authorization_endpoint is None:
            raise ValueError("the device grant needs device_authorization_endpoint")
        return self

    @property
    def offers_direct(self) -> bool:
        """Whether the Company offers Direct Sign-In (§3.2, §4.4)."""

        return AUTHORIZATION_CODE_GRANT in self.grant_types_supported

    @property
    def offers_device(self) -> bool:
        """Whether the Company offers Device Sign-In (§3.2, §4.4)."""

        return DEVICE_CODE_GRANT in self.grant_types_supported

    def lists_resource(self, domain: str) -> bool:
        """Whether `protected_resources` names `https://{domain}` (§3.2).

        Exactly, except that the host compares ignoring case: an entry with a path, a
        port or a trailing slash does not match.
        """

        wanted = domain.lower().rstrip(".")
        for entry in self.protected_resources:
            if not entry.startswith("https://"):
                continue
            host = entry[len("https://") :]
            if host and not any(char in host for char in "/?#:@") and host.lower() == wanted:
                return True
        return False

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, value: str) -> str:
        # Compared with `auth.issuer` character for character (§3.2): never normalized.
        return _https_url(value, "issuer")

    @field_validator(
        "token_endpoint",
        "revocation_endpoint",
        "authorization_endpoint",
        "device_authorization_endpoint",
        "pushed_authorization_request_endpoint",
    )
    @classmethod
    def validate_urls(cls, value: str | None, info: Any) -> str | None:
        return _https_url(value, info.field_name).rstrip("/") if value is not None else None


class ProtectedResourceMetadata(ProtocolModel):
    """RFC 9728 protected resource metadata, with the fields this protocol uses (§3.2, §4.5).

    The Company's domain publishes it with `resource` exactly `https://{domain}` and
    its issuer, if any, in `authorization_servers`; a service that accepts only tokens issued
    for it publishes it with its own `resource`, as MCP servers do (§4.5, §7).
    """

    resource: str
    #: Absent or empty at the domain of a Company with no issuer (§3.2).
    authorization_servers: list[str] = Field(default_factory=list)
    scopes_supported: list[str] = Field(default_factory=list)
    bearer_methods_supported: list[str] = Field(default_factory=list)
    #: At an MCP server it, not the issuer's list, says whether a token proves (§7).
    dpop_signing_alg_values_supported: list[str] | None = None

    @field_validator("resource")
    @classmethod
    def validate_resource(cls, value: str) -> str:
        # Compared exactly as written: never normalized (§3.2, §4.5).
        return _https_url(value, "resource")

    @field_validator("authorization_servers")
    @classmethod
    def validate_servers(cls, value: list[str]) -> list[str]:
        return [_https_url(item, "authorization server") for item in value]


def protected_resource_metadata_url(url: str) -> str:
    """Where a resource's RFC 9728 metadata is (§3.1 of RFC 9728): the well-known path first.

    `https://example.com` has it at `https://example.com/.well-known/oauth-protected-resource`;
    `https://example.com/mcp` at `https://example.com/.well-known/oauth-protected-resource/mcp`.
    """

    parsed = urlsplit(url)
    path = parsed.path.rstrip("/")
    return f"https://{parsed.netloc}/.well-known/oauth-protected-resource{path}"


class ClientMetadata(ProtocolModel):
    client_id: str
    client_name: str = Field(min_length=1)
    logo_uri: str | None = None
    jwks_uri: str
    redirect_uris: list[str] = Field(default_factory=list)
    token_endpoint_auth_method: Literal["private_key_jwt"] = "private_key_jwt"

    @field_validator("client_id", "logo_uri", "jwks_uri")
    @classmethod
    def validate_urls(cls, value: str | None, info: Any) -> str | None:
        return _https_url(value, info.field_name) if value is not None else None

    @field_validator("redirect_uris")
    @classmethod
    def validate_redirects(cls, value: list[str]) -> list[str]:
        # An HTTPS URL, or a loopback redirect URI for an app on the User's computer (§4.1).
        return [
            item if is_loopback_redirect(item) else _https_url(item, "redirect URI")
            for item in value
        ]

    @model_validator(mode="after")
    def validate_same_domain_urls(self) -> ClientMetadata:
        domain = urlsplit(self.client_id).hostname
        urls = [
            self.jwks_uri,
            *(uri for uri in self.redirect_uris if not is_loopback_redirect(uri)),
        ]
        if any(urlsplit(url).hostname != domain for url in urls):
            raise ValueError("jwks_uri and HTTPS redirect_uris must use the client_id domain")
        return self


_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class JsonWebKey(ProtocolModel):
    """One asymmetric public signing key published by a personal agent."""

    kty: Literal["EC", "RSA"]
    kid: str | None = None
    use: Literal["sig"] | None = None
    alg: Literal["ES256", "PS384"] | None = None
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    n: str | None = None
    e: str | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_private_material(cls, value: Any) -> Any:
        if isinstance(value, dict) and _PRIVATE_JWK_MEMBERS.intersection(value):
            raise ValueError("JWKS keys must not contain private or symmetric key material")
        return value

    @model_validator(mode="after")
    def validate_public_key(self) -> JsonWebKey:
        if self.kty == "EC":
            if self.crv != "P-256" or not self.x or not self.y:
                raise ValueError("EC signing keys must be complete P-256 public keys")
            if self.alg not in {None, "ES256"}:
                raise ValueError("P-256 signing keys may advertise only ES256")
        elif not self.n or not self.e:
            raise ValueError("RSA signing keys must include public modulus and exponent")
        elif self.alg not in {None, "PS384"}:
            # PS384 lets a key sign blindly (§4.1, §10.7).
            raise ValueError("RSA signing keys may advertise only PS384")
        return self


class JsonWebKeySet(ProtocolModel):
    """A non-empty set of public keys suitable for PAP assertion verification."""

    keys: list[JsonWebKey] = Field(min_length=1)


class Operation(ProtocolModel):
    """One action the Company performs once the User approves it (Operations 3).

    `revision` is opaque: it identifies these terms, and the Company changes it
    whenever the `summary`, `terms`, or `expires_at` change.
    """

    operation_id: str
    revision: str
    summary: str = Field(min_length=1)
    terms: dict[str, Any] | None = None
    expires_at: datetime

    @model_serializer(mode="wrap")
    def _absent_not_null(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """`terms`, when there are none, is absent, never `null`."""

        value = handler(self)
        if value.get("terms") is None:
            value.pop("terms", None)
        return value

    _ids = field_validator("operation_id", "revision")(
        lambda value: _identifier(value, "an operation ID or revision")
    )

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return value


class Approval(ProtocolModel):
    """A statement that the User approved this revision of an operation (Operations 5, 6)."""

    operation_id: str
    revision: str

    _ids = field_validator("operation_id", "revision")(
        lambda value: _identifier(value, "an operation ID or revision")
    )


class OperationsContent(ProtocolModel):
    """The Operations extension's content of a message, `extensions.operations` (Operations 2).

    `operation` in a Company message (Operations 4), `approval` in a Personal Agent
    message (Operations 6): one of the two, never both.
    """

    operation: Operation | None = None
    approval: Approval | None = None

    @model_validator(mode="after")
    def validate_one(self) -> OperationsContent:
        if (self.operation is None) == (self.approval is None):
            raise ValueError("extensions.operations carries an operation or an approval")
        return self


class Link(ProtocolModel):
    """A web page a Company message refers to (Links 3): its HTTPS `url`, and its `title`
    as the message refers to it. Both are content from the Company (§10.1)."""

    url: str
    title: str | None = Field(default=None, min_length=1)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _https_url(value, "a link")


class LinksContent(ProtocolModel):
    """The Links extension's content of a Company message, `extensions.links` (Links 3)."""

    items: list[Link]


class Disclosure(ProtocolModel):
    """A notice a Company marks apart from the rest of a message (Disclosures 3), such as
    an allergen warning. The Personal Agent decides whether to show it."""

    text: str = Field(min_length=1)


class DisclosuresContent(ProtocolModel):
    """The Disclosures extension's content of a Company message, `extensions.disclosures`
    (Disclosures 3)."""

    items: list[Disclosure]


#: The extensions that define message content (§8.4), each with its content model.
LINKS_EXTENSION = "links"
LINKS_VERSION = "1"
DISCLOSURES_EXTENSION = "disclosures"
DISCLOSURES_VERSION = "1"
MESSAGE_CONTENT_MODELS: dict[str, type[ProtocolModel]] = {
    "operations": OperationsContent,
    LINKS_EXTENSION: LinksContent,
    DISCLOSURES_EXTENSION: DisclosuresContent,
}


def operations_content(
    *, operation: Operation | None = None, approval: Approval | None = None
) -> dict[str, dict[str, Any]]:
    """A message's `extensions` carrying the Operations extension's content (Operations 2)."""

    content = OperationsContent(operation=operation, approval=approval)
    return {"operations": content.model_dump(mode="json", exclude_none=True)}


class Author(ProtocolModel):
    """Who wrote a message (§7.4): `agent` or `human`, and for a Company message, who.

    `id`, `name` and `image` name the Company's person or AI persona; each is optional,
    and the Personal Agent never sends them.
    """

    type: Literal["agent", "human"]
    id: str | None = None
    name: str | None = Field(default=None, min_length=1)
    image: str | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError("an author ID must use the URL-safe base64 alphabet")
        return value

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str | None) -> str | None:
        return None if value is None else _https_url(value, "author image")


class Message(ProtocolModel):
    """A message sent by either side, or returned in a conversation event (§8.4).

    `id` is set by the Company when it records the message as an event: a Personal
    Agent message's ID is its request's ID (§8.3), a Company message's one it chooses.
    On a message the Personal Agent builds, `id` is the request ID the client sends
    at the top level of the `POST`; the message itself goes without it.
    """

    id: str | None = None
    author: Author
    role: Literal["user", "company"] | None = None
    #: What the writer had seen (§8.4), hints neither side depends on: on a Company Agent
    #: message, the ID of the latest request it took into account; on a message the
    #: Personal Agent wrote, the last cursor it had read. A person's message carries neither.
    as_of_request: str | None = None
    as_of_cursor: str | None = None
    text: str | None = None
    data: dict[str, Any] | None = None
    context: dict[str, Any] | None = None
    #: Content extensions define, keyed by extension name (§8.4): `operations` carries an
    #: operation or an approval, `links` and `disclosures` their items. A side sends an
    #: extension's content only to a side that lists the same version; content of an
    #: extension this SDK does not define is kept as the object it is.
    extensions: dict[str, dict[str, Any]] | None = None

    @property
    def operation(self) -> Operation | None:
        """A Company message's operation, for the User's approval (Operations 4)."""

        content = self._content("operations", OperationsContent)
        return None if content is None else cast(OperationsContent, content).operation

    @property
    def approval(self) -> Approval | None:
        """A Personal Agent message's approval: only this approves, never `text` (Operations 6)."""

        content = self._content("operations", OperationsContent)
        return None if content is None else cast(OperationsContent, content).approval

    @property
    def links(self) -> list[Link]:
        """The web pages a Company message refers to (Links 3); none without the extension."""

        content = self._content(LINKS_EXTENSION, LinksContent)
        return [] if content is None else list(cast(LinksContent, content).items)

    @property
    def disclosures(self) -> list[Disclosure]:
        """The notices a Company message marks apart (Disclosures 3); none without the extension."""

        content = self._content(DISCLOSURES_EXTENSION, DisclosuresContent)
        return [] if content is None else list(cast(DisclosuresContent, content).items)

    def _content(self, name: str, model: type[ProtocolModel]) -> ProtocolModel | None:
        value = None if self.extensions is None else self.extensions.get(name)
        return None if value is None else model.model_validate(value)

    @field_validator("extensions")
    @classmethod
    def validate_extensions(
        cls, value: dict[str, dict[str, Any]] | None
    ) -> dict[str, dict[str, Any]] | None:
        """Each extension's content is an object; the ones this SDK defines, in their shape."""

        if value is None:
            return value
        for name, content in value.items():
            if not isinstance(content, dict):
                raise ValueError(f"extensions.{name} must be a JSON object")
            model = MESSAGE_CONTENT_MODELS.get(name)
            if model is not None:
                try:
                    model.model_validate(content)
                except ValidationError as error:
                    raise ValueError(f"extensions.{name}: {error.errors()[0]['msg']}") from error
        return value

    @field_validator("id", "as_of_request", "as_of_cursor")
    @classmethod
    def validate_id(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError(
                "message IDs, request IDs and cursors use the URL-safe base64 alphabet"
            )
        return value

    @field_validator("context")
    @classmethod
    def validate_context(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        """The facts §7.4 defines use its field names and formats; others pass through."""

        if value is None:
            return value
        locale = value.get("locale")
        if locale is not None and (not isinstance(locale, str) or not _LOCALE.fullmatch(locale)):
            raise ValueError("context.locale must be a language tag such as en-US")
        zone = value.get("time_zone")
        if zone is not None and not _iana_zone(zone):
            raise ValueError("context.time_zone must be an IANA time zone name")
        available = value.get("user_available")
        if available is not None and not isinstance(available, bool):
            raise ValueError("context.user_available must be true or false")
        return value

    @model_validator(mode="after")
    def validate_content(self) -> Message:
        content = (self.text, self.data, self.context, self.extensions)
        if all(value is None for value in content):
            raise ValueError("a message requires text, data, context, or extensions")
        # Only messages written by an AI say what they took into account (§8.4): a person
        # types while messages arrive. `as_of_request` is the Company Agent's, `as_of_cursor`
        # the Personal Agent's.
        if self.author.type == "human" and (self.as_of_request or self.as_of_cursor):
            raise ValueError("a person's message carries neither as_of_request nor as_of_cursor")
        if self.role == "user" and self.as_of_request is not None:
            raise ValueError("as_of_request is the Company Agent's")
        if self.role == "company" and self.as_of_cursor is not None:
            raise ValueError("as_of_cursor is the Personal Agent's")
        return self


#: The `handoff` values and responders this version defines (§8.7).
HANDOFF_STATES = ("none", "pending")
RESPONDERS = ("agent", "human")


def known_handoff(value: object) -> object:
    """A `handoff` this SDK doesn't recognize reads as `pending` (§8.7)."""

    return value if not isinstance(value, str) or value in HANDOFF_STATES else "pending"


def known_responder(value: object) -> object:
    """A `responder` this SDK doesn't recognize reads as `human` (§8.7)."""

    return value if not isinstance(value, str) or value in RESPONDERS else "human"


class ConversationState(ProtocolModel):
    """Where a conversation stands, in four fields each independent of the others (§8.7).

    `working` is true while the Company has work in progress: a request it accepted but
    hasn't acted on, a reply being written, or work it started on its own; a Personal
    Agent that wants the whole reply reads until it is false. `handoff` is `pending`
    while the Company looks for a person (§8.9). `responder` is who handles the Company
    side. `closed` means the conversation takes no more messages (§8.12). A new
    conversation starts with `handoff` `none`, `responder` `agent` and `closed` false.
    """

    working: bool
    handoff: Literal["none", "pending"]
    responder: Literal["agent", "human"]
    closed: bool

    _handoff = field_validator("handoff", mode="before")(
        classmethod(lambda cls, value: known_handoff(value))
    )
    _responder = field_validator("responder", mode="before")(
        classmethod(lambda cls, value: known_responder(value))
    )


#: Event types draft 0.3 defines (§7.5); a personal agent skips any other type.
KNOWN_EVENT_TYPES = frozenset(
    {"message", "state", "authorization", "user_requested", "direct_opened", "direct_closed"}
)


class ConversationEvent(ProtocolModel):
    """One ordered PAP conversation event, including unknown future types."""

    id: str
    type: str = Field(min_length=1)
    created_at: datetime
    message: Message | None = None
    #: A `state` event's fields (§8.7): `handoff`, `responder` and `closed`, after any
    #: of them changes; `working` is never an event.
    handoff: Literal["none", "pending"] | None = None
    responder: Literal["agent", "human"] | None = None
    closed: bool | None = None
    error: Literal["insufficient_scope"] | None = None
    scope: str | None = None
    reason: str | None = None
    conversation_id: str | None = None

    @field_validator("id", "conversation_id")
    @classmethod
    def validate_ids(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError("conversation event IDs must use the URL-safe base64 alphabet")
        return value

    _handoff = field_validator("handoff", mode="before")(
        classmethod(lambda cls, value: known_handoff(value))
    )
    _responder = field_validator("responder", mode="before")(
        classmethod(lambda cls, value: known_responder(value))
    )

    @property
    def known(self) -> bool:
        """Whether this SDK knows the type; an unknown one is skipped, never an error."""

        return self.type in KNOWN_EVENT_TYPES

    @field_validator("created_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_known_type(self) -> ConversationEvent:
        if self.type == "message" and self.message is None:
            raise ValueError("a message event requires message")
        if self.type == "state" and (
            self.handoff is None or self.responder is None or self.closed is None
        ):
            raise ValueError("a state event requires handoff, responder and closed")
        if self.type == "authorization":
            # Always both: the error, and the scopes the request needs (§7.11).
            if self.error is None or not self.scope:
                raise ValueError("an authorization event requires error and scope")
        if self.type == "user_requested" and not self.reason:
            raise ValueError("a user_requested event requires reason")
        if self.type in {"direct_opened", "direct_closed"} and self.conversation_id is None:
            raise ValueError("a direct conversation event requires conversation_id")
        return self


class ConversationEventPage(ProtocolModel):
    """A cursor page returned by a PAP conversation read or waited write, with the
    conversation's state when the Company responded (§8.5, §8.7).

    While `has_more` is true the state fields can be newer than the events returned: a
    reader applies the events in order and relies on the state once `has_more` is false.
    """

    conversation_id: str
    events: list[ConversationEvent]
    cursor: str
    has_more: bool
    working: bool
    handoff: Literal["none", "pending"]
    responder: Literal["agent", "human"]
    closed: bool

    _handoff = field_validator("handoff", mode="before")(
        classmethod(lambda cls, value: known_handoff(value))
    )
    _responder = field_validator("responder", mode="before")(
        classmethod(lambda cls, value: known_responder(value))
    )

    @property
    def state(self) -> ConversationState:
        """The four state fields together (§8.7)."""

        return ConversationState(
            working=self.working,
            handoff=self.handoff,
            responder=self.responder,
            closed=self.closed,
        )

    @field_validator("conversation_id", "cursor")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("conversation IDs and cursors must use the URL-safe base64 alphabet")
        return value


class AlternativeReference(ProtocolModel):
    """Where an alternative points (§8.2): an OpenAPI operation, an MCP tool, or a page."""

    type: str = Field(min_length=1)
    url: str | None = None
    operation_id: str | None = Field(default=None, min_length=1)
    tool: str | None = Field(default=None, min_length=1)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        return None if value is None else _https_url(value, "reference URL")

    @model_validator(mode="after")
    def validate_fields(self) -> AlternativeReference:
        needed = {"openapi": ("url", "operation_id"), "mcp": ("url", "tool"), "web": ("url",)}
        if any(getattr(self, name) is None for name in needed.get(self.type, ())):
            raise ValueError(f"a {self.type} reference lacks a required field")
        return self


class Alternative(ProtocolModel):
    """Another way to do a task (§8.2): `instructions`, `references`, or both.

    Content from the company (§9.1): a description of its interfaces, never
    instructions the agent has to follow.
    """

    instructions: str | None = Field(default=None, min_length=1)
    references: list[AlternativeReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_content(self) -> Alternative:
        if self.instructions is None and not self.references:
            raise ValueError("an alternative needs instructions or references")
        return self

    def usable_references(self, document: DiscoveryDocument) -> list[AlternativeReference]:
        """The references an agent may follow (§8.2).

        Types it knows only, and an `openapi` or `mcp` reference only when its `url`
        is an API of that type the company's poppy.json lists: never another
        company's server.
        """

        listed = {(api.type, api.url) for api in document.apis}
        return [
            reference
            for reference in self.references
            if reference.type == "web"
            or (reference.type in {"openapi", "mcp"} and (reference.type, reference.url) in listed)
        ]


class ExcludedTask(ProtocolModel):
    """A task the company chose not to offer through the protocol (§8.1)."""

    task: str = Field(min_length=1, max_length=200)
    alternative: Alternative | None = None


class ExcludedTasks(ProtocolModel):
    """The document at `excluded_tasks.url` (§8.1): the same for every user."""

    tasks: list[ExcludedTask]


class DiscoveredCompany(ProtocolModel):
    """A verified `poppy.json`, its domain's protected resource metadata, and its issuer's.

    A Company with no issuer has no `oauth_metadata`, and `resource_metadata` only when
    the domain publishes it with no authorization server; it offers no sign-in (§3.2).
    """

    discovery_url: str
    document: DiscoveryDocument
    oauth_metadata: OAuthServerMetadata | None = None
    resource_metadata: ProtectedResourceMetadata | None = None

    @property
    def issuer(self) -> str | None:
        """The Company's OAuth issuer, as found from its domain (§3.2)."""

        return None if self.oauth_metadata is None else self.oauth_metadata.issuer

    @property
    def resource(self) -> str:
        """`https://{organization.domain}`: the resource the default access token is for."""

        return f"https://{self.document.organization.domain}"

    @property
    def identifier(self) -> str:
        """Who the Company is (§3.2): its issuer, else `https://{organization.domain}`.

        Session JWTs name it in `aud`, and User IDs and Agent IDs are scoped by it. Discovery
        reaches the domain only when it established that there is no issuer: never after an
        error, a timeout, or an issuer that failed to verify.
        """

        return self.issuer or self.resource

    @property
    def sign_in_disabled(self) -> bool:
        """Whether the Company turned sign-in off with `auth.disabled` (§3.2)."""

        return self.document.sign_in_disabled

    @property
    def protocol_version(self) -> str:
        """The protocol version the Company is used at (§3.4): `document` is that
        version's document, and every Session with the Company names it in `Poppy-Version`."""

        return self.document.protocol_version

    @property
    def sign_in_types(self) -> tuple[str, ...]:
        """The sign-in types the Company offers a Personal Agent, in the order it prefers
        them (§4): `direct`, then `device`, then `mediated`.

        Direct and Device Sign-In are the issuer's grants, Mediated Sign-In its grant with
        the extension listed; none at all without an issuer or with sign-in turned off.
        """

        metadata = self.oauth_metadata
        if metadata is None or self.sign_in_disabled:
            return ()
        offered = (
            metadata.offers_direct,
            metadata.offers_device,
            MEDIATED_EXTENSION in self.document.extensions
            and MEDIATED_GRANT in metadata.grant_types_supported,
        )
        return tuple(name for name, yes in zip(SIGN_IN_TYPES, offered, strict=True) if yes)

    @property
    def preferred_sign_in(self) -> str | None:
        """The sign-in type to use (§4): Direct Sign-In when the Company offers it, else Device
        Sign-In, else Mediated Sign-In; `None` when it offers none."""

        types = self.sign_in_types
        return types[0] if types else None

    @property
    def skills(self) -> list[SkillEntry]:
        """The Company's skills this SDK can use (§9.4), resolved against `discovery_url`."""

        return self.document.usable_skills(self.discovery_url)

    def require_oauth(self) -> OAuthServerMetadata:
        """The issuer's metadata, or `AuthorizationError`, before any sign-in.

        `no_issuer` for a Company with no issuer, `sign_in_disabled` for one that turned
        sign-in off (§3.2): a Personal Agent starts no sign-in with either.
        """

        if self.oauth_metadata is None:
            raise AuthorizationError("no_issuer", "A Company with no issuer offers no sign-in")
        if self.sign_in_disabled:
            raise AuthorizationError(
                "sign_in_disabled", "The Company turned sign-in off for Personal Agents"
            )
        return self.oauth_metadata
