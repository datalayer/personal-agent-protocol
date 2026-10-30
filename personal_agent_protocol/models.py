# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Wire models for Personal Agent Protocol draft 0.3."""

from __future__ import annotations

import re
from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

_VERSION = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)$")
#: The `protocol_version` values this SDK uses a document of (§3.1): before 1.0 every
#: version can break the one before, so only its own `major.minor`.
SUPPORTED_PROTOCOL_VERSIONS = frozenset({"0.3"})
#: The DPoP algorithm every company accepts (§3.2): a list a company publishes includes it.
DPOP_REQUIRED_ALGORITHM = "ES256"
_EXTENSION_VERSION = re.compile(r"^(0|[1-9][0-9]*)$")
#: OAuth scope syntax (RFC 6749 §3.3): one scope token.
_SCOPE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")
#: The grants a Company's token endpoint MUST accept (§3.2): starting and renewing Sessions,
#: and Account Tokens.
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
REFRESH_TOKEN_GRANT = "refresh_token"  # noqa: S105 - an OAuth token or grant type, not a credential
#: The grants that say the Company offers Direct and Device Sign-In (§3.2, §4.4).
AUTHORIZATION_CODE_GRANT = "authorization_code"
DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
#: The grant for a Bearer token at an MCP server that doesn't support DPoP (§4.3).
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - an OAuth token or grant type, not a credential
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

    _normalize_domain = field_validator("domain")(_domain)


class ScopeOption(ProtocolModel):
    scopes: list[str] = Field(default_factory=list)


class MediatedField(ProtocolModel):
    name: str = Field(min_length=1)
    label: str = Field(min_length=1)
    secret: bool


class MediatedSignIn(ScopeOption):
    """Mediated Sign-In, transitional (§4.7): the only sign-in type with its own scopes."""

    endpoint: str
    fields: list[MediatedField] = Field(min_length=1)

    _scopes = field_validator("scopes")(lambda value: [_scope(item) for item in value])

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return _https_url(value, "mediated sign-in endpoint")


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
    """`auth` (§3.1): optional; the issuer it names, Mediated Sign-In, the Company's scopes.

    `issuer` is needed only when the domain's protected resource metadata lists more
    than one authorization server, and then names one of them; with one, it may be
    left out, and if present names that one (§3.1, §3.2). Direct and Device Sign-In are
    not here: the issuer's `grant_types_supported` says whether the Company offers them.
    """

    issuer: str | None = None
    mediated: MediatedSignIn | None = None
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
    type: str = Field(min_length=1)
    endpoint: str

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
    browser_session_endpoint: str | None = None

    @field_validator("browser_session_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str | None) -> str | None:
        return _https_url(value, "browser session endpoint") if value is not None else None


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
    organization: Organization
    auth: AuthCapabilities | None = None
    agent: AgentDescriptor | None = None
    web: WebDescriptor | None = None
    apis: list[ApiDescriptor] = Field(default_factory=list)
    feedback: FeedbackDescriptor | None = None
    excluded_tasks: ExcludedTasksDescriptor | None = None
    extensions: dict[str, ExtensionDescriptor] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def validate_protocol_version(cls, value: str) -> str:
        if not _VERSION.fullmatch(value):
            raise ValueError("protocol_version must use major.minor")
        if value not in SUPPORTED_PROTOCOL_VERSIONS:
            # Before 1.0 a document is used only at a major.minor this SDK supports (§3.1).
            raise ValueError("unsupported Personal Agent Protocol version")
        return value

    @model_validator(mode="after")
    def validate_interfaces(self) -> DiscoveryDocument:
        if self.agent is None and not self.apis and self.web is None:
            raise ValueError("one of agent, apis, or web is required")
        return self

    @property
    def needs_issuer(self) -> bool:
        """Whether the Company must have an OAuth issuer (§3.2).

        One that lists `agent`, `apis`, `feedback`, `web.browser_session_endpoint`,
        or an extension: without an issuer it can only be browsed as a website.
        """

        return (
            self.agent is not None
            or bool(self.apis)
            or self.feedback is not None
            or bool(self.web and self.web.browser_session_endpoint)
            or bool(self.extensions)
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

    @property
    def offers_token_exchange(self) -> bool:
        """Whether Bearer tokens for MCP servers without DPoP can be had (§4.3)."""

        return TOKEN_EXCHANGE_GRANT in self.grant_types_supported

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

    @field_validator("dpop_signing_alg_values_supported")
    @classmethod
    def validate_dpop_algorithms(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and DPOP_REQUIRED_ALGORITHM not in value:
            raise ValueError("dpop_signing_alg_values_supported must include ES256")
        return value

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
    its issuer in `authorization_servers`; a service that accepts only tokens issued
    for it publishes it with its own `resource`, as MCP servers do (§4.5, §7).
    """

    resource: str
    authorization_servers: list[str] = Field(min_length=1)
    scopes_supported: list[str] = Field(default_factory=list)
    bearer_methods_supported: list[str] = Field(default_factory=list)

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
    token_endpoint_auth_method: Literal["private_key_jwt"] = "private_key_jwt"  # noqa: S105
    extensions: dict[str, ExtensionDescriptor] = Field(default_factory=dict)

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
    alg: Literal["ES256", "RS256"] | None = None
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
        elif self.alg not in {None, "RS256"}:
            raise ValueError("RSA signing keys may advertise only RS256")
        return self


class JsonWebKeySet(ProtocolModel):
    """A non-empty set of public keys suitable for PAP assertion verification."""

    keys: list[JsonWebKey] = Field(min_length=1)


class OperationResult(ProtocolModel):
    summary: str = Field(min_length=1)
    data: dict[str, Any] | None = None


class OperationConfirmation(ProtocolModel):
    revision: int = Field(ge=1)
    approved_by: Literal["user", "standing_permission"]
    confirmed_at: datetime

    @field_validator("confirmed_at")
    @classmethod
    def validate_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("confirmed_at must include a timezone")
        return value


class Operation(ProtocolModel):
    operation_id: str
    revision: int = Field(ge=1)
    state: Literal["proposed", "in_progress", "succeeded", "failed", "cancelled", "expired"]
    summary: str = Field(min_length=1)
    terms: dict[str, Any] | None = None
    expires_at: datetime | None = None
    user_approval_required: bool = False
    url: str | None = None
    confirmation: OperationConfirmation | None
    result: OperationResult | None

    @model_serializer(mode="wrap")
    def _absent_not_null(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Optional members with no value are absent, never `null` (Operations §3).

        Only `confirmation` and `result` are "null until" something happens;
        `expires_at` (required while proposed), `terms`, and `url` are omitted.
        """

        value = handler(self)
        for name in ("expires_at", "terms", "url"):
            if value.get(name) is None:
                value.pop(name, None)
        return value

    @field_validator("operation_id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("operation ID must use the URL-safe base64 alphabet")
        return value

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        return _https_url(value, "operation URL") if value is not None else None

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> Operation:
        if self.state == "proposed" and self.expires_at is None:
            raise ValueError("a proposed operation requires expires_at")
        if self.state == "proposed" and self.confirmation is not None:
            raise ValueError("a proposed operation cannot be confirmed")
        if self.confirmation and self.confirmation.revision != self.revision:
            raise ValueError("confirmation must name the current revision")
        final = self.state in {"succeeded", "failed", "cancelled", "expired"}
        if final and self.result is None:
            raise ValueError("a final operation requires a result")
        return self


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
    """Message sent by either side or returned in a conversation event."""

    id: str
    author: Author
    role: Literal["user", "company"] | None = None
    text: str | None = None
    data: dict[str, Any] | None = None
    context: dict[str, Any] | None = None
    operation: Operation | None = None

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("message ID must use the URL-safe base64 alphabet")
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
        if all(value is None for value in (self.text, self.data, self.context, self.operation)):
            raise ValueError("a message requires text, data, context, or operation")
        return self


#: The conversation statuses and responders this version defines (§8.7).
CONVERSATION_STATUSES = ("working", "idle", "queued", "closed")
RESPONDERS = ("agent", "human")


def known_status(value: object) -> object:
    """A `status` this SDK doesn't recognize reads as `working` (§8.7)."""

    return value if not isinstance(value, str) or value in CONVERSATION_STATUSES else "working"


def known_responder(value: object) -> object:
    """A `responder` this SDK doesn't recognize reads as `human` (§8.7)."""

    return value if not isinstance(value, str) or value in RESPONDERS else "human"


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
    status: Literal["working", "idle", "queued", "closed"] | None = None
    responder: Literal["agent", "human"] | None = None
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

    _status = field_validator("status", mode="before")(
        classmethod(lambda cls, value: known_status(value))
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
        if self.type == "state" and (self.status is None or self.responder is None):
            raise ValueError("a state event requires status and responder")
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
    """A cursor page returned by a PAP conversation read or waited write."""

    conversation_id: str
    events: list[ConversationEvent]
    cursor: str
    has_more: bool
    status: Literal["working", "idle", "queued", "closed"]
    responder: Literal["agent", "human"]

    _status = field_validator("status", mode="before")(
        classmethod(lambda cls, value: known_status(value))
    )
    _responder = field_validator("responder", mode="before")(
        classmethod(lambda cls, value: known_responder(value))
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

    `resource_metadata` and `oauth_metadata` are `None` only for a Company that has
    no issuer, which can only be browsed as a website (§3.2).
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
