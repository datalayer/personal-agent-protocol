# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Wire models for Personal Agent Protocol draft 0.1."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_VERSION = re.compile(r"^(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)$")
_EXTENSION_VERSION = re.compile(r"^(0|[1-9][0-9]*)$")
_DOMAIN = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,256}$")


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError(f"{label} must be an HTTPS URL without user information")
    return value


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
    endpoint: str
    fields: list[MediatedField] = Field(min_length=1)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        return _https_url(value, "mediated sign-in endpoint")


class AuthCapabilities(ProtocolModel):
    issuer: str
    direct: ScopeOption | None = None
    device: ScopeOption | None = None
    mediated: MediatedSignIn | None = None
    custom_scopes: dict[str, str] = Field(default_factory=dict)

    @field_validator("issuer")
    @classmethod
    def validate_issuer(cls, value: str) -> str:
        return _https_url(value, "auth issuer").rstrip("/")


class AgentProtocol(ProtocolModel):
    type: str = Field(min_length=1)
    endpoint: str
    resource: str | None = None

    @field_validator("endpoint", "resource")
    @classmethod
    def validate_urls(cls, value: str | None, info: Any) -> str | None:
        return _https_url(value, info.field_name) if value is not None else None


class AgentDescriptor(ProtocolModel):
    protocols: list[AgentProtocol] = Field(min_length=1)


class ApiDescriptor(ProtocolModel):
    type: str = Field(min_length=1)
    url: str
    description: str = Field(min_length=1)
    resource: str | None = None

    @field_validator("url", "resource")
    @classmethod
    def validate_urls(cls, value: str | None, info: Any) -> str | None:
        return _https_url(value, info.field_name) if value is not None else None


class WebDescriptor(ProtocolModel):
    browser_session_endpoint: str | None = None

    @field_validator("browser_session_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str | None) -> str | None:
        return _https_url(value, "browser session endpoint") if value is not None else None


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
    extensions: dict[str, ExtensionDescriptor] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def validate_protocol_version(cls, value: str) -> str:
        match = _VERSION.fullmatch(value)
        if not match:
            raise ValueError("protocol_version must use major.minor")
        if match.group("major") != "0":
            raise ValueError("unsupported Personal Agent Protocol major version")
        return value

    @model_validator(mode="after")
    def validate_interfaces(self) -> DiscoveryDocument:
        if self.agent is None and not self.apis and self.web is None:
            raise ValueError("one of agent, apis, or web is required")
        needs_auth = self.agent is not None or bool(self.apis)
        needs_auth = needs_auth or bool(self.web and self.web.browser_session_endpoint)
        if needs_auth and self.auth is None:
            raise ValueError("auth is required for sessions, APIs, or conversations")
        return self


class OAuthServerMetadata(ProtocolModel):
    issuer: str
    token_endpoint: str
    revocation_endpoint: str
    authorization_endpoint: str | None = None
    device_authorization_endpoint: str | None = None
    poppy_domains: list[str] = Field(min_length=1)

    @field_validator(
        "issuer",
        "token_endpoint",
        "revocation_endpoint",
        "authorization_endpoint",
        "device_authorization_endpoint",
    )
    @classmethod
    def validate_urls(cls, value: str | None, info: Any) -> str | None:
        return _https_url(value, info.field_name).rstrip("/") if value is not None else None

    @field_validator("poppy_domains")
    @classmethod
    def normalize_domains(cls, value: list[str]) -> list[str]:
        return [_domain(item) for item in value]


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
        return [_https_url(item, "redirect URI") for item in value]

    @model_validator(mode="after")
    def validate_same_domain_urls(self) -> ClientMetadata:
        domain = urlsplit(self.client_id).hostname
        urls = [self.jwks_uri, *self.redirect_uris]
        if any(urlsplit(url).hostname != domain for url in urls):
            raise ValueError("jwks_uri and redirect_uris must use the client_id domain")
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


class Message(ProtocolModel):
    """Message sent by either side or returned in a conversation event."""

    id: str
    sender: Literal["agent", "human"]
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

    @model_validator(mode="after")
    def validate_content(self) -> Message:
        if all(
            value is None
            for value in (self.text, self.data, self.context, self.operation)
        ):
            raise ValueError("a message requires text, data, context, or operation")
        return self


class ConversationEvent(ProtocolModel):
    """One ordered PAP conversation event, including unknown future types."""

    id: str
    type: str = Field(min_length=1)
    created_at: datetime
    message: Message | None = None
    status: Literal["working", "idle", "queued", "closed"] | None = None
    responder: Literal["agent", "human"] | None = None
    error: Literal["sign_in_required", "insufficient_scope"] | None = None
    scope: str | None = None
    reason: str | None = None
    conversation_id: str | None = None

    @field_validator("id", "conversation_id")
    @classmethod
    def validate_ids(cls, value: str | None) -> str | None:
        if value is not None and not _IDENTIFIER.fullmatch(value):
            raise ValueError("conversation event IDs must use the URL-safe base64 alphabet")
        return value

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
            if self.error is None:
                raise ValueError("an authorization event requires error")
            if self.error == "insufficient_scope" and not self.scope:
                raise ValueError("insufficient_scope requires scope")
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

    @field_validator("conversation_id", "cursor")
    @classmethod
    def validate_ids(cls, value: str) -> str:
        if not _IDENTIFIER.fullmatch(value):
            raise ValueError("conversation IDs and cursors must use the URL-safe base64 alphabet")
        return value


class DiscoveredCompany(ProtocolModel):
    discovery_url: str
    document: DiscoveryDocument
    oauth_metadata: OAuthServerMetadata | None = None
