# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Operator signatures: an HTTP Message Signature beside the Session header (§5.3).

A Personal Agent SHOULD sign requests that carry the Session header with RFC 9421 and
Web Bot Auth (`draft-ietf-webbotauth-httpsig-protocol-01`), so traffic-management
infrastructure can authenticate the operator before the Company's application sees the
request. It is compatibility support, not a credential: its absence does not make a
Session JWT invalid, and a verified one authenticates its key source, never a `client_id`.

- `WebBotAuthSigner` is what a host contributes to `pap.operatorSigner`, which has no
  default: the key is the operator's, published in a directory the host serves. It
  covers the authority, the `Signature-Agent` member, the method, path and query,
  `poppy-session`, and `authorization` when present (§5.3). `Ed25519OperatorKey` keeps
  the key in this process; a key in a KMS is any `OperatorSigningKey`.
- `operator_directory` is the key set a host publishes at its `Signature-Agent` URL.
- `verify_operator_signature` is a Company's side, with the draft's outcomes kept apart:
  `absent`, `verified`, `invalid` and `unverified`. Each is the Company's to act on.

Operator keys are never delegated keys, DPoP keys or keys from `jwks_uri`, and a device
never holds a shared operator key (Guides, operator signatures).
"""

from __future__ import annotations

import base64
import re
import secrets
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol, cast, runtime_checkable

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .crypto import jwk_thumbprint
from .errors import PersonalAgentProtocolError, ProofError
from .reactor import OperatorSignature, OperatorSignatureRequest

#: The headers of a signed request (RFC 9421 §4; Web Bot Auth §5.2.5).
SIGNATURE_HEADER = "Signature"
SIGNATURE_INPUT_HEADER = "Signature-Input"
SIGNATURE_AGENT_HEADER = "Signature-Agent"
#: The tag that marks a signature as Web Bot Auth's (§5.2).
WEB_BOT_AUTH_TAG = "web-bot-auth"
#: The RFC 9421 algorithm these signatures use.
OPERATOR_SIGNATURE_ALGORITHM = "ed25519"
#: The label a signature, and its `Signature-Agent` member, go by.
OPERATOR_SIGNATURE_LABEL = "sig1"
#: A signature lives this long: each request and retry gets a fresh one.
OPERATOR_SIGNATURE_LIFETIME = timedelta(seconds=60)
#: The well-known URL of an operator's directory, and its media type (Web Bot Auth §8).
OPERATOR_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory"
OPERATOR_DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json"
#: The components a signature covers before `poppy-session` and `authorization`.
OPERATOR_SIGNATURE_COMPONENTS = ("@authority", "signature-agent", "@method", "@path", "@query")
#: A Company's refusal of a signature, at 403: this SDK's code, as the spec names none.
OPERATOR_SIGNATURE_REFUSED = "operator_signature_refused"
#: No more signatures are read from one request.
MAX_OFFERED_SIGNATURES = 8

_DERIVED = frozenset({"@method", "@authority", "@path", "@query", "@target-uri"})
_KEY = re.compile(r"[a-z*][a-z0-9_\-.*]*")
_TOKEN = re.compile(r"[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*")
_NUMBER = re.compile(r"-?[0-9]{1,15}(\.[0-9]{1,3})?")
_BYTES = re.compile(r"[A-Za-z0-9+/=]*")


@runtime_checkable
class OperatorSigningKey(Protocol):
    """An operator's key: `keyid` is its RFC 8037 thumbprint, and it signs with Ed25519."""

    @property
    def keyid(self) -> str: ...

    async def sign(self, data: bytes) -> bytes: ...


@dataclass(frozen=True)
class Ed25519OperatorKey:
    """An operator's Ed25519 key in this process's memory."""

    private_key: Ed25519PrivateKey
    public_jwk: dict[str, str]
    keyid: str

    async def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)


def operator_key_from(private_key: Ed25519PrivateKey) -> Ed25519OperatorKey:
    """The `Ed25519OperatorKey` of a private key."""

    raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public = {"kty": "OKP", "crv": "Ed25519", "x": _base64url(raw)}
    return Ed25519OperatorKey(private_key, public, jwk_thumbprint(public))


def new_operator_key() -> Ed25519OperatorKey:
    """A new Ed25519 key, used for nothing but operator signatures (§5.3)."""

    return operator_key_from(Ed25519PrivateKey.generate())


def operator_directory(keys: Sequence[Ed25519OperatorKey]) -> dict[str, Any]:
    """The JWK Set a host serves at its `Signature-Agent` URL (Web Bot Auth §5.5.1)."""

    return {"keys": [{**key.public_jwk, "kid": key.keyid, "use": "sig"} for key in keys]}


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


# Signature bases (RFC 9421 §2) ----------------------------------------------------------


@dataclass(frozen=True)
class _Component:
    """One covered component: its name, its `key` parameter, and its identifier as sent."""

    name: str
    key: str | None
    identifier: str


def _covered(names: Sequence[str], label: str) -> list[_Component]:
    return [
        _Component(name, label, f'"{name}";key="{label}"')
        if name == "signature-agent"
        else _Component(name, None, f'"{name}"')
        for name in names
    ]


def _derived(name: str, method: str, url: str) -> str:
    target = httpx.URL(url)
    path, _, query = target.raw_path.decode("ascii").partition("?")
    if name == "@method":
        return method.upper()
    if name == "@authority":
        return target.netloc.decode("ascii")
    if name == "@path":
        return path or "/"
    if name == "@query":
        return f"?{query}"
    return str(target)


def _value(
    component: _Component, method: str, url: str, headers: Mapping[str, str], agent: str | None
) -> str:
    if component.name in _DERIVED:
        return _derived(component.name, method, url)
    if component.key is not None:
        if agent is None:
            raise ValueError("a component's member is absent")
        return agent
    value = headers.get(component.name)
    if value is None:
        raise ValueError("a covered header is absent")
    return value.strip()


def _base(
    covered: Sequence[_Component],
    parameters: str,
    method: str,
    url: str,
    headers: Mapping[str, str],
    agent: str | None,
) -> bytes:
    lines = [
        f"{component.identifier}: {_value(component, method, url, headers, agent)}"
        for component in covered
    ]
    return "\n".join([*lines, f'"@signature-params": {parameters}']).encode()


# Signing --------------------------------------------------------------------------------


async def sign_operator_request(
    request: OperatorSignatureRequest,
    key: OperatorSigningKey,
    *,
    signature_agent: str,
    created: int,
    expires: int,
    nonce: str,
    tag: str = WEB_BOT_AUTH_TAG,
    components: Sequence[str] | None = None,
) -> OperatorSignature:
    """The signature of one request, its `created`, `expires` and `nonce` given.

    `components` defaults to what §5.3 and Web Bot Auth ask: `authorization` joins
    `poppy-session` when the request has one.
    """

    if not signature_agent.startswith("https://") or re.search(r'["\\\s]', signature_agent):
        raise ValueError("a Signature-Agent is an HTTPS URL")
    label = OPERATOR_SIGNATURE_LABEL
    authorization = request.authorization
    headers = {"poppy-session": request.session_jwt.get_secret_value()}
    if authorization is not None:
        headers["authorization"] = authorization.get_secret_value()
    names = components or (*OPERATOR_SIGNATURE_COMPONENTS, *headers)
    covered = _covered(names, label)
    listed = " ".join(component.identifier for component in covered)
    parameters = (
        f'({listed});created={created};keyid="{key.keyid}";alg="{OPERATOR_SIGNATURE_ALGORITHM}"'
        f';expires={expires};nonce="{nonce}";tag="{tag}"'
    )
    agent = f'"{signature_agent}"'
    base = _base(covered, parameters, request.method, request.url, headers, agent)
    value = base64.b64encode(await key.sign(base)).decode()
    return OperatorSignature(
        signature_agent=f"{label}={agent}",
        signature_input=f"{label}={parameters}",
        signature=f"{label}=:{value}:",
    )


class WebBotAuthSigner:
    """`pap.operatorSigner`: a fresh Web Bot Auth signature for each request (§5.3).

    `signature_agent` is the HTTPS URL that serves the key in `operator_directory`.
    It signs for every tenant with its one key: a host with a key per tenant contributes
    a signer of its own over `sign_operator_request`.
    """

    def __init__(
        self,
        key: OperatorSigningKey,
        *,
        signature_agent: str,
        now: Callable[[], datetime] | None = None,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        lifetime: timedelta = OPERATOR_SIGNATURE_LIFETIME,
    ) -> None:
        if lifetime <= timedelta(0):
            raise ValueError("an operator signature's lifetime must be positive")
        self.key = key
        self.signature_agent = signature_agent
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.random_bytes = random_bytes
        self.lifetime = lifetime

    async def sign(self, request: OperatorSignatureRequest) -> OperatorSignature:
        issued = self.now()
        if issued.tzinfo is None:
            raise ProofError("invalid_clock", "The operator signature's clock must be aware")
        random = self.random_bytes(32)
        if len(random) != 32:
            raise ProofError("weak_randomness", "An operator signature's nonce needs 256 bits")
        created = int(issued.timestamp())
        return await sign_operator_request(
            request,
            self.key,
            signature_agent=self.signature_agent,
            created=created,
            expires=created + int(self.lifetime.total_seconds()),
            nonce=_base64url(random),
        )


# Reading signatures (RFC 8941) -----------------------------------------------------------


@dataclass(frozen=True)
class _Field:
    """A dictionary member or inner-list item: its value, parameters and text as sent."""

    value: Any
    parameters: dict[str, Any]
    raw: str


class _Parser:
    """The parts of RFC 8941 these headers use; anything else raises `ValueError`."""

    def __init__(self, text: str) -> None:
        self.text = text.strip(" ")
        self.at = 0

    def _peek(self) -> str:
        return self.text[self.at] if self.at < len(self.text) else ""

    def _match(self, pattern: re.Pattern[str]) -> str:
        found = pattern.match(self.text, self.at)
        if found is None:
            raise ValueError("a malformed structured field")
        self.at = found.end()
        return found.group()

    def _spaces(self, *allowed: str) -> None:
        while self._peek() and self._peek() in (allowed or " "):
            self.at += 1

    def _string(self) -> str:
        self.at += 1
        out: list[str] = []
        while True:
            char = self._peek()
            if not char or not " " <= char <= "~":
                raise ValueError("an unterminated string")
            self.at += 1
            if char == '"':
                return "".join(out)
            if char == "\\":
                char = self._peek()
                if char not in ('"', "\\"):
                    raise ValueError("a bad escape")
                self.at += 1
            out.append(char)

    def _bare(self) -> Any:
        char = self._peek()
        if char == '"':
            return self._string()
        if char == ":":
            self.at += 1
            encoded = self._match(_BYTES)
            if self._peek() != ":" or len(encoded) % 4:
                raise ValueError("a malformed byte sequence")
            self.at += 1
            return base64.b64decode(encoded, validate=True)
        if char == "?":
            self.at += 2
            if self.text[self.at - 1 : self.at] not in ("0", "1"):
                raise ValueError("a malformed boolean")
            return self.text[self.at - 1] == "1"
        if char == "-" or char.isdigit():
            number = self._match(_NUMBER)
            return float(number) if "." in number else int(number)
        return self._match(_TOKEN)

    def _parameters(self) -> dict[str, Any]:
        parameters: dict[str, Any] = {}
        while self._peek() == ";":
            self.at += 1
            self._spaces()
            name = self._match(_KEY)
            value: Any = True
            if self._peek() == "=":
                self.at += 1
                value = self._bare()
            parameters[name] = value
        return parameters

    def _item(self) -> _Field:
        start = self.at
        value = self._bare()
        parameters = self._parameters()
        return _Field(value, parameters, self.text[start : self.at])

    def _member(self) -> _Field:
        if self._peek() != "(":
            return self._item()
        start = self.at
        self.at += 1
        items: list[_Field] = []
        while True:
            self._spaces()
            if self._peek() == ")":
                self.at += 1
                break
            items.append(self._item())
            if self._peek() not in (" ", ")"):
                raise ValueError("a malformed inner list")
        parameters = self._parameters()
        return _Field(items, parameters, self.text[start : self.at])

    def dictionary(self) -> dict[str, _Field]:
        members: dict[str, _Field] = {}
        while self.at < len(self.text):
            name = self._match(_KEY)
            if self._peek() == "=":
                self.at += 1
                members[name] = self._member()
            else:
                members[name] = _Field(True, self._parameters(), "?1")
            self._spaces(" ", "\t")
            if self.at == len(self.text):
                break
            if self._peek() != ",":
                raise ValueError("a malformed dictionary")
            self.at += 1
            self._spaces(" ", "\t")
            if self.at == len(self.text):
                raise ValueError("a trailing comma")
        return members


# Verifying ------------------------------------------------------------------------------

Outcome = Literal["absent", "verified", "invalid", "unverified"]
#: Keys published at a `Signature-Agent` URL: the URL and the `keyid` asked of it.
OperatorKeys = Callable[[str, str], Awaitable[Sequence[Mapping[str, Any]]]]


@dataclass(frozen=True)
class OperatorVerdict:
    """What one request's operator signature came to (Web Bot Auth, appendix C.1).

    `absent`: none offered, or none tagged `web-bot-auth`. `verified`: `operator` is the
    `Signature-Agent` URL that provided the key. `invalid`: a signature, component or
    freshness check failed. `unverified`: no key to decide with, as the directory could
    not be read, does not list it, or it isn't Ed25519.
    """

    outcome: Outcome
    operator: str | None = None


@dataclass(frozen=True)
class _Offered:
    """One signature tagged `web-bot-auth`: what is needed to check it."""

    label: str
    covered: tuple[_Component, ...]
    parameters: dict[str, Any]
    parameters_text: str
    signature: bytes
    agent: _Field


def _component(item: _Field) -> _Component:
    name = item.value
    if not isinstance(name, str) or not name:
        raise ValueError("a component is a string")
    extra = set(item.parameters) - {"key"}
    key = item.parameters.get("key")
    if extra or (key is not None and (name != "signature-agent" or not isinstance(key, str))):
        raise ValueError("a component's parameters aren't supported")
    if name.startswith("@") and name not in _DERIVED:
        raise ValueError("a derived component isn't supported")
    return _Component(name, key, item.raw)


def _offered(headers: Mapping[str, str]) -> list[_Offered]:
    """The signatures tagged `web-bot-auth`; `ValueError` when the headers don't parse."""

    text = headers.get("signature-input")
    if text is None:
        return []
    inputs = _Parser(text).dictionary()
    if len(inputs) > MAX_OFFERED_SIGNATURES:
        raise ValueError("too many signatures")
    tagged = {
        label: member
        for label, member in inputs.items()
        if isinstance(member.value, list) and member.parameters.get("tag") == WEB_BOT_AUTH_TAG
    }
    if not tagged:
        return []
    signatures = _Parser(headers.get("signature", "")).dictionary()
    agents = _Parser(headers.get("signature-agent", "")).dictionary()
    offered = []
    for label, member in tagged.items():
        signature = signatures.get(label)
        agent = agents.get(label)
        if signature is None or agent is None or not isinstance(signature.value, bytes):
            raise ValueError("a signature, or its Signature-Agent member, is absent")
        covered = tuple(_component(item) for item in member.value)
        offered.append(
            _Offered(label, covered, member.parameters, member.raw, signature.value, agent)
        )
    return offered


def _sound(offered: _Offered, headers: Mapping[str, str], now: float, window: float) -> bool:
    """The components §5.3 and Web Bot Auth §5.2 require, the parameters, and freshness."""

    names = {component.name for component in offered.covered}
    member = any(
        component.name == "signature-agent" and component.key == offered.label
        for component in offered.covered
    )
    needs = {"poppy-session", *(("authorization",) if "authorization" in headers else ())}
    created, expires = offered.parameters.get("created"), offered.parameters.get("expires")
    url = offered.agent.value
    return (
        member
        and needs <= names
        and bool(names & {"@authority", "@target-uri"})
        and type(created) is int
        and type(expires) is int
        and isinstance(offered.parameters.get("keyid"), str)
        and not offered.agent.parameters
        and isinstance(url, str)
        and url.startswith("https://")
        and created <= now + window
        and created < expires
        and now < expires
    )


async def _checked(
    offered: _Offered,
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    keys: OperatorKeys,
    now: float,
    window: float,
) -> OperatorVerdict:
    if not _sound(offered, headers, now, window):
        return OperatorVerdict("invalid")
    agent = cast(str, offered.agent.value)
    keyid = cast(str, offered.parameters["keyid"])
    if offered.parameters.get("alg", OPERATOR_SIGNATURE_ALGORITHM) != OPERATOR_SIGNATURE_ALGORITHM:
        return OperatorVerdict("unverified")
    try:
        published = await keys(agent, keyid)
    except PersonalAgentProtocolError:
        return OperatorVerdict("unverified")
    jwk = next((item for item in published if _thumbprint(item) == keyid), None)
    if jwk is None:
        return OperatorVerdict("unverified")
    try:
        base = _base(
            offered.covered, offered.parameters_text, method, url, headers, offered.agent.raw
        )
        key = Ed25519PublicKey.from_public_bytes(_decoded(str(jwk["x"])))
        key.verify(offered.signature, base)
    except (InvalidSignature, ValueError):
        return OperatorVerdict("invalid")
    return OperatorVerdict("verified", agent)


def _decoded(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _thumbprint(jwk: Mapping[str, Any]) -> str | None:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not jwk.get("x"):
        return None
    return jwk_thumbprint(dict(jwk))


async def verify_operator_signature(
    *,
    method: str,
    url: str,
    headers: Mapping[str, str],
    keys: OperatorKeys,
    now: datetime,
    window: timedelta = timedelta(seconds=60),
) -> OperatorVerdict:
    """What the request's operator signature comes to; `headers` are lower-case.

    One verified signature is enough. `window` is the clock skew `created` is allowed.
    The Session JWT is verified apart from this, whatever it says (§5.3).
    """

    try:
        offered = _offered(headers)
    except ValueError:
        return OperatorVerdict("invalid")
    if not offered:
        return OperatorVerdict("absent")
    verdicts = [
        await _checked(
            one,
            method=method,
            url=url,
            headers=headers,
            keys=keys,
            now=now.timestamp(),
            window=window.total_seconds(),
        )
        for one in offered
    ]
    for outcome in ("verified", "invalid"):
        for verdict in verdicts:
            if verdict.outcome == outcome:
                return verdict
    return verdicts[0]


def operator_signature_base(
    method: str, url: str, headers: Mapping[str, str], agent: str | None = None
) -> bytes:
    """The bytes the first `web-bot-auth` signature of `headers` signed (RFC 9421 §2.5)."""

    offered = _offered(headers)[0]
    return _base(
        offered.covered, offered.parameters_text, method, url, headers, agent or offered.agent.raw
    )


def accept_signature(headers: Mapping[str, str]) -> str:
    """The `Accept-Signature` of a refusal: what this request should have signed (RFC 9421 §5)."""

    label = OPERATOR_SIGNATURE_LABEL
    names = [*OPERATOR_SIGNATURE_COMPONENTS, "poppy-session"]
    if "authorization" in headers:
        names.append("authorization")
    listed = " ".join(component.identifier for component in _covered(names, label))
    return f'{label}=({listed});created;expires;tag="{WEB_BOT_AUTH_TAG}"'


__all__ = [
    "MAX_OFFERED_SIGNATURES",
    "OPERATOR_DIRECTORY_MEDIA_TYPE",
    "OPERATOR_DIRECTORY_PATH",
    "OPERATOR_SIGNATURE_ALGORITHM",
    "OPERATOR_SIGNATURE_COMPONENTS",
    "OPERATOR_SIGNATURE_LABEL",
    "OPERATOR_SIGNATURE_LIFETIME",
    "OPERATOR_SIGNATURE_REFUSED",
    "SIGNATURE_AGENT_HEADER",
    "SIGNATURE_HEADER",
    "SIGNATURE_INPUT_HEADER",
    "WEB_BOT_AUTH_TAG",
    "Ed25519OperatorKey",
    "OperatorKeys",
    "OperatorSigningKey",
    "OperatorVerdict",
    "WebBotAuthSigner",
    "accept_signature",
    "new_operator_key",
    "operator_directory",
    "operator_key_from",
    "operator_signature_base",
    "sign_operator_request",
    "verify_operator_signature",
]
