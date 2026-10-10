# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Safe primitives for PAP Direct Sign-In with OAuth and PKCE."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Callable, Iterable
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from pydantic import Field, SecretStr, field_validator

from .errors import AuthorizationError
from .models import ProtocolModel
from .sessions import JWT_CLIENT_ASSERTION

RandomBytes = Callable[[int], bytes]
_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5b\x5d-\x7e]+$")
_AUTHORIZATION_PARAMETERS = {
    "response_type",
    "client_id",
    "redirect_uri",
    "scope",
    "state",
    "code_challenge",
    "code_challenge_method",
}


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _entropy(length: int, random_bytes: RandomBytes) -> bytes:
    value = random_bytes(length)
    if len(value) < length:
        raise AuthorizationError("weak_entropy", f"authorization requires {length * 8} random bits")
    return value


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise AuthorizationError("invalid_url", f"{label} must be an HTTPS URL")
    return value


def _scopes(values: Iterable[str]) -> tuple[str, ...]:
    scopes = tuple(dict.fromkeys(values))
    if not scopes or any(not _SCOPE_TOKEN.fullmatch(scope) for scope in scopes):
        raise AuthorizationError("invalid_scope", "at least one valid OAuth scope is required")
    return scopes


class DirectSignInRequest(ProtocolModel):
    """Authorization request state that redacts its URL and PKCE values."""

    authorization_url: SecretStr
    issuer: str
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    state: SecretStr
    code_verifier: SecretStr

    @field_validator("issuer", "client_id", "redirect_uri")
    @classmethod
    def validate_urls(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "URL")
        return _https_url(value, str(field_name))


def build_direct_sign_in_request(
    *,
    authorization_endpoint: str,
    issuer: str,
    client_id: str,
    redirect_uri: str,
    scopes: Iterable[str],
    random_bytes: RandomBytes = secrets.token_bytes,
) -> DirectSignInRequest:
    """Build a user-browser authorization URL with random state and S256 PKCE."""

    endpoint = _https_url(authorization_endpoint, "authorization endpoint")
    validated_scopes = _scopes(scopes)
    state = _base64url(_entropy(16, random_bytes))
    verifier = _base64url(_entropy(32, random_bytes))
    challenge = _base64url(hashlib.sha256(verifier.encode("ascii")).digest())
    parsed = urlsplit(endpoint)
    query = [
        item
        for item in parse_qsl(parsed.query, keep_blank_values=True)
        if item[0] not in _AUTHORIZATION_PARAMETERS
    ]
    query.extend(
        [
            ("response_type", "code"),
            ("client_id", _https_url(client_id, "client ID")),
            ("redirect_uri", _https_url(redirect_uri, "redirect URI")),
            ("scope", " ".join(validated_scopes)),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ]
    )
    authorization_url = urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(query, quote_via=quote), "")
    )
    return DirectSignInRequest(
        authorization_url=SecretStr(authorization_url),
        issuer=_https_url(issuer, "issuer"),
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=validated_scopes,
        state=SecretStr(state),
        code_verifier=SecretStr(verifier),
    )


class DirectSignInCallback(ProtocolModel):
    """Validated one-time authorization code."""

    code: SecretStr
    issuer: str


def validate_direct_sign_in_callback(
    request: DirectSignInRequest,
    callback_url: str,
) -> DirectSignInCallback:
    """Validate redirect location, state, and issuer before exposing the code."""

    expected = urlsplit(request.redirect_uri)
    callback = urlsplit(_https_url(callback_url, "callback URL"))
    if callback.fragment:
        raise AuthorizationError("invalid_callback", "authorization callback has a fragment")
    if (callback.scheme, callback.netloc, callback.path) != (
        expected.scheme,
        expected.netloc,
        expected.path,
    ):
        raise AuthorizationError("redirect_mismatch", "callback does not match redirect URI")
    expected_query = dict(parse_qsl(expected.query, keep_blank_values=True))
    pairs = parse_qsl(callback.query, keep_blank_values=True)
    for key in ("code", "state", "iss", "error"):
        if sum(name == key for name, _ in pairs) > 1:
            raise AuthorizationError(
                "invalid_callback", "authorization callback repeats a security parameter"
            )
    values = dict(pairs)
    if any(values.get(key) != value for key, value in expected_query.items()):
        raise AuthorizationError("redirect_mismatch", "callback changed redirect URI parameters")
    if "error" in values:
        raise AuthorizationError("authorization_denied", "company did not authorize the request")
    if not hmac.compare_digest(values.get("state", ""), request.state.get_secret_value()):
        raise AuthorizationError("state_mismatch", "authorization state does not match")
    if values.get("iss") != request.issuer:
        raise AuthorizationError("issuer_mismatch", "authorization issuer does not match")
    code = values.get("code")
    if not code:
        raise AuthorizationError("invalid_callback", "authorization callback has no code")
    return DirectSignInCallback(code=SecretStr(code), issuer=request.issuer)


class AuthorizationCodeGrant(ProtocolModel):
    """Redacted PAP authorization-code exchange values."""

    code: SecretStr
    redirect_uri: str
    code_verifier: SecretStr
    session_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,256}$")
    client_id: str
    client_assertion: SecretStr

    @field_validator("redirect_uri", "client_id")
    @classmethod
    def validate_urls(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "URL")
        return _https_url(value, str(field_name))

    def as_form(self) -> dict[str, str]:
        """Reveal secrets only at the final token-request boundary."""

        return {
            "grant_type": "authorization_code",
            "code": self.code.get_secret_value(),
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.code_verifier.get_secret_value(),
            "session_id": self.session_id,
            "client_id": self.client_id,
            "client_assertion_type": JWT_CLIENT_ASSERTION,
            "client_assertion": self.client_assertion.get_secret_value(),
        }
