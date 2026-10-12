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
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import cast
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx
from pydantic import Field, SecretStr, field_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import AuthorizationError, ProtocolValidationError
from .json import loads_strict
from .models import ProtocolModel
from .reactor import (
    AUTHORIZATION_STATE_STORES,
    BROWSER_HANDOFFS,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    RANDOM_SOURCES,
    SIGNERS,
    TOKEN_STORES,
    AuthorizationStateStore,
    BrowserHandoff,
    Clock,
    DpopProofProvider,
    DpopProofRequest,
    RandomSource,
    Signer,
    TokenStore,
    first_contribution,
)
from .sessions import (
    JWT_CLIENT_ASSERTION,
    ClientAssertionClaims,
    SessionToken,
    _opaque_id,
)
from .telemetry import sign_in_method, sign_in_result, signed_in_as, traced

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


class DirectSignInStart(ProtocolModel):
    """Non-secret status returned after handing authorization to the user."""

    expires_at: datetime
    requested_scopes: tuple[str, ...]


class DirectSignInResult(ProtocolModel):
    """Signed-in Session plus any scopes the company did not grant.

    The Account Token (the response's `refresh_token`) never stays in `token`:
    it is moved into `pap.tokenStore` behind `account_token_reference` (§4.8).
    """

    token: SessionToken
    granted_scopes: tuple[str, ...]
    missing_scopes: tuple[str, ...]
    account_token_reference: str | None = None


@dataclass(frozen=True)
class _PendingDirectSignIn:
    request: DirectSignInRequest
    token_endpoint: str
    tenant_id: str
    pairwise_user_id: str
    session_id: str
    expires_at: datetime


def _state_reference(state: str) -> str:
    try:
        encoded = state.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AuthorizationError("invalid_callback", "authorization state is invalid") from exc
    return "direct:" + hashlib.sha256(encoded).hexdigest()


def _callback_state(callback_url: str) -> str:
    callback = urlsplit(_https_url(callback_url, "callback URL"))
    if callback.fragment:
        raise AuthorizationError("invalid_callback", "authorization callback has a fragment")
    pairs = parse_qsl(callback.query, keep_blank_values=True)
    states = [value for name, value in pairs if name == "state"]
    if len(states) != 1 or not states[0]:
        raise AuthorizationError(
            "invalid_callback", "authorization callback must contain one state value"
        )
    return states[0]


class DirectSignInClient:
    """Orchestrate one-use browser authorization and proof-bound code exchange."""

    def __init__(
        self,
        *,
        reactor: PluginPlatform,
        http_client: httpx.AsyncClient,
        max_response_bytes: int = 100 * 1024,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.reactor = reactor
        self.http = http_client
        self.max_response_bytes = max_response_bytes

    @traced("pap.sign_in.direct.begin", before=signed_in_as("direct"), after=sign_in_result)
    async def begin(
        self,
        *,
        authorization_endpoint: str,
        token_endpoint: str,
        issuer: str,
        client_id: str,
        redirect_uri: str,
        scopes: Iterable[str],
        tenant_id: str,
        pairwise_user_id: str,
        session_id: str,
        lifetime_seconds: int = 600,
    ) -> DirectSignInStart:
        """Store one-use state, then open the authorization URL for the user."""

        if not 0 < lifetime_seconds <= 900:
            raise ValueError("Direct Sign-In state lifetime must be between 1 and 900 seconds")
        if not tenant_id or len(tenant_id) > 256:
            raise ValueError("tenant_id must contain between 1 and 256 characters")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", pairwise_user_id):
            raise ValueError("pairwise_user_id must be an opaque URL-safe identifier")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", session_id):
            raise ValueError("session_id must be an opaque URL-safe identifier")
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        random_source = cast(
            RandomSource,
            first_contribution(self.reactor, RANDOM_SOURCES, "random source"),
        )
        store = cast(
            AuthorizationStateStore,
            first_contribution(
                self.reactor,
                AUTHORIZATION_STATE_STORES,
                "authorization state store",
            ),
        )
        browser = cast(
            BrowserHandoff,
            first_contribution(self.reactor, BROWSER_HANDOFFS, "browser handoff"),
        )
        request = build_direct_sign_in_request(
            authorization_endpoint=authorization_endpoint,
            issuer=issuer,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            random_bytes=random_source.bytes,
        )
        expires_at = clock.now() + timedelta(seconds=lifetime_seconds)
        reference = _state_reference(request.state.get_secret_value())
        pending = _PendingDirectSignIn(
            request=request,
            token_endpoint=_https_url(token_endpoint, "token endpoint"),
            tenant_id=tenant_id,
            pairwise_user_id=pairwise_user_id,
            session_id=session_id,
            expires_at=expires_at,
        )
        await store.put(reference, pending, expires_at=expires_at)
        try:
            await browser.open(request.authorization_url)
        except Exception:
            await store.take(reference)
            raise
        return DirectSignInStart(
            expires_at=expires_at,
            requested_scopes=request.scopes,
        )

    @traced("pap.sign_in.direct.complete", before=sign_in_method("direct"), after=sign_in_result)
    async def complete(self, callback_url: str) -> DirectSignInResult:
        """Consume callback state and exchange its code with fresh proof material."""

        state = _callback_state(callback_url)
        store = cast(
            AuthorizationStateStore,
            first_contribution(
                self.reactor,
                AUTHORIZATION_STATE_STORES,
                "authorization state store",
            ),
        )
        pending = await store.take(_state_reference(state))
        if not isinstance(pending, _PendingDirectSignIn):
            raise AuthorizationError(
                "invalid_or_expired_state",
                "authorization state is unknown, expired, or already used",
            )
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        if clock.now() > pending.expires_at:
            raise AuthorizationError("invalid_or_expired_state", "authorization state has expired")
        callback = validate_direct_sign_in_callback(pending.request, callback_url)
        return await self._exchange(pending, callback)

    async def _exchange(
        self,
        pending: _PendingDirectSignIn,
        callback: DirectSignInCallback,
    ) -> DirectSignInResult:
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        random_source = cast(
            RandomSource,
            first_contribution(self.reactor, RANDOM_SOURCES, "random source"),
        )
        signer = cast(Signer, first_contribution(self.reactor, SIGNERS, "signer"))
        dpop = cast(
            DpopProofProvider,
            first_contribution(
                self.reactor,
                DPOP_PROOF_PROVIDERS,
                "DPoP proof provider",
            ),
        )
        nonce: str | None = None
        for attempt in range(2):
            now = clock.now()
            issued_at = int(now.timestamp())
            claims = ClientAssertionClaims(
                iss=pending.request.client_id,
                sub=pending.request.client_id,
                aud=pending.token_endpoint,
                iat=issued_at,
                exp=issued_at + 60,
                jti=_opaque_id("jti", random_source.bytes),
            )
            assertion = await signer.sign(
                claims.model_dump(),
                purpose="client_assertion",
            )
            proof = await dpop.create(
                DpopProofRequest(
                    method="POST",
                    url=pending.token_endpoint,
                    tenant_id=pending.tenant_id,
                    subject=pending.pairwise_user_id,
                    issuer=pending.request.issuer,
                    nonce=nonce,
                )
            )
            grant = AuthorizationCodeGrant(
                code=callback.code,
                redirect_uri=pending.request.redirect_uri,
                code_verifier=pending.request.code_verifier,
                session_id=pending.session_id,
                client_id=pending.request.client_id,
                client_assertion=assertion,
            )
            try:
                response = await self.http.post(
                    pending.token_endpoint,
                    data=grant.as_form(),
                    headers={"Accept": "application/json", "DPoP": proof.get_secret_value()},
                    follow_redirects=False,
                )
            except httpx.HTTPError as exc:
                raise AuthorizationError(
                    "request_failed", "Direct Sign-In token exchange failed"
                ) from exc
            payload = self._decode(response)
            if response.is_success:
                return await self._result(response, payload, pending)
            error_code = payload.get("error") if isinstance(payload, dict) else None
            safe_code = error_code if isinstance(error_code, str) else "http_error"
            if safe_code == "use_dpop_nonce" and attempt == 0:
                nonce = response.headers.get("dpop-nonce")
                if not nonce:
                    raise AuthorizationError(
                        "missing_dpop_nonce",
                        "Company requested a DPoP nonce but did not send one",
                        status_code=response.status_code,
                    )
                continue
            raise AuthorizationError(
                safe_code,
                "Company refused the Direct Sign-In token exchange",
                status_code=response.status_code,
            )
        raise AuthorizationError("use_dpop_nonce", "Company rejected the refreshed DPoP proof")

    def _decode(self, response: httpx.Response) -> object:
        if len(response.content) > self.max_response_bytes:
            raise AuthorizationError(
                "response_too_large",
                "Direct Sign-In response exceeds size limit",
                status_code=response.status_code,
            )
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
        if content_type != "application/json":
            raise AuthorizationError(
                "invalid_content_type",
                "Direct Sign-In token endpoint must return JSON",
                status_code=response.status_code,
            )
        try:
            return loads_strict(response.content)
        except ProtocolValidationError as exc:
            raise AuthorizationError(
                "invalid_json",
                "Direct Sign-In token endpoint returned invalid JSON",
                status_code=response.status_code,
            ) from exc

    async def _result(
        self,
        response: httpx.Response,
        payload: object,
        pending: _PendingDirectSignIn,
    ) -> DirectSignInResult:
        try:
            token = SessionToken.model_validate(payload)
        except (ValueError, ProtocolValidationError) as exc:
            raise AuthorizationError(
                "invalid_token_response",
                "Direct Sign-In token response is malformed",
                status_code=response.status_code,
            ) from exc
        if token.token_type != "DPoP" or not token.signed_in:  # noqa: S105 - token type
            raise AuthorizationError(
                "invalid_token_response",
                "Direct Sign-In must return a signed-in DPoP Session Token",
                status_code=response.status_code,
            )
        if token.session_id != pending.session_id:
            raise AuthorizationError(
                "session_mismatch",
                "Direct Sign-In response changed the existing Session",
                status_code=response.status_code,
            )
        requested = pending.request.scopes
        granted = token.scopes
        if any(scope not in requested for scope in granted):
            raise AuthorizationError(
                "scope_escalation",
                "Company returned a scope that was not requested",
                status_code=response.status_code,
            )
        account_reference: str | None = None
        if token.refresh_token is not None:
            # The Account Token is a secret (§4.8): behind an opaque reference, never returned.
            random_source = cast(
                RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random source")
            )
            account_reference = _opaque_id("account", random_source.bytes)
            store = cast(TokenStore, first_contribution(self.reactor, TOKEN_STORES, "token store"))
            await store.put(account_reference, token.refresh_token)
        return DirectSignInResult(
            token=token.model_copy(update={"refresh_token": None}),
            granted_scopes=granted,
            missing_scopes=tuple(scope for scope in requested if scope not in granted),
            account_token_reference=account_reference,
        )
