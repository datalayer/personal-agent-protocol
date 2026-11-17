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
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import cast
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import httpx
from pydantic import SecretStr, field_validator
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import AuthorizationError, ProtocolValidationError
from .json import loads_strict
from .models import ProtocolModel, is_loopback_redirect
from .reactor import (
    AUTHORIZATION_STATE_STORES,
    BROWSER_HANDOFFS,
    CLOCKS,
    RANDOM_SOURCES,
    AuthorizationStateStore,
    BrowserHandoff,
    Clock,
    RandomSource,
    first_contribution,
    send_bounded,
)
from .refusals import refusal_code, refuse_redirect, refused_without_body
from .sessions import (
    SessionClient,
    SignInResult,
    TokenResponse,
    finish_sign_in,
    proves_with_dpop,
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
    "prompt",
    "request_uri",
}
#: The OpenID Connect `prompt` a Direct Sign-In request carries (OpenID Connect Core
#: §3.1.2.1, §4.2): the Company shows its consent page even when the account granted
#: every scope to the `client_id` before (§10.8).
PROMPT_CONSENT = "consent"


def _json(response: httpx.Response) -> object:
    """A response's JSON body, or `None` when it has none that parses."""

    if response.headers.get("content-type", "").split(";", 1)[0].strip() != "application/json":
        return None
    try:
        return loads_strict(response.content)
    except (ProtocolValidationError, UnicodeDecodeError, ValueError):
        return None


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


def _redirect_url(value: str, label: str) -> str:
    """A redirect URI: HTTPS, or a loopback URI for an app on the User's computer (§4.1)."""

    return value if is_loopback_redirect(value) else _https_url(value, label)


def _scopes(values: Iterable[str]) -> tuple[str, ...]:
    scopes = tuple(dict.fromkeys(values))
    if not scopes or any(not _SCOPE_TOKEN.fullmatch(scope) for scope in scopes):
        raise AuthorizationError("invalid_scope", "at least one valid OAuth scope is required")
    return scopes


class DirectSignInRequest(ProtocolModel):
    """Authorization request state that redacts its URL and PKCE values.

    `authorization_url` carries every parameter; `parameters`, the same parameters form
    encoded, is what a Pushed Authorization Request sends (RFC 9126, §4.2), after which
    the browser opens `pushed_authorization_url` with only `client_id` and `request_uri`.
    """

    authorization_url: SecretStr
    issuer: str
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    state: SecretStr
    code_verifier: SecretStr
    authorization_endpoint: str | None = None
    parameters: SecretStr | None = None

    def pushed_authorization_url(self, request_uri: str) -> SecretStr:
        """The authorization URL after a push (RFC 9126 §4): `client_id` and
        `request_uri` only, on the authorization endpoint."""

        if self.authorization_endpoint is None:
            raise ValueError("this request has no authorization endpoint")
        parsed = urlsplit(self.authorization_endpoint)
        query = [
            item
            for item in parse_qsl(parsed.query, keep_blank_values=True)
            if item[0] not in _AUTHORIZATION_PARAMETERS
        ]
        query.extend([("client_id", self.client_id), ("request_uri", request_uri)])
        return SecretStr(
            urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urlencode(query, quote_via=quote), "")
            )
        )

    @field_validator("issuer", "client_id")
    @classmethod
    def validate_urls(cls, value: str, info: object) -> str:
        field_name = getattr(info, "field_name", "URL")
        return _https_url(value, str(field_name))

    @field_validator("redirect_uri")
    @classmethod
    def validate_redirect(cls, value: str) -> str:
        return _redirect_url(value, "redirect_uri")


def build_direct_sign_in_request(
    *,
    authorization_endpoint: str,
    issuer: str,
    client_id: str,
    redirect_uri: str,
    scopes: Iterable[str],
    random_bytes: RandomBytes = secrets.token_bytes,
    prompt_consent: bool = True,
) -> DirectSignInRequest:
    """Build a user-browser authorization URL with random state and S256 PKCE (§4.2).

    Plain OAuth: the sign-in names no Session, and any of the User's Sessions uses
    the tokens it returns (§5.4). It names no `resource` either: one sign-in covers
    every service the Company offers, and each token request names one (§4.5).

    `prompt_consent` adds `prompt=consent` (§4.2, §10.8), which a request MUST carry
    unless the Personal Agent receives the redirect only on the device that opened the
    authorization URL; only then is it `False`.
    """

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
    parameters = [
        ("response_type", "code"),
        ("client_id", _https_url(client_id, "client ID")),
        ("redirect_uri", _redirect_url(redirect_uri, "redirect URI")),
        ("scope", " ".join(validated_scopes)),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
    if prompt_consent:
        parameters.append(("prompt", PROMPT_CONSENT))
    query.extend(parameters)
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
        authorization_endpoint=endpoint,
        parameters=SecretStr(urlencode(parameters, quote_via=quote)),
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
    callback = urlsplit(_redirect_url(callback_url, "callback URL"))
    if callback.fragment:
        raise AuthorizationError("invalid_callback", "authorization callback has a fragment")
    # A loopback redirect URI matches with any port (RFC 8252 §7.3, §4.5).
    loopback = is_loopback_redirect(request.redirect_uri)
    if (callback.scheme, callback.hostname if loopback else callback.netloc, callback.path) != (
        expected.scheme,
        expected.hostname if loopback else expected.netloc,
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


class DirectSignInStart(ProtocolModel):
    """Non-secret status returned after handing authorization to the user."""

    expires_at: datetime
    requested_scopes: tuple[str, ...]
    #: Whether the authorization URL opens on a device other than the one the User is
    #: using (§4.2): a cross-device flow, as Device Sign-In always is (§10.8).
    cross_device: bool = False
    #: The request's `state`, for a host whose redirect lands in another service than the
    #: one that began (its callback keyed by it there): with PAR or a `link_page` the URL the
    #: browser opens does not carry it. Never shown to the User or a model.
    state: SecretStr | None = None


#: The longest a Direct Sign-In request lives when its link opens on another device: a
#: cross-device request is short-lived (RFC 10027 §2, which §4.2 makes a MUST there).
CROSS_DEVICE_LIFETIME_SECONDS = 300


class DirectSignInResult(SignInResult):
    """A completed Direct Sign-In: the access token, and the refresh token's reference."""


@dataclass(frozen=True)
class _PendingDirectSignIn:
    request: DirectSignInRequest
    token_endpoint: str
    tenant_id: str
    expires_at: datetime
    dpop_signing_algs: Sequence[str] | None = None
    pairwise_user_id: str | None = None
    #: Where the request is pushed (RFC 9126), when it is: each opening pushes it again.
    pushed_authorization_request_endpoint: str | None = None
    #: The link the agent's own page opens it by (`begin(link_page=...)`), dropped with the
    #: state when the sign-in completes.
    link: str | None = None


async def _peek(store: AuthorizationStateStore, reference: str) -> object | None:
    """A state record read without consuming it: the store's `get` when it has one (the
    contract's SHOULD since 0.37.2). A store with only `put` and `take` is read by taking
    and putting back, which a `complete` running between the two steps can race: such a
    store SHOULD add `get`."""

    get = getattr(store, "get", None)
    if callable(get):
        return await get(reference)
    value = await store.take(reference)
    expires_at = getattr(value, "expires_at", None)
    if value is not None and isinstance(expires_at, datetime):
        await store.put(reference, value, expires_at=expires_at)
    return value


def _link_reference(link: str) -> str:
    try:
        encoded = link.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AuthorizationError("invalid_or_expired_state", "sign-in link is invalid") from exc
    return "direct-link:" + hashlib.sha256(encoded).hexdigest()


def _state_reference(state: str) -> str:
    try:
        encoded = state.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AuthorizationError("invalid_callback", "authorization state is invalid") from exc
    return "direct:" + hashlib.sha256(encoded).hexdigest()


def _callback_state(callback_url: str) -> str:
    callback = urlsplit(_redirect_url(callback_url, "callback URL"))
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
        self.sessions = SessionClient(
            reactor=reactor, http_client=http_client, max_response_bytes=max_response_bytes
        )

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
        lifetime_seconds: int | None = None,
        dpop_signing_algs: Sequence[str] | None = None,
        pairwise_user_id: str | None = None,
        cross_device: bool = False,
        same_device_redirect: bool = False,
        pushed_authorization_request_endpoint: str | None = None,
        require_pushed_authorization_requests: bool = False,
        link_page: str | None = None,
    ) -> DirectSignInStart:
        """Store one-use state, then open the authorization URL for the user (§4.2).

        The request carries `prompt=consent`, so the Company shows its consent page even
        for scopes the account granted before (§4.2, §10.8), unless `same_device_redirect`
        says the host receives the redirect only on the device that opened the URL (a
        loopback `redirect_uri`, or its own app signed in as the User who started).

        `pushed_authorization_request_endpoint` and `require_pushed_authorization_requests`
        are the issuer's (RFC 9126, §3.2): with an endpoint, the request is pushed there
        with a client assertion, and a DPoP proof when tokens are bound, and the browser
        opens the authorization endpoint with only `client_id` and `request_uri` (§4.2: a
        SHOULD whenever it is listed, a MUST when required). A `request_uri` expires
        quickly, so a link the User opens later SHOULD go to the agent's own page:
        `link_page`, an HTTPS URL with `{link}`, is what the browser handoff then gets, and
        that page calls `open_link(link)` when opened, which pushes the request and
        returns the authorization URL to redirect to.

        `dpop_signing_algs` is the issuer's `dpop_signing_alg_values_supported`: the
        code exchange sends a DPoP proof when it includes ES256 (§4.5), by the DPoP key
        of `pairwise_user_id`, the User ID the sign-in is for, which proving needs.

        Nothing in the redirect says who approved the sign-in (§10.8). `cross_device`
        says the URL opens on a device other than the one the User is using, such as a
        link sent to a phone: the request then lives at most
        `CROSS_DEVICE_LIFETIME_SECONDS` (RFC 10027 §2), the host asks only for the scopes
        the task needs, and it says who the link is for when it shows it. Whenever it
        can, the host receives the redirect only on the device that opened the URL (a
        loopback `redirect_uri`, or its own app signed in as the User who started), and
        names the User it finds there to `complete(completed_by=...)`.
        """

        longest = CROSS_DEVICE_LIFETIME_SECONDS if cross_device else 900
        if lifetime_seconds is None:
            lifetime_seconds = min(600, longest)
        if not 0 < lifetime_seconds <= longest:
            raise ValueError(
                f"Direct Sign-In state lifetime must be between 1 and {longest} seconds"
            )
        if not tenant_id or len(tenant_id) > 256:
            raise ValueError("tenant_id must contain between 1 and 256 characters")
        if require_pushed_authorization_requests and pushed_authorization_request_endpoint is None:
            raise ValueError("a Company that requires PAR lists where to push (RFC 9126 §5)")
        if link_page is not None:
            if "{link}" not in link_page:
                raise ValueError("link_page is an HTTPS URL with {link}")
            _https_url(link_page.replace("{link}", "x"), "link page")
        proves_with_dpop(dpop_signing_algs, pairwise_user_id)
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
            prompt_consent=not same_device_redirect,
        )
        expires_at = clock.now() + timedelta(seconds=lifetime_seconds)
        reference = _state_reference(request.state.get_secret_value())
        pending = _PendingDirectSignIn(
            request=request,
            token_endpoint=_https_url(token_endpoint, "token endpoint"),
            tenant_id=tenant_id,
            expires_at=expires_at,
            dpop_signing_algs=dpop_signing_algs,
            pairwise_user_id=pairwise_user_id,
            pushed_authorization_request_endpoint=(
                None
                if pushed_authorization_request_endpoint is None
                else _https_url(pushed_authorization_request_endpoint, "PAR endpoint")
            ),
        )
        link = None if link_page is None else _base64url(_entropy(16, random_source.bytes))
        pending = replace(pending, link=link)
        await store.put(reference, pending, expires_at=expires_at)
        try:
            if link_page is not None and link is not None:
                # The link's own record, a copy of the request: opening the link never takes
                # the callback state `complete` consumes (§4.2).
                await store.put(_link_reference(link), pending, expires_at=expires_at)
                await browser.open(SecretStr(link_page.replace("{link}", link)))
            else:
                await browser.open(await self._authorization_url(pending))
        except Exception:
            await store.take(reference)
            if link is not None:
                await store.take(_link_reference(link))
            raise
        return DirectSignInStart(
            expires_at=expires_at,
            requested_scopes=request.scopes,
            cross_device=cross_device,
            state=request.state,
        )

    async def open_link(self, link: str) -> SecretStr:
        """The authorization URL for a sign-in link the User opened on the agent's own
        page (`begin(link_page=...)`, §4.2): the request pushed now when the Company takes
        PAR, so its short-lived `request_uri` is fresh, else the full URL. The page
        redirects the browser there. A link may be opened again until the sign-in
        completes or expires; `AuthorizationError` for an unknown or expired one."""

        store = cast(
            AuthorizationStateStore,
            first_contribution(
                self.reactor, AUTHORIZATION_STATE_STORES, "authorization state store"
            ),
        )
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        # Read, never consumed: only the callback `complete` receives takes state, so an
        # opening and a completing callback can interleave, and a completed sign-in's link
        # opens nothing more.
        link_reference = _link_reference(link)
        pending = await _peek(store, link_reference)
        if isinstance(pending, str):
            # A link begun by 0.37.0, whose record names the callback state's reference: that
            # state is followed, still never consumed, so a link left unexpired across an
            # upgrade opens as before.
            legacy = pending
            pending = await _peek(store, legacy) if legacy.startswith("direct:") else None
            if isinstance(pending, _PendingDirectSignIn) and not callable(
                getattr(store, "get", None)
            ):
                # A store without `get` took the string record to read it: put back, with the
                # sign-in's expiry, so the link opens again until the sign-in completes.
                await store.put(link_reference, legacy, expires_at=pending.expires_at)
        if not isinstance(pending, _PendingDirectSignIn) or clock.now() > pending.expires_at:
            raise AuthorizationError(
                "invalid_or_expired_state", "the sign-in link is unknown or has expired"
            )
        return await self._authorization_url(pending)

    async def _authorization_url(self, pending: _PendingDirectSignIn) -> SecretStr:
        """The URL the browser opens: after a push when the Company takes PAR (§4.2)."""

        if pending.pushed_authorization_request_endpoint is None:
            return pending.request.authorization_url
        return pending.request.pushed_authorization_url(await self._push(pending))

    async def _push(self, pending: _PendingDirectSignIn) -> str:
        """Push the request (RFC 9126 §2): its parameters, a fresh client assertion, and a
        DPoP proof when tokens are bound, so the code is bound to the key (RFC 9449
        §10.1); a `use_dpop_nonce` refusal is retried once. The `request_uri`."""

        request = pending.request
        endpoint = cast(str, pending.pushed_authorization_request_endpoint)
        proves = proves_with_dpop(pending.dpop_signing_algs, pending.pairwise_user_id)
        nonce: str | None = None
        while True:
            form = dict(parse_qsl(cast(SecretStr, request.parameters).get_secret_value()))
            form.update(
                await self.sessions.client_authentication(
                    client_id=request.client_id, issuer=request.issuer
                )
            )
            headers = {"Accept": "application/json"}
            if proves:
                proof = await self.sessions._proof(
                    endpoint,
                    pending.tenant_id,
                    request.issuer,
                    cast(str, pending.pairwise_user_id),
                    nonce,
                )
                headers["DPoP"] = proof.get_secret_value()
            try:
                response = await send_bounded(
                    self.http,
                    self.http.build_request("POST", endpoint, data=form, headers=headers),
                    max_bytes=self.max_response_bytes,
                )
            except httpx.HTTPError as exc:
                raise AuthorizationError("request_failed", "Pushed authorization failed") from exc
            refuse_redirect(response, AuthorizationError)
            payload = None if refused_without_body(response) else _json(response)
            given = response.headers.get("dpop-nonce")
            if (
                proves
                and nonce is None
                and given is not None
                and response.status_code == 400
                and isinstance(payload, dict)
                and payload.get("error") == "use_dpop_nonce"
            ):
                nonce = given
                continue
            break
        if response.status_code not in {200, 201}:
            raise AuthorizationError(
                refusal_code(response, payload, "http_error"),
                "The company refused the pushed authorization request",
                status_code=response.status_code,
            )
        request_uri = payload.get("request_uri") if isinstance(payload, dict) else None
        expires_in = payload.get("expires_in") if isinstance(payload, dict) else None
        if (
            not isinstance(request_uri, str)
            or not request_uri
            or not isinstance(expires_in, int)
            or isinstance(expires_in, bool)
            or expires_in <= 0
        ):
            raise AuthorizationError(
                "invalid_par_response", "The pushed authorization response is malformed"
            )
        return request_uri

    @traced("pap.sign_in.direct.complete", before=sign_in_method("direct"), after=sign_in_result)
    async def complete(
        self, callback_url: str, *, completed_by: str | None = None
    ) -> DirectSignInResult:
        """Consume callback state and exchange its code with fresh proof material.

        `completed_by` is the `tenant_id` of the User the host found in the browser at
        `redirect_uri`, when it can tell, such as by its own sign-in there: a redirect
        that arrives for another User than the one who started the sign-in is refused
        (`sign_in_started_by_another_user`), the state used up and no code exchanged, so a
        link someone forwarded gives its sender no tokens (§4.2, §10.8).
        """

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
        if pending.link is not None:
            # The sign-in is used up: its link opens nothing more.
            await store.take(_link_reference(pending.link))
        clock = cast(Clock, first_contribution(self.reactor, CLOCKS, "clock"))
        if clock.now() > pending.expires_at:
            raise AuthorizationError("invalid_or_expired_state", "authorization state has expired")
        if completed_by is not None and completed_by != pending.tenant_id:
            raise AuthorizationError(
                "sign_in_started_by_another_user",
                "The redirect arrived for another User than the one who started the sign-in",
            )
        callback = validate_direct_sign_in_callback(pending.request, callback_url)
        return await self._exchange(pending, callback)

    async def _exchange(
        self,
        pending: _PendingDirectSignIn,
        callback: DirectSignInCallback,
    ) -> DirectSignInResult:
        request = pending.request
        form = {
            "grant_type": "authorization_code",
            "code": callback.code.get_secret_value(),
            "redirect_uri": request.redirect_uri,
            "code_verifier": request.code_verifier.get_secret_value(),
        }
        response = await self.sessions.token_request(
            client_id=request.client_id,
            issuer=request.issuer,
            token_endpoint=pending.token_endpoint,
            form=lambda: form,
            error=AuthorizationError,
            tenant_id=pending.tenant_id,
            dpop_signing_algs=pending.dpop_signing_algs,
            pairwise_user_id=pending.pairwise_user_id,
        )
        return await self._result(response, pending)

    async def _result(
        self,
        response: TokenResponse,
        pending: _PendingDirectSignIn,
    ) -> DirectSignInResult:
        result = await finish_sign_in(
            self.reactor, response, pending.request.scopes, error=AuthorizationError
        )
        return DirectSignInResult(**dict(result))
