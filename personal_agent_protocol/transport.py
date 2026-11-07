# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""The Session header on every request to a Company's APIs and endpoints (§5.2, §5.6).

Each request carries a fresh Session JWT (`Poppy-Session`) from the host's
`pap.sessionSigner`, and, signed in, the account's access token in `Authorization`,
with the scheme its `token_type` names. A `DPoP` token goes with a fresh proof from
`pap.dpopProver` on every request and retry, and a `use_dpop_nonce` challenge is
retried once; the latest nonce is kept per origin for later requests (§4.5). A host
that contributes `pap.operatorSigner` signs each of them too, last, over the Session
JWT and the token (§5.3). A `session_ended` answer starts a new Session once, and
the request is sent again in it; a second one is returned to the caller, who stops.
An `invalid_session` answer goes straight back to the caller: a new Session would not
fix it, so the request is not sent again until its cause is fixed (§5.3, §5.5, §7).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
from typing import cast
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .errors import TransportError
from .extensions import format_extensions_header
from .json import loads_strict
from .operator_signatures import (
    SIGNATURE_AGENT_HEADER,
    SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER,
)
from .reactor import (
    CLOCKS,
    DPOP_PROVERS,
    OPERATOR_SIGNERS,
    RANDOM_SOURCES,
    RATE_LIMIT_BUDGETS,
    RETRY_POLICIES,
    SESSION_SIGNERS,
    Clock,
    DpopProofRequest,
    DpopProver,
    OperatorSignatureRequest,
    OperatorSigner,
    RandomSource,
    RateLimitBudget,
    RetryPolicy,
    SessionJwtRequest,
    SessionSigner,
    SystemClock,
    first_contribution,
    optional_contribution,
    parse_retry_after,
    send_bounded,
)
from .refusals import dpop_nonce_asked, refuse_redirect
from .sessions import DPOP_HEADER, DPOP_NONCE_HEADER, AccessToken, PapSession

#: The header that carries the Session JWT (§5.2).
SESSION_HEADER = "Poppy-Session"
#: The protocol version the request is in (§3.4), on every request with the Session header.
VERSION_HEADER = "Poppy-Version"
#: The extensions the Session uses, one version each (§3.4), when it uses any.
EXTENSIONS_HEADER = "Poppy-Extensions"
#: Refusals that ask the caller to come back later (Guides, retries and rate limits).
_LATER = frozenset({429, 503})
#: Methods retried on their own: they change nothing at the company.
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
#: Headers the host owns: a caller never sets them.
_HOST_OWNED = frozenset(
    {
        "authorization",
        "dpop",
        "poppy-session",
        SIGNATURE_HEADER.lower(),
        SIGNATURE_INPUT_HEADER.lower(),
        SIGNATURE_AGENT_HEADER.lower(),
    }
)


def _https_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise TransportError("invalid_url", "PAP resource URL must use HTTPS")
    return value


def _origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    return parsed.scheme, (parsed.hostname or "").lower(), parsed.port or 443


def budget_key(url: str) -> str:
    """The shared rate-limit budget a request draws on: its company's origin."""

    scheme, host, port = _origin(url)
    return f"{scheme}://{host}:{port}"


def session_ended(response: httpx.Response) -> bool:
    """Whether the company answered `session_ended` (§5.5): HTTP 400 and its JSON body.

    The Session has ended, or the company refused an account change in it (§5.4): the
    personal agent starts a new Session and sends the request again, once. The other
    Session error, `invalid_session` (§5.3), is never retried: a new Session would fail
    the same way.
    """

    return session_error(response) == "session_ended"


def version_unsupported(response: httpx.Response) -> bool:
    """Whether the company answered `version_unsupported` (§3.4): HTTP 400 and its JSON body.

    `Poppy-Version` was missing, or names a version the company doesn't serve. The
    personal agent fetches `poppy.json` again (`DiscoveryClient.discover(fresh=True)`) and
    chooses again: a new Session at another version, and the request again once, or,
    when it chooses the same version or none, no more of this request. The transport
    never retries it: the choice is discovery's.
    """

    return session_error(response) == "version_unsupported"


def session_error(response: httpx.Response) -> str | None:
    """The Session error the company answered with, `invalid_session` (§5.3),
    `session_ended` (§5.5) or `version_unsupported` (§3.4): HTTP 400 and a JSON body
    naming it. None for any other response.
    """

    if response.status_code != 400:
        return None
    try:
        payload = loads_strict(response.content)
    except Exception:
        return None
    error = payload.get("error") if isinstance(payload, dict) else None
    return error if error in {"invalid_session", "session_ended", "version_unsupported"} else None


async def session_headers(
    reactor: PluginPlatform,
    method: str,
    url: str,
    *,
    session: PapSession,
    token: AccessToken | None,
    dpop_nonce: str | None = None,
) -> dict[str, str]:
    """The headers of one request: every credential, fresh (§4.5, §5.2).

    `Poppy-Session` always; with an access token, `Authorization`; with a `DPoP` token,
    a `DPoP` proof too, whose `ath` covers the same token as the Session JWT's.
    `dpop_nonce` is the server's latest for this origin. Last, with a `pap.operatorSigner`
    contributed, the operator signature over them (§5.3).
    """

    signer = cast(SessionSigner, first_contribution(reactor, SESSION_SIGNERS, "session signer"))
    jwt = await signer.sign(
        SessionJwtRequest(
            method=method.upper(),
            url=url,
            tenant_id=session.tenant_id,
            issuer=session.issuer,
            client_id=session.client_id,
            sid=session.sid,
            sub=session.sub,
            agent_id=session.agent_id,
            access_token=None if token is None else token.access_token,
        )
    )
    # The Session header and, with it, the version the Session uses the Company at (§3.4).
    headers = {SESSION_HEADER: jwt.get_secret_value(), VERSION_HEADER: session.protocol_version}
    declared = format_extensions_header(session.extensions)
    if declared is not None:
        headers[EXTENSIONS_HEADER] = declared
    if token is not None:
        headers["Authorization"] = f"{token.token_type} {token.access_token.get_secret_value()}"
    if token is not None and token.token_type == "DPoP":  # noqa: S105 - an OAuth token type
        prover = cast(DpopProver, first_contribution(reactor, DPOP_PROVERS, "DPoP prover"))
        proof = await prover.prove(
            DpopProofRequest(
                method=method.upper(),
                url=url,
                tenant_id=session.tenant_id,
                issuer=session.issuer,
                sub=session.sub,
                access_token=token.access_token,
                nonce=dpop_nonce,
            )
        )
        headers[DPOP_HEADER] = proof.get_secret_value()
    operator = optional_contribution(reactor, OPERATOR_SIGNERS, "operator signer")
    if operator is not None:
        authorization = headers.get("Authorization")
        signed = await cast(OperatorSigner, operator).sign(
            OperatorSignatureRequest(
                method=method.upper(),
                url=url,
                tenant_id=session.tenant_id,
                session_jwt=jwt,
                authorization=None if authorization is None else SecretStr(authorization),
            )
        )
        headers[SIGNATURE_AGENT_HEADER] = signed.signature_agent
        headers[SIGNATURE_INPUT_HEADER] = signed.signature_input
        headers[SIGNATURE_HEADER] = signed.signature
    return headers


class SessionHttpClient:
    """Send requests with the Session header; a redirect is refused, never followed (§3)."""

    def __init__(
        self,
        *,
        reactor: PluginPlatform,
        http_client: httpx.AsyncClient,
        max_response_bytes: int = 1024 * 1024,
    ) -> None:
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.reactor = reactor
        self.http = http_client
        #: No more than this (and one byte) of a response is read; the client checks the rest.
        self.max_response_bytes = max_response_bytes
        #: The latest `DPoP-Nonce` each origin gave a request with a `DPoP` token (§4.5).
        self.dpop_nonces: dict[str, str] = {}

    async def request(
        self,
        method: str,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """Send a request in `session`, within the company's shared budget.

        Signed in with `token`, signed out without. Every attempt draws on
        `pap.rateLimitBudget` for the company's origin and carries a fresh Session
        JWT. A 429 or 503 shares its `Retry-After` with every task through the
        budget; a safe method (GET, HEAD, OPTIONS) is then retried by
        `pap.retryPolicy` — never sooner than `Retry-After`, with exponential
        backoff and jitter otherwise. A write, or a pause longer than the policy
        allows, returns the refusal to the caller. `session_ended` starts a new
        Session once (`session.restart()`) and sends the request again in it, and a
        `use_dpop_nonce` challenge sends it again once with the nonce. `invalid_session`
        is returned to the caller as it is (§5.3): no new Session is started.
        """

        policy = optional_contribution(self.reactor, RETRY_POLICIES, "retry policy")
        budget = optional_contribution(self.reactor, RATE_LIMIT_BUDGETS, "rate-limit budget")
        retry = policy if isinstance(policy, RetryPolicy) else RetryPolicy(max_attempts=1)
        key = budget_key(url)
        attempts = 0
        restarted = nonce_retried = False
        while True:
            if isinstance(budget, RateLimitBudget):
                await budget.acquire(key)
            response = await self._request_once(
                method, url, session=session, token=token, headers=headers, content=content
            )
            attempts += 1
            if session_ended(response) and not restarted:
                # The Session has ended: a new one, once (§5.5, §7).
                restarted = True
                session.restart(self._random_bytes)
                continue
            if not nonce_retried and self._asks_a_nonce(response, token):
                nonce_retried = True
                continue
            if response.status_code not in _LATER:
                return response
            retry_after = parse_retry_after(response.headers.get("retry-after"), self._now())
            delay = (
                retry.delay(attempts, retry_after, self._jitter())
                if method.upper() in _SAFE_METHODS
                else None
            )
            pause = delay if delay is not None else retry_after
            if isinstance(budget, RateLimitBudget) and pause is not None:
                await budget.defer(key, pause)
            if delay is None:
                return response
            if not isinstance(budget, RateLimitBudget):
                await asyncio.sleep(delay)

    def _now(self) -> datetime:
        clock = optional_contribution(self.reactor, CLOCKS, "clock")
        return (clock if isinstance(clock, Clock) else SystemClock()).now()

    def _random_bytes(self, length: int) -> bytes:
        source = cast(RandomSource, first_contribution(self.reactor, RANDOM_SOURCES, "random"))
        return source.bytes(length)

    def _jitter(self) -> float:
        source = optional_contribution(self.reactor, RANDOM_SOURCES, "random source")
        if not isinstance(source, RandomSource):
            return 0.5
        return int.from_bytes(source.bytes(4), "big") / 2**32

    def _dpop_nonce(self, url: str, token: AccessToken | None) -> str | None:
        return None if token is None else self.dpop_nonces.get(budget_key(url))

    def _keep_dpop_nonce(
        self, url: str, token: AccessToken | None, response: httpx.Response
    ) -> None:
        given = response.headers.get(DPOP_NONCE_HEADER)
        if given and token is not None and token.token_type == "DPoP":  # noqa: S105
            self.dpop_nonces[budget_key(url)] = given

    @staticmethod
    def _asks_a_nonce(response: httpx.Response, token: AccessToken | None) -> bool:
        bound = token is not None and token.token_type == "DPoP"  # noqa: S105
        return bound and dpop_nonce_asked(response) is not None

    def _headers(self, supplied: Mapping[str, str] | None) -> dict[str, str]:
        values = dict(supplied or {})
        if any(name.lower() in _HOST_OWNED for name in values):
            raise TransportError(
                "protected_header",
                "Authorization, DPoP, Poppy-Session and signature headers are host-owned",
            )
        return values

    async def _request_once(
        self,
        method: str,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None,
        headers: Mapping[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """One request with a fresh Session JWT; no redirect followed."""

        target = _https_url(url)
        supplied = self._headers(headers)
        signed = await session_headers(
            self.reactor,
            method,
            target,
            session=session,
            token=token,
            dpop_nonce=self._dpop_nonce(target, token),
        )
        try:
            response = await send_bounded(
                self.http,
                self.http.build_request(
                    method.upper(), target, content=content, headers={**supplied, **signed}
                ),
                max_bytes=self.max_response_bytes,
            )
        except httpx.HTTPError as exc:
            raise TransportError("request_failed", "PAP resource request failed") from exc
        # A redirect would carry the token and a Session JWT to another URL: refused (§3).
        refuse_redirect(response)
        self._keep_dpop_nonce(target, token, response)
        return response

    @asynccontextmanager
    async def stream(
        self,
        method: str,
        url: str,
        *,
        session: PapSession,
        token: AccessToken | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> AsyncIterator[httpx.Response]:
        """Open a streamed response (SSE) in `session`; no redirect followed.

        `session_ended` starts a new Session once, and `use_dpop_nonce` sends it again
        once, as `request` does; `invalid_session` is yielded as it is.
        """

        target = _https_url(url)
        supplied = self._headers(headers)
        restarted = nonce_retried = False
        while True:
            signed = await session_headers(
                self.reactor,
                method,
                target,
                session=session,
                token=token,
                dpop_nonce=self._dpop_nonce(target, token),
            )
            request = self.http.build_request(
                method.upper(), target, headers={**supplied, **signed}
            )
            try:
                response = await self.http.send(request, stream=True, follow_redirects=False)
            except httpx.HTTPError as exc:
                raise TransportError("request_failed", "PAP stream request failed") from exc
            try:
                if response.status_code == 400 and not restarted:
                    await response.aread()
                    if session_ended(response):
                        restarted = True
                        session.restart(self._random_bytes)
                        continue
                self._keep_dpop_nonce(target, token, response)
                if not nonce_retried and self._asks_a_nonce(response, token):
                    nonce_retried = True
                    continue
                refuse_redirect(response)
                yield response
                return
            finally:
                await response.aclose()
