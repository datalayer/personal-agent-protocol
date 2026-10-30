# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A personal-agent conformance suite, run against any PAP company's base URL.

The suite plays a personal agent with a demo-kit identity (`AgentIdentity`):
it discovers the company, starts Sessions, signs in, talks, and approves
operations through the public SDK, and sends the forged, replayed, and
mismatched requests a company MUST refuse. Every case is described by a
shared fixture (`protocol/fixtures/conformance/*.json`) and names the ledger
requirements it shows.

What the runner cannot do itself, the `UserDriver` does: the user approving
Device Sign-In on the company's page, and — for a demo company only — the
company's operator revising an operation, forgetting old events, or moving a
shared clock. A case that needs a capability the driver lacks is skipped,
never passed.

```python
context = ConformanceContext(
    "https://manzanita.example", identity=atlas, http=http, driver=driver, scenario=scenario
)
report = await run_conformance(context)
report.to_json()   # schema_version 1
report.to_junit()  # JUnit XML
```
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol, cast, runtime_checkable
from urllib.parse import urlencode, urlsplit
from xml.etree import ElementTree

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .accounts import (
    RefreshTokenClient,
    RefreshTokenContext,
    ServiceTokens,
    stale_resource_metadata,
)
from .apis import ApiClient, ApiError, conversation_endpoint, openapi_url
from .auth import DirectSignInClient
from .browser import BrowserSessionClient
from .conversations import ConversationClient, TextDelta
from .crypto import (
    SESSION_JWT_ALGORITHM,
    SESSION_JWT_TYPE,
    DelegatedSessionSigner,
    JoseSigner,
    delegation_claims,
    jwk_thumbprint,
    session_jwt_claims,
)
from .demo.kit import AgentIdentity, ControlledBrowser, MemoryVault, MutableClock, PersonalAgentHost
from .device import DeviceSignInClient
from .discovery import DiscoveryClient
from .errors import PersonalAgentProtocolError, TransportError
from .feedback import feedback_endpoint
from .mcp import McpClient, McpError, fetch_mcp_server_metadata, mcp_api
from .models import Approval, Author, ConversationEvent, DiscoveredCompany, Message, Operation
from .operations import (
    APPROVAL_HEADER,
    OperationsClient,
    approval_header,
    operations_negotiated,
)
from .profile import PROTOCOL_PROFILE
from .reactor import (
    CLOCKS,
    SESSION_SIGNERS,
    AddressResolver,
    Clock,
    SessionJwtRequest,
    SystemClock,
    build_pap_reactor,
    first_contribution,
    resolve_addresses,
)
from .refusals import challenge_parameters
from .requirements import protocol_path
from .sessions import AccessToken, PapSession, SessionClient
from .transport import SessionHttpClient

Kind = Literal["positive", "negative", "recovery"]
Outcome = Literal["passed", "failed", "skipped"]
SCHEMA_VERSION = 1
SUITES = ("protocol", "security", "lifecycle", "conversations", "operations")


# Fixtures ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FixtureCase:
    """One shared conformance fixture case."""

    id: str
    suite: str
    kind: Kind
    role: str
    requirements: tuple[str, ...]
    description: str = ""
    check: str | None = None
    input: Any = None
    expect: Any = None
    target: str | None = None
    mutation: dict[str, Any] = field(default_factory=dict)


def load_fixture_cases(suites: Iterable[str] = SUITES) -> tuple[FixtureCase, ...]:
    """Every fixture case of the named suites, in file order."""

    cases: list[FixtureCase] = []
    for suite in suites:
        document = json.loads(
            protocol_path("fixtures", "conformance", f"{suite}.json").read_text(encoding="utf-8")
        )
        for raw in document["cases"]:
            cases.append(
                FixtureCase(
                    id=raw["id"],
                    suite=suite,
                    kind=raw["kind"],
                    role=raw["role"],
                    requirements=tuple(raw.get("requirements", ())),
                    description=raw.get("description", ""),
                    check=raw.get("check"),
                    input=raw.get("input"),
                    expect=raw.get("expect"),
                    target=raw.get("target"),
                    mutation=dict(raw.get("mutation", {})),
                )
            )
    return tuple(cases)


# The user, and a demo company's operator ---------------------------------------------


@runtime_checkable
class UserDriver(Protocol):
    """What the runner cannot do as a personal agent.

    `capabilities` names the optional ones a case may need: `revise`,
    `forget_events`, `disconnect`, `performed`, `clock` (`wait` moves a shared
    clock instead of sleeping), `second_identity` (`other_identity` is a
    second agent the company can resolve, listing no extensions), and
    `direct_sign_in` (`approve_authorization` plays the user on the company's
    consent page, for a company that offers Direct Sign-In and no Device
    Sign-In: it answers the callback URL the company redirected to).
    """

    capabilities: frozenset[str]
    accounts: tuple[str, str]
    other_identity: AgentIdentity | None

    async def approve_device(
        self, user_code: str, *, account: str, scopes: Sequence[str] | None = None
    ) -> None: ...

    async def wait(self, seconds: float) -> None: ...

    async def approve_authorization(
        self, authorization_url: str, *, account: str, scopes: Sequence[str] | None = None
    ) -> str: ...

    async def revise(self, operation_id: str) -> None: ...

    async def forget_events(self, conversation_id: str) -> None: ...

    async def disconnect(self, client_id: str, account: str) -> None: ...

    async def performed(self, operation_id: str) -> int: ...


@dataclass(frozen=True)
class Proposal:
    """A company API call that needs the user's approval (Operations 4).

    `documented_as` is how the company's OpenAPI description names the path.
    """

    method: str
    path: str
    body: Any = None
    documented_as: str | None = None


@dataclass(frozen=True)
class Scenario:
    """What the suite asks of one company: its scopes, paths, and prompts.

    `proposals` are keyed `user` (it is performed), `fails` (it fails partway),
    and `unknown` (its outcome stays unknown). `operation_prompt` makes the
    company agent return the `user` operation in a conversation;
    `account_prompt` makes it ask for sign-in. `mcp_read_tool` needs
    `read_scope`; `mcp_propose_tool` returns the `user` operation.
    """

    read_path: str
    read_scope: str
    scopes: tuple[str, ...]
    proposals: dict[str, Proposal] = field(default_factory=dict)
    operation_prompt: str | None = None
    account_prompt: str | None = None
    greeting: str = "Hello."
    mcp_read_tool: str | None = None
    mcp_propose_tool: str | None = None


class SkipCase(Exception):  # noqa: N818 - control flow for a case that cannot run
    """The target or driver lacks what this case needs."""


class ConformanceFailure(AssertionError):  # noqa: N818 - a failed check
    """The company did not behave as the case requires."""


def check(condition: object, message: str) -> None:
    """Fail the case with `message` (never a secret) unless `condition` holds."""

    if not condition:
        raise ConformanceFailure(message)


# One personal agent ------------------------------------------------------------------


class Agent:
    """A personal agent: its identity, Reactor host, and SDK clients."""

    def __init__(
        self,
        identity: AgentIdentity,
        *,
        http: httpx.AsyncClient,
        clock: Clock,
        address_resolver: AddressResolver,
        browser_http: httpx.AsyncClient | None = None,
    ) -> None:
        self.identity = identity
        self.http = http
        self.vault = MemoryVault()
        self.browser = ControlledBrowser(browser_http) if browser_http is not None else None
        #: The user's browser: the authorization URLs Direct Sign-In opened, for the driver.
        self.user_browser = _UserBrowser()
        host = PersonalAgentHost(
            identity,
            cast(MutableClock, clock),
            vault=self.vault,
            controlled_browser=self.browser,
            browser=cast(Any, self.user_browser),
        )
        self.reactor: PluginPlatform
        self.reactor, _ = build_pap_reactor(
            http_client=http,
            address_resolver=address_resolver,
            plugins=[(_manifest(identity), host)],
        )
        self.transport = SessionHttpClient(reactor=self.reactor, http_client=http)
        self.sessions = SessionClient(reactor=self.reactor, http_client=http)
        self.device = DeviceSignInClient(reactor=self.reactor, http_client=http)
        self.accounts = RefreshTokenClient(reactor=self.reactor, http_client=http)
        self.api = ApiClient(transport=self.transport)
        self.conversations = ConversationClient(transport=self.transport)
        self.operations = OperationsClient(reactor=self.reactor, sleep=lambda _: asyncio.sleep(0))


class _UserBrowser:
    """`pap.browserHandoff` for the suite: it keeps the URL; the driver plays the user."""

    def __init__(self) -> None:
        self.urls: list[str] = []

    async def open(self, authorization_url: SecretStr) -> None:
        self.urls.append(authorization_url.get_secret_value())


def _manifest(identity: AgentIdentity) -> Any:
    from reactor import PluginManifest

    return PluginManifest(name=f"{identity.domain}-conformance", version="1")


@dataclass
class SignedIn:
    """A Session, signed in: its access token, and the refresh token's opaque reference."""

    session: PapSession
    token: AccessToken
    reference: str


class ConformanceContext:
    """The target company and the personal agent the suite plays."""

    def __init__(
        self,
        base_url: str,
        *,
        identity: AgentIdentity,
        http: httpx.AsyncClient,
        driver: UserDriver,
        scenario: Scenario,
        clock: Clock | None = None,
        address_resolver: AddressResolver = resolve_addresses,
        tenant_id: str = "pap-conformance",
        browser_http: httpx.AsyncClient | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("the company base URL must be an HTTPS origin")
        self.base_url = f"https://{parsed.netloc}"
        self.domain = parsed.hostname
        self.http = http
        self.driver = driver
        self.scenario = scenario
        self.tenant_id = tenant_id
        self.address_resolver = address_resolver
        self.clock: Clock = clock or SystemClock()
        self.agent = Agent(
            identity,
            http=http,
            clock=self.clock,
            address_resolver=address_resolver,
            browser_http=browser_http,
        )
        self._other: Agent | None = None
        self._company: DiscoveredCompany | None = None
        #: Where API paths resolve: the origin of the company's OpenAPI API, once discovered.
        self._api_base: str | None = None

    def new_browser(self) -> httpx.AsyncClient:
        """Another browser, with a cookie jar of its own, on the runner's browser network."""

        if self.agent.browser is None:
            raise SkipCase("the runner was given no browser of its own")
        # The same transport (and so the same network and TLS trust), new cookies.
        return httpx.AsyncClient(transport=self.agent.browser.http._transport)

    # The company -------------------------------------------------------------------

    async def company(self) -> DiscoveredCompany:
        if self._company is None:
            client = DiscoveryClient(reactor=self.agent.reactor)
            self._company = await client.discover(self.domain)
            api = next(
                (api for api in self._company.document.apis or () if api.type == "openapi"), None
            )
            if api is not None:
                parsed = urlsplit(str(api.url))
                self._api_base = f"{parsed.scheme}://{parsed.netloc}"
        return self._company

    async def metadata(self) -> Any:
        company = await self.company()
        if company.oauth_metadata is None:
            raise SkipCase("the company offers no Sessions (no auth)")
        return company.oauth_metadata

    async def conversations_endpoint(self) -> str:
        endpoint = conversation_endpoint((await self.company()).document)
        if endpoint is None:
            raise SkipCase("the company lists no poppy conversation protocol")
        return endpoint

    async def operations_negotiated(self) -> None:
        if not operations_negotiated(
            (await self.company()).document, _client_metadata(self.agent.identity)
        ):
            raise SkipCase("operations v2 is not negotiated with this company")

    def url(self, path: str) -> str:
        """An API path at the company's API (its OpenAPI `url`'s origin), else its origin."""

        return f"{self._api_base or self.base_url}{path}"

    # Capabilities ------------------------------------------------------------------

    def require(self, *capabilities: str) -> None:
        missing = [name for name in capabilities if name not in self.driver.capabilities]
        if missing:
            raise SkipCase(f"the driver cannot {', '.join(missing)}")

    def proposal(self, kind: str) -> Proposal:
        proposal = self.scenario.proposals.get(kind)
        if proposal is None:
            raise SkipCase(f"the scenario has no {kind!r} proposal")
        return proposal

    def other_agent(self) -> Agent:
        self.require("second_identity")
        if self._other is None:
            identity = cast(AgentIdentity, self.driver.other_identity)
            self._other = Agent(
                identity, http=self.http, clock=self.clock, address_resolver=self.address_resolver
            )
        return self._other

    def now(self) -> datetime:
        return cast(Clock, first_contribution(self.agent.reactor, CLOCKS, "clock")).now()

    # Users and Sessions --------------------------------------------------------------

    @staticmethod
    def new_user() -> str:
        """A fresh pairwise User ID, so no case sees another's state."""

        return "usr_conf_" + base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")

    async def session(self, user: str, agent: Agent | None = None) -> PapSession:
        metadata = await self.metadata()
        actor = agent or self.agent
        return await actor.sessions.start(
            client_id=actor.identity.client_id,
            pairwise_user_id=user,
            issuer=metadata.issuer,
            tenant_id=self.tenant_id,
        )

    async def sign_in(
        self,
        user: str,
        session: PapSession,
        *,
        scopes: Sequence[str] | None = None,
        granted: Sequence[str] | None = None,
        account: str | None = None,
        agent: Agent | None = None,
    ) -> SignedIn:
        """Device Sign-In, the user approving on the company's page through the driver."""

        metadata = await self.metadata()
        actor = agent or self.agent
        if not metadata.offers_device:
            if "direct_sign_in" in self.driver.capabilities and metadata.offers_direct:
                return await self._direct_sign_in(
                    actor, user, session, scopes=scopes, granted=granted, account=account
                )
            raise SkipCase("the company offers no Device Sign-In")
        started = await actor.device.begin(
            device_authorization_endpoint=cast(str, metadata.device_authorization_endpoint),
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=actor.identity.client_id,
            scopes=tuple(scopes or self.scenario.scopes),
            tenant_id=self.tenant_id,
            organization=(await self.company()).document.organization,
            protected_resources=metadata.protected_resources,
        )
        await self.driver.approve_device(
            started.user_code, account=account or self.driver.accounts[0], scopes=granted
        )
        for _ in range(10):
            await self.driver.wait(started.poll_interval)
            polled = await actor.device.poll(started.reference)
            if polled.status == "complete":
                token, reference = polled.token, polled.refresh_token_reference
                check(token is not None and reference is not None, "sign-in returns its token")
                return SignedIn(session, cast(AccessToken, token), cast(str, reference))
        raise ConformanceFailure("Device Sign-In did not complete after approval")

    async def _direct_sign_in(
        self,
        actor: Agent,
        user: str,
        session: PapSession,
        *,
        scopes: Sequence[str] | None,
        granted: Sequence[str] | None,
        account: str | None,
    ) -> SignedIn:
        """Direct Sign-In, the driver playing the user on the company's consent page."""

        metadata = await self.metadata()
        client = DirectSignInClient(reactor=actor.reactor, http_client=self.http)
        await client.begin(
            authorization_endpoint=cast(str, metadata.authorization_endpoint),
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=actor.identity.client_id,
            redirect_uri=str(actor.identity.metadata["redirect_uris"][0]),
            scopes=tuple(scopes or self.scenario.scopes),
            tenant_id=self.tenant_id,
        )
        callback = await self.driver.approve_authorization(
            actor.user_browser.urls[-1],
            account=account or self.driver.accounts[0],
            scopes=granted,
        )
        done = await client.complete(callback)
        check(done.refresh_token_reference is not None, "sign-in returns its refresh token")
        return SignedIn(session, done.token, cast(str, done.refresh_token_reference))

    async def account_context(self, user: str, agent: Agent | None = None) -> RefreshTokenContext:
        metadata = await self.metadata()
        actor = agent or self.agent
        return RefreshTokenContext(
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=actor.identity.client_id,
            tenant_id=self.tenant_id,
            revocation_endpoint=metadata.revocation_endpoint,
        )

    async def refresh_token(self, reference: str) -> SecretStr:
        value = await self.agent.vault.get(reference)
        check(isinstance(value, SecretStr), "the refresh token is stored behind its reference")
        return cast(SecretStr, value)

    # Raw requests (for what the SDK would never send) ---------------------------------

    async def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> httpx.Response:
        """One request exactly as given: no cookies, no redirects followed."""

        request = httpx.Request(method, url, headers=headers or {}, content=content)
        return await self.http.send(request, follow_redirects=False)

    async def auth(
        self,
        session: PapSession,
        method: str,
        url: str,
        token: AccessToken | None = None,
        *,
        agent: Agent | None = None,
    ) -> dict[str, str]:
        """The headers of one request in `session`: `Poppy-Session`, and `Authorization`."""

        signer = cast(
            DelegatedSessionSigner,
            first_contribution((agent or self.agent).reactor, SESSION_SIGNERS, "session signer"),
        )
        jwt_value = await signer.sign(self.jwt_request(session, method, url, token))
        headers = {"Poppy-Session": jwt_value.get_secret_value()}
        if token is not None:
            headers["Authorization"] = f"Bearer {token.access_token.get_secret_value()}"
        return headers

    @staticmethod
    def jwt_request(
        session: PapSession, method: str, url: str, token: AccessToken | SecretStr | None = None
    ) -> SessionJwtRequest:
        return SessionJwtRequest(
            method=method,
            url=url,
            tenant_id=session.tenant_id,
            issuer=session.issuer,
            client_id=session.client_id,
            sid=session.sid,
            sub=session.sub,
            agent_id=session.agent_id,
            access_token=token.access_token if isinstance(token, AccessToken) else token,
        )

    async def forged_session_jwt(  # noqa: C901 - one branch per mutation
        self,
        session: PapSession,
        method: str,
        url: str,
        *,
        token: AccessToken | SecretStr | None = None,
        mutation: dict[str, Any] | None = None,
    ) -> str:
        """A Session JWT the SDK would never send: real keys, one thing wrong (§5.2)."""

        mutation = mutation or {}
        identity = self.agent.identity
        now = self.now() + timedelta(seconds=mutation.get("iat_offset", 0))
        request = self.jwt_request(session, method, url, token)
        claims = session_jwt_claims(request, issued_at=now)
        if "aud" in mutation:
            metadata = await self.metadata()
            claims["aud"] = (
                metadata.token_endpoint if mutation["aud"] == "token_endpoint" else mutation["aud"]
            )
        if "htm" in mutation:
            claims["htm"] = mutation["htm"]
        if "htu" in mutation:
            claims["htu"] = mutation["htu"]
        if "ath" in mutation:
            claims["ath"] = mutation["ath"]
        if mutation.get("drop_ath"):
            claims.pop("ath", None)
        delegated = ec.generate_private_key(ec.SECP256R1())
        public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(delegated.public_key()))
        issued = self.now() + timedelta(seconds=mutation.get("delegation_iat_offset", 0))
        lifetime = timedelta(seconds=mutation.get("delegation_lifetime", 3600))
        body = delegation_claims(
            client_id=identity.client_id,
            public=public,
            issued_at=issued,
            lifetime=min(lifetime, timedelta(hours=24)),
        )
        if lifetime > timedelta(hours=24):
            body["exp"] = cast(int, body["iat"]) + int(lifetime.total_seconds())
        if mutation.get("delegation_extra"):
            body.update(mutation["delegation_extra"])
        delegation = (
            await JoseSigner(identity.private_key, key_id=identity.kid).sign(
                body, purpose="delegation"
            )
        ).get_secret_value()
        if mutation.get("delegation_signer") == "stranger":
            stranger = ec.generate_private_key(ec.SECP256R1())
            delegation = (
                await JoseSigner(stranger, key_id=identity.kid).sign(body, purpose="delegation")
            ).get_secret_value()
        if mutation.get("delegation_typ"):
            delegation = jwt.encode(
                body,
                identity.private_key,
                algorithm="ES256",
                headers={"typ": mutation["delegation_typ"], "kid": identity.kid},
            )
        header: dict[str, Any] = {
            "typ": mutation.get("typ", SESSION_JWT_TYPE),
            "kid": mutation.get("kid", jwk_thumbprint(public)),
            "pap_dlg": delegation,
        }
        if mutation.get("no_delegation"):
            # Signed directly with a key from `jwks_uri`, which never signs a Session JWT.
            del header["pap_dlg"]
            header["kid"] = identity.kid
            return jwt.encode(claims, identity.private_key, algorithm="ES256", headers=header)
        if mutation.get("alg") == "none":
            return f"{_segment({**header, 'alg': 'none'})}.{_segment(claims)}."
        return jwt.encode(claims, delegated, algorithm=SESSION_JWT_ALGORITHM, headers=header)

    def assertion(
        self,
        claims: dict[str, Any],
        *,
        identity: AgentIdentity | None = None,
        algorithm: str = "ES256",
        headers: dict[str, Any] | None = None,
    ) -> str:
        """Sign assertion claims with the agent's key (or forge an unsigned/odd one)."""

        signer = identity or self.agent.identity
        header = {"typ": "JWT", "kid": signer.kid, **(headers or {})}
        if algorithm == "none":
            return f"{_segment({**header, 'alg': 'none'})}.{_segment(claims)}."
        if algorithm == "HS256":
            # The agent's public key used as an HMAC secret: algorithm confusion.
            secret = json.dumps(signer.jwks["keys"][0], sort_keys=True).encode()
            signing_input = f"{_segment({**header, 'alg': 'HS256'})}.{_segment(claims)}"
            import hmac

            mac = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
            return f"{signing_input}.{_b64(mac)}"
        token = jwt.encode(claims, signer.private_key, algorithm="ES256", headers=header)
        if algorithm == "PS384":
            _, payload, signature = token.split(".")
            return f"{_segment({**header, 'alg': 'PS384'})}.{payload}.{signature}"
        return token

    def claims(self, *, subject: str, audience: str, lifetime: int = 60, shift: int = 0) -> dict:
        issued = int(self.now().timestamp()) + shift
        return {
            "iss": self.agent.identity.client_id,
            "sub": subject,
            "aud": audience,
            "iat": issued,
            "exp": issued + lifetime,
            "jti": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("="),
        }

    async def token_request(self, form: dict[str, str]) -> httpx.Response:
        """A raw token request: no Session header goes to an OAuth endpoint (§5.2)."""

        metadata = await self.metadata()
        return await self.send(
            "POST",
            metadata.token_endpoint,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
            content=urlencode(form).encode(),
        )

    async def client_form(self, identity: AgentIdentity | None = None) -> dict[str, str]:
        metadata = await self.metadata()
        actor = identity or self.agent.identity
        claims = self.claims(subject=actor.client_id, audience=metadata.issuer)
        claims["iss"] = actor.client_id
        return {
            "client_id": actor.client_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.assertion(claims, identity=actor),
        }


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _segment(value: dict[str, Any]) -> str:
    return _b64(json.dumps(value, separators=(",", ":")).encode())


def _client_metadata(identity: AgentIdentity) -> Any:
    from .models import ClientMetadata

    return ClientMetadata.model_validate(identity.metadata)


def _error(response: httpx.Response) -> str | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    error = payload.get("error") if isinstance(payload, dict) else None
    return error if isinstance(error, str) else None


def expect_refusal(response: httpx.Response, status: int, error: str | None, what: str) -> None:
    check(
        response.status_code == status,
        f"{what}: expected HTTP {status}, got {response.status_code}",
    )
    if error is not None:
        check(_error(response) == error, f"{what}: expected {error!r}, got {_error(response)!r}")


# Cases -------------------------------------------------------------------------------

CaseFunction = Callable[[ConformanceContext, FixtureCase], Awaitable[None]]
CASES: dict[str, CaseFunction] = {}


def case(*ids: str) -> Callable[[CaseFunction], CaseFunction]:
    """Register one coroutine for the fixture cases `ids`."""

    def register(function: CaseFunction) -> CaseFunction:
        for case_id in ids:
            if case_id in CASES:
                raise ValueError(f"conformance case {case_id} is registered twice")
            CASES[case_id] = function
        return function

    return register


# Protocol ----------------------------------------------------------------------------


@case("protocol.extension-required-company")
async def _extension_required(ctx: ConformanceContext, _: FixtureCase) -> None:
    other = ctx.other_agent()
    check("operations" not in other.identity.extensions, "the second identity lists no operations")
    proposal = ctx.proposal("user")
    user = ctx.new_user()
    session = await ctx.session(user, other)
    signed = await ctx.sign_in(user, session, agent=other)
    with _raises(ApiError) as raised:
        await other.api.call(
            proposal.method,
            ctx.url(proposal.path),
            session=signed.session,
            token=signed.token,
            body=proposal.body if proposal.body is not None else {},
        )
    error = raised.value
    check(error.code == "extension_required", f"expected extension_required, got {error.code}")
    check(error.status_code == 403, "extension_required is HTTP 403")


# Security: assertions ----------------------------------------------------------------


@case(
    "security.client-assertion-alg-none",
    "security.client-assertion-hs256-public-key",
    "security.client-assertion-ps384-header-on-ec-key",
    "security.client-assertion-embedded-key-ignored",
    "security.client-assertion-bad-audience",
    "security.client-assertion-audience-array",
    "security.client-assertion-token-endpoint-audience",
)
async def _client_assertion(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    metadata = await ctx.metadata()
    mutation = fixture.mutation
    client_id = ctx.agent.identity.client_id
    audience: Any = mutation.get("aud", metadata.issuer)
    if mutation.get("aud") == "token_endpoint":
        # The token endpoint is not the issuer: refused, compared character for character.
        audience = metadata.token_endpoint
    if mutation.get("aud_array"):
        audience = [metadata.issuer, "https://other-company.example"]
    claims = ctx.claims(subject=client_id, audience=audience)
    headers: dict[str, Any] = {}
    identity = None
    if mutation.get("signer") == "stranger":
        identity = AgentIdentity(domain=ctx.agent.identity.domain, name="Stranger", kid="key-1")
        if mutation.get("embed_jwk"):
            headers["jwk"] = identity.jwks["keys"][0]
    client_assertion = ctx.assertion(
        claims, identity=identity, algorithm=mutation.get("alg", "ES256"), headers=headers
    )
    form = {
        "grant_type": "refresh_token",
        "refresh_token": "rt_conformance_unknown",
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
    }
    response = await ctx.token_request(form)
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)
    check(client_assertion not in response.text, "a refusal never echoes the assertion")


@case(
    "security.session-jwt-alg-none",
    "security.session-jwt-wrong-signature",
    "security.session-jwt-wrong-typ",
    "security.session-jwt-wrong-kid",
    "security.session-jwt-signed-with-jwks-key",
    "security.session-jwt-expired-delegation",
    "security.session-jwt-delegation-over-24-hours",
    "security.session-jwt-delegation-wrong-typ",
    "security.session-jwt-delegation-stranger-key",
    "security.session-jwt-other-audience",
    "security.session-jwt-token-endpoint-audience",
    "security.session-jwt-method-mismatch",
    "security.session-jwt-url-mismatch",
    "security.session-jwt-stale",
    "security.session-jwt-from-the-future",
    "security.session-jwt-ath-mismatch",
    "security.session-jwt-ath-missing",
    "security.session-jwt-ath-without-token",
)
async def _session_jwt(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    """A Session JWT with one thing wrong: `invalid_session`, HTTP 400, whatever it was (§5.3)."""

    mutation = fixture.mutation
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    url = ctx.url(ctx.scenario.read_path)
    headers = await ctx.auth(session, "GET", url, signed.token)
    control = await ctx.send("GET", url, headers=headers)
    check(control.status_code == 200, "a valid Session JWT is accepted")
    token: AccessToken | None = signed.token
    if mutation.get("signed_out"):
        token = None
    forged = await ctx.forged_session_jwt(session, "GET", url, token=token, mutation=mutation)
    if mutation.get("tamper_signature"):
        other = await ctx.auth(session, "GET", url, signed.token)
        forged = ".".join([*headers["Poppy-Session"].split(".")[:2], _flip(other["Poppy-Session"])])
    sent = {"Poppy-Session": forged}
    if token is not None:
        sent["Authorization"] = f"Bearer {token.access_token.get_secret_value()}"
    response = await ctx.send("GET", url, headers=sent)
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)
    check(forged not in response.text, "a refusal never echoes the Session JWT")


def _flip(compact: str) -> str:
    """A signature that doesn't verify: another JWT's, one bit changed."""

    signature = compact.rsplit(".", 1)[1]
    return ("A" if signature[0] != "A" else "B") + signature[1:]


@case("security.session-header-missing")
async def _no_session_header(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    """A request with no Session header is refused, and its access token useless (§5.3)."""

    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    url = ctx.url(ctx.scenario.read_path)
    token = signed.token.access_token.get_secret_value()
    for headers in ({}, {"Authorization": f"Bearer {token}"}):
        response = await ctx.send("GET", url, headers=headers)
        expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)
        check(token not in response.text, "a refusal never echoes the access token")


@case("security.session-jwt-replay")
async def _session_jwt_replay(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    """A company MAY refuse a reused `jti` (§5.3); the reference company does."""

    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    url = ctx.url(ctx.scenario.read_path)
    headers = await ctx.auth(session, "GET", url, signed.token)
    first = await ctx.send("GET", url, headers=headers)
    check(first.status_code == 200, "the first use is accepted")
    second = await ctx.send("GET", url, headers=headers)
    expect_refusal(second, fixture.expect["status"], fixture.expect["error"], fixture.id)


@case("security.session-header-twice")
async def _session_header_twice(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    """Exactly one `Poppy-Session` header holding one JWT: two are `invalid_session` (§5.2)."""

    user = ctx.new_user()
    session = await ctx.session(user)
    url = ctx.url(ctx.scenario.read_path)
    first = await ctx.auth(session, "GET", url)
    second = await ctx.auth(session, "GET", url)
    request = httpx.Request(
        "GET",
        url,
        headers=[
            ("Poppy-Session", first["Poppy-Session"]),
            ("Poppy-Session", second["Poppy-Session"]),
        ],
    )
    response = await ctx.http.send(request, follow_redirects=False)
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)


@case("security.session-sub-stays-the-same")
async def _session_sub(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    """A known `sid` keeps its `sub` (§5.2, §5.3): another User ID in it is refused."""

    session = await ctx.session(ctx.new_user())
    url = ctx.url(ctx.scenario.read_path)
    await ctx.send("GET", url, headers=await ctx.auth(session, "GET", url))
    other = PapSession(
        sid=session.sid,
        sub=ctx.new_user(),
        issuer=session.issuer,
        client_id=session.client_id,
        tenant_id=session.tenant_id,
    )
    response = await ctx.send("GET", url, headers=await ctx.auth(other, "GET", url))
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)


@case("security.access-token-of-another-agent")
async def _token_of_another_agent(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    """The access token was issued to the same `client_id` as `iss` (§5.3)."""

    other = ctx.other_agent()
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    theirs = await ctx.session(user, other)
    url = ctx.url(ctx.scenario.read_path)
    response = await ctx.send(
        "GET", url, headers=await ctx.auth(theirs, "GET", url, signed.token, agent=other)
    )
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)


@case("security.token-in-url-refused")
async def _token_in_url(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    token = signed.token.access_token.get_secret_value()
    url = ctx.url(ctx.scenario.read_path)
    headers = await ctx.auth(session, "GET", url)
    response = await ctx.send("GET", f"{url}?{urlencode({'access_token': token})}", headers=headers)
    # Any refusal will do (§5.6 says only MUST NOT accept): 400 or 401 are both seen.
    check(
        400 <= response.status_code < 500,
        f"a token in the URL: expected a refusal, got {response.status_code}",
    )
    check(token not in response.text, "a refusal never echoes the access token")


@case("security.authorization-header-without-cookies")
async def _no_cookies(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    body = json.dumps(
        {
            "message": {
                "id": _message_id(),
                "author": {"type": "agent"},
                "text": ctx.scenario.greeting,
            }
        }
    ).encode()
    response = await ctx.send(
        "POST",
        endpoint,
        headers={
            **await ctx.auth(session, "POST", endpoint),
            "Content-Type": "application/json",
        },
        content=body,
    )
    check(response.status_code == 201, f"served without cookies: got {response.status_code}")


@case("security.token-responses-not-cached")
async def _no_store(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    form = {
        "grant_type": "refresh_token",
        "refresh_token": (await ctx.refresh_token(signed.reference)).get_secret_value(),
        **(await ctx.client_form()),
    }
    issued = await ctx.token_request(form)
    check(issued.status_code == 200, "the refresh is answered")
    check("no-store" in issued.headers.get("cache-control", ""), "a token response is not cached")
    if metadata.device_authorization_endpoint is not None:
        device_form = {
            "scope": ctx.scenario.read_scope,
            **(await ctx.client_form()),
            "client_assertion": ctx.assertion(
                ctx.claims(subject=ctx.agent.identity.client_id, audience=metadata.issuer)
            ),
        }
        codes = await ctx.send(
            "POST",
            metadata.device_authorization_endpoint,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            content=urlencode(device_form).encode(),
        )
        check(codes.status_code == 200, "Device Sign-In starts")
        check(
            "no-store" in codes.headers.get("cache-control", ""),
            "a device-code response is not cached",
        )


@case("security.refusals-disclose-no-credential")
async def _no_disclosure(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    refresh_token = await ctx.refresh_token(signed.reference)
    secret = refresh_token.get_secret_value()
    # The refresh token sent where it does not belong, with a bad client assertion.
    form = {
        "grant_type": "refresh_token",
        "refresh_token": secret,
        **(await ctx.client_form()),
    }
    form["client_assertion"] = ctx.assertion(
        ctx.claims(subject=ctx.agent.identity.client_id, audience="https://elsewhere.example/t")
    )
    refused = await ctx.token_request(form)
    check(refused.status_code in {400, 401}, "a bad client assertion is refused")
    for value in (secret, form["client_assertion"]):
        check(value not in refused.text, "a token refusal never echoes a credential")
    url = ctx.url(ctx.scenario.read_path)
    used = await ctx.send(
        "GET",
        url,
        headers={
            "Authorization": f"Bearer {secret}",
            "Poppy-Session": await ctx.forged_session_jwt(session, "GET", url, token=refresh_token),
        },
    )
    expect_refusal(used, 401, "invalid_token", "a refresh token at an API")
    check(secret not in used.text, "an API refusal never echoes a credential")


# Lifecycle -----------------------------------------------------------------------------


async def _probe(
    ctx: ConformanceContext, session: PapSession, token: AccessToken | None = None
) -> str:
    """What a read says of the request (§7): `served`, `signed_out`, or `invalid_token`.

    Signed out, a request for the account gets a 401 challenge with `scope` and no
    error code; an access token that stopped working gets `invalid_token`.
    """

    url = ctx.url(ctx.scenario.read_path)
    response = await ctx.send("GET", url, headers=await ctx.auth(session, "GET", url, token))
    if response.status_code == 200:
        return "served"
    challenge = challenge_parameters(response.headers.get("www-authenticate", ""))
    if response.status_code == 401 and "error" not in challenge and "scope" in challenge:
        return "signed_out"
    if response.status_code == 401 and challenge.get("error") == "invalid_token":
        return "invalid_token"
    return f"http_{response.status_code}"


@case("lifecycle.signed-out-session")
async def _signed_out(ctx: ConformanceContext, _: FixtureCase) -> None:
    session = await ctx.session(ctx.new_user())
    check(len(session.sid) >= 22, "a sid has at least 128 random bits")
    check(await _probe(ctx, session) == "signed_out", "a new Session is signed out")


@case("lifecycle.parallel-sessions")
async def _parallel(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    first, second = await asyncio.gather(ctx.session(user), ctx.session(user))
    check(first.sid != second.sid, "parallel Sessions are distinct")
    endpoint = await ctx.conversations_endpoint()
    for session in (first, second):
        receipt = await ctx.agent.conversations.start(
            endpoint, _message(ctx.scenario.greeting), session=session
        )
        check(receipt.conversation_id, "each Session is served")


@case("lifecycle.signed-out-challenge")
async def _signed_out_challenge(ctx: ConformanceContext, _: FixtureCase) -> None:
    """An account request with no access token: 401, `scope`, no error code (§7)."""

    session = await ctx.session(ctx.new_user())
    url = ctx.url(ctx.scenario.read_path)
    response = await ctx.send("GET", url, headers=await ctx.auth(session, "GET", url))
    check(response.status_code == 401, f"expected 401, got {response.status_code}")
    challenge = challenge_parameters(response.headers.get("www-authenticate", ""))
    check("scope" in challenge and "error" not in challenge, "the challenge names scopes only")
    with _raises(ApiError) as raised:
        await ctx.agent.api.call("GET", url, session=session)
    check(raised.value.code == "insufficient_scope", "the SDK reads it as insufficient_scope")


@case("lifecycle.sign-in-scopes")
async def _sign_in_scopes(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    granted = (ctx.scenario.read_scope,)
    signed = await ctx.sign_in(user, session, granted=granted)
    check(signed.token.scopes == granted, "only what the user approved is granted")
    check(await _probe(ctx, session, signed.token) == "served", "signed in with the token")
    check(await _probe(ctx, session) == "signed_out", "without it, the Session is signed out")


@case("lifecycle.unknown-scope-refused")
async def _unknown_scope(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    if metadata.device_authorization_endpoint is None:
        raise SkipCase("no Device Sign-In")
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.device.begin(
            device_authorization_endpoint=metadata.device_authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=ctx.agent.identity.client_id,
            scopes=("conformance:not-a-scope",),
            tenant_id=ctx.tenant_id,
            organization=(await ctx.company()).document.organization,
            protected_resources=metadata.protected_resources,
        )
    check(raised.value.code == "invalid_scope", f"got {raised.value.code}")


@case("lifecycle.refresh-token-serves-any-session")
async def _any_session(ctx: ConformanceContext, _: FixtureCase) -> None:
    """A refresh token isn't tied to a Session: any of the User's uses its tokens (§4.4, §5.4)."""

    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    fresh = await ctx.session(user)
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user)
    )
    check(result.status == "signed_in" and result.token is not None, "an access token comes back")
    check(
        await _probe(ctx, fresh, cast(AccessToken, result.token)) == "served",
        "and works in another Session",
    )


@case("lifecycle.rotated-token")
async def _rotated(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    before = await ctx.refresh_token(signed.reference)
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user)
    )
    if not result.rotated:
        raise SkipCase("the company does not rotate refresh tokens")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": before.get_secret_value(),
        **(await ctx.client_form()),
    }
    old = await ctx.token_request(form)
    expect_refusal(old, 400, "invalid_grant", "a rotated-away refresh token")
    again = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user)
    )
    check(again.status == "signed_in", "the stored, rotated token keeps working")


@case("lifecycle.narrower-scopes")
async def _narrower(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    result = await ctx.agent.accounts.refresh(
        signed.reference,
        context=await ctx.account_context(user),
        scopes=(ctx.scenario.read_scope,),
    )
    check(result.status == "signed_in", "a narrower refresh is answered")
    check(result.granted_scopes == (ctx.scenario.read_scope,), "only the narrower scope")


@case("lifecycle.wider-scopes-refused")
async def _wider(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user), granted=(ctx.scenario.read_scope,))
    result = await ctx.agent.accounts.refresh(
        signed.reference,
        context=await ctx.account_context(user),
        scopes=ctx.scenario.scopes,
    )
    check(result.status == "re_consent_required", f"got {result.status}")


@case("lifecycle.refresh-token-from-another-client")
async def _other_client(ctx: ConformanceContext, _: FixtureCase) -> None:
    other = ctx.other_agent()
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    form = {
        "grant_type": "refresh_token",
        "refresh_token": (await ctx.refresh_token(signed.reference)).get_secret_value(),
        **(await ctx.client_form(other.identity)),
    }
    response = await ctx.token_request(form)
    expect_refusal(response, 400, "invalid_grant", "another client's refresh token")


@case("lifecycle.refresh-token-at-api")
async def _refresh_token_at_api(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    secret = await ctx.refresh_token(signed.reference)
    url = ctx.url(ctx.scenario.read_path)
    response = await ctx.send(
        "GET",
        url,
        headers={
            "Authorization": f"Bearer {secret.get_secret_value()}",
            "Poppy-Session": await ctx.forged_session_jwt(session, "GET", url, token=secret),
        },
    )
    expect_refusal(response, 401, "invalid_token", "a refresh token at an API")


@case("lifecycle.sign-out-takes-effect")
async def _sign_out_now(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    check(await _probe(ctx, session, signed.token) == "served", "signed in, the read is served")
    revoked = await ctx.agent.accounts.revoke(
        signed.reference, context=await ctx.account_context(user)
    )
    check(revoked.revoked and revoked.deleted_locally, "the refresh token is revoked and gone")
    check(
        await _probe(ctx, session, signed.token) == "invalid_token",
        "the access token it gave stops working right away",
    )


@case("lifecycle.sign-out-session-continues")
async def _sign_out_continues(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    secret = await ctx.refresh_token(signed.reference)
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    check(await _probe(ctx, session) == "signed_out", "the Session continues signed out")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": secret.get_secret_value(),
        **(await ctx.client_form()),
    }
    expect_refusal(await ctx.token_request(form), 400, "invalid_grant", "a revoked token")


@case("lifecycle.sign-out-revokes-every-refresh-token")
async def _sign_out_everything(ctx: ConformanceContext, _: FixtureCase) -> None:
    """Sign-out revokes every refresh token held for the account (§4.6, §5.5)."""

    user = ctx.new_user()
    account = ctx.driver.accounts[0]
    first = await ctx.sign_in(user, await ctx.session(user), account=account)
    second = await ctx.sign_in(user, await ctx.session(user), account=account)
    context = await ctx.account_context(user)
    done = await ctx.agent.accounts.sign_out((first.reference, second.reference), context=context)
    check(done.signed_out and done.revoked == 2, "every refresh token is revoked")
    for signed in (first, second):
        check(
            await _probe(ctx, signed.session, signed.token) == "invalid_token",
            "the access tokens they gave stop working",
        )
        check(await _probe(ctx, signed.session) == "signed_out", "its Session goes on signed out")


@case("lifecycle.disconnect-from-account-settings")
async def _disconnect(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("disconnect")
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    await ctx.driver.disconnect(ctx.agent.identity.client_id, ctx.driver.accounts[0])
    check(
        await _probe(ctx, session, signed.token) == "invalid_token",
        "its access tokens stop working",
    )
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user)
    )
    check(result.status == "signed_out", "the agent finds out from invalid_grant")
    check(await ctx.agent.vault.get(signed.reference) is None, "and forgets the token")


# Conversations ------------------------------------------------------------------------


def _message_id() -> str:
    return "msg_" + base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")


def _message(text: str, author: Literal["agent", "human"] = "agent") -> Message:
    return Message(id=_message_id(), author=Author(type=author), text=text)


@case("conversations.start-and-reply")
async def _start_and_reply(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    receipt = await ctx.agent.conversations.start(
        endpoint, _message(ctx.scenario.greeting), session=session
    )
    check(receipt.status and receipt.responder, "the answer has status and responder")
    url = f"{endpoint}/{receipt.conversation_id}/events"
    raw = await ctx.send(
        "GET",
        url,
        headers={
            **await ctx.auth(session, "GET", url),
        },
    )
    body = raw.json()
    for key in ("cursor", "has_more", "status", "responder"):
        check(key in body, f"a read includes {key}")
    company = [
        e["message"]
        for e in body["events"]
        if e.get("type") == "message" and e["message"].get("role") == "company"
    ]
    check(company, "the company replies")
    check(
        all((m.get("author") or {}).get("type") in {"agent", "human"} for m in company),
        "replies carry author",
    )


@case("conversations.retry-replays")
async def _retry(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    message = _message(ctx.scenario.greeting)
    first = await ctx.agent.conversations.start(endpoint, message, session=session)
    page = await ctx.agent.conversations.read_events(
        endpoint, first.conversation_id, session=session
    )
    again = await ctx.agent.conversations.start(endpoint, message, session=session)
    check(again.conversation_id == first.conversation_id, "a retry returns the same one")
    after = await ctx.agent.conversations.read_events(
        endpoint, first.conversation_id, session=session
    )
    check(len(after.events) == len(page.events), "a retry adds nothing")


@case("conversations.message-id-conflict")
async def _conflict(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    message = _message(ctx.scenario.greeting)
    await ctx.agent.conversations.start(endpoint, message, session=session)
    changed = message.model_copy(update={"text": "Something else entirely."})
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.start(endpoint, changed, session=session)
    check(raised.value.code == "message_id_conflict", f"got {raised.value.code}")
    check(raised.value.status_code == 409, "message_id_conflict is HTTP 409")


async def _conversation(
    ctx: ConformanceContext,
    user: str,
    session: PapSession,
    token: AccessToken | None = None,
) -> str:
    endpoint = await ctx.conversations_endpoint()
    receipt = await ctx.agent.conversations.start(
        endpoint, _message(ctx.scenario.greeting), session=session, token=token
    )
    return receipt.conversation_id


@case("conversations.invalid-cursor")
async def _invalid_cursor(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    conversation = await _conversation(ctx, user, session)
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.read_events(
            await ctx.conversations_endpoint(),
            conversation,
            session=session,
            cursor="evt_never_issued_by_the_company",
        )
    check(raised.value.code == "invalid_cursor", f"got {raised.value.code}")
    check(raised.value.status_code == 400, "invalid_cursor is HTTP 400")


@case("conversations.cursor-expired-recovery")
async def _cursor_expired(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("forget_events")
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    conversation = await _conversation(ctx, user, session)
    page = await ctx.agent.conversations.read_events(endpoint, conversation, session=session)
    saved = page.events[0].id
    await ctx.agent.conversations.send(
        endpoint, conversation, _message("One more thing."), session=session
    )
    await ctx.driver.forget_events(conversation)
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.read_events(
            endpoint, conversation, session=session, cursor=saved
        )
    check(raised.value.code == "cursor_expired", f"got {raised.value.code}")
    check(raised.value.status_code == 410, "cursor_expired is HTTP 410")
    told: list[bool] = []
    events = ctx.agent.conversations.events(
        endpoint,
        conversation,
        session=session,
        cursor=saved,
        wait=0,
        on_cursor_expired=lambda: told.append(True),
    )
    async with contextlib.aclosing(events) as stream:
        first = await anext(stream)
    check(told == [True], "the host is told part of the conversation is missing")
    check(first.id != saved, "reading restarts from what the company still keeps")


@case("conversations.has-more-drained")
async def _has_more(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    conversation = await _conversation(ctx, user, session)
    page = await ctx.agent.conversations.read_events(endpoint, conversation, session=session)
    sent = 0
    while not page.has_more and sent < 80:
        await ctx.agent.conversations.send(
            endpoint, conversation, _message(f"Note {sent}."), session=session
        )
        sent += 1
        if sent % 10 == 0:
            page = await ctx.agent.conversations.read_events(
                endpoint, conversation, session=session
            )
    if not page.has_more:
        raise SkipCase("the company returned every event in one page")
    ids: list[str] = []
    cursor: str | None = None
    while True:
        current = await ctx.agent.conversations.read_events(
            endpoint, conversation, session=session, cursor=cursor
        )
        ids.extend(event.id for event in current.events)
        cursor = current.cursor
        if not current.has_more:
            break
    check(len(ids) == len(set(ids)), "draining has_more pages repeats nothing")
    check(ids[: len(page.events)] == [e.id for e in page.events], "pages keep the order")


@case("conversations.empty-read")
async def _empty(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    conversation = await _conversation(ctx, user, session)
    page = await ctx.agent.conversations.read_events(endpoint, conversation, session=session)
    empty = await ctx.agent.conversations.read_events(
        endpoint, conversation, session=session, cursor=page.cursor
    )
    check(empty.events == [], "nothing new: no events")
    check(empty.cursor == page.cursor, "the cursor is the request's own")
    check(empty.has_more is False, "has_more is false")


async def _stream_items(
    ctx: ConformanceContext,
    user: str,
    session: PapSession,
    conversation: str,
    *,
    last_event_id: str | None,
    until: Callable[[list[Any]], bool],
) -> list[Any]:
    endpoint = await ctx.conversations_endpoint()
    items: list[Any] = []
    stream = ctx.agent.conversations.stream(
        endpoint,
        conversation,
        session=session,
        last_event_id=last_event_id,
        max_reconnects=1,
    )
    async with contextlib.aclosing(stream) as iterator:
        async for item in iterator:
            items.append(item)
            if until(items):
                break
    return items


@case("conversations.sse-reconnect")
async def _sse(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    conversation = await _conversation(ctx, user, session)
    await ctx.agent.conversations.send(
        endpoint, conversation, _message("And another question."), session=session
    )
    every = await ctx.agent.conversations.read_events(endpoint, conversation, session=session)
    ids = [event.id for event in every.events]
    check(len(ids) >= 3, "the conversation has events to stream")

    def events_of(items: list[Any]) -> list[ConversationEvent]:
        return [item for item in items if isinstance(item, ConversationEvent)]

    try:
        first = await _stream_items(
            ctx, user, session, conversation, last_event_id=None,
            until=lambda items: len(events_of(items)) >= 2,
        )  # fmt: skip
    except PersonalAgentProtocolError as error:
        if error.code == "sse_unsupported":
            raise SkipCase("the company does not stream") from error
        raise
    handled = events_of(first)[-1].id
    resumed = await _stream_items(
        ctx, user, session, conversation, last_event_id=handled,
        until=lambda items: len(events_of(items)) >= 1,
    )  # fmt: skip
    check(
        events_of(resumed)[0].id == ids[ids.index(handled) + 1],
        "the stream resumes right after Last-Event-ID",
    )


@case("conversations.text-delta-not-actionable")
async def _deltas(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    conversation = await _conversation(ctx, user, session)

    def company_message(items: list[Any]) -> bool:
        return any(
            isinstance(item, ConversationEvent)
            and item.message is not None
            and item.message.role == "company"
            for item in items
        )

    try:
        items = await _stream_items(
            ctx, user, session, conversation, last_event_id=None, until=company_message
        )
    except PersonalAgentProtocolError as error:
        if error.code == "sse_unsupported":
            raise SkipCase("the company does not stream") from error
        raise
    deltas = [item for item in items if isinstance(item, TextDelta)]
    if not deltas:
        raise SkipCase("the company sends no text-delta pieces")
    check(all(delta.actionable is False for delta in deltas), "a delta is never actionable")
    complete = {
        item.message.id: item.message.text
        for item in items
        if isinstance(item, ConversationEvent) and item.message is not None
    }
    for delta in deltas:
        check(delta.message_id in complete, "the complete message replaces the pieces")


@case("conversations.attribution")
async def _attribution(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    words = _message("These are the user's own words.", author="human")
    receipt = await ctx.agent.conversations.start(endpoint, words, session=session)
    page = await ctx.agent.conversations.read_events(
        endpoint, receipt.conversation_id, session=session
    )
    messages = [event.message for event in page.events if event.message is not None]
    mine = [m for m in messages if m.id == words.id]
    check(mine and mine[0].role == "user", "the user's message comes back with role user")
    check(mine and mine[0].author.type == "human", "and keeps author human")
    theirs = [m for m in messages if m.role == "company"]
    check(
        theirs and all(m.author.type in {"agent", "human"} for m in theirs), "replies have author"
    )


@case("conversations.handoff")
async def _handoff(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    conversation = await _conversation(ctx, user, session)
    receipt = await ctx.agent.conversations.handoff(endpoint, conversation, session=session)
    check(receipt.status in {"queued", "idle", "working"}, "handoff answers a status")
    page = await ctx.agent.conversations.read_events(endpoint, conversation, session=session)
    states = [event for event in page.events if event.type == "state"]
    check(states, "each status change is a state event")
    check(states[-1].status == page.status, "the last state event is the current status")
    check(states[-1].responder == page.responder, "and the current responder")


@case("conversations.direct-conversation")
async def _direct(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    parent = await _conversation(ctx, user, session)
    direct = await ctx.agent.conversations.start_direct(
        endpoint, parent, _message("I'd like to ask myself.", author="human"), session=session
    )
    page = await ctx.agent.conversations.read_events(endpoint, parent, session=session)
    opened = [e for e in page.events if e.type == "direct_opened"]
    check(opened and opened[-1].conversation_id == direct.conversation_id, "direct_opened")
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.send(
            endpoint, parent, _message("Meanwhile."), session=session
        )
    check(raised.value.code == "direct_conversation_open", f"got {raised.value.code}")
    check(
        (raised.value.details or {}).get("conversation_id") == direct.conversation_id,
        "the refusal names the Direct Conversation",
    )
    await ctx.agent.conversations.close(endpoint, direct.conversation_id, session=session)
    page = await ctx.agent.conversations.read_events(endpoint, parent, session=session)
    check(any(e.type == "direct_closed" for e in page.events), "direct_closed")
    await ctx.agent.conversations.send(endpoint, parent, _message("Back to you."), session=session)


@case("conversations.direct-of-direct-refused")
async def _direct_of_direct(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    parent = await _conversation(ctx, user, session)
    direct = await ctx.agent.conversations.start_direct(
        endpoint, parent, _message("Hi.", author="human"), session=session
    )
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.start_direct(
            endpoint, direct.conversation_id, _message("Hi.", author="human"), session=session
        )
    check(
        raised.value.code
        in {"conversation_not_found", "conversation_closed", "direct_conversation_open"},
        f"got {raised.value.code}",
    )


@case("conversations.authorization-then-same-conversation")
async def _authorization(ctx: ConformanceContext, _: FixtureCase) -> None:
    prompt = ctx.scenario.account_prompt
    if prompt is None:
        raise SkipCase("the scenario has no account prompt")
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    receipt = await ctx.agent.conversations.start(endpoint, _message(prompt), session=session)
    page = await ctx.agent.conversations.read_events(
        endpoint, receipt.conversation_id, session=session
    )
    asks = [event for event in page.events if event.type == "authorization"]
    check(asks, "the company asks for sign-in with an authorization event")
    check(
        any(e.message is not None and e.message.role == "company" for e in page.events),
        "and says so in a message",
    )
    signed = await ctx.sign_in(user, session)
    again = await ctx.agent.conversations.send(
        endpoint,
        receipt.conversation_id,
        _message(prompt),
        session=signed.session,
        token=signed.token,
    )
    check(again.conversation_id == receipt.conversation_id, "the same conversation continues")


@case("conversations.closed")
async def _closed(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    conversation = await _conversation(ctx, user, session)
    closed = await ctx.agent.conversations.close(endpoint, conversation, session=session)
    check(closed.status == "closed", "closing answers status closed")
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.send(
            endpoint, conversation, _message("Still there?"), session=session
        )
    check(raised.value.code == "conversation_closed", f"got {raised.value.code}")
    check(raised.value.status_code == 409, "conversation_closed is HTTP 409")
    page = await ctx.agent.conversations.read_events(endpoint, conversation, session=session)
    check(page.status == "closed" and page.events, "its events stay readable")


@case("conversations.not-found-indistinguishable")
async def _not_found(ctx: ConformanceContext, _: FixtureCase) -> None:
    owner = ctx.new_user()
    theirs = await _conversation(ctx, owner, await ctx.session(owner))
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    bodies = []
    for conversation in (theirs, "cnv_conformance_unknown_000000"):
        url = f"{endpoint}/{conversation}/events"
        response = await ctx.send(
            "GET",
            url,
            headers={
                **await ctx.auth(session, "GET", url),
            },
        )
        bodies.append((response.status_code, response.json()))
    check(bodies[0] == bodies[1], "another user's and an unknown conversation look the same")
    check(bodies[0][0] == 404 and bodies[0][1].get("error") == "conversation_not_found", "404")


@case("conversations.signed-out-on-account-conversation")
async def _account_conversation(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    signed = await ctx.sign_in(user, session)
    conversation = await _conversation(ctx, user, session, signed.token)
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.read_events(endpoint, conversation, session=session)
    # The challenge with `scope` and no error code, read as `insufficient_scope` (§5.5, §7).
    check(raised.value.code == "insufficient_scope", f"got {raised.value.code}")
    check(raised.value.status_code == 401, "a signed-out request gets the 401 challenge")


# Operations --------------------------------------------------------------------------


async def _signed_in_user(ctx: ConformanceContext) -> tuple[str, SignedIn]:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    return user, signed


async def _propose(ctx: ConformanceContext, signed: SignedIn, kind: str) -> Operation:
    """The request for the action: refused, with the operation (Operations 4)."""

    answer = await _request(ctx, signed, kind)
    check(answer.status == 403 and answer.operation is not None, "approval_required, HTTP 403")
    return cast(Operation, answer.operation)


async def _request(
    ctx: ConformanceContext,
    signed: SignedIn,
    kind: str,
    approval: Approval | None = None,
    *,
    token: AccessToken | None = None,
    session: PapSession | None = None,
) -> Any:
    proposal = ctx.proposal(kind)
    return await ctx.agent.api.call(
        proposal.method,
        ctx.url(proposal.path),
        session=signed.session if session is None else session,
        token=signed.token if token is None else token,
        body=proposal.body if proposal.body is not None else {},
        approval=approval,
    )


async def _performed(ctx: ConformanceContext, operation: Operation, times: int) -> None:
    if "performed" in ctx.driver.capabilities:
        count = await ctx.driver.performed(operation.operation_id)
        check(count == times, f"performed {times} time(s), not {count}")


def _approved(operation: Operation) -> Approval:
    """A statement of the user's approval: the conformance runner plays the user here."""

    return Approval(operation_id=operation.operation_id, revision=operation.revision)


def _check_new_revision(answer: Any, operation: Operation, named: str) -> Operation:
    check(answer.operation is not None, "the company returns the operation, performing nothing")
    fresh = cast(Operation, answer.operation)
    check(fresh.revision != named, "never the revision the approval named")
    check(fresh.operation_id == operation.operation_id, "the same action, the same operation")
    return fresh


@case("operations.approval-required")
async def _approval_required(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    check(operation.summary.strip(), "it has a summary")
    check(operation.revision, "it has an opaque revision")
    check(operation.expires_at > ctx.now(), "it can still be approved")
    await _performed(ctx, operation, 0)
    proposal = ctx.proposal("user")
    if proposal.documented_as is not None:
        api = openapi_url((await ctx.company()).document)
        paths = (await ctx.send("GET", api)).json().get("paths", {}) if api else {}
        documented = proposal.documented_as
        check(
            "approval_required" in json.dumps(paths.get(documented, {})),
            "the API description says the endpoint can return approval_required",
        )


@case("operations.same-request-same-revision")
async def _same_revision(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    first = await _propose(ctx, signed, "user")
    second = await _propose(ctx, signed, "user")
    check(second == first, "the same request, the same terms: the same revision")


@case("operations.approved-performed")
async def _performs(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    done = await _request(ctx, signed, "user", _approved(operation))
    check(done.operation is None and 200 <= done.status < 300, f"performed, got {done.status}")
    await _performed(ctx, operation, 1)


@case("operations.retry-after-the-outcome")
async def _at_most_once(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    approval = _approved(operation)
    first = await _request(ctx, signed, "user", approval)
    second = await _request(ctx, signed, "user", approval)
    check(second.body == first.body, "a retry gets the original response")
    await _performed(ctx, operation, 1)


@case("operations.retry-before-the-outcome")
async def _before_outcome(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "unknown")
    approval = _approved(operation)
    for attempt in ("the first request", "a retry"):
        with _raises(ApiError) as raised:
            await _request(ctx, signed, "unknown", approval)
        check(raised.value.status_code == 503, f"{attempt} waits, HTTP 503, never a failure")
        check(
            (raised.value.details or {}).get("retry_after"),
            f"{attempt} says when: Retry-After",
        )
    await _performed(ctx, operation, 1)


@case("operations.new-revision-on-changed-terms")
async def _changed_terms(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("revise")
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    await ctx.driver.revise(operation.operation_id)
    answer = await _request(ctx, signed, "user", _approved(operation))
    current = _check_new_revision(answer, operation, operation.revision)
    check(current.summary != operation.summary, "the new revision has the new terms")
    await _performed(ctx, operation, 0)
    done = await _request(ctx, signed, "user", _approved(current))
    check(done.operation is None, "the new revision, approved, is performed")
    await _performed(ctx, operation, 1)


@case("operations.approval-of-a-revision-never-returned")
async def _never_returned(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    forged = Approval(operation_id=operation.operation_id, revision="never_returned_0000")
    answer = await _request(ctx, signed, "user", forged)
    _check_new_revision(answer, operation, forged.revision)
    await _performed(ctx, operation, 0)


@case("operations.approval-of-another-request")
async def _another_request(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    proposal = ctx.proposal("user")
    answer = await ctx.agent.api.call(
        proposal.method,
        ctx.url(proposal.path),
        session=signed.session,
        token=signed.token,
        body={"changed": "this request is not the one that returned the operation"},
        approval=_approved(operation),
    )
    _check_new_revision(answer, operation, operation.revision)
    await _performed(ctx, operation, 0)


@case("operations.approval-unknown-members-ignored")
async def _unknown_members(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    proposal = ctx.proposal("user")
    url = ctx.url(proposal.path)
    response = await ctx.send(
        proposal.method,
        url,
        headers={
            **await ctx.auth(signed.session, proposal.method, url, signed.token),
            "Content-Type": "application/json",
            APPROVAL_HEADER: f"later=1, {approval_header(_approved(operation))}, flag;a=b",
        },
        content=json.dumps(proposal.body if proposal.body is not None else {}).encode(),
    )
    check(response.status_code == 200, f"unknown members are ignored, got {response.status_code}")
    await _performed(ctx, operation, 1)


@case("operations.malformed-approval-header-ignored")
async def _malformed(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    proposal = ctx.proposal("user")
    url = ctx.url(proposal.path)
    for value in (
        f"operation_id={operation.operation_id}",  # Tokens, not Strings
        f'operation_id="{operation.operation_id}"',  # no revision
        f'operation_id="{operation.operation_id}", revision="{operation.revision}',  # unclosed
    ):
        response = await ctx.send(
            proposal.method,
            url,
            headers={
                **await ctx.auth(signed.session, proposal.method, url, signed.token),
                "Content-Type": "application/json",
                APPROVAL_HEADER: value,
            },
            content=json.dumps(proposal.body if proposal.body is not None else {}).encode(),
        )
        expect_refusal(response, 403, "approval_required", "a request without an approval")
    await _performed(ctx, operation, 0)


@case("operations.expired")
async def _expired(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("clock")
    await ctx.operations_negotiated()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    await ctx.driver.wait((operation.expires_at - ctx.now()).total_seconds() + 1)
    # The access token may have expired meanwhile: a new one from the refresh token.
    refreshed = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user)
    )
    token = cast(AccessToken, refreshed.token)
    answer = await _request(ctx, signed, "user", _approved(operation), token=token)
    _check_new_revision(answer, operation, operation.revision)
    await _performed(ctx, operation, 0)


@case("operations.any-session-of-the-account-approves")
async def _account_session(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    another = await ctx.session(user)
    done = await _request(ctx, signed, "user", _approved(operation), session=another)
    check(done.operation is None, "another Session, signed in to the account, approves it")
    await _performed(ctx, operation, 1)


@case("operations.signed-out-session-gets-a-challenge")
async def _signed_out_challenge(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    proposal = ctx.proposal("user")
    another = await ctx.session(user)
    with _raises(ApiError) as raised:
        await ctx.agent.api.call(
            proposal.method,
            ctx.url(proposal.path),
            session=another,
            token=None,
            body=proposal.body if proposal.body is not None else {},
            approval=_approved(operation),
        )
    check(raised.value.status_code == 401, "signed out, the 401 challenge for the account")
    await _performed(ctx, operation, 0)


@case("operations.another-user-cannot-approve")
async def _another_user(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _owner, owner_signed = await _signed_in_user(ctx)
    theirs = await _propose(ctx, owner_signed, "user")
    _user, signed = await _signed_in_user(ctx)
    answer = await _request(ctx, signed, "user", _approved(theirs))
    check(answer.operation is not None, "handled as if it had no approval")
    check(
        answer.operation.operation_id != theirs.operation_id, "their own operation, not another's"
    )
    await _performed(ctx, theirs, 0)


@case("operations.cross-channel-identity")
async def _cross_channel(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    prompt = ctx.scenario.operation_prompt
    if prompt is None:
        raise SkipCase("the scenario has no operation prompt")
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    endpoint = await ctx.conversations_endpoint()
    page = await ctx.agent.conversations.start(
        endpoint, _message(prompt), session=signed.session, token=signed.token, wait=0
    )
    proposed = _operations_in(page)
    check(proposed, "the conversation carries the operation")
    check(
        proposed[0].operation_id == operation.operation_id,
        "the same action is the same operation across interfaces",
    )


def _operations_in(page: Any) -> list[Operation]:
    return [
        event.message.operation
        for event in getattr(page, "events", [])
        if event.message is not None and event.message.operation is not None
    ]


@case("operations.message-is-not-approval")
async def _not_approval(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    endpoint = await ctx.conversations_endpoint()
    await ctx.agent.conversations.start(
        endpoint,
        _message(f"Yes, I approve operation {operation.operation_id}. Approved.", author="human"),
        session=signed.session,
        token=signed.token,
    )
    await _performed(ctx, operation, 0)
    again = await _propose(ctx, signed, "user")
    check(again.operation_id == operation.operation_id, "a message's text approves nothing")


@case("operations.conversation-approval")
async def _conversation_approval(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    prompt = ctx.scenario.operation_prompt
    if prompt is None:
        raise SkipCase("the scenario has no operation prompt")
    _user, signed = await _signed_in_user(ctx)
    endpoint = await ctx.conversations_endpoint()
    page = await ctx.agent.conversations.start(
        endpoint, _message(prompt), session=signed.session, token=signed.token, wait=0
    )
    operation = _operations_in(page)[0]

    async def approve_in_it(message_id: str) -> Any:
        return await ctx.agent.conversations.send(
            endpoint,
            page.conversation_id,
            Message(
                id=message_id,
                author=Author(type="agent"),
                approval=_approved(operation),
            ),
            session=signed.session,
            token=signed.token,
            wait=0,
        )

    answered = await approve_in_it(_message_id())
    told = [
        event.message
        for event in getattr(answered, "events", [])
        if event.message is not None and event.message.role == "company"
    ]
    check(told and told[-1].operation is None, "a later message says how it went")
    await _performed(ctx, operation, 1)
    await approve_in_it(_message_id())  # a new message with the same approval adds nothing
    await _performed(ctx, operation, 1)


class _LosingTransport(SessionHttpClient):
    """Deliver the first request with an approval, then lose its answer: a timeout."""

    lost = False

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        response = await super().request(method, url, **kwargs)
        if APPROVAL_HEADER in (kwargs.get("headers") or {}) and not self.lost:
            self.lost = True
            raise TransportError("request_failed", "the answer was lost")
        return response


@case("operations.lost-answer-same-approval")
async def _recovery(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "user")
    losing = _LosingTransport(reactor=ctx.agent.reactor, http_client=ctx.http)
    api = ApiClient(transport=losing)
    proposal = ctx.proposal("user")

    async def request(approval: Approval) -> Any:
        return await api.call(
            proposal.method,
            ctx.url(proposal.path),
            session=signed.session,
            token=signed.token,
            body=proposal.body if proposal.body is not None else {},
            approval=approval,
        )

    sent = await ctx.agent.operations.send(request, _approved(operation))
    check(losing.lost, "the answer was lost")
    check(sent.status == "answered", f"the same approval, sent again, got {sent.status}")
    await _performed(ctx, operation, 1)


@case("operations.failed-partial-result")
async def _failed(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    _user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, signed, "fails")
    answers = []
    for _attempt in range(2):
        with _raises(ApiError) as raised:
            await _request(ctx, signed, "fails", _approved(operation))
        answers.append((raised.value.code, raised.value.status_code))
    check(answers[0] == answers[1], "a retry gets the same answer")
    await _performed(ctx, operation, 1)


# MCP (§4.5, §7) ------------------------------------------------------------------------


async def _mcp_url(ctx: ConformanceContext) -> str:
    api = mcp_api((await ctx.company()).document)
    if api is None:
        raise SkipCase("the company lists no MCP server")
    return api.url


def _tool(name: str | None) -> str:
    if name is None:
        raise SkipCase("the scenario names no MCP tool for this")
    return name


async def _mcp_client(
    ctx: ConformanceContext, session: PapSession, token: AccessToken | None, url: str
) -> McpClient:
    return McpClient(
        http_client=ctx.http,
        url=url,
        session=session,
        reactor=ctx.agent.reactor,
        token=token,
    )


async def _signed_in_mcp(ctx: ConformanceContext) -> tuple[str, SignedIn, AccessToken, str]:
    """A signed-in user's access token for the MCP server: `resource` is its `url` (§7)."""

    url = await _mcp_url(ctx)
    user, signed = await _signed_in_user(ctx)
    result = await ctx.agent.accounts.token_for_mcp(
        signed.reference, context=await ctx.account_context(user), url=url
    )
    check(result.status == "signed_in" and result.token is not None, "a token for the server")
    return user, signed, cast(AccessToken, result.token), url


@case("lifecycle.mcp-protected-resource-metadata")
async def _mcp_metadata(ctx: ConformanceContext, _: FixtureCase) -> None:
    url = await _mcp_url(ctx)
    metadata = await ctx.metadata()
    served = await fetch_mcp_server_metadata(ctx.http, url, issuer=metadata.issuer)
    check(served.resource == url, "the metadata names the MCP server as its resource")
    check(url in metadata.protected_resources, "the issuer lists the MCP server")
    company = await ctx.company()
    resource = await DiscoveryClient(reactor=ctx.agent.reactor).service_resource(company, url)
    check(resource == url, "so a personal agent requests a token for its url (§4.5)")
    user = ctx.new_user()
    session = await ctx.session(user)
    signed_in = await ctx.sign_in(user, session)
    bare = await ctx.send(
        "POST",
        url,
        headers={
            **await ctx.auth(session, "POST", url, signed_in.token),
            "Content-Type": "application/json",
        },
        content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
    )
    check(bare.status_code == 401, "a default access token is refused at the MCP server")
    challenge = bare.headers.get("www-authenticate", "")
    check(challenge.startswith("Bearer") and "resource_metadata" in challenge, "Bearer challenge")
    check('error="invalid_token"' in challenge, "invalid_token: not issued for this service")


@case("lifecycle.mcp-token-for-its-url")
async def _mcp_token(ctx: ConformanceContext, _: FixtureCase) -> None:
    read_tool = _tool(ctx.scenario.mcp_read_tool)
    _user, signed, token, url = await _signed_in_mcp(ctx)
    check(token.token_type == "Bearer", "a Bearer token")  # noqa: S105
    check(token.resource == url, "issued for the server's url")
    answer = await (await _mcp_client(ctx, signed.session, token, url)).call_tool(read_tool)
    check(not answer.is_error, "the MCP server accepts it")
    # Signed out: the Session header alone, which this server takes; its scopes are enforced.
    other = await ctx.session(ctx.new_user())
    with _raises(McpError) as raised:
        await (await _mcp_client(ctx, other, None, url)).call_tool(read_tool)
    check(
        raised.value.code == "insufficient_scope",
        f"the MCP server enforces scopes, got {raised.value.code}",
    )
    check(raised.value.status_code == 401, "signed out, the 401 challenge")


@case("lifecycle.mcp-token-only-at-mcp")
async def _mcp_only(ctx: ConformanceContext, _: FixtureCase) -> None:
    _user, signed, token, _url = await _signed_in_mcp(ctx)
    secret = token.access_token.get_secret_value()
    targets = [("GET", ctx.url(ctx.scenario.read_path))]
    with contextlib.suppress(SkipCase):
        targets.append(("POST", await ctx.conversations_endpoint()))
    for method, target in targets:
        headers = {
            **await ctx.auth(signed.session, method, target, token),
            "Content-Type": "application/json",
        }
        response = await ctx.send(method, target, headers=headers, content=b"{}")
        check(response.status_code == 401, f"an MCP token is refused at {method} {target}")
        check(
            'error="invalid_token"' in response.headers.get("www-authenticate", ""),
            "invalid_token",
        )
        check(
            "resource_metadata" in response.headers.get("www-authenticate", ""),
            "with resource_metadata, for stale metadata (§4.5)",
        )
        check(secret not in response.text, "and never echoed")


@case("lifecycle.resource-not-served")
async def _resource_not_served(ctx: ConformanceContext, _: FixtureCase) -> None:
    """A `resource` the company doesn't serve is `invalid_target` (RFC 8707, §4.5)."""

    user, signed = await _signed_in_user(ctx)
    form = {
        "grant_type": "refresh_token",
        "refresh_token": (await ctx.refresh_token(signed.reference)).get_secret_value(),
        "resource": "https://elsewhere.example/mcp",
        **(await ctx.client_form()),
    }
    expect_refusal(await ctx.token_request(form), 400, "invalid_target", "another resource")
    del user


@case("lifecycle.stale-resource-metadata")
async def _stale_metadata(ctx: ConformanceContext, _: FixtureCase) -> None:
    """A service refusing a token not issued for it says where its metadata is (§4.5)."""

    url = await _mcp_url(ctx)
    read_tool = _tool(ctx.scenario.mcp_read_tool)
    user, signed = await _signed_in_user(ctx)
    tokens = ServiceTokens(
        refresh=ctx.agent.accounts,
        discovery=DiscoveryClient(reactor=ctx.agent.reactor),
        company=await ctx.company(),
        reference=signed.reference,
        context=await ctx.account_context(user),
    )
    # Stale: the default token, as if the server had no metadata of its own.
    default = await tokens.token_for(ctx.url(ctx.scenario.read_path))
    check(default is not None and default.resource is None, "the default token")
    stale = cast(AccessToken, default).model_copy(update={"resource": url})
    with _raises(McpError) as raised:
        await (await _mcp_client(ctx, signed.session, stale, url)).call_tool(read_tool)
    check(stale_resource_metadata(raised.value), "invalid_token with resource_metadata")
    fresh = await tokens.token_for(url, fresh=True)
    check(fresh is not None and fresh.resource == url, "a token for the service, read again")
    answer = await (await _mcp_client(ctx, signed.session, fresh, url)).call_tool(read_tool)
    check(not answer.is_error, "and the service takes it")


@case("lifecycle.mcp-sign-out-takes-effect")
async def _mcp_sign_out(ctx: ConformanceContext, _: FixtureCase) -> None:
    read_tool = _tool(ctx.scenario.mcp_read_tool)
    user, signed, token, url = await _signed_in_mcp(ctx)
    client = await _mcp_client(ctx, signed.session, token, url)
    check(not (await client.call_tool(read_tool)).is_error, "signed in, the tool answers")
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    with _raises(McpError) as raised:
        await client.call_tool(read_tool)
    check(raised.value.code == "invalid_token", f"got {raised.value.code}")


@case("operations.cross-channel-mcp")
async def _cross_channel_mcp(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    propose_tool = _tool(ctx.scenario.mcp_propose_tool)
    _user, signed, token, url = await _signed_in_mcp(ctx)
    through_api = await _propose(ctx, signed, "user")
    answer = await (await _mcp_client(ctx, signed.session, token, url)).call_tool(propose_tool)
    check(answer.is_error, "an error result, nothing done")
    check(answer.operation is not None, "with structuredContent.operation")
    check(
        cast(Operation, answer.operation).operation_id == through_api.operation_id,
        "the same operation as through the API",
    )


@case("operations.mcp-approval")
async def _mcp_approval(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_negotiated()
    propose_tool = _tool(ctx.scenario.mcp_propose_tool)
    _user, signed, token, url = await _signed_in_mcp(ctx)
    client = await _mcp_client(ctx, signed.session, token, url)
    operation = cast(Operation, (await client.call_tool(propose_tool)).operation)
    approval = _approved(operation)
    done = await client.call_tool(propose_tool, approval=approval)
    check(not done.is_error and done.operation is None, "the same call, approved, is performed")
    again = await client.call_tool(propose_tool, approval=approval)
    check(again.text == done.text, "a retry gets the original result")
    await _performed(ctx, operation, 1)


# Draft 0.2 company rules --------------------------------------------------------------


@case("protocol.feedback-report")
async def _feedback(ctx: ConformanceContext, _: FixtureCase) -> None:
    """A report with the Session header, no scope: 202, or 200; malformed, 400 (§9.3)."""

    endpoint = feedback_endpoint((await ctx.company()).document)
    if endpoint is None:
        raise SkipCase("the company lists no feedback endpoint")
    user = ctx.new_user()
    session = await ctx.session(user)

    async def post(body: dict[str, Any]) -> httpx.Response:
        return await ctx.send(
            "POST",
            endpoint,
            headers={
                **await ctx.auth(session, "POST", endpoint),
                "Content-Type": "application/json",
            },
            content=json.dumps(body).encode(),
        )

    report = {"task": "Conformance task", "description": "Not offered."}
    accepted = await post(report)
    # 202, or 200 with an alternative when the task can be done after all (§9.3).
    check(
        accepted.status_code in {200, 202},
        f"a report is accepted with 202 or 200, got {accepted.status_code}",
    )
    unknown = await post({**report, "later": "a member it doesn't recognize"})
    check(unknown.status_code in {200, 202}, "a member it doesn't recognize is ignored")
    expect_refusal(await post({**report, "task": "x" * 201}), 400, "invalid_request", "too long")
    bare = await ctx.send(
        "POST", endpoint, headers={"Content-Type": "application/json"}, content=b"{}"
    )
    expect_refusal(bare, 400, "invalid_session", "a report needs the Session header")


@case("conversations.read-fields")
async def _read_fields(ctx: ConformanceContext, _: FixtureCase) -> None:
    """Every read has conversation_id, events, cursor, has_more, status, responder (§7.5)."""

    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    conversation = await _conversation(ctx, user, session)
    url = f"{endpoint.rstrip('/')}/{conversation}/events"
    first = await ctx.send(
        "GET",
        url,
        headers={
            **await ctx.auth(session, "GET", url),
        },
    )
    page = first.json()
    later = f"{url}?cursor={page['cursor']}"
    empty = (
        await ctx.send(
            "GET",
            later,
            headers={
                **await ctx.auth(session, "GET", later),
            },
        )
    ).json()
    fields = {"conversation_id", "events", "cursor", "has_more", "status", "responder"}
    for read in (page, empty):
        check(fields <= set(read), f"a read has {sorted(fields - set(read))} missing")
    check(empty["events"] == [], "events is an empty list when there are none")


# The website (§6) ---------------------------------------------------


async def _browser(ctx: ConformanceContext) -> tuple[ControlledBrowser, str]:
    web = (await ctx.company()).document.web
    if web is None or web.browser_session_endpoint is None:
        raise SkipCase("the company offers no browser sessions")
    if ctx.agent.browser is None:
        raise SkipCase("the runner was given no browser of its own")
    return ctx.agent.browser, web.browser_session_endpoint


async def _join(
    ctx: ConformanceContext, signed: SignedIn | PapSession, page: str
) -> list[httpx.Response]:
    """Join the runner's own browser to the Session (§6), then open `page` in it.

    Returns the join's responses: the 303 that set the Session's cookie first.
    """

    browser, endpoint = await _browser(ctx)
    session = signed.session if isinstance(signed, SignedIn) else signed
    token = signed.token if isinstance(signed, SignedIn) else None
    await BrowserSessionClient(reactor=ctx.agent.reactor, transport=ctx.agent.transport).join(
        browser_session_endpoint=endpoint, session=session, token=token
    )
    joined = cast(httpx.Response, browser.page)
    check(joined.history and joined.history[0].status_code == 303, "joined with 303 See Other")
    await browser.get(page)
    return list(joined.history)


@case("lifecycle.browser-joins-session")
async def _browser_joins(ctx: ConformanceContext, _: FixtureCase) -> None:
    _browser_used, endpoint = await _browser(ctx)
    loaded = await ctx.send("GET", endpoint)
    check(loaded.status_code == 200, "the join page loads with a GET")
    for name, value in (
        ("cache-control", "no-store"),
        ("content-security-policy", "frame-ancestors 'none'"),
        ("cross-origin-opener-policy", "same-origin"),
    ):
        check(value in loaded.headers.get(name, ""), f"the join page sends {name}: {value}")
    join_cookie = loaded.headers.get("set-cookie", "")
    for flag in ("__Host-", "Secure", "HttpOnly", "SameSite=Strict"):
        check(flag.lower() in join_cookie.lower(), f"the join cookie has {flag}")
    _user, signed = await _signed_in_user(ctx)
    joined = await _join(ctx, signed, ctx.url("/"))
    cookies = [
        value
        for response in joined
        for value in response.headers.get_list("set-cookie")
        if "max-age=0" not in value.lower()
    ]
    session_cookie = next((c for c in cookies if "secure" in c.lower()), "")
    for flag in ("Secure", "HttpOnly"):
        check(flag.lower() in session_cookie.lower(), f"the Session's cookie is {flag}")
    check("max-age" not in session_cookie.lower(), "the cookie has no lifetime of its own")


@case("lifecycle.browser-join-refused")
async def _browser_refused(ctx: ConformanceContext, _: FixtureCase) -> None:
    """Steps 2 and 3 of §6 and the attacks of §10.6: each wrong join sets no Session cookie."""

    _browser_unused, endpoint = await _browser(ctx)
    user = ctx.new_user()
    session = await ctx.session(user)
    code_field = re.compile(r'name="code" value="([^"]+)"')
    authorize_url = f"{endpoint.rstrip('/')}/authorize"

    async def form() -> tuple[httpx.AsyncClient, str]:
        browser = ctx.new_browser()
        page = await browser.get(endpoint)
        found = code_field.search(page.text)
        check(found is not None, "the join page holds a code")
        return browser, cast(re.Match[str], found).group(1)

    async def authorize(code: str) -> httpx.Response:
        return await ctx.send(
            "POST",
            authorize_url,
            headers={
                **await ctx.auth(session, "POST", authorize_url),
                "Content-Type": "application/json",
            },
            content=json.dumps({"code": code}).encode(),
        )

    async def submit(browser: httpx.AsyncClient, code: str) -> httpx.Response:
        return await browser.post(endpoint, data={"code": code})

    def joined(response: httpx.Response) -> bool:
        return any(
            "max-age=0" not in value.lower() for value in response.headers.get_list("set-cookie")
        )

    browser, code = await form()
    done = await authorize(code)
    check(done.status_code == 204, f"the agent authorizes a code: got {done.status_code}")
    again = await authorize(code)
    expect_refusal(again, 400, "invalid_request", "a code authorized twice")
    unknown = await authorize("bc_conformance_" + "x" * 16)
    expect_refusal(unknown, 400, "invalid_request", "a code the company never issued")
    victim = ctx.new_browser()
    stolen = await submit(victim, code)
    check(
        stolen.status_code == 400 and not joined(stolen), "a code from another browser joins none"
    )
    used = await submit(browser, code)
    check(used.status_code == 400 and not joined(used), "a code is used once, whatever the result")
    browser, code = await form()
    unauthorized = await submit(browser, code)
    check(
        unauthorized.status_code == 400 and not joined(unauthorized),
        "a code the agent never authorized joins none",
    )
    browser, code = await form()
    check((await authorize(code)).status_code == 204, "the agent authorizes a new code")
    valid = await submit(browser, code)
    check(valid.status_code == 303 and joined(valid), "a valid join sets the Session's cookie")


# Running and reporting ----------------------------------------------------------------


class _Raised:
    value: Any = None


@contextlib.contextmanager
def _raises(kind: type[BaseException]) -> Any:
    """Expect `kind` (a refusal) from the block; anything else fails the case."""

    holder = _Raised()
    try:
        yield holder
    except kind as error:
        holder.value = error
        return
    raise ConformanceFailure(f"expected the company to refuse ({kind.__name__})")


@dataclass(frozen=True)
class CaseResult:
    id: str
    suite: str
    kind: str
    requirements: tuple[str, ...]
    outcome: Outcome
    duration_seconds: float
    message: str | None = None
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "suite": self.suite,
            "kind": self.kind,
            "requirements": list(self.requirements),
            "outcome": self.outcome,
            "duration_seconds": round(self.duration_seconds, 4),
            "message": self.message,
        }


@dataclass(frozen=True)
class ConformanceReport:
    """The suite's results, as JSON or JUnit."""

    target: str
    agent: str
    profile: str
    started_at: datetime
    results: tuple[CaseResult, ...]

    @classmethod
    def from_json(cls, document: dict[str, Any]) -> ConformanceReport:
        """Read back a report written by `to_json`."""

        if document.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported conformance report schema")
        return cls(
            target=document["target"],
            agent=document["agent"],
            profile=document["profile"],
            started_at=datetime.fromisoformat(document["started_at"]),
            results=tuple(
                CaseResult(
                    id=item["id"],
                    suite=item["suite"],
                    kind=item["kind"],
                    requirements=tuple(item["requirements"]),
                    outcome=item["outcome"],
                    duration_seconds=float(item["duration_seconds"]),
                    message=item.get("message"),
                )
                for item in document["cases"]
            ),
        )

    def counts(self) -> dict[str, int]:
        counts = {"passed": 0, "failed": 0, "skipped": 0}
        for result in self.results:
            counts[result.outcome] += 1
        return counts

    @property
    def passed(self) -> bool:
        return self.counts()["failed"] == 0

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "protocol": "personal-agent-protocol",
            "profile": self.profile,
            "extensions": {"operations": "1"},
            "role": "personal-agent",
            "target": self.target,
            "agent": self.agent,
            "started_at": self.started_at.isoformat(),
            "summary": self.counts(),
            "cases": [result.as_dict() for result in self.results],
        }

    def to_junit(self) -> str:
        root = ElementTree.Element("testsuites", name="pap-conformance")
        by_suite: dict[str, list[CaseResult]] = {}
        for result in self.results:
            by_suite.setdefault(result.suite, []).append(result)
        for suite, results in by_suite.items():
            element = ElementTree.SubElement(
                root,
                "testsuite",
                name=f"pap.{suite}",
                tests=str(len(results)),
                failures=str(sum(r.outcome == "failed" for r in results)),
                skipped=str(sum(r.outcome == "skipped" for r in results)),
                time=f"{sum(r.duration_seconds for r in results):.4f}",
            )
            for result in results:
                testcase = ElementTree.SubElement(
                    element,
                    "testcase",
                    classname=f"pap.{suite}",
                    name=result.id,
                    time=f"{result.duration_seconds:.4f}",
                )
                properties = ElementTree.SubElement(testcase, "properties")
                for requirement in result.requirements:
                    ElementTree.SubElement(
                        properties, "property", name="requirement", value=requirement
                    )
                if result.outcome == "failed":
                    ElementTree.SubElement(
                        testcase, "failure", message=result.message or "failed"
                    ).text = result.message
                elif result.outcome == "skipped":
                    ElementTree.SubElement(testcase, "skipped", message=result.message or "")
        return ElementTree.tostring(root, encoding="unicode", xml_declaration=True)


def select_cases(
    *,
    ids: Iterable[str] = (),
    requirements: Iterable[str] = (),
    suites: Iterable[str] = (),
) -> tuple[FixtureCase, ...]:
    """The runner's fixture cases, filtered by ID, requirement, or suite."""

    wanted_ids, wanted_reqs, wanted_suites = frozenset(ids), frozenset(requirements), set(suites)
    return tuple(
        fixture
        for fixture in load_fixture_cases()
        if fixture.id in CASES
        and (not wanted_ids or fixture.id in wanted_ids)
        and (not wanted_reqs or wanted_reqs.intersection(fixture.requirements))
        and (not wanted_suites or fixture.suite in wanted_suites)
    )


async def run_conformance(
    context: ConformanceContext,
    *,
    cases: Iterable[FixtureCase] | None = None,
    timeout: float = 30.0,
) -> ConformanceReport:
    """Run each case against the company; a failure never stops the others."""

    started = datetime.now(timezone.utc)
    results: list[CaseResult] = []
    for fixture in cases if cases is not None else select_cases():
        began = time.perf_counter()
        outcome: Outcome = "passed"
        message: str | None = None
        try:
            await asyncio.wait_for(CASES[fixture.id](context, fixture), timeout)
        except SkipCase as skipped:
            outcome, message = "skipped", str(skipped)
        except ConformanceFailure as failure:
            outcome, message = "failed", str(failure)
        except PersonalAgentProtocolError as error:
            outcome, message = "failed", f"{type(error).__name__}: {error.code}"
        except TimeoutError:
            outcome, message = "failed", f"timed out after {timeout:g}s"
        except Exception as error:
            outcome, message = "failed", f"{type(error).__name__}"
        results.append(
            CaseResult(
                id=fixture.id,
                suite=fixture.suite,
                kind=fixture.kind,
                requirements=fixture.requirements,
                outcome=outcome,
                duration_seconds=time.perf_counter() - began,
                message=message,
                description=fixture.description,
            )
        )
    return ConformanceReport(
        target=context.base_url,
        agent=context.agent.identity.client_id,
        profile=PROTOCOL_PROFILE,
        started_at=started,
        results=tuple(results),
    )


__all__ = [
    "CASES",
    "Agent",
    "CaseResult",
    "ConformanceContext",
    "ConformanceFailure",
    "ConformanceReport",
    "FixtureCase",
    "Proposal",
    "Scenario",
    "SkipCase",
    "UserDriver",
    "check",
    "load_fixture_cases",
    "run_conformance",
    "select_cases",
]
