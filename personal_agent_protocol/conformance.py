# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A personal-agent conformance suite, run against any PAP company's base URL.

The suite plays a personal agent with a demo-kit identity (`AgentIdentity`):
it discovers the company, starts Sessions, signs in, talks, and confirms
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
from pydantic import SecretStr
from reactor import PluginPlatform  # type: ignore[import-untyped]

from .accounts import AccountTokenClient, AccountTokenContext
from .apis import ApiClient, ApiError, conversation_endpoint, openapi_url
from .auth import DirectSignInClient
from .browser import BrowserSessionClient
from .conversations import ConversationClient, TextDelta
from .crypto import JoseDpopProofProvider
from .demo.kit import AgentIdentity, ControlledBrowser, MemoryVault, MutableClock, PersonalAgentHost
from .device import DeviceSignInClient
from .discovery import DiscoveryClient
from .errors import PersonalAgentProtocolError, TransportError
from .feedback import feedback_endpoint
from .mcp import McpClient, McpError, fetch_mcp_server_metadata, mcp_api
from .models import Author, ConversationEvent, DiscoveredCompany, Message, Operation
from .operations import (
    STANDING_PERMISSION_STORES,
    InMemoryStandingPermissionStore,
    OperationError,
    OperationsClient,
    StandingPermission,
    TermLimit,
    approve,
    operation_page,
    operations_endpoint,
)
from .profile import PROTOCOL_PROFILE
from .reactor import (
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    AddressResolver,
    Clock,
    DpopProofRequest,
    SystemClock,
    build_pap_reactor,
    first_contribution,
    resolve_addresses,
)
from .requirements import protocol_path
from .sessions import SessionClient, SessionToken, Who
from .transport import DpopHttpClient

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
    """A company API call that proposes an operation (Operations §4.1).

    `documented_as` is how the company's OpenAPI description names the path.
    """

    method: str
    path: str
    body: Any = None
    documented_as: str | None = None


@dataclass(frozen=True)
class Scenario:
    """What the suite asks of one company: its scopes, paths, and prompts.

    `proposals` are keyed `user` (needs the user's approval), `standing`
    (a standing permission may cover it), `fails` (fails partway), and
    `unknown` (its outcome stays unknown). `operation_prompt` makes the
    company agent propose the `user` proposal in a conversation;
    `account_prompt` makes it ask for sign-in. `mcp_read_tool` needs
    `read_scope`; `mcp_propose_tool` proposes the `user` proposal.
    `web_confirm_form` is what the operation's page posts to confirm it
    (`{revision}` is replaced), since the website's form is the company's own.
    """

    read_path: str
    read_scope: str
    scopes: tuple[str, ...]
    proposals: dict[str, Proposal] = field(default_factory=dict)
    standing_action: str | None = None
    standing_limits: tuple[TermLimit, ...] = ()
    standing_too_low: tuple[TermLimit, ...] = ()
    operation_prompt: str | None = None
    account_prompt: str | None = None
    greeting: str = "Hello."
    mcp_read_tool: str | None = None
    mcp_propose_tool: str | None = None
    web_confirm_form: dict[str, str] | None = None


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
        self.standing = InMemoryStandingPermissionStore()
        self.browser = ControlledBrowser(browser_http) if browser_http is not None else None
        #: The user's browser: the authorization URLs Direct Sign-In opened, for the driver.
        self.user_browser = _UserBrowser()
        host = PersonalAgentHost(
            identity,
            cast(MutableClock, clock),
            vault=self.vault,
            standing=self.standing,
            controlled_browser=self.browser,
            browser=cast(Any, self.user_browser),
        )
        self.reactor: PluginPlatform
        self.reactor, _ = build_pap_reactor(
            http_client=http,
            address_resolver=address_resolver,
            plugins=[(_manifest(identity), host)],
        )
        self.transport = DpopHttpClient(reactor=self.reactor, http_client=http)
        self.sessions = SessionClient(reactor=self.reactor, http_client=http)
        self.device = DeviceSignInClient(reactor=self.reactor, http_client=http)
        self.accounts = AccountTokenClient(reactor=self.reactor, http_client=http)
        self.api = ApiClient(transport=self.transport)
        self.conversations = ConversationClient(transport=self.transport)
        self.operations = OperationsClient(transport=self.transport)


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
    """A signed-in Session and the opaque reference to its Account Token."""

    token: SessionToken
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

    async def operations_endpoint(self) -> str:
        endpoint = operations_endpoint(
            (await self.company()).document,
            _client_metadata(self.agent.identity),
        )
        if endpoint is None:
            raise SkipCase("operations v1 is not negotiated with this company")
        return endpoint

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

    async def who(self, user: str) -> Who:
        metadata = await self.metadata()
        return {"tenant_id": self.tenant_id, "issuer": metadata.issuer}

    async def session(self, user: str, agent: Agent | None = None) -> SessionToken:
        metadata = await self.metadata()
        actor = agent or self.agent
        return await actor.sessions.start(
            client_id=actor.identity.client_id,
            pairwise_user_id=user,
            issuer=metadata.issuer,
            token_endpoint=metadata.token_endpoint,
            tenant_id=self.tenant_id,
        )

    async def sign_in(
        self,
        user: str,
        session: SessionToken,
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
            session_key=session.session_key,
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
                token, reference = polled.token, polled.account_token_reference
                check(token is not None and reference is not None, "sign-in returns its token")
                return SignedIn(cast(SessionToken, token), cast(str, reference))
        raise ConformanceFailure("Device Sign-In did not complete after approval")

    async def _direct_sign_in(
        self,
        actor: Agent,
        user: str,
        session: SessionToken,
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
            session_key=session.session_key,
        )
        callback = await self.driver.approve_authorization(
            actor.user_browser.urls[-1],
            account=account or self.driver.accounts[0],
            scopes=granted,
        )
        done = await client.complete(callback)
        check(done.account_token_reference is not None, "sign-in returns its Account Token")
        return SignedIn(done.token, cast(str, done.account_token_reference))

    async def account_context(self, user: str, agent: Agent | None = None) -> AccountTokenContext:
        metadata = await self.metadata()
        actor = agent or self.agent
        return AccountTokenContext(
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=actor.identity.client_id,
            tenant_id=self.tenant_id,
            pairwise_user_id=user,
            revocation_endpoint=metadata.revocation_endpoint,
        )

    async def account_token(self, reference: str) -> SecretStr:
        value = await self.agent.vault.get(reference)
        check(isinstance(value, SecretStr), "the Account Token is stored behind its reference")
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

    async def proof(
        self,
        user: str,
        method: str,
        url: str,
        *,
        token: SessionToken | SecretStr | None = None,
        session_key: str | None = None,
        agent: Agent | None = None,
        shift: float = 0,
        nonce: str | None = None,
    ) -> str:
        """A DPoP proof, optionally made `shift` seconds off.

        Signed with `session_key`, else the key of `token`'s Session, else a new
        Session Key: a proof from a key the company has never seen starts a Session
        at the token endpoint (§4.3).
        """

        del user  # a proof names a Session by its key, not the user (§4.3)
        metadata = await self.metadata()
        provider = first_contribution(
            (agent or self.agent).reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"
        )
        if session_key is None and isinstance(token, SessionToken):
            session_key = token.session_key
        if session_key is None:
            session_key = await provider.new_session_key(  # type: ignore[attr-defined]
                tenant_id=self.tenant_id, issuer=metadata.issuer
            )
        if shift:
            if not isinstance(provider, JoseDpopProofProvider):
                raise SkipCase("the DPoP provider cannot make a proof at another time")
            provider = JoseDpopProofProvider(
                provider.keys, now=lambda: self.now() + timedelta(seconds=shift)
            )
        access = token.access_token if isinstance(token, SessionToken) else token
        proof = await provider.create(  # type: ignore[attr-defined]
            DpopProofRequest(
                method=method,
                url=url,
                tenant_id=self.tenant_id,
                issuer=metadata.issuer,
                session_key=session_key,
                access_token=access,
                nonce=nonce,
            )
        )
        return cast(SecretStr, proof).get_secret_value()

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
        if algorithm == "RS256":
            _, payload, signature = token.split(".")
            return f"{_segment({**header, 'alg': 'RS256'})}.{payload}.{signature}"
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

    async def token_request(
        self,
        user: str,
        form: dict[str, str],
        *,
        dpop: str | None | Literal[True] = True,
    ) -> httpx.Response:
        """A raw token request; `dpop=True` makes a fresh valid proof, `None` sends none."""

        metadata = await self.metadata()
        endpoint = metadata.token_endpoint
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        if dpop is True:
            headers["DPoP"] = await self.proof(user, "POST", endpoint)
        elif dpop is not None:
            headers["DPoP"] = dpop
        return await self.send("POST", endpoint, headers=headers, content=urlencode(form).encode())

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
            token=signed.token,
            body=proposal.body if proposal.body is not None else {},
            **(await ctx.who(user)),
        )
    error = raised.value
    check(error.code == "extension_required", f"expected extension_required, got {error.code}")
    check(error.status_code == 403, "extension_required is HTTP 403")


# Security: assertions ----------------------------------------------------------------


@case(
    "security.client-assertion-alg-none",
    "security.client-assertion-hs256-public-key",
    "security.client-assertion-rs256-header-on-ec-key",
    "security.client-assertion-embedded-key-ignored",
    "security.client-assertion-bad-audience",
    "security.client-assertion-audience-array",
    "security.client-assertion-token-endpoint-audience",
)
async def _client_assertion(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    metadata = await ctx.metadata()
    mutation = fixture.mutation
    user = ctx.new_user()
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
    session_claims = ctx.claims(subject=user, audience=metadata.issuer)
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": ctx.assertion(session_claims),
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
    }
    response = await ctx.token_request(user, form)
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)
    check(client_assertion not in response.text, "a refusal never echoes the assertion")


@case(
    "security.session-assertion-bad-audience",
    "security.session-assertion-token-endpoint-audience",
    "security.session-assertion-five-minutes",
    "security.session-assertion-wrong-issuer",
    "security.session-assertion-clock-skew-tolerated",
    "security.session-assertion-from-the-future",
    "security.session-assertion-expired",
    "security.session-assertion-long-lived",
    "security.session-assertion-replay",
    "security.browser-assertion-at-token-endpoint",
)
async def _session_assertion(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    metadata = await ctx.metadata()
    mutation = fixture.mutation
    user = ctx.new_user()
    claims = ctx.claims(
        subject=user,
        audience=metadata.token_endpoint
        if mutation.get("aud") == "token_endpoint"
        else mutation.get("aud", metadata.issuer),
        lifetime=int(mutation.get("lifetime", 60)),
        shift=int(mutation.get("iat_offset", 0)),
    )
    if "iss" in mutation:
        claims["iss"] = mutation["iss"]
    headers = {"typ": mutation["typ"]} if "typ" in mutation else None
    assertion = ctx.assertion(claims, headers=headers)

    async def send() -> httpx.Response:
        form = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion,
            **(await ctx.client_form()),
        }
        return await ctx.token_request(user, form)

    response = await send()
    if mutation.get("replay"):
        check(response.status_code == 200, "the first use of the assertion is accepted")
        response = await send()
    if fixture.expect["status"] == 200:
        check(response.status_code == 200, f"{fixture.id}: expected 200")
        body = response.json()
        # Signed out: the grant says so, and there is no `scope` (§4.2); no Session is named.
        check("scope" not in body and "signed_in" not in body, "a new Session starts signed out")
        check("session_id" not in body, "the response names no Session: its key does")
        return
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)


@case("security.token-request-without-dpop", "security.token-dpop-with-ath")
async def _token_dpop(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": ctx.assertion(ctx.claims(subject=user, audience=metadata.issuer)),
        **(await ctx.client_form()),
    }
    if fixture.mutation.get("omit"):
        response = await ctx.token_request(user, form, dpop=None)
    else:
        proof = await ctx.proof(
            user,
            "POST",
            metadata.token_endpoint,
            token=SecretStr(fixture.mutation["ath"]),
        )
        response = await ctx.token_request(user, form, dpop=proof)
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)


# Security: proofs at a resource -----------------------------------------------------------


@case(
    "security.dpop-alg-none",
    "security.dpop-wrong-signature",
    "security.dpop-other-key",
    "security.dpop-method-mismatch",
    "security.dpop-url-mismatch",
    "security.dpop-stale",
    "security.dpop-replay",
    "security.dpop-token-hash-mismatch",
    "security.dpop-missing",
    "security.dpop-token-as-bearer",
)
async def _resource_dpop(  # noqa: C901 - one branch per proof mutation
    ctx: ConformanceContext, fixture: FixtureCase
) -> None:
    mutation = fixture.mutation
    user = ctx.new_user()
    session = await ctx.session(user)
    url = ctx.url(ctx.scenario.read_path)
    token = session.access_token.get_secret_value()

    async def valid() -> str:
        return await ctx.proof(user, "GET", url, token=session)

    # The control: a valid proof is accepted (the read may still need sign-in).
    control = await ctx.send(
        "GET", url, headers={"Authorization": f"DPoP {token}", "DPoP": await valid()}
    )
    check(control.status_code not in {400, 401}, "a valid proof is accepted")

    headers = {"Authorization": f"{mutation.get('scheme', 'DPoP')} {token}"}
    if mutation.get("alg") == "none":
        proof = await valid()
        header = json.loads(base64.urlsafe_b64decode(proof.split(".")[0] + "=="))
        headers["DPoP"] = f"{_segment({**header, 'alg': 'none'})}.{proof.split('.')[1]}."
    elif mutation.get("tamper_signature"):
        first, second = await valid(), await valid()
        headers["DPoP"] = ".".join([*first.split(".")[:2], second.split(".")[2]])
    elif mutation.get("key") == "other":
        # Another key than the one the token is bound to: a fresh Session Key.
        headers["DPoP"] = await ctx.proof(user, "GET", url, token=session.access_token)
    elif "htm" in mutation:
        headers["DPoP"] = await ctx.proof(user, mutation["htm"], url, token=session)
    elif "htu" in mutation:
        headers["DPoP"] = await ctx.proof(user, "GET", mutation["htu"], token=session)
    elif "iat_offset" in mutation:
        headers["DPoP"] = await ctx.proof(
            user, "GET", url, token=session, shift=mutation["iat_offset"]
        )
    elif mutation.get("replay"):
        replayed = await valid()
        used = await ctx.send("GET", url, headers={**headers, "DPoP": replayed})
        check(used.status_code not in {400, 401}, "the first use of the proof is accepted")
        headers["DPoP"] = replayed
    elif "ath" in mutation:
        headers["DPoP"] = await ctx.proof(user, "GET", url, token=SecretStr(mutation["ath"]))
    elif not mutation.get("omit"):
        headers["DPoP"] = await valid()
    response = await ctx.send("GET", url, headers=headers)
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)
    check(token not in response.text, "a refusal never echoes the Session Token")
    if response.status_code == 401:
        check(
            "www-authenticate" in response.headers,
            "a token or proof refusal carries WWW-Authenticate",
        )


@case("security.token-in-url-refused")
async def _token_in_url(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    token = session.access_token.get_secret_value()
    url = ctx.url(ctx.scenario.read_path)
    proof = await ctx.proof(user, "GET", url, token=session)
    response = await ctx.send(
        "GET", f"{url}?{urlencode({'access_token': token})}", headers={"DPoP": proof}
    )
    # Any refusal will do (§4.3 says only MUST NOT accept): 400 or 401 are both seen.
    check(
        400 <= response.status_code < 500,
        f"a token in the URL: expected a refusal, got {response.status_code}",
    )
    check(token not in response.text, "a refusal never echoes the Session Token")


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
            "Authorization": f"DPoP {session.access_token.get_secret_value()}",
            "DPoP": await ctx.proof(user, "POST", endpoint, token=session),
            "Content-Type": "application/json",
        },
        content=body,
    )
    check(response.status_code == 201, f"served without cookies: got {response.status_code}")


@case("security.token-responses-not-cached")
async def _no_store(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": ctx.assertion(ctx.claims(subject=user, audience=metadata.issuer)),
        **(await ctx.client_form()),
    }
    issued = await ctx.token_request(user, form)
    check(issued.status_code == 200, "the Session starts")
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
    metadata = await ctx.metadata()
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    account_token = (await ctx.account_token(signed.reference)).get_secret_value()
    # The Account Token sent where it does not belong, with a bad client assertion.
    form = {
        "grant_type": "refresh_token",
        "refresh_token": account_token,
        **(await ctx.client_form()),
    }
    form["client_assertion"] = ctx.assertion(
        ctx.claims(subject=ctx.agent.identity.client_id, audience="https://elsewhere.example/t")
    )
    refused = await ctx.token_request(user, form)
    check(refused.status_code in {400, 401}, "a bad client assertion is refused")
    for secret in (account_token, form["client_assertion"]):
        check(secret not in refused.text, "a token refusal never echoes a credential")
    url = ctx.url(ctx.scenario.read_path)
    used = await ctx.send(
        "GET",
        url,
        headers={
            "Authorization": f"DPoP {account_token}",
            "DPoP": await ctx.proof(user, "GET", url, token=SecretStr(account_token)),
        },
    )
    expect_refusal(used, 401, "invalid_token", "an Account Token at an API")
    check(account_token not in used.text, "an API refusal never echoes a credential")
    del metadata


# Lifecycle -----------------------------------------------------------------------------


async def _probe(ctx: ConformanceContext, user: str, token: SessionToken) -> int:
    """The status of a read with this token: 401 invalid, 403 signed out, 200 signed in."""

    url = ctx.url(ctx.scenario.read_path)
    response = await ctx.send(
        "GET",
        url,
        headers={
            "Authorization": f"DPoP {token.access_token.get_secret_value()}",
            "DPoP": await ctx.proof(user, "GET", url, token=token),
        },
    )
    return response.status_code


@case("lifecycle.signed-out-session")
async def _signed_out(ctx: ConformanceContext, _: FixtureCase) -> None:
    session = await ctx.session(ctx.new_user())
    check(session.token_type == "DPoP", "a proof-bound Session Token is DPoP")  # noqa: S105
    check(session.expires_in > 0, "expires_in is greater than 0")
    check(session.expires_in <= 24 * 3600, "Session Tokens last hours, not days")
    check(not session.signed_in and session.scope == "", "a new Session is signed out")


@case("lifecycle.parallel-sessions")
async def _parallel(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    first, second = await asyncio.gather(ctx.session(user), ctx.session(user))
    check(first.session_key != second.session_key, "parallel Sessions are distinct")
    endpoint = await ctx.conversations_endpoint()
    for session in (first, second):
        receipt = await ctx.agent.conversations.start(
            endpoint, _message(ctx.scenario.greeting), token=session, **(await ctx.who(user))
        )
        check(receipt.conversation_id, "each Session is served")


@case("lifecycle.renew-signed-out")
async def _renew(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    old = await ctx.session(user)
    new = await ctx.agent.sessions.renew(
        client_id=ctx.agent.identity.client_id,
        pairwise_user_id=user,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=ctx.tenant_id,
        session_key=old.session_key,
    )
    check(new.session_key == old.session_key, "renewal keeps the Session")
    check(await _probe(ctx, user, new) == 403, "the new token is served (signed out)")
    # Whether the replaced token stops at once is the company's choice (no MUST in §4.2):
    # it is not checked here.


@case("lifecycle.renew-for-another-user")
async def _renew_other(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    owner = await ctx.session(ctx.new_user())
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.sessions.renew(
            client_id=ctx.agent.identity.client_id,
            pairwise_user_id=ctx.new_user(),
            issuer=metadata.issuer,
            token_endpoint=metadata.token_endpoint,
            tenant_id=ctx.tenant_id,
            session_key=owner.session_key,
        )
    # A key naming another user's Session is `invalid_grant` (§4.2).
    check(raised.value.code == "invalid_grant", f"got {raised.value.code}")


@case("lifecycle.sign-in-scopes")
async def _sign_in_scopes(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    granted = (ctx.scenario.read_scope,)
    signed = await ctx.sign_in(user, session, granted=granted)
    check(signed.token.signed_in, "the Session is signed in")
    check(signed.token.session_key == session.session_key, "the same Session is signed in")
    check(signed.token.scopes == granted, "only what the user approved is granted")


@case("lifecycle.unknown-scope-refused")
async def _unknown_scope(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    if metadata.device_authorization_endpoint is None:
        raise SkipCase("no Device Sign-In")
    user = ctx.new_user()
    session = await ctx.session(user)
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.device.begin(
            device_authorization_endpoint=metadata.device_authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=ctx.agent.identity.client_id,
            scopes=("conformance:not-a-scope",),
            tenant_id=ctx.tenant_id,
            session_key=session.session_key,
            organization=(await ctx.company()).document.organization,
            protected_resources=metadata.protected_resources,
        )
    check(raised.value.code == "invalid_scope", f"got {raised.value.code}")


@case("lifecycle.account-token-signs-in-new-session")
async def _new_session(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    fresh = await ctx.session(user)
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_key=fresh.session_key
    )
    check(result.status == "signed_in" and result.token is not None, "the Session signs in")
    check(await _probe(ctx, user, cast(SessionToken, result.token)) == 200, "it reads")


@case("lifecycle.rotated-token")
async def _rotated(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    before = await ctx.account_token(signed.reference)
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_key=session.session_key
    )
    if not result.rotated:
        raise SkipCase("the company does not rotate Account Tokens")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": before.get_secret_value(),
        **(await ctx.client_form()),
    }
    metadata = await ctx.metadata()
    proof = await ctx.proof(user, "POST", metadata.token_endpoint, session_key=session.session_key)
    old = await ctx.token_request(user, form, dpop=proof)
    expect_refusal(old, 400, "invalid_grant", "a rotated-away Account Token")
    again = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_key=session.session_key
    )
    check(again.status == "signed_in", "the stored, rotated token keeps working")


@case("lifecycle.narrower-scopes")
async def _narrower(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    result = await ctx.agent.accounts.refresh(
        signed.reference,
        context=await ctx.account_context(user),
        session_key=session.session_key,
        scopes=(ctx.scenario.read_scope,),
    )
    check(result.status == "signed_in", "a narrower refresh signs in")
    check(result.granted_scopes == (ctx.scenario.read_scope,), "only the narrower scope")


@case("lifecycle.wider-scopes-refused")
async def _wider(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session, granted=(ctx.scenario.read_scope,))
    result = await ctx.agent.accounts.refresh(
        signed.reference,
        context=await ctx.account_context(user),
        session_key=session.session_key,
        scopes=ctx.scenario.scopes,
    )
    check(result.status == "re_consent_required", f"got {result.status}")


@case("lifecycle.account-token-from-another-client")
async def _other_client(ctx: ConformanceContext, _: FixtureCase) -> None:
    other = ctx.other_agent()
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    other_session = await ctx.session(user, other)
    form = {
        "grant_type": "refresh_token",
        "refresh_token": (await ctx.account_token(signed.reference)).get_secret_value(),
        **(await ctx.client_form(other.identity)),
    }
    metadata = await ctx.metadata()
    proof = await ctx.proof(
        user, "POST", metadata.token_endpoint, agent=other, session_key=other_session.session_key
    )
    response = await ctx.token_request(user, form, dpop=proof)
    expect_refusal(response, 400, "invalid_grant", "another client's Account Token")


@case("lifecycle.account-token-at-api")
async def _account_token_at_api(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    secret = await ctx.account_token(signed.reference)
    url = ctx.url(ctx.scenario.read_path)
    response = await ctx.send(
        "GET",
        url,
        headers={
            "Authorization": f"DPoP {secret.get_secret_value()}",
            "DPoP": await ctx.proof(user, "GET", url, token=secret),
        },
    )
    expect_refusal(response, 401, "invalid_token", "an Account Token at an API")


@case("lifecycle.account-mismatch")
async def _mismatch(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    first, second = ctx.driver.accounts
    signed = await ctx.sign_in(user, await ctx.session(user), account=first)
    other_session = await ctx.session(user)
    await ctx.sign_in(user, other_session, account=second)
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.accounts.refresh(
            signed.reference,
            context=await ctx.account_context(user),
            session_key=other_session.session_key,
        )
    check(raised.value.code == "account_mismatch", f"got {raised.value.code}")


@case("lifecycle.account-token-for-another-users-session")
async def _another_users_session(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    stranger = await ctx.session(ctx.new_user())
    metadata = await ctx.metadata()
    form = {
        "grant_type": "refresh_token",
        "refresh_token": (await ctx.account_token(signed.reference)).get_secret_value(),
        **(await ctx.client_form()),
    }
    proof = await ctx.proof(user, "POST", metadata.token_endpoint, session_key=stranger.session_key)
    # The key names another user's Session: refused, no token issued (§4.8).
    response = await ctx.token_request(user, form, dpop=proof)
    expect_refusal(response, 400, "invalid_grant", "an Account Token for another user's Session")


@case("lifecycle.sign-out-takes-effect")
async def _sign_out_now(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    check(await _probe(ctx, user, signed.token) == 200, "signed in, the read is served")
    revoked = await ctx.agent.accounts.revoke(
        signed.reference, context=await ctx.account_context(user)
    )
    check(revoked.revoked and revoked.deleted_locally, "the Account Token is revoked and gone")
    check(
        await _probe(ctx, user, signed.token) == 403,
        "the earlier signed-in token is handled as signed out right away",
    )


@case("lifecycle.sign-out-session-continues")
async def _sign_out_continues(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    secret = await ctx.account_token(signed.reference)
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    renewed = await ctx.agent.sessions.renew(
        client_id=ctx.agent.identity.client_id,
        pairwise_user_id=user,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=ctx.tenant_id,
        session_key=session.session_key,
    )
    check(not renewed.signed_in, "the Session continues signed out")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": secret.get_secret_value(),
        **(await ctx.client_form()),
    }
    proof = await ctx.proof(user, "POST", metadata.token_endpoint, session_key=session.session_key)
    expect_refusal(
        await ctx.token_request(user, form, dpop=proof), 400, "invalid_grant", "a revoked token"
    )


@case("lifecycle.sign-out-every-session")
async def _sign_out_every_session(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    first = await ctx.session(user)
    signed = await ctx.sign_in(user, first)
    second = await ctx.session(user)
    rotated = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_key=second.session_key
    )
    check(rotated.status == "signed_in" and rotated.token is not None, "a second Session signs in")
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    for token in (signed.token, cast(SessionToken, rotated.token)):
        check(await _probe(ctx, user, token) == 403, "every Session from the sign-in is signed out")
    renewed = await ctx.agent.sessions.renew(
        client_id=ctx.agent.identity.client_id,
        pairwise_user_id=user,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=ctx.tenant_id,
        session_key=first.session_key,
    )
    check(not renewed.signed_in, "renewing with the assertion gives a signed-out token")


@case("lifecycle.disconnect-from-account-settings")
async def _disconnect(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("disconnect")
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    await ctx.driver.disconnect(ctx.agent.identity.client_id, ctx.driver.accounts[0])
    check(await _probe(ctx, user, signed.token) == 403, "its Sessions are signed out")
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_key=session.session_key
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
    who = await ctx.who(user)
    receipt = await ctx.agent.conversations.start(
        endpoint, _message(ctx.scenario.greeting), token=session, **who
    )
    check(receipt.status and receipt.responder, "the answer has status and responder")
    url = f"{endpoint}/{receipt.conversation_id}/events"
    raw = await ctx.send(
        "GET",
        url,
        headers={
            "Authorization": f"DPoP {session.access_token.get_secret_value()}",
            "DPoP": await ctx.proof(user, "GET", url, token=session),
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
    who = await ctx.who(user)
    message = _message(ctx.scenario.greeting)
    first = await ctx.agent.conversations.start(endpoint, message, token=session, **who)
    page = await ctx.agent.conversations.read_events(
        endpoint, first.conversation_id, token=session, **who
    )
    again = await ctx.agent.conversations.start(endpoint, message, token=session, **who)
    check(again.conversation_id == first.conversation_id, "a retry returns the same one")
    after = await ctx.agent.conversations.read_events(
        endpoint, first.conversation_id, token=session, **who
    )
    check(len(after.events) == len(page.events), "a retry adds nothing")


@case("conversations.message-id-conflict")
async def _conflict(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    who = await ctx.who(user)
    message = _message(ctx.scenario.greeting)
    await ctx.agent.conversations.start(endpoint, message, token=session, **who)
    changed = message.model_copy(update={"text": "Something else entirely."})
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.start(endpoint, changed, token=session, **who)
    check(raised.value.code == "message_id_conflict", f"got {raised.value.code}")
    check(raised.value.status_code == 409, "message_id_conflict is HTTP 409")


async def _conversation(ctx: ConformanceContext, user: str, session: SessionToken) -> str:
    endpoint = await ctx.conversations_endpoint()
    receipt = await ctx.agent.conversations.start(
        endpoint, _message(ctx.scenario.greeting), token=session, **(await ctx.who(user))
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
            token=session,
            cursor="evt_never_issued_by_the_company",
            **(await ctx.who(user)),
        )
    check(raised.value.code == "invalid_cursor", f"got {raised.value.code}")
    check(raised.value.status_code == 400, "invalid_cursor is HTTP 400")


@case("conversations.cursor-expired-recovery")
async def _cursor_expired(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("forget_events")
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    who = await ctx.who(user)
    conversation = await _conversation(ctx, user, session)
    page = await ctx.agent.conversations.read_events(endpoint, conversation, token=session, **who)
    saved = page.events[0].id
    await ctx.agent.conversations.send(
        endpoint, conversation, _message("One more thing."), token=session, **who
    )
    await ctx.driver.forget_events(conversation)
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.read_events(
            endpoint, conversation, token=session, cursor=saved, **who
        )
    check(raised.value.code == "cursor_expired", f"got {raised.value.code}")
    check(raised.value.status_code == 410, "cursor_expired is HTTP 410")
    told: list[bool] = []
    events = ctx.agent.conversations.events(
        endpoint,
        conversation,
        token=session,
        cursor=saved,
        wait=0,
        on_cursor_expired=lambda: told.append(True),
        **who,
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
    who = await ctx.who(user)
    conversation = await _conversation(ctx, user, session)
    page = await ctx.agent.conversations.read_events(endpoint, conversation, token=session, **who)
    sent = 0
    while not page.has_more and sent < 80:
        await ctx.agent.conversations.send(
            endpoint, conversation, _message(f"Note {sent}."), token=session, **who
        )
        sent += 1
        if sent % 10 == 0:
            page = await ctx.agent.conversations.read_events(
                endpoint, conversation, token=session, **who
            )
    if not page.has_more:
        raise SkipCase("the company returned every event in one page")
    ids: list[str] = []
    cursor: str | None = None
    while True:
        current = await ctx.agent.conversations.read_events(
            endpoint, conversation, token=session, cursor=cursor, **who
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
    who = await ctx.who(user)
    conversation = await _conversation(ctx, user, session)
    page = await ctx.agent.conversations.read_events(endpoint, conversation, token=session, **who)
    empty = await ctx.agent.conversations.read_events(
        endpoint, conversation, token=session, cursor=page.cursor, **who
    )
    check(empty.events == [], "nothing new: no events")
    check(empty.cursor == page.cursor, "the cursor is the request's own")
    check(empty.has_more is False, "has_more is false")


async def _stream_items(
    ctx: ConformanceContext,
    user: str,
    session: SessionToken,
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
        token=session,
        last_event_id=last_event_id,
        max_reconnects=1,
        **(await ctx.who(user)),
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
    who = await ctx.who(user)
    conversation = await _conversation(ctx, user, session)
    await ctx.agent.conversations.send(
        endpoint, conversation, _message("And another question."), token=session, **who
    )
    every = await ctx.agent.conversations.read_events(endpoint, conversation, token=session, **who)
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
    who = await ctx.who(user)
    words = _message("These are the user's own words.", author="human")
    receipt = await ctx.agent.conversations.start(endpoint, words, token=session, **who)
    page = await ctx.agent.conversations.read_events(
        endpoint, receipt.conversation_id, token=session, **who
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
    who = await ctx.who(user)
    conversation = await _conversation(ctx, user, session)
    receipt = await ctx.agent.conversations.handoff(endpoint, conversation, token=session, **who)
    check(receipt.status in {"queued", "idle", "working"}, "handoff answers a status")
    page = await ctx.agent.conversations.read_events(endpoint, conversation, token=session, **who)
    states = [event for event in page.events if event.type == "state"]
    check(states, "each status change is a state event")
    check(states[-1].status == page.status, "the last state event is the current status")
    check(states[-1].responder == page.responder, "and the current responder")


@case("conversations.direct-conversation")
async def _direct(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    who = await ctx.who(user)
    parent = await _conversation(ctx, user, session)
    direct = await ctx.agent.conversations.start_direct(
        endpoint, parent, _message("I'd like to ask myself.", author="human"), token=session, **who
    )
    page = await ctx.agent.conversations.read_events(endpoint, parent, token=session, **who)
    opened = [e for e in page.events if e.type == "direct_opened"]
    check(opened and opened[-1].conversation_id == direct.conversation_id, "direct_opened")
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.send(
            endpoint, parent, _message("Meanwhile."), token=session, **who
        )
    check(raised.value.code == "direct_conversation_open", f"got {raised.value.code}")
    check(
        (raised.value.details or {}).get("conversation_id") == direct.conversation_id,
        "the refusal names the Direct Conversation",
    )
    await ctx.agent.conversations.close(endpoint, direct.conversation_id, token=session, **who)
    page = await ctx.agent.conversations.read_events(endpoint, parent, token=session, **who)
    check(any(e.type == "direct_closed" for e in page.events), "direct_closed")
    await ctx.agent.conversations.send(
        endpoint, parent, _message("Back to you."), token=session, **who
    )


@case("conversations.direct-of-direct-refused")
async def _direct_of_direct(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    who = await ctx.who(user)
    parent = await _conversation(ctx, user, session)
    direct = await ctx.agent.conversations.start_direct(
        endpoint, parent, _message("Hi.", author="human"), token=session, **who
    )
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.start_direct(
            endpoint, direct.conversation_id, _message("Hi.", author="human"), token=session, **who
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
    who = await ctx.who(user)
    receipt = await ctx.agent.conversations.start(endpoint, _message(prompt), token=session, **who)
    page = await ctx.agent.conversations.read_events(
        endpoint, receipt.conversation_id, token=session, **who
    )
    asks = [event for event in page.events if event.type == "authorization"]
    check(asks, "the company asks for sign-in with an authorization event")
    check(
        any(e.message is not None and e.message.role == "company" for e in page.events),
        "and says so in a message",
    )
    signed = await ctx.sign_in(user, session)
    again = await ctx.agent.conversations.send(
        endpoint, receipt.conversation_id, _message(prompt), token=signed.token, **who
    )
    check(again.conversation_id == receipt.conversation_id, "the same conversation continues")


@case("conversations.closed")
async def _closed(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    who = await ctx.who(user)
    conversation = await _conversation(ctx, user, session)
    closed = await ctx.agent.conversations.close(endpoint, conversation, token=session, **who)
    check(closed.status == "closed", "closing answers status closed")
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.send(
            endpoint, conversation, _message("Still there?"), token=session, **who
        )
    check(raised.value.code == "conversation_closed", f"got {raised.value.code}")
    check(raised.value.status_code == 409, "conversation_closed is HTTP 409")
    page = await ctx.agent.conversations.read_events(endpoint, conversation, token=session, **who)
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
                "Authorization": f"DPoP {session.access_token.get_secret_value()}",
                "DPoP": await ctx.proof(user, "GET", url, token=session),
            },
        )
        bodies.append((response.status_code, response.json()))
    check(bodies[0] == bodies[1], "another user's and an unknown conversation look the same")
    check(bodies[0][0] == 404 and bodies[0][1].get("error") == "conversation_not_found", "404")


@case("conversations.signed-out-token-on-account-conversation")
async def _account_conversation(ctx: ConformanceContext, _: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    who = await ctx.who(user)
    signed = await ctx.sign_in(user, session)
    conversation = await _conversation(ctx, user, signed.token)
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    signed_out = await ctx.agent.sessions.renew(
        client_id=ctx.agent.identity.client_id,
        pairwise_user_id=user,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=ctx.tenant_id,
        session_key=session.session_key,
    )
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.read_events(endpoint, conversation, token=signed_out, **who)
    check(raised.value.code == "insufficient_scope", f"got {raised.value.code}")


# Operations --------------------------------------------------------------------------


async def _signed_in_user(ctx: ConformanceContext) -> tuple[str, SignedIn]:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    return user, signed


async def _propose(ctx: ConformanceContext, user: str, signed: SignedIn, kind: str) -> Operation:
    proposal = ctx.proposal(kind)
    answer = await ctx.agent.api.call(
        proposal.method,
        ctx.url(proposal.path),
        token=signed.token,
        body=proposal.body if proposal.body is not None else {},
        **(await ctx.who(user)),
    )
    check(answer.status == 202 and answer.operation is not None, "the API answers 202")
    return cast(Operation, answer.operation)


@case("operations.proposed-not-performed")
async def _proposed(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "user")
    check(operation.state == "proposed", "a proposal is proposed")
    check(operation.summary.strip(), "it has a summary")
    check(operation.confirmation is None and operation.result is None, "nothing happened yet")
    if "performed" in ctx.driver.capabilities:
        check(await ctx.driver.performed(operation.operation_id) == 0, "nothing was performed")
    description = openapi_url((await ctx.company()).document)
    documented = ctx.proposal("user").documented_as
    if description is not None and documented is not None:
        paths = (await ctx.http.get(description)).json().get("paths", {})
        check(
            "operation" in json.dumps(paths.get(documented, {})),
            "the API description says the endpoint returns an operation",
        )


@case("operations.readable-until-final")
async def _readable(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "user")
    read = await ctx.agent.operations.read(
        endpoint, operation.operation_id, token=signed.token, **(await ctx.who(user))
    )
    check(read == operation, "the same operation, unchanged")


@case("operations.confirm-succeeded")
async def _confirm(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "user")
    outcome = await ctx.agent.operations.confirm(
        endpoint,
        operation,
        approval=approve(operation),
        token=signed.token,
        **(await ctx.who(user)),
    )
    done = cast(Operation, outcome.operation)
    check(outcome.status == "confirmed" and done.state == "succeeded", f"got {done.state}")
    check(done.confirmation is not None, "the confirmation is recorded")
    confirmation = cast(Any, done.confirmation)
    check(confirmation.revision == operation.revision, "for the approved revision")
    check(confirmation.approved_by == "user", "approved by the user")
    check(done.result is not None and done.result.summary, "the result says what happened")
    check(done.terms == operation.terms, "it did what the revision described")


@case("operations.at-most-once")
async def _at_most_once(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "user")
    approval = approve(operation)
    first = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approval, token=signed.token, **who
    )
    second = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approval, token=signed.token, **who
    )
    check(first.operation == second.operation, "a repeated confirm returns the same record")
    if "performed" in ctx.driver.capabilities:
        check(await ctx.driver.performed(operation.operation_id) == 1, "performed once")


@case("operations.terms-changed")
async def _terms_changed(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("revise")
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "user")
    await ctx.driver.revise(operation.operation_id)
    outcome = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approve(operation), token=signed.token, **who
    )
    check(outcome.status == "terms_changed", f"got {outcome.status}")
    current = cast(Operation, outcome.operation)
    check(current.revision == operation.revision + 1, "the current revision comes back")
    check(outcome.changed, "with what changed")
    done = await ctx.agent.operations.confirm(
        endpoint, current, approval=approve(current), token=signed.token, **who
    )
    check(done.status == "confirmed", "the new revision, approved, confirms")


@case("operations.user-approval-required")
async def _approval_required(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "user")
    if not operation.user_approval_required:
        raise SkipCase("the scenario's user proposal does not require the user's approval")
    with _raises(OperationError) as local:
        await ctx.agent.operations.confirm(
            endpoint,
            operation,
            standing=("company", "account", "action"),
            token=signed.token,
            **(await ctx.who(user)),
        )
    check(local.value.code == "user_approval_required", "the SDK refuses it locally")
    url = f"{endpoint}/{operation.operation_id}/confirm"
    response = await ctx.send(
        "POST",
        url,
        headers={
            "Authorization": f"DPoP {signed.token.access_token.get_secret_value()}",
            "DPoP": await ctx.proof(user, "POST", url, token=signed.token),
            "Content-Type": "application/json",
        },
        content=json.dumps(
            {"revision": operation.revision, "approved_by": "standing_permission"}
        ).encode(),
    )
    expect_refusal(response, 403, "user_approval_required", "a standing permission")


def _permission(
    ctx: ConformanceContext, limits: tuple[TermLimit, ...], uses: int | None
) -> tuple[str, str, str]:
    store = first_contribution(ctx.agent.reactor, STANDING_PERMISSION_STORES, "standing")
    if not isinstance(store, InMemoryStandingPermissionStore):
        raise SkipCase("the standing permission store cannot be seeded")
    action = ctx.scenario.standing_action
    if action is None:
        raise SkipCase("the scenario has no standing-permission action")
    # Each case starts from the user's permissions it grants itself, and no others.
    store.permissions.clear()
    reference = f"perm_{secrets.token_hex(8)}"
    company, account = ctx.domain, ctx.driver.accounts[0]
    store.permissions[reference] = StandingPermission(
        reference=reference,
        company=company,
        account=account,
        action=action,
        limits=limits,
        expires_at=ctx.now() + timedelta(hours=1),
        uses_remaining=uses,
    )
    return company, account, action


@case("operations.standing-permission-within-bounds")
async def _standing_ok(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    standing = _permission(ctx, ctx.scenario.standing_limits, uses=2)
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "standing")
    outcome = await ctx.agent.operations.confirm(
        endpoint, operation, standing=standing, token=signed.token, **(await ctx.who(user))
    )
    done = cast(Operation, outcome.operation)
    check(outcome.status == "confirmed", f"got {outcome.status}")
    check(done.confirmation is not None, "confirmed")
    confirmation = cast(Any, done.confirmation)
    check(confirmation.approved_by == "standing_permission", "under the standing permission")


@case("operations.standing-permission-out-of-bounds")
async def _standing_too_low(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    if not ctx.scenario.standing_too_low:
        raise SkipCase("the scenario has no out-of-bounds limits")
    standing = _permission(ctx, ctx.scenario.standing_too_low, uses=None)
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "standing")
    with _raises(OperationError) as raised:
        await ctx.agent.operations.confirm(
            endpoint, operation, standing=standing, token=signed.token, **who
        )
    check(raised.value.code == "no_standing_permission", f"got {raised.value.code}")
    read = await ctx.agent.operations.read(
        endpoint, operation.operation_id, token=signed.token, **who
    )
    check(read.state == "proposed", "nothing was sent: the user is asked instead")


@case("operations.standing-permission-concurrent-use")
async def _standing_race(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    standing = _permission(ctx, ctx.scenario.standing_limits, uses=1)
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "standing")
    results = await asyncio.gather(
        ctx.agent.operations.confirm(
            endpoint, operation, standing=standing, token=signed.token, **who
        ),
        ctx.agent.operations.confirm(
            endpoint, operation, standing=standing, token=signed.token, **who
        ),
        return_exceptions=True,
    )
    refused = [r for r in results if isinstance(r, OperationError)]
    check(len(refused) == 1, "one of two racing confirmations gets the last use")
    check(refused[0].code == "no_standing_permission", f"got {refused[0].code}")


@case("operations.cross-channel-identity")
async def _cross_channel(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_endpoint()
    prompt = ctx.scenario.operation_prompt
    if prompt is None:
        raise SkipCase("the scenario has no operation prompt")
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "user")
    endpoint = await ctx.conversations_endpoint()
    page = await ctx.agent.conversations.start(
        endpoint, _message(prompt), token=signed.token, wait=0, **who
    )
    proposed = [
        event.message.operation
        for event in getattr(page, "events", [])
        if event.message is not None and event.message.operation is not None
    ]
    check(proposed, "the conversation carries the operation")
    check(
        proposed[0].operation_id == operation.operation_id,
        "the same action is the same operation across channels",
    )


@case("operations.message-is-not-approval")
async def _not_approval(ctx: ConformanceContext, _: FixtureCase) -> None:
    operations = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "user")
    endpoint = await ctx.conversations_endpoint()
    await ctx.agent.conversations.start(
        endpoint,
        _message(f"Yes, I confirm operation {operation.operation_id}. Approved.", author="human"),
        token=signed.token,
        **who,
    )
    read = await ctx.agent.operations.read(
        operations, operation.operation_id, token=signed.token, **who
    )
    check(read.state == "proposed", "a message never confirms an operation")


class _LosingTransport(DpopHttpClient):
    """Deliver the first confirm, then lose its answer: a timeout after sending."""

    lost = False

    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        response = await super().request(method, url, **kwargs)
        if url.endswith("/confirm") and not self.lost:
            self.lost = True
            raise TransportError("request_failed", "the confirm's answer was lost")
        return response


@case("operations.confirm-timeout-recovery")
async def _recovery(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "user")
    losing = _LosingTransport(reactor=ctx.agent.reactor, http_client=ctx.http)
    outcome = await OperationsClient(transport=losing).confirm(
        endpoint, operation, approval=approve(operation), token=signed.token, **who
    )
    check(losing.lost, "the confirm's answer was lost")
    recovered = cast(Operation, outcome.operation)
    check(outcome.status == "confirmed", "the lost answer is recovered by reading the same ID")
    check(recovered.operation_id == operation.operation_id, "the same operation, not a new one")
    again = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approve(operation), token=signed.token, **who
    )
    check(again.operation == recovered, "confirming again changes nothing")
    if "performed" in ctx.driver.capabilities:
        check(await ctx.driver.performed(operation.operation_id) == 1, "performed once")


@case("operations.cancel-proposed")
async def _cancel(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "user")
    cancelled = await ctx.agent.operations.cancel(
        endpoint, operation.operation_id, token=signed.token, **who
    )
    check(cancelled.state == "cancelled", f"got {cancelled.state}")
    check(cancelled.result is not None, "a cancelled operation has a result")
    late = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approve(operation), token=signed.token, **who
    )
    check(late.status == "not_confirmed", f"a late confirm changes nothing, got {late.status}")
    check(cast(Operation, late.operation).state == "cancelled", "it stays cancelled")
    if "performed" in ctx.driver.capabilities:
        check(await ctx.driver.performed(operation.operation_id) == 0, "never performed")


@case("operations.in-progress-outcome-unknown")
async def _unknown(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "unknown")
    outcome = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approve(operation), token=signed.token, **who
    )
    current = cast(Operation, outcome.operation)
    check(current.state == "in_progress", f"an unknown outcome is in_progress, got {current.state}")
    check(outcome.retry_after is not None, "with Retry-After")
    url = f"{endpoint}/{operation.operation_id}"
    read = await ctx.send(
        "GET",
        url,
        headers={
            "Authorization": f"DPoP {signed.token.access_token.get_secret_value()}",
            "DPoP": await ctx.proof(user, "GET", url, token=signed.token),
        },
    )
    check(read.json().get("state") == "in_progress", "never failed while unknown")
    check("retry-after" in read.headers, "a read in progress carries Retry-After")
    cancelled = await ctx.agent.operations.cancel(
        endpoint, operation.operation_id, token=signed.token, **who
    )
    check(cancelled.state == "in_progress", "cancelling leaves it in progress until known")


@case("operations.failed-partial-result")
async def _failed(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "fails")
    outcome = await ctx.agent.operations.confirm(
        endpoint,
        operation,
        approval=approve(operation),
        token=signed.token,
        **(await ctx.who(user)),
    )
    done = cast(Operation, outcome.operation)
    check(done.state == "failed", f"got {done.state}")
    check(done.result is not None and done.result.summary, "the result says what was changed")


@case("operations.expired")
async def _expired(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("clock")
    endpoint = await ctx.operations_endpoint()
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "user")
    check(operation.expires_at is not None, "a proposal has expires_at")
    expires_at = cast(datetime, operation.expires_at)
    await ctx.driver.wait((expires_at - ctx.now()).total_seconds() + 1)
    # The Session Token may have expired meanwhile: sign the Session in again.
    refreshed = await ctx.agent.accounts.refresh(
        signed.reference,
        context=await ctx.account_context(user),
        session_key=signed.token.session_key,
    )
    token = cast(SessionToken, refreshed.token)
    who = await ctx.who(user)
    read = await ctx.agent.operations.read(endpoint, operation.operation_id, token=token, **who)
    check(read.state == "expired", f"got {read.state}")
    late = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approve(operation), token=token, **who
    )
    check(late.status == "not_confirmed", "an expired operation is returned as it is")


@case("operations.not-found-indistinguishable")
async def _operation_not_found(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    owner, owner_signed = await _signed_in_user(ctx)
    theirs = await _propose(ctx, owner, owner_signed, "user")
    user, signed = await _signed_in_user(ctx)
    answers = []
    for operation_id in (theirs.operation_id, "op_conformance_unknown_0000"):
        with _raises(OperationError) as raised:
            await ctx.agent.operations.read(
                endpoint, operation_id, token=signed.token, **(await ctx.who(user))
            )
        answers.append((raised.value.code, raised.value.status_code))
    check(answers[0] == answers[1], "another user's and an unknown operation look the same")
    check(answers[0] == ("operation_not_found", 404), f"got {answers[0]}")


# MCP (§4.3, §6) ------------------------------------------------------------------------


async def _mcp_url(ctx: ConformanceContext) -> str:
    api = mcp_api((await ctx.company()).document)
    if api is None:
        raise SkipCase("the company lists no MCP server")
    return api.url


def _tool(name: str | None) -> str:
    if name is None:
        raise SkipCase("the scenario names no MCP tool for this")
    return name


async def _mcp_dpop(ctx: ConformanceContext, url: str) -> bool:
    """Whether the MCP server supports DPoP, from its protected resource metadata (§4.3)."""

    metadata = await ctx.metadata()
    served = await fetch_mcp_server_metadata(ctx.http, url, issuer=metadata.issuer)
    return served.supports_dpop


async def _mcp_client(
    ctx: ConformanceContext, user: str, token: SessionToken, url: str
) -> McpClient:
    return McpClient(
        http_client=ctx.http,
        token=token,
        url=url,
        reactor=ctx.agent.reactor,
        who=await ctx.who(user),
    )


async def _signed_in_bearer(ctx: ConformanceContext) -> tuple[str, SignedIn, SessionToken, str]:
    """A signed-in Session's token for the MCP server: DPoP or Bearer, as the server says."""

    url = await _mcp_url(ctx)
    dpop = await _mcp_dpop(ctx, url)
    user, signed = await _signed_in_user(ctx)
    token = await _mcp_token(ctx, user, signed.token, url, dpop, reference=signed.reference)
    check(token.signed_in, "a signed-in MCP token")
    return user, signed, token, url


async def _mcp_token(
    ctx: ConformanceContext,
    user: str,
    session: SessionToken,
    url: str,
    dpop: bool,
    *,
    reference: str | None = None,
) -> SessionToken:
    """A token for the MCP server, as the server says (§4.3).

    One that supports DPoP: the Session's own request with `resource` (the Account Token
    when signed in, the assertion otherwise). One that doesn't: Token Exchange of the
    Session's DPoP token for a Bearer one.
    """

    metadata = await ctx.metadata()
    if not dpop:
        return await ctx.agent.sessions.token_for_mcp(
            client_id=ctx.agent.identity.client_id,
            issuer=metadata.issuer,
            token_endpoint=metadata.token_endpoint,
            tenant_id=ctx.tenant_id,
            session_key=session.session_key,
            subject_token=session.access_token,
            resource=url,
        )
    if reference is not None:
        result = await ctx.agent.accounts.refresh(
            reference,
            context=await ctx.account_context(user),
            session_key=session.session_key,
            resource=url,
        )
        check(result.status == "signed_in" and result.token is not None, "a signed-in token")
        return cast(SessionToken, result.token)
    return await ctx.agent.sessions.renew(
        client_id=ctx.agent.identity.client_id,
        pairwise_user_id=user,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=ctx.tenant_id,
        session_key=session.session_key,
        resource=url,
    )


@case("lifecycle.mcp-protected-resource-metadata")
async def _mcp_metadata(ctx: ConformanceContext, _: FixtureCase) -> None:
    url = await _mcp_url(ctx)
    metadata = await ctx.metadata()
    parts = urlsplit(url)
    location = f"https://{parts.netloc}/.well-known/oauth-protected-resource{parts.path}"
    document = (await ctx.send("GET", location)).json()
    check(document.get("resource") == url, "the metadata names the MCP server as its resource")
    check(
        metadata.issuer in document.get("authorization_servers", []),
        "authorization_servers includes auth.issuer",
    )
    supports_dpop = "dpop_signing_alg_values_supported" in document
    if supports_dpop:
        check(
            "ES256" in document["dpop_signing_alg_values_supported"],
            "an MCP server that supports DPoP lists ES256",
        )
    bare = await ctx.send(
        "POST",
        url,
        headers={"Content-Type": "application/json"},
        content=b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
    )
    check(bare.status_code == 401, "an unauthenticated MCP call is 401")
    challenge = bare.headers.get("www-authenticate", "")
    check(challenge.startswith("Bearer") and "resource_metadata" in challenge, "Bearer challenge")
    if supports_dpop:
        # One challenge per scheme it accepts, each with resource_metadata (§6).
        check(", DPoP " in challenge, "a DPoP server also challenges with DPoP")
        check(challenge.count("resource_metadata=") == 2, "each challenge names the metadata")


@case("lifecycle.mcp-bearer-for-its-url")
async def _mcp_bearer(ctx: ConformanceContext, _: FixtureCase) -> None:
    read_tool = _tool(ctx.scenario.mcp_read_tool)
    user, signed, bearer, url = await _signed_in_bearer(ctx)
    dpop = await _mcp_dpop(ctx, url)
    expected = "DPoP" if dpop else "Bearer"
    check(bearer.token_type == expected, f"a {expected} token, as the server supports")
    check(bearer.session_key == signed.token.session_key, "for the same Session")
    answer = await (await _mcp_client(ctx, user, bearer, url)).call_tool(read_tool)
    check(not answer.is_error, "the MCP server accepts it")
    other = ctx.new_user()
    session = await ctx.session(other)
    signed_out = await _mcp_token(ctx, other, session, url, dpop)
    check(not signed_out.signed_in, "a signed-out Session gets a signed-out MCP token")
    with _raises(McpError) as raised:
        await (await _mcp_client(ctx, other, signed_out, url)).call_tool(read_tool)
    check(
        raised.value.code in {"insufficient_scope"},
        f"the MCP server enforces scopes, got {raised.value.code}",
    )
    del user


@case("lifecycle.mcp-bearer-only-at-mcp")
async def _mcp_only(ctx: ConformanceContext, _: FixtureCase) -> None:
    user, signed, bearer, url = await _signed_in_bearer(ctx)
    secret = bearer.access_token.get_secret_value()
    targets = [("GET", ctx.url(ctx.scenario.read_path))]
    with contextlib.suppress(SkipCase):
        targets.append(("POST", await ctx.conversations_endpoint()))
    with contextlib.suppress(SkipCase):
        targets.append(("GET", f"{await ctx.operations_endpoint()}/op_conformance_any"))
    for method, target in targets:
        for scheme in ("Bearer", "DPoP"):
            headers = {"Authorization": f"{scheme} {secret}", "Content-Type": "application/json"}
            if scheme == "DPoP":
                headers["DPoP"] = await ctx.proof(user, method, target, token=bearer)
            response = await ctx.send(method, target, headers=headers, content=b"{}")
            check(response.status_code == 401, f"an MCP token is refused at {method} {target}")
            check(secret not in response.text, "and never echoed")
    dpop_at_mcp = await ctx.send(
        "POST",
        url,
        headers={
            "Authorization": f"Bearer {signed.token.access_token.get_secret_value()}",
            "Content-Type": "application/json",
        },
        content=b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
    )
    check(dpop_at_mcp.status_code == 401, "the MCP server refuses a DPoP Session Token")
    # Token Exchange for anything but an MCP server without DPoP: `invalid_target` (§4.3).
    metadata = await ctx.metadata()
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": signed.token.access_token.get_secret_value(),
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "resource": ctx.url(ctx.scenario.read_path),
        **(await ctx.client_form()),
    }
    proof = await ctx.proof(
        user, "POST", metadata.token_endpoint, session_key=signed.token.session_key
    )
    elsewhere = await ctx.token_request(user, form, dpop=proof)
    expect_refusal(elsewhere, 400, "invalid_target", "a Bearer token for another resource")


@case("lifecycle.mcp-sign-out-takes-effect")
async def _mcp_sign_out(ctx: ConformanceContext, _: FixtureCase) -> None:
    read_tool = _tool(ctx.scenario.mcp_read_tool)
    user, signed, bearer, url = await _signed_in_bearer(ctx)
    client = await _mcp_client(ctx, user, bearer, url)
    check(not (await client.call_tool(read_tool)).is_error, "signed in, the tool answers")
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    with _raises(McpError) as raised:
        await client.call_tool(read_tool)
    check(raised.value.code == "insufficient_scope", f"got {raised.value.code}")


@case("operations.cross-channel-mcp")
async def _cross_channel_mcp(ctx: ConformanceContext, _: FixtureCase) -> None:
    await ctx.operations_endpoint()
    propose_tool = _tool(ctx.scenario.mcp_propose_tool)
    user, signed, bearer, url = await _signed_in_bearer(ctx)
    through_api = await _propose(ctx, user, signed, "user")
    answer = await (await _mcp_client(ctx, user, bearer, url)).call_tool(propose_tool)
    check(answer.operation is not None, "the tool returns structuredContent.operation")
    check(answer.operation == through_api, "the same operation as through the API")


# Draft 0.2 company rules --------------------------------------------------------------


@case("security.dpop-header-twice")
async def _dpop_twice(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    """Exactly one DPoP header holding one JWT (§4.3): two are an invalid proof."""

    metadata = await ctx.metadata()
    user = ctx.new_user()
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": ctx.assertion(ctx.claims(subject=user, audience=metadata.issuer)),
        **(await ctx.client_form()),
    }
    proofs = [await ctx.proof(user, "POST", metadata.token_endpoint) for _ in range(2)]
    request = httpx.Request(
        "POST",
        metadata.token_endpoint,
        headers=[
            ("Content-Type", "application/x-www-form-urlencoded"),
            ("Accept", "application/json"),
            ("DPoP", proofs[0]),
            ("DPoP", proofs[1]),
        ],
        content=urlencode(form).encode(),
    )
    response = await ctx.http.send(request, follow_redirects=False)
    check(
        response.status_code == 400, f"two DPoP headers: expected 400, got {response.status_code}"
    )
    check(
        _error(response) in {"invalid_dpop_proof", "invalid_request"},
        f"two DPoP headers: got {_error(response)!r}",
    )


@case("lifecycle.account-mismatch-after-sign-out")
async def _mismatch_after_sign_out(ctx: ConformanceContext, _: FixtureCase) -> None:
    """A Session ever signed in to one account is never signed in to another (§4.4, §4.8)."""

    metadata = await ctx.metadata()
    user = ctx.new_user()
    first, second = ctx.driver.accounts
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session, account=first)
    other = await ctx.sign_in(user, await ctx.session(user), account=second)
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    renewed = await ctx.agent.sessions.renew(
        client_id=ctx.agent.identity.client_id,
        pairwise_user_id=user,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=ctx.tenant_id,
        session_key=session.session_key,
    )
    check(not renewed.signed_in, "after sign-out the Session continues signed out")
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.accounts.refresh(
            other.reference,
            context=await ctx.account_context(user),
            session_key=session.session_key,
        )
    check(raised.value.code == "account_mismatch", f"got {raised.value.code}")


@case("lifecycle.mcp-token-type-by-server")
async def _mcp_token_type(ctx: ConformanceContext, _: FixtureCase) -> None:
    """The token type follows the MCP server in `resource`; each wrong way is
    `invalid_target`, and every token request carries a proof (§4.3)."""

    url = await _mcp_url(ctx)
    dpop = await _mcp_dpop(ctx, url)
    metadata = await ctx.metadata()
    user = ctx.new_user()
    session = await ctx.session(user)

    def proof() -> Any:
        return ctx.proof(user, "POST", metadata.token_endpoint, session_key=session.session_key)

    async def renewal() -> dict[str, str]:
        # Fresh assertions each time: a `jti` is never sent twice (§4.1, §4.2).
        return {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": ctx.assertion(ctx.claims(subject=user, audience=metadata.issuer)),
            "resource": url,
            **(await ctx.client_form()),
        }

    async def exchange() -> dict[str, str]:
        return {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": session.access_token.get_secret_value(),
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": url,
            **(await ctx.client_form()),
        }

    unproven = await ctx.token_request(user, await renewal(), dpop=None)
    expect_refusal(unproven, 400, "invalid_dpop_proof", "a token request without a proof")
    if dpop:
        refused = await ctx.token_request(user, await exchange(), dpop=await proof())
        expect_refusal(refused, 400, "invalid_target", "Token Exchange for a DPoP MCP server")
        issued = await ctx.token_request(user, await renewal(), dpop=await proof())
        check(issued.status_code == 200, "with a proof, a token is issued")
        check(issued.json().get("token_type") == "DPoP", "a DPoP token for a DPoP MCP server")
    else:
        refused = await ctx.token_request(user, await renewal(), dpop=await proof())
        expect_refusal(refused, 400, "invalid_target", "a Bearer server's token by another grant")
        issued = await ctx.token_request(user, await exchange(), dpop=await proof())
        check(issued.status_code == 200, "Token Exchange issues a token")
        body = issued.json()
        check(body.get("token_type") == "Bearer", "a Bearer token for this MCP server")
        check(
            body.get("issued_token_type") == "urn:ietf:params:oauth:token-type:access_token",
            "issued_token_type names an access token",
        )


@case("protocol.feedback-report")
async def _feedback(ctx: ConformanceContext, _: FixtureCase) -> None:
    """A report with a Session Token, no scope: 202; an unknown kind too; malformed 400 (§8)."""

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
                "Authorization": f"DPoP {session.access_token.get_secret_value()}",
                "DPoP": await ctx.proof(user, "POST", endpoint, token=session),
                "Content-Type": "application/json",
            },
            content=json.dumps(body).encode(),
        )

    report = {"kind": "missing", "task": "Conformance task", "description": "Not offered."}
    accepted = await post(report)
    # 202, or 200 with an alternative when the task can be done after all (§8.3).
    check(
        accepted.status_code in {200, 202},
        f"a report is accepted with 202 or 200, got {accepted.status_code}",
    )
    unknown = await post({**report, "kind": "conformance-later-kind"})
    check(unknown.status_code in {200, 202}, "a kind it doesn't recognize is accepted")
    expect_refusal(await post({**report, "task": "x" * 201}), 400, "invalid_request", "too long")
    bare = await ctx.send(
        "POST", endpoint, headers={"Content-Type": "application/json"}, content=b"{}"
    )
    check(bare.status_code == 401, "a report needs a Session Token")


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
            "Authorization": f"DPoP {session.access_token.get_secret_value()}",
            "DPoP": await ctx.proof(user, "GET", url, token=session),
        },
    )
    page = first.json()
    later = f"{url}?cursor={page['cursor']}"
    empty = (
        await ctx.send(
            "GET",
            later,
            headers={
                "Authorization": f"DPoP {session.access_token.get_secret_value()}",
                "DPoP": await ctx.proof(user, "GET", later, token=session),
            },
        )
    ).json()
    fields = {"conversation_id", "events", "cursor", "has_more", "status", "responder"}
    for read in (page, empty):
        check(fields <= set(read), f"a read has {sorted(fields - set(read))} missing")
    check(empty["events"] == [], "events is an empty list when there are none")


# The website (§5, Operations §4.4) ---------------------------------------------------


async def _browser(ctx: ConformanceContext) -> tuple[ControlledBrowser, str]:
    web = (await ctx.company()).document.web
    if web is None or web.browser_session_endpoint is None:
        raise SkipCase("the company offers no browser sessions")
    if ctx.agent.browser is None:
        raise SkipCase("the runner was given no browser of its own")
    return ctx.agent.browser, web.browser_session_endpoint


async def _join(
    ctx: ConformanceContext, user: str, session_key: str, page: str
) -> list[httpx.Response]:
    """Join the runner's own browser to the Session (§5), then open `page` in it.

    Returns the join's responses: the 303 that set the Session's cookie first.
    """

    browser, endpoint = await _browser(ctx)
    await BrowserSessionClient(reactor=ctx.agent.reactor).join(
        browser_session_endpoint=endpoint,
        tenant_id=ctx.tenant_id,
        issuer=(await ctx.metadata()).issuer,
        session_key=session_key,
    )
    joined = cast(httpx.Response, browser.page)
    check(joined.history and joined.history[0].status_code == 303, "joined with 303 See Other")
    await browser.get(page)
    del user
    return list(joined.history)


@case("lifecycle.browser-joins-session")
async def _browser_joins(ctx: ConformanceContext, _: FixtureCase) -> None:
    browser, endpoint = await _browser(ctx)
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
    user, signed = await _signed_in_user(ctx)
    operation = await _propose(ctx, user, signed, "standing")
    page = operation_page(operation, (await ctx.company()).document.organization.domain)
    joined = await _join(ctx, user, signed.token.session_key, page)
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
    landed = cast(httpx.Response, browser.page)
    check(landed.status_code == 200, "the operation's page shows in the Session")
    await ctx.agent.accounts.revoke(signed.reference, context=await ctx.account_context(user))
    after = await browser.get(page)
    check(after.status_code in {401, 403, 404}, "signed out, the website shows it no more")


@case("lifecycle.browser-join-refused")
async def _browser_refused(ctx: ConformanceContext, _: FixtureCase) -> None:
    """Step 3 of §5 and the attacks of §9.6: each wrong join sets no Session cookie."""

    _browser_unused, endpoint = await _browser(ctx)
    metadata = await ctx.metadata()
    user = ctx.new_user()
    session = await ctx.session(user)
    code_field = re.compile(r'name="code" value="([^"]+)"')

    async def form() -> tuple[httpx.AsyncClient, str]:
        browser = ctx.new_browser()
        page = await browser.get(endpoint)
        found = code_field.search(page.text)
        check(found is not None, "the join page holds a code")
        return browser, cast(re.Match[str], found).group(1)

    async def proof(code: str, session_key: str | None = session.session_key) -> str:
        return await ctx.proof(user, "POST", endpoint, session_key=session_key, nonce=code)

    async def submit(browser: httpx.AsyncClient, code: str, signed: str) -> httpx.Response:
        return await browser.post(endpoint, data={"code": code, "proof": signed})

    def joined(response: httpx.Response) -> bool:
        return any(
            "max-age=0" not in value.lower() for value in response.headers.get_list("set-cookie")
        )

    browser, code = await form()
    signed = await proof(code)
    victim = ctx.new_browser()
    stolen = await submit(victim, code, signed)
    check(
        stolen.status_code == 400 and not joined(stolen), "a code from another browser joins none"
    )
    used = await submit(browser, code, signed)
    check(used.status_code == 400 and not joined(used), "a code is used once, whatever the result")
    browser, code = await form()
    other = await submit(browser, code, await proof("bc_conformance_" + "x" * 16))
    check(other.status_code == 400 and not joined(other), "a proof over another code joins none")
    browser, code = await form()
    stray_key = await ctx.proof(user, "POST", endpoint, nonce=code)
    stray = await submit(browser, code, stray_key)
    check(stray.status_code == 400 and not joined(stray), "a key naming no Session joins none")
    browser, code = await form()
    valid = await submit(browser, code, await proof(code))
    check(valid.status_code == 303 and joined(valid), "a valid join sets the Session's cookie")
    del metadata


@case("operations.web-confirm-at-most-once")
async def _web_confirm(ctx: ConformanceContext, _: FixtureCase) -> None:
    endpoint = await ctx.operations_endpoint()
    browser, _endpoint = await _browser(ctx)
    form = ctx.scenario.web_confirm_form
    if form is None:
        raise SkipCase("the scenario does not know the website's confirm form")
    user, signed = await _signed_in_user(ctx)
    who = await ctx.who(user)
    operation = await _propose(ctx, user, signed, "user")
    page = operation_page(operation, (await ctx.company()).document.organization.domain)
    await _join(ctx, user, signed.token.session_key, page)
    fields = {name: value.format(revision=operation.revision) for name, value in form.items()}
    await browser.submit(page, fields)
    read = await ctx.agent.operations.read(
        endpoint, operation.operation_id, token=signed.token, **who
    )
    check(read.state != "proposed", "confirmed on the website")
    check(read.confirmation is not None, "with its confirmation")
    again = await ctx.agent.operations.confirm(
        endpoint, operation, approval=approve(operation), token=signed.token, **who
    )
    check(again.operation == read, "confirming at the endpoint too changes nothing")
    if "performed" in ctx.driver.capabilities:
        check(await ctx.driver.performed(operation.operation_id) == 1, "performed once")


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
