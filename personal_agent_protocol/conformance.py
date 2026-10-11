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
from .conversations import ConversationClient, TextDelta
from .crypto import JoseDpopProofProvider
from .demo.kit import AgentIdentity, MemoryVault, MutableClock, PersonalAgentHost
from .device import DeviceSignInClient
from .discovery import DiscoveryClient
from .errors import PersonalAgentProtocolError, TransportError
from .models import ConversationEvent, DiscoveredCompany, Message, Operation
from .operations import (
    STANDING_PERMISSION_STORES,
    InMemoryStandingPermissionStore,
    OperationError,
    OperationsClient,
    StandingPermission,
    TermLimit,
    approve,
    operations_endpoint,
)
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
from .sessions import SessionClient, SessionToken
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
    clock instead of sleeping), and `second_identity` (`other_identity` is a
    second agent the company can resolve, listing no extensions).
    """

    capabilities: frozenset[str]
    accounts: tuple[str, str]
    other_identity: AgentIdentity | None

    async def approve_device(
        self, user_code: str, *, account: str, scopes: Sequence[str] | None = None
    ) -> None: ...

    async def wait(self, seconds: float) -> None: ...

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
    `account_prompt` makes it ask for sign-in.
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
    ) -> None:
        self.identity = identity
        self.http = http
        self.vault = MemoryVault()
        self.standing = InMemoryStandingPermissionStore()
        host = PersonalAgentHost(
            identity,
            cast(MutableClock, clock),
            vault=self.vault,
            standing=self.standing,
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


def _manifest(identity: AgentIdentity) -> Any:
    from reactor import PluginManifest  # type: ignore[import-untyped]

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
        self.agent = Agent(identity, http=http, clock=self.clock, address_resolver=address_resolver)
        self._other: Agent | None = None
        self._company: DiscoveredCompany | None = None

    # The company -------------------------------------------------------------------

    async def company(self) -> DiscoveredCompany:
        if self._company is None:
            client = DiscoveryClient(reactor=self.agent.reactor)
            self._company = await client.discover(self.domain)
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
        return f"{self.base_url}{path}"

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

    async def who(self, user: str) -> dict[str, str]:
        metadata = await self.metadata()
        return {"tenant_id": self.tenant_id, "pairwise_user_id": user, "issuer": metadata.issuer}

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
        if metadata.device_authorization_endpoint is None:
            raise SkipCase("the company offers no Device Sign-In")
        actor = agent or self.agent
        started = await actor.device.begin(
            device_authorization_endpoint=metadata.device_authorization_endpoint,
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=actor.identity.client_id,
            scopes=tuple(scopes or self.scenario.scopes),
            tenant_id=self.tenant_id,
            pairwise_user_id=user,
            session_id=session.session_id,
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
        agent: Agent | None = None,
        shift: float = 0,
    ) -> str:
        """A DPoP proof from the user's key, optionally made `shift` seconds off."""

        metadata = await self.metadata()
        provider = first_contribution(
            (agent or self.agent).reactor, DPOP_PROOF_PROVIDERS, "DPoP proof provider"
        )
        if shift:
            if not isinstance(provider, JoseDpopProofProvider):
                raise SkipCase("the DPoP provider cannot make a proof at another time")
            provider = JoseDpopProofProvider(
                provider.key_resolver, now=lambda: self.now() + timedelta(seconds=shift)
            )
        access = token.access_token if isinstance(token, SessionToken) else token
        proof = await provider.create(  # type: ignore[attr-defined]
            DpopProofRequest(
                method=method,
                url=url,
                tenant_id=self.tenant_id,
                subject=user,
                issuer=metadata.issuer,
                access_token=access,
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

            signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
            return f"{signing_input}.{_b64(signature)}"
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
        claims = self.claims(subject=actor.client_id, audience=metadata.token_endpoint)
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
)
async def _client_assertion(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    metadata = await ctx.metadata()
    mutation = fixture.mutation
    user = ctx.new_user()
    client_id = ctx.agent.identity.client_id
    audience: Any = mutation.get("aud", metadata.token_endpoint)
    if mutation.get("aud_array"):
        audience = [metadata.token_endpoint, "https://other-company.example/oauth/token"]
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
    session_claims = ctx.claims(subject=user, audience=metadata.token_endpoint)
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
        audience=mutation.get("aud", metadata.token_endpoint),
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
        check(response.json().get("signed_in") is False, "a new Session starts signed out")
        return
    expect_refusal(response, fixture.expect["status"], fixture.expect["error"], fixture.id)


@case("security.token-request-without-dpop", "security.token-dpop-with-ath")
async def _token_dpop(ctx: ConformanceContext, fixture: FixtureCase) -> None:
    metadata = await ctx.metadata()
    user = ctx.new_user()
    form = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": ctx.assertion(ctx.claims(subject=user, audience=metadata.token_endpoint)),
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
        headers["DPoP"] = await ctx.proof(ctx.new_user(), "GET", url, token=session)
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
        first = await ctx.send("GET", url, headers={**headers, "DPoP": replayed})
        check(first.status_code not in {400, 401}, "the first use of the proof is accepted")
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
    expect_refusal(response, 401, "invalid_token", "a token in the URL")


@case("security.authorization-header-without-cookies")
async def _no_cookies(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    endpoint = await ctx.conversations_endpoint()
    body = json.dumps(
        {"message": {"id": _message_id(), "sender": "agent", "text": ctx.scenario.greeting}}
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
        "assertion": ctx.assertion(ctx.claims(subject=user, audience=metadata.token_endpoint)),
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
                ctx.claims(
                    subject=ctx.agent.identity.client_id,
                    audience=metadata.device_authorization_endpoint,
                )
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
        "session_id": session.session_id,
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
    check(first.session_id != second.session_id, "parallel Sessions are distinct")
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
        session_id=old.session_id,
    )
    check(new.session_id == old.session_id, "renewal keeps the Session")
    check(await _probe(ctx, user, new) == 403, "the new token is served (signed out)")
    check(await _probe(ctx, user, old) == 401, "the replaced token stops working")


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
            session_id=owner.session_id,
        )
    check(raised.value.code == "invalid_session", f"got {raised.value.code}")


@case("lifecycle.sign-in-scopes")
async def _sign_in_scopes(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    session = await ctx.session(user)
    granted = (ctx.scenario.read_scope,)
    signed = await ctx.sign_in(user, session, granted=granted)
    check(signed.token.signed_in, "the Session is signed in")
    check(signed.token.session_id == session.session_id, "the same Session is signed in")
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
            pairwise_user_id=user,
            session_id=session.session_id,
        )
    check(raised.value.code == "invalid_scope", f"got {raised.value.code}")


@case("lifecycle.account-token-signs-in-new-session")
async def _new_session(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    fresh = await ctx.session(user)
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_id=fresh.session_id
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
        signed.reference, context=await ctx.account_context(user), session_id=session.session_id
    )
    if not result.rotated:
        raise SkipCase("the company does not rotate Account Tokens")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": before.get_secret_value(),
        "session_id": session.session_id,
        **(await ctx.client_form()),
    }
    old = await ctx.token_request(user, form)
    expect_refusal(old, 400, "invalid_grant", "a rotated-away Account Token")
    again = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_id=session.session_id
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
        session_id=session.session_id,
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
        session_id=session.session_id,
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
        "session_id": other_session.session_id,
        **(await ctx.client_form(other.identity)),
    }
    metadata = await ctx.metadata()
    proof = await ctx.proof(user, "POST", metadata.token_endpoint, agent=other)
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
            session_id=other_session.session_id,
        )
    check(raised.value.code == "account_mismatch", f"got {raised.value.code}")


@case("lifecycle.account-token-for-another-users-session")
async def _another_users_session(ctx: ConformanceContext, _: FixtureCase) -> None:
    user = ctx.new_user()
    signed = await ctx.sign_in(user, await ctx.session(user))
    stranger = await ctx.session(ctx.new_user())
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.accounts.refresh(
            signed.reference,
            context=await ctx.account_context(user),
            session_id=stranger.session_id,
        )
    check(raised.value.code == "invalid_session", f"got {raised.value.code}")


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
        session_id=session.session_id,
    )
    check(not renewed.signed_in, "the Session continues signed out")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": secret.get_secret_value(),
        "session_id": session.session_id,
        **(await ctx.client_form()),
    }
    expect_refusal(await ctx.token_request(user, form), 400, "invalid_grant", "a revoked token")


@case("lifecycle.disconnect-from-account-settings")
async def _disconnect(ctx: ConformanceContext, _: FixtureCase) -> None:
    ctx.require("disconnect")
    user = ctx.new_user()
    session = await ctx.session(user)
    signed = await ctx.sign_in(user, session)
    await ctx.driver.disconnect(ctx.agent.identity.client_id, ctx.driver.accounts[0])
    check(await _probe(ctx, user, signed.token) == 403, "its Sessions are signed out")
    result = await ctx.agent.accounts.refresh(
        signed.reference, context=await ctx.account_context(user), session_id=session.session_id
    )
    check(result.status == "signed_out", "the agent finds out from invalid_grant")
    check(await ctx.agent.vault.get(signed.reference) is None, "and forgets the token")


# Conversations ------------------------------------------------------------------------


def _message_id() -> str:
    return "msg_" + base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")


def _message(text: str, sender: Literal["agent", "human"] = "agent") -> Message:
    return Message(id=_message_id(), sender=sender, text=text)


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
    check(all(m.get("sender") in {"agent", "human"} for m in company), "replies carry sender")


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
    words = _message("These are the user's own words.", sender="human")
    receipt = await ctx.agent.conversations.start(endpoint, words, token=session, **who)
    page = await ctx.agent.conversations.read_events(
        endpoint, receipt.conversation_id, token=session, **who
    )
    messages = [event.message for event in page.events if event.message is not None]
    mine = [m for m in messages if m.id == words.id]
    check(mine and mine[0].role == "user", "the user's message comes back with role user")
    check(mine and mine[0].sender == "human", "and keeps sender human")
    theirs = [m for m in messages if m.role == "company"]
    check(theirs and all(m.sender in {"agent", "human"} for m in theirs), "replies have sender")


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
        endpoint, parent, _message("I'd like to ask myself.", sender="human"), token=session, **who
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
        endpoint, parent, _message("Hi.", sender="human"), token=session, **who
    )
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.start_direct(
            endpoint, direct.conversation_id, _message("Hi.", sender="human"), token=session, **who
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
        session_id=session.session_id,
    )
    with _raises(PersonalAgentProtocolError) as raised:
        await ctx.agent.conversations.read_events(endpoint, conversation, token=signed_out, **who)
    check(raised.value.code == "sign_in_required", f"got {raised.value.code}")


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
        _message(f"Yes, I confirm operation {operation.operation_id}. Approved.", sender="human"),
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
        session_id=signed.token.session_id,
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
        profile="0.1",
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
