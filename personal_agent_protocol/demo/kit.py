# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""A self-contained PAP world for examples and tests: no network, no model, real crypto.

- `AgentIdentity` is a personal agent's real ES256 key, its client metadata
  and JWKS, served at its own HTTPS origin (`AgentIdentity.website`).
- `InProcessNetwork` routes each domain to an ASGI application through
  `httpx`, and answers DNS for those domains with a public address so PAP's
  SSRF policy applies unchanged. Requests are real HTTP over ASGI in one
  process; nothing leaves it.
- `personal_agent_reactor` assembles the personal agent's Reactor host: its
  signer, DPoP keys, clock, token and state stores, protected input, and
  standing permissions, each a contribution.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Iterable, MutableMapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from ..crypto import DpopKeyMaterial, JoseDpopProofProvider, JoseSigner
from ..errors import DiscoveryError
from ..operations import STANDING_PERMISSION_STORES, InMemoryStandingPermissionStore
from ..reactor import (
    AUTHORIZATION_STATE_STORES,
    CLOCKS,
    DPOP_PROOF_PROVIDERS,
    PROTECTED_INPUTS,
    SIGNERS,
    TOKEN_STORES,
    DpopProofRequest,
    ProtectedInputRequest,
    build_pap_reactor,
)

#: A public address the SSRF policy accepts; nothing is ever sent to it.
PUBLIC_ADDRESS = "93.184.216.34"

Asgi = Callable[[MutableMapping[str, Any], Any, Any], Awaitable[None]]


class MutableClock:
    """One clock for every party, so a demo can skip a polling interval."""

    def __init__(self, start: datetime | None = None) -> None:
        self.value = start or datetime(2026, 10, 11, 9, tzinfo=timezone.utc)

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += timedelta(seconds=seconds)


def json_site(documents: dict[str, Any]) -> Asgi:
    """An ASGI site serving fixed JSON documents by path."""

    async def app(scope: MutableMapping[str, Any], receive: Any, send: Any) -> None:
        document = documents.get(scope["path"])
        status = 200 if document is not None else 404
        body = json.dumps(document if document is not None else {"error": "not_found"}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app


@dataclass
class AgentIdentity:
    """A personal agent's identity: its `client_id`, keys, and published metadata."""

    domain: str
    name: str
    path: str = "/agent.json"
    extensions: tuple[str, ...] = ("operations",)
    private_key: ec.EllipticCurvePrivateKey = field(
        default_factory=lambda: ec.generate_private_key(ec.SECP256R1())
    )
    kid: str = "key-1"

    @property
    def client_id(self) -> str:
        return f"https://{self.domain}{self.path}"

    @property
    def jwks(self) -> dict[str, Any]:
        public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(self.private_key.public_key()))
        return {"keys": [{**public, "kid": self.kid, "use": "sig", "alg": "ES256"}]}

    @property
    def metadata(self) -> dict[str, Any]:
        return {
            "client_id": self.client_id,
            "client_name": self.name,
            "jwks_uri": f"https://{self.domain}/jwks.json",
            "redirect_uris": [f"https://{self.domain}/oauth/callback"],
            "token_endpoint_auth_method": "private_key_jwt",
            "extensions": {name: {"version": "1"} for name in self.extensions},
        }

    def website(self) -> Asgi:
        return json_site({self.path: self.metadata, "/jwks.json": self.jwks})

    def signer(self) -> JoseSigner:
        return JoseSigner(self.private_key, algorithm="ES256", key_id=self.kid)


class InProcessNetwork:
    """Domains served by ASGI applications, reachable over HTTPS through `httpx`."""

    def __init__(self) -> None:
        self.apps: dict[str, Asgi] = {}

    def add(self, domain: str, app: Asgi) -> None:
        self.apps[domain] = app

    def client(self) -> httpx.AsyncClient:
        """A client that reaches every domain on the network, including ones added later."""

        return httpx.AsyncClient(transport=_Routing(self), timeout=10.0)

    async def resolve(self, host: str) -> list[str]:
        if host not in self.apps:
            raise DiscoveryError("dns_failed", "Could not resolve discovery host")
        return [PUBLIC_ADDRESS]


class _Routing(httpx.AsyncBaseTransport):
    def __init__(self, network: InProcessNetwork) -> None:
        self.network = network

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        app = self.network.apps.get(request.url.host)
        if request.url.scheme != "https" or app is None:
            raise httpx.ConnectError(f"{request.url.host} is not on the network", request=request)
        return await httpx.ASGITransport(app=app).handle_async_request(request)  # type: ignore[arg-type]


class MemoryVault:
    """A token store and a one-use state store in one place (never shown to a model)."""

    def __init__(self) -> None:
        self.values: dict[str, Any] = {}

    async def put(self, reference: str, value: Any, **_: object) -> None:
        self.values[reference] = value

    async def get(self, reference: str) -> Any:
        return self.values.get(reference)

    async def take(self, reference: str) -> Any:
        return self.values.pop(reference, None)

    async def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


class ScriptedInput:
    """The host's trusted input surface, answered from a script in a demo."""

    def __init__(self, *answers: dict[str, str]) -> None:
        self.answers = list(answers)
        self.asked: list[ProtectedInputRequest] = []

    async def collect(self, request: ProtectedInputRequest) -> dict[str, SecretStr]:
        self.asked.append(request)
        return {name: SecretStr(value) for name, value in self.answers.pop(0).items()}


class DpopKeys:
    """One EC key per (tenant, user, company): the Session's proof-of-possession key."""

    def __init__(self) -> None:
        self.keys: dict[tuple[str, str, str], DpopKeyMaterial] = {}

    async def __call__(self, request: DpopProofRequest) -> DpopKeyMaterial:
        key = (request.tenant_id, request.subject, request.issuer)
        if key not in self.keys:
            private = ec.generate_private_key(ec.SECP256R1())
            public = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private.public_key()))
            self.keys[key] = DpopKeyMaterial(private_key=private, public_jwk=public)
        return self.keys[key]


@dataclass
class PersonalAgentHost:
    """The contributions a personal agent's host makes, for its Reactor."""

    identity: AgentIdentity
    clock: MutableClock
    vault: MemoryVault = field(default_factory=MemoryVault)
    protected_input: ScriptedInput = field(default_factory=ScriptedInput)
    standing: InMemoryStandingPermissionStore = field(
        default_factory=InMemoryStandingPermissionStore
    )

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(CLOCKS, self.clock, contribution_id="demo-clock")
        contribute(SIGNERS, self.identity.signer(), contribution_id="agent-key")
        contribute(
            DPOP_PROOF_PROVIDERS,
            JoseDpopProofProvider(DpopKeys(), now=self.clock.now),
            contribution_id="dpop-keys",
        )
        contribute(TOKEN_STORES, self.vault, contribution_id="vault")
        contribute(AUTHORIZATION_STATE_STORES, self.vault, contribution_id="vault")
        contribute(PROTECTED_INPUTS, self.protected_input, contribution_id="trusted-input")
        contribute(STANDING_PERMISSION_STORES, self.standing, contribution_id="standing")


def personal_agent_reactor(
    host: PersonalAgentHost,
    *,
    network: InProcessNetwork,
    http_client: httpx.AsyncClient,
    plugins: Iterable[tuple[PluginManifest, object]] = (),
) -> PluginPlatform:
    """The personal agent's Reactor host: PAP core, then the host's contributions."""

    reactor, _ = build_pap_reactor(
        http_client=http_client,
        address_resolver=network.resolve,
        plugins=[
            (PluginManifest(name=f"{host.identity.domain}-host", version="1"), host),
            *plugins,
        ],
    )
    return reactor


class ClockPlugin:
    """Give a company the demo's shared clock."""

    def __init__(self, clock: MutableClock) -> None:
        self.clock = clock

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(CLOCKS, self.clock, contribution_id="demo-clock")  # type: ignore[attr-defined]
