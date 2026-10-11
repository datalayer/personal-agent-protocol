# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The company side of PAP, assembled from Reactor contributions.

```python
service = build_company(config, plugins=[(manifest, my_company_plugin)], http_client=http)
app = company_app(service)  # any ASGI server or httpx.ASGITransport
```
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx
from reactor import PluginManifest, hookimpl  # type: ignore[import-untyped]

from ..identity import AgentIdentityClient
from ..models import ClientMetadata, JsonWebKeySet
from ..reactor import AddressResolver, build_pap_reactor, resolve_addresses
from .asgi import company_app
from .points import (
    CLIENT_POLICIES,
    CLIENT_RESOLVERS,
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    COMPANY_APIS,
    COMPANY_STORES,
    OPERATION_EXECUTORS,
    REPLAY_CACHES,
    AccountDirectory,
    AllowEveryAgent,
    ApiCall,
    ApiResult,
    Authenticated,
    ClientPolicy,
    ClientResolver,
    CompanyAgent,
    CompanyApi,
    CompanyStore,
    MemoryCompanyStore,
    MemoryReplayCache,
    OperationExecutor,
    OperationFailed,
    OperationOutcomeUnknown,
    ProposedOperation,
    Reply,
    Turn,
)
from .service import CompanyConfig, CompanyRequest, CompanyResponse, CompanyService
from .verify import verify_assertion


class IdentityClientResolver:
    """Resolve a personal agent's metadata and keys over HTTPS (§4.1)."""

    def __init__(self, identity: AgentIdentityClient) -> None:
        self.identity = identity

    async def resolve(self, client_id: str) -> tuple[ClientMetadata, JsonWebKeySet]:
        return await self.identity.fetch_metadata(client_id), await self.identity.fetch_jwks(
            client_id
        )


class CompanyDefaultsPlugin:
    """The company side's defaults: memory store and replay cache, open policy."""

    def __init__(self, resolver: ClientResolver) -> None:
        self.resolver = resolver

    @hookimpl
    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(COMPANY_STORES, MemoryCompanyStore(), contribution_id="memory", order=100)
        contribute(REPLAY_CACHES, MemoryReplayCache(), contribution_id="memory", order=100)
        contribute(CLIENT_POLICIES, AllowEveryAgent(), contribution_id="allow", order=100)
        contribute(CLIENT_RESOLVERS, self.resolver, contribution_id="https", order=100)


def build_company(
    config: CompanyConfig,
    *,
    http_client: httpx.AsyncClient,
    plugins: Iterable[tuple[PluginManifest, object]] = (),
    address_resolver: AddressResolver = resolve_addresses,
) -> CompanyService:
    """Assemble a company: PAP core, company defaults, then the company's own plugins.

    The company's plugins contribute at least `pap.company.accounts` and
    `pap.company.agent`, and one `pap.company.operationExecutor` per action
    its agent proposes; a lower `order` replaces any default.
    """

    reactor, _ = build_pap_reactor(http_client=http_client, address_resolver=address_resolver)
    identity = AgentIdentityClient(reactor=reactor, http_client=http_client)
    reactor.register_plugin(
        PluginManifest(
            name="personal-agent-protocol.company",
            version="0.3.3",
            contribution_points=[
                COMPANY_STORES.id,
                COMPANY_ACCOUNTS.id,
                COMPANY_AGENTS.id,
                COMPANY_APIS.id,
                OPERATION_EXECUTORS.id,
                CLIENT_POLICIES.id,
                CLIENT_RESOLVERS.id,
                REPLAY_CACHES.id,
            ],
        ),
        CompanyDefaultsPlugin(IdentityClientResolver(identity)),
    )
    for manifest, implementation in plugins:
        reactor.register_plugin(manifest, implementation)
    return CompanyService(config=config, reactor=reactor)


__all__ = [
    "CLIENT_POLICIES",
    "CLIENT_RESOLVERS",
    "COMPANY_ACCOUNTS",
    "COMPANY_AGENTS",
    "COMPANY_APIS",
    "COMPANY_STORES",
    "OPERATION_EXECUTORS",
    "REPLAY_CACHES",
    "AccountDirectory",
    "AllowEveryAgent",
    "ApiCall",
    "ApiResult",
    "Authenticated",
    "ClientPolicy",
    "ClientResolver",
    "CompanyAgent",
    "CompanyApi",
    "CompanyConfig",
    "CompanyDefaultsPlugin",
    "CompanyRequest",
    "CompanyResponse",
    "CompanyService",
    "CompanyStore",
    "IdentityClientResolver",
    "MemoryCompanyStore",
    "MemoryReplayCache",
    "OperationExecutor",
    "OperationFailed",
    "OperationOutcomeUnknown",
    "ProposedOperation",
    "Reply",
    "Turn",
    "build_company",
    "company_app",
    "verify_assertion",
]
