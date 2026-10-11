# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Run the conformance suite against Manzanita: the world, the scenario, the driver.

`ManzanitaConformance` puts Manzanita and two personal-agent identities on an
in-process network: Atlas, which lists the Operations extension, and Plain,
which lists none. `DemoDriver` plays Ada approving Device Sign-In on
Manzanita's page and, because this company is a demo, its operator (revising
an operation, forgetting old events, moving the shared clock).

```python
world = ManzanitaConformance()
async with served_over_tls(world.network):
    report = await run_conformance(world.context())
```
"""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal

from ..company import CompanyService
from ..conformance import ConformanceContext, Proposal, Scenario
from ..operations import TermLimit
from .kit import AgentIdentity, InProcessNetwork, MutableClock
from .manzanita import DOMAIN, ManzanitaPlugin, manzanita

#: What the suite asks of Manzanita.
MANZANITA_SCENARIO = Scenario(
    read_path="/api/orders",
    read_scope="orders:read",
    scopes=("orders:read", "orders:write"),
    proposals={
        "user": Proposal(
            "POST",
            "/api/orders/ord_7Hk2/exchanges",
            documented_as="/api/orders/{order_id}/exchanges",
        ),
        "standing": Proposal("POST", "/api/orders/ord_7Hk2/gift-wrap"),
        "fails": Proposal("POST", "/api/orders/ord_7Hk2/returns"),
        "unknown": Proposal("POST", "/api/orders/ord_7Hk2/repairs"),
    },
    standing_action="orders.gift_wrap",
    standing_limits=(
        TermLimit("price.amount", maximum=Decimal("10.00")),
        TermLimit("price.currency", allowed=frozenset({"USD"})),
    ),
    standing_too_low=(TermLimit("price.amount", maximum=Decimal("1.00")),),
    operation_prompt="The jacket is not warm enough: can we exchange it for a warmer one?",
    account_prompt="Where is my jacket order?",
    mcp_read_tool="list_orders",
    mcp_propose_tool="exchange_jacket",
    web_confirm_form={"action": "confirm", "revision": "{revision}", "approved_by": "user"},
)


class DemoDriver:
    """Ada, and Manzanita's operator: everything the runner cannot do as an agent."""

    capabilities = frozenset(
        {"revise", "forget_events", "disconnect", "performed", "clock", "second_identity"}
    )

    def __init__(
        self,
        service: CompanyService,
        plugin: ManzanitaPlugin,
        clock: MutableClock,
        other_identity: AgentIdentity,
    ) -> None:
        self.service = service
        self.plugin = plugin
        self.clock = clock
        self.other_identity: AgentIdentity | None = other_identity
        self.accounts = ("acct_ada", "acct_ada_business")

    async def approve_device(
        self, user_code: str, *, account: str, scopes: Sequence[str] | None = None
    ) -> None:
        await self.service.approve_device(user_code, account_id=account, scopes=scopes)

    async def wait(self, seconds: float) -> None:
        self.clock.advance(seconds)

    async def revise(self, operation_id: str) -> None:
        current = (await self.service.operation_record(operation_id)).operation
        await self.service.revise(
            operation_id,
            summary=f"{current.summary} Ships in 5 days instead of 2.",
            terms={**(current.terms or {}), "ships_in_days": 5},
        )

    async def forget_events(self, conversation_id: str) -> None:
        await self.service.forget_events(conversation_id, keep=1)

    async def disconnect(self, client_id: str, account: str) -> None:
        await self.service.disconnect(client_id, account)

    async def performed(self, operation_id: str) -> int:
        executors = (
            self.plugin.executor,
            self.plugin.gift_wrap,
            self.plugin.returns,
            self.plugin.repairs,
        )
        return sum(executor.performed.count(operation_id) for executor in executors)


class ManzanitaConformance:
    """Manzanita, Atlas, and Plain on one in-process network (serve it over TLS to test)."""

    def __init__(self) -> None:
        self.clock = MutableClock()
        self.network = InProcessNetwork()
        self.atlas = AgentIdentity(domain="atlas.example", name="Atlas")
        self.plain = AgentIdentity(domain="plain.example", name="Plain", extensions=())
        for identity in (self.atlas, self.plain):
            self.network.add(identity.domain, identity.website())
        self.service, self.plugin = manzanita(self.network, self.clock)
        self.driver = DemoDriver(self.service, self.plugin, self.clock, self.plain)
        self.http = self.network.client()

    def context(self) -> ConformanceContext:
        return ConformanceContext(
            f"https://{DOMAIN}",
            identity=self.atlas,
            http=self.http,
            driver=self.driver,
            scenario=MANZANITA_SCENARIO,
            clock=self.clock,
            address_resolver=self.network.resolve,
            browser_http=self.network.client(),
        )
