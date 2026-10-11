# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Ledgerly: a fictional accounting firm that is a company and a personal agent at once.

Two companies working together, in draft 0.1's own terms. Draft 0.1 defines
no company-to-company protocol, so this is **composition**:

- To Ada's personal agent (Atlas), Ledgerly is a PAP company: discovery,
  Sessions, sign-in, a company agent, and Operations.
- To Northwind Bank, Ledgerly is a PAP **personal agent** acting for the same
  Ada, with its own `client_id` and JWKS on its own domain, connected to her
  Northwind account through Device Sign-In that she approves on Northwind's
  page.

Every approval is an Operation, never a chat message:

- A payment Northwind proposes is relayed to Ada as a Ledgerly operation
  (`northwind.payment`) quoting Northwind's summary as written. When Ada
  approves it, Ledgerly's executor checks the Northwind revision is unchanged
  and confirms it at Northwind with `approved_by: user`; Northwind's
  `result.summary` becomes Ledgerly's, as written.
- A standing permission is itself an operation Ada approves
  (`ledgerly.standing_permission`). Within its bounds, Ledgerly confirms
  Northwind's proposals with `approved_by: standing_permission` and tells
  Ada what was done; beyond them, it asks her again.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from decimal import Decimal
from typing import Any

import httpx
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from ..company import (
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    OPERATION_EXECUTORS,
    Authenticated,
    CompanyConfig,
    CompanyService,
    ProposedOperation,
    Reply,
    Turn,
    build_company,
    company_app,
)
from ..conversations import ConversationClient, generate_message_id
from ..device import DeviceSignInClient
from ..discovery import DiscoveryClient
from ..models import ClientMetadata, DiscoveredCompany, Message, Operation, OperationResult
from ..operations import (
    InMemoryStandingPermissionStore,
    OperationError,
    OperationsClient,
    StandingPermission,
    TermLimit,
    approve,
    operations_endpoint,
)
from ..sessions import SessionClient, SessionToken, Who, generate_pairwise_user_id
from ..transport import DpopHttpClient
from .kit import (
    AgentIdentity,
    ClockPlugin,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    one_origin,
    personal_agent_reactor,
)
from .northwind import DOMAIN as NORTHWIND

DOMAIN = "ledgerly.example"
TENANT = "ledgerly"
INVOICES = {
    "INV-0042": ("1250.00", "EUR", "Acme GmbH"),
    "INV-0043": ("980.00", "EUR", "Acme GmbH"),
    "INV-0044": ("3400.00", "EUR", "Acme GmbH"),
}

CONFIG = CompanyConfig(
    name="Ledgerly",
    domain=DOMAIN,
    scopes=("books:read", "payments:write"),
    write_scopes=("payments:write",),
    custom_scopes={"books:read": "See your books", "payments:write": "Pay bills for you"},
)

_INVOICE = re.compile(r"\bINV-\d{4}\b")


@dataclass
class NorthwindLink:
    """Ledgerly's connection to Northwind for one of its users."""

    pairwise_user_id: str
    session: SessionToken | None = None
    device_reference: str | None = None
    user_code: str | None = None
    account_token_reference: str | None = None


class LedgerlyAsPersonalAgent:
    """Ledgerly's PAP personal agent: what it does at Northwind for its users."""

    def __init__(self, network: InProcessNetwork, clock: MutableClock) -> None:
        self.identity = AgentIdentity(domain=DOMAIN, name="Ledgerly", path="/poppy/agent.json")
        self.standing = InMemoryStandingPermissionStore()
        self.host = PersonalAgentHost(self.identity, clock, standing=self.standing)
        self.http: httpx.AsyncClient = network.client()
        self.reactor: PluginPlatform = personal_agent_reactor(
            self.host, network=network, http_client=self.http
        )
        transport = DpopHttpClient(reactor=self.reactor, http_client=self.http)
        self.conversations = ConversationClient(transport=transport)
        self.operations = OperationsClient(transport=transport)
        self.links: dict[str, NorthwindLink] = {}
        self.pending: dict[str, Operation] = {}
        self.company: DiscoveredCompany | None = None

    async def bank(self) -> DiscoveredCompany:
        if self.company is None:
            self.company = await DiscoveryClient(
                reactor=self.reactor, http_client=self.http
            ).discover(NORTHWIND)
        return self.company

    def who(self, link: NorthwindLink, company: DiscoveredCompany) -> Who:
        return {
            "tenant_id": TENANT,
            "pairwise_user_id": link.pairwise_user_id,
            "issuer": company.oauth_metadata.issuer,  # type: ignore[union-attr]
        }

    async def connect(self, account_id: str) -> NorthwindLink:
        """Start (or continue) Device Sign-In at Northwind for this Ledgerly user."""

        company = await self.bank()
        metadata = company.oauth_metadata
        if metadata is None or metadata.device_authorization_endpoint is None:
            raise RuntimeError("Northwind does not offer Device Sign-In")
        link = self.links.setdefault(
            account_id, NorthwindLink(pairwise_user_id=generate_pairwise_user_id())
        )
        if link.session is None:
            link.session = await SessionClient(reactor=self.reactor, http_client=self.http).start(
                client_id=self.identity.client_id,
                pairwise_user_id=link.pairwise_user_id,
                issuer=metadata.issuer,
                token_endpoint=metadata.token_endpoint,
                tenant_id=TENANT,
            )
        device = DeviceSignInClient(reactor=self.reactor, http_client=self.http)
        if link.device_reference is None and link.account_token_reference is None:
            started = await device.begin(
                device_authorization_endpoint=metadata.device_authorization_endpoint,
                token_endpoint=metadata.token_endpoint,
                issuer=metadata.issuer,
                client_id=self.identity.client_id,
                scopes=("accounts:read", "payments:write"),
                tenant_id=TENANT,
                pairwise_user_id=link.pairwise_user_id,
                session_id=link.session.session_id,
            )
            link.device_reference, link.user_code = started.reference, started.user_code
            return link
        if link.device_reference is not None:
            polled = await device.poll(link.device_reference)
            if polled.status == "complete":
                link.session = polled.token
                link.account_token_reference = polled.account_token_reference
                link.device_reference = None
        return link

    async def ask_to_pay(self, link: NorthwindLink, reference: str) -> Operation:
        """Ask Northwind's agent to pay an invoice; return the operation it proposes."""

        company = await self.bank()
        amount, currency, payee = INVOICES[reference]
        endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
        page = await self.conversations.start(
            endpoint,
            Message(
                id=generate_message_id(self.reactor),
                sender="agent",
                text=f"Pay {reference}: {currency} {amount} to {payee}",
            ),
            token=link.session,  # type: ignore[arg-type]
            wait=0,
            **self.who(link, company),
        )
        for event in reversed(page.events):  # type: ignore[union-attr]
            if event.message is not None and event.message.operation is not None:
                return event.message.operation
        raise RuntimeError("Northwind proposed no payment")

    def endpoint(self, company: DiscoveredCompany) -> str:
        endpoint = operations_endpoint(
            company.document, ClientMetadata.model_validate(self.identity.metadata)
        )
        if endpoint is None:
            raise RuntimeError("Ledgerly and Northwind do not both list Operations v1")
        return endpoint


def _standing_terms(
    payee: str, maximum: str, currency: str, uses: int, days: int
) -> dict[str, Any]:
    return {
        "company": "Northwind Bank",
        "action": "payments.transfer",
        "payee": payee,
        "maximum": {"amount": maximum, "currency": currency},
        "uses": uses,
        "days": days,
    }


class LedgerlyAgent:
    """Ledgerly's company agent, answering Atlas, acting at Northwind."""

    def __init__(self, at_northwind: LedgerlyAsPersonalAgent) -> None:
        self.at = at_northwind

    async def respond(self, turn: Turn) -> Sequence[Reply]:
        if turn.account_id is None:
            return [Reply(authorization=("sign_in_required", "books:read payments:write"))]
        text = turn.text or ""
        link = await self.at.connect(turn.account_id)
        if link.account_token_reference is None:
            return [
                Reply(
                    text=(
                        "To pay from your Northwind account, let Ledgerly connect to it: open "
                        f"https://{NORTHWIND}/device and enter {link.user_code}. Tell me when done."
                    ),
                    data={
                        "connect": {
                            "company": "Northwind Bank",
                            "verification_uri": f"https://{NORTHWIND}/device",
                            "user_code": link.user_code,
                        }
                    },
                )
            ]
        if "allow" in text.lower() and "without asking" in text.lower():
            terms = _standing_terms("Acme GmbH", "2000.00", "EUR", 5, 30)
            return [
                Reply(
                    text="Here is the permission, to approve.",
                    operation=ProposedOperation(
                        action="ledgerly.standing_permission",
                        summary=(
                            "Let Ledgerly pay Acme GmbH from your Northwind account without "
                            "asking, up to EUR 2000.00 each, at most 5 payments, for 30 days."
                        ),
                        terms=terms,
                        user_approval_required=True,
                    ),
                )
            ]
        invoice = _INVOICE.search(text)
        if invoice is None:
            return [Reply(text="Your books are up to date. Which invoice should I pay?")]
        proposal = await self.at.ask_to_pay(link, invoice.group())
        company = await self.at.bank()
        outcome = None
        try:
            outcome = await self.at.operations.confirm(
                self.at.endpoint(company),
                proposal,
                standing=("Northwind Bank", link.pairwise_user_id, "payments.transfer"),
                token=link.session,  # type: ignore[arg-type]
                **self.at.who(link, company),
            )
        except OperationError as error:
            if error.code != "no_standing_permission":
                raise
        if outcome is not None and outcome.operation is not None and outcome.operation.result:
            return [
                Reply(
                    text=(
                        "Paid under your standing permission. Northwind Bank: "
                        f"{outcome.operation.result.summary}"
                    ),
                    data={"northwind_operation_id": proposal.operation_id},
                )
            ]
        self.at.pending[proposal.operation_id] = proposal
        return [
            Reply(
                text="Northwind Bank proposes this payment; it needs your approval.",
                operation=ProposedOperation(
                    action="northwind.payment",
                    summary=f"At Northwind Bank: {proposal.summary}",
                    terms={
                        "northwind_operation_id": proposal.operation_id,
                        "northwind_revision": proposal.revision,
                        **(proposal.terms or {}),
                    },
                    user_approval_required=True,
                ),
            )
        ]


class NorthwindPaymentExecutor:
    """Confirm at Northwind the exact revision Ada approved in Ledgerly."""

    action = "northwind.payment"

    def __init__(self, at_northwind: LedgerlyAsPersonalAgent) -> None:
        self.at = at_northwind

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        terms = operation.terms or {}
        proposal = self.at.pending.pop(str(terms["northwind_operation_id"]))
        relayed = {k: v for k, v in terms.items() if not k.startswith("northwind_")}
        if proposal.revision != terms["northwind_revision"] or proposal.terms != relayed:
            raise RuntimeError("Northwind's proposal is not what Ada approved")
        link = self.at.links[account_id]
        company = await self.at.bank()
        # Ada approved these exact terms in Ledgerly: Ledgerly's own interface (Operations §5).
        outcome = await self.at.operations.confirm(
            self.at.endpoint(company),
            proposal,
            approval=approve(proposal),
            token=link.session,  # type: ignore[arg-type]
            **self.at.who(link, company),
        )
        result = outcome.operation.result if outcome.operation else None
        if result is None:
            raise RuntimeError("Northwind has not finished the payment")
        return OperationResult(summary=f"Northwind Bank: {result.summary}", data=result.data)


class StandingPermissionExecutor:
    """Record the standing permission Ada approved, bounded term by term."""

    action = "ledgerly.standing_permission"

    def __init__(self, at_northwind: LedgerlyAsPersonalAgent, clock: MutableClock) -> None:
        self.at = at_northwind
        self.clock = clock

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        terms = operation.terms or {}
        link = self.at.links[account_id]
        maximum = terms["maximum"]
        permission = StandingPermission(
            reference=f"perm_{operation.operation_id}",
            company="Northwind Bank",
            account=link.pairwise_user_id,
            action=str(terms["action"]),
            limits=(
                TermLimit("payee", allowed=frozenset({str(terms["payee"])})),
                TermLimit("amount.amount", maximum=Decimal(str(maximum["amount"]))),
                TermLimit("amount.currency", allowed=frozenset({str(maximum["currency"])})),
            ),
            expires_at=self.clock.now() + timedelta(days=int(terms["days"])),
            uses_remaining=int(terms["uses"]),
        )
        self.at.standing.permissions[permission.reference] = permission
        return OperationResult(summary=operation.summary.replace("Let Ledgerly", "Ledgerly may"))


class LedgerlyAccounts:
    async def authenticate(self, credentials: dict[str, SecretStr]) -> Authenticated | None:
        return None

    async def check_code(self, code_reference: str, code: SecretStr) -> bool:
        return False


class LedgerlyPlugin:
    def __init__(self, at_northwind: LedgerlyAsPersonalAgent, clock: MutableClock) -> None:
        self.at = at_northwind
        self.clock = clock

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(COMPANY_ACCOUNTS, LedgerlyAccounts(), contribution_id="accounts")
        contribute(COMPANY_AGENTS, LedgerlyAgent(self.at), contribution_id="agent")
        contribute(OPERATION_EXECUTORS, NorthwindPaymentExecutor(self.at), contribution_id="pay")
        contribute(
            OPERATION_EXECUTORS,
            StandingPermissionExecutor(self.at, self.clock),
            contribution_id="standing",
        )


def ledgerly(
    network: InProcessNetwork, clock: MutableClock
) -> tuple[CompanyService, LedgerlyAsPersonalAgent]:
    """Build Ledgerly: its company at `ledgerly.example`, its agent identity on the same origin."""

    at_northwind = LedgerlyAsPersonalAgent(network, clock)
    service = build_company(
        CONFIG,
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=[
            (PluginManifest(name="ledgerly", version="1"), LedgerlyPlugin(at_northwind, clock)),
            (PluginManifest(name="ledgerly-clock", version="1"), ClockPlugin(clock)),
        ],
    )
    network.add(
        DOMAIN,
        one_origin(
            at_northwind.identity.website(),
            company_app(service),
            (at_northwind.identity.path, "/jwks.json"),
        ),
    )
    return service, at_northwind
