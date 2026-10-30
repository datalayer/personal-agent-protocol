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

Every approval is an Operation, never a chat message. A payment Northwind asks
approval for is relayed to Ada as a Ledgerly operation (`northwind.payment`) quoting
Northwind's summary as written. When Ada approves it, Ledgerly's executor checks the
Northwind revision is unchanged and sends Northwind the approval of that exact
revision, in the conversation that returned it; what Northwind says it came to
becomes Ledgerly's answer, as written. Ada is asked about every payment.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

import httpx
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from ..company import (
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    OPERATION_EXECUTORS,
    ActionResult,
    Authenticated,
    CompanyConfig,
    CompanyService,
    ProposedOperation,
    Reply,
    SignInContext,
    Turn,
    build_company,
    company_app,
)
from ..conversations import ConversationClient, generate_message_id
from ..device import DeviceSignInClient
from ..discovery import DiscoveryClient
from ..models import Approval, Author, DiscoveredCompany, Message, Operation
from ..sessions import AccessToken, PapSession, SessionClient, generate_pairwise_user_id
from ..transport import SessionHttpClient
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
    scope_descriptions={
        "books:read": "See your books: invoices, bills and payments",
        "payments:write": "Pay your bills, once you approve each payment",
    },
    scope_hints={"books:read": ("none", True), "payments:write": ("irreversible", True)},
)

_INVOICE = re.compile(r"\bINV-\d{4}\b")


@dataclass
class NorthwindLink:
    """Ledgerly's connection to Northwind for one of its users."""

    pairwise_user_id: str
    session: PapSession | None = None
    token: AccessToken | None = None
    device_reference: str | None = None
    user_code: str | None = None
    refresh_token_reference: str | None = None


class LedgerlyAsPersonalAgent:
    """Ledgerly's PAP personal agent: what it does at Northwind for its users."""

    def __init__(self, network: InProcessNetwork, clock: MutableClock) -> None:
        self.identity = AgentIdentity(domain=DOMAIN, name="Ledgerly", path="/poppy/agent.json")
        self.host = PersonalAgentHost(self.identity, clock)
        self.http: httpx.AsyncClient = network.client()
        self.reactor: PluginPlatform = personal_agent_reactor(
            self.host, network=network, http_client=self.http
        )
        transport = SessionHttpClient(reactor=self.reactor, http_client=self.http)
        self.conversations = ConversationClient(transport=transport)
        self.links: dict[str, NorthwindLink] = {}
        #: Each payment waiting for Ada, and the Northwind conversation that returned it.
        self.pending: dict[str, tuple[Operation, str]] = {}
        self.company: DiscoveredCompany | None = None

    async def bank(self) -> DiscoveredCompany:
        if self.company is None:
            self.company = await DiscoveryClient(
                reactor=self.reactor, http_client=self.http
            ).discover(NORTHWIND)
        return self.company

    async def connect(self, account_id: str) -> NorthwindLink:
        """Start (or continue) Device Sign-In at Northwind for this Ledgerly user."""

        company = await self.bank()
        metadata = company.oauth_metadata
        if metadata is None or not metadata.offers_device:
            raise RuntimeError("Northwind does not offer Device Sign-In")
        link = self.links.setdefault(
            account_id, NorthwindLink(pairwise_user_id=generate_pairwise_user_id())
        )
        if link.session is None:
            link.session = await SessionClient(reactor=self.reactor, http_client=self.http).start(
                client_id=self.identity.client_id,
                pairwise_user_id=link.pairwise_user_id,
                issuer=metadata.issuer,
                tenant_id=TENANT,
            )
        device = DeviceSignInClient(reactor=self.reactor, http_client=self.http)
        if link.device_reference is None and link.refresh_token_reference is None:
            started = await device.begin(
                device_authorization_endpoint=cast(str, metadata.device_authorization_endpoint),
                token_endpoint=metadata.token_endpoint,
                issuer=metadata.issuer,
                client_id=self.identity.client_id,
                scopes=("accounts:read", "payments:write"),
                tenant_id=TENANT,
                organization=company.document.organization,
                protected_resources=metadata.protected_resources,
            )
            link.device_reference, link.user_code = started.reference, started.user_code
            return link
        if link.device_reference is not None:
            polled = await device.poll(link.device_reference)
            if polled.status == "complete":
                link.token = polled.token
                link.refresh_token_reference = polled.refresh_token_reference
                link.device_reference = None
        return link

    async def conversation_endpoint(self) -> str:
        company = await self.bank()
        return company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    async def ask_to_pay(self, link: NorthwindLink, reference: str) -> tuple[Operation, str]:
        """Ask Northwind's agent to pay an invoice: the operation, and its conversation."""

        amount, currency, payee = INVOICES[reference]
        page = await self.conversations.start(
            await self.conversation_endpoint(),
            Message(
                id=generate_message_id(self.reactor),
                author=Author(type="agent"),
                text=f"Pay {reference}: {currency} {amount} to {payee}",
            ),
            session=link.session,  # type: ignore[arg-type]
            token=link.token,
            wait=0,
        )
        for event in reversed(page.events):  # type: ignore[union-attr]
            if event.message is not None and event.message.operation is not None:
                return event.message.operation, page.conversation_id
        raise RuntimeError("Northwind returned no payment to approve")

    async def send_approval(
        self, link: NorthwindLink, proposal: Operation, conversation_id: str
    ) -> Message:
        """Send Northwind Ada's approval of this exact revision: what it says it came to."""

        page = await self.conversations.send(
            await self.conversation_endpoint(),
            conversation_id,
            Message(
                id=generate_message_id(self.reactor),
                author=Author(type="agent"),
                approval=Approval(operation_id=proposal.operation_id, revision=proposal.revision),
            ),
            session=link.session,  # type: ignore[arg-type]
            token=link.token,
            wait=0,
        )
        for event in reversed(page.events):  # type: ignore[union-attr]
            if event.message is not None and event.message.role == "company":
                return event.message
        raise RuntimeError("Northwind has not finished the payment")


class LedgerlyAgent:
    """Ledgerly's company agent, answering Atlas, acting at Northwind."""

    def __init__(self, at_northwind: LedgerlyAsPersonalAgent) -> None:
        self.at = at_northwind

    async def respond(self, turn: Turn) -> Sequence[Reply]:
        if turn.account_id is None:
            return [Reply(authorization=("insufficient_scope", "books:read payments:write"))]
        text = turn.text or ""
        link = await self.at.connect(turn.account_id)
        if link.refresh_token_reference is None:
            return [
                Reply(
                    # The code is for the person's page alone (`data`), as in a PapSignIn
                    # display: the text, which a model reads, names only the page.
                    text=(
                        "To pay from your Northwind account, let Ledgerly connect to it: open "
                        f"https://{NORTHWIND}/device and enter the code shown with this "
                        "message. Tell me when done."
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
        invoice = _INVOICE.search(text)
        if invoice is None:
            return [Reply(text="Your books are up to date. Which invoice should I pay?")]
        proposal, conversation_id = await self.at.ask_to_pay(link, invoice.group())
        self.at.pending[proposal.operation_id] = (proposal, conversation_id)
        return [
            Reply(
                text="Northwind Bank asks approval for this payment.",
                operation=ProposedOperation(
                    action="northwind.payment",
                    subject=invoice.group(),
                    summary=f"At Northwind Bank: {proposal.summary}",
                    terms={
                        "northwind_operation_id": proposal.operation_id,
                        "northwind_revision": proposal.revision,
                        **(proposal.terms or {}),
                    },
                ),
            )
        ]


class NorthwindPaymentExecutor:
    """Send Northwind the approval of the exact revision Ada approved in Ledgerly."""

    action = "northwind.payment"

    def __init__(self, at_northwind: LedgerlyAsPersonalAgent) -> None:
        self.at = at_northwind

    async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
        terms = operation.terms or {}
        proposal, conversation_id = self.at.pending.pop(str(terms["northwind_operation_id"]))
        relayed = {k: v for k, v in terms.items() if not k.startswith("northwind_")}
        if proposal.revision != terms["northwind_revision"] or proposal.terms != relayed:
            raise RuntimeError("Northwind's operation is not what Ada approved")
        link = self.at.links[cast(str, account_id)]
        # Ada approved these exact terms in Ledgerly: Ledgerly's own interface (Operations 5).
        answer = await self.at.send_approval(link, proposal, conversation_id)
        return ActionResult(summary=f"Northwind Bank: {answer.text}", data=answer.data)


class LedgerlyAccounts:
    async def authenticate(
        self, credentials: dict[str, SecretStr], context: SignInContext
    ) -> Authenticated | None:
        return None

    async def check_code(self, code_reference: str, code: SecretStr) -> bool:
        return False


class LedgerlyPlugin:
    def __init__(self, at_northwind: LedgerlyAsPersonalAgent) -> None:
        self.at = at_northwind

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(COMPANY_ACCOUNTS, LedgerlyAccounts(), contribution_id="accounts")
        contribute(COMPANY_AGENTS, LedgerlyAgent(self.at), contribution_id="agent")
        contribute(OPERATION_EXECUTORS, NorthwindPaymentExecutor(self.at), contribution_id="pay")


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
            (PluginManifest(name="ledgerly", version="1"), LedgerlyPlugin(at_northwind)),
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
