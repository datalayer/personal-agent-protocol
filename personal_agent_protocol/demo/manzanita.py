# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Manzanita Outfitters: a fictional company, assembled from Reactor contributions.

The company of the upstream home page's example: a user wants to return a
jacket that is not warm enough. Manzanita offers Device and Mediated Sign-In,
a company agent, and the Operations extension. Its parts are contributions:

- `ManzanitaAccounts` (`pap.company.accounts`): one account, Ada's, with a
  password and a one-time code.
- `ManzanitaAgent` (`pap.company.agent`): reads the order once signed in
  (`authorization` until then) and proposes the exchange as an operation.
- `ExchangeExecutor` (`pap.company.operationExecutor`): performs the
  exchange, once.
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence

from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

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
from ..models import Operation, OperationResult
from .kit import ClockPlugin, InProcessNetwork, MutableClock

DOMAIN = "manzanita.example"
ADA = {"email": "ada@example.com", "password": "correct horse battery staple"}
ADA_CODE = "246810"
ORDER = {"order_id": "ord_7Hk2", "item": "Ridge Jacket, size M", "status": "delivered"}

CONFIG = CompanyConfig(
    name="Manzanita Outfitters",
    domain=DOMAIN,
    scopes=("orders:read", "orders:write"),
    write_scopes=("orders:write",),
    mediated_fields=(("email", "Email", False), ("password", "Password", True)),
    custom_scopes={"orders:read": "See your orders", "orders:write": "Exchange and return items"},
)


class ManzanitaAccounts:
    """Ada's account: her password, then a code sent to her email."""

    async def authenticate(self, credentials: dict[str, SecretStr]) -> Authenticated | None:
        email = credentials.get("email")
        password = credentials.get("password")
        if (
            email is None
            or password is None
            or email.get_secret_value() != ADA["email"]
            or not hmac.compare_digest(password.get_secret_value(), ADA["password"])
        ):
            return None
        return Authenticated(
            account_id="acct_ada", code_reference="code_ada", sent_to="a•••@example.com"
        )

    async def check_code(self, code_reference: str, code: SecretStr) -> bool:
        return code_reference == "code_ada" and hmac.compare_digest(
            code.get_secret_value(), ADA_CODE
        )


class ManzanitaAgent:
    """Manzanita's company agent: a few rules, enough to show the protocol."""

    async def respond(self, turn: Turn) -> Sequence[Reply]:
        text = (turn.text or "").lower()
        if turn.account_id is None:
            if "order" in text or "jacket" in text or "exchange" in text:
                return [
                    Reply(text="I can look that up once you sign in to your Manzanita account."),
                    Reply(authorization=("sign_in_required", "orders:read orders:write")),
                ]
            return [Reply(text="Hello from Manzanita Outfitters. Ask me about an order.")]
        if "exchange" in text or "warmer" in text:
            if "orders:write" not in turn.scopes:
                return [Reply(authorization=("insufficient_scope", "orders:write"))]
            return [
                Reply(
                    text="The insulated Ridge Jacket is in stock. Here is the exchange.",
                    operation=ProposedOperation(
                        action="orders.exchange",
                        summary=(
                            "Exchange the Ridge Jacket (M) from order ord_7Hk2 for the "
                            "insulated Ridge Jacket (M), USD 70.00 more."
                        ),
                        terms={
                            "order_id": "ord_7Hk2",
                            "price_difference": {"amount": "70.00", "currency": "USD"},
                        },
                        user_approval_required=True,
                    ),
                )
            ]
        return [Reply(text="Your order ord_7Hk2: Ridge Jacket, size M, delivered.", data=ORDER)]


class ExchangeExecutor:
    """Perform an exchange once: the operation ID is the downstream idempotency key."""

    action = "orders.exchange"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        self.performed.append(operation.operation_id)
        terms = operation.terms or {}
        difference = terms.get("price_difference") or {}
        amount = f"{difference.get('currency', 'USD')} {difference.get('amount', '0.00')}"
        return OperationResult(
            summary=(
                "Exchanged the Ridge Jacket (M) for the insulated Ridge Jacket (M). "
                f"{amount} charged to the card ending 4242; a return label was emailed."
            ),
            data={"order_id": terms.get("order_id"), "charged": difference},
        )


class ManzanitaPlugin:
    def __init__(self) -> None:
        self.executor = ExchangeExecutor()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(COMPANY_ACCOUNTS, ManzanitaAccounts(), contribution_id="accounts")
        contribute(COMPANY_AGENTS, ManzanitaAgent(), contribution_id="agent")
        contribute(OPERATION_EXECUTORS, self.executor, contribution_id="exchange")


def manzanita(
    network: InProcessNetwork, clock: MutableClock
) -> tuple[CompanyService, ManzanitaPlugin]:
    """Build Manzanita and put it on the network at `manzanita.example`."""

    plugin = ManzanitaPlugin()
    service = build_company(
        CONFIG,
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=[
            (PluginManifest(name="manzanita", version="1"), plugin),
            (PluginManifest(name="manzanita-clock", version="1"), ClockPlugin(clock)),
        ],
    )
    network.add(DOMAIN, company_app(service))
    return service, plugin
