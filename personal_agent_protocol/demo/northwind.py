# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Northwind Bank: a fictional bank whose company agent proposes payments.

A payment is an operation (`payments.transfer`) that does not require the
user's own approval, so a personal agent may confirm it under a standing
permission the user gave it. The bank performs each payment once.
"""

from __future__ import annotations

import re
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

DOMAIN = "northwind.example"
ACCOUNT = "acct_ada_northwind"
IBAN = "DE89 3704 0044 0532 0130 00"

CONFIG = CompanyConfig(
    name="Northwind Bank",
    domain=DOMAIN,
    scopes=("accounts:read", "payments:write"),
    write_scopes=("payments:write",),
    custom_scopes={"accounts:read": "See balances", "payments:write": "Make payments"},
)

_PAY = re.compile(
    r"pay (?P<reference>[A-Z]+-\d+): "
    r"(?P<currency>[A-Z]{3}) (?P<amount>\d+\.\d{2}) to (?P<payee>.+)$",
    re.IGNORECASE,
)


class NorthwindAccounts:
    """Northwind signs its users in on its own page (Device Sign-In): nothing mediated."""

    async def authenticate(self, credentials: dict[str, SecretStr]) -> Authenticated | None:
        return None

    async def check_code(self, code_reference: str, code: SecretStr) -> bool:
        return False


class NorthwindAgent:
    """Answers balances and proposes the payments it is asked for, exactly as asked."""

    async def respond(self, turn: Turn) -> Sequence[Reply]:
        if turn.account_id is None:
            return [Reply(authorization=("sign_in_required", "accounts:read payments:write"))]
        match = _PAY.match((turn.text or "").strip())
        if match is None:
            return [
                Reply(
                    text="Balance on the current account: EUR 12,400.00.",
                    data={"balance": {"amount": "12400.00", "currency": "EUR"}},
                )
            ]
        if "payments:write" not in turn.scopes:
            return [Reply(authorization=("insufficient_scope", "payments:write"))]
        amount, currency = match["amount"], match["currency"]
        payee, reference = match["payee"], match["reference"]
        return [
            Reply(
                text=f"Ready to pay {reference}.",
                operation=ProposedOperation(
                    action="payments.transfer",
                    summary=(
                        f"Pay {currency} {amount} to {payee} for {reference} from the current "
                        f"account {IBAN}, today. Payments cannot be recalled once sent."
                    ),
                    terms={
                        "amount": {"amount": amount, "currency": currency},
                        "payee": payee,
                        "reference": reference,
                        "from_account": IBAN,
                    },
                    user_approval_required=False,
                ),
            )
        ]


class TransferExecutor:
    action = "payments.transfer"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        self.performed.append(operation.operation_id)
        terms = operation.terms or {}
        amount = terms["amount"]
        return OperationResult(
            summary=(
                f"Sent {amount['currency']} {amount['amount']} to {terms['payee']} for "
                f"{terms['reference']} from {IBAN}. Bank reference NW-{len(self.performed):04d}."
            ),
            data={"bank_reference": f"NW-{len(self.performed):04d}"},
        )


class NorthwindPlugin:
    def __init__(self) -> None:
        self.executor = TransferExecutor()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(COMPANY_ACCOUNTS, NorthwindAccounts(), contribution_id="accounts")
        contribute(COMPANY_AGENTS, NorthwindAgent(), contribution_id="agent")
        contribute(OPERATION_EXECUTORS, self.executor, contribution_id="transfers")


def northwind(
    network: InProcessNetwork, clock: MutableClock
) -> tuple[CompanyService, NorthwindPlugin]:
    """Build Northwind and put it on the network at `northwind.example`."""

    plugin = NorthwindPlugin()
    service = build_company(
        CONFIG,
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=[
            (PluginManifest(name="northwind", version="1"), plugin),
            (PluginManifest(name="northwind-clock", version="1"), ClockPlugin(clock)),
        ],
    )
    network.add(DOMAIN, company_app(service))
    return service, plugin
