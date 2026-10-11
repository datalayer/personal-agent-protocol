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
  exchange, once. Gift wrap (a small charge a standing permission can
  cover), a return that fails partway, and a repair whose carrier never
  answers show the other ends of an operation.
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence

from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from ..company import (
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    COMPANY_APIS,
    COMPANY_MCP,
    OPERATION_EXECUTORS,
    ApiCall,
    ApiResult,
    Authenticated,
    CompanyConfig,
    CompanyService,
    CompanyStore,
    OperationFailed,
    OperationOutcomeUnknown,
    ProposedOperation,
    Reply,
    ToolResult,
    Turn,
    build_company,
    company_app,
)
from ..models import Operation, OperationResult
from .kit import ClockPlugin, InProcessNetwork, MutableClock, StorePlugin

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
    web=True,
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
                    operation=EXCHANGE,
                )
            ]
        return [Reply(text="Your order ord_7Hk2: Ridge Jacket, size M, delivered.", data=ORDER)]


class ManzanitaApi:
    """Manzanita's OpenAPI API: orders, and exchanges proposed as operations."""

    description = "Orders and exchanges"

    def openapi(self) -> dict[str, object]:
        return {
            "openapi": "3.1.0",
            "info": {"title": "Manzanita Outfitters", "version": "1"},
            "paths": {
                "/api/orders": {"get": {"summary": "Your orders (orders:read)"}},
                "/api/orders/{order_id}/exchanges": {
                    "post": {"summary": "Propose an exchange (orders:write): 202 and an operation"}
                },
                "/api/orders/{order_id}/gift-wrap": {
                    "post": {"summary": "Propose gift wrap (orders:write): 202 and an operation"}
                },
                "/api/orders/{order_id}/returns": {
                    "post": {"summary": "Propose a return (orders:write): 202 and an operation"}
                },
                "/api/orders/{order_id}/repairs": {
                    "post": {"summary": "Propose a repair (orders:write): 202 and an operation"}
                },
            },
        }

    async def handle(self, call: ApiCall) -> ApiResult:
        if call.method == "GET" and call.path == "/orders":
            if call.account_id is None:
                return ApiResult.sign_in_required("orders:read")
            if "orders:read" not in call.scopes:
                return ApiResult.insufficient_scope("orders:read")
            return ApiResult(body={"orders": [ORDER]})
        prefix = f"/orders/{ORDER['order_id']}/"
        if call.method == "POST" and call.path.startswith(prefix):
            proposal = PROPOSALS.get(call.path.removeprefix(prefix))
            if proposal is None:
                return ApiResult.not_found()
            if call.account_id is None:
                return ApiResult.sign_in_required("orders:write")
            if "orders:write" not in call.scopes:
                return ApiResult.insufficient_scope("orders:write")
            return ApiResult(operation=proposal)
        return ApiResult.not_found()


EXCHANGE = ProposedOperation(
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
)

#: What each consequential API path proposes (Operations §4.1).
PROPOSALS = {
    "exchanges": EXCHANGE,
    "gift-wrap": ProposedOperation(
        action="orders.gift_wrap",
        summary="Gift-wrap order ord_7Hk2 before it ships again, USD 5.00.",
        terms={"order_id": "ord_7Hk2", "price": {"amount": "5.00", "currency": "USD"}},
    ),
    "returns": ProposedOperation(
        action="orders.return",
        summary="Return the Ridge Jacket (M) from order ord_7Hk2 for a refund of USD 180.00.",
        terms={"order_id": "ord_7Hk2", "refund": {"amount": "180.00", "currency": "USD"}},
        user_approval_required=True,
    ),
    "repairs": ProposedOperation(
        action="orders.repair",
        summary="Send the Ridge Jacket (M) from order ord_7Hk2 for a zip repair, free.",
        terms={"order_id": "ord_7Hk2", "price": {"amount": "0.00", "currency": "USD"}},
        user_approval_required=True,
    ),
}


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


class GiftWrapExecutor:
    action = "orders.gift_wrap"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        self.performed.append(operation.operation_id)
        return OperationResult(
            summary="Order ord_7Hk2 will be gift-wrapped. USD 5.00 charged to the card ending 4242."
        )


class ReturnExecutor:
    """A return that fails partway: the label exists, the refund did not go through."""

    action = "orders.return"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        self.performed.append(operation.operation_id)
        raise OperationFailed(
            OperationResult(
                summary=(
                    "A return label for the Ridge Jacket (M) was emailed, but the refund of "
                    "USD 180.00 could not be issued; no money moved."
                ),
                data={"return_label": "rtn_8Lp3", "refunded": None},
            )
        )


class RepairExecutor:
    """A repair booked with a carrier that never answers: the outcome is unknown."""

    action = "orders.repair"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        self.performed.append(operation.operation_id)
        raise OperationOutcomeUnknown("the carrier did not answer")


class ManzanitaMcp:
    """Manzanita's MCP server: the same orders and exchange, as tools (§6, Operations §4.2)."""

    description = "Orders and exchanges, as MCP tools"

    def tools(self) -> list[dict[str, object]]:
        return [
            {
                "name": "list_orders",
                "description": "Your orders (orders:read).",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "exchange_jacket",
                "description": "Propose the insulated jacket in exchange (orders:write).",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    async def call(self, name: str, arguments: dict[str, object], call: ApiCall) -> ToolResult:
        if name == "list_orders":
            if call.account_id is None:
                return ToolResult.sign_in_required("orders:read")
            if "orders:read" not in call.scopes:
                return ToolResult.insufficient_scope("orders:read")
            return ToolResult(
                text="Order ord_7Hk2: Ridge Jacket, size M, delivered.",
                structured={"orders": [ORDER]},
            )
        if name == "exchange_jacket":
            if call.account_id is None:
                return ToolResult.sign_in_required("orders:write")
            if "orders:write" not in call.scopes:
                return ToolResult.insufficient_scope("orders:write")
            return ToolResult(operation=EXCHANGE)
        return ToolResult(text=f"Unknown tool {name}.", is_error=True)


class ManzanitaPlugin:
    def __init__(self) -> None:
        self.executor = ExchangeExecutor()
        self.gift_wrap = GiftWrapExecutor()
        self.returns = ReturnExecutor()
        self.repairs = RepairExecutor()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(COMPANY_ACCOUNTS, ManzanitaAccounts(), contribution_id="accounts")
        contribute(COMPANY_AGENTS, ManzanitaAgent(), contribution_id="agent")
        contribute(OPERATION_EXECUTORS, self.executor, contribution_id="exchange")
        contribute(OPERATION_EXECUTORS, self.gift_wrap, contribution_id="gift-wrap")
        contribute(OPERATION_EXECUTORS, self.returns, contribution_id="returns")
        contribute(OPERATION_EXECUTORS, self.repairs, contribution_id="repairs")
        contribute(COMPANY_APIS, ManzanitaApi(), contribution_id="api")
        contribute(COMPANY_MCP, ManzanitaMcp(), contribution_id="mcp")


def manzanita(
    network: InProcessNetwork, clock: MutableClock, *, store: CompanyStore | None = None
) -> tuple[CompanyService, ManzanitaPlugin]:
    """Build Manzanita and put it on the network at `manzanita.example`.

    With `store`, Manzanita keeps its state there: building it again over the
    same store is Manzanita restarted (or another replica of it).
    """

    plugin = ManzanitaPlugin()
    plugins: list[tuple[PluginManifest, object]] = [
        (PluginManifest(name="manzanita", version="1"), plugin),
        (PluginManifest(name="manzanita-clock", version="1"), ClockPlugin(clock)),
    ]
    if store is not None:
        plugins.append((PluginManifest(name="manzanita-store", version="1"), StorePlugin(store)))
    service = build_company(
        CONFIG,
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=plugins,
    )
    network.add(DOMAIN, company_app(service))
    return service, plugin
