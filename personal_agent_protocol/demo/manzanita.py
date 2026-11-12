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
  (`authorization` until then) and returns the exchange as an operation.
- `ExchangeExecutor` (`pap.company.operationExecutor`): performs the
  exchange, once. Gift wrap, a return that fails partway, and a repair whose
  carrier never answers show the other ends of an operation.
"""

from __future__ import annotations

import hmac
from collections.abc import Sequence
from typing import Any

from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from ..company import (
    COMPANY_ACCOUNTS,
    COMPANY_AGENTS,
    COMPANY_APIS,
    COMPANY_MCP,
    OPERATION_EXECUTORS,
    ActionResult,
    ApiCall,
    ApiResult,
    Authenticated,
    CompanyConfig,
    CompanyService,
    CompanyStore,
    Decline,
    DeclineRequest,
    OperationFailed,
    OperationOutcomeUnknown,
    ProposedOperation,
    Reply,
    SignInContext,
    ToolResult,
    Turn,
    build_company,
    company_app,
)
from ..models import Link, Operation
from .kit import ClockPlugin, InProcessNetwork, MutableClock, StorePlugin

DOMAIN = "manzanita.example"
ADA = {"email": "ada@example.com", "password": "correct horse battery staple"}
ADA_CODE = "246810"
ORDER = {"order_id": "ord_7Hk2", "item": "Ridge Jacket, size M", "status": "delivered"}
#: The page an order reply refers to, sent as a link to an agent that lists Links (Links 3).
TRACKING_LINK = Link(
    url=f"https://{DOMAIN}/orders/ord_7Hk2/tracking", title="Tracking for order ord_7Hk2"
)
#: The notice an exchange reply carries, as a disclosure to an agent that lists Disclosures,
#: in `text` to any other (Disclosures 2, 3).
EXCHANGE_NOTICE = "Exchanged items ship once the original jacket is received."
#: The `reason` of the `user_requested` event Manzanita adds for a damaged jacket (§8.10).
INVITATION = "A returns specialist would like to talk with you about the damaged jacket."
#: Manzanita's first message in the Direct Conversation the user accepted (§8.10).
OPENING = "Hi, this is Rosa from Manzanita returns. Tell me what happened with the jacket."
#: Replies that say only yes (guides, *Explicit replies and approvals*): one could answer
#: sign-in, an earlier question or a request for approval, so a company agent treats it as
#: answering none of them and asks which is meant, acting on nothing.
ACKNOWLEDGEMENTS = frozenset(
    {"yes", "ok", "okay", "done", "sure", "fine", "go ahead", "approved", "confirmed", "agreed"}
)
#: What the demo company agents answer such a reply with.
WHICH_ONE = "Which do you mean? Say what you are answering, and I will go on from there."


def acknowledgement_only(text: str | None) -> bool:
    """Whether `text` is a bare acknowledgement, which could answer more than one question."""

    return (text or "").strip().rstrip(".!").lower() in ACKNOWLEDGEMENTS


#: The jackets Manzanita's UCP catalog search answers from.
UCP_PRODUCTS: tuple[dict[str, Any], ...] = (
    {
        "id": "stormline-insulated-m",
        "title": "Stormline insulated jacket, M",
        "price": {"amount": 12900, "currency": "USD"},
    },
    {
        "id": "stormline-insulated-l",
        "title": "Stormline insulated jacket, L",
        "price": {"amount": 12900, "currency": "USD"},
    },
    {
        "id": "trailhead-shell-m",
        "title": "Trailhead shell jacket, M",
        "price": {"amount": 8900, "currency": "USD"},
    },
)


def decline_agent_returns(request: DeclineRequest) -> Decline | None:
    """Manzanita's own rule (Operations 6): a return is refunded only on the person's own
    approval. An approval a personal agent gave on an instruction is declined, with a way
    on; the same revision approved by the person is acted on."""

    if request.action == "orders.return" and request.approval.approver == "agent":
        return Decline(
            reason="A return is refunded only when you approve it yourself.",
            alternative={
                "instructions": "Approve the return when your personal agent asks you.",
                "references": [{"type": "web", "url": "https://manzanita.example/returns"}],
            },
        )
    return None


CONFIG = CompanyConfig(
    name="Manzanita Outfitters",
    domain=DOMAIN,
    scopes=("orders:read", "orders:write"),
    write_scopes=("orders:write",),
    mediated_fields=(("email", "Email", False), ("password", "Password", True)),
    links=True,
    disclosures=True,
    scope_descriptions={
        "orders:read": "See your orders, returns and exchanges",
        "orders:write": "Exchange or return items in your orders",
    },
    scope_hints={"orders:read": ("none", True), "orders:write": ("reversible", True)},
    excluded_tasks=({"task": "Change the size of an item after it has shipped"},),
    decline=decline_agent_returns,
    feedback_answers={
        "Pay with a gift card": {
            "instructions": "Gift cards are applied on the checkout page, before paying.",
            "references": [{"type": "web", "url": "https://manzanita.example/checkout"}],
        }
    },
    web=True,
    # The UCP test shop (the UCP extension, version 1): its catalog, searched through UCP.
    ucp=True,
    ucp_products=UCP_PRODUCTS,
)


class ManzanitaAccounts:
    """Ada's account: her password, then a code sent to her email."""

    async def authenticate(
        self, credentials: dict[str, SecretStr], context: SignInContext
    ) -> Authenticated | None:
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
        if turn.opening:
            # The user accepted the invitation: the company speaks first (§8.10).
            return [Reply(text=OPENING, persona={"id": "rosa", "name": "Rosa"})]
        if acknowledgement_only(turn.text):
            # A reply that could answer more than one open question answers none (guides).
            return [Reply(text=WHICH_ONE)]
        if turn.account_id is not None and "damaged" in text:
            # A person would like to talk with the user: an invitation, not a message.
            return [
                Reply(text="I'm sorry about that. A returns specialist would like a word."),
                Reply(user_requested=INVITATION),
            ]
        if turn.account_id is None:
            if "order" in text or "jacket" in text or "exchange" in text:
                return [
                    Reply(text="I can look that up once you sign in to your Manzanita account."),
                    Reply(authorization=("insufficient_scope", "orders:read orders:write")),
                ]
            return [Reply(text="Hello from Manzanita Outfitters. Ask me about an order.")]
        if "exchange" in text or "warmer" in text:
            if "orders:write" not in turn.scopes:
                return [Reply(authorization=("insufficient_scope", "orders:write"))]
            if not turn.supports_operations:
                # No operation can reach this agent: say so, never "here is the exchange".
                return [
                    Reply(
                        text="The insulated Ridge Jacket is in stock. Your agent cannot "
                        "approve exchanges with us: exchange it on manzanita.example."
                    )
                ]
            return [
                Reply(
                    text="The insulated Ridge Jacket is in stock. Here is the exchange.",
                    operation=EXCHANGE,
                    disclosures=(EXCHANGE_NOTICE,),
                )
            ]
        if "orders:read" not in turn.scopes:
            # Signed in, but not allowed to read orders: ask for the scope, say nothing.
            return [Reply(authorization=("insufficient_scope", "orders:read"))]
        return [
            Reply(
                text="Your order ord_7Hk2: Ridge Jacket, size M, delivered.",
                data=ORDER,
                links=(TRACKING_LINK,),
            )
        ]


class ManzanitaApi:
    """Manzanita's OpenAPI API: orders, and exchanges that need the user's approval."""

    description = "Orders and exchanges"

    def openapi(self) -> dict[str, object]:
        return {
            "openapi": "3.1.0",
            "info": {"title": "Manzanita Outfitters", "version": "1"},
            "paths": {
                "/api/orders": {"get": {"summary": "Your orders (orders:read)"}},
                "/api/orders/{order_id}/exchanges": {
                    "post": {"summary": "An exchange (orders:write): 403 approval_required"}
                },
                "/api/orders/{order_id}/gift-wrap": {
                    "post": {"summary": "Gift wrap (orders:write): 403 approval_required"}
                },
                "/api/orders/{order_id}/returns": {
                    "post": {"summary": "A return (orders:write): 403 approval_required"}
                },
                "/api/orders/{order_id}/repairs": {
                    "post": {"summary": "A repair (orders:write): 403 approval_required"}
                },
            },
        }

    async def handle(self, call: ApiCall) -> ApiResult:
        if call.method == "GET" and call.path == "/orders":
            if call.account_id is None:
                return ApiResult.insufficient_scope("orders:read")
            if "orders:read" not in call.scopes:
                return ApiResult.insufficient_scope("orders:read")
            return ApiResult(body={"orders": [ORDER]})
        prefix = f"/orders/{ORDER['order_id']}/"
        if call.method == "POST" and call.path.startswith(prefix):
            proposal = PROPOSALS.get(call.path.removeprefix(prefix))
            if proposal is None:
                return ApiResult.not_found()
            if call.account_id is None:
                return ApiResult.insufficient_scope("orders:write")
            if "orders:write" not in call.scopes:
                return ApiResult.insufficient_scope("orders:write")
            return ApiResult(operation=proposal)
        return ApiResult.not_found()


EXCHANGE = ProposedOperation(
    action="orders.exchange",
    subject="ord_7Hk2",
    summary=(
        "Exchange the Ridge Jacket (M) from order ord_7Hk2 for the "
        "insulated Ridge Jacket (M), USD 70.00 more."
    ),
    terms={
        "order_id": "ord_7Hk2",
        "price_difference": {"amount": "70.00", "currency": "USD"},
    },
)

#: What each consequential API path needs the user's approval of (Operations 4).
PROPOSALS = {
    "exchanges": EXCHANGE,
    "gift-wrap": ProposedOperation(
        action="orders.gift_wrap",
        subject="ord_7Hk2",
        summary="Gift-wrap order ord_7Hk2 before it ships again, USD 5.00.",
        terms={"order_id": "ord_7Hk2", "price": {"amount": "5.00", "currency": "USD"}},
    ),
    "returns": ProposedOperation(
        action="orders.return",
        subject="ord_7Hk2",
        summary="Return the Ridge Jacket (M) from order ord_7Hk2 for a refund of USD 180.00.",
        terms={"order_id": "ord_7Hk2", "refund": {"amount": "180.00", "currency": "USD"}},
    ),
    "repairs": ProposedOperation(
        action="orders.repair",
        subject="ord_7Hk2",
        summary="Send the Ridge Jacket (M) from order ord_7Hk2 for a zip repair, free.",
        terms={"order_id": "ord_7Hk2", "price": {"amount": "0.00", "currency": "USD"}},
    ),
}


class ExchangeExecutor:
    """Perform an exchange once: the operation ID is the downstream idempotency key."""

    action = "orders.exchange"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
        self.performed.append(operation.operation_id)
        terms = operation.terms or {}
        difference = terms.get("price_difference") or {}
        amount = f"{difference.get('currency', 'USD')} {difference.get('amount', '0.00')}"
        return ActionResult(
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

    async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
        self.performed.append(operation.operation_id)
        return ActionResult(
            summary="Order ord_7Hk2 will be gift-wrapped. USD 5.00 charged to the card ending 4242."
        )


class ReturnExecutor:
    """A return that fails partway: the label exists, the refund did not go through."""

    action = "orders.return"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
        self.performed.append(operation.operation_id)
        raise OperationFailed(
            ActionResult(
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

    async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
        self.performed.append(operation.operation_id)
        raise OperationOutcomeUnknown("the carrier did not answer")


class ManzanitaMcp:
    """Manzanita's MCP server: the same orders and exchange, as tools (§7, Operations 4)."""

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
                "description": "Exchange for the insulated jacket (orders:write).",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]

    async def call(self, name: str, arguments: dict[str, object], call: ApiCall) -> ToolResult:
        if name == "list_orders":
            if call.account_id is None:
                return ToolResult.insufficient_scope("orders:read")
            if "orders:read" not in call.scopes:
                return ToolResult.insufficient_scope("orders:read")
            return ToolResult(
                text="Order ord_7Hk2: Ridge Jacket, size M, delivered.",
                structured={"orders": [ORDER]},
            )
        if name == "exchange_jacket":
            if call.account_id is None:
                return ToolResult.insufficient_scope("orders:write")
            if "orders:write" not in call.scopes:
                return ToolResult.insufficient_scope("orders:write")
            return ToolResult(operation=EXCHANGE)
        return ToolResult(text=f"Unknown tool {name}.", is_error=True)


class ManzanitaPlugin:
    def __init__(self) -> None:
        self.accounts = ManzanitaAccounts()
        self.executor = ExchangeExecutor()
        self.gift_wrap = GiftWrapExecutor()
        self.returns = ReturnExecutor()
        self.repairs = RepairExecutor()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(COMPANY_ACCOUNTS, self.accounts, contribution_id="accounts")
        contribute(COMPANY_AGENTS, ManzanitaAgent(), contribution_id="agent")
        contribute(OPERATION_EXECUTORS, self.executor, contribution_id="exchange")
        contribute(OPERATION_EXECUTORS, self.gift_wrap, contribution_id="gift-wrap")
        contribute(OPERATION_EXECUTORS, self.returns, contribution_id="returns")
        contribute(OPERATION_EXECUTORS, self.repairs, contribution_id="repairs")
        contribute(COMPANY_APIS, ManzanitaApi(), contribution_id="api")
        contribute(COMPANY_MCP, ManzanitaMcp(), contribution_id="mcp")


def manzanita(
    network: InProcessNetwork,
    clock: MutableClock,
    *,
    store: CompanyStore | None = None,
    config: CompanyConfig | None = None,
) -> tuple[CompanyService, ManzanitaPlugin]:
    """Build Manzanita and put it on the network at `manzanita.example`.

    With `store`, Manzanita keeps its state there: building it again over the
    same store is Manzanita restarted (or another replica of it). `config`
    replaces `CONFIG`, for a test that changes one of its settings.
    """

    plugin = ManzanitaPlugin()
    plugins: list[tuple[PluginManifest, object]] = [
        (PluginManifest(name="manzanita", version="1"), plugin),
        (PluginManifest(name="manzanita-clock", version="1"), ClockPlugin(clock)),
    ]
    if store is not None:
        plugins.append((PluginManifest(name="manzanita-store", version="1"), StorePlugin(store)))
    service = build_company(
        CONFIG if config is None else config,
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=plugins,
    )
    network.add(DOMAIN, company_app(service))
    return service, plugin
