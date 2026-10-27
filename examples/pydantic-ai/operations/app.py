# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent demonstrating the PAP Operations extension (version 1)."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import timedelta
from decimal import Decimal
from typing import Any

import httpx
from pydantic_ai import Agent

from personal_agent_protocol import (
    Author,
    ClientMetadata,
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    OAuthServerMetadata,
    Operation,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.northwind import ACCOUNT, DOMAIN, northwind
from personal_agent_protocol.operations import (
    ConfirmOutcome,
    OperationError,
    OperationsClient,
    StandingPermission,
    TermLimit,
    approve,
    operations_endpoint,
)

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_northwind_00000"
STANDING = ("Northwind Bank", PAIRWISE, "payments.transfer")


class LostAnswer(httpx.AsyncBaseTransport):
    """The network between Atlas and Northwind: one confirmation's answer is lost.

    When armed, the next `confirm` reaches the bank (which performs it) and the
    answer never comes back. Every other request passes through unchanged.
    """

    def __init__(self, inner: httpx.AsyncClient) -> None:
        self.inner = inner
        self.armed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        response = await self.inner.send(request)
        if self.armed and request.method == "POST" and request.url.path.endswith("/confirm"):
            self.armed = False
            raise httpx.ReadTimeout("the answer was lost", request=request)
        return httpx.Response(
            response.status_code, headers=response.headers, content=response.content
        )


def recorded(outcome: ConfirmOutcome) -> Operation:
    """The operation record a confirmation answered with."""

    if outcome.operation is None:
        raise RuntimeError("the confirmation carried no operation")
    return outcome.operation


async def without_the_extension(
    network: InProcessNetwork,
    clock: MutableClock,
    plain: AgentIdentity,
    metadata: OAuthServerMetadata,
    endpoint: str,
    operation: Operation,
) -> str:
    """What the bank tells an agent whose metadata does not list Operations v1."""

    async with network.client() as http:
        reactor = personal_agent_reactor(
            PersonalAgentHost(plain, clock), network=network, http_client=http
        )
        session = await SessionClient(reactor=reactor, http_client=http).start(
            client_id=plain.client_id,
            pairwise_user_id=PAIRWISE,
            issuer=metadata.issuer,
            token_endpoint=metadata.token_endpoint,
            tenant_id=TENANT,
        )
        try:
            await OperationsClient(
                transport=DpopHttpClient(reactor=reactor, http_client=http)
            ).read(
                endpoint,
                operation.operation_id,
                token=session,
                tenant_id=TENANT,
                issuer=metadata.issuer,
            )
        except OperationError as error:
            return error.code
    return "answered"


agent = Agent(
    instructions=(
        "Use explain_operations to explain PAP Operations. A chat message is never "
        "approval: only the user's approval of an exact revision, or a standing "
        "permission they granted, confirms an operation. Never expose tokens or proofs."
    ),
)


@agent.tool_plain
async def explain_operations() -> dict[str, Any]:  # noqa: C901 - one walkthrough, in order
    """Propose, approve, revise, recover, and pre-authorize payments; return safe evidence."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    plain = AgentIdentity(domain="plain.example", name="Plain", extensions=())
    for identity in (atlas, plain):
        network.add(identity.domain, identity.website())
    bank, bank_plugin = northwind(network, clock)
    wire = LostAnswer(network.client())
    http = httpx.AsyncClient(transport=wire)
    host = PersonalAgentHost(atlas, clock)
    reactor = personal_agent_reactor(host, network=network, http_client=http)
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    if not (metadata is not None and metadata.device_authorization_endpoint is not None):
        raise RuntimeError("the example world is incomplete")
    who = {"tenant_id": TENANT, "issuer": metadata.issuer}

    # Ada signs Atlas in at Northwind (Device Sign-In on the bank's own page).
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=TENANT,
    )
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("accounts:read", "payments:write"),
        tenant_id=TENANT,
        session_key=session.session_key,
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await bank.approve_device(started.user_code, account_id=ACCOUNT)
    clock.advance(started.poll_interval)
    token = (await device.poll(started.reference)).token
    if not (token is not None):
        raise RuntimeError("the example world is incomplete")

    # Negotiation: both the bank's poppy.json and the agent's metadata list version 1.
    endpoint = operations_endpoint(company.document, ClientMetadata.model_validate(atlas.metadata))
    without = operations_endpoint(company.document, ClientMetadata.model_validate(plain.metadata))
    if not (endpoint is not None):
        raise RuntimeError("the example world is incomplete")
    transport = DpopHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)
    operations = OperationsClient(transport=transport)
    chat = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    async def propose(text: str) -> Operation:
        page = await conversations.start(
            chat,
            Message(id=generate_message_id(reactor), author=Author(type="agent"), text=text),
            token=token,
            wait=0,
            **who,
        )
        proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
        if not (proposal is not None):
            raise RuntimeError("the example world is incomplete")
        return proposal

    async def refused(**confirm: Any) -> str:
        try:
            await operations.confirm(endpoint, token=token, **confirm, **who)
        except OperationError as error:
            return error.code
        return "confirmed"

    # 1. A proposal; no standing permission covers it, so the user is asked.
    first = await propose("Pay INV-0042: EUR 1250.00 to Acme GmbH")
    unapproved = await refused(operation=first, standing=STANDING)

    # 2. Ada approves revision 1; the bank revises the terms before the confirm lands.
    approval = approve(first)
    await bank.revise(
        first.operation_id,
        summary=first.summary.replace("1250.00", "1262.50") + " Includes a EUR 12.50 fee.",
        terms={**(first.terms or {}), "amount": {"amount": "1262.50", "currency": "EUR"}},
    )
    changed = await operations.confirm(endpoint, first, approval=approval, token=token, **who)
    revised = changed.operation
    if not (revised is not None):
        raise RuntimeError("the example world is incomplete")
    stale_approval = await refused(operation=revised, approval=approval)

    # 3. Ada approves revision 2; the confirm's answer is lost and recovered by reading
    #    the same operation back, never re-proposed or assumed failed.
    wire.armed = True
    recovered = await operations.confirm(
        endpoint, revised, approval=approve(revised), token=token, **who
    )
    retried = await operations.confirm(
        endpoint, revised, approval=approve(revised), token=token, **who
    )
    performed_for_first = len(bank_plugin.executor.performed)

    # 4. A standing permission the user granted in the host: Acme GmbH, at most
    #    EUR 2000.00, one payment, thirty days. Checked term by term, one use reserved.
    host.standing.permissions["perm_acme"] = StandingPermission(
        reference="perm_acme",
        company=STANDING[0],
        account=STANDING[1],
        action=STANDING[2],
        limits=(
            TermLimit("payee", allowed=frozenset({"Acme GmbH"})),
            TermLimit("amount.amount", maximum=Decimal("2000.00")),
            TermLimit("amount.currency", allowed=frozenset({"EUR"})),
        ),
        expires_at=clock.now() + timedelta(days=30),
        uses_remaining=1,
    )
    second = await propose("Pay INV-0043: EUR 980.00 to Acme GmbH")
    within = await operations.confirm(endpoint, second, standing=STANDING, token=token, **who)
    beyond = await propose("Pay INV-0044: EUR 3400.00 to Acme GmbH")
    beyond_bounds = await refused(operation=beyond, standing=STANDING)

    # 5. Cancelling a proposal: nothing is changed.
    cancelled = await operations.cancel(endpoint, beyond.operation_id, token=token, **who)

    # 6. An agent that does not list the extension gets no operations from the bank.
    extension = await without_the_extension(network, clock, plain, metadata, endpoint, beyond)
    for client in (http, wire.inner):
        await client.aclose()

    return {
        "negotiated": endpoint is not None,
        "negotiated_without_the_extension": without is not None,
        "bank_requires_user_approval": first.user_approval_required,
        "standing_confirm_without_permission": unapproved,
        "after_bank_revision": changed.status,
        "new_revision": revised.revision,
        "changed_terms": changed.changed,
        "old_approval_on_new_revision": stale_approval,
        "lost_answer_recovered": recovered.status,
        "state_after_recovery": recorded(recovered).state,
        "retry_is_the_same_record": recorded(retried).state,
        "payments_performed_for_the_first_proposal": performed_for_first,
        "within_standing_permission": within.status,
        "approved_by": recorded(within).model_dump()["confirmation"]["approved_by"],
        "standing_uses_left": host.standing.permissions["perm_acme"].uses_remaining,
        "beyond_standing_permission": beyond_bounds,
        "cancelled": cancelled.state,
        "cancel_result": cancelled.result.summary if cancelled.result else None,
        "result_summary_as_written": recorded(recovered).model_dump()["result"]["summary"],
        "agent_without_extension": extension,
        "tokens_and_proofs_withheld": True,
    }


async def main() -> None:
    result = await agent.run(
        "Explain how a personal agent confirms a company's proposed payment: exact "
        "approval, changed terms, a lost answer, and a standing permission.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
