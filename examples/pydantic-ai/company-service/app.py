# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent building a PAP company with the SDK, then using it as Ada.

Juniper Library is a fictional company built here from `personal_agent_protocol.company`:
a `CompanyConfig`, a company store that passes `check_store`, a company agent that
proposes renewing a loan, and the operation executor that performs it. The service
is served over ASGI with `company_app` on an in-process network, and Atlas, Ada's
personal agent from the same SDK, talks to it end to end: discovery, a signed-out
Session, a conversation that asks her to sign in, Device Sign-In on the library's
page, the renewal proposed, Ada's approval of that exact revision, and the renewal
performed once however often the confirmation is sent.

The tool hands the model the steps, the library's summaries, and counts; no token,
code, or proof enters it.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Sequence
from typing import Any

from pydantic_ai import Agent
from reactor import PluginManifest

from personal_agent_protocol import (
    ClientMetadata,
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    generate_message_id,
)
from personal_agent_protocol.company import (
    COMPANY_AGENTS,
    COMPANY_STORES,
    OPERATION_EXECUTORS,
    CompanyConfig,
    MemoryCompanyStore,
    ProposedOperation,
    Reply,
    Turn,
    build_company,
    company_app,
)
from personal_agent_protocol.company.testing import check_store
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    ClockPlugin,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.models import Operation, OperationResult
from personal_agent_protocol.operations import OperationsClient, approve, operations_endpoint

DOMAIN = "juniper.example"
TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_juniper_00000000"
LOAN = {"loan_id": "loan_31", "title": "The Left Hand of Darkness", "due": "2026-10-20"}

CONFIG = CompanyConfig(
    name="Juniper Library",
    domain=DOMAIN,
    scopes=("loans:read", "loans:write"),
    write_scopes=("loans:write",),
    custom_scopes={"loans:read": "See your loans", "loans:write": "Renew your loans"},
)

RENEWAL = ProposedOperation(
    action="loans.renew",
    summary="Renew 'The Left Hand of Darkness' (loan_31) for three weeks, until 2026-11-10.",
    terms={"loan_id": "loan_31", "due": "2026-11-10"},
    user_approval_required=True,
)


class JuniperAgent:
    """The library's company agent (`pap.company.agent`): a few rules."""

    async def respond(self, turn: Turn) -> Sequence[Reply]:
        if turn.account_id is None:
            return [
                Reply(text="I can look at your loans once you sign in to Juniper Library."),
                Reply(authorization=("sign_in_required", "loans:read loans:write")),
            ]
        if "renew" in (turn.text or "").lower():
            return [Reply(text="That loan can be renewed once more.", operation=RENEWAL)]
        return [Reply(text="You have one loan, due 2026-10-20.", data=LOAN)]


class RenewExecutor:
    """Perform a renewal (`pap.company.operationExecutor`); the operation ID is its key."""

    action = "loans.renew"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str) -> OperationResult:
        self.performed.append(operation.operation_id)
        due = (operation.terms or {}).get("due")
        return OperationResult(summary=f"Renewed until {due}.", data={"due": due})


class JuniperPlugin:
    """The library's own parts, contributed ahead of the defaults."""

    def __init__(self, store: MemoryCompanyStore) -> None:
        self.store = store
        self.executor = RenewExecutor()

    def provide_contributions(self, contributions: Any) -> None:
        contribute = contributions.contribute
        contribute(COMPANY_STORES, self.store, contribution_id="juniper-store", order=0)
        contribute(COMPANY_AGENTS, JuniperAgent(), contribution_id="agent")
        contribute(OPERATION_EXECUTORS, self.executor, contribution_id="renew")


agent = Agent(
    instructions=(
        "Use run_company_service to show how a company is built with the PAP SDK and "
        "how a personal agent uses it. Say what Ada approved and what the library did. "
        "Never expose tokens, codes, or proofs."
    ),
)


@agent.tool_plain
async def run_company_service() -> dict[str, Any]:
    """Build Juniper Library, serve it, and run Ada's renewal through it; return safe evidence."""

    steps: list[str] = []
    clock = MutableClock()
    network = InProcessNetwork()

    # The store: the company's async keyed store. A database store runs the same kit.
    await check_store(lambda: MemoryCompanyStore(clock), now=clock.now)
    steps.append("the store passed check_store")

    # The company: config, store, agent, executor; served over ASGI on its own origin.
    plugin = JuniperPlugin(MemoryCompanyStore(clock))
    library = build_company(
        CONFIG,
        http_client=network.client(),
        address_resolver=network.resolve,
        plugins=[
            (PluginManifest(name="juniper", version="1"), plugin),
            (PluginManifest(name="juniper-clock", version="1"), ClockPlugin(clock)),
        ],
    )
    network.add(DOMAIN, company_app(library))
    steps.append("Juniper Library served over ASGI at https://juniper.example")

    # The personal agent, from the same SDK.
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    transport = DpopHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)

    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    if not (metadata is not None and metadata.device_authorization_endpoint is not None):
        raise RuntimeError("the example world is incomplete")
    steps.append(f"discovered {company.document.organization.name}")
    who = {"tenant_id": TENANT, "pairwise_user_id": PAIRWISE, "issuer": metadata.issuer}
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        token_endpoint=metadata.token_endpoint,
        tenant_id=TENANT,
    )
    steps.append("started a signed-out Session")
    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    def say(text: str) -> Message:
        return Message(id=generate_message_id(reactor), sender="human", text=text)

    page = await conversations.start(
        endpoint, say("When is my book due?"), token=session, wait=0, **who
    )
    asked = page.events[-1]
    steps.append(f"the library asked to sign in ({asked.type}: {asked.error})")

    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("loans:read", "loans:write"),
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
        session_id=session.session_id,
    )
    await library.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    signed_in = (await device.poll(started.reference)).token
    if signed_in is None:
        raise RuntimeError("the example world is incomplete")
    steps.append("Ada approved the sign-in on the library's page; the same Session is signed in")

    page = await conversations.send(
        endpoint,
        page.conversation_id,
        say("Please renew it"),
        token=signed_in,
        cursor=page.cursor,
        wait=0,
        **who,
    )
    proposal = page.events[-1].message.operation  # type: ignore[union-attr]
    ops = operations_endpoint(company.document, ClientMetadata.model_validate(atlas.metadata))
    if proposal is None or ops is None:
        raise RuntimeError("the example world is incomplete")
    steps.append(f"the library proposed revision {proposal.revision}: {proposal.summary}")

    operations = OperationsClient(transport=transport)
    approval = approve(proposal)
    confirmed = await operations.confirm(ops, proposal, approval=approval, token=signed_in, **who)
    again = await operations.confirm(ops, proposal, approval=approval, token=signed_in, **who)
    record = confirmed.operation
    if record is None or again.operation is None:
        raise RuntimeError("the example world is incomplete")
    steps.append("Ada approved that exact revision; the confirmation was sent twice")
    await http.aclose()

    return {
        "steps": steps,
        "advertised_scopes": company.document.auth.custom_scopes,
        "proposal": {
            "summary": proposal.summary,
            "revision": proposal.revision,
            "user_approval_required": proposal.user_approval_required,
        },
        "confirmed": record.state,
        "result": record.result.summary if record.result else None,
        "second_confirmation": again.operation.state,
        "same_operation": again.operation.operation_id == record.operation_id,
        "times_performed": len(plugin.executor.performed),
        "tokens_codes_and_proofs_withheld": True,
    }


async def main() -> None:
    """Ask the agent to explain the company and the journey."""

    result = await agent.run(
        "How is Juniper Library built with the PAP SDK, and how did Ada renew her book?",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
