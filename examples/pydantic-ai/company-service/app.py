# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent building a PAP company with the SDK, then using it as Ada.

Juniper Library is a fictional company built here from `personal_agent_protocol.company`:
a `CompanyConfig`, a company store that passes `check_store`, a company agent that
asks approval to renew a loan, and the operation executor that performs it. The service
is served over ASGI with `company_app` on an in-process network, and Atlas, Ada's
personal agent from the same SDK, talks to it end to end: discovery, a signed-out
Session, a conversation answered with `insufficient_scope`, Device Sign-In on the library's
page, the renewal proposed, Ada's approval of that exact revision, and the renewal
performed once however often the approval is sent.

The tool hands the model the steps, the library's summaries, and counts; no token,
code, or Session JWT enters it.
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
    Author,
    ClientMetadata,
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    Message,
    SessionClient,
    SessionHttpClient,
    generate_message_id,
)
from personal_agent_protocol.company import (
    COMPANY_AGENTS,
    COMPANY_STORES,
    OPERATION_EXECUTORS,
    ActionResult,
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
    ScriptedApprovals,
    personal_agent_reactor,
)
from personal_agent_protocol.models import Operation
from personal_agent_protocol.operations import OperationsClient, operations_negotiated

DOMAIN = "juniper.example"
TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_juniper_00000000"
LOAN = {"loan_id": "loan_31", "title": "The Left Hand of Darkness", "due": "2026-10-20"}

CONFIG = CompanyConfig(
    name="Juniper Library",
    domain=DOMAIN,
    scopes=("loans:read", "loans:write"),
    write_scopes=("loans:write",),
    # The library's own scopes, each described in words a user and a model understand
    # (`auth.scopes`), with what its most consequential operation changes and whether it
    # touches personal data (`auth.scope_hints`). Scope names are the company's to choose.
    scope_descriptions={"loans:read": "See your loans", "loans:write": "Renew your loans"},
    scope_hints={"loans:read": ("none", True), "loans:write": ("reversible", True)},
)

RENEWAL = ProposedOperation(
    action="loans.renew",
    summary="Renew 'The Left Hand of Darkness' (loan_31) for three weeks, until 2026-11-10.",
    terms={"loan_id": "loan_31", "due": "2026-11-10"},
    subject="loan_31",
)


class JuniperAgent:
    """The library's company agent (`pap.company.agent`): a few rules."""

    async def respond(self, turn: Turn) -> Sequence[Reply]:
        if turn.account_id is None:
            return [
                Reply(text="I can look at your loans once you sign in to Juniper Library."),
                # An `authorization` event: the scope this request needs, which only a
                # signed-in Session can have.
                Reply(authorization=("insufficient_scope", "loans:read loans:write")),
            ]
        if "renew" in (turn.text or "").lower():
            return [Reply(text="That loan can be renewed once more.", operation=RENEWAL)]
        return [Reply(text="You have one loan, due 2026-10-20.", data=LOAN)]


class RenewExecutor:
    """Perform a renewal (`pap.company.operationExecutor`); the operation ID is its key."""

    action = "loans.renew"

    def __init__(self) -> None:
        self.performed: list[str] = []

    async def perform(self, operation: Operation, account_id: str | None) -> ActionResult:
        self.performed.append(operation.operation_id)
        due = (operation.terms or {}).get("due")
        return ActionResult(summary=f"Renewed until {due}.", data={"due": due})


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
        "Never expose tokens, codes, or Session JWTs."
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
        PersonalAgentHost(atlas, clock, approvals=ScriptedApprovals(always=True)),
        network=network,
        http_client=http,
    )
    transport = SessionHttpClient(reactor=reactor, http_client=http)
    conversations = ConversationClient(transport=transport)

    company = await DiscoveryClient(reactor=reactor, http_client=http).discover(DOMAIN)
    metadata = company.oauth_metadata
    if not (metadata is not None and metadata.device_authorization_endpoint is not None):
        raise RuntimeError("the example world is incomplete")
    steps.append(f"discovered {company.document.organization.name}")
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id=PAIRWISE,
        issuer=metadata.issuer,
        tenant_id=TENANT,
    )
    steps.append("started a signed-out Session, its ID chosen here")
    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]

    def say(text: str) -> Message:
        return Message(id=generate_message_id(reactor), author=Author(type="human"), text=text)

    page = await conversations.start(endpoint, say("When is my book due?"), session=session, wait=0)
    asked = [e for e in page.events if e.type != "state"][-1]
    steps.append(f"the library asked for more scope ({asked.type}: {asked.error} {asked.scope})")

    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=metadata.device_authorization_endpoint,
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("loans:read", "loans:write"),
        tenant_id=TENANT,
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
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
        session=session,
        token=signed_in,
        cursor=page.cursor,
        wait=0,
    )
    proposal = [e for e in page.events if e.type != "state"][-1].message.operation  # type: ignore[union-attr]
    negotiated = operations_negotiated(
        company.document, ClientMetadata.model_validate(atlas.metadata)
    )
    if proposal is None or not negotiated:
        raise RuntimeError("the example world is incomplete")
    steps.append(f"the library asked approval of revision {proposal.revision}: {proposal.summary}")

    approval = await OperationsClient(reactor=reactor).ask_user(
        proposal, organization=company.document.organization, tenant_id=TENANT
    )

    async def send_approval() -> Any:
        return await conversations.send(
            endpoint,
            page.conversation_id,
            Message(
                id=generate_message_id(reactor), author=Author(type="agent"), approval=approval
            ),
            session=session,
            token=signed_in,
            wait=0,
        )

    answered = await send_approval()
    told = [e.message for e in answered.events if e.message and e.message.role == "company"][-1]
    await send_approval()
    steps.append("Ada approved that exact revision; the approval was sent twice")
    await http.aclose()

    return {
        "steps": steps,
        "advertised_scopes": company.document.auth.scopes,
        "scope_hints": {
            name: hint.model_dump(exclude_none=True)
            for name, hint in company.document.auth.scope_hints.items()
        },
        "operation": {"summary": proposal.summary, "revision": proposal.revision},
        "result": told.text,
        "times_performed": len(plugin.executor.performed),
        "tokens_codes_and_session_jwts_withheld": True,
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
