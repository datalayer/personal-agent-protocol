# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent demonstrating PAP Mediated Sign-In with protected input."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import AuthorizationError, DiscoveryClient, SessionClient
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    ScriptedInput,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import ADA, ADA_CODE, manzanita
from personal_agent_protocol.mediated import MediatedSignInClient

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"

agent = Agent(
    instructions=(
        "Use explain_mediated_sign_in to explain PAP Mediated Sign-In. Never ask the "
        "user for a password or one-time code in chat: the host's own protected input "
        "collects them. Never expose credentials, codes, or tokens."
    ),
)


@agent.tool_plain
async def explain_mediated_sign_in() -> dict[str, Any]:
    """Sign a Session in through Manzanita's mediated endpoint; return safe evidence."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    manzanita(network, clock)
    http = network.client()
    # The host's trusted input surface (`pap.protectedInput`). In a real host the user
    # types into it; here a script answers: her credentials, a wrong code, the right one.
    typed = ScriptedInput(dict(ADA), {"code": "000000"}, {"code": ADA_CODE})
    host = PersonalAgentHost(atlas, clock, protected_input=typed)
    reactor = personal_agent_reactor(host, network=network, http_client=http)

    company = await DiscoveryClient(reactor=reactor, http_client=http).discover("manzanita.example")
    auth = company.document.auth
    if not (auth is not None and auth.mediated is not None and company.oauth_metadata):
        raise RuntimeError("the example world is incomplete")
    who = {"tenant_id": TENANT, "pairwise_user_id": PAIRWISE, "issuer": auth.issuer}
    sessions = SessionClient(reactor=reactor, http_client=http)

    async def signed_out_session():  # type: ignore[no-untyped-def]
        return await sessions.start(
            client_id=atlas.client_id,
            pairwise_user_id=PAIRWISE,
            issuer=auth.issuer,
            token_endpoint=company.oauth_metadata.token_endpoint,  # type: ignore[union-attr]
            tenant_id=TENANT,
        )

    session = await signed_out_session()
    mediated = MediatedSignInClient(reactor=reactor, http_client=http)

    # An endpoint off the company's domain is refused before the user is asked anything.
    off_domain = auth.mediated.model_copy(
        update={"endpoint": "https://collector.attacker.example/sign-in"}
    )
    try:
        await mediated.sign_in(
            mediated=off_domain,
            organization=company.document.organization,
            issuer=auth.issuer,
            scopes=("orders:read",),
            token=session,
            tenant_id=TENANT,
            pairwise_user_id=PAIRWISE,
        )
        off_domain_refused = "not refused"
    except AuthorizationError as error:
        off_domain_refused = error.code
    asked_before_refusal = len(typed.asked)

    # The declared fields, collected by the host, sent once to the mediated endpoint.
    started = await mediated.sign_in(
        mediated=auth.mediated,
        organization=company.document.organization,
        issuer=auth.issuer,
        scopes=("orders:read", "orders:write"),
        token=session,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )
    if not (started.reference is not None):
        raise RuntimeError("the example world is incomplete")

    # Only the Session that started the sign-in may finish it.
    stranger = await signed_out_session()
    try:
        await mediated.submit_code(started.reference, token=stranger, **who)
        other_session = "accepted"
    except AuthorizationError as error:
        other_session = error.code

    wrong = await mediated.submit_code(started.reference, token=session, **who)
    done = await mediated.submit_code(started.reference, token=session, **who)
    await http.aclose()

    return {
        "off_domain_endpoint": off_domain_refused,
        "user_asked_before_off_domain_refusal": asked_before_refusal,
        "fields_asked_for": [field.label for field in typed.asked[0].fields],
        "secret_fields": [field.name for field in typed.asked[0].fields if field.secret],
        "asked_on_behalf_of": typed.asked[0].company_domain,
        "first_answer": started.status,
        "code_sent_to": started.sent_to,
        "other_session_finishing": other_session,
        "wrong_code": wrong.status,
        "same_reference_after_wrong_code": wrong.reference == started.reference,
        "final_status": done.status,
        "same_session_signed_in": done.token is not None
        and done.token.signed_in
        and done.token.session_id == session.session_id,
        "granted_scopes": done.granted_scopes,
        "account_token_stored_by_reference": done.account_token_reference in host.vault.values,
        "protected_input_purposes": [request.purpose for request in typed.asked],
        "credentials_and_codes_withheld": True,
        "tokens_withheld": True,
    }


async def main() -> None:
    result = await agent.run(
        "Explain how a personal agent signs a user in when the company offers only "
        "Mediated Sign-In, and how the password and one-time code stay out of the chat.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
