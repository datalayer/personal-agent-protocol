# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent demonstrating PAP Account Tokens against a real PAP company."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

from pydantic_ai import Agent

from personal_agent_protocol import (
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    DpopHttpClient,
    Message,
    SessionClient,
    SessionToken,
    generate_message_id,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import manzanita

TENANT = "atlas-example"
PAIRWISE = "usr_ada_at_manzanita_000000"

agent = Agent(
    instructions=(
        "Use explain_account_tokens to explain PAP Account Tokens. Never ask for or "
        "expose an Account Token, Session Token, assertion, or DPoP proof."
    ),
)


@agent.tool_plain
async def explain_account_tokens() -> dict[str, Any]:
    """Refresh, rotate, narrow, expire, and revoke Account Tokens; return safe evidence."""

    # Manzanita Outfitters (the reference company) and Atlas (Ada's personal agent),
    # both on an in-process network: real HTTP, real keys, nothing leaves the process.
    clock = MutableClock()
    network = InProcessNetwork()
    atlas = AgentIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    shop, _ = manzanita(network, clock)
    http = network.client()
    host = PersonalAgentHost(atlas, clock)
    reactor = personal_agent_reactor(host, network=network, http_client=http)
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover("manzanita.example")
    metadata = company.oauth_metadata
    if not (metadata is not None and metadata.device_authorization_endpoint is not None):
        raise RuntimeError("the example world is incomplete")
    who = {"tenant_id": TENANT, "pairwise_user_id": PAIRWISE, "issuer": metadata.issuer}
    sessions = SessionClient(reactor=reactor, http_client=http)
    device = DeviceSignInClient(reactor=reactor, http_client=http)

    async def signed_in_session() -> tuple[SessionToken, str]:
        """A signed-out Session, then Device Sign-In Ada approves on Manzanita's page."""

        session = await sessions.start(
            client_id=atlas.client_id,
            pairwise_user_id=PAIRWISE,
            issuer=metadata.issuer,
            token_endpoint=metadata.token_endpoint,
            tenant_id=TENANT,
        )
        started = await device.begin(
            device_authorization_endpoint=metadata.device_authorization_endpoint,  # type: ignore[arg-type]
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=atlas.client_id,
            scopes=("orders:read", "orders:write"),
            tenant_id=TENANT,
            pairwise_user_id=PAIRWISE,
            session_id=session.session_id,
        )
        shop.approve_device(started.user_code, account_id="acct_ada")
        clock.advance(started.poll_interval)
        done = await device.poll(started.reference)
        if not (done.token is not None and done.account_token_reference is not None):
            raise RuntimeError("the example world is incomplete")
        return done.token, done.account_token_reference

    accounts = AccountTokenClient(reactor=reactor, http_client=http)
    context = AccountTokenContext(
        token_endpoint=metadata.token_endpoint,
        revocation_endpoint=metadata.revocation_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        tenant_id=TENANT,
        pairwise_user_id=PAIRWISE,
    )

    # 1. Refresh signs the same Session in again; the company rotates the Account Token.
    token, reference = await signed_in_session()
    stored_before = host.vault.values[reference]
    refreshed = await accounts.refresh(reference, context=context, session_id=token.session_id)
    rotated_in_place = host.vault.values[reference] is not stored_before
    same_session = refreshed.token is not None and refreshed.token.session_id == token.session_id

    # 2. Two refreshes at once: the Reactor `pap.accountTokenLock` serializes them, so the
    #    second presents the token the first rotated in, never the one it revoked.
    racing = await asyncio.gather(
        accounts.refresh(reference, context=context, session_id=token.session_id),
        accounts.refresh(reference, context=context, session_id=token.session_id),
    )

    # 3. Narrower is allowed; wider is the user's decision, not a retry.
    narrowed = await accounts.refresh(
        reference, context=context, session_id=token.session_id, scopes=("orders:read",)
    )
    wider = await accounts.refresh(
        reference,
        context=context,
        session_id=token.session_id,
        scopes=("orders:read", "orders:admin"),
    )

    # 4. Ninety-one days later the company answers `invalid_grant`: the stored copy is
    #    deleted and the Session continues signed out.
    clock.advance(91 * 24 * 3600)
    expired = await accounts.refresh(reference, context=context, session_id=token.session_id)
    expired_deleted = reference not in host.vault.values

    # 5. Revocation (RFC 7009) signs out every Session signed in with the token.
    token, reference = await signed_in_session()
    revoked = await accounts.revoke(reference, context=context)
    conversations = ConversationClient(transport=DpopHttpClient(reactor=reactor, http_client=http))
    endpoint = company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    page = await conversations.start(
        endpoint,
        Message(id=generate_message_id(reactor), sender="human", text="Where is my order?"),
        token=token,
        wait=0,
        **who,
    )
    after_revocation = await accounts.refresh(
        reference, context=context, session_id=token.session_id
    )
    await http.aclose()

    return {
        "refresh_status": refreshed.status,
        "same_session": same_session,
        "rotated": refreshed.rotated,
        "rotated_token_replaced_the_stored_one": rotated_in_place,
        "concurrent_refreshes_serialized": [result.status for result in racing],
        "narrowed_granted_scopes": narrowed.granted_scopes,
        "wider_request": wider.status,
        "expired_token": expired.status,
        "expired_token_deleted_locally": expired_deleted,
        "revoked_at_company": revoked.revoked,
        "revoked_token_deleted_locally": revoked.deleted_locally,
        "session_after_revocation": [event.type for event in page.events][-1]
        + ": "
        + str(page.events[-1].error),
        "refresh_after_revocation": after_revocation.status,
        "account_token_withheld": True,
        "session_tokens_and_proofs_withheld": True,
    }


async def main() -> None:
    result = await agent.run(
        "Explain how a personal agent keeps a user signed in with a PAP Account Token: "
        "refresh, rotation, narrowing, expiry, and revocation.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
