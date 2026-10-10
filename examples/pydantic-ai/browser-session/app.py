# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent that demonstrates a PAP browser-session handoff."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from pydantic import SecretStr
from pydantic_ai import Agent
from reactor import PluginManifest

from personal_agent_protocol import (
    BROWSER_FORM_POSTS,
    CLOCKS,
    SIGNERS,
    BrowserSessionClient,
    BrowserSessionError,
    JoseSigner,
    build_pap_reactor,
    verify_browser_assertion,
)

NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


class ControlledBrowser:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, SecretStr]]] = []

    async def post(self, endpoint: str, fields: dict[str, SecretStr]) -> None:
        self.posts.append((endpoint, fields))


class ReplayCache:
    def __init__(self) -> None:
        self.keys: set[str] = set()

    async def mark_once(self, key: str, *, expires_at: datetime) -> bool:
        if key in self.keys:
            return False
        self.keys.add(key)
        return True


class BrowserSecurityPlugin:
    def __init__(self, signer: JoseSigner, browser: ControlledBrowser) -> None:
        self.signer = signer
        self.browser = browser

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(
            CLOCKS,
            type("Clock", (), {"now": lambda _: NOW})(),
            contribution_id="fixed-clock",
            order=0,
        )
        contribute(SIGNERS, self.signer, contribution_id="protected-signer")
        contribute(BROWSER_FORM_POSTS, self.browser, contribution_id="controlled-browser")


agent = Agent(
    instructions=(
        "Use explain_browser_session to explain how a PAP-controlled browser joins a Session. "
        "Never request or expose an assertion, pairwise user ID, Session ID, cookie, or key."
    ),
)


@agent.tool_plain
async def explain_browser_session() -> dict[str, Any]:
    """Exercise signing, form POST, verification, and replay rejection safely."""

    private_key = ec.generate_private_key(ec.SECP256R1())
    browser = ControlledBrowser()
    reactor, owned_http = build_pap_reactor()
    reactor.register_plugin(
        PluginManifest(name="pap-browser-session-example", version="1"),
        BrowserSecurityPlugin(JoseSigner(private_key, key_id="agent-key"), browser),
    )
    started = await BrowserSessionClient(reactor=reactor).join(
        client_id="https://assistant.example/agent.json",
        pairwise_user_id="usr_host_only_example",
        browser_session_endpoint="https://shop.example/poppy/browser-session",
        session_id="ses_host_only_example",
        return_to="https://orders.shop.example/current",
        company_domain="shop.example",
    )
    endpoint, fields = browser.posts[0]
    cache = ReplayCache()
    verify_options = {
        "public_key": private_key.public_key(),
        "expected_endpoint": endpoint,
        "company_domain": "shop.example",
        "expected_client_id": "https://assistant.example/agent.json",
        "expected_pairwise_user_id": "usr_host_only_example",
        "expected_session_id": "ses_host_only_example",
        "replay_cache": cache,
        "now": NOW,
    }
    verified = await verify_browser_assertion(fields["assertion"], **verify_options)
    try:
        await verify_browser_assertion(fields["assertion"], **verify_options)
    except BrowserSessionError:
        replay_rejected = True
    else:
        replay_rejected = False
    reactor.stop()
    if owned_http is not None:
        await owned_http.aclose()

    return {
        "status": "browser_joined",
        "top_level_form_post": True,
        "assertion_in_request_body": "assertion" in fields,
        "assertion_absent_from_url": "assertion=" not in endpoint,
        "jwt_type": "poppy-browser+jwt",
        "maximum_lifetime_seconds": 60,
        "company_domain_return": verified.return_to == started.return_to,
        "same_session": verified.session_id == "ses_host_only_example",
        "replay_rejected": replay_rejected,
        "assertion_withheld": True,
        "session_identity_withheld": True,
        "cookie_owned_by_company": True,
    }


async def main() -> None:
    result = await agent.run(
        "Explain how the controlled browser joins an existing PAP Session "
        "without exposing credentials.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
