# Copyright (c) 2025-2026 Datalayer, Inc.
# BSD 3-Clause License

"""A Pydantic AI agent that demonstrates complete PAP Direct Sign-In."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
from pydantic import SecretStr
from pydantic_ai import Agent
from reactor import PluginManifest

from personal_agent_protocol import (
    AUTHORIZATION_STATE_STORES,
    BROWSER_HANDOFFS,
    SIGNERS,
    TOKEN_STORES,
    AuthorizationError,
    DirectSignInClient,
    build_pap_reactor,
)


class OneUseStateStore:
    """Keep authorization state host-side and delete it when read."""

    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    async def put(self, reference: str, value: object, *, expires_at: datetime) -> None:
        self.values[reference] = value

    async def take(self, reference: str) -> object | None:
        return self.values.pop(reference, None)


class HostVault:
    """`pap.tokenStore`: the refresh token stays here, behind an opaque reference."""

    def __init__(self) -> None:
        self.values: dict[str, SecretStr] = {}

    async def put(self, reference: str, token: SecretStr) -> None:
        self.values[reference] = token

    async def get(self, reference: str) -> SecretStr | None:
        return self.values.get(reference)

    async def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


class RecordingBrowser:
    """Stand in for a trusted browser without returning its URL to the agent."""

    def __init__(self) -> None:
        self.urls: list[SecretStr] = []

    async def open(self, authorization_url: SecretStr) -> None:
        self.urls.append(authorization_url)


class RecordingSigner:
    def __init__(self) -> None:
        self.purposes: list[str] = []

    async def sign(self, _: dict[str, object], *, purpose: str) -> SecretStr:
        self.purposes.append(purpose)
        return SecretStr(f"host-only-assertion-{len(self.purposes)}")


class DirectSignInSecurityPlugin:
    """Supply replaceable host capabilities through Reactor."""

    def __init__(
        self,
        store: OneUseStateStore,
        browser: RecordingBrowser,
        signer: RecordingSigner,
        vault: HostVault,
    ) -> None:
        self.vault = vault
        self.store = store
        self.browser = browser
        self.signer = signer

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(AUTHORIZATION_STATE_STORES, self.store, contribution_id="one-use-state")
        contribute(BROWSER_HANDOFFS, self.browser, contribution_id="trusted-browser")
        contribute(SIGNERS, self.signer, contribution_id="protected-signer")
        contribute(TOKEN_STORES, self.vault, contribution_id="host-vault")


agent = Agent(
    instructions=(
        "Use explain_direct_sign_in_lifecycle to explain PAP Direct Sign-In. "
        "Never ask for or expose an authorization URL, callback, code, state, "
        "verifier, assertion, access token, or refresh token."
    ),
)


@agent.tool_plain
async def explain_direct_sign_in_lifecycle() -> dict[str, Any]:
    """Run a complete local flow and return only non-secret evidence."""

    forms: list[dict[str, list[str]]] = []

    def company(request: httpx.Request) -> httpx.Response:
        forms.append(parse_qs(request.content.decode()))
        return httpx.Response(
            200,
            json={
                # Plain OAuth: a Bearer token for the account, naming no Session.
                "access_token": "host-only-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "orders:read",
                "refresh_token": "host-only-refresh-token",
            },
        )

    store = OneUseStateStore()
    browser = RecordingBrowser()
    signer = RecordingSigner()
    vault = HostVault()
    async with httpx.AsyncClient(transport=httpx.MockTransport(company)) as http:
        reactor, _ = build_pap_reactor(http_client=http)
        reactor.register_plugin(
            PluginManifest(name="pap-direct-sign-in-example-security", version="1"),
            DirectSignInSecurityPlugin(store, browser, signer, vault),
        )
        client = DirectSignInClient(reactor=reactor, http_client=http)
        started = await client.begin(
            authorization_endpoint="https://auth.shop.example/oauth/authorize",
            token_endpoint="https://auth.shop.example/oauth/token",  # noqa: S106
            issuer="https://auth.shop.example",
            client_id="https://assistant.example/agent.json",
            redirect_uri="https://assistant.example/oauth/callback",
            scopes=["orders:read", "orders:return"],
            tenant_id="example-tenant",
        )
        authorization = urlsplit(browser.urls[0].get_secret_value())
        query = parse_qs(authorization.query)
        state = query["state"][0]
        callback_url = "https://assistant.example/oauth/callback?" + urlencode(
            {
                "code": "host-only-one-use-code",
                "state": state,
                "iss": "https://auth.shop.example",
            }
        )
        result = await client.complete(callback_url)
        try:
            await client.complete(callback_url)
        except AuthorizationError as error:
            state_reuse_rejected = error.code == "invalid_or_expired_state"
        else:
            state_reuse_rejected = False
        reactor.stop()

    return {
        "status": "signed_in",
        "requested_scopes": started.requested_scopes,
        "granted_scopes": result.granted_scopes,
        "missing_scopes": result.missing_scopes,
        "token_type": result.token.token_type,
        "names_no_session": not {"sid", "dpop_jkt"} & (set(query) | set(forms[0])),
        "pkce_method": "S256",
        "trusted_browser_handoff": len(browser.urls) == 1,
        "state_reuse_rejected": state_reuse_rejected,
        "code_verifier_sent": "code_verifier" in forms[0],
        "client_assertion_sent": signer.purposes == ["client_assertion"],
        "authorization_url_withheld": True,
        "callback_and_code_withheld": True,
        "assertions_withheld": True,
        "access_and_refresh_tokens_withheld": True,
        # The refresh token went to the host's token store; the result holds only a reference.
        "refresh_token_in_result": "refresh_token" in result.token.model_dump(),
        "refresh_token_stored": result.refresh_token_reference in vault.values,
    }


async def main() -> None:
    result = await agent.run(
        "Show how PAP Direct Sign-In signs a user in, including partial consent, "
        "and where the tokens it returns are kept.",
        model=os.getenv("PAP_EXAMPLE_MODEL", "openai:gpt-4o-mini"),
    )
    sys.stdout.write(f"{result.output}\n")


if __name__ == "__main__":
    asyncio.run(main())
