# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Account Tokens: refresh, rotation, narrowing, invalid_grant, revocation (§4.8, §4.9)."""

import asyncio
from urllib.parse import parse_qsl

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    DPOP_PROOF_PROVIDERS,
    SIGNERS,
    TOKEN_STORES,
    AuthorizationError,
    DpopProofRequest,
)
from personal_agent_protocol.accounts import AccountTokenClient, AccountTokenContext
from personal_agent_protocol.reactor import build_pap_reactor

CONTEXT = AccountTokenContext(
    token_endpoint="https://auth.shop.example/oauth/token",  # noqa: S106
    revocation_endpoint="https://auth.shop.example/oauth/revoke",
    issuer="https://auth.shop.example",
    client_id="https://assistant.example/agent.json",
    tenant_id="tenant",
    pairwise_user_id="usr_pairwise",
)


class MemoryTokens:
    def __init__(self) -> None:
        self.values: dict[str, SecretStr] = {"account_ref": SecretStr("account-token-1")}

    async def put(self, reference: str, token: SecretStr) -> None:
        self.values[reference] = token

    async def get(self, reference: str) -> SecretStr | None:
        return self.values.get(reference)

    async def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


class Signer:
    def __init__(self) -> None:
        self.purposes: list[str] = []

    async def sign(self, _: dict[str, object], *, purpose: str) -> SecretStr:
        self.purposes.append(purpose)
        return SecretStr(purpose)


class Dpop:
    def __init__(self) -> None:
        self.requests: list[DpopProofRequest] = []
        self.made: list[str] = []
        self.discarded: list[str] = []

    async def new_session_key(self, *, tenant_id: str, issuer: str) -> str:
        self.made.append(f"{'n' * 42}{len(self.made)}")
        return self.made[-1]

    async def create(self, request: DpopProofRequest) -> SecretStr:
        self.requests.append(request)
        return SecretStr("proof")

    async def discard_session_key(self, *, tenant_id: str, issuer: str, session_key: str) -> None:
        self.discarded.append(session_key)


class Security:
    def __init__(self) -> None:
        self.tokens = MemoryTokens()
        self.dpop = Dpop()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(TOKEN_STORES, self.tokens, contribution_id="memory")
        contribute(SIGNERS, Signer(), contribution_id="signer")
        contribute(DPOP_PROOF_PROVIDERS, self.dpop, contribution_id="dpop")


def signed_in(**extra: object) -> dict[str, object]:
    return {
        "access_token": "session-token",
        "token_type": "DPoP",
        "expires_in": 300,
        "scope": "orders:read",
        **extra,
    }


def arrange(handler):  # type: ignore[no-untyped-def]
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    security = Security()
    reactor.register_plugin(PluginManifest(name="security", version="1"), security)
    return AccountTokenClient(reactor=reactor, http_client=http), security


def form(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


def test_refresh_signs_the_session_in_and_rotates_the_stored_token() -> None:
    seen: list[dict[str, str]] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(form(request))
        return httpx.Response(200, json=signed_in(refresh_token="account-token-2"))  # noqa: S106

    client, security = arrange(company)
    result = asyncio.run(client.refresh("account_ref", context=CONTEXT, session_key="K" * 43))

    assert result.status == "signed_in"
    assert result.rotated
    assert result.token is not None and result.token.refresh_token is None
    assert security.tokens.values["account_ref"].get_secret_value() == "account-token-2"
    assert seen[0]["grant_type"] == "refresh_token"
    # The proof's key names the Session; no parameter does (§4.3).
    assert "session_key" not in seen[0] and "session_id" not in seen[0]
    assert [request.session_key for request in security.dpop.requests] == ["K" * 43]
    assert "scope" not in seen[0]


def test_a_narrower_refresh_reports_what_was_left_out() -> None:
    def company(request: httpx.Request) -> httpx.Response:
        assert form(request)["scope"] == "orders:read orders:return"
        assert form(request)["resource"] == "https://api.shop.example/"
        return httpx.Response(200, json=signed_in())

    client, security = arrange(company)
    result = asyncio.run(
        client.refresh(
            "account_ref",
            context=CONTEXT,
            session_key="K" * 43,
            scopes=("orders:read", "orders:return"),
            resource="https://api.shop.example/",
        )
    )
    assert result.missing_scopes == ("orders:return",)
    assert not result.rotated
    assert security.tokens.values["account_ref"].get_secret_value() == "account-token-1"


def test_a_wider_scope_is_re_consent_not_a_retry() -> None:
    client, security = arrange(lambda _: httpx.Response(400, json={"error": "invalid_scope"}))
    result = asyncio.run(
        client.refresh("account_ref", context=CONTEXT, session_key="K" * 43, scopes=("orders:write",))
    )
    assert result.status == "re_consent_required"
    assert "account_ref" in security.tokens.values


def test_invalid_grant_then_a_renewal_that_works_means_the_account_token_ended() -> None:
    answers = [
        httpx.Response(400, json={"error": "invalid_grant"}),
        httpx.Response(200, json={"access_token": "t", "token_type": "DPoP", "expires_in": 60}),
    ]
    client, security = arrange(lambda _: answers.pop(0))
    result = asyncio.run(client.refresh("account_ref", context=CONTEXT, session_key="K" * 43))
    # Renewing with the assertion worked: the Session lives on signed out (§4.8).
    assert result.status == "signed_out" and result.token is not None
    assert not result.token.signed_in
    assert "account_ref" not in security.tokens.values


def test_invalid_grant_on_both_means_the_session_ended() -> None:
    client, security = arrange(lambda _: httpx.Response(400, json={"error": "invalid_grant"}))
    result = asyncio.run(client.refresh("account_ref", context=CONTEXT, session_key="K" * 43))
    # The renewal is refused too: the Session ended, the Account Token still works (§4.8).
    assert result.status == "session_ended"
    assert "account_ref" in security.tokens.values
    assert security.dpop.discarded == ["K" * 43]


def test_without_a_session_key_a_new_session_starts_signed_in() -> None:
    client, security = arrange(lambda _: httpx.Response(200, json=signed_in()))
    result = asyncio.run(client.refresh("account_ref", context=CONTEXT))
    assert result.status == "signed_in" and result.token is not None
    assert result.token.session_key == security.dpop.made[0]


def test_a_scope_the_company_was_not_asked_for_is_refused() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(200, json=signed_in(scope="orders:read orders:write"))
    )
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(
            client.refresh(
                "account_ref", context=CONTEXT, session_key="K" * 43, scopes=("orders:read",)
            )
        )
    assert raised.value.code == "scope_escalation"


def test_a_bearer_answer_to_a_refresh_is_refused() -> None:
    # Bearer Session Tokens come from Token Exchange alone (§4.3).
    client, _ = arrange(lambda _: httpx.Response(200, json=signed_in(token_type="Bearer")))
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(client.refresh("account_ref", context=CONTEXT, session_key="K" * 43))
    assert raised.value.code == "invalid_token_response"


def test_one_dpop_nonce_retry_with_a_fresh_proof() -> None:
    calls = 0

    def company(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "n-1"}
            )
        return httpx.Response(200, json=signed_in())

    client, security = arrange(company)
    asyncio.run(client.refresh("account_ref", context=CONTEXT, session_key="K" * 43))
    assert [request.nonce for request in security.dpop.requests] == [None, "n-1"]


def test_concurrent_refreshes_rotate_one_after_the_other() -> None:
    used: list[str] = []

    async def company(request: httpx.Request) -> httpx.Response:
        presented = form(request)["refresh_token"]
        used.append(presented)
        await asyncio.sleep(0)
        number = int(presented.rsplit("-", 1)[1])
        return httpx.Response(200, json=signed_in(refresh_token=f"account-token-{number + 1}"))

    client, security = arrange(company)

    async def both() -> None:
        await asyncio.gather(
            client.refresh("account_ref", context=CONTEXT, session_key="K" * 43),
            client.refresh("account_ref", context=CONTEXT, session_key="K" * 43),
        )

    asyncio.run(both())
    # Each refresh presented the token the previous one rotated in: never the same twice.
    assert used == ["account-token-1", "account-token-2"]
    assert security.tokens.values["account_ref"].get_secret_value() == "account-token-3"


def test_revocation_forgets_the_token_once_the_company_answers() -> None:
    def company(request: httpx.Request) -> httpx.Response:
        body = form(request)
        assert body["token_type_hint"] == "refresh_token"
        assert "DPoP" not in request.headers
        return httpx.Response(200)

    client, security = arrange(company)
    result = asyncio.run(client.revoke("account_ref", context=CONTEXT))
    assert result.revoked and result.deleted_locally
    assert "account_ref" not in security.tokens.values


def test_a_refused_revocation_keeps_the_token_for_a_retry() -> None:
    client, security = arrange(
        lambda _: httpx.Response(503, json={"error": "temporarily_unavailable"})
    )
    with pytest.raises(AuthorizationError):
        asyncio.run(client.revoke("account_ref", context=CONTEXT))
    assert "account_ref" in security.tokens.values


def test_no_error_carries_the_account_token() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(400, json={"error": "server_error", "echo": "account-token-1"})
    )
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(client.refresh("account_ref", context=CONTEXT, session_key="K" * 43))
    assert "account-token-1" not in repr(raised.value)
    assert "account-token-1" not in str(raised.value)
