# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Refresh tokens: refresh, rotation, narrowing, invalid_grant, revocation (§4.4, §4.6, §5.5)."""

import asyncio
from urllib.parse import parse_qsl

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import SIGNERS, TOKEN_STORES, AuthorizationError
from personal_agent_protocol.accounts import (
    RefreshTokenClient,
    RefreshTokenContext,
    stale_resource_metadata,
)
from personal_agent_protocol.reactor import build_pap_reactor

CONTEXT = RefreshTokenContext(
    token_endpoint="https://auth.shop.example/oauth/token",  # noqa: S106
    revocation_endpoint="https://auth.shop.example/oauth/revoke",
    issuer="https://auth.shop.example",
    client_id="https://assistant.example/agent.json",
    tenant_id="tenant",
)


class MemoryTokens:
    def __init__(self) -> None:
        self.values: dict[str, SecretStr] = {"refresh_ref": SecretStr("refresh-token-1")}

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


class Security:
    def __init__(self) -> None:
        self.tokens = MemoryTokens()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(TOKEN_STORES, self.tokens, contribution_id="memory")
        contribute(SIGNERS, Signer(), contribution_id="signer")


def signed_in(**extra: object) -> dict[str, object]:
    return {
        "access_token": "access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "orders:read",
        **extra,
    }


def arrange(handler):  # type: ignore[no-untyped-def]
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    security = Security()
    reactor.register_plugin(PluginManifest(name="security", version="1"), security)
    return RefreshTokenClient(reactor=reactor, http_client=http), security


def form(request: httpx.Request) -> dict[str, str]:
    return dict(parse_qsl(request.content.decode()))


def test_refresh_gets_an_access_token_and_rotates_the_stored_token() -> None:
    seen: list[httpx.Request] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=signed_in(refresh_token="refresh-token-2"))  # noqa: S106

    client, security = arrange(company)
    result = asyncio.run(client.refresh("refresh_ref", context=CONTEXT))

    assert result.status == "signed_in"
    assert result.rotated
    assert result.token is not None
    assert result.token.access_token.get_secret_value() == "access-token"
    assert "refresh-token-2" not in result.model_dump_json()
    assert security.tokens.values["refresh_ref"].get_secret_value() == "refresh-token-2"
    sent = form(seen[0])
    assert sent["grant_type"] == "refresh_token"
    assert sent["refresh_token"] == "refresh-token-1"
    # No Session is named: any of the User's Sessions uses the token (§4.4, §5.4).
    assert "session_key" not in sent and "session_id" not in sent
    assert "poppy-session" not in seen[0].headers and "dpop" not in seen[0].headers
    assert "scope" not in sent


def test_a_narrower_refresh_reports_what_was_left_out() -> None:
    def company(request: httpx.Request) -> httpx.Response:
        assert form(request)["scope"] == "orders:read orders:return"
        assert form(request)["resource"] == "https://api.shop.example/"
        return httpx.Response(200, json=signed_in())

    client, security = arrange(company)
    result = asyncio.run(
        client.refresh(
            "refresh_ref",
            context=CONTEXT,
            scopes=("orders:read", "orders:return"),
            resource="https://api.shop.example/",
        )
    )
    assert result.missing_scopes == ("orders:return",)
    assert result.token is not None and result.token.resource == "https://api.shop.example/"
    assert not result.rotated
    assert security.tokens.values["refresh_ref"].get_secret_value() == "refresh-token-1"


def test_a_wider_scope_is_re_consent_not_a_retry() -> None:
    client, security = arrange(lambda _: httpx.Response(400, json={"error": "invalid_scope"}))
    result = asyncio.run(client.refresh("refresh_ref", context=CONTEXT, scopes=("orders:write",)))
    assert result.status == "re_consent_required"
    assert "refresh_ref" in security.tokens.values


def test_invalid_grant_forgets_the_token_and_the_sessions_go_on_signed_out() -> None:
    client, security = arrange(lambda _: httpx.Response(400, json={"error": "invalid_grant"}))
    result = asyncio.run(client.refresh("refresh_ref", context=CONTEXT))
    # The stored copy is useless and goes; the Sessions continue signed out (§5.5).
    assert result.status == "signed_out" and result.token is None
    assert "refresh_ref" not in security.tokens.values


def test_a_reference_with_no_token_is_signed_out_without_asking() -> None:
    calls = 0

    def company(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(500)

    client, _ = arrange(company)
    assert asyncio.run(client.refresh("gone", context=CONTEXT)).status == "signed_out"
    assert calls == 0


def test_a_scope_the_company_was_not_asked_for_is_refused() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(200, json=signed_in(scope="orders:read orders:write"))
    )
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(client.refresh("refresh_ref", context=CONTEXT, scopes=("orders:read",)))
    assert raised.value.code == "scope_escalation"


def test_a_dpop_answer_to_a_refresh_with_no_proof_is_refused() -> None:
    client, _ = arrange(lambda _: httpx.Response(200, json=signed_in(token_type="DPoP")))  # noqa: S106 - an OAuth token type, not a credential
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(client.refresh("refresh_ref", context=CONTEXT))
    assert raised.value.code == "unsupported_token_type"


def test_a_token_for_an_mcp_server_names_it_as_the_resource() -> None:
    seen: list[dict[str, str]] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(form(request))
        return httpx.Response(200, json=signed_in())

    mcp = "https://mcp.shop.example/mcp"
    client, _ = arrange(company)
    result = asyncio.run(client.token_for_mcp("refresh_ref", context=CONTEXT, url=mcp))
    assert result.status == "signed_in"
    assert result.token is not None and result.token.resource == mcp
    # An OAuth refresh with `resource` (RFC 8707, §4.5): no Token Exchange.
    assert seen[0]["grant_type"] == "refresh_token"
    assert seen[0]["resource"] == mcp
    assert "subject_token" not in seen[0]


def test_a_token_refused_with_resource_metadata_means_the_view_is_stale() -> None:
    stale = AuthorizationError(
        "invalid_token", "refused", details={"resource_metadata": "https://mcp.shop.example/prm"}
    )
    assert stale_resource_metadata(stale)
    assert not stale_resource_metadata(AuthorizationError("invalid_token", "refused"))
    assert not stale_resource_metadata(AuthorizationError("insufficient_scope", "refused"))


def test_concurrent_refreshes_rotate_one_after_the_other() -> None:
    used: list[str] = []

    async def company(request: httpx.Request) -> httpx.Response:
        presented = form(request)["refresh_token"]
        used.append(presented)
        await asyncio.sleep(0)
        number = int(presented.rsplit("-", 1)[1])
        return httpx.Response(200, json=signed_in(refresh_token=f"refresh-token-{number + 1}"))

    client, security = arrange(company)

    async def both() -> None:
        await asyncio.gather(
            client.refresh("refresh_ref", context=CONTEXT),
            client.refresh("refresh_ref", context=CONTEXT),
        )

    asyncio.run(both())
    # Each refresh presented the token the previous one rotated in: never the same twice.
    assert used == ["refresh-token-1", "refresh-token-2"]
    assert security.tokens.values["refresh_ref"].get_secret_value() == "refresh-token-3"


def test_revocation_forgets_the_token_once_the_company_answers() -> None:
    def company(request: httpx.Request) -> httpx.Response:
        body = form(request)
        assert body["token_type_hint"] == "refresh_token"
        assert "dpop" not in request.headers and "poppy-session" not in request.headers
        return httpx.Response(200)

    client, security = arrange(company)
    result = asyncio.run(client.revoke("refresh_ref", context=CONTEXT))
    assert result.revoked and result.deleted_locally
    assert "refresh_ref" not in security.tokens.values


def test_a_refused_revocation_keeps_the_token_for_a_retry() -> None:
    client, security = arrange(
        lambda _: httpx.Response(503, json={"error": "temporarily_unavailable"})
    )
    with pytest.raises(AuthorizationError):
        asyncio.run(client.revoke("refresh_ref", context=CONTEXT))
    assert "refresh_ref" in security.tokens.values


def test_sign_out_revokes_every_refresh_token_held_for_the_account() -> None:
    revoked: list[str] = []

    def company(request: httpx.Request) -> httpx.Response:
        revoked.append(form(request)["token"])
        return httpx.Response(200)

    client, security = arrange(company)
    security.tokens.values["other_ref"] = SecretStr("refresh-token-other")
    result = asyncio.run(client.sign_out(["refresh_ref", "other_ref"], context=CONTEXT))
    assert (result.revoked, result.signed_out) == (2, True)
    assert revoked == ["refresh-token-1", "refresh-token-other"]
    assert security.tokens.values == {}


def test_no_error_carries_the_refresh_token() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(400, json={"error": "server_error", "echo": "refresh-token-1"})
    )
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(client.refresh("refresh_ref", context=CONTEXT))
    assert "refresh-token-1" not in repr(raised.value)
    assert "refresh-token-1" not in str(raised.value)
