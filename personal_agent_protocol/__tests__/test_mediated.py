# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Mediated Sign-In extension v1: credentials to one token endpoint, once, never to a model."""

import asyncio
from urllib.parse import parse_qs

import httpx
import pytest
from pydantic import SecretStr, ValidationError
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    AUTHORIZATION_STATE_STORES,
    SIGNERS,
    TOKEN_STORES,
    AuthorizationError,
    MediatedSignIn,
    mediated_sign_in,
)
from personal_agent_protocol.extensions import extension_required, negotiate_extensions
from personal_agent_protocol.mediated import MEDIATED_GRANT, MediatedSignInClient
from personal_agent_protocol.models import (
    DiscoveredCompany,
    DiscoveryDocument,
    ExtensionDescriptor,
    OAuthServerMetadata,
)
from personal_agent_protocol.reactor import (
    PROTECTED_INPUTS,
    ProtectedInputRequest,
    build_pap_reactor,
)

TOKEN_ENDPOINT = "https://auth.shop.example/oauth/token"
CLIENT_ID = "https://agent.example/agent.json"
AGENT = {"protocols": [{"type": "poppy", "endpoint": "https://shop.example/poppy/conversations"}]}
EXTENSION = {
    "version": "1",
    "fields": [
        {"name": "email", "label": "Email", "secret": False},
        {"name": "password", "label": "Password", "secret": True},
    ],
    "scopes": ["orders:read", "orders:return"],
}


def company(
    extension: dict[str, object] | None = EXTENSION, grants: tuple[str, ...] = (MEDIATED_GRANT,)
) -> DiscoveredCompany:
    document: dict[str, object] = {
        "protocol_version": "0.3",
        "organization": {"name": "Shop", "domain": "shop.example"},
        "agent": AGENT,
    }
    if extension is not None:
        document["extensions"] = {"mediated-sign-in": extension}
    return DiscoveredCompany(
        discovery_url="https://shop.example/.well-known/poppy.json",
        document=DiscoveryDocument.model_validate(document),
        oauth_metadata=OAuthServerMetadata.model_validate(
            {
                "issuer": "https://auth.shop.example",
                "token_endpoint": TOKEN_ENDPOINT,
                "revocation_endpoint": "https://auth.shop.example/oauth/revoke",
                "grant_types_supported": ["refresh_token", *grants],
                "protected_resources": ["https://shop.example"],
            }
        ),
    )


class Answers:
    """The host's trusted surface: what the user typed, and what it was asked."""

    def __init__(self, *answers: dict[str, str]) -> None:
        self.answers = list(answers)
        self.asked: list[ProtectedInputRequest] = []

    async def collect(self, request: ProtectedInputRequest) -> dict[str, SecretStr]:
        self.asked.append(request)
        return {name: SecretStr(value) for name, value in self.answers.pop(0).items()}


class Memory:
    def __init__(self) -> None:
        self.values: dict[str, object] = {}

    async def put(self, reference: str, value: object, **_: object) -> None:
        self.values[reference] = value

    async def get(self, reference: str) -> object | None:
        return self.values.get(reference)

    async def take(self, reference: str) -> object | None:
        return self.values.pop(reference, None)

    async def delete(self, reference: str) -> None:
        self.values.pop(reference, None)


class Signer:
    async def sign(self, claims: dict[str, object], *, purpose: str) -> SecretStr:
        assert purpose == "client_assertion"
        return SecretStr("client-assertion")


class Host:
    def __init__(self, answers: Answers) -> None:
        self.answers = answers
        self.state = Memory()
        self.tokens = Memory()

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(PROTECTED_INPUTS, self.answers, contribution_id="trusted-surface")
        contribute(AUTHORIZATION_STATE_STORES, self.state, contribution_id="memory")
        contribute(TOKEN_STORES, self.tokens, contribution_id="memory")
        contribute(SIGNERS, Signer(), contribution_id="agent-key")


def arrange(handler, *answers: dict[str, str]):  # type: ignore[no-untyped-def]
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    host = Host(Answers(*answers))
    reactor.register_plugin(PluginManifest(name="host", version="1"), host)
    return MediatedSignInClient(reactor=reactor, http_client=http), host


def complete(**extra: object) -> dict[str, object]:
    return {
        "access_token": "signed-in-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "scope": "orders:read",
        "refresh_token": "private-refresh-token",
        **extra,
    }


def code_required(**extra: object) -> httpx.Response:
    return httpx.Response(
        400,
        json={
            "error": "code_required",
            "sign_in_id": "sgn_3Hq8",
            "sent_to": "Text to the phone number ending in 71",
            "expires_in": 600,
            **extra,
        },
    )


def form_of(request: httpx.Request) -> dict[str, str]:
    return {name: values[0] for name, values in parse_qs(request.content.decode()).items()}


def sign_in(client: MediatedSignInClient, offered: DiscoveredCompany | None = None):  # type: ignore[no-untyped-def]
    return asyncio.run(
        client.sign_in(
            company=company() if offered is None else offered,
            client_id=CLIENT_ID,
            scopes=("orders:read", "orders:return"),
            tenant_id="tenant-one",
        )
    )


CREDENTIALS = {"email": "ada@example.com", "password": "correct horse"}


def test_the_declared_fields_go_to_the_token_endpoint_as_the_grant() -> None:
    seen: list[httpx.Request] = []

    def shop(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=complete())

    client, host = arrange(shop, CREDENTIALS)
    result = sign_in(client)

    assert str(seen[0].url) == TOKEN_ENDPOINT
    # No Session header at an OAuth endpoint (spec 5.2), and no JSON body.
    assert "poppy-session" not in seen[0].headers and "authorization" not in seen[0].headers
    form = form_of(seen[0])
    assert form.pop("client_assertion") == "client-assertion"
    assert form == {
        "grant_type": MEDIATED_GRANT,
        "scope": "orders:read orders:return",
        "email": "ada@example.com",
        "password": "correct horse",
        "client_id": CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }
    assert host.answers.asked[0].purpose == "credentials"
    assert host.answers.asked[0].issuer == "https://auth.shop.example"
    assert [field.name for field in host.answers.asked[0].fields] == ["email", "password"]
    assert result.status == "complete"
    assert result.missing_scopes == ("orders:return",)
    assert result.token is not None
    stored = host.tokens.values[result.refresh_token_reference]  # type: ignore[index]
    assert stored.get_secret_value() == "private-refresh-token"  # type: ignore[attr-defined]
    assert "private-refresh-token" not in result.model_dump_json()
    assert "correct horse" not in result.model_dump_json()


def test_a_one_time_code_continues_without_the_credentials_or_scope() -> None:
    seen: list[httpx.Request] = []

    def shop(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return code_required() if len(seen) == 1 else httpx.Response(200, json=complete())

    client, host = arrange(shop, CREDENTIALS, {"code": "246810"})
    started = sign_in(client)
    assert started.status == "code_required"
    assert started.sent_to == "Text to the phone number ending in 71"
    assert started.expires_at is not None and started.reference is not None

    finished = asyncio.run(client.submit_code(started.reference))
    assert str(seen[1].url) == TOKEN_ENDPOINT
    form = form_of(seen[1])
    form.pop("client_assertion")
    assert form == {
        "grant_type": MEDIATED_GRANT,
        "sign_in_id": "sgn_3Hq8",
        "one_time_code": "246810",
        "client_id": CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }
    assert host.answers.asked[1].purpose == "one_time_code"
    assert host.answers.asked[1].sent_to == "Text to the phone number ending in 71"
    assert host.answers.asked[1].company_domain == "shop.example"
    # The sign-in keeps the scopes of the first request.
    assert finished.status == "complete" and finished.missing_scopes == ("orders:return",)


def test_a_wrong_code_asks_again_and_invalid_grant_ends_it() -> None:
    answers = iter(
        [code_required(), code_required(), httpx.Response(400, json={"error": "invalid_grant"})]
    )
    client, host = arrange(lambda _: next(answers), CREDENTIALS, {"code": "1"}, {"code": "2"})
    started = sign_in(client)
    again = asyncio.run(client.submit_code(started.reference))
    assert again.status == "code_required" and again.reference == started.reference
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(client.submit_code(started.reference))
    assert raised.value.code == "invalid_grant"
    assert host.state.values == {}


@pytest.mark.parametrize(
    "error", ["invalid_grant", "expired_token", "access_denied", "invalid_scope"]
)
def test_the_extension_errors_end_the_sign_in(error: str) -> None:
    client, _ = arrange(lambda _: httpx.Response(400, json={"error": error}), CREDENTIALS)
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == error and raised.value.status_code == 400
    assert "correct horse" not in repr(raised.value.__dict__)


def test_a_code_required_without_its_sign_in_id_is_refused() -> None:
    client, host = arrange(
        lambda _: httpx.Response(400, json={"error": "code_required"}), CREDENTIALS
    )
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "invalid_mediated_response"
    assert host.state.values == {}


def test_a_redirect_never_carries_the_credentials_elsewhere() -> None:
    seen: list[str] = []

    def shop(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(307, headers={"Location": "/elsewhere"})

    client, _ = arrange(shop, CREDENTIALS)
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "redirect_refused"
    assert seen == [TOKEN_ENDPOINT]


def test_a_company_without_the_grant_offers_no_mediated_sign_in() -> None:
    assert mediated_sign_in(company()) == MediatedSignIn.model_validate(EXTENSION)
    assert mediated_sign_in(company(grants=())) is None
    assert mediated_sign_in(company(None)) is None
    # Another major version doesn't count as support.
    assert mediated_sign_in(company({"version": "2", "fields": []})) is None
    client, host = arrange(lambda _: httpx.Response(500), CREDENTIALS)
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client, company(grants=()))
    assert raised.value.code == "no_mediated"
    assert host.answers.asked == []


def test_the_old_auth_mediated_offers_nothing() -> None:
    document = DiscoveryDocument.model_validate(
        {
            "protocol_version": "0.3",
            "organization": {"name": "Shop", "domain": "shop.example"},
            "agent": AGENT,
            "auth": {
                "mediated": {
                    "endpoint": "https://auth.shop.example/poppy/sign-in",
                    "fields": EXTENSION["fields"],
                    "scopes": ["orders:read"],
                }
            },
        }
    )
    assert mediated_sign_in(company().model_copy(update={"document": document})) is None


@pytest.mark.parametrize(
    "name",
    [
        "grant_type",
        "scope",
        "resource",
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "sign_in_id",
        "one_time_code",
    ],
)
def test_a_forbidden_field_name_is_refused(name: str) -> None:
    fields = [{"name": name, "label": "Anything", "secret": False}]
    with pytest.raises(ValidationError):
        MediatedSignIn.model_validate({"version": "1", "fields": fields, "scopes": []})
    client, host = arrange(lambda _: httpx.Response(500), {name: "x"})
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client, company({"version": "1", "fields": fields, "scopes": ["orders:read"]}))
    assert raised.value.code == "invalid_mediated_extension"
    assert host.answers.asked == []


def test_answers_must_be_exactly_the_declared_fields() -> None:
    client, _ = arrange(lambda _: httpx.Response(500), {"email": "a@example.com"})
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "invalid_protected_input"


def test_rate_limited_is_reported_with_retry_after_and_no_credential() -> None:
    client, _ = arrange(
        # A 429 has `Retry-After` and no body (§5.6).
        lambda _: httpx.Response(429, headers={"Retry-After": "30"}),
        CREDENTIALS,
    )
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "rate_limited"
    assert raised.value.details == {"retry_after": "30"}
    assert "correct horse" not in repr(raised.value.__dict__)


def test_a_rate_limited_code_keeps_the_sign_in() -> None:
    answers = iter([code_required(), httpx.Response(429, headers={"Retry-After": "30"})])
    client, host = arrange(lambda _: next(answers), CREDENTIALS, {"code": "1"})
    started = sign_in(client)
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(client.submit_code(started.reference))
    assert raised.value.code == "rate_limited"
    assert started.reference in host.state.values


def test_a_dpop_answer_to_a_mediated_sign_in_with_no_proof_is_refused() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(200, json=complete(token_type="DPoP")),  # noqa: S106 - a token type
        CREDENTIALS,
    )
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "unsupported_token_type"


def test_an_extension_used_by_the_request_is_negotiated_without_an_agent_entry() -> None:
    company_side = {"mediated-sign-in": ExtensionDescriptor(version="1")}
    assert negotiate_extensions(company_side, {}) == {"mediated-sign-in": "1"}
    # Another major version is not this extension.
    assert negotiate_extensions({"mediated-sign-in": ExtensionDescriptor(version="2")}, {}) == {}


def test_a_refusal_of_an_extension_the_request_uses_is_not_extension_required() -> None:
    """A Company can't refuse it: such a 403 isn't what the extension's error means (§3.3)."""

    body = {"error": "extension_required", "extension": "mediated-sign-in"}
    assert extension_required(403, body) is None
    assert extension_required(403, {**body, "extension": "operations"}) == "operations"
