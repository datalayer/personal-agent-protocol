# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Mediated Sign-In: credentials to one endpoint, once, never to a model (§4.7)."""

import asyncio
import json

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    AUTHORIZATION_STATE_STORES,
    DPOP_PROOF_PROVIDERS,
    TOKEN_STORES,
    AuthorizationError,
    DpopProofRequest,
    SessionToken,
)
from personal_agent_protocol.mediated import MediatedSignInClient
from personal_agent_protocol.models import MediatedSignIn, Organization
from personal_agent_protocol.reactor import (
    PROTECTED_INPUTS,
    ProtectedInputRequest,
    build_pap_reactor,
)

ENDPOINT = "https://auth.shop.example/poppy/sign-in"
COMPANY = Organization(name="Shop", domain="shop.example")
MEDIATED = MediatedSignIn(
    endpoint=ENDPOINT,
    fields=[
        {"name": "email", "label": "Email", "secret": False},
        {"name": "password", "label": "Password", "secret": True},
    ],
    scopes=["orders:read"],
)
SIGNED_OUT = SessionToken(
    access_token=SecretStr("session-token"),
    token_type="DPoP",  # noqa: S106
    expires_in=300,
    session_key="K" * 43,
    signed_in=False,
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


class Dpop:
    async def create(self, request: DpopProofRequest) -> SecretStr:
        assert request.access_token is not None
        return SecretStr("proof")


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
        contribute(DPOP_PROOF_PROVIDERS, Dpop(), contribution_id="dpop")


def arrange(handler, *answers: dict[str, str]):  # type: ignore[no-untyped-def]
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    host = Host(Answers(*answers))
    reactor.register_plugin(PluginManifest(name="host", version="1"), host)
    return MediatedSignInClient(reactor=reactor, http_client=http), host


def complete(**extra: object) -> dict[str, object]:
    return {
        "status": "complete",
        "access_token": "signed-in-token",
        "token_type": "DPoP",
        "expires_in": 300,
        "scope": "orders:read",
        "refresh_token": "account-token",
        **extra,
    }


def sign_in(client: MediatedSignInClient):  # type: ignore[no-untyped-def]
    return asyncio.run(
        client.sign_in(
            mediated=MEDIATED,
            organization=COMPANY,
            issuer="https://auth.shop.example",
            scopes=("orders:read", "orders:return"),
            token=SIGNED_OUT,
            tenant_id="tenant",
        )
    )


CREDENTIALS = {"email": "ada@example.com", "password": "correct horse"}


def test_the_declared_fields_go_to_the_endpoint_and_the_session_is_signed_in() -> None:
    seen: list[httpx.Request] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=complete())

    client, host = arrange(company, CREDENTIALS)
    result = sign_in(client)

    assert str(seen[0].url) == ENDPOINT
    assert seen[0].headers["authorization"] == "DPoP session-token"
    assert json.loads(seen[0].content) == {
        "scope": "orders:read orders:return",
        "credentials": CREDENTIALS,
    }
    assert host.answers.asked[0].purpose == "credentials"
    assert [field.name for field in host.answers.asked[0].fields] == ["email", "password"]
    assert result.status == "complete"
    assert result.missing_scopes == ("orders:return",)
    assert result.token is not None and result.token.refresh_token is None
    assert host.tokens.values[result.account_token_reference].get_secret_value() == "account-token"  # type: ignore[index, union-attr]
    assert "correct horse" not in result.model_dump_json()


def test_a_one_time_code_continues_without_the_credentials() -> None:
    seen: list[httpx.Request] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 1:
            return httpx.Response(
                200,
                json={
                    "status": "code_required",
                    "sign_in_id": "si_1",
                    "code": {"sent_to": "a•••@example.com"},
                    "expires_at": "2026-10-11T12:05:00Z",
                },
            )
        return httpx.Response(200, json=complete())

    client, host = arrange(company, CREDENTIALS, {"code": "246810"})
    started = sign_in(client)
    assert started.status == "code_required" and started.sent_to == "a•••@example.com"
    assert started.reference is not None

    finished = asyncio.run(
        client.submit_code(
            started.reference,
            token=SIGNED_OUT,
            tenant_id="tenant",
            issuer="https://auth.shop.example",
        )
    )
    assert str(seen[1].url) == f"{ENDPOINT}/si_1"
    assert json.loads(seen[1].content) == {"code": "246810"}
    assert host.answers.asked[1].purpose == "one_time_code"
    assert host.answers.asked[1].sent_to == "a•••@example.com"
    assert finished.status == "complete"


def test_a_wrong_code_asks_again_and_failed_ends_it() -> None:
    answers = iter(
        [
            {
                "status": "code_required",
                "sign_in_id": "si_1",
                "code": {},
                "expires_at": "2026-10-11T12:05:00Z",
            },
            {
                "status": "code_required",
                "sign_in_id": "si_1",
                "code": {},
                "expires_at": "2026-10-11T12:05:00Z",
            },
            {"status": "failed"},
        ]
    )
    client, host = arrange(
        lambda _: httpx.Response(200, json=next(answers)),
        CREDENTIALS,
        {"code": "1"},
        {"code": "2"},
    )
    started = sign_in(client)
    again = asyncio.run(
        client.submit_code(
            started.reference,
            token=SIGNED_OUT,
            tenant_id="t",
            issuer="https://auth.shop.example",
        )
    )
    assert again.status == "code_required" and again.reference == started.reference
    failed = asyncio.run(
        client.submit_code(
            started.reference,
            token=SIGNED_OUT,
            tenant_id="t",
            issuer="https://auth.shop.example",
        )
    )
    assert failed.status == "failed"
    assert host.state.values == {}


def test_only_the_session_that_started_it_can_finish_it() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(
            200,
            json={
                "status": "code_required",
                "sign_in_id": "si_1",
                "code": {},
                "expires_at": "2026-10-11T12:05:00Z",
            },
        ),
        CREDENTIALS,
    )
    started = sign_in(client)
    other = SIGNED_OUT.model_copy(update={"session_key": "ses_2"})
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(
            client.submit_code(
                started.reference,
                token=other,
                tenant_id="t",
                issuer="https://auth.shop.example",
            )
        )
    assert raised.value.code == "session_mismatch"


def test_a_redirect_never_carries_the_credentials_elsewhere() -> None:
    seen: list[str] = []

    def company(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(307, headers={"Location": "/elsewhere"})

    client, _ = arrange(company, CREDENTIALS)
    with pytest.raises(AuthorizationError):
        sign_in(client)
    assert seen == [ENDPOINT]


def test_an_endpoint_off_the_company_domain_is_refused_before_asking() -> None:
    client, host = arrange(lambda _: httpx.Response(500), CREDENTIALS)
    off = MEDIATED.model_copy(update={"endpoint": "https://collector.example/sign-in"})
    with pytest.raises(AuthorizationError) as raised:
        asyncio.run(
            client.sign_in(
                mediated=off,
                organization=COMPANY,
                issuer="https://auth.shop.example",
                scopes=("orders:read",),
                token=SIGNED_OUT,
                tenant_id="t",
            )
        )
    assert raised.value.code == "unsafe_mediated_endpoint"
    assert host.answers.asked == []


def test_answers_must_be_exactly_the_declared_fields() -> None:
    client, _ = arrange(lambda _: httpx.Response(500), {"email": "a@example.com"})
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "invalid_protected_input"


def test_rate_limited_is_reported_with_retry_after_and_no_credential() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(
            429, json={"error": "rate_limited"}, headers={"Retry-After": "30"}
        ),
        CREDENTIALS,
    )
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "rate_limited"
    assert raised.value.details == {"retry_after": "30"}
    assert "correct horse" not in repr(raised.value.__dict__)


def test_a_bearer_answer_to_a_mediated_sign_in_is_refused() -> None:
    client, _ = arrange(
        lambda _: httpx.Response(200, json=complete(token_type="Bearer")), CREDENTIALS
    )
    with pytest.raises(AuthorizationError) as raised:
        sign_in(client)
    assert raised.value.code == "invalid_token_response"


def test_expired_is_a_status_not_an_error() -> None:
    client, _ = arrange(lambda _: httpx.Response(200, json={"status": "expired"}), CREDENTIALS)
    assert sign_in(client).status == "expired"
