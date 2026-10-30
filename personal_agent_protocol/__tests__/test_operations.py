# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Operations v1: negotiation, exact approval, standing permissions, recovery."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr
from reactor import PluginManifest

from personal_agent_protocol import (
    CLOCKS,
    SESSION_SIGNERS,
    AccessToken,
    ClientMetadata,
    DiscoveryDocument,
    Operation,
    PapSession,
    SessionHttpClient,
    SessionJwtRequest,
    build_pap_reactor,
)
from personal_agent_protocol.operations import (
    STANDING_PERMISSION_STORES,
    InMemoryStandingPermissionStore,
    OperationError,
    OperationsClient,
    StandingPermission,
    TermLimit,
    approve,
    operations_endpoint,
)

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"
ENDPOINT = "https://api.shop.example/poppy/operations"
NOW = datetime(2026, 10, 10, 12, tzinfo=timezone.utc)


def proposed(**changes: object) -> Operation:
    data = json.loads((FIXTURES / "operation-valid.json").read_text())
    data.update(changes)
    return Operation.model_validate(data)


def confirmed(operation: Operation, approved_by: str = "user") -> dict[str, object]:
    return {
        **operation.model_dump(mode="json"),
        "state": "succeeded",
        "confirmation": {
            "revision": operation.revision,
            "approved_by": approved_by,
            "confirmed_at": "2026-10-10T12:00:05Z",
        },
        "result": {"summary": "Exchanged the jacket; USD 70.00 charged to the card on file."},
    }


class SessionJwts:
    async def sign(self, request: SessionJwtRequest) -> SecretStr:
        return SecretStr("session-jwt")


class Clock:
    def now(self) -> datetime:
        return NOW


class Host:
    def __init__(self, store: InMemoryStandingPermissionStore | None) -> None:
        self.store = store

    def provide_contributions(self, contributions: object) -> None:
        contribute = contributions.contribute  # type: ignore[attr-defined]
        contribute(SESSION_SIGNERS, SessionJwts(), contribution_id="session-jwts")
        contribute(CLOCKS, Clock(), contribution_id="fixed", order=10)
        if self.store is not None:
            contribute(STANDING_PERMISSION_STORES, self.store, contribution_id="memory")


def session() -> PapSession:
    return PapSession(
        sid="S" * 22,
        sub="usr_1",
        issuer="https://auth.shop.example",
        client_id="https://agent.example/agent.json",
        tenant_id="tenant",
    )


def token() -> AccessToken:
    return AccessToken(access_token=SecretStr("s"), expires_in=300, scope="orders:write")


def client_for(handler, store: InMemoryStandingPermissionStore | None = None):  # type: ignore[no-untyped-def]
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    reactor.register_plugin(PluginManifest(name="host", version="1"), Host(store))
    return OperationsClient(transport=SessionHttpClient(reactor=reactor, http_client=http))


def permission(**changes: object) -> StandingPermission:
    values: dict[str, object] = {
        "reference": "perm_exchanges",
        "company": "https://auth.shop.example",
        "account": "usr_1",
        "action": "orders.exchange",
        "limits": (
            TermLimit("price_difference.amount", maximum=Decimal("100.00")),
            TermLimit("price_difference.currency", allowed=frozenset({"USD"})),
        ),
        "expires_at": NOW + timedelta(days=30),
        "uses_remaining": 1,
    }
    values.update(changes)
    return StandingPermission(**values)  # type: ignore[arg-type]


STANDING = ("https://auth.shop.example", "usr_1", "orders.exchange")


def test_operations_are_used_only_when_both_sides_list_version_1() -> None:
    document = DiscoveryDocument.model_validate(
        {
            **json.loads((FIXTURES / "discovery-valid.json").read_text()),
            "extensions": {"operations": {"version": "1", "endpoint": ENDPOINT}},
        }
    )
    metadata = json.loads((FIXTURES / "client-metadata-valid.json").read_text())
    with_ops = ClientMetadata.model_validate(
        {**metadata, "extensions": {"operations": {"version": "1"}}}
    )
    without = ClientMetadata.model_validate({**metadata, "extensions": {}})
    newer = ClientMetadata.model_validate(
        {**metadata, "extensions": {"operations": {"version": "2"}}}
    )
    assert operations_endpoint(document, with_ops) == ENDPOINT
    assert operations_endpoint(document, without) is None
    assert operations_endpoint(document, newer) is None


@pytest.mark.asyncio
async def test_the_user_approves_one_revision_and_it_is_confirmed_once() -> None:
    operation = proposed()
    bodies: list[dict[str, object]] = []

    def company(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(200, json=confirmed(operation))

    outcome = await client_for(company).confirm(
        ENDPOINT, operation, approval=approve(operation), session=session(), token=token()
    )
    assert bodies == [{"revision": 1, "approved_by": "user"}]
    assert outcome.status == "confirmed"
    assert outcome.operation.result.summary.startswith("Exchanged the jacket")  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_an_approval_of_another_revision_is_refused_locally() -> None:
    first = proposed()
    second = proposed(revision=2, summary="Exchange the jacket for USD 90.00 more.")
    with pytest.raises(OperationError) as raised:
        await client_for(lambda _: httpx.Response(500)).confirm(
            ENDPOINT, second, approval=approve(first), session=session(), token=token()
        )
    assert raised.value.code == "approval_mismatch"


@pytest.mark.asyncio
async def test_terms_changed_returns_the_new_revision_and_what_changed() -> None:
    operation = proposed()
    newer = proposed(
        revision=2,
        terms={"order_id": "ord_7Hk2", "price_difference": {"amount": "85.00", "currency": "USD"}},
    )

    outcome = await client_for(
        lambda _: httpx.Response(
            409, json={"error": "terms_changed", "operation": newer.model_dump(mode="json")}
        )
    ).confirm(ENDPOINT, operation, approval=approve(operation), session=session(), token=token())
    assert outcome.status == "terms_changed"
    assert outcome.operation.revision == 2  # type: ignore[union-attr]
    assert outcome.changed == ("price_difference.amount",)


@pytest.mark.asyncio
async def test_a_standing_permission_covers_every_term_and_spends_one_use() -> None:
    operation = proposed(user_approval_required=False)
    store = InMemoryStandingPermissionStore((permission(),))
    outcome = await client_for(
        lambda _: httpx.Response(200, json=confirmed(operation, "standing_permission")), store
    ).confirm(ENDPOINT, operation, standing=STANDING, session=session(), token=token())
    assert outcome.status == "confirmed"
    assert store.permissions["perm_exchanges"].uses_remaining == 0


@pytest.mark.parametrize(
    ("operation_changes", "permission_changes"),
    [
        (
            {
                "terms": {
                    "order_id": "o",
                    "price_difference": {"amount": "170.00", "currency": "USD"},
                }
            },
            {},
        ),
        (
            {
                "terms": {
                    "order_id": "o",
                    "price_difference": {"amount": "70.00", "currency": "EUR"},
                }
            },
            {},
        ),
        ({"terms": {"order_id": "o"}}, {}),
        ({}, {"action": "orders.cancel"}),
        ({}, {"expires_at": NOW}),
        ({}, {"uses_remaining": 0}),
        ({"user_approval_required": True}, {}),
    ],
)
@pytest.mark.asyncio
async def test_a_standing_permission_that_does_not_cover_it_asks_the_user(
    operation_changes: dict[str, object], permission_changes: dict[str, object]
) -> None:
    operation = proposed(**{"user_approval_required": False, **operation_changes})
    store = InMemoryStandingPermissionStore((permission(**permission_changes),))
    with pytest.raises(OperationError) as raised:
        await client_for(lambda _: httpx.Response(500), store).confirm(
            ENDPOINT, operation, standing=STANDING, session=session(), token=token()
        )
    assert raised.value.code in {"no_standing_permission", "user_approval_required"}


@pytest.mark.asyncio
async def test_a_refused_confirmation_gives_the_use_back() -> None:
    operation = proposed(user_approval_required=False)
    store = InMemoryStandingPermissionStore((permission(),))
    outcome = await client_for(
        lambda _: httpx.Response(403, json={"error": "user_approval_required"}), store
    ).confirm(ENDPOINT, operation, standing=STANDING, session=session(), token=token())
    assert outcome.status == "approval_required"
    assert store.permissions["perm_exchanges"].uses_remaining == 1


@pytest.mark.asyncio
async def test_a_lost_answer_is_read_back_by_the_same_id_never_assumed_failed() -> None:
    operation = proposed()
    calls: list[str] = []

    def company(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        if request.method == "POST":
            raise httpx.ReadTimeout("lost", request=request)
        return httpx.Response(
            200, json={**confirmed(operation), "state": "in_progress", "result": None}
        )

    outcome = await client_for(company).confirm(
        ENDPOINT, operation, approval=approve(operation), session=session(), token=token()
    )
    assert calls == ["POST /poppy/operations/exc_5Rt2/confirm", "GET /poppy/operations/exc_5Rt2"]
    assert outcome.status == "confirmed" and outcome.operation.state == "in_progress"  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_cancel_and_extension_required() -> None:
    operation = proposed()

    def company(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/cancel"):
            return httpx.Response(
                200,
                json={
                    **operation.model_dump(mode="json"),
                    "state": "cancelled",
                    "result": {"summary": "Nothing was changed."},
                },
            )
        return httpx.Response(403, json={"error": "extension_required", "extension": "operations"})

    client = client_for(company)
    cancelled = await client.cancel(ENDPOINT, "exc_5Rt2", session=session(), token=token())
    assert cancelled.state == "cancelled" and cancelled.result.summary == "Nothing was changed."  # type: ignore[union-attr]
    with pytest.raises(OperationError) as raised:
        await client.read(ENDPOINT, "exc_5Rt2", session=session(), token=token())
    assert raised.value.code == "extension_required"
    assert raised.value.details == {"extension": "operations"}
