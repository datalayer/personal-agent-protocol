# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Idempotency-Key on API writes (guides, *Retries*), from protocol/fixtures.

The personal agent's side: `ApiClient` sends a random UUID (version 4) on every
write, the caller's key on a retry, none on a read. The company's side: the
fixture's steps against the reference company, signed in with `orders:write`.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import DpopHttpClient, build_pap_reactor, new_idempotency_key
from personal_agent_protocol.apis import WRITE_METHODS, ApiClient, ApiError
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.operations import OperationsClient, approve

from .test_direct_and_api import begin, direct_world
from .test_operations import Host, token

FIXTURE = json.loads(
    (
        Path(__file__).parents[2] / "protocol" / "fixtures" / "idempotency-api-writes.json"
    ).read_text()
)
UUID_V4 = re.compile(FIXTURE["uuid_v4"])
URL = "https://api.shop.example/orders"
WHO = {"tenant_id": "tenant", "pairwise_user_id": "usr_1", "issuer": "https://auth.shop.example"}


def scripted(answer: httpx.Response) -> tuple[ApiClient, list[httpx.Request]]:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return answer

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    reactor.register_plugin(PluginManifest(name="host", version="1"), Host(None))
    return ApiClient(transport=DpopHttpClient(reactor=reactor, http_client=http)), sent


def test_the_sdks_write_methods_are_the_fixtures() -> None:
    assert sorted(WRITE_METHODS) == sorted(FIXTURE["write_methods"])
    assert not WRITE_METHODS & set(FIXTURE["read_methods"])
    assert UUID_V4.fullmatch(new_idempotency_key())
    default = timedelta(seconds=FIXTURE["default_lifetime_seconds"])
    assert CONFIG.idempotency_lifetime == default


@pytest.mark.asyncio
async def test_every_write_carries_a_random_uuid_v4_and_a_read_none() -> None:
    api, sent = scripted(httpx.Response(200, json={"ok": True}))
    keys = []
    for method in FIXTURE["write_methods"]:
        answer = await api.call(method.lower(), URL, token=token(), body={}, **WHO)
        keys.append(sent[-1].headers["Idempotency-Key"])
        assert UUID_V4.fullmatch(keys[-1]) and answer.idempotency_key == keys[-1]
    assert len(set(keys)) == len(keys)
    read = await api.call("GET", URL, token=token(), **WHO)
    assert "Idempotency-Key" not in sent[-1].headers and read.idempotency_key is None


@pytest.mark.asyncio
async def test_a_retry_sends_the_callers_key_and_a_refusal_carries_it() -> None:
    api, sent = scripted(httpx.Response(503, json={"error": "temporarily_unavailable"}))
    with pytest.raises(ApiError) as raised:
        await api.call("POST", URL, token=token(), body={"size": "M"}, **WHO)
    key = raised.value.idempotency_key
    assert key is not None and sent[-1].headers["Idempotency-Key"] == key
    with pytest.raises(ApiError):
        await api.call("POST", URL, token=token(), body={"size": "M"}, idempotency_key=key, **WHO)
    assert sent[-1].headers["Idempotency-Key"] == key
    assert sent[-2].headers["DPoP"] and len(sent) == 2


@pytest.mark.asyncio
async def test_a_bad_key_or_a_key_on_a_read_is_the_callers_mistake() -> None:
    api, sent = scripted(httpx.Response(200, json={}))
    for bad in FIXTURE["invalid_keys"]:
        with pytest.raises(ValueError):
            await api.call("POST", URL, token=token(), body={}, idempotency_key=bad, **WHO)
    with pytest.raises(ValueError):
        await api.call("GET", URL, token=token(), idempotency_key=new_idempotency_key(), **WHO)
    assert sent == []


def _operation(answer: Any) -> dict[str, Any]:
    return answer.operation.model_dump(mode="json")


@pytest.mark.asyncio
async def test_the_reference_company_keeps_each_key_per_session_for_its_lifetime() -> None:
    world, browser = direct_world()
    lifetime = timedelta(seconds=FIXTURE["lifetime_seconds"])
    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, idempotency_lifetime=lifetime)
    )
    tokens = {}
    for name in ("first", "second"):
        session = await world.signed_out_session()
        client = await begin(world, browser, session, ("orders:read", "orders:write"))
        callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
        tokens[name] = (await client.complete(callback)).token
    assert tokens["first"].session_id != tokens["second"].session_id
    api = ApiClient(transport=world.transport)
    answers: dict[str, Any] = {}
    for step in FIXTURE["steps"]:
        if "confirm" in step:
            operation = answers[step["confirm"]].operation
            await OperationsClient(transport=world.transport).confirm(
                world.shop.config.operations_endpoint,
                operation,
                approval=approve(operation),
                token=tokens["first"],
                **world.who,
            )
            continue
        world.clock.advance(step.get("advance_seconds", 0))
        call = api.call(
            "POST",
            f"https://manzanita.example{step['path']}",
            token=tokens[step.get("session", "first")],
            body=step["body"],
            idempotency_key=step["key"],
            **world.who,
        )
        expect = step["expect"]
        if "error" in expect:
            with pytest.raises(ApiError) as raised:
                await call
            assert (raised.value.status_code, raised.value.code) == (
                expect["status"],
                expect["error"],
            ), step["name"]
            assert raised.value.idempotency_key == step["key"]
            continue
        answer = await call
        assert answer.status == expect["status"], step["name"]
        assert answer.idempotency_key == step["key"]
        if expect["answer"] == "first":
            assert _operation(answer) == _operation(answers["first"]), step["name"]
            assert answer.operation.state == "proposed"  # type: ignore[union-attr]
        else:
            assert answer.operation is not None, step["name"]
            assert (
                "first" not in answers
                or answer.operation.operation_id != answers["first"].operation.operation_id
            ), step["name"]
        answers[step["name"]] = answer
    # The first exchange was performed once, whatever the retries.
    assert world.plugin.executor.performed == [answers["first"].operation.operation_id]


@pytest.mark.asyncio
async def test_a_bad_key_is_invalid_request_and_a_refusal_is_not_remembered() -> None:
    world, browser = direct_world()
    session = await world.signed_out_session()
    api = ApiClient(transport=world.transport)
    exchanges = "https://manzanita.example/api/orders/ord_7Hk2/exchanges"
    for bad in (key for key in FIXTURE["invalid_keys"] if key.isascii()):
        response = await world.transport.request(
            "POST",
            exchanges,
            token=session,
            headers={"Idempotency-Key": bad, "Content-Type": "application/json"},
            content=b"{}",
            **world.who,
        )
        assert (response.status_code, response.json()["error"]) == (400, "invalid_request")
    key = new_idempotency_key()
    with pytest.raises(ApiError) as raised:
        await api.call("POST", exchanges, token=session, body={}, idempotency_key=key, **world.who)
    assert raised.value.code == "sign_in_required"
    # Signed in, the same key is a new request: the refusal was not kept.
    client = await begin(world, browser, session, ("orders:read", "orders:write"))
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    signed_in = (await client.complete(callback)).token
    answer = await api.call(
        "POST", exchanges, token=signed_in, body={}, idempotency_key=key, **world.who
    )
    assert answer.status == 202 and answer.operation is not None
