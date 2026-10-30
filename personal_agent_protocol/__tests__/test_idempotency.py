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
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    SESSION_SIGNERS,
    AccessToken,
    PapSession,
    SessionHttpClient,
    SessionJwtRequest,
    build_pap_reactor,
    new_idempotency_key,
)
from personal_agent_protocol.apis import WRITE_METHODS, ApiClient, ApiError
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.models import Approval

from .test_direct_and_api import begin, direct_world

FIXTURE = json.loads(
    (
        Path(__file__).parents[2] / "protocol" / "fixtures" / "idempotency-api-writes.json"
    ).read_text()
)
UUID_V4 = re.compile(FIXTURE["uuid_v4"])
URL = "https://api.shop.example/orders"


class SessionJwts:
    async def sign(self, request: SessionJwtRequest) -> SecretStr:
        return SecretStr("session-jwt")


class Host:
    def __init__(self, _: object = None) -> None:
        pass

    def provide_contributions(self, contributions: object) -> None:
        contributions.contribute(  # type: ignore[attr-defined]
            SESSION_SIGNERS, SessionJwts(), contribution_id="session-jwts"
        )


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


def scripted(answer: httpx.Response) -> tuple[ApiClient, list[httpx.Request]]:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return answer

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    reactor, _ = build_pap_reactor(http_client=http)
    reactor.register_plugin(PluginManifest(name="host", version="1"), Host(None))
    return ApiClient(transport=SessionHttpClient(reactor=reactor, http_client=http)), sent


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
        answer = await api.call(method.lower(), URL, session=session(), token=token(), body={})
        keys.append(sent[-1].headers["Idempotency-Key"])
        assert UUID_V4.fullmatch(keys[-1]) and answer.idempotency_key == keys[-1]
    assert len(set(keys)) == len(keys)
    read = await api.call("GET", URL, session=session(), token=token())
    assert "Idempotency-Key" not in sent[-1].headers and read.idempotency_key is None


@pytest.mark.asyncio
async def test_a_retry_sends_the_callers_key_and_a_refusal_carries_it() -> None:
    api, sent = scripted(httpx.Response(503, json={"error": "temporarily_unavailable"}))
    with pytest.raises(ApiError) as raised:
        await api.call("POST", URL, session=session(), token=token(), body={"size": "M"})
    key = raised.value.idempotency_key
    assert key is not None and sent[-1].headers["Idempotency-Key"] == key
    with pytest.raises(ApiError):
        await api.call(
            "POST", URL, session=session(), token=token(), body={"size": "M"}, idempotency_key=key
        )
    assert sent[-1].headers["Idempotency-Key"] == key
    assert sent[-2].headers["Poppy-Session"] and len(sent) == 2


@pytest.mark.asyncio
async def test_a_bad_key_or_a_key_on_a_read_is_the_callers_mistake() -> None:
    api, sent = scripted(httpx.Response(200, json={}))
    for bad in FIXTURE["invalid_keys"]:
        with pytest.raises(ValueError):
            await api.call(
                "POST", URL, session=session(), token=token(), body={}, idempotency_key=bad
            )
    with pytest.raises(ValueError):
        await api.call(
            "GET", URL, session=session(), token=token(), idempotency_key=new_idempotency_key()
        )
    assert sent == []


@pytest.mark.asyncio
async def test_the_reference_company_keeps_each_key_per_session_for_its_lifetime() -> None:
    world, browser = direct_world()
    lifetime = timedelta(seconds=FIXTURE["lifetime_seconds"])
    world.shop, world.plugin = manzanita(
        world.network, world.clock, config=replace(CONFIG, idempotency_lifetime=lifetime)
    )
    tokens = {}
    sessions = {}
    for name in ("first", "second"):
        sessions[name] = await world.signed_out_session()
        client = await begin(world, browser, sessions[name], ("orders:read", "orders:write"))
        callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
        tokens[name] = (await client.complete(callback)).token
    assert sessions["first"].sid != sessions["second"].sid
    api = ApiClient(transport=world.transport)
    answers: dict[str, Any] = {}
    for step in FIXTURE["steps"]:
        world.clock.advance(step.get("advance_seconds", 0))
        operation = answers[step["approve"]].operation if "approve" in step else None
        call = api.call(
            "POST",
            f"https://manzanita.example{step['path']}",
            session=sessions[step.get("session", "first")],
            token=tokens[step.get("session", "first")],
            body=step["body"],
            idempotency_key=step["key"],
            approval=None
            if operation is None
            else Approval(operation_id=operation.operation_id, revision=operation.revision),
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
            assert answer.body == answers["first"].body, step["name"]
        elif expect["answer"] == "performed":
            assert answer.operation is None and answer.body["summary"], step["name"]
        else:
            assert answer.operation is not None, step["name"]
            assert (
                "asked" not in answers
                or answer.operation.operation_id != answers["asked"].operation.operation_id
            ), step["name"]
        answers[step["name"]] = answer
    # The first exchange was performed once, whatever the retries.
    assert world.plugin.executor.performed == [answers["asked"].operation.operation_id]


@pytest.mark.asyncio
async def test_a_bad_key_is_invalid_request_and_a_refusal_is_not_remembered() -> None:
    world, browser = direct_world()
    current = await world.signed_out_session()
    api = ApiClient(transport=world.transport)
    exchanges = "https://manzanita.example/api/orders/ord_7Hk2/exchanges"
    for bad in (key for key in FIXTURE["invalid_keys"] if key.isascii()):
        response = await world.transport.request(
            "POST",
            exchanges,
            session=current,
            headers={"Idempotency-Key": bad, "Content-Type": "application/json"},
            content=b"{}",
        )
        assert (response.status_code, response.json()["error"]) == (400, "invalid_request")
    key = new_idempotency_key()
    with pytest.raises(ApiError) as raised:
        await api.call("POST", exchanges, session=current, body={}, idempotency_key=key)
    assert raised.value.code == "insufficient_scope"
    # Signed in, the same key is a new request: the refusal was not kept.
    client = await begin(world, browser, current, ("orders:read", "orders:write"))
    callback = await world.shop.approve_authorization(browser.request_id, account_id="acct_ada")  # type: ignore[arg-type]
    signed_in = (await client.complete(callback)).token
    answer = await api.call(
        "POST", exchanges, session=current, token=signed_in, body={}, idempotency_key=key
    )
    assert answer.status == 403 and answer.operation is not None
