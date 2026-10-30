# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Seeded fuzzing: strict JSON, URL safety, and the operation state machine (PAP plan §5).

Hypothesis is not a dependency of this repository, so the generators here are
plain seeded `random.Random`: every run is reproducible, and
`PAP_FUZZ_SEED` / `PAP_FUZZ_ITERATIONS` widen a local run
(`PAP_FUZZ_ITERATIONS=5000 pytest personal_agent_protocol/__tests__/test_fuzz.py`).
"""

# Seeded test data, not secrets; "0.0.0.0" is a generated address.
# ruff: noqa: S311, S104
from __future__ import annotations

import ipaddress
import json
import os
import random
import string
from typing import Any

import pytest

from personal_agent_protocol.conformance import _propose, _signed_in_user
from personal_agent_protocol.demo.conformance import ManzanitaConformance
from personal_agent_protocol.errors import (
    DiscoveryError,
    PersonalAgentProtocolError,
    ProtocolValidationError,
)
from personal_agent_protocol.json import loads_strict
from personal_agent_protocol.operations import OperationError, approve
from personal_agent_protocol.reactor import ApprovedUrl, PublicUrlSafetyPolicy

SEED = int(os.environ.get("PAP_FUZZ_SEED", "20261011"))
ITERATIONS = int(os.environ.get("PAP_FUZZ_ITERATIONS", "300"))
FINAL = {"succeeded", "failed", "cancelled", "expired"}


def _key(rng: random.Random) -> str:
    alphabet = string.ascii_letters + string.digits + "_-é ☃"
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 8)))


def _value(rng: random.Random, depth: int) -> Any:
    kind = rng.randrange(7 if depth < 3 else 4)
    if kind == 0:
        return rng.randint(-(10**12), 10**12)
    if kind == 1:
        return _key(rng)
    if kind == 2:
        return rng.choice([True, False, None])
    if kind == 3:
        return rng.random() * 1000
    if kind == 4:
        return [_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {_key(rng): _value(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def _escape(key: str, rng: random.Random) -> str:
    """The same member name, spelled differently on the wire (`\\u` escapes)."""

    return "".join(
        f"\\u{ord(c):04x}" if rng.random() < 0.5 and ord(c) < 0x10000 else c for c in key
    )


def _with_duplicate(rng: random.Random, value: Any) -> str | None:  # noqa: C901
    """Serialize `value` with one object member repeated, or `None` if it has no object."""

    objects: list[dict[str, Any]] = []

    def collect(node: Any) -> None:
        if isinstance(node, dict):
            objects.append(node)
            for child in node.values():
                collect(child)
        elif isinstance(node, list):
            for child in node:
                collect(child)

    collect(value)
    candidates = [node for node in objects if node]
    if not candidates:
        return None
    target = rng.choice(candidates)
    name = rng.choice(list(target))
    marker = object()
    target["\x00dup"] = marker

    def encode(node: Any) -> str:
        if node is marker:
            return json.dumps(rng.choice([1, "x", None]))
        if isinstance(node, dict):
            members = []
            for key, child in node.items():
                if key == "\x00dup":
                    members.append(f'"{_escape(name, rng)}":{encode(child)}')
                else:
                    members.append(f"{json.dumps(key)}:{encode(child)}")
            if node is target and rng.random() < 0.5:
                members.insert(0, members.pop())  # the repeat may come first
            return "{" + ",".join(members) + "}"
        if isinstance(node, list):
            return "[" + ",".join(encode(child) for child in node) + "]"
        return json.dumps(node)

    return encode(value)


def test_strict_json_accepts_every_unique_document_and_refuses_every_duplicate() -> None:
    rng = random.Random(SEED)
    refused = 0
    for _ in range(ITERATIONS):
        document = {_key(rng): _value(rng, 0) for _ in range(rng.randint(1, 5))}
        text = json.dumps(document, ensure_ascii=rng.random() < 0.5)
        assert loads_strict(text) == json.loads(text)
        assert loads_strict(text.encode()) == json.loads(text)
        duplicated = _with_duplicate(rng, document)
        if duplicated is None:
            continue
        with pytest.raises(ProtocolValidationError) as raised:
            loads_strict(duplicated)
        assert raised.value.code == "duplicate_json_member"
        refused += 1
    assert refused > ITERATIONS // 2


@pytest.mark.parametrize(
    "text", ["NaN", "[Infinity]", '{"a": -Infinity}', "", "{", '{"a" 1}', "\xff", "[1,]"]
)
def test_strict_json_refuses_what_rfc_8259_does_not_allow(text: str) -> None:
    with pytest.raises(ProtocolValidationError) as raised:
        loads_strict(text if text != "\xff" else b"\xff")
    assert raised.value.code == "invalid_json"


def test_strict_json_survives_random_bytes() -> None:
    rng = random.Random(SEED + 1)
    for _ in range(ITERATIONS):
        blob = bytes(rng.randrange(256) for _ in range(rng.randint(0, 40)))
        try:
            loads_strict(blob)
        except ProtocolValidationError as error:
            assert error.code in {"invalid_json", "duplicate_json_member"}


# URL safety ----------------------------------------------------------------------------

_ADDRESSES = [
    "93.184.216.34",
    "8.8.8.8",
    "2606:4700:4700::1111",
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.9",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "::1",
    "fd00::5",
    "fe80::1",
    "::ffff:127.0.0.1",
    "::ffff:93.184.216.34",
    "224.0.0.1",
    "255.255.255.255",
    "2001:db8::1",
]


def _url(rng: random.Random) -> str:
    scheme = rng.choice(["https", "https", "https", "http", "HTTPS", "ftp", "javascript", ""])
    user = rng.choice(["", "", "", "ada@", "ada:secret@", ":@"])
    host = rng.choice(
        [
            "company.example",
            "a.b.company.example",
            "localhost",
            "[::1]",
            "127.0.0.1",
            "",
            "xn--caf-dma.example",
            "company.example.",
        ]
    )
    port = rng.choice(["", "", ":443", ":8443", ":0", ":99999", ":x"])
    path = rng.choice(["/.well-known/poppy.json", "", "/a b", "/%2e%2e/", "?q=1", "#frag"])
    separator = "://" if scheme else rng.choice(["//", ""])
    return f"{scheme}{separator}{user}{host}{port}{path}"


@pytest.mark.asyncio
async def test_url_safety_approves_only_https_public_addresses() -> None:
    rng = random.Random(SEED + 2)
    for _ in range(ITERATIONS):
        url = _url(rng)
        addresses = rng.sample(_ADDRESSES, rng.randint(1, 3))
        allow_private = rng.random() < 0.2

        async def resolve(_: str, answer: list[str] = addresses) -> list[str]:
            return answer

        policy = PublicUrlSafetyPolicy(resolve, allow_private_networks=allow_private)
        try:
            approved = await policy.assert_safe(url)
        except DiscoveryError as error:
            assert error.code in {"unsafe_url", "unsafe_address", "dns_failed"}, (url, error.code)
            continue
        except ValueError:
            continue  # urlsplit refuses some ports before any policy decision
        assert isinstance(approved, ApprovedUrl)
        assert url.lower().startswith("https://") and "@" not in url.split("/")[2]
        assert approved.addresses == tuple(str(ipaddress.ip_address(a)) for a in addresses)
        if not allow_private:
            assert all(ipaddress.ip_address(a).is_global for a in addresses), (url, addresses)


# The operation state machine -------------------------------------------------------------


@pytest.mark.asyncio
async def test_random_operation_histories_keep_the_state_machine() -> None:  # noqa: C901
    """Confirm, cancel, revise and time passing, in any order: the invariants hold.

    A final state never changes; an operation is performed at most once; only a
    confirmed operation carries a confirmation; a stale revision never confirms.
    """

    rng = random.Random(SEED + 3)
    world = ManzanitaConformance()
    ctx = world.context()
    endpoint = await ctx.operations_endpoint()
    histories = max(8, ITERATIONS // 30)
    for _ in range(histories):
        user, signed = await _signed_in_user(ctx)
        kind = rng.choice(["user", "user", "fails", "unknown"])
        first = await _propose(ctx, user, signed, kind)
        latest = first
        final: Any = None
        for _ in range(rng.randint(1, 6)):
            action = rng.choice(["confirm", "confirm_stale", "cancel", "revise", "wait"])
            try:
                if action == "confirm":
                    await ctx.agent.operations.confirm(
                        endpoint,
                        latest,
                        approval=approve(latest),
                        session=signed.session,
                        token=signed.token,
                    )
                elif action == "confirm_stale":
                    outcome = await ctx.agent.operations.confirm(
                        endpoint,
                        first,
                        approval=approve(first),
                        session=signed.session,
                        token=signed.token,
                    )
                    if first.revision != latest.revision and outcome.status == "confirmed":
                        raise AssertionError("a stale revision confirmed")
                elif action == "cancel":
                    await ctx.agent.operations.cancel(
                        endpoint, first.operation_id, session=signed.session, token=signed.token
                    )
                elif action == "revise":
                    await world.driver.revise(first.operation_id)
                else:
                    world.clock.advance(rng.choice([1, 60, 600, 1200]))
            except (OperationError, PersonalAgentProtocolError, ValueError, KeyError):
                pass  # a refusal is fine; the invariants below are what matter
            if action == "wait":
                refreshed = await ctx.agent.accounts.refresh(
                    signed.reference,
                    context=await ctx.account_context(user),
                )
                if refreshed.token is not None:
                    signed.token = refreshed.token
            current = await ctx.agent.operations.read(
                endpoint, first.operation_id, session=signed.session, token=signed.token
            )
            if current.state == "proposed":
                latest = current
            assert current.revision >= latest.revision
            if final is not None:
                assert current == final, "a final operation never changes"
            if current.state in FINAL:
                final = current
            if current.confirmation is not None:
                assert current.state in {"succeeded", "failed", "in_progress"}
            else:
                assert current.state not in {"succeeded", "failed"}
            assert await world.driver.performed(first.operation_id) <= 1
