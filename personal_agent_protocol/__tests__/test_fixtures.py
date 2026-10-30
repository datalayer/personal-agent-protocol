# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The personal agent's side of the shared conformance fixtures, checked locally.

Fixture cases with a `check` are decided by the SDK alone (parsing, URL
safety, discovery over a mocked network). Cases with the `company` role are
run by the conformance runner against a company (`test_conformance.py`).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterable
from typing import Any

import httpcore
import httpx
import jwt
import pytest

from personal_agent_protocol import DiscoveryClient, SessionClient, SessionHttpClient
from personal_agent_protocol.apis import ApiClient, conversation_endpoint, known_apis
from personal_agent_protocol.conformance import load_fixture_cases
from personal_agent_protocol.crypto import DelegatedSessionSigner, InMemoryDelegatedKeys
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.errors import (
    PersonalAgentProtocolError,
    ProtocolValidationError,
    SessionError,
)
from personal_agent_protocol.extensions import (
    extension_name_kind,
    extension_required,
    negotiate_extensions,
)
from personal_agent_protocol.feedback import feedback_endpoint
from personal_agent_protocol.json import loads_strict
from personal_agent_protocol.models import (
    Author,
    ConversationEventPage,
    DiscoveryDocument,
    ExtensionDescriptor,
    Message,
    Operation,
)
from personal_agent_protocol.reactor import PublicUrlSafetyPolicy, SessionJwtRequest

LOCAL = [case for case in load_fixture_cases() if case.check is not None]


def _mock_network(responses: dict[str, dict[str, Any]]) -> httpx.AsyncClient:
    async def handler(request: httpx.Request) -> httpx.Response:
        answer = responses.get(str(request.url))
        if answer is None:
            return httpx.Response(404, json={"error": "not_found"})
        headers = dict(answer.get("headers", {}))
        if "json" in answer:
            body = json.dumps(answer["json"]).encode()
            body += b" " * int(answer.get("padding_bytes", 0))
            headers.setdefault("content-type", answer.get("content_type", "application/json"))
            if "trickle" in answer:
                return httpx.Response(
                    answer["status"], headers=headers, stream=_Trickle(body, **answer["trickle"])
                )
        else:
            body = str(answer.get("text", "")).encode()
            headers.setdefault("content-type", answer.get("content_type", "text/plain"))
        return httpx.Response(answer["status"], headers=headers, content=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class _Trickle(httpx.AsyncByteStream):
    """A body sent a few bytes at a time: a slow (or slowloris) server."""

    def __init__(self, body: bytes, *, chunk_bytes: int, interval_seconds: float) -> None:
        self.body, self.size, self.interval = body, chunk_bytes, interval_seconds

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for start in range(0, len(self.body), self.size):
            await asyncio.sleep(self.interval)
            yield self.body[start : start + self.size]


class _RecordingBackend(httpcore.AsyncNetworkBackend):
    """Record where each connection would go; connect nowhere."""

    def __init__(self) -> None:
        self.hosts: list[str] = []

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        self.hosts.append(host)
        raise httpcore.ConnectError("the test network connects nowhere")


async def _public(_: str) -> list[str]:
    return ["93.184.216.34"]


def _descriptors(values: dict[str, Any]) -> dict[str, ExtensionDescriptor]:
    return {name: ExtensionDescriptor.model_validate(value) for name, value in values.items()}


async def _check(case: Any) -> None:  # noqa: C901 - one branch per fixture check
    given, expect = case.input, case.expect
    if case.check == "discovery_document":
        if not expect["valid"]:
            with pytest.raises(ValueError):
                DiscoveryDocument.model_validate(given)
            return
        document = DiscoveryDocument.model_validate(given)
        for key, value in expect.get("extra", {}).items():
            assert (document.model_extra or {})[key] == value
        if "known_api_types" in expect:
            assert [api.type for api in known_apis(document)] == expect["known_api_types"]
        if "conversation_endpoint" in expect:
            assert conversation_endpoint(document) == expect["conversation_endpoint"]
        if "feedback_endpoint" in expect:
            assert feedback_endpoint(document) == expect["feedback_endpoint"]
    elif case.check == "extension_negotiation":
        negotiated = negotiate_extensions(
            _descriptors(given["company"]), _descriptors(given["agent"])
        )
        assert negotiated == expect["negotiated"]
    elif case.check == "extension_names":
        kinds: dict[str, list[str]] = {"plain": [], "third-party": [], "invalid": []}
        for name in given:
            kinds[extension_name_kind(name)].append(name)
        assert sorted(kinds["third-party"]) == expect["third_party"]
        assert sorted(kinds["plain"]) == expect["plain"]
        assert sorted(kinds["invalid"]) == sorted(expect["invalid"])
        preserved = _descriptors(
            {k: v for k, v in given.items() if extension_name_kind(k) != "invalid"}
        )
        assert preserved["example.com/gift-wrap"].model_extra == {"color": "red"}
    elif case.check == "extension_required":
        assert (
            extension_required(given["status"], given["body"], given.get("www_authenticate"))
            == expect["extension"]
        )
    elif case.check == "conversation_page":
        page = ConversationEventPage.model_validate(given)
        assert [event.type for event in page.events if event.known] == expect["known_types"]
        assert [event.type for event in page.events if not event.known] == expect["unknown_types"]
        assert (page.model_extra or {}) == {"region": "eu"}
    elif case.check == "message_context":
        for context in given["valid"]:
            assert (
                Message(id="msg_ctx", author=Author(type="agent"), context=context).context
                == context
            )
        for context in given["invalid"]:
            with pytest.raises(ValueError):
                Message(id="msg_ctx", author=Author(type="agent"), context=context)
    elif case.check == "operation":
        operation = Operation.model_validate(given)
        for key, value in expect.get("extra", {}).items():
            assert (operation.model_extra or {})[key] == value
    elif case.check == "discovery":
        http = _mock_network(given["responses"])
        client = DiscoveryClient(
            http_client=http,
            address_resolver=_public,
            timeout=float(given.get("timeout_seconds", 5.0)),
        )
        try:
            if "error" in expect:
                with pytest.raises(PersonalAgentProtocolError) as raised:
                    await client.discover(given["domain"])
                assert raised.value.code == expect["error"]
                return
            company = await client.discover(given["domain"])
        finally:
            await http.aclose()
        if "issuer" in expect and expect["issuer"] is None:
            # No issuer: a website to browse only (§3.2).
            assert company.oauth_metadata is None and company.resource_metadata is None
        elif "issuer" in expect:
            assert company.oauth_metadata is not None
            assert company.oauth_metadata.issuer == expect["issuer"]
        if "organization_domain" in expect:
            assert company.document.organization.domain == expect["organization_domain"]
        if "discovery_url" in expect:
            assert company.discovery_url == expect["discovery_url"]
    elif case.check == "url_safety":

        async def resolve(_: str) -> list[str]:
            return list(given["addresses"])

        policy = PublicUrlSafetyPolicy(resolve)
        if expect.get("safe"):
            await policy.assert_safe(given["url"])
            return
        with pytest.raises(PersonalAgentProtocolError) as raised:
            await policy.assert_safe(given["url"])
        assert raised.value.code == expect["error"]
    elif case.check == "pinned_connect":
        answers = [list(answer) for answer in given["answers"]]
        resolutions = 0

        async def rebinding(_: str) -> list[str]:
            nonlocal resolutions
            resolutions += 1
            return answers.pop(0)

        backend = _RecordingBackend()
        socket_transport = httpx.AsyncHTTPTransport()
        socket_transport._pool._network_backend = backend
        async with httpx.AsyncClient(transport=socket_transport) as http:
            client = DiscoveryClient(http_client=http, address_resolver=rebinding)
            with pytest.raises(PersonalAgentProtocolError) as raised:
                await client.discover(httpx.URL(given["url"]).host)
        assert raised.value.code == "request_failed"
        assert backend.hosts == expect["connects_to"]
        assert resolutions == expect["resolutions"]
    elif case.check == "strict_json":
        for document in given:
            with pytest.raises(ProtocolValidationError) as raised:
                loads_strict(document)
            assert raised.value.code == expect["error"]
    elif case.check == "rate_limited":

        async def limited(_: httpx.Request) -> httpx.Response:
            return httpx.Response(given["status"], headers=given["headers"], json=given["body"])

        identity = AgentIdentity(domain="atlas.example", name="Atlas")
        network = InProcessNetwork()
        http = httpx.AsyncClient(transport=httpx.MockTransport(limited))
        reactor = personal_agent_reactor(
            PersonalAgentHost(identity, MutableClock()), network=network, http_client=http
        )
        sessions = SessionClient(reactor=reactor, http_client=http)
        with pytest.raises(PersonalAgentProtocolError) as raised:
            await sessions.token_request(
                client_id=identity.client_id,
                issuer="https://shop.example",
                token_endpoint="https://shop.example/oauth/token",  # noqa: S106 - a URL
                form=lambda: {"grant_type": "refresh_token", "refresh_token": "rt_rate_limited"},
                error=SessionError,
                tenant_id="t",
                dpop_signing_algs=None,
            )
        assert raised.value.code == expect["error"]
        assert raised.value.details == {"retry_after": expect["retry_after"]}
        # An API call is not retried either: the caller is told how long to wait.
        session = await sessions.start(
            client_id=identity.client_id,
            pairwise_user_id="usr_rate_limited_0000000",
            issuer="https://shop.example",
            tenant_id="t",
        )
        with pytest.raises(PersonalAgentProtocolError) as refused:
            await ApiClient(transport=SessionHttpClient(reactor=reactor, http_client=http)).call(
                "GET", "https://shop.example/api/orders", session=session
            )
        await http.aclose()
        assert refused.value.code == expect["error"]
        assert refused.value.details == {"retry_after": expect["retry_after"]}
    elif case.check == "delegated_key_per_user_id":
        identity = AgentIdentity(domain="agent.example", name="Agent")
        signer = DelegatedSessionSigner(InMemoryDelegatedKeys(), signer=identity.signer())
        keys, delegations = set(), set()
        for item in given["requests"]:
            request = SessionJwtRequest(
                method="GET",
                url=f"{item['issuer']}/api/orders",
                tenant_id="t",
                issuer=item["issuer"],
                client_id=identity.client_id,
                sid="c2lkX2Zvcl90aGVfZml4dHVyZQ",
                sub=item["sub"],
            )
            header = jwt.get_unverified_header((await signer.sign(request)).get_secret_value())
            keys.add(header["kid"])
            delegations.add(
                jwt.decode(header["pap_dlg"], options={"verify_signature": False})["jti"]
            )
        assert len(keys) == expect["keys"]
        assert len(delegations) == expect["delegations"]
    else:  # pragma: no cover - a fixture with a check this test does not know
        raise AssertionError(f"unknown fixture check {case.check!r}")


@pytest.mark.asyncio
@pytest.mark.parametrize("case", LOCAL, ids=[case.id for case in LOCAL])
async def test_local_fixture_case(case: Any) -> None:
    await _check(case)


def test_every_fixture_case_is_local_or_run_by_the_conformance_runner() -> None:
    from personal_agent_protocol.conformance import CASES

    for case in load_fixture_cases():
        if case.check is None:
            assert case.id in CASES, f"{case.id} has neither a local check nor a runner case"
    fixture_ids = {case.id for case in load_fixture_cases()}
    assert set(CASES) <= fixture_ids, "every runner case is described by a fixture"
