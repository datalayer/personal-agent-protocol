# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Operator signatures (§5.3, RFC 9421, Web Bot Auth): what each side does with one."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, cast

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import SecretStr
from reactor import PluginManifest, PluginPlatform  # type: ignore[import-untyped]

from personal_agent_protocol import (
    OPERATOR_SIGNERS,
    SESSION_SIGNERS,
    Ed25519OperatorKey,
    OperatorSignatureRequest,
    PapSession,
    SessionHttpClient,
    TransportError,
    WebBotAuthSigner,
    build_pap_reactor,
    new_operator_key,
    operator_directory,
    operator_key_from,
    sign_operator_request,
    verify_operator_signature,
)
from personal_agent_protocol.company import CompanyConfig
from personal_agent_protocol.errors import DiscoveryError, IdentityError, ProtocolValidationError
from personal_agent_protocol.identity import MAX_OPERATOR_KEYS, AgentIdentityClient
from personal_agent_protocol.operator_signatures import (
    OPERATOR_DIRECTORY_MEDIA_TYPE,
    OPERATOR_DIRECTORY_PATH,
    SIGNATURE_AGENT_HEADER,
    SIGNATURE_HEADER,
    SIGNATURE_INPUT_HEADER,
    accept_signature,
)
from personal_agent_protocol.transport import session_headers

NOW = datetime(2026, 10, 31, 12, 0, tzinfo=timezone.utc)
STAMP = int(NOW.timestamp())
URL = "https://shop.example/api/orders?limit=2"
AGENT = "https://agent.example/operator-keys.json"
SESSION_JWT = "session.jwt.value"
TOKEN = "Bearer a-token"


def _request(authorization: str | None = TOKEN) -> OperatorSignatureRequest:
    return OperatorSignatureRequest(
        method="GET",
        url=URL,
        tenant_id="tenant",
        session_jwt=SecretStr(SESSION_JWT),
        authorization=None if authorization is None else SecretStr(authorization),
    )


async def _headers(
    key: Ed25519OperatorKey, authorization: str | None = TOKEN, **options: Any
) -> dict[str, str]:
    signed = await sign_operator_request(
        _request(authorization),
        key,
        signature_agent=options.pop("signature_agent", AGENT),
        created=options.pop("created", STAMP),
        expires=options.pop("expires", STAMP + 60),
        nonce="nonce",
        **options,
    )
    headers = {
        "poppy-session": SESSION_JWT,
        "signature-agent": signed.signature_agent,
        "signature-input": signed.signature_input,
        "signature": signed.signature,
    }
    if authorization is not None:
        headers["authorization"] = authorization
    return headers


def _keys(*known: Ed25519OperatorKey) -> Any:
    async def keys(url: str, keyid: str) -> list[dict[str, Any]]:
        assert url == AGENT
        return list(operator_directory(list(known))["keys"])

    return keys


async def _verdict(headers: dict[str, str], keys: Any) -> Any:
    return await verify_operator_signature(
        method="GET", url=URL, headers=headers, keys=keys, now=NOW
    )


@pytest.mark.asyncio
async def test_a_signature_verifies_and_names_its_key_source() -> None:
    key = new_operator_key()
    verdict = await _verdict(await _headers(key), _keys(key))
    assert (verdict.outcome, verdict.operator) == ("verified", AGENT)


@pytest.mark.asyncio
async def test_what_a_signed_request_is_refused_for() -> None:
    key = new_operator_key()
    good = await _headers(key)
    for changed in (
        {"poppy-session": "another.jwt.value"},
        {"authorization": "Bearer another-token"},
        {"signature-input": good["signature-input"].replace('"@method"', '"@method')},
        {"signature-input": f"{good['signature-input']},"},
        {"signature-input": ", ".join(f"s{n}=()" for n in range(9))},
        {"signature": "sig1=:!!!!:"},
        {"signature": "sig2=:AAAA:"},
        {"signature-agent": "sig1=http"},
        {"signature-agent": 'sig1="http://agent.example/keys"'},
        {"signature-agent": f'sig1="{AGENT}";type=jwks_uri'},
    ):
        assert (await _verdict({**good, **changed}, _keys(key))).outcome == "invalid", changed


@pytest.mark.asyncio
async def test_a_request_with_a_token_needs_it_covered_but_one_without_does_not() -> None:
    key = new_operator_key()
    assert (await _verdict(await _headers(key, None), _keys(key))).outcome == "verified"
    plain = await _headers(key, None)
    with_token = {**plain, "authorization": TOKEN}
    assert (await _verdict(with_token, _keys(key))).outcome == "invalid"


@pytest.mark.asyncio
async def test_no_signature_or_another_profiles_is_absent() -> None:
    key = new_operator_key()
    assert (await _verdict({"poppy-session": SESSION_JWT}, _keys(key))).outcome == "absent"
    other = await _headers(key, tag="another-profile")
    assert (await _verdict(other, _keys(key))).outcome == "absent"


@pytest.mark.asyncio
async def test_no_key_to_decide_with_is_unverified() -> None:
    key = new_operator_key()
    good = await _headers(key)
    assert (await _verdict(good, _keys())).outcome == "unverified"

    async def outage(url: str, keyid: str) -> list[dict[str, Any]]:
        raise DiscoveryError("metadata_timeout", "no answer")

    assert (await _verdict(good, outage)).outcome == "unverified"
    other = good["signature-input"].replace('alg="ed25519"', 'alg="rsa-pss-sha512"')
    assert (await _verdict({**good, "signature-input": other}, _keys(key))).outcome == "unverified"


@pytest.mark.asyncio
async def test_a_signature_agent_that_is_no_url_decides_nothing() -> None:
    client = AgentIdentityClient()
    key = new_operator_key()
    good = await _headers(key)
    headers = {**good, "signature-agent": 'sig1="https://[nonsense"'}

    async def keys(url: str, keyid: str) -> list[dict[str, Any]]:
        return await client.fetch_operator_keys(url, keyid=keyid)

    assert (await _verdict(headers, keys)).outcome == "unverified"
    await client.aclose()


@pytest.mark.asyncio
async def test_freshness_is_the_verifiers_clock_and_window() -> None:
    key = new_operator_key()
    for created, expires, outcome in (
        (STAMP - 120, STAMP - 60, "invalid"),
        (STAMP - 60, STAMP, "invalid"),
        (STAMP + 61, STAMP + 120, "invalid"),
        (STAMP + 60, STAMP + 120, "verified"),
        (STAMP, STAMP, "invalid"),
    ):
        headers = await _headers(key, created=created, expires=expires)
        assert (await _verdict(headers, _keys(key))).outcome == outcome, (created, expires)


@pytest.mark.asyncio
async def test_one_verified_signature_of_several_is_enough() -> None:
    key = new_operator_key()
    good = await _headers(key)
    extra = 'proxy=("@authority");created=1;tag="another-profile"'
    headers = {**good, "signature-input": f"{extra}, {good['signature-input']}"}
    assert (await _verdict(headers, _keys(key))).outcome == "verified"


def test_a_signature_agent_is_an_https_url_and_keys_are_ed25519() -> None:
    key = operator_key_from(Ed25519PrivateKey.generate())
    assert operator_directory([key])["keys"][0]["kid"] == key.keyid
    assert "d" not in operator_directory([key])["keys"][0]
    assert OPERATOR_DIRECTORY_PATH == "/.well-known/http-message-signatures-directory"


@pytest.mark.asyncio
@pytest.mark.parametrize("agent", ["http://agent.example/keys", 'https://agent.example/"'])
async def test_a_signer_refuses_a_signature_agent_it_cannot_write(agent: str) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        await _headers(new_operator_key(), signature_agent=agent)


def test_accept_signature_asks_for_what_this_request_should_cover() -> None:
    assert '"authorization"' in accept_signature({"authorization": TOKEN})
    asked = accept_signature({})
    assert '"poppy-session"' in asked and '"authorization"' not in asked
    assert asked.endswith(';created;expires;tag="web-bot-auth"')


def test_a_company_takes_off_optional_or_required() -> None:
    with pytest.raises(ValueError, match="operator_signatures"):
        CompanyConfig(
            domain="shop.example",
            name="Shop",
            scopes=("orders:read",),
            operator_signatures=cast(Any, "sometimes"),
        )


# The transport ---------------------------------------------------------------------------


class _Sessions:
    async def sign(self, request: Any) -> SecretStr:
        return SecretStr(f"jwt.{request.sid}.value")


def _session() -> PapSession:
    return PapSession(
        sid="S" * 22,
        sub="usr_pairwise",
        issuer="https://shop.example",
        client_id="https://agent.example/agent.json",
        tenant_id="tenant",
    )


class _Host:
    def __init__(self, operator: object | None) -> None:
        self.operator = operator

    def provide_contributions(self, contributions: Any) -> None:
        contributions.contribute(SESSION_SIGNERS, _Sessions(), contribution_id="sessions")
        if self.operator is not None:
            contributions.contribute(OPERATOR_SIGNERS, self.operator, contribution_id="operator")


def _reactor(operator: object | None, http: httpx.AsyncClient) -> PluginPlatform:
    from reactor import hookimpl  # type: ignore[import-untyped]

    class Plugin(_Host):
        @hookimpl
        def provide_contributions(self, contributions: Any) -> None:
            super().provide_contributions(contributions)

    reactor, _ = build_pap_reactor(
        http_client=http,
        plugins=[(PluginManifest(name="host", version="1"), Plugin(operator))],
    )
    return reactor


@pytest.mark.asyncio
async def test_with_no_signer_contributed_requests_go_unsigned() -> None:
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    headers = await session_headers(
        _reactor(None, http), "GET", URL, session=_session(), token=None
    )
    assert list(headers) == ["Poppy-Session"]
    await http.aclose()


@pytest.mark.asyncio
async def test_every_attempt_is_signed_anew_and_covers_the_session_jwt_it_carries() -> None:
    sent: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        if len(sent) == 1:
            return httpx.Response(400, json={"error": "invalid_session"})
        return httpx.Response(200, json={})

    http = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    key = new_operator_key()
    signer = WebBotAuthSigner(key, signature_agent=AGENT, now=lambda: NOW)
    client = SessionHttpClient(reactor=_reactor(signer, http), http_client=http)
    answer = await client.request("POST", URL, session=_session(), content=b"{}")
    assert answer.status_code == 200
    assert len(sent) == 2
    assert sent[0].headers[SIGNATURE_INPUT_HEADER] != sent[1].headers[SIGNATURE_INPUT_HEADER]
    for request in sent:
        headers = {name.lower(): value for name, value in request.headers.items()}
        verdict = await verify_operator_signature(
            method="POST", url=URL, headers=headers, keys=_keys(key), now=NOW
        )
        assert verdict.outcome == "verified"
    await http.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name", [SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SIGNATURE_AGENT_HEADER.upper()]
)
async def test_a_caller_never_sets_the_signature_headers(name: str) -> None:
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))
    client = SessionHttpClient(reactor=_reactor(None, http), http_client=http)
    with pytest.raises(TransportError, match="host-owned"):
        await client.request("GET", URL, session=_session(), headers={name: "x"})
    await http.aclose()


@pytest.mark.asyncio
async def test_a_signer_needs_an_aware_clock_and_real_randomness() -> None:
    key = new_operator_key()
    naive = WebBotAuthSigner(key, signature_agent=AGENT, now=lambda: NOW.replace(tzinfo=None))
    with pytest.raises(Exception, match="aware"):
        await naive.sign(_request())
    weak = WebBotAuthSigner(key, signature_agent=AGENT, random_bytes=lambda _: b"")
    with pytest.raises(Exception, match="256 bits"):
        await weak.sign(_request())
    with pytest.raises(ValueError, match="lifetime"):
        WebBotAuthSigner(key, signature_agent=AGENT, lifetime=timedelta(0))


# The directory ---------------------------------------------------------------------------


class _Directory:
    """A directory whose answer changes, counting its fetches."""

    def __init__(self, document: object, *, status: int = 200) -> None:
        self.document = document
        self.status = status
        self.fetches = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.fetches += 1
        return httpx.Response(
            self.status,
            content=json.dumps(self.document),
            headers={
                "Cache-Control": "max-age=3600",
                "Content-Type": OPERATOR_DIRECTORY_MEDIA_TYPE,
                "Location": "https://elsewhere.example/",
            },
        )


async def _public(_: str) -> list[str]:
    return ["93.184.216.34"]


def _client(directory: _Directory) -> tuple[AgentIdentityClient, httpx.AsyncClient]:
    http = httpx.AsyncClient(transport=httpx.MockTransport(directory))
    return AgentIdentityClient(http_client=http, address_resolver=_public), http


@pytest.mark.asyncio
async def test_a_directory_is_cached_read_again_for_a_new_key_and_kept_through_an_outage() -> None:
    first, second = new_operator_key(), new_operator_key()
    directory = _Directory(operator_directory([first]))
    client, http = _client(directory)
    assert await client.fetch_operator_keys(AGENT, keyid=first.keyid)
    assert await client.fetch_operator_keys(AGENT, keyid=first.keyid)
    assert directory.fetches == 1

    directory.status = 503
    with pytest.raises(IdentityError):
        await client.fetch_operator_keys(AGENT, keyid=second.keyid)
    assert directory.fetches == 2
    # The outage kept the cached set, and a stream of unknown keys fetches no more.
    assert await client.fetch_operator_keys(AGENT, keyid=second.keyid)
    assert await client.fetch_operator_keys(AGENT, keyid=first.keyid)
    assert directory.fetches == 2
    await http.aclose()


@pytest.mark.asyncio
async def test_a_directory_that_cannot_be_read_is_not_fetched_for_every_request() -> None:
    key = new_operator_key()
    directory = _Directory({}, status=404)
    client, http = _client(directory)
    for _ in range(3):
        with pytest.raises(IdentityError):
            await client.fetch_operator_keys(AGENT, keyid=key.keyid)
    assert directory.fetches == 1
    await http.aclose()


@pytest.mark.asyncio
async def test_a_directory_never_redirects_and_is_bounded_and_public() -> None:
    key = new_operator_key()
    client, http = _client(_Directory({}, status=302))
    with pytest.raises(IdentityError):
        await client.fetch_operator_keys(AGENT, keyid=key.keyid)
    await http.aclose()

    jwk = operator_directory([key])["keys"][0]
    client, http = _client(_Directory({"keys": [jwk] * (MAX_OPERATOR_KEYS + 1)}))
    with pytest.raises(ProtocolValidationError):
        await client.fetch_operator_keys(AGENT, keyid=key.keyid)
    await http.aclose()

    other = {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}
    client, http = _client(_Directory({"keys": [other, {**jwk, "d": "secret"}]}))
    assert await client.fetch_operator_keys(AGENT, keyid=key.keyid) == []
    await http.aclose()
