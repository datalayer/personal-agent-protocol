# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Everything sent to a company goes through the resolving transport (PAP_DATALAYER V-06).

Metadata was always fetched on the safe path; `create_resolving_client` puts
the rest there too — Sessions, conversations, API calls, Operations, MCP: the
host resolved and refused unless every address is public, nothing sent, and
the connection pinned to what was approved.
"""

from __future__ import annotations

import httpx
import pytest

from personal_agent_protocol import ResolvingTransport, create_resolving_client
from personal_agent_protocol.errors import DiscoveryError
from personal_agent_protocol.reactor import PinnedNetworkBackend

#: Loopback, private networks, a Kubernetes service range (EKS 172.20/16, the
#: kubeadm default 10.96/12), link-local cloud metadata, and IPv6 equivalents.
INTERNAL = (
    "10.0.0.5",
    "127.0.0.1",
    "172.20.0.10",
    "10.96.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "::1",
    "fd00::1",
    "::ffff:10.0.0.5",
)


def _company(sent: list[httpx.Request]) -> httpx.MockTransport:
    def answer(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={"ok": True})

    return httpx.MockTransport(answer)


def _resolving_to(*addresses: str):  # type: ignore[no-untyped-def]
    async def resolve(host: str) -> list[str]:
        return list(addresses)

    return resolve


@pytest.mark.asyncio
@pytest.mark.parametrize("address", INTERNAL)
async def test_a_company_resolving_inside_is_refused_and_sent_nothing(address: str) -> None:
    sent: list[httpx.Request] = []
    async with create_resolving_client(
        resolver=_resolving_to(address), transport=_company(sent)
    ) as http:
        for method, body in (("GET", None), ("POST", b'{"text": "hello"}')):
            with pytest.raises(DiscoveryError) as raised:
                await http.request(
                    method, "https://company.example/pap/conversations", content=body
                )
            assert raised.value.code == "unsafe_address"
    assert sent == []


@pytest.mark.asyncio
async def test_one_internal_address_among_public_ones_is_refused() -> None:
    sent: list[httpx.Request] = []
    async with create_resolving_client(
        resolver=_resolving_to("93.184.216.34", "10.0.0.5"), transport=_company(sent)
    ) as http:
        with pytest.raises(DiscoveryError) as raised:
            await http.get("https://company.example/api/orders")
    assert raised.value.code == "unsafe_address" and sent == []


@pytest.mark.asyncio
async def test_a_public_company_is_reached_and_plain_http_is_not() -> None:
    sent: list[httpx.Request] = []
    async with create_resolving_client(
        resolver=_resolving_to("93.184.216.34"), transport=_company(sent)
    ) as http:
        answered = await http.post(
            "https://company.example/pap/operations/op_1/confirm", content=b"{}"
        )
        assert answered.json() == {"ok": True}
        with pytest.raises(DiscoveryError) as raised:
            await http.get("http://company.example/api/orders")
        assert raised.value.code == "unsafe_url"
    assert [str(request.url) for request in sent] == [
        "https://company.example/pap/operations/op_1/confirm"
    ]


@pytest.mark.asyncio
async def test_a_name_that_rebinds_inside_is_refused_on_the_next_request() -> None:
    """Each request is vetted again: a company that answered from a public
    address and then points its name inside is refused, never retried."""

    answers = iter((["93.184.216.34"], ["10.0.0.5"]))

    async def rebinding(host: str) -> list[str]:
        return next(answers)

    sent: list[httpx.Request] = []
    async with create_resolving_client(resolver=rebinding, transport=_company(sent)) as http:
        await http.get("https://company.example/api/orders")
        with pytest.raises(DiscoveryError) as raised:
            await http.get("https://company.example/api/orders")
    assert raised.value.code == "unsafe_address" and len(sent) == 1


@pytest.mark.asyncio
async def test_an_unresolvable_company_is_dns_failed() -> None:
    async def nowhere(host: str) -> list[str]:
        raise DiscoveryError("dns_failed", "Could not resolve discovery host")

    async with create_resolving_client(resolver=nowhere, transport=_company([])) as http:
        with pytest.raises(DiscoveryError) as raised:
            await http.get("https://company.example/api/orders")
    assert raised.value.code == "dns_failed"


def test_the_client_follows_no_redirect_and_no_proxy_and_its_sockets_are_pinned() -> None:
    http = create_resolving_client()
    assert http.follow_redirects is False and http._mounts == {}
    transport = http._transport
    assert isinstance(transport, ResolvingTransport)
    backend = transport._inner._pool._network_backend  # type: ignore[attr-defined]
    assert isinstance(backend, PinnedNetworkBackend)


@pytest.mark.asyncio
async def test_a_bounded_client_reads_no_body_past_its_limit() -> None:
    from personal_agent_protocol.errors import TransportError

    def answer(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/declared":
            return httpx.Response(200, content=b"a" * 2048)
        # Sent in chunks with no length declared: refused while reading.
        return httpx.Response(200, stream=_Chunks(b"a" * 512, 4))

    async with create_resolving_client(
        resolver=_resolving_to("93.184.216.34"),
        transport=httpx.MockTransport(answer),
        max_response_bytes=1024,
    ) as http:
        for path in ("/declared", "/chunked"):
            with pytest.raises(TransportError) as raised:
                await http.get(f"https://company.example{path}")
            assert raised.value.code == "response_too_large"
    async with create_resolving_client(
        resolver=_resolving_to("93.184.216.34"),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"a" * 1024)),
        max_response_bytes=1024,
    ) as http:
        assert len((await http.get("https://company.example/at-the-limit")).content) == 1024


class _Chunks(httpx.AsyncByteStream):
    def __init__(self, chunk: bytes, count: int) -> None:
        self.chunk, self.count = chunk, count

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        for _ in range(self.count):
            yield self.chunk
