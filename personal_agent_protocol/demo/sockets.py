# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Serve an `InProcessNetwork` over real sockets and real TLS, on this machine.

`served_over_tls(network)` starts one uvicorn server on `127.0.0.1` with a
certificate for every domain on the network, issued by a throwaway CA, and
routes each request by its `Host` to that domain's application. While it
runs, every client of the network dials that server, keeping each domain's
own name for SNI and certificate verification: every party
— personal agents and companies alike — then talks over TCP and TLS exactly as
it would across the internet, with no change to their code.

Needs the `server` extra (uvicorn).
"""

from __future__ import annotations

import asyncio
import datetime
import socket
import ssl
import tempfile
from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpcore
import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .kit import InProcessNetwork


def _certificates(domains: Iterable[str], directory: Path) -> tuple[Path, Path, Path]:
    """A CA, and a leaf for every domain it signs: (ca.pem, cert.pem, key.pem)."""

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAP demo CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    names = sorted(set(domains))
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = (
        directory / "ca.pem",
        directory / "cert.pem",
        directory / "key.pem",
    )
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return ca_path, cert_path, key_path


class _DialLocal(httpcore.AsyncNetworkBackend):
    """Connect every network domain to the local server; TLS still names the domain."""

    def __init__(self, domains: frozenset[str], port: int) -> None:
        self.domains = domains
        self.port = port
        self.backend = httpcore.AnyIOBackend()

    async def connect_tcp(self, host: str, port: int, **kwargs: Any) -> httpcore.AsyncNetworkStream:
        if host not in self.domains:
            raise httpcore.ConnectError(f"{host} is not on the network")
        return await self.backend.connect_tcp("127.0.0.1", self.port, **kwargs)

    async def connect_unix_socket(self, path: str, **kwargs: Any) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("no unix sockets on the demo network")

    async def sleep(self, seconds: float) -> None:
        await self.backend.sleep(seconds)


def _by_host(network: InProcessNetwork) -> Any:
    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            while (message := await receive())["type"] != "lifespan.shutdown":
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
            await send({"type": "lifespan.shutdown.complete"})
            return
        host = dict(scope["headers"]).get(b"host", b"").decode().split(":", 1)[0]
        target = network.apps.get(host)
        if target is None:
            await send({"type": "http.response.start", "status": 421, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        await target(scope, receive, send)

    return app


@asynccontextmanager
async def served_over_tls(network: InProcessNetwork) -> AsyncIterator[InProcessNetwork]:
    """Serve the network over TCP and TLS while the block runs."""

    import uvicorn  # the `server` extra

    with tempfile.TemporaryDirectory() as directory:
        ca, cert, key = _certificates(network.apps, Path(directory))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Accepted connections inherit it: no Nagle wait on each small TLS record.
        listener.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(
            uvicorn.Config(
                _by_host(network),
                ssl_certfile=str(cert),
                ssl_keyfile=str(key),
                log_level="warning",
                lifespan="on",
            )
        )
        task = asyncio.create_task(server.serve(sockets=[listener]))
        while not server.started:
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
        context = ssl.create_default_context(cafile=str(ca))
        domains = frozenset(network.apps)

        transport = httpx.AsyncHTTPTransport(verify=context)
        transport._pool._network_backend = _DialLocal(domains, port)
        network.socket_transport = transport
        try:
            yield network
        finally:
            network.socket_transport = None
            await transport.aclose()
            server.should_exit = True
            await task
            listener.close()
