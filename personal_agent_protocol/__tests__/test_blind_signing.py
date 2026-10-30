# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Blind signing (§10.7, RFC 9474): ordinary `PS384`, and a key that never sees the JWT."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from personal_agent_protocol import (
    BlindJoseSigner,
    ConversationClient,
    DeviceSignInClient,
    DiscoveryClient,
    RefreshTokenClient,
    RefreshTokenContext,
    SessionClient,
    SessionHttpClient,
)
from personal_agent_protocol.blind import RsaBlindSigningKey
from personal_agent_protocol.crypto import DelegatedSessionSigner, InMemoryDelegatedKeys
from personal_agent_protocol.demo.kit import (
    AgentIdentity,
    InProcessNetwork,
    MutableClock,
    PersonalAgentHost,
    personal_agent_reactor,
)
from personal_agent_protocol.demo.manzanita import manzanita
from personal_agent_protocol.errors import ProofError
from personal_agent_protocol.models import Author, Message
from personal_agent_protocol.reactor import SessionJwtRequest
from personal_agent_protocol.sessions import build_client_assertion_claims

#: One key for the module: an RSA key takes a moment to make.
PRIVATE = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class WatchingKey(RsaBlindSigningKey):
    """The key holder, keeping everything it was ever sent."""

    def __init__(self) -> None:
        super().__init__(PRIVATE)
        self.seen: list[bytes] = []

    async def blind_sign(self, blinded: bytes) -> bytes:
        self.seen.append(blinded)
        return await super().blind_sign(blinded)


def signer(key: WatchingKey) -> BlindJoseSigner:
    return BlindJoseSigner(key, public_key=key.public_key, key_id="blind-1")


def assertion_claims(client_id: str = "https://agent.example/agent.json") -> dict[str, object]:
    return build_client_assertion_claims(
        client_id=client_id, issuer="https://shop.example"
    ).model_dump()


@pytest.mark.asyncio
async def test_a_blind_signature_verifies_as_ordinary_ps384() -> None:
    key = WatchingKey()
    claims = assertion_claims()
    compact = (await signer(key).sign(claims, purpose="client_assertion")).get_secret_value()
    assert jwt.get_unverified_header(compact) == {"alg": "PS384", "typ": "JWT", "kid": "blind-1"}
    decoded = jwt.decode(
        compact,
        PRIVATE.public_key(),
        algorithms=["PS384"],
        audience="https://shop.example",
        options={"verify_exp": False, "verify_iat": False},
    )
    assert decoded == claims


@pytest.mark.asyncio
async def test_the_key_holder_sees_only_the_blinded_message() -> None:
    """The same JWT signed twice blinds differently; nothing of it reaches the key."""

    key = WatchingKey()
    claims = assertion_claims()
    first = (await signer(key).sign(claims, purpose="client_assertion")).get_secret_value()
    await signer(key).sign(claims, purpose="client_assertion")
    assert len(key.seen) == 2 and key.seen[0] != key.seen[1]
    signing_input = first.rsplit(".", 1)[0].encode()
    payload = base64.urlsafe_b64decode(first.split(".")[1] + "==")
    for blinded in key.seen:
        for part in (signing_input, payload, b"shop.example", str(claims["jti"]).encode()):
            assert part not in blinded
        assert len(blinded) == PRIVATE.key_size // 8


@pytest.mark.asyncio
async def test_a_delegation_is_signed_blindly_too() -> None:
    """One signer, both purposes (§10.7): the delegation has its own `typ`."""

    key = WatchingKey()
    delegated = DelegatedSessionSigner(InMemoryDelegatedKeys(), signer=signer(key))
    await delegated.sign(
        SessionJwtRequest(
            method="GET",
            url="https://shop.example/api/orders",
            tenant_id="t",
            issuer="https://shop.example",
            client_id="https://agent.example/agent.json",
            sid="Yx2b7Qd_Kp8mR3vT1nWc4A",
            sub="usr_1",
        )
    )
    assert len(key.seen) == 1


@pytest.mark.asyncio
async def test_no_jti_from_the_device_no_signature() -> None:
    """The variant is safe only with a value the signer can't guess (§10.7, RFC 9474 §7.3)."""

    key = WatchingKey()
    for claims in ({"iss": "x"}, {"iss": "x", "jti": "short"}):
        with pytest.raises(ProofError, match="weak_randomness"):
            await signer(key).sign(claims, purpose="client_assertion")
    assert key.seen == []


@pytest.mark.asyncio
async def test_a_wrong_answer_never_leaves_the_device() -> None:
    class Lying(WatchingKey):
        async def blind_sign(self, blinded: bytes) -> bytes:
            return (await super().blind_sign(blinded))[::-1]

    key = Lying()
    with pytest.raises(ProofError, match="signing_failed"):
        await signer(key).sign(assertion_claims(), purpose="client_assertion")


def test_a_short_key_is_refused() -> None:
    short = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - refused
    with pytest.raises(ValueError, match="2048"):
        RsaBlindSigningKey(short)


@dataclass(eq=False)
class BlindIdentity(AgentIdentity):
    """An agent whose `jwks_uri` key is RSA, and signs blindly."""

    holder: WatchingKey = field(default_factory=WatchingKey)
    kid: str = "blind-1"

    @property
    def jwks(self) -> dict[str, Any]:
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(PRIVATE.public_key()))
        return {"keys": [{**public, "kid": self.kid, "use": "sig", "alg": "PS384"}]}

    def signer(self) -> BlindJoseSigner:  # type: ignore[override]
        return signer(self.holder)


@pytest.mark.asyncio
async def test_a_company_takes_an_agent_that_signs_everything_blindly() -> None:
    """Device Sign-In, a refresh, and a signed-in call: every signature is a blind one."""

    clock = MutableClock()
    network = InProcessNetwork()
    atlas = BlindIdentity(domain="atlas.example", name="Atlas")
    network.add(atlas.domain, atlas.website())
    shop, _ = manzanita(network, clock)
    http = network.client()
    reactor = personal_agent_reactor(
        PersonalAgentHost(atlas, clock), network=network, http_client=http
    )
    company = await DiscoveryClient(reactor=reactor, http_client=http).discover("manzanita.example")
    metadata = company.oauth_metadata
    assert metadata is not None
    device = DeviceSignInClient(reactor=reactor, http_client=http)
    started = await device.begin(
        device_authorization_endpoint=str(metadata.device_authorization_endpoint),
        token_endpoint=metadata.token_endpoint,
        issuer=metadata.issuer,
        client_id=atlas.client_id,
        scopes=("orders:read",),
        tenant_id="t",
        organization=company.document.organization,
        protected_resources=metadata.protected_resources,
    )
    await shop.approve_device(started.user_code, account_id="acct_ada")
    clock.advance(started.poll_interval)
    done = await device.poll(started.reference)
    assert done.status == "complete" and done.refresh_token_reference is not None
    refreshed = await RefreshTokenClient(reactor=reactor, http_client=http).refresh(
        done.refresh_token_reference,
        context=RefreshTokenContext(
            token_endpoint=metadata.token_endpoint,
            issuer=metadata.issuer,
            client_id=atlas.client_id,
            tenant_id="t",
        ),
    )
    assert refreshed.status == "signed_in"
    session = await SessionClient(reactor=reactor, http_client=http).start(
        client_id=atlas.client_id,
        pairwise_user_id="usr_ada_blind",
        issuer=metadata.issuer,
        tenant_id="t",
    )
    conversations = ConversationClient(
        transport=SessionHttpClient(reactor=reactor, http_client=http)
    )
    answer = await conversations.start(
        company.document.agent.protocols[0].endpoint,  # type: ignore[union-attr]
        Message(id="msg_blind_0000000000000000", author=Author(type="agent"), text="Hello"),
        session=session,
        token=refreshed.token,
    )
    assert answer.conversation_id
    # Device authorization, the poll, the refresh, and one delegation.
    assert len(atlas.holder.seen) == 4
