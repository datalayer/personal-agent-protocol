# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Delegated keys (§5.2, §5.3, §10.7): what the signer writes, what a company verifies."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from personal_agent_protocol import JoseSigner
from personal_agent_protocol.company.points import MemoryReplayCache
from personal_agent_protocol.company.verify import (
    DelegationCache,
    verify_delegation,
    verify_session_jwt,
)
from personal_agent_protocol.crypto import (
    DelegatedSessionSigner,
    InMemoryDelegatedKeys,
    delegation_claims,
    jwk_thumbprint,
    session_jwt_claims,
)
from personal_agent_protocol.demo.kit import AgentIdentity, MutableClock
from personal_agent_protocol.errors import SessionError
from personal_agent_protocol.models import ClientMetadata, JsonWebKeySet
from personal_agent_protocol.reactor import SessionJwtRequest

from .test_company_end_to_end import World

ISSUER = "https://shop.example"
URL = "https://shop.example/api/orders"
SID = "Yx2b7Qd_Kp8mR3vT1nWc4A"
IDENTITY = AgentIdentity(domain="agent.example", name="Agent")
CLIENT_ID = IDENTITY.client_id


def request(sub: str = "usr_1", issuer: str = ISSUER, **changes: Any) -> SessionJwtRequest:
    values: dict[str, Any] = {
        "method": "GET",
        "url": URL,
        "tenant_id": "t",
        "issuer": issuer,
        "client_id": CLIENT_ID,
        "sid": SID,
        "sub": sub,
        **changes,
    }
    return SessionJwtRequest(**values)


class Fixture:
    def __init__(self) -> None:
        self.clock = MutableClock()
        self.keys = InMemoryDelegatedKeys()
        self.fetches = 0
        self.signer = DelegatedSessionSigner(
            self.keys, signer=IDENTITY.signer(), now=self.clock.now
        )

    async def resolve(self, client_id: str, kid: str | None) -> Any:
        self.fetches += 1
        return (
            ClientMetadata.model_validate(IDENTITY.metadata),
            JsonWebKeySet.model_validate(IDENTITY.jwks),
        )

    async def verify(self, compact: str, cache: DelegationCache | None = None) -> Any:
        return await verify_session_jwt(
            compact,
            issuer=ISSUER,
            method="GET",
            url=URL,
            resolve=self.resolve,
            replay_cache=MemoryReplayCache(self.clock),
            now=self.clock.now(),
            delegations=cache,
        )

    def forged(self, delegation: str, private: Any, public: dict[str, Any]) -> str:
        claims = session_jwt_claims(request(), issued_at=self.clock.now())
        return jwt.encode(
            claims,
            private,
            algorithm="ES256",
            headers={
                "typ": "poppy-session+jwt",
                "kid": jwk_thumbprint(public),
                "pap_dlg": delegation,
            },
        )

    async def delegation(self, *, lifetime: timedelta, issued: datetime | None = None) -> Any:
        private = ec.generate_private_key(ec.SECP256R1())
        public = jwt.algorithms.ECAlgorithm.to_jwk(private.public_key(), as_dict=True)
        claims = delegation_claims(
            client_id=CLIENT_ID,
            public=public,
            issued_at=issued or self.clock.now(),
            lifetime=min(lifetime, timedelta(hours=24)),
        )
        if lifetime > timedelta(hours=24):
            claims["exp"] = int(claims["iat"]) + int(lifetime.total_seconds())  # type: ignore[call-overload]
        signed = await IDENTITY.signer().sign(claims, purpose="delegation")
        return signed.get_secret_value(), private, public


@pytest.mark.asyncio
async def test_a_session_jwt_has_the_specs_header_and_claims() -> None:
    world = Fixture()
    compact = (await world.signer.sign(request(agent_id="agt_1"))).get_secret_value()
    header = jwt.get_unverified_header(compact)
    assert set(header) == {"typ", "alg", "kid", "pap_dlg"}
    assert (header["typ"], header["alg"]) == ("poppy-session+jwt", "ES256")
    claims = jwt.decode(compact, options={"verify_signature": False})
    assert set(claims) == {"iss", "aud", "sid", "sub", "agent_id", "htm", "htu", "iat", "jti"}
    verified = await world.verify(compact)
    assert (verified.client_id, verified.sid, verified.sub) == (CLIENT_ID, SID, "usr_1")
    assert verified.agent_id == "agt_1"
    # `htu` has no query or fragment (§5.2).
    with_query = await world.signer.sign(request(url=f"{URL}?page=2#top"))
    assert (
        jwt.decode(with_query.get_secret_value(), options={"verify_signature": False})["htu"] == URL
    )


@pytest.mark.asyncio
async def test_a_delegation_names_no_user_and_no_company() -> None:
    world = Fixture()
    await world.signer.sign(request(agent_id="agt_1"))
    key = await world.keys.current(tenant_id="t", issuer=ISSUER, sub="usr_1")
    assert key is not None
    compact = key.delegation.get_secret_value()
    header = jwt.get_unverified_header(compact)
    assert header["typ"] == "pap-delegation+jwt" and header["kid"] == IDENTITY.kid
    claims = jwt.decode(compact, options={"verify_signature": False})
    assert set(claims) == {"iss", "cnf", "iat", "exp", "jti"}
    assert claims["iss"] == CLIENT_ID and set(claims["cnf"]) == {"jwk"}
    assert "d" not in claims["cnf"]["jwk"]
    assert claims["exp"] - claims["iat"] <= 24 * 3600
    assert "usr_1" not in str(claims) and ISSUER not in str(claims)


@pytest.mark.asyncio
async def test_each_user_id_has_its_own_key_and_delegation() -> None:
    """Two User IDs never share a thumbprint or a `jti`, at one company or two (§5.2)."""

    world = Fixture()
    seen = []
    for sub, issuer in (("usr_1", ISSUER), ("usr_2", ISSUER), ("usr_1", "https://other.example")):
        compact = (await world.signer.sign(request(sub, issuer))).get_secret_value()
        header = jwt.get_unverified_header(compact)
        delegation = jwt.decode(header["pap_dlg"], options={"verify_signature": False})
        seen.append((header["kid"], delegation["jti"]))
    assert len({kid for kid, _ in seen}) == 3
    assert len({jti for _, jti in seen}) == 3
    assert len(world.keys) == 3
    # And one User ID keeps its key from one request to the next.
    again = (await world.signer.sign(request())).get_secret_value()
    assert jwt.get_unverified_header(again)["kid"] == seen[0][0]


@pytest.mark.asyncio
async def test_a_delegation_is_rotated_before_it_expires_and_never_signed_past() -> None:
    world = Fixture()
    first = jwt.get_unverified_header((await world.signer.sign(request())).get_secret_value())
    world.clock.advance(3600 - 301)
    kept = jwt.get_unverified_header((await world.signer.sign(request())).get_secret_value())
    assert kept["kid"] == first["kid"]
    world.clock.advance(2)
    compact = (await world.signer.sign(request())).get_secret_value()
    rotated = jwt.get_unverified_header(compact)
    assert rotated["kid"] != first["kid"]
    delegation = jwt.decode(rotated["pap_dlg"], options={"verify_signature": False})
    claims = jwt.decode(compact, options={"verify_signature": False})
    assert claims["iat"] < delegation["exp"]
    await world.verify(compact)


@pytest.mark.parametrize(
    ("lifetime", "too_long"), [(timedelta(hours=25), True), (timedelta(hours=1), False)]
)
@pytest.mark.asyncio
async def test_a_delegation_over_24_hours_or_expired_is_invalid_session(
    lifetime: timedelta, too_long: bool
) -> None:
    world = Fixture()
    issued = world.clock.now() if too_long else world.clock.now() - timedelta(hours=2)
    delegation, private, public = await world.delegation(lifetime=lifetime, issued=issued)
    with pytest.raises(SessionError) as refused:
        await world.verify(world.forged(delegation, private, public))
    assert refused.value.code == "invalid_session" and refused.value.status_code == 400


@pytest.mark.asyncio
async def test_a_session_jwt_signed_directly_with_a_jwks_key_is_invalid_session() -> None:
    world = Fixture()
    claims = session_jwt_claims(request(), issued_at=world.clock.now())
    direct = jwt.encode(
        claims,
        IDENTITY.private_key,
        algorithm="ES256",
        headers={"typ": "poppy-session+jwt", "kid": IDENTITY.kid},
    )
    with pytest.raises(SessionError, match="invalid_session"):
        await world.verify(direct)


@pytest.mark.asyncio
async def test_a_delegation_with_a_private_member_is_refused() -> None:
    world = Fixture()
    private = ec.generate_private_key(ec.SECP256R1())
    secret = jwt.algorithms.ECAlgorithm.to_jwk(private, as_dict=True)
    claims = {
        "iss": CLIENT_ID,
        "cnf": {"jwk": secret},
        "iat": int(world.clock.now().timestamp()),
        "exp": int(world.clock.now().timestamp()) + 60,
        "jti": "Dl1x7yQbX1m3Jk0aT9cWvA",
    }
    signed = await JoseSigner(IDENTITY.private_key, key_id=IDENTITY.kid).sign(
        claims, purpose="delegation"
    )
    with pytest.raises(SessionError, match="invalid_session"):
        await verify_delegation(
            signed.get_secret_value(),
            client_id=CLIENT_ID,
            resolve=world.resolve,
            now=world.clock.now(),
        )


@pytest.mark.asyncio
async def test_a_company_caches_a_verified_delegation_until_it_expires() -> None:
    world = Fixture()
    cache = DelegationCache()
    for _ in range(3):
        await world.verify((await world.signer.sign(request())).get_secret_value(), cache)
    assert world.fetches == 1 and len(cache) == 1
    # Another agent presenting it is refused, cached or not.
    key = await world.keys.current(tenant_id="t", issuer=ISSUER, sub="usr_1")
    assert key is not None
    with pytest.raises(SessionError, match="invalid_session"):
        await verify_delegation(
            key.delegation.get_secret_value(),
            client_id="https://other.example/agent.json",
            resolve=world.resolve,
            now=world.clock.now(),
            cache=cache,
        )
    world.clock.advance(3601)
    assert cache.get(key.delegation.get_secret_value(), world.clock.now()) is None


@pytest.mark.asyncio
async def test_the_company_remembers_an_ended_sid_and_the_agent_starts_again_once() -> None:
    """`invalid_session`: a new `sid`, once; the same one is never started again (§5.5)."""

    world = World()
    session = await world.signed_out_session()
    endpoint = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    await world.conversations.start(endpoint, world.message("Hello"), session=session)
    ended = session.sid
    assert await world.shop.end_session(session.client_id, ended)
    await world.conversations.start(endpoint, world.message("Hello again"), session=session)
    assert session.sid != ended
    headers = await _headers(world, ended, endpoint)
    refused = await world.http.post(endpoint, headers=headers, json={})
    assert refused.status_code == 400 and refused.json() == {"error": "invalid_session"}


async def _headers(world: World, sid: str, url: str) -> dict[str, str]:
    from personal_agent_protocol.reactor import SESSION_SIGNERS, first_contribution

    signer: Any = first_contribution(world.reactor, SESSION_SIGNERS, "session signer")
    signed = await signer.sign(
        SessionJwtRequest(
            method="POST",
            url=url,
            tenant_id="atlas-demo",
            issuer=world.company.issuer,
            client_id=world.atlas.client_id,
            sid=sid,
            sub="usr_ada_at_manzanita_000000",
        )
    )
    return {"Poppy-Session": signed.get_secret_value()}


@pytest.mark.asyncio
async def test_a_session_that_ended_on_its_own_is_remembered() -> None:
    world = World()
    session = await world.signed_out_session()
    url = world.company.document.agent.protocols[0].endpoint  # type: ignore[union-attr]
    first = await world.http.post(url, headers=await _headers(world, session.sid, url), json={})
    assert first.status_code != 400 or first.json() != {"error": "invalid_session"}
    world.clock.advance(world.shop.config.session_lifetime.total_seconds() + 1)
    late = await world.http.post(url, headers=await _headers(world, session.sid, url), json={})
    assert late.status_code == 400 and late.json() == {"error": "invalid_session"}
