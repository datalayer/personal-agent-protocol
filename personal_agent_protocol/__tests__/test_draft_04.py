# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""What draft 0.4 adds, both sides, in one process: `src/__tests__/draft-04.test.mjs`
ports it.

Direct Sign-In preferred (§4, P4-01).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from personal_agent_protocol.actions import discover_company
from personal_agent_protocol.company import CompanyConfig
from personal_agent_protocol.demo.kit import InProcessNetwork, MutableClock
from personal_agent_protocol.demo.manzanita import CONFIG, manzanita
from personal_agent_protocol.models import (
    DEVICE_CODE_GRANT,
    MEDIATED_GRANT,
    DiscoveredCompany,
    DiscoveryDocument,
    OAuthServerMetadata,
)

from .test_company_end_to_end import World

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"


def _company(grants: list[str], *, disabled: bool = False) -> DiscoveredCompany:
    document = json.loads((FIXTURES / "discovery-valid.json").read_text())
    if disabled:
        document["auth"]["disabled"] = True
    metadata = json.loads((FIXTURES / "oauth-metadata-valid.json").read_text())
    metadata["grant_types_supported"] = ["refresh_token", *grants]
    if "authorization_code" not in grants:
        del metadata["authorization_endpoint"]
    if DEVICE_CODE_GRANT not in grants:
        del metadata["device_authorization_endpoint"]
    return DiscoveredCompany(
        discovery_url="https://example.com/.well-known/poppy.json",
        document=DiscoveryDocument.model_validate(document),
        oauth_metadata=OAuthServerMetadata.model_validate(metadata),
    )


# Direct Sign-In preferred (§4) ---------------------------------------------------------


def test_direct_sign_in_is_preferred_when_offered() -> None:
    """The agent uses Direct Sign-In when the Company offers it, else Device, else
    Mediated (§4); a Company with sign-in off or no issuer offers none."""

    everything = _company(["authorization_code", DEVICE_CODE_GRANT, MEDIATED_GRANT])
    assert everything.sign_in_types == ("direct", "device", "mediated")
    assert everything.preferred_sign_in == "direct"
    # A Company guarding high-value resources offers Direct only (RFC 10027 §6.2.1.5).
    assert _company(["authorization_code"]).preferred_sign_in == "direct"
    device_only = _company([DEVICE_CODE_GRANT, MEDIATED_GRANT])
    assert device_only.sign_in_types == ("device", "mediated")
    assert device_only.preferred_sign_in == "device"
    assert _company([MEDIATED_GRANT]).preferred_sign_in == "mediated"
    assert _company([]).preferred_sign_in is None
    disabled = _company(["authorization_code", DEVICE_CODE_GRANT], disabled=True)
    assert disabled.sign_in_types == () and disabled.preferred_sign_in is None
    no_issuer = DiscoveredCompany(
        discovery_url=everything.discovery_url,
        document=everything.document.model_copy(update={"auth": None}),
    )
    assert no_issuer.preferred_sign_in is None


@pytest.mark.asyncio
async def test_the_discovery_summary_lists_sign_in_types_direct_first() -> None:
    world = World()
    summary = await discover_company(
        "manzanita.example", reactor=world.reactor, http_client=world.http
    )
    assert summary["sign_in"] == ["direct", "device", "mediated"]
    assert summary["preferred_sign_in"] == "direct"


def test_the_reference_company_offers_direct_sign_in() -> None:
    """A Company that offers sign-in SHOULD offer Direct Sign-In (§4): the reference
    company does by default, and one that offers Direct only lists no device grant."""

    assert CONFIG.direct and CONFIG.device
    service, _ = manzanita(InProcessNetwork(), MutableClock())
    grants = service.oauth_metadata()["grant_types_supported"]
    assert "authorization_code" in grants and DEVICE_CODE_GRANT in grants
    bank = CompanyConfig(
        name="Bank",
        domain="bank.example",
        scopes=("accounts:read",),
        scope_descriptions={"accounts:read": "See your accounts"},
        operations=False,
        device=False,
    )
    assert bank.direct and not bank.device
