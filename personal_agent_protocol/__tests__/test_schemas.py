# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The shared fixtures, and what the reference company publishes, against upstream's schemas.

`protocol/schemas/` holds the JSON Schemas of the upstream company kit at the
commit `protocol/UPSTREAM.md` names, copied unchanged. Each shared fixture
validates against its schema, and so do the documents the reference company
serves, so both SDKs and the company agree with the specification's own shapes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jwt
import pytest
from jsonschema import Draft202012Validator
from pydantic import SecretStr
from referencing import Registry, Resource

from personal_agent_protocol.conformance import load_fixture_cases
from personal_agent_protocol.crypto import DelegatedSessionSigner, InMemoryDelegatedKeys
from personal_agent_protocol.demo.kit import AgentIdentity, InProcessNetwork, MutableClock
from personal_agent_protocol.demo.manzanita import manzanita
from personal_agent_protocol.models import Alternative
from personal_agent_protocol.reactor import SessionJwtRequest

ROOT = Path(__file__).parents[2] / "protocol"
SCHEMAS = ROOT / "schemas"
FIXTURES = ROOT / "fixtures"


def _registry() -> Registry:
    resources = [
        (path.name, Resource.from_contents(json.loads(path.read_text())))
        for path in sorted(SCHEMAS.glob("*.schema.json"))
    ]
    return Registry().with_resources(resources)


REGISTRY = _registry()


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMAS / f"{name}.schema.json").read_text())
    return Draft202012Validator(schema, registry=REGISTRY)


def errors(name: str, document: Any) -> list[str]:
    return [error.message for error in validator(name).iter_errors(document)]


#: Each shared fixture and the upstream schema it is an instance of.
FIXTURE_SCHEMAS = {
    "discovery-valid.json": "poppy",
    "oauth-metadata-valid.json": "authorization-server-metadata",
    "protected-resource-metadata-valid.json": "protected-resource-metadata",
    "client-metadata-valid.json": "client-metadata",
    "feedback-report-valid.json": "feedback-report",
    "alternative-valid.json": "alternative",
    "token-response-valid.json": "token-response",
    "session-jwt-valid.json": "session-jwt",
    "delegation-valid.json": "delegation",
    "invalid-session-valid.json": "oauth-error",
}

#: Fixtures of Operations version 1, which upstream's schemas no longer describe.
OPERATIONS_V1 = {
    "operation-valid.json": "operation",
    "conversation-events-valid.json": "events-response",
}


def test_the_vendored_schemas_are_well_formed() -> None:
    for path in SCHEMAS.glob("*.schema.json"):
        Draft202012Validator.check_schema(json.loads(path.read_text()))
    assert {"session-jwt", "delegation", "token-response", "oauth-error"} <= {
        path.name.removesuffix(".schema.json") for path in SCHEMAS.glob("*.schema.json")
    }


@pytest.mark.parametrize(("fixture", "schema"), sorted(FIXTURE_SCHEMAS.items()))
def test_a_shared_fixture_is_valid_by_its_upstream_schema(fixture: str, schema: str) -> None:
    assert errors(schema, json.loads((FIXTURES / fixture).read_text())) == []


@pytest.mark.xfail(reason="Operations v2 port pending", strict=True)
@pytest.mark.parametrize(("fixture", "schema"), sorted(OPERATIONS_V1.items()))
def test_an_operations_fixture_is_valid_by_its_upstream_schema(fixture: str, schema: str) -> None:
    assert errors(schema, json.loads((FIXTURES / fixture).read_text())) == []


@pytest.mark.parametrize(
    "case",
    [
        case
        for case in load_fixture_cases(("protocol",))
        if case.check == "discovery_document" and case.kind == "positive"
    ],
    ids=lambda case: case.id,
)
def test_a_positive_discovery_case_is_valid_by_the_upstream_schema(case: Any) -> None:
    assert errors("poppy", case.input) == []


def test_feedback_has_no_kind_and_an_alternative_no_length_cap() -> None:
    """3e9bada: a report is `task` and `description`; `instructions` has no maximum (§9.2, §9.3)."""

    report = json.loads((FIXTURES / "feedback-report-valid.json").read_text())
    assert set(report) == {"task", "description"}
    long = {"instructions": "Open the cart. " * 400}
    assert len(long["instructions"]) > 2000
    assert errors("alternative", long) == []
    assert Alternative.model_validate(long).instructions == long["instructions"]


def test_unknown_status_and_responder_are_allowed_in_an_event_by_type_only() -> None:
    """A state event's values come from the spec's lists; the SDK reads others as 8.7 says."""

    event = {
        "id": "evt_1",
        "type": "state",
        "created_at": "2026-10-10T17:03:00Z",
        "status": "idle",
        "responder": "agent",
    }
    assert errors("event", event) == []


@pytest.mark.asyncio
async def test_what_the_reference_company_publishes_is_valid_by_the_upstream_schemas() -> None:
    network = InProcessNetwork()
    service, _ = manzanita(network, MutableClock())
    assert errors("poppy", service.discovery_document()) == []
    assert errors("protected-resource-metadata", service.domain_resource_metadata()) == []
    assert errors("authorization-server-metadata", service.oauth_metadata()) == []
    if service._mcp() is not None:
        assert errors("protected-resource-metadata", service.protected_resource_metadata()) == []


@pytest.mark.asyncio
async def test_what_the_sdk_signs_is_valid_by_the_upstream_schemas() -> None:
    """A Session JWT and its delegation, decoded, as `DelegatedSessionSigner` writes them."""

    identity = AgentIdentity(domain="agent.example", name="Agent")
    clock = MutableClock()
    signer = DelegatedSessionSigner(
        InMemoryDelegatedKeys(), signer=identity.signer(), now=clock.now
    )
    compact = await signer.sign(
        SessionJwtRequest(
            method="POST",
            url="https://api.example.com/orders",
            tenant_id="t",
            issuer="https://auth.example.com",
            client_id=identity.client_id,
            sid="Yx2b7Qd_Kp8mR3vT1nWc4A",
            sub="usr_1",
            access_token=SecretStr("at_1"),
        )
    )
    value = compact.get_secret_value()
    header = jwt.get_unverified_header(value)
    claims = jwt.decode(value, options={"verify_signature": False})
    assert errors("session-jwt", {"header": header, "payload": claims}) == []
    delegation = {
        "header": jwt.get_unverified_header(header["pap_dlg"]),
        "payload": jwt.decode(header["pap_dlg"], options={"verify_signature": False}),
    }
    assert errors("delegation", delegation) == []
