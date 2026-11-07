# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from personal_agent_protocol.errors import ProtocolValidationError
from personal_agent_protocol.json import loads_strict
from personal_agent_protocol.models import (
    ClientMetadata,
    ConversationEventPage,
    DiscoveryDocument,
    Message,
    Operation,
)

FIXTURES = Path(__file__).parents[2] / "protocol" / "fixtures"


def test_discovery_fixture_round_trips_and_preserves_extensions() -> None:
    source = json.loads((FIXTURES / "discovery-valid.json").read_text())
    document = DiscoveryDocument.model_validate(source)

    assert document.protocol_version == "0.3"
    assert document.apis[1].type == "mcp"
    assert document.extensions["operations"].version == "2"
    assert document.extensions["mediated-sign-in"].model_extra == {
        "fields": source["extensions"]["mediated-sign-in"]["fields"],
        "scopes": ["orders:read"],
    }


def test_discovery_needs_an_issuer_for_an_api_not_auth() -> None:
    """`auth` is optional (3e9bada): the issuer comes from the domain (§3.2)."""

    document = DiscoveryDocument.model_validate(
        {
            "protocol_version": "0.3",
            "organization": {"name": "Example", "domain": "example.com"},
            "apis": [
                {
                    "type": "openapi",
                    "url": "https://api.example.com/openapi.json",
                    "description": "Example",
                }
            ],
        }
    )
    assert document.auth is None and not document.needs_issuer
    website = DiscoveryDocument.model_validate(
        {
            "protocol_version": "0.3",
            "organization": {"name": "Example", "domain": "example.com"},
            "web": {},
        }
    )
    assert not website.needs_issuer


def test_strict_json_rejects_duplicate_members() -> None:
    with pytest.raises(ProtocolValidationError, match="duplicate_json_member"):
        loads_strict('{"issuer":"first","issuer":"second"}')


def test_an_operation_of_the_old_shape_is_refused() -> None:
    with pytest.raises(ValidationError):
        Operation.model_validate(
            {
                "operation_id": "op_123",
                "revision": 2,
                "state": "in_progress",
                "summary": "Change the booking",
                "confirmation": None,
                "result": None,
            }
        )


def test_shared_client_conversation_and_operation_fixtures() -> None:
    client = ClientMetadata.model_validate_json(
        (FIXTURES / "client-metadata-valid.json").read_text()
    )
    operation = Operation.model_validate_json((FIXTURES / "operation-valid.json").read_text())
    page = ConversationEventPage.model_validate_json(
        (FIXTURES / "conversation-events-valid.json").read_text()
    )

    assert client.extensions["example.org/preferences"].model_extra == {"mode": "compact"}
    assert operation.revision == "1791487200-k3Jd9Qx2mW8v"
    assert page.events[0].message is not None
    # The operation is the Operations extension's content, `extensions.operations` (§8.4).
    assert page.events[0].message.operation == operation
    assert page.events[0].message.extensions == {
        "operations": {"operation": operation.model_dump(mode="json")}
    }
    assert page.events[2].type == "example.org/future-event"
    assert page.events[2].model_extra == {"future": True}
    # Links and Disclosures content, and an extension's content this SDK does not define.
    linked = page.events[3].message
    assert linked is not None and linked.operation is None and linked.approval is None
    assert [(link.url, link.title) for link in linked.links] == [
        ("https://example.com/help/returns", "Return policy")
    ]
    assert [item.text for item in linked.disclosures] == [
        "Contains peanuts. Made in a facility that also processes tree nuts."
    ]
    assert linked.extensions is not None
    assert linked.extensions["example.org/future-content"] == {"anything": True}


def test_message_requires_content() -> None:
    with pytest.raises(ValidationError, match="requires text, data, context, or extensions"):
        Message.model_validate({"id": "msg_empty", "author": {"type": "agent"}})


def test_known_conversation_event_requires_its_fields() -> None:
    with pytest.raises(ValidationError, match="state event requires handoff, responder and closed"):
        ConversationEventPage.model_validate(
            {
                "conversation_id": "cnv_one",
                "events": [
                    {
                        "id": "evt_one",
                        "type": "state",
                        "created_at": "2026-10-10T17:03:00Z",
                        "handoff": "none",
                    }
                ],
                "cursor": "evt_one",
                "has_more": False,
                "working": False,
                "handoff": "none",
                "responder": "agent",
                "closed": False,
            }
        )


def test_client_metadata_requires_same_domain_for_security_urls() -> None:
    with pytest.raises(ValidationError, match="client_id domain"):
        ClientMetadata.model_validate(
            {
                "client_id": "https://agent.example/agent.json",
                "client_name": "Example Agent",
                "jwks_uri": "https://attacker.example/jwks.json",
                "redirect_uris": [],
            }
        )
