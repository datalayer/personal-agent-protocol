# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""The SDK's telemetry: one event per protocol stage, attributes from an allowlist.

Manzanita's journeys (Device and Mediated Sign-In, a conversation, an operation,
Account Tokens, a stranger refused) run with a `pap.telemetry` sink on every
Reactor; the events name each stage and its outcome, an error carries only its
code, and the OpenTelemetry adapter makes the same events spans. What no event may
carry, whatever a test passes, is checked against the allowlist itself; that no
credential of a real run reaches an event is `test_canaries.py`'s.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Iterator
from typing import Any

import pytest
from pydantic import SecretStr
from reactor import PluginManifest  # type: ignore[import-untyped]

from personal_agent_protocol import (
    TELEMETRY_ATTRIBUTES,
    TELEMETRY_EVENTS,
    TELEMETRY_SINKS,
    OpenTelemetrySink,
    RecordingTelemetrySink,
    TelemetryEvent,
)
from personal_agent_protocol.reactor import PapCorePlugin
from personal_agent_protocol.telemetry import safe_attributes

from . import test_company_end_to_end as journeys
from .test_company_end_to_end import World

FORBIDDEN = (
    "token",
    "assertion",
    "proof",
    "code",
    "cookie",
    "password",
    "secret",
    "credential",
    "mediated",
    "key",
    "session_id",
    "user_id",
    "pairwise",
    "url",
)


def contribute_to_every_reactor(monkeypatch: pytest.MonkeyPatch, sink: object) -> None:
    """Every PAP Reactor the run builds (agents' and companies') gets `sink`."""

    original = PapCorePlugin.provide_contributions

    @functools.wraps(original)
    def with_sink(self: PapCorePlugin, contributions: Any) -> None:
        original(self, contributions)
        contributions.contribute(TELEMETRY_SINKS, sink, contribution_id="tests", order=100)

    monkeypatch.setattr(PapCorePlugin, "provide_contributions", with_sink)


@pytest.fixture
def recorded(monkeypatch: pytest.MonkeyPatch) -> Iterator[RecordingTelemetrySink]:
    sink = RecordingTelemetrySink()
    contribute_to_every_reactor(monkeypatch, sink)
    yield sink


def _names(sink: RecordingTelemetrySink, outcome: str = "ok") -> set[str]:
    return {event.name for event in sink.events if event.outcome == outcome}


@pytest.mark.asyncio
async def test_each_stage_of_a_journey_is_one_event(recorded: RecordingTelemetrySink) -> None:
    await journeys.test_a_user_and_a_company_from_question_to_confirmed_exchange()
    await journeys.test_mediated_sign_in_with_a_one_time_code()
    await journeys.test_the_conversation_streams_and_a_stranger_cannot_read_it()

    assert {event.stage for event in recorded.events} == {
        "discovery",
        "session",
        "sign_in",
        "conversation",
        "operation",
    }
    assert {
        "pap.discovery.discover",
        "pap.session.start",
        "pap.sign_in.device.begin",
        "pap.sign_in.device.poll",
        "pap.sign_in.mediated.sign_in",
        "pap.sign_in.mediated.submit_code",
        "pap.sign_in.account_token.refresh",
        "pap.sign_in.account_token.revoke",
        "pap.conversation.start",
        "pap.conversation.send",
        "pap.conversation.close",
        "pap.operation.confirm",
    } <= _names(recorded)
    # The stranger's read is refused: an error event with the refusal's code only.
    (refused,) = [e for e in recorded.events if e.name == "pap.conversation.read_events"]
    assert refused.outcome == "error"
    assert refused.attributes == {
        "pap.company.domain": "manzanita.example",
        "pap.error": "conversation_not_found",
    }
    discovered = next(e for e in recorded.events if e.name == "pap.discovery.discover")
    assert discovered.attributes == {
        "pap.company.domain": "manzanita.example",
        "pap.company.issuer": "https://manzanita.example",
    }
    polls = [e.attributes for e in recorded.events if e.name == "pap.sign_in.device.poll"]
    assert [p["pap.sign_in.status"] for p in polls] == ["pending", "complete"]
    assert polls[-1]["pap.session.signed_in"] is True
    confirms = [e.attributes for e in recorded.events if e.name == "pap.operation.confirm"]
    assert confirms[0] == {
        "pap.company.domain": "manzanita.example",
        "pap.operation.status": "confirmed",
        "pap.operation.state": "succeeded",
        "pap.operation.revision": 1,
    }
    refreshes = [e for e in recorded.events if e.name == "pap.sign_in.account_token.refresh"]
    assert [e.attributes["pap.sign_in.status"] for e in refreshes] == [
        "signed_in",
        "re_consent_required",
        "signed_out",
    ]
    assert all(e.duration_ms >= 0 for e in recorded.events)
    for event in recorded.events:
        assert set(event.attributes) <= set(TELEMETRY_ATTRIBUTES)
        assert event.as_attributes()["pap.stage"] == TELEMETRY_EVENTS[event.name]


@pytest.mark.asyncio
async def test_without_a_sink_nothing_is_emitted_and_nothing_changes() -> None:
    world = World()
    session = await world.signed_out_session()
    assert session.signed_in is False


def test_no_allowlisted_attribute_names_a_secret() -> None:
    for name in TELEMETRY_ATTRIBUTES:
        assert name.startswith("pap.")
        assert not any(word in name for word in FORBIDDEN), name
    for name in TELEMETRY_EVENTS:
        assert name.startswith("pap.")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("pap.company.issuer", "https://manzanita.example/?token=CANARY"),
        ("pap.company.issuer", "https://user:pw@manzanita.example"),
        ("pap.company.issuer", "https://manzanita.example/#frag"),
        ("pap.company.issuer", "http://manzanita.example"),
        ("pap.company.domain", "00000001CANARYAAAA.example"),
        ("pap.company.domain", "manzanita.example/path"),
        ("pap.error", "00000001CANARYAAAAAAAAAAAAAAAA"),
        ("pap.error", "invalid grant: eyJhbGciOi"),
        ("pap.sign_in.status", SecretStr("signed_in")),
        ("pap.operation.state", "x" * 49),
        ("pap.operation.revision", -1),
        ("pap.operation.revision", True),
        ("pap.session.signed_in", "yes"),
        ("pap.sign_in.method", "password"),
    ],
)
def test_a_value_that_fails_its_rule_is_dropped(name: str, value: object) -> None:
    assert safe_attributes({name: value}) == {}


def test_an_attribute_outside_the_allowlist_is_refused() -> None:
    for name in ("pap.session.token", "pap.operation.id", "authorization", "pap.url"):
        with pytest.raises(ValueError, match="not a telemetry attribute"):
            safe_attributes({name: "x"})
    with pytest.raises(ValueError):
        TelemetryEvent(name="pap.session.start", outcome="ok", duration_ms=1, attributes={"x": 1})
    with pytest.raises(ValueError):
        TelemetryEvent(
            name="pap.session.start",
            outcome="ok",
            duration_ms=1,
            attributes={"pap.company.issuer": "https://a.example/?code=1"},
        )
    with pytest.raises(ValueError, match="not a telemetry event"):
        TelemetryEvent(name="pap.tokens.dump", outcome="ok", duration_ms=1)


@pytest.mark.asyncio
async def test_a_failing_sink_never_fails_the_protocol(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class Broken:
        def record(self, event: TelemetryEvent) -> None:
            raise RuntimeError(f"cannot export {event.attributes}")

    contribute_to_every_reactor(monkeypatch, Broken())
    with caplog.at_level(logging.WARNING, logger="personal_agent_protocol.telemetry"):
        session = await World().signed_out_session()
    assert session.session_id
    assert caplog.messages and set(caplog.messages) == {"The telemetry sink failed: RuntimeError"}


@pytest.mark.asyncio
async def test_two_sinks_at_one_order_fail_closed(recorded: RecordingTelemetrySink) -> None:
    world = World()

    class Second:
        def provide_contributions(self, contributions: Any) -> None:
            contributions.contribute(
                TELEMETRY_SINKS, RecordingTelemetrySink(), contribution_id="b", order=100
            )

    world.reactor.register_plugin(PluginManifest(name="second-sink", version="1"), Second())
    with pytest.raises(RuntimeError, match="ambiguous telemetry sink"):
        await world.signed_out_session()


@pytest.mark.asyncio
async def test_the_opentelemetry_adapter_makes_each_event_a_span(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("opentelemetry.sdk")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.trace import StatusCode

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    recording = RecordingTelemetrySink()
    otel = OpenTelemetrySink(provider.get_tracer("tests"))

    class Both:
        def record(self, event: TelemetryEvent) -> None:
            recording.record(event)
            otel.record(event)

    contribute_to_every_reactor(monkeypatch, Both())
    await journeys.test_the_conversation_streams_and_a_stranger_cannot_read_it()

    spans = exporter.get_finished_spans()
    assert [span.name for span in spans] == [event.name for event in recording.events]
    for span, event in zip(spans, recording.events, strict=True):
        assert dict(span.attributes or {}) == event.as_attributes()
        assert span.end_time is not None and span.start_time is not None
        assert span.end_time >= span.start_time
        expected = StatusCode.ERROR if event.outcome == "error" else StatusCode.UNSET
        assert span.status.status_code == expected
        assert span.status.description is None


def test_the_opentelemetry_adapter_names_its_optional_dependency(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import builtins

    real_import = builtins.__import__

    def without_opentelemetry(name: str, *args: Any, **kwargs: Any) -> Any:
        if name.startswith("opentelemetry"):
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_opentelemetry)
    with pytest.raises(ImportError, match=r"personal-agent-protocol\[telemetry\]"):
        OpenTelemetrySink()
