# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Traces and analytics events of the SDK's protocol stages, redacted by construction.

A host contributes a `TelemetrySink` to `pap.telemetry`; without one nothing is
emitted. Each discovery, Session, sign-in, conversation, and operation call then
produces one `TelemetryEvent` when it finishes: its name (`TELEMETRY_EVENTS`), its stage,
`ok` or `error`, its duration, and attributes.

A company built on `personal_agent_protocol.company` reports through the same
point (stage `company`): an agent's identity verified for the first time or
with new metadata, a Session started or renewed, a Session moved to another
interface (a Bearer token for the MCP server, a browser joining it), and each
request it refused, with the protocol's code, the route, the status, and
whether a proof or assertion was a replay. The device flow's
`authorization_pending` and `slow_down` are progress, not refusals.

Attributes are an allowlist (`TELEMETRY_ATTRIBUTES`). An attribute outside it is
a programming error (`ValueError`); a value that fails its rule (a lowercase
identifier, a domain, an `https` issuer, a number, a flag) is dropped. No rule
admits a token, an assertion, a proof, a code, a cookie, a password, a mediated
field, a Session or conversation ID, a pairwise User ID, or a URL with a query:
those values are never offered, and could not pass if they were.

`OpenTelemetrySink` turns each event into an OpenTelemetry span (the
`opentelemetry-api` dependency is optional: the `telemetry` extra);
`RecordingTelemetrySink` keeps them in memory, for tests and analytics.
"""

from __future__ import annotations

import functools
import inspect
import logging
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, TypeVar
from urllib.parse import urlsplit

from .__version__ import __version__
from .errors import PersonalAgentProtocolError
from .reactor import TELEMETRY_SINKS, TelemetrySink, optional_contribution

logger = logging.getLogger(__name__)

Stage = Literal["discovery", "session", "sign_in", "conversation", "operation", "company"]
STAGES: tuple[Stage, ...] = (
    "discovery",
    "session",
    "sign_in",
    "conversation",
    "operation",
    "company",
)

#: Every event the SDK emits, and its stage.
TELEMETRY_EVENTS: dict[str, Stage] = {
    "pap.discovery.discover": "discovery",
    "pap.session.start": "session",
    "pap.sign_in.direct.begin": "sign_in",
    "pap.sign_in.direct.complete": "sign_in",
    "pap.sign_in.device.begin": "sign_in",
    "pap.sign_in.device.poll": "sign_in",
    "pap.sign_in.mediated.sign_in": "sign_in",
    "pap.sign_in.mediated.submit_code": "sign_in",
    "pap.sign_in.refresh_token.refresh": "sign_in",
    "pap.sign_in.refresh_token.revoke": "sign_in",
    "pap.conversation.start": "conversation",
    "pap.conversation.send": "conversation",
    "pap.conversation.read_events": "conversation",
    "pap.conversation.start_direct": "conversation",
    "pap.conversation.handoff": "conversation",
    "pap.conversation.close": "conversation",
    "pap.operation.ask_user": "operation",
    "pap.operation.send": "operation",
    # What a company built on `personal_agent_protocol.company` did and refused.
    "pap.company.identity.check": "company",
    "pap.company.session.start": "company",
    "pap.company.interface.switch": "company",
    "pap.company.sign_out": "company",
    "pap.company.refused": "company",
}

#: The interfaces a company offers a personal agent (`pap.interface`).
INTERFACES: tuple[str, ...] = ("agent", "openapi", "mcp", "web")

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{0,47}$")
_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+[a-z]{{2,63}}$")
_PATH = re.compile(r"^(?:/[A-Za-z0-9._~-]{1,64}){0,8}/?$")


def _identifier(value: object) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))


def _domain(value: object) -> bool:
    return isinstance(value, str) and bool(_DOMAIN.fullmatch(value))


def _issuer(value: object) -> bool:
    """An `https` origin with at most a plain path: no user information, query, or fragment."""

    if not isinstance(value, str) or len(value) > 256:
        return False
    parts = urlsplit(value)
    return (
        parts.scheme == "https"
        and "@" not in parts.netloc
        and not parts.query
        and not parts.fragment
        and "?" not in value
        and "#" not in value
        and _domain(parts.hostname)
        and parts.port is None
        and bool(_PATH.fullmatch(parts.path))
    )


def _count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1_000_000


def _flag(value: object) -> bool:
    return isinstance(value, bool)


def _one_of(*allowed: str) -> Callable[[object], bool]:
    return lambda value: value in allowed


#: The only attribute names an event may carry, each with the rule its value must pass.
TELEMETRY_ATTRIBUTES: dict[str, Callable[[object], bool]] = {
    "pap.stage": _one_of(*STAGES),
    "pap.outcome": _one_of("ok", "error"),
    "pap.error": _identifier,
    "pap.company.domain": _domain,
    "pap.company.issuer": _issuer,
    "pap.sign_in.method": _one_of("direct", "device", "mediated", "refresh_token"),
    "pap.sign_in.status": _identifier,
    "pap.session.signed_in": _flag,
    "pap.scopes.granted": _count,
    "pap.scopes.missing": _count,
    "pap.conversation.status": _identifier,
    "pap.conversation.events": _count,
    "pap.operation.status": _identifier,
    "pap.client.id": _issuer,
    "pap.interface": _one_of(*INTERFACES),
    "pap.company.route": _identifier,
    "pap.http.status": _count,
    "pap.replayed": _flag,
}

AttributeValue = str | int | bool


def safe_attributes(values: Mapping[str, object]) -> dict[str, AttributeValue]:
    """The allowlisted attributes of `values`, each value checked; `None` and failures dropped.

    A name outside `TELEMETRY_ATTRIBUTES` raises `ValueError`: the SDK never offers one.
    """

    safe: dict[str, AttributeValue] = {}
    for name, value in values.items():
        rule = TELEMETRY_ATTRIBUTES.get(name)
        if rule is None:
            raise ValueError(f"{name} is not a telemetry attribute")
        if value is not None and rule(value):
            safe[name] = value  # type: ignore[assignment]
    return safe


@dataclass(frozen=True)
class TelemetryEvent:
    """One finished protocol stage: a span for traces, an event for analytics."""

    name: str
    outcome: Literal["ok", "error"]
    duration_ms: float
    attributes: Mapping[str, AttributeValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.name not in TELEMETRY_EVENTS:
            raise ValueError(f"{self.name} is not a telemetry event")
        if self.outcome not in {"ok", "error"}:
            raise ValueError("outcome is ok or error")
        if not self.duration_ms >= 0:
            raise ValueError("duration_ms must not be negative")
        if dict(self.attributes) != safe_attributes(self.attributes):
            raise ValueError("a telemetry attribute failed its rule")

    @property
    def stage(self) -> Stage:
        return TELEMETRY_EVENTS[self.name]

    def as_attributes(self) -> dict[str, AttributeValue]:
        """Every attribute, the stage and outcome included (what a span carries)."""

        return {**self.attributes, "pap.stage": self.stage, "pap.outcome": self.outcome}

    def as_dict(self) -> dict[str, Any]:
        """The event as JSON-ready data, for an analytics pipeline."""

        return {
            "name": self.name,
            "stage": self.stage,
            "outcome": self.outcome,
            "duration_ms": self.duration_ms,
            "attributes": dict(self.attributes),
        }


class RecordingTelemetrySink:
    """`pap.telemetry` in memory: every event, in order."""

    def __init__(self) -> None:
        self.events: list[TelemetryEvent] = []

    def record(self, event: TelemetryEvent) -> None:
        self.events.append(event)


class OpenTelemetrySink:
    """`pap.telemetry` as OpenTelemetry spans, one per event, under the current span.

    Give it a tracer, or install the optional `opentelemetry-api` (the `telemetry`
    extra) and it takes the global provider's. A failed stage's span has an error
    status whose only detail is the `pap.error` attribute.
    """

    def __init__(self, tracer: Any | None = None) -> None:
        if tracer is None:
            try:
                from opentelemetry import trace
            except ImportError as error:
                raise ImportError(
                    "OpenTelemetrySink needs opentelemetry-api: "
                    'pip install "personal-agent-protocol[telemetry]"'
                ) from error
            tracer = trace.get_tracer("personal_agent_protocol", __version__)
        self.tracer = tracer

    def record(self, event: TelemetryEvent) -> None:
        end = time.time_ns()
        start = end - int(event.duration_ms * 1_000_000)
        span = self.tracer.start_span(
            event.name, start_time=start, attributes=event.as_attributes()
        )
        if event.outcome == "error":
            from opentelemetry.trace import Status, StatusCode

            span.set_status(Status(StatusCode.ERROR))
        span.end(end_time=end)


def telemetry_sink(reactor: Any) -> TelemetrySink | None:
    """The host's sink, `None` when it contributes none; two at one order fail closed."""

    if reactor is None:
        return None
    return optional_contribution(reactor, TELEMETRY_SINKS, "telemetry sink")  # type: ignore[return-value]


def emit(
    sink: TelemetrySink,
    name: str,
    outcome: Literal["ok", "error"],
    duration_ms: float,
    attributes: Mapping[str, object],
) -> None:
    """Record one event; a failing sink is logged by its type and never fails the call."""

    event = TelemetryEvent(
        name=name,
        outcome=outcome,
        duration_ms=max(0.0, duration_ms),
        attributes=safe_attributes(attributes),
    )
    try:
        sink.record(event)
    except Exception as error:
        logger.warning("The telemetry sink failed: %s", type(error).__name__)


Arguments = Mapping[str, Any]
Before = Callable[[Arguments], Mapping[str, object]]
After = Callable[[Any], Mapping[str, object]]
Method = TypeVar("Method", bound=Callable[..., Awaitable[Any]])


def _reactor_of(client: object) -> Any:
    reactor = getattr(client, "reactor", None)
    if reactor is None:
        reactor = getattr(getattr(client, "transport", None), "reactor", None)
    return reactor


def traced(
    name: str, *, before: Before | None = None, after: After | None = None
) -> Callable[[Method], Method]:
    """Emit `name` when the decorated client method finishes, through the client's Reactor.

    `before` reads attributes from the call's arguments, `after` from its result;
    a `PersonalAgentProtocolError` is `error` with its code (any other exception
    `unexpected`), and is raised on unchanged.
    """

    if name not in TELEMETRY_EVENTS:
        raise ValueError(f"{name} is not a telemetry event")

    def decorate(method: Method) -> Method:
        signature = inspect.signature(method)

        @functools.wraps(method)
        async def wrapper(self: object, *args: Any, **kwargs: Any) -> Any:
            sink = telemetry_sink(_reactor_of(self))
            if sink is None:
                return await method(self, *args, **kwargs)
            attributes: dict[str, object] = {}
            if before is not None:
                bound = signature.bind(self, *args, **kwargs)
                bound.apply_defaults()
                attributes.update(before(bound.arguments))
            started = time.perf_counter()
            try:
                result = await method(self, *args, **kwargs)
            except PersonalAgentProtocolError as error:
                elapsed = (time.perf_counter() - started) * 1000
                emit(sink, name, "error", elapsed, {**attributes, "pap.error": error.code})
                raise
            except Exception:
                elapsed = (time.perf_counter() - started) * 1000
                emit(sink, name, "error", elapsed, {**attributes, "pap.error": "unexpected"})
                raise
            if after is not None:
                attributes.update(after(result))
            emit(sink, name, "ok", (time.perf_counter() - started) * 1000, attributes)
            return result

        return wrapper  # type: ignore[return-value]

    return decorate


def domain_of(url: object) -> str | None:
    """The host of a URL, for `pap.company.domain` (never its path or query)."""

    return urlsplit(url).hostname if isinstance(url, str) else None


# What the SDK's clients report: read from their arguments and results ---------------------


def by_domain(arguments: Arguments) -> dict[str, object]:
    domain = arguments.get("domain")
    return {"pap.company.domain": domain.rstrip(".").lower() if isinstance(domain, str) else None}


def by_issuer(arguments: Arguments) -> dict[str, object]:
    issuer = arguments.get("issuer")
    context = arguments.get("context")
    if issuer is None and context is not None:
        issuer = getattr(context, "issuer", None)
    return {"pap.company.issuer": issuer, "pap.company.domain": domain_of(issuer)}


def by_endpoint(arguments: Arguments) -> dict[str, object]:
    return {"pap.company.domain": domain_of(arguments.get("endpoint"))}


def signed_in_as(method: str) -> Before:
    """`by_issuer`, and which sign-in this is."""

    return lambda arguments: {**by_issuer(arguments), "pap.sign_in.method": method}


def sign_in_method(method: str) -> Before:
    return lambda arguments: {"pap.sign_in.method": method}


def company_result(result: Any) -> dict[str, object]:
    metadata = getattr(result, "oauth_metadata", None)
    return {"pap.company.issuer": getattr(metadata, "issuer", None)}


def session_result(result: Any) -> dict[str, object]:
    # A new Session is signed out: it is signed in on each request with an access token.
    return {"pap.session.signed_in": False}


def sign_in_result(result: Any) -> dict[str, object]:
    token = getattr(result, "token", None)
    granted = getattr(result, "granted_scopes", None)
    missing = getattr(result, "missing_scopes", None)
    status = getattr(result, "status", None)
    if status is None and getattr(result, "revoked", None) is not None:
        status = "revoked" if result.revoked else "not_revoked"
    return {
        "pap.sign_in.status": status if status is not None else "started",
        "pap.session.signed_in": True if token is not None else None,
        "pap.scopes.granted": len(granted) if granted is not None else None,
        "pap.scopes.missing": len(missing) if missing is not None else None,
    }


def conversation_result(result: Any) -> dict[str, object]:
    events = getattr(result, "events", None)
    return {
        "pap.conversation.status": getattr(result, "status", None),
        "pap.conversation.events": len(events) if events is not None else None,
    }


def operation_result(result: Any) -> dict[str, object]:
    """How an approval step ended: never the operation's terms or its IDs."""

    status = getattr(result, "status", None)
    return {"pap.operation.status": status if isinstance(status, str) else "approved"}
