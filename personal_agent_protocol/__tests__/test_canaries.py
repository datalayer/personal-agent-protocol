# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""Credentials never reach logs, errors, model input, URLs, traces, or analytics (K-08, gates).

The demo worlds — Manzanita (Device, Direct, and Mediated Sign-In, Account
Tokens, conversations, operations, MCP with a Bearer token, the website),
Northwind with Ledgerly (two companies), the conformance runner's positive,
negative, and recovery cases, and the Pydantic AI examples' tools — run with
recognisable canaries:

- every opaque value the SDK and the companies mint (Session and Account
  Tokens, device codes, authorization codes, PKCE verifiers, assertion and
  proof IDs) comes from a `pap.randomSource` that writes `CANARY` and a counter
  into it;
- Ada's mediated password and one-time code are canary strings.

Every credential the parties exchange is then harvested from the wire, by kind
(Session and Bearer tokens, Account Tokens, DPoP proofs and private keys,
client, Session, and browser assertions, authorization and device codes, PKCE
verifiers, mediated passwords and one-time codes, website cookies), and none
may appear in:

- a log record of any logger at DEBUG, with its traceback;
- a trace or an analytics event: every Reactor of the run (the agents' and the
  companies') has a `pap.telemetry` sink, each `TelemetryEvent` is kept as the
  JSON an analytics pipeline would get, and, where `opentelemetry-sdk` is
  installed, as the span the `OpenTelemetrySink` exports (name, attributes,
  status);
- an exception the SDK raises: its `str`, `repr`, and attributes;
- a URL any party requests (the protocol puts a credential in no requested
  URL; the authorization code travels in the redirect back to the agent's
  `redirect_uri`, and the device `user_code` in `verification_uri_complete`,
  both opened by the user's browser, never requested by an agent — checked
  below);
- what a model reads: every response body but the token and device
  endpoints' (conversation replies, API and MCP results, operation
  summaries, mediated sign-in answers), each `PapSignIn.model_view()`, and the
  examples' tool results.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import inspect
import json
import logging
import runpy
import secrets
import sys
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import jwt
import pytest

import personal_agent_protocol
from personal_agent_protocol.demo import kit, manzanita
from personal_agent_protocol.errors import PersonalAgentProtocolError
from personal_agent_protocol.reactor import TELEMETRY_SINKS, PapCorePlugin, SystemRandomSource
from personal_agent_protocol.telemetry import OpenTelemetrySink, TelemetryEvent

from . import (
    test_company_end_to_end,
    test_company_refusals,
    test_direct_and_api,
    test_guide_security,
    test_mcp_and_web,
    test_two_companies,
)

PACKAGE = Path(personal_agent_protocol.__file__).parent
EXAMPLES = PACKAGE.parent / "examples" / "pydantic-ai"
PASSWORD = "CANARY-password-7f3a9c"
ONE_TIME_CODE = "CANARY-code-5521"
#: Values shorter than this are not searched for (a six-digit code would match anywhere).
SHORTEST = 8
#: The examples' tools that take arguments, and what a model would pass them.
EXAMPLE_ARGUMENTS = {"explain_dpop_proof": ("POST", "https://manzanita.example/oauth/token")}
#: Response bodies that carry credentials by design, to the agent's code alone.
CREDENTIAL_ENDPOINTS = ("/oauth/token", "/oauth/device")


class CanaryRandom:
    """`pap.randomSource` everywhere: a counter and `CANARY`, then padding."""

    def __init__(self) -> None:
        self.count = 0

    def bytes(self, length: int) -> bytes:
        if length <= 0:
            raise ValueError("random byte length must be positive")
        if length < 12:  # short values (user codes) stay random: they must not collide
            return secrets.token_bytes(length)
        self.count += 1
        width = -(-length // 3) * 4
        # The counter first: a device user code is the first eight characters of an ID.
        text = f"{self.count:08d}CANARY".ljust(width, "A")
        return base64.urlsafe_b64decode(text)[:length]


@dataclass
class Harvest:
    """The credentials seen on the wire, and every sink they must stay out of."""

    secrets: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    urls: list[str] = field(default_factory=list)
    model_texts: list[tuple[str, str]] = field(default_factory=list)
    chat_texts: list[tuple[str, str]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    callbacks: list[str] = field(default_factory=list)
    telemetry: list[str] = field(default_factory=list)
    stages: set[str] = field(default_factory=set)

    def secret(self, kind: str, value: object) -> None:
        if isinstance(value, str) and len(value) >= SHORTEST:
            self.secrets[kind].add(value)

    def request(self, request: httpx.Request) -> None:
        self.urls.append(str(request.url))
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if token:
            self.secret(f"{scheme} access token", token)
        self.secret("DPoP proof", request.headers.get("dpop"))
        for name, value in _cookies(request.headers.get("cookie", "")):
            self.secret(f"cookie {name}", value)
        body = request.content
        kind = request.headers.get("content-type", "")
        path = request.url.path
        if kind.startswith("application/x-www-form-urlencoded"):
            form = dict(parse_qsl(body.decode()))
            self.secret("client assertion", form.get("client_assertion"))
            self.secret("Session or browser assertion", form.get("assertion"))
            self.secret("authorization code", form.get("code"))
            self.secret("PKCE verifier", form.get("code_verifier"))
            self.secret("device code", form.get("device_code"))
            self.secret("Account Token", form.get("refresh_token"))
            self.secret("revoked token", form.get("token"))
        elif kind.startswith("application/json") and path.startswith("/poppy/sign-in"):
            sent = json.loads(body or b"{}")
            self.secret("mediated password", sent.get("credentials", {}).get("password"))
            self.secret("one-time code", sent.get("code"))

    def response(self, request: httpx.Request, response: httpx.Response) -> None:
        for name, value in _cookies(response.headers.get("set-cookie", "")):
            self.secret(f"cookie {name}", value)
        if not response.headers.get("content-type", "").startswith("application/json"):
            if response.headers.get("content-type", "").startswith(("text/", "application/")):
                self.model_texts.append((f"{request.method} {request.url.path}", response.text))
            return
        if request.url.path in CREDENTIAL_ENDPOINTS:
            answer = response.json()
            self.secret(f"{answer.get('token_type', '')} access token", answer.get("access_token"))
            self.secret("Account Token", answer.get("refresh_token"))
            self.secret("device code", answer.get("device_code"))
            self.secret("user code", answer.get("user_code"))
            return
        where = f"{request.method} {request.url.path}"
        self.model_texts.append((where, response.text))
        answer = json.loads(response.content) if response.content else None
        for event in answer.get("events", ()) if isinstance(answer, dict) else ():
            message = event.get("message") or {}
            self.chat_texts.append((f"a message in {where}", str(message.get("text"))))

    def all_secrets(self, *, but: tuple[str, ...] = ()) -> dict[str, str]:
        return {
            value: kind
            for kind, values in self.secrets.items()
            if kind not in but
            for value in values
        }


def _cookies(header: str) -> Iterator[tuple[str, str]]:
    for part in header.replace(",", ";").split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name and name.lower() not in {"path", "expires", "max-age", "samesite"}:
            yield name, value


class _Records(logging.Handler):
    def __init__(self, harvest: Harvest) -> None:
        super().__init__(logging.DEBUG)
        self.harvest = harvest
        self.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        self.harvest.logs.append(self.format(record))


def _describe(error: BaseException) -> str:
    parts = [type(error).__name__, str(error), repr(error), repr(error.args)]
    parts.extend(repr(value) for value in getattr(error, "__dict__", {}).values())
    return " ".join(parts)


@pytest.fixture
def harvest(monkeypatch: pytest.MonkeyPatch) -> Iterator[Harvest]:
    found = Harvest()

    # Canaries: minted values, the mediated password, and the one-time code.
    canary = CanaryRandom()
    monkeypatch.setattr(SystemRandomSource, "bytes", lambda self, length: canary.bytes(length))
    monkeypatch.setitem(manzanita.ADA, "password", PASSWORD)
    monkeypatch.setattr(manzanita, "ADA_CODE", ONE_TIME_CODE)
    monkeypatch.setattr(test_company_end_to_end, "ADA_CODE", ONE_TIME_CODE)
    _record_the_wire(monkeypatch, found)
    _record_private_keys(monkeypatch, found)
    _record_telemetry(monkeypatch, found)
    with _recorded_errors(monkeypatch, found), _recorded_logs(found):
        yield found


def _record_the_wire(monkeypatch: pytest.MonkeyPatch, found: Harvest) -> None:
    """Every request any party makes on the in-process network, and its answer."""

    original = kit._Routing.handle_async_request

    async def recording(self: Any, request: httpx.Request) -> httpx.Response:
        found.request(request)
        response = await original(self, request)
        await response.aread()
        found.response(request, response)
        return response

    monkeypatch.setattr(kit._Routing, "handle_async_request", recording)


class _Telemetry:
    """`pap.telemetry` on every Reactor: each event as analytics JSON and as an exported span."""

    def __init__(self, found: Harvest) -> None:
        self.found = found
        self.spans: Any = None
        try:
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import SimpleSpanProcessor
            from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
                InMemorySpanExporter,
            )
        except ImportError:  # the adapter is optional; the analytics JSON is always kept
            self.otel = None
            return
        self.spans = InMemorySpanExporter()
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(self.spans))
        self.otel = OpenTelemetrySink(provider.get_tracer("canaries"))

    def record(self, event: TelemetryEvent) -> None:
        self.found.stages.add(event.stage)
        self.found.telemetry.append(json.dumps(event.as_dict()))
        if self.otel is not None:
            self.otel.record(event)
            for span in self.spans.get_finished_spans():
                self.found.telemetry.append(
                    json.dumps(
                        {
                            "span": span.name,
                            "attributes": dict(span.attributes or {}),
                            "status": str(span.status.description),
                        }
                    )
                )
            self.spans.clear()


def _record_telemetry(monkeypatch: pytest.MonkeyPatch, found: Harvest) -> None:
    sink = _Telemetry(found)
    original = PapCorePlugin.provide_contributions

    @functools.wraps(original)
    def with_sink(self: PapCorePlugin, contributions: Any) -> None:
        original(self, contributions)
        contributions.contribute(TELEMETRY_SINKS, sink, contribution_id="canaries", order=100)

    monkeypatch.setattr(PapCorePlugin, "provide_contributions", with_sink)


def _record_private_keys(monkeypatch: pytest.MonkeyPatch, found: Harvest) -> None:
    """The DPoP keys and the agents' signing keys."""

    keys = kit.DpopKeys.__call__

    async def dpop_keys(self: Any, request: Any) -> Any:
        material = await keys(self, request)
        found.secret("DPoP private key", _private(material.private_key))
        return material

    monkeypatch.setattr(kit.DpopKeys, "__call__", dpop_keys)
    signer = kit.AgentIdentity.signer

    def identity_signer(self: kit.AgentIdentity) -> Any:
        found.secret("agent signing key", _private(self.private_key))
        return signer(self)

    monkeypatch.setattr(kit.AgentIdentity, "signer", identity_signer)


@contextlib.contextmanager
def _recorded_errors(monkeypatch: pytest.MonkeyPatch, found: Harvest) -> Iterator[None]:
    """Every SDK error made, and (3.12+, `sys.monitoring`) every exception SDK code raises."""

    init = PersonalAgentProtocolError.__init__

    def recorded_init(self: PersonalAgentProtocolError, *args: Any, **kwargs: Any) -> None:
        init(self, *args, **kwargs)
        found.errors.append(_describe(self))

    monkeypatch.setattr(PersonalAgentProtocolError, "__init__", recorded_init)
    monitoring = getattr(sys, "monitoring", None)
    if monitoring is None:
        yield
        return
    tool = next(i for i in range(6) if monitoring.get_tool(i) is None)
    monitoring.use_tool_id(tool, "pap-canaries")

    def raised(code: Any, _offset: int, error: BaseException) -> None:
        # A StopIteration is how an awaited step hands its value back (a body chunk read
        # within a size limit): control flow, never an error anything reports.
        if isinstance(error, StopIteration | StopAsyncIteration):
            return
        if code.co_filename.startswith(str(PACKAGE)) and "__tests__" not in code.co_filename:
            found.errors.append(_describe(error))

    monitoring.register_callback(tool, monitoring.events.RAISE, raised)
    monitoring.set_events(tool, monitoring.events.RAISE)
    try:
        yield
    finally:
        monitoring.set_events(tool, 0)
        monitoring.register_callback(tool, monitoring.events.RAISE, None)
        monitoring.free_tool_id(tool)


@contextlib.contextmanager
def _recorded_logs(found: Harvest) -> Iterator[None]:
    """Every logger, enabled, at DEBUG, into one handler on the root."""

    handler = _Records(found)
    root = logging.getLogger()
    loggers = [
        logger
        for logger in logging.root.manager.loggerDict.values()
        if isinstance(logger, logging.Logger)
    ]
    saved = [(logger, logger.level, logger.disabled, logger.propagate) for logger in loggers]
    for logger in loggers:
        logger.setLevel(logging.NOTSET)
        logger.disabled = False
        logger.propagate = True
    root_level = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    try:
        yield
    finally:
        root.removeHandler(handler)
        root.setLevel(root_level)
        for logger, level, disabled, propagate in saved:
            logger.setLevel(level)
            logger.disabled = disabled
            logger.propagate = propagate


def _private(key: Any) -> str:
    return str(json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key))["d"])


def _leaks(harvest: Harvest, sinks: list[tuple[str, str]], **kwargs: Any) -> list[str]:
    """Where a credential appears: its kind, the sink, and the text around it (canaries only)."""

    found = []
    for value, kind in harvest.all_secrets(**kwargs).items():
        for where, text in sinks:
            at = text.find(value)
            if at >= 0:
                around = text[max(0, at - 80) : at + len(value) + 40].replace(value, f"<{kind}>")
                found.append(f"{kind} in {where[:120]}: …{around}…")
    return found


def _assert_nothing_leaked(harvest: Harvest) -> None:
    values = harvest.all_secrets()
    kinds = set(harvest.secrets)
    # Every kind of credential was seen, so the search is not vacuous.
    for kind in (
        "DPoP access token",
        "Bearer access token",
        "Account Token",
        "DPoP proof",
        "DPoP private key",
        "agent signing key",
        "client assertion",
        "Session or browser assertion",
        "authorization code",
        "PKCE verifier",
        "device code",
        "user code",
        "mediated password",
        "one-time code",
        "cookie __Host-poppy_session",
        "cookie __Host-poppy_consent",
    ):
        assert kind in kinds, f"no {kind} was exchanged: the canary run is incomplete"
    minted = [value for value in values if "CANARY" in value]
    assert minted, "minted credentials carry the canary"
    assert harvest.logs, "the run logged nothing: the log capture is not wired"
    assert harvest.errors, "the run raised nothing: the error capture is not wired"
    assert harvest.stages == {
        "discovery",
        "session",
        "sign_in",
        "conversation",
        "operation",
    }, "a protocol stage emitted no telemetry: the trace capture is not wired"
    counts = ", ".join(f"{kind} {len(found)}" for kind, found in sorted(harvest.secrets.items()))
    sys.stdout.write(  # the numbers, in the test output (`-s`)
        f"canaries: {len(values)} credentials ({counts}); searched {len(harvest.logs)} log "
        f"records, {len(harvest.errors)} errors, {len(harvest.urls)} URLs, "
        f"{len(harvest.telemetry)} telemetry events and spans, "
        f"{len(harvest.model_texts)} model-readable bodies, {len(harvest.chat_texts)} messages\n"
    )

    _assert_no_leak(harvest)


def _assert_no_leak(harvest: Harvest) -> None:
    # Logs and errors: no credential at all.
    assert _leaks(harvest, [("a log record", record) for record in harvest.logs]) == []
    assert _leaks(harvest, [("an error", error) for error in harvest.errors]) == []
    # Traces and analytics: no credential at all, the user code included.
    assert _leaks(harvest, [("a telemetry event", event) for event in harvest.telemetry]) == []
    # Requested URLs: no credential. The user code is in `verification_uri_complete`
    # (RFC 8628 §3.3.1), which the user's browser opens; no agent requests it.
    assert _leaks(harvest, [(url, url) for url in harvest.urls]) == []
    # What a model reads: no credential. A device user code may travel in a message's
    # `data`, for the person's page (as in a PapSignIn display), never in its text.
    assert _leaks(harvest, harvest.model_texts, but=("user code",)) == []
    assert _leaks(harvest, harvest.chat_texts) == []


@pytest.mark.asyncio
async def test_no_credential_reaches_logs_errors_urls_or_model_text(harvest: Harvest) -> None:
    from personal_agent_protocol.conformance import CASES, run_conformance, select_cases
    from personal_agent_protocol.demo.conformance import ManzanitaConformance

    # Manzanita: Device Sign-In, conversations, operations, Account Tokens.
    await test_company_end_to_end.test_a_user_and_a_company_from_question_to_confirmed_exchange()
    await test_company_end_to_end.test_mediated_sign_in_with_a_one_time_code()
    await test_company_end_to_end.test_the_conversation_streams_and_a_stranger_cannot_read_it()
    # Direct Sign-In with PKCE, the consent page, and the API.
    direct = test_direct_and_api
    await direct.test_signed_out_then_direct_sign_in_then_a_read_and_a_proposed_exchange()
    await direct.test_a_code_works_once()
    await test_guide_security.test_the_consent_form_is_bound_to_the_browser_that_was_shown_it()
    # MCP with a Bearer token, and the website with its cookie.
    await (
        test_mcp_and_web.test_a_signed_in_bearer_reads_and_proposes_through_mcp_the_same_operation()
    )
    await test_mcp_and_web.test_a_bearer_token_is_refused_everywhere_but_its_mcp_server()
    await test_mcp_and_web.test_the_operation_confirmed_on_the_website_is_the_same_operation_once()
    await test_mcp_and_web.test_the_website_follows_the_session_and_refuses_bad_assertions()
    await test_guide_security.test_the_operation_page_refuses_cross_site_and_another_browsers_form()
    # Refusals: replays, other keys, polling too fast, conflicts.
    await test_company_refusals.test_a_replayed_token_request_is_refused()
    await test_company_refusals.test_a_session_token_with_another_key_is_refused()
    await test_company_refusals.test_polling_too_fast_is_slow_down()
    # Northwind and Ledgerly: two companies, Ledgerly a personal agent at the bank.
    two = test_two_companies
    await two.test_ledgerly_pays_at_northwind_for_ada_with_her_approval_then_within_her_bounds()
    # The conformance runner: every positive, negative, and recovery case but the one
    # whose probe puts a Session Token in a URL on purpose, to see the company refuse it.
    world = ManzanitaConformance()
    cases = tuple(case for case in select_cases() if case.id != "security.token-in-url-refused")
    report = await run_conformance(world.context(), cases=cases)
    assert len(report.results) == len(CASES) - 1
    assert [r.id for r in report.results if r.outcome == "failed"] == []
    harvest.model_texts.append(("the conformance report", json.dumps(report.to_json())))

    # Sign-in displays: what a model is told of each.
    harvest.model_texts.extend(_sign_in_views(harvest))
    _assert_nothing_leaked(harvest)


def _sign_in_views(harvest: Harvest) -> list[tuple[str, str]]:
    from personal_agent_protocol.ui import PapSignIn

    user_codes = sorted(harvest.secrets["user code"])
    views = []
    for user_code in user_codes:
        display = PapSignIn(
            mode="device",
            open=f"https://manzanita.example/device?user_code={user_code}",
            code=user_code,
        )
        views.append(
            (f"PapSignIn(device {user_code}).model_view()", json.dumps(display.model_view()))
        )
    for url in harvest.urls:
        if urlsplit(url).path == "/oauth/authorize":
            display = PapSignIn(mode="direct", open=url)
            views.append(("PapSignIn(direct).model_view()", json.dumps(display.model_view())))
    mediated = PapSignIn(
        mode="mediated",
        open="https://datalayer.example/pap/sign-in?ticket=t",
        sent_to="a•••@example.com",
    )
    views.append(("PapSignIn(mediated).model_view()", json.dumps(mediated.model_view())))
    assert user_codes and len(views) > len(user_codes) + 1
    return views


@pytest.mark.asyncio
async def test_the_examples_tools_tell_a_model_no_credential(harvest: Harvest) -> None:
    pytest.importorskip("pydantic_ai")
    ran = []
    results: list[tuple[str, str]] = []
    for path in sorted(EXAMPLES.glob("*/app.py")):
        namespace = runpy.run_path(str(path), run_name="pap_canaries")
        for name, value in namespace.items():
            if not name.startswith(("run_", "explain_", "demonstrate_", "read_")):
                continue
            if not callable(value) or getattr(value, "__module__", None) != "pap_canaries":
                continue
            arguments = EXAMPLE_ARGUMENTS.get(name, ())
            required = [
                parameter
                for parameter in inspect.signature(value).parameters.values()
                if parameter.default is inspect.Parameter.empty
            ]
            assert len(required) == len(arguments), f"{name} needs arguments"
            result = value(*arguments)
            if hasattr(result, "__await__"):
                result = await result
            results.append((f"{path.parent.name}: {name}()", json.dumps(result, default=str)))
            ran.append(name)
    assert {"run_manzanita_journey", "run_two_companies"} <= set(ran)
    assert harvest.secrets, "the tools exchanged no credential"
    # What the tools hand their model, the user code included; then the other sinks.
    assert _leaks(harvest, results) == []
    _assert_no_leak(harvest)
