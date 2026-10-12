# Telemetry

Atlas, Ada's personal agent, contributes a `pap.telemetry` sink to its Reactor
and runs a journey with Manzanita: discovery, a signed-out Session, a question,
Device Sign-In, and a confirmed exchange. The SDK emits one event per protocol
stage, its attributes taken from an allowlist (a domain, an issuer, a status, a
count). The tool hands the model those events exactly as a trace exporter or an
analytics pipeline would receive them: no token, code, proof, cookie, or
identifier can be in them.

With `opentelemetry-api` installed (`pip install "personal-agent-protocol[telemetry]"`),
contribute `OpenTelemetrySink()` instead and the same events become spans.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [telemetry guide](https://personalagentprotocol.org/docs/guides/telemetry).
