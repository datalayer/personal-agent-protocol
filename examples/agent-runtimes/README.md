<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

# PAP company inspector with Agent Runtimes

This example is an Agent Runtimes Python `Application`. Its agent receives one
read-only tool, `inspect_pap_company`, which uses the PAP SDK to:

1. fetch `https://<domain>/.well-known/poppy.json` over real HTTPS;
1. validate the discovery document and its supported PAP version;
1. fetch OAuth metadata when authentication is advertised;
1. bind the exact issuer to the requested company domain; and
1. return only a small, verified, non-secret capability summary.

The model never receives raw discovery bodies, authorization URLs, callback
URLs, assertions, DPoP proofs, Session Tokens, or Account Tokens.

## Install and run

From the `personal-agent-protocol` repository:

```bash
python -m pip install -e '.[examples]'
loop apps run examples/agent-runtimes/app.py
```

Ask the application to inspect a domain that publishes PAP discovery metadata.
The request uses the SDK's public-network policy and response bounds. Production
services must additionally pin approved DNS results or use an enforcing egress
proxy, as described in the security documentation.

To validate the application definition without starting an agent runtime:

```bash
python -c "from agent_runtimes.loop.apps.build import build; print(build('examples/agent-runtimes/app.py').text)"
```

## Datalayer deployment boundary

This compact example performs discovery inside the application process so the
SDK integration is visible. In Datalayer Studio, the application tool should
call a typed metadata-gateway capability with an opaque tenant/application
context. The gateway owns DNS pinning, egress, caching, rate limits, and audit;
it returns this same safe summary. Direct Sign-In is then initiated through the
authorization gateway and trusted Preview browser handoff—not through an agent
tool—so secrets never cross runtime or model context.
