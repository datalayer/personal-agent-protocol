<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

# PAP feature examples with Agent Runtimes

Each directory is one small Agent Runtimes Python `Application` and teaches one
PAP feature:

| Example                                                 | Feature                                                                      | What may reach the model                           |
| ------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------- |
| [`company-discovery`](./company-discovery/)             | Company discovery, version/domain/issuer validation, and interface inventory | Verified company capability summary                |
| [`agent-identity`](./agent-identity/)                   | Client metadata, same-domain JWKS, and public signing policy                 | Verified identity summary                          |
| [`session-assertion`](./session-assertion/)             | Pairwise subject and short-lived, unique Session assertion claims            | Claim policy only; no subject, `jti`, or assertion |
| [`direct-sign-in-boundary`](./direct-sign-in-boundary/) | OAuth state, S256 PKCE, and user-owned browser handoff boundary              | Requested scopes and security properties only      |

The first two use Agent Runtimes' `PapPersonalAgentCapability`, available in
both its Python and TypeScript packages. It owns the model-safe summary
boundary while the PAP SDK owns wire validation.

## Install and run

From the `personal-agent-protocol` repository:

```bash
python -m pip install -e .
python -m pip install -e ../agent-runtimes
loop apps run examples/agent-runtimes/company-discovery/app.py
```

Ask the application to inspect a domain that publishes PAP discovery metadata.
The request uses the SDK's public-network policy and response bounds. Production
services must additionally pin approved DNS results or use an enforcing egress
proxy, as described in the security documentation.

To validate the application definition without starting an agent runtime:

```bash
python scripts/validate_agent_runtime_examples.py
```

## Datalayer deployment boundary

These compact examples perform public-metadata work in process so the SDK
integration is visible. In Datalayer Studio, the application tools call typed
metadata-gateway capabilities with opaque tenant/application context. The
gateway owns DNS pinning, egress, caching, rate limits, and audit; it returns
the same safe summaries. Direct Sign-In is initiated through the authorization
gateway and trusted Preview browser handoff—not through an agent tool—so
secrets never cross runtime or model context.
