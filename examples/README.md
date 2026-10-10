<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

# Personal Agent Protocol examples

- [`pydantic-ai/`](./pydantic-ai/) contains raw PAP examples built with plain
  Pydantic AI. Each example teaches one protocol feature without depending on
  Agent Runtimes.
- The paired Agent Runtimes applications live in the
  [`agent-runtimes` repository](https://github.com/datalayer/agent-runtimes/tree/main/examples/personal-agent-protocol).

Examples are intentionally explicit about trust boundaries. Authorization
callbacks, PKCE verifiers, assertions, proofs, and tokens must stay in trusted
host services and must never become agent tool arguments or results.
