<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

# Personal Agent Protocol examples

- [`agent-runtimes/`](./agent-runtimes/) is a small Agent Runtimes application
  whose agent can inspect a PAP company over real HTTPS. It exposes only a
  verified, credential-free discovery summary as a read-only tool result.

Examples are intentionally explicit about trust boundaries. Authorization
callbacks, PKCE verifiers, assertions, proofs, and tokens must stay in trusted
host services and must never become agent tool arguments or results.
