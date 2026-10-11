<!--
  ~ Copyright (c) 2023-2024 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

## 0.6.0 (2026-10-11)

- **Breaking — company store:** `pap.company.store` is an async keyed store of
  versioned JSON records: `get`, `put`, `create` (only if absent), `replace`
  (compare-and-set on a version), `take` (read and delete at once), and
  `delete`, each by kind and key with an optional expiry; an expired record
  reads as absent. The dict-of-records `CompanyStore` (Maps in TypeScript) is
  gone, with no compatibility path. The service never mutates a stored record:
  one-use codes, Direct Sign-In decisions, device approval and consumption,
  Account Token rotation (one refresh claims the presented token), revocation
  of a whole sign-in, Mediated attempts, message IDs, conversation events and
  status, and operation confirmation (one compare-and-set to `in_progress`;
  only its winner performs) go through `create`, `take`, or `replace`, so a
  company restarted, replaced, or rolled back over a durable store continues
  every flow. Records are frozen dataclasses with `to_json`/`from_json` in
  Python and JSON-ready objects in TypeScript; `MemoryCompanyStore` keeps JSON
  copies with real versions and judges expiry by the company's `pap.clock`.
- **Breaking — company methods are async:** `approve_device`, `deny_device`,
  `approve_authorization`, `deny_authorization`, `authorization_request`,
  `revise`, `settle`, `forget_events`, and `disconnect` (and their TypeScript
  names) now return coroutines or promises. `operation_record(operation_id)`
  (`operationRecord`) reads an operation as the company keeps it. The
  in-memory `CompanyService.extensions` map is gone: a client's declared
  extensions are a store record.
- **Store conformance kit:** `personal_agent_protocol.company.testing.check_store`
  and `checkStore` (`@datalayer/personal-agent-protocol/server`) check any
  backend: absent and present records, expiry, `take` once under concurrency,
  `create` only if absent, compare-and-set conflicts, values copied rather than
  shared, and a round trip of every record kind. Python and TypeScript tests
  restart a company over one store mid-flow (device approval, Account Token
  rotation, an operation confirmed once, an event cursor resumed).
- The demo companies take a `store` (Manzanita in both languages), and
  `demo.kit.StorePlugin` contributes one.

## 0.5.0 (2026-10-11)

- **Security:** Direct Sign-In moves the Account Token into `pap.tokenStore`
  behind an opaque `account_…` reference, as Device and Mediated Sign-In do: the
  result's token no longer carries `refresh_token`, and the new
  `account_token_reference` (`accountTokenReference` in TypeScript) names it
  (§4.8). Hosts that read `result.token.refresh_token` read the token store.
- **Company:** hosted sign-in pages. `CompanyConfig.device_page` (`devicePage`)
  becomes the Device Sign-In `verification_uri` (`&code=<user_code>` completes
  it); `consent_page` (`consentPage`, with `{request_id}`) makes
  `GET /oauth/authorize` answer `303` to it after every check, never for an
  unverified `redirect_uri`. `authorization_request(request_id)`
  (`authorizationRequest`) reads a pending request back for that page without
  consuming it.
- **TypeScript parity:** `negotiateExtensions`, `extensionNameKind`,
  `extensionDomain`, `extensionRequired`, `knownApis`, `conversationEndpoint`,
  `openapiUrl`; message `context` facts validated as in Python; a 429's
  `Retry-After` is `details.retry_after` on Session, conversation and
  operation errors (Sessions used `retryAfter`); `confirm` answers
  `not_confirmed` for a cancelled or expired operation. The TypeScript specs
  pass every conformance fixture case the SDK decides alone.
- **Fuzzing** (seeded, no new dependency): strict JSON, URL safety and the
  operation state machine in Python; strict JSON and URL safety in TypeScript.
  It found, and this release fixes: Python's strict JSON accepted `NaN`,
  `Infinity` and `-Infinity` (not JSON, and refused by TypeScript), and the URL
  safety policy accepted an empty user-information part (`https://:@host/`).

## 0.4.0 (2026-10-11)

Both sides of PAP draft 0.1 and Operations v1, in Python and TypeScript.

- **Personal agent:** Account Tokens (refresh, serialized rotation, narrowing,
  revocation), Mediated Sign-In with protected input, conversation streaming
  (SSE, `text-delta`, `Last-Event-ID`), handoff, Direct Conversations and
  closing, the Operations v1 client (exact approval, standing permissions,
  recovery), resource-bound MCP Bearer, OpenAPI and MCP clients, operations
  from every channel.
- **Company:** a framework-neutral reference company assembled from Reactor
  points (`pap.company.*`), served over ASGI (Python) and node:http(s)
  (TypeScript): discovery, Sessions, Direct, Device and Mediated Sign-In,
  Account Tokens, conversations, an OpenAPI API and an MCP endpoint, the
  browser session, Operations performed at most once.
- **Demonstrations:** a user with a company (Manzanita), two companies working
  together (Ledgerly at Northwind Bank), served in process or over real TCP
  and TLS (`server` extra).
- **Conformance:** the requirement ledger of every MUST and SHOULD
  (`protocol/requirements.yaml`), 113 fixture cases, a runner with JSON and
  JUnit output (91 of 91 against the reference company over TLS), and the four
  Python/TypeScript pairings.
- **CLI:** `pap sessions`, `auth`, `api`, `conversations`, `operations`,
  `requirements`, `conformance`, with protected input never as an option.
