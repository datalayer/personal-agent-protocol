<!--
  ~ Copyright (c) 2023-2024 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

## 0.8.0 (2026-10-11)

- **Consent pages bind the browser (Guides, consent pages):** the built-in
  consent page sets a `__Host-poppy_consent` cookie (`Secure`, `HttpOnly`,
  `SameSite=Strict`), stores its digest with the sign-in request
  (`PendingAuthorization.browser_binding`, `browserBinding`), and puts a CSRF
  token derived from the cookie in its form, which posts to
  `/oauth/authorize`. `CompanyService.consent_decision(request)`
  (`consentDecision`) returns the user's decision only for a same-origin POST
  (`Sec-Fetch-Site`, `Origin`) carrying the bound cookie and its token; a
  cross-site POST, a foreign or opaque origin, a missing cookie or token, and a
  form replayed from another browser are refused. A hosted consent page gets no
  binding. The website's operation page carries a token derived from its
  `poppy_session` cookie and refuses a cross-site POST or another browser's
  form with `403`. Pages keep `frame-ancestors 'none'` and `X-Frame-Options:
  DENY`.
- **Overlapping JWKS verified at the company:** during a rotation assertions
  signed with either key verify; the retired key is refused once the cached set
  expires; unknown `kid`s refetch at most once a minute (tests in both SDKs;
  the guide says how long to keep a retired key published).
- **Credentials stay out of logs, errors, URLs, and model context:** a canary
  suite in both SDKs runs the demo worlds, every conformance case, and the
  Pydantic AI examples' tools with `CANARY`-minted values and canary
  passwords, and fails if any credential exchanged appears in a log record, a
  raised error, a requested URL, a model-readable body, a message's text, or a
  `PapSignIn` model view; the TypeScript suite also checks the built `lib/` and
  that the browser entry reaches no demo credential. Fixed the leak it found:
  Ledgerly's connect reply put Northwind's device user code in the message
  text (it is now in the message's `data` only).
- **Load tests** (`load` mark, `PAP_LOAD_SIZE`; 512 in CI) for replay caches,
  shared budgets, device polling, and SSE fan-out, with
  [a docs page](docs/docs/protocol/load-tests.mdx). They found and this release
  fixes:
  - `MemoryReplayCache` never forgot an identifier. It now takes a clock
    (the company's), sweeps expired identifiers whenever it doubles, and
    reports its `len()` / `size`. The verifiers now remember an identifier
    exactly as long as they would accept it: a DPoP proof until its `iat`
    leaves the acceptance window (it was `now` plus the window), a client or
    Session assertion until `exp` plus the 30-second skew (it was `exp`) — a
    replay cache that honoured the old expiries could accept a replay inside
    those gaps.
  - `SharedRateLimitBudget` slept while holding its per-company lock, so
    `max_wait` bounded each caller's own sleep but not its time queued. It now
    reserves each caller's turn when it asks (the generic cell rate algorithm):
    concurrent callers never exceed the rate and burst, a turn beyond
    `max_wait` is refused at once with `rate_limited`, and a timer that fires
    early (Node's can) is slept out. TypeScript's default sleep rounds up to
    whole milliseconds.
- **Kits:** `check_replay_cache` / `checkReplayCache` check a
  `pap.company.replayCache` (of many callers marking one identifier at once,
  exactly one wins); `check_store` / `checkStore` take a `concurrency`.

## 0.7.0 (2026-10-11)

- **reactor.ui displays:** `personal_agent_protocol.ui.PapSignIn`
  (`application/vnd.datalayer.pap.sign-in+json`, version 1) is a sign-in
  waiting for the person (`direct`, `device` or `mediated`; an `https` page
  only). The page to open and the device code are for the page alone — a
  device's verification URL may carry the code — so neither is in the
  model's view, and the text names only the company's domain. `from_answer`
  reads a `pap_sign_in` answer and `tool_meta()` is the MCP `_meta` that carries
  the display. The core plugin declares the type through `provide_display_types`.
  Needs `datalayer_reactor` 1.1 (the new `ui` extra); nothing else imports it.

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
