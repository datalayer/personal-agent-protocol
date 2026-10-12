<!--
  ~ Copyright (c) 2023-2024 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

## 0.16.0 (2026-10-12)

- **A company reports what it did and refused**
  ([docs](docs/docs/guides/telemetry.mdx#what-a-company-reports)): the
  company service in both languages emits to `pap.telemetry` (stage
  `company`) an agent's identity verified for the first time or with new
  metadata, a Session started or renewed, a Session moved to the MCP server or
  a browser (`pap.company.interface.switch`), a sign-in ended
  (`pap.company.sign_out`), and each refused request with
  the protocol's code, the route, the status and whether a proof or assertion
  was a replay (`pap.replayed`). New attributes `pap.client.id`,
  `pap.interface`, `pap.company.route`, `pap.http.status`, `pap.replayed`;
  device-flow progress is not a refusal.

## 0.15.0 (2026-10-12)

- **A password reset ends the sign-ins from before it**
  ([docs](docs/docs/guides/company.mdx)): a company's `AccountDirectory` that
  also answers `signed_out_before(account_id)` (`AccountSignOuts`; TypeScript:
  the optional `signedOutBefore`) is asked on every signed-in request and
  Account Token refresh; a sign-in from before that moment is refused
  (`invalid_token`, `invalid_grant`) and revoked whole — its Account Tokens,
  and the Sessions signed in with them continuing signed out — while a sign-in
  after it works. Account Tokens record when their sign-in happened
  (`signed_in_at`); one without it is taken for earlier.

## 0.14.0 (2026-10-12)

- **Every request to a company on the safe path**
  ([docs](docs/docs/guides/operational-limits.mdx)): `create_resolving_client`
  (`ResolvingTransport`) resolves the host before each request — Sessions,
  sign-ins, conversations, API calls, Operations, MCP — refuses it unless it is
  HTTPS and every address is public (`unsafe_url`, `unsafe_address`), and dials
  only the approved addresses; no redirect followed, no environment proxy;
  `max_response_bytes` bounds every body for callers that read whole bodies.
  Python's counterpart of `createResolvingFetch`.

## 0.13.0 (2026-10-12)

- **`PapOutcome`, what a confirmed operation came to, as a Reactor display**
  ([docs](docs/docs/guides/operations.mdx)): `personal_agent_protocol.ui`
  declares `application/vnd.datalayer.pap.outcome+json` v1 — the company, what
  was confirmed, the revision, the state, the company's final `result.summary`
  verbatim (partial effects included; required once final, none while in
  progress) and who confirmed it; `PapOutcome.of(company, operation)`. The core
  plugin registers it. TypeScript: `PapOutcomeData`, `isPapOutcome`,
  `papOutcomeText`, `papOutcomeDisplay`, checked against
  `protocol/fixtures/pap-outcome-display.json`.
- **A scope no longer offered ends the Sessions holding it**
  ([docs](docs/docs/guides/company.mdx)): both reference companies refuse a
  Session whose scopes the current configuration no longer offers (a rollback,
  a narrower version) as `invalid_token`, and an Account Token refresh for such
  a scope as `invalid_scope`; asked within what is offered, the same token
  serves.

## 0.12.0 (2026-10-12)

- **`PapConfirm`, an operation to confirm as a Reactor display**
  ([docs](docs/docs/guides/operations.mdx)): `personal_agent_protocol.ui`
  declares `application/vnd.datalayer.pap.confirm+json` v1 — the company's
  words and terms, the revision, what it does (a Rules class), the revision it
  replaced, whether only the person may confirm it, and the Session by a
  one-way reference (`PapSessionShown.of`) the model never sees. The core
  plugin registers it beside `PapSignIn`. TypeScript: `PapConfirmData`,
  `isPapConfirm`, `papConfirmText`, `papConfirmDisplay`, checked against the
  example the Python tests write (`protocol/fixtures/pap-confirm-display.json`).

## 0.11.0 (2026-10-12)

The SDKs of 0.10.0, released as the first complete Python and TypeScript
SDKs: no API or wire change since 0.10.0, and no migration.

- **Docs: Open security points** ([docs](docs/docs/security/review.mdx))
  replaces the record of the 0.10.0 review with what is open now: residual
  risks (unbounded known-client records, the account directory's own
  throttling), what a deployment provides (a durable shared company store, key
  custody, the agent's stores, Node network policy), the draft's open
  questions, and interoperability not yet exercised.
- **Docs: a blog**, with the 0.11.0 announcement.

## 0.10.0 (2026-10-12)

- **Security review** ([docs](docs/docs/security/review.mdx)): an independent
  review of both SDKs, each finding confirmed by a probe and fixed in both
  SDKs where the behaviour exists, with a regression test per finding
  (`test_security_review.py`, `security-review.test.mjs`); contract changes in
  the [migration guide](docs/docs/releases/migration.mdx).

  - A sign-in after an MCP Bearer token no longer downgrades the Session: the
    signed-in token is DPoP, for no resource, replacing only DPoP tokens.
  - Mediated Sign-In attempts are limited in the store (by account identifier,
    agent's user, Session; wrong codes per account across sign-ins), then
    `429 rate_limited` with `Retry-After`, the lockout doubling;
    `AccountDirectory.authenticate` takes a `SignInContext`. A missing or
    unknown scope is `invalid_scope`.
  - The default replay cache lives in the company store (`StoreReplayCache`):
    a store shared by replicas is a shared cache. The memory store sweeps
    expired records.
  - A retried conversation start answers through the ownership check.
  - Operations record the scopes confirming them requires; `operations`
    without `write_scopes` is a configuration error.
  - TypeScript SSRF: `isGlobalAddress`, a textual check that refuses every
    non-global literal and local name, and `createResolvingFetch` (resolve,
    vet every address, dial the vetted one) as the Node company's default.
    Python judges NAT64, IPv4-compatible, and 6to4 addresses by the IPv4
    address they carry.
  - Responses are read only up to their limit; a request with a body is never
    re-sent to a redirect; TypeScript metadata deadlines abort the request.
  - The client policy is asked before any `client_id` is resolved and on
    every token use; malformed bodies are `400`, repeated `Authorization` or
    `DPoP` headers refused.
  - `pap operations approve` needs a terminal or an approval surface; stored
    approvals carry a MAC under a key in the token store; the CLI's files
    change under a lock.
  - The web cookie is `__Host-poppy_session`; the demo agents read nothing
    without the read scope; approval summaries quote only identifiers.

- **External interoperability exercise** (pi-poppy, poppy-agent, poppy-demo,
  poppyseed): an operation past `proposed` omits `expires_at` instead of
  `null`; a client assertion's `aud` may be the issuer, the token endpoint, or
  the endpoint called; token-endpoint DPoP refusals carry `WWW-Authenticate`;
  a token in the query is refused everywhere; Mediated credentials may go to
  the issuer's host; assertions live at most 120 s with a 16+ character `jti`
  (DPoP proofs too), and an unfetchable `client_id` is remembered briefly;
  agent replies are framed by `working`/`idle` state events; the conformance
  suite accepts any refusal of a token in the URL, resolves API paths at the
  API's origin, and has a Direct Sign-In driver hook.

- **TypeScript: OpenAPI and MCP at a company, with a resource-bound Bearer:**
  `ApiClient` (`src/apis.ts`) calls a company's OpenAPI API as Python's does
  (a `202` returns its operation, refusals carry their scope, a `429` its
  `retry_after`, bodies bounded); `McpClient` and `McpBearerAuth`
  (`src/mcp.ts`) reach its MCP server with a Bearer token sent only to that
  server's exact URL; `SessionClient.bearerForMcp` and
  `AccountTokenClient.bearerForMcp` acquire it, resource-bound, without DPoP.

- **TypeScript company: browser sessions.** `web.browser_session_endpoint`,
  a one-use browser assertion from a live Session, a `Secure`, `HttpOnly`,
  `SameSite=Lax` session cookie, and operation pages confirmed or cancelled
  through a same-site form bound to a CSRF token — one confirmation path with
  the API, at most once.

- **All four language pairings pass every conformance case:** 91 passed, 0
  failed, 0 skipped in each (the TypeScript agent gained an MCP client and a
  controlled browser).

- **Live-session actions, one implementation on every surface:** the `pap`
  plugin registers seven read-only actions (`pap.company.discover`,
  `pap.sessions.show`, `pap.conversations.events|follow`,
  `pap.operations.show`, `pap.requirements.list|show`) and three that change
  what the user holds (`pap.operations.cancel`, `pap.sessions.end`,
  `pap.auth.disconnect`) in Reactor's command registry (Studio's palette) or a
  REPL's `SlashCommandRegistry`; the new `pap commands list|run <id>` runs them
  too. Each runs the coroutine of the `pap` command of the same name and
  answers its versioned JSON. The three run only when the host contributes the
  new `pap.approvalSurface` (Python hosts) and it answers yes;
  configuration, credential entry, sign-in, messages, API calls and approvals
  stay CLI-only. `pap.company.discover` now discovers through the agent's own
  Reactor.

- **Telemetry, redacted by construction, in both SDKs:** a `pap.telemetry` sink
  receives one `TelemetryEvent` per discovery, Session, sign-in, conversation,
  and operation stage, with attributes from an allowlist; an OpenTelemetry
  adapter (`OpenTelemetrySink`, the `telemetry` extra; `openTelemetrySink` in
  TypeScript) makes them spans. The canary suites now also prove no credential
  reaches a trace or an analytics event.

- **Safety demonstrations:** replay, issuer mix-up, cross-tenant access, stale
  approval, retries, restart, rollback, revocation, and rotation, one
  end-to-end test each in both SDKs (`docs/docs/security/demonstrations.mdx`).

## 0.9.0 (2026-10-11)

- **The exact draft, in code:** `PROTOCOL_PROFILE` (`0.1`) and
  `PROTOCOL_REVISION` (`2026-10-09`, the specification page implemented), with
  `OPERATIONS_VERSION` (`1`), exported by both SDKs; the reference companies'
  discovery documents and the conformance runners read them, and a test in
  each language holds the other SDK, the package descriptions, the README,
  `protocol/UPSTREAM.md`, the requirement ledger, and the docs to the same
  values.
- **Breaking — unused contribution points removed:** `pap.protocolProfile`
  (`PROTOCOL_PROFILES`, `ProtocolProfile(s)`), `pap.extensionHandler`
  (`EXTENSION_HANDLERS`, `ExtensionHandler(s)`), and `pap.keyStore`
  (`KEY_STORES`, `KeyStore(s)`, `KeyReference`): no SDK code read them. See the
  [migration guide](docs/docs/releases/migration.mdx).
- **Aligned Reactor contributions:** `protocol/reactor-points.json` lists every
  point (17 for the personal agent, 9 for the company) with its contract,
  default, and tenant scope; a table-driven test in each SDK checks its
  exports, contracts and defaults against it, and each point's lifecycle
  (contributed, replaced by a lower `order`, removed with its plugin, equal
  orders failing closed), plus the tenant-scoped `pap.pairwiseUserIdStore` and
  `pap.dpopProofProvider`. The alignment fixed:
  - **Breaking:** optional points (cache, clock, random source, retry policy,
    rate-limit budget where optional, `pap.company.api`, `pap.company.mcp`)
    now fail closed on two contributions at the winning order
    (`optional_contribution` / `optionalContribution`), and the
    lowest-order `pap.company.operationExecutor` for an action performs it.
  - The TypeScript company serves `pap.company.mcp` (`CompanyMcps`,
    `CompanyMcp`, `ToolResult`, `ToolResults`): `/mcp` with Bearer Session
    Tokens for its URL, RFC 9728 metadata, and tools that propose operations,
    as in Python; Manzanita's MCP server in both languages. The Python agent
    now passes the four MCP conformance cases and `operations.cross-channel-mcp`
    against the TypeScript company.
  - **Breaking (TypeScript company):** renewing a Session with the Session
    assertion gives a signed-out token, as in Python (§4.2).
  - `pap.standingPermissionStore` is declared by the core plugin in both SDKs.
- **Every public code example runs in CI:** each Python and TypeScript block
  of the README and the docs runs as written against reference companies on
  an in-process network (`test_docs_examples.py`, `docs-examples.test.mjs`),
  the JSON examples are parsed by their wire models, and every tool of every
  Pydantic AI example runs. It found and this release fixes: the caching
  example's `CacheBounds(min_seconds=300)` raised (its default lifetime was
  outside the bounds), the sessions guide started and renewed with the local
  user as the tenant, and a budget example used `build_pap_reactor` without
  importing it. A new `Examples` workflow also builds every Agent Runtimes PAP
  example application with the latest Agent Runtimes release (1.3.111 or
  later) and rejects duplicate application and tool IDs.
- **Release documentation:** [Compatibility](docs/docs/releases/compatibility.mdx)
  (the draft, the SDK versions, the four pairings),
  [Migration](docs/docs/releases/migration.mdx) (every breaking release),
  and [Support](docs/docs/releases/support.mdx) (supported versions, how to
  report, the security contact), with the conformance report under Releases.
- **Signed releases:** PyPI distributions are published with attestations
  and the npm package with provenance, both from the `Release` workflow.

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
  form with `403`. Pages keep `frame-ancestors 'none'` and `X-Frame-Options: DENY`.
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
