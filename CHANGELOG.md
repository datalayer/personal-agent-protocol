<!--
  ~ Copyright (c) 2023-2024 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

# Changelog

## Unreleased

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
