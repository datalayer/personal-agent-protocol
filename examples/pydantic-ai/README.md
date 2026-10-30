# PAP with Pydantic AI

These examples use PAP directly from plain Pydantic AI agents. They have no
Agent Runtimes dependency; the Agent Runtimes-specific applications live in
the Agent Runtimes repository under `examples/personal-agent-protocol`.

| Example                                                   | Feature                                                         | Tool result boundary              |
| --------------------------------------------------------- | --------------------------------------------------------------- | --------------------------------- |
| [`company-discovery`](./company-discovery/)               | HTTPS company discovery and validation                          | Public capability summary         |
| [`agent-identity`](./agent-identity/)                     | Client metadata and same-domain JWKS                            | Identity and signing policy       |
| [`delegation`](./delegation/)                             | Short-lived claims naming no User and no Company                | Policy only; identifiers withheld |
| [`direct-sign-in-boundary`](./direct-sign-in-boundary/)   | OAuth state, S256 PKCE, no Session named                        | Security properties only          |
| [`direct-sign-in-lifecycle`](./direct-sign-in-lifecycle/) | Complete sign-in, consent and token custody                     | Lifecycle evidence only           |
| [`device-sign-in`](./device-sign-in/)                     | Device code, paced polling and token custody                    | Lifecycle evidence only           |
| [`session-jwt`](./session-jwt/)                           | A delegated key, request binding, replay rejection              | Verified policy; secrets withheld |
| [`session-lifecycle`](./session-lifecycle/)               | Start, a Session JWT per request, restart; one key per User ID  | Lifecycle evidence only           |
| [`browser-session`](./browser-session/)                   | Join form: one-time code authorized with the Session header     | Browser policy only               |
| [`session-transport`](./session-transport/)               | The Session header, restart and refused redirects               | Transport policy only             |
| [`conversation-messages`](./conversation-messages/)       | Start and continue with idempotent IDs                          | Conversation state only           |
| [`conversation-events`](./conversation-events/)           | Long poll, drain, recover, de-duplicate                         | Safe event content only           |
| [`conversation-streaming`](./conversation-streaming/)     | SSE, `Last-Event-ID`, display-only deltas                       | Counts and complete messages      |
| [`conversation-control`](./conversation-control/)         | `insufficient_scope`, Direct, handoff, close                    | Statuses and event types          |
| [`account-tokens`](./account-tokens/)                     | Refresh, rotation, narrowing, expiry, revocation                | Statuses and scopes only          |
| [`mediated-sign-in`](./mediated-sign-in/)                 | Protected input, one endpoint, one-time code                    | Labels and statuses only          |
| [`operations`](./operations/)                             | Exact approval, new revisions, a lost answer sent again          | States and company summaries      |
| [`user-with-a-company`](./user-with-a-company/)           | The whole journey with Manzanita                                | Steps in plain words              |
| [`two-companies`](./two-companies/)                       | Ledgerly at Northwind for Ada (composition)                     | Summaries and approvers           |
| [`live-session-actions`](./live-session-actions/)         | Actions by ID, as Studio, a REPL and `pap commands run` invoke  | Answers and refusal codes         |
| [`telemetry`](./telemetry/)                               | One allowlisted event per protocol stage, OpenTelemetry-ready   | Stage events only                 |
| [`company-apis`](./company-apis/)                         | OpenAPI and MCP, each with its own access token                 | Orders, statuses, summaries       |
| [`company-service`](./company-service/)                   | A company built with the SDK, used end to end                   | Steps and a count                 |
| [`sign-in-display`](./sign-in-display/)                   | `PapSignIn`: the page's display vs `model_view()`               | Model view; page shape only       |

Install and run from the PAP repository:

```bash
python -m pip install -e '.[examples]'
export OPENAI_API_KEY=...
python examples/pydantic-ai/company-discovery/app.py
```

Set `PAP_EXAMPLE_MODEL` to use another Pydantic AI model string. The default is
`openai:gpt-4o-mini`.

The `account-tokens`, `mediated-sign-in`, `conversation-*`, `operations`,
`user-with-a-company`, `two-companies`, `live-session-actions`, `telemetry`,
`company-apis`, `browser-session`, and `sign-in-display` examples run against
the reference company in `personal_agent_protocol.demo`: real keys and real
HTTP over ASGI, in one process, with no network and no model in the tool.
`company-service` builds its own company with
`personal_agent_protocol.company` and runs the same way.

Validate all example definitions without calling a model:

```bash
python scripts/validate_pydantic_ai_examples.py
```
