# PAP with Pydantic AI

These examples use PAP directly from plain Pydantic AI agents. They have no
Agent Runtimes dependency; the Agent Runtimes-specific applications live in
the Agent Runtimes repository under `examples/personal-agent-protocol`.

| Example                                                 | Feature                                 | Tool result boundary              |
| ------------------------------------------------------- | --------------------------------------- | --------------------------------- |
| [`company-discovery`](./company-discovery/)             | HTTPS company discovery and validation  | Public capability summary         |
| [`agent-identity`](./agent-identity/)                   | Client metadata and same-domain JWKS    | Identity and signing policy       |
| [`session-assertion`](./session-assertion/)             | Pairwise subject and short-lived claims | Policy only; identifiers withheld |
| [`direct-sign-in-boundary`](./direct-sign-in-boundary/) | OAuth state and S256 PKCE               | Security properties only          |
| [`direct-sign-in-lifecycle`](./direct-sign-in-lifecycle/) | Complete Session upgrade and consent  | Lifecycle evidence only           |
| [`dpop-proof`](./dpop-proof/)                           | Request binding and replay rejection    | Verified policy; secrets withheld |
| [`session-lifecycle`](./session-lifecycle/)             | Start, nonce retry, and renewal over HTTP | Lifecycle evidence only          |

Install and run from the PAP repository:

```bash
python -m pip install -e '.[examples]'
export OPENAI_API_KEY=...
python examples/pydantic-ai/company-discovery/app.py
```

Set `PAP_EXAMPLE_MODEL` to use another Pydantic AI model string. The default is
`openai:gpt-4o-mini`.

Validate all example definitions without calling a model:

```bash
python scripts/validate_pydantic_ai_examples.py
```
