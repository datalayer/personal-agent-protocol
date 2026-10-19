# Company APIs

Atlas, Ada's personal agent, reaches Manzanita Outfitters through the two APIs
its `poppy.json` lists. The OpenAPI API is called with `ApiClient` and the
Session's DPoP-bound token: signed out, it answers `sign_in_required` with the
scope signing in would give; signed in, it reads Ada's orders and answers the
exchange with `202` and a proposed operation. The MCP server is called with
`McpClient` and a token issued for its URL alone
(`AccountTokenClient.token_for_mcp`): DPoP, since Manzanita's protected
resource metadata lists `dpop_signing_alg_values_supported`
(`fetch_mcp_server_metadata`), or Bearer for an MCP server without DPoP. It
lists its tools, reads the same orders, and proposes the same exchange, one
operation record across both channels. The company refuses that token
anywhere else.

The tool returns statuses, scopes, tool names, the orders, and Manzanita's
summaries as written. Tokens, the device code, and proofs stay in the host.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [APIs coverage](https://personalagentprotocol.org/docs/protocol/coverage/apis)
and the [Operations guide](https://personalagentprotocol.org/docs/guides/operations).
