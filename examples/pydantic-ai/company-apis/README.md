# Company APIs

Atlas, Ada's personal agent, reaches Manzanita Outfitters through the two APIs
its `poppy.json` lists. The OpenAPI API is called with `ApiClient` and the
Session's DPoP-bound token: signed out, it answers `insufficient_scope` with the
scope it needs; signed in, it reads Ada's orders and answers the exchange with
`403 approval_required` and an operation. The MCP server is called with `McpClient` and a
token issued for its URL alone, chosen by its protected resource metadata
(`fetch_mcp_server_metadata`):

- a server that supports DPoP (`dpop_signing_alg_values_supported`) gets a DPoP
  token for the same Session: `AccountTokenClient.refresh(..., resource=url)`;
- a server without DPoP gets a Bearer token by Token Exchange
  (`SessionClient.token_for_mcp`): the Session's DPoP token is the
  `subject_token`, the server's URL the `resource`, and the company's discovery
  says it offers the grant (`offers_token_exchange`).

The journey runs against both: Manzanita as published, and Manzanita with an
MCP server without DPoP. Each time the MCP server lists its tools, reads the
same orders, and returns the same exchange, one operation across both
channels, and the company refuses the MCP token anywhere else.

The tool returns statuses, scopes, tool names, the orders, and Manzanita's
summaries as written. Tokens, the device code, and proofs stay in the host.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [APIs coverage](https://personalagentprotocol.org/docs/protocol/coverage/apis)
and the [Operations guide](https://personalagentprotocol.org/docs/guides/operations).
