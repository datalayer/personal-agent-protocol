# Company APIs

Atlas, Ada's personal agent, reaches Manzanita Outfitters through the two APIs
its `poppy.json` lists. The OpenAPI API is called with `ApiClient`, with the
Session header and, signed in, an access token: signed out, it answers `insufficient_scope` with the
scope it needs; signed in, it reads Ada's orders and answers the exchange with
`403 approval_required` and an operation. The MCP server is called with `McpClient` and a
token issued for its URL alone, chosen by its protected resource metadata
(`fetch_mcp_server_metadata`):

- a server that lists `dpop_signing_alg_values_supported` gets a DPoP-bound token,
  sent with a proof beside the Session header;
- any other server gets a Bearer token, MCP's baseline, even at an issuer that
  lists DPoP.

Both come from `RefreshTokenClient.token_for_mcp(..., server=)`, which requests the
token with `resource` set to the server's URL.

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
