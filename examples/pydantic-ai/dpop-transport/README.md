# DPoP-aware HTTP transport

This example sends a PAP API request with a Session Token and a fresh DPoP
proof signed with the Session Key (the key whose thumbprint names the Session;
the request names only the tenant and the issuer), handles one company nonce
challenge, refuses a redirect (draft 0.3 §3: no token or proof goes to the URL a
protocol endpoint redirects to), and rejects caller-supplied authorization
headers.

Tokens, proofs, nonces, and Session Keys remain host-owned.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [DPoP transport flow](https://personalagentprotocol.org/examples/dpop-transport/).
