# DPoP-aware HTTP transport

This example sends a PAP API request with a Session Token and fresh DPoP proof,
handles one company nonce challenge, follows a same-origin redirect with a new
target-bound proof, and rejects caller-supplied authorization headers.

Tokens, proofs, nonces, and pairwise identity remain host-owned.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [DPoP transport flow](https://personalagentprotocol.org/examples/dpop-transport/).
