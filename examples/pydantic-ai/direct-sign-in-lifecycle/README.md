# Direct Sign-In lifecycle

This example runs the complete PAP Direct Sign-In upgrade for an existing
signed-out Session. It demonstrates one-use state, S256 PKCE, a trusted browser
handoff, exact callback validation, proof-bound token exchange, a DPoP nonce
retry, partial consent, and continuity of the original Session.

The Pydantic AI tool receives only safe outcome evidence. Authorization URLs,
callback parameters, codes, verifiers, assertions, proofs, Session Tokens, and
Account Tokens stay inside host-owned code.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Direct Sign-In guide](https://personalagentprotocol.org/docs/guides/direct-sign-in)
for the production trust boundaries and failure rules.
