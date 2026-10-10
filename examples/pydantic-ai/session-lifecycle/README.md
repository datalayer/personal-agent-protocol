# Signed-out Session lifecycle

This example drives the real PAP `SessionClient` through Session start, one
DPoP nonce challenge, and renewal over a deterministic local HTTP transport.
Reactor supplies the protected signer and DPoP provider. The tool returns only
lifecycle evidence; the pairwise subject, Session ID, assertions, proofs,
nonce, and tokens remain host-only.

```bash
python examples/pydantic-ai/session-lifecycle/app.py
```

See the canonical [Sessions guide](../../../docs/docs/guides/sessions.mdx).
