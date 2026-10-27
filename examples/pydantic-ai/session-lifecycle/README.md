# Signed-out Session lifecycle

This example drives the real PAP `SessionClient` through Session start, one
DPoP nonce challenge, renewal, and the Session's end over a deterministic local
HTTP transport. Reactor supplies the protected signer and a DPoP provider with
real Session Keys.

Starting a Session makes a new Session Key; its JWK thumbprint names the
Session, so no Session ID is sent or received. Renewing proves the same key.
When the company answers `invalid_grant`, the Session has ended: its key is
discarded and never reused, and the next Session starts with a new one. The
tool returns only lifecycle evidence; the pairwise subject, Session Keys,
assertions, proofs, nonce, and tokens remain host-only.

```bash
python examples/pydantic-ai/session-lifecycle/app.py
```

See the canonical [Sessions guide](../../../docs/docs/guides/sessions.mdx).
