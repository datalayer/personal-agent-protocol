# DPoP proof boundary

The tool makes a Session Key (one per Session, kept by the host's key custody;
its JWK thumbprint names the Session), then creates and verifies a real ES256
DPoP proof with it, including HTTP method, normalized URL, access-token hash,
company nonce, and one-use replay checks. The verified proof's key thumbprint
is the Session Key; once the Session ends its key is discarded and the
provider refuses to sign with it again. It returns only boolean policy
evidence. The proof, token, nonce, JWK, `jti`, key thumbprint, and private key
never enter model context.

```bash
python examples/pydantic-ai/dpop-proof/app.py
```

See the canonical [JOSE and DPoP guide](../../../docs/docs/guides/cryptography.mdx).
