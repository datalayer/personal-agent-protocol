# DPoP proof boundary

The tool creates and verifies a real ES256 DPoP proof, including HTTP method,
normalized URL, access-token hash, company nonce, and one-use replay checks. It
returns only boolean policy evidence. The proof, token, nonce, JWK, `jti`, key
thumbprint, and private key never enter model context.

```bash
python examples/pydantic-ai/dpop-proof/app.py
```

See the canonical [JOSE and DPoP guide](../../../docs/docs/guides/cryptography.mdx).
