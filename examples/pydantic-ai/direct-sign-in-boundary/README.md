# Direct Sign-In boundary

The tool creates real random state and an S256 PKCE verifier but returns only
safe security properties. The host—not the model—owns the authorization URL,
state, verifier, callback and tokens.

```bash
python examples/pydantic-ai/direct-sign-in-boundary/app.py
```

See the canonical
[Direct Sign-In guide](../../../docs/docs/guides/direct-sign-in.mdx).
