# Direct Sign-In boundary

The tool creates real random state, an S256 PKCE verifier, and a Session Key,
and builds the authorization URL with `dpop_jkt` set to the Session Key's
thumbprint: the company binds the authorization code to that key, so it signs
in that Session and no other key can redeem it. It returns only safe security
properties. Registration, discovery, and allowed-scope values
come from trusted `PAP_*` host configuration and are not tool arguments. The
host—not the model—owns the redirect URI, authorization URL, state, verifier,
callback, and tokens.

```bash
python examples/pydantic-ai/direct-sign-in-boundary/app.py
```

See the canonical
[Direct Sign-In guide](../../../docs/docs/guides/direct-sign-in.mdx).
