# Personal-agent identity

This application verifies public client metadata and its same-domain JWKS. It
returns the client name, redirect count, extension versions, and allowed
signing algorithms. JWK coordinates, endpoint URLs, and private key material
never become a tool result.

```bash
loop apps run examples/agent-runtimes/agent-identity/app.py
```
