# Session assertion safety

The agent's tool creates real PAP Session claims internally, then returns only
their lifetime and binding policy. A Reactor plugin contributes a host-owned
SQLite store that keeps one stable, opaque subject for the configured tenant,
local user, and verified company issuer. Those keys and the subject are not
tool arguments or results. Pairwise subject, `jti`, unsigned claims, and
signing keys remain outside model context.

The assertion names the agent (`iss`) and the user (`sub`, the pairwise User
ID); it does not name the Session. The token request that carries it also
carries a DPoP proof signed with a new Session Key, and that key's thumbprint
is what names the Session from then on: renewing it means a new assertion
proved with the same Session Key.

```bash
python examples/pydantic-ai/session-assertion/app.py
```

See the canonical [Sessions guide](../../../docs/docs/guides/sessions.mdx).
