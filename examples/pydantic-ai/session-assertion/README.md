# Session assertion safety

The agent's tool creates real PAP Session claims internally, then returns only
their lifetime and binding policy. Pairwise subject, `jti`, unsigned claims and
signing keys remain outside model context.

```bash
python examples/pydantic-ai/session-assertion/app.py
```

See the canonical [Sessions guide](../../../docs/docs/guides/sessions.mdx).
