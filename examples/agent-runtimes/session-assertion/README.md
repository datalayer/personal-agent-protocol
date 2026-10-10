# Session assertion safety

This application teaches the signed-out Session assertion contract. It builds
real PAP claims with a random pairwise subject and unique `jti`, but returns
only the lifetime, audience binding, and safety properties. The subject and
`jti` are deliberately withheld and no unsigned claims are presented as a
usable assertion.

```bash
loop apps run examples/agent-runtimes/session-assertion/app.py
```
