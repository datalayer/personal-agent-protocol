# Account Tokens

This example keeps Ada signed in to Manzanita Outfitters with the real Python
SDK `AccountTokenClient`, against the reference company from
`personal_agent_protocol.demo` (real keys, real HTTP over ASGI, no network). It
refreshes the same Session, shows rotation, races two refreshes through the
Reactor `pap.accountTokenLock`, narrows scopes, asks for wider scopes
(`re_consent_required`), lets the token expire (`invalid_grant` → signed out),
and revokes it.

The Pydantic AI tool receives only statuses and scope names. Account Tokens,
Session Tokens, client assertions, and DPoP proofs stay in the host's Reactor
stores.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Account Tokens guide](https://personalagentprotocol.org/docs/guides/account-tokens)
and the [example flow](https://personalagentprotocol.org/docs/examples/account-tokens).
