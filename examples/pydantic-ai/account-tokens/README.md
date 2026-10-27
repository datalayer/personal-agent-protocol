# Account Tokens

This example keeps Ada signed in to Manzanita Outfitters with the real Python
SDK `AccountTokenClient`, against the reference company from
`personal_agent_protocol.demo` (real keys, real HTTP over ASGI, no network). It
refreshes the same Session (named by its Session Key, the thumbprint of the key
that signs its DPoP proofs), shows rotation, races two refreshes through the
Reactor `pap.accountTokenLock`, narrows scopes, asks for wider scopes
(`re_consent_required`), lets the Session end (`session_ended`: its key is
discarded) and the token expire (`invalid_grant` → signed out), and revokes it.
After revocation the company answers the Session with an `authorization` event:
`insufficient_scope`.

The Pydantic AI tool receives only statuses and scope names. Account Tokens,
Session Tokens, Session Keys, client assertions, and DPoP proofs stay in the
host's Reactor stores.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Account Tokens guide](https://personalagentprotocol.org/docs/guides/account-tokens)
and the [example flow](https://personalagentprotocol.org/docs/examples/account-tokens).
