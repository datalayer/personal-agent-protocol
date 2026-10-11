# A user with a company

The whole journey of one user with one company, both sides from this SDK:
Ada asks Atlas, her personal agent, to exchange a jacket at Manzanita
Outfitters. Discovery, a signed-out Session, an `authorization` event, Device
Sign-In on Manzanita's page, the same conversation continuing signed in, the
proposed exchange approved exactly and performed once, and finally a narrowed
Account Token and its revocation.

Manzanita is the reference company from `personal_agent_protocol.company`,
assembled from Reactor contributions in `personal_agent_protocol.demo`. The
tool returns the steps in plain words and the outcome; no token, code, or
proof enters it.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [company guide](https://personalagentprotocol.org/docs/guides/company)
and the [example flow](https://personalagentprotocol.org/docs/examples/user-with-a-company).
