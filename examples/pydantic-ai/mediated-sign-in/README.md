# Mediated Sign-In

This example signs Ada in to Manzanita Outfitters through the company's
mediated endpoint with the real Python SDK `MediatedSignInClient`. Her email,
password, and one-time code are collected by the host's trusted input surface
(the Reactor `pap.protectedInput` contribution, scripted here), never by the
model. It also shows an off-domain endpoint refused before anything is asked,
a code refused from another Session (another Session Key), a wrong code asking
again, and the Session that started the sign-in, still named by the same
Session Key, signed in at the end.

The Pydantic AI tool receives field labels, statuses, the company's masked
`sent_to`, and granted scopes. Credentials, codes, and tokens never enter it.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Mediated Sign-In guide](https://personalagentprotocol.org/docs/guides/mediated-sign-in)
and the [example flow](https://personalagentprotocol.org/docs/examples/mediated-sign-in).
