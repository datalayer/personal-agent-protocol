# Company service

A company built with `personal_agent_protocol.company`, then used by a
personal agent from the same SDK. Juniper Library is a `CompanyConfig` (name,
domain, scopes, custom scope words), a company store (the async keyed store,
checked here with `check_store` as a database store would be), a company
agent that asks to sign in and proposes renewing a loan, and one operation
executor that performs the renewal. `build_company` assembles them from
Reactor contributions and `company_app` serves the service over ASGI.

Atlas, Ada's personal agent, then runs the whole journey against it:
discovery, a signed-out Session, an `authorization` event, Device Sign-In on
the library's page, the renewal proposed in the same conversation, Ada's
approval of that exact revision, and the renewal performed once although the
confirmation is sent twice.

The tool returns the steps in plain words, the library's summaries, and how
many times the executor ran. No token, code, or proof enters it.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [company guide](https://personalagentprotocol.org/docs/guides/company).
