# Company service

A company built with `personal_agent_protocol.company`, then used by a
personal agent from the same SDK. Juniper Library is a `CompanyConfig` (name,
domain, its own scopes with their descriptions and hints, published as
`auth.scopes` and `auth.scope_hints`), a company store (the async keyed store,
checked here with `check_store` as a database store would be), a company agent
that answers `insufficient_scope` when signed out and proposes renewing a
loan, and one operation executor that performs the renewal. `build_company`
assembles them from Reactor contributions and `company_app` serves the service
over ASGI.

Atlas, Ada's personal agent, then runs the whole journey against it:
discovery, a signed-out Session named by its Session Key, an `authorization`
event with `insufficient_scope` and the scope needed, Device Sign-In on the
library's page signing that same Session in, the renewal proposed in the same
conversation, Ada's approval of that exact revision, and the renewal performed
once although the confirmation is sent twice.

The tool returns the steps in plain words, the library's summaries, and how
many times the executor ran. No token, code, or proof enters it.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [company guide](https://personalagentprotocol.org/docs/guides/company).
