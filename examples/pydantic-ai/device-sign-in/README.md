# Device Sign-In

This example runs PAP Device Sign-In through the real Python SDK. It shows the
human a company-owned link and code, respects the company's polling interval
and `slow_down`, upgrades the existing Session, reports partial consent, and
stores the Account Token behind an opaque Reactor reference.

The Pydantic AI tool receives only lifecycle evidence. Device codes, client
assertions, DPoP proofs, Session Tokens, and Account Tokens remain in host-owned
code.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Device Sign-In guide](https://personalagentprotocol.org/docs/guides/device-sign-in).
