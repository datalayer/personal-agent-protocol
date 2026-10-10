# Browser Session

This example signs a short-lived `poppy-browser+jwt` assertion, hands it to a
controlled browser as a top-level form POST, verifies it on the company side,
and proves that replay is rejected.

The assertion is sent only in the request body. Pairwise identity, Session ID,
signing key, assertion, and the company's resulting cookie never enter model
context.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Browser Session flow](https://personalagentprotocol.org/examples/browser-session/).
