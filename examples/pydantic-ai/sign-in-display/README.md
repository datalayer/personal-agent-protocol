# Sign-in display

What a person's page shows for a PAP sign-in, and what a model is told of it.
Atlas starts a real Device Sign-In at Manzanita Outfitters and answers with a
`PapSignIn` display from `personal_agent_protocol.ui` (the `ui` extra:
`pip install "personal-agent-protocol[ui]"`). The page gets the whole display,
in an MCP result's `_meta["reactor.ui/display"]` (`tool_meta()`): the
company's sign-in page to open and the code to enter there. The model gets
`model_view()`: the display's text, which names only the company's domain,
with neither the link (a verification URL may carry the code) nor the code.
Ada then approves on Manzanita's page and the Session is signed in.

The tool returns the model view as is and, of the page's display, only its
shape: field names, the page's host, and whether the link and the code are
there. Neither value enters it.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Device Sign-In guide](https://personalagentprotocol.org/docs/guides/device-sign-in)
and the [security boundaries](https://personalagentprotocol.org/docs/security).
