# Operations

This example confirms Northwind Bank's proposed payments with the real Python
SDK `OperationsClient`: negotiation, a refused standing confirm, the user's
exact approval, `terms_changed` after the bank revises, an old approval refused
locally, a lost confirmation answer recovered by reading the same operation
back, a standing permission checked term by term through the Reactor
`pap.standingPermissionStore`, cancellation, and `extension_required` for an
agent that does not list the extension.

The tool returns states, changed term paths, and the bank's `result.summary`
as written. Tokens and proofs stay in the host.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Operations guide](https://personalagentprotocol.org/docs/guides/operations)
and the [example flow](https://personalagentprotocol.org/docs/examples/operations).
