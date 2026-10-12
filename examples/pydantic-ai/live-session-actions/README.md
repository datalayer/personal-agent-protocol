# Live-session actions

A Pydantic AI agent runs PAP's live-session actions the way Studio's palette, a
REPL's slash commands, and `pap commands run <id>` run them: by ID, through the
Reactor command registry the `pap` plugin registered them in. Every surface
calls the same implementation, which answers the same versioned JSON as the
`pap` command of the same name.

The tool discovers Manzanita, lists the Sessions the agent holds, and reads a
requirement of the ledger. Then it tries to end a Session: that action changes
what Ada holds, and this host contributes no approval surface
(`pap.approvalSurface`), so it is refused with `approval_required` and nothing
is done. A model can read through these actions; it can never end a Session,
cancel an operation, or sign Ada out on its own.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [CLI guide](https://personalagentprotocol.org/docs/guides/cli#live-session-actions).
