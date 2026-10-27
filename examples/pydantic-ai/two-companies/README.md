# Two companies

Ledgerly, an accounting firm, pays Ada's invoices at Northwind Bank for her.

This is **composition**, not a company-to-company protocol: PAP draft 0.3
defines none. Ledgerly is a PAP company to Atlas (Ada's personal agent) and,
for the same Ada, a PAP personal agent at Northwind with its own `client_id`
and keys. Ada connects Ledgerly to Northwind on Northwind's own page. Every
approval is an Operation: Northwind's proposal is relayed to Ada as a Ledgerly
operation quoting it as written, and a standing permission is itself an
operation she approves. Within its bounds Ledgerly confirms with
`approved_by: standing_permission`; beyond them, Ada is asked again.

The tool returns summaries as the companies wrote them and who approved each
payment. No token, code, or proof enters it.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Operations guide](https://personalagentprotocol.org/docs/guides/operations)
and the [example flow](https://personalagentprotocol.org/docs/examples/two-companies).
