# Browser Session

This example joins the personal agent's own browser to a PAP Session (§5),
against Manzanita Outfitters with its website on, from
`personal_agent_protocol.demo` (real keys, real HTTP over ASGI, no network).

1. The agent's browser loads Manzanita's `web.browser_session_endpoint` with a
   GET. The page is a form with a one-time `code` and an empty `proof` field;
   a `SameSite=Strict`, `HttpOnly`, `Secure` cookie ties the code to that
   browser, and the page is never cached or framed.
1. The host reads the code from that page alone (never from a message or
   another page) and signs a DPoP proof with the Session Key: `htm` POST, `htu`
   the endpoint, the code as its `nonce`, no `ath`.
1. The browser submits code and proof. Manzanita checks the cookie against the
   code, that the code is unused and unexpired, and that the proof's key is an
   active Session's key, then answers `303` with its own cookie for that
   Session.

Then it shows the two refusals §9.6 asks for: the same code submitted again,
with a fresh valid proof, is refused; and a code the agent's browser loaded,
submitted from another browser without its cookie, is refused (and used up), so
a code an attacker obtained can't sign someone else's browser into the
attacker's Session.

Join codes, proofs, the Session Key, and the company's cookies never enter
model context: the tool returns statuses and booleans.

```bash
PAP_EXAMPLE_MODEL=openai:gpt-4o-mini python app.py
```

Read the [Browser Session flow](https://personalagentprotocol.org/examples/browser-session/).
