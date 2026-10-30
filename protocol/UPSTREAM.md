# Upstream protocol snapshot

- Protocol: Personal Agent Protocol (Poppy)
- Profile implemented: draft 0.3
- Upstream page revision: 2026-10-26
- Upstream source: commit a95b757 of https://github.com/personal-agent-protocol/personal-agent-protocol
- Last reviewed by this repository: 2026-10-27
- Specification: https://personalagentprotocol.org/docs/0.3/spec
- Guides: https://personalagentprotocol.org/docs/0.3/guides
- Operations extension: version 2
- Mediated Sign-In extension: version 1
- Mediated Sign-In extension page: https://personalagentprotocol.org/docs/0.3/extensions/mediated-sign-in
- Operations extension page: https://personalagentprotocol.org/docs/0.3/extensions/operations

Draft 0.3 is still being written upstream, at /docs/spec; this repository
implements it as of commit a95b757, reviewed on 2026-10-27, and every later
upstream commit is reviewed before a release names it. The changes from 0.2,
each in the CHANGELOG and the 0.2 → 0.3 migration page: Session Keys name
Sessions (no `session_id`), authorization and device codes are bound to them,
`invalid_grant` for an ended Session's key; `signed_in` removed, `scope` as in
RFC 6749; `insufficient_scope` replaces `sign_in_required`; Bearer tokens for
MCP servers without DPoP by Token Exchange; `grant_types_supported` says the
sign-in types, `scopes_supported` and `auth.scopes` the company's own scopes,
`auth.scope_hints` what they allow; `protected_resources` replaces
`poppy_domains`; discovery redirects end at the well-known path; loopback
redirect URIs; Agent IDs; the browser joins a Session through a form with a
one-time code (no browser assertion); `author` replaces `sender`; excluded
tasks, alternatives, and feedback answered with one; more secrets kept out of
model context.

Upstream is a draft. Changes are reviewed and released as explicit protocol
profiles; generated code must never change from an unattended documentation
fetch. Draft 0.1 stays readable, frozen, at
https://personalagentprotocol.org/docs/0.1/spec; draft 0.2 is frozen at
https://personalagentprotocol.org/docs/0.2/spec. This repository implements
0.3 only and uses no earlier document.

## Vendored JSON Schemas

`protocol/schemas/` holds JSON Schemas copied unchanged from the upstream
company kit (`kit/company/schemas/`) at commit 3e9bada, under the upstream
repository's license (Apache License 2.0). The tests check the shared
fixtures and the reference company's documents against them
(`personal_agent_protocol/__tests__/test_schemas.py`). They are replaced
whole when a later upstream commit is adopted, never edited here.
