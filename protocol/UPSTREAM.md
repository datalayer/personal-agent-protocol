# Upstream protocol snapshot

- Protocol: Personal Agent Protocol (Poppy)
- Profile implemented: draft 0.3
- Upstream page revision: 2026-10-28
- Upstream source: commit 3e9bada of https://github.com/personal-agent-protocol/personal-agent-protocol
- Last reviewed by this repository: 2026-10-30
- Specification: https://personalagentprotocol.org/docs/0.3/spec
- Guides: https://personalagentprotocol.org/docs/0.3/guides
- Operations extension: version 2
- Mediated Sign-In extension: version 1
- Mediated Sign-In extension page: https://personalagentprotocol.org/docs/0.3/extensions/mediated-sign-in
- Operations extension page: https://personalagentprotocol.org/docs/0.3/extensions/operations

Draft 0.3 is still being written upstream, at /docs/spec; this repository
implements it as of commit 3e9bada, reviewed on 2026-10-30, and every later
upstream commit is reviewed before a release names it. 3e9bada rewrote 0.3, and
the SDKs keep no compatibility with the a95b757 shape 0.27 implements. The
changes, each in the CHANGELOG and the 0.27 → 0.28 migration page: Sessions are
separate from OAuth, with a `Poppy-Session` JWT per request named by a random
`sid`, signed with short-lived delegated keys vouched for by a delegation (no
JWT bearer grant, Session assertion, renewal, or Session Key); `ES256` and
`PS384` for client assertions and delegations, and blind signing; plain OAuth
refresh and access tokens, with DPoP the Company's choice; the issuer from the
domain's protected resource metadata (RFC 9728), `auth` optional; tokens for
one service by `resource`, and MCP tokens the same way (no Token Exchange); the
browser join by `/authorize`; `invalid_session` for a failed header; a 401
challenge when signed out; rate limits as 429 with `Retry-After` and no body;
Operations version 2; the Mediated Sign-In extension; feedback without `kind`;
`poppy:` scopes no longer reserved.

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
