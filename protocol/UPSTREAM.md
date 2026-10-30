# Upstream protocol snapshot

- Protocol: Personal Agent Protocol (Poppy)
- Profile implemented: draft 0.3
- Upstream page revision: 2026-10-30
- Upstream source: commit ec16efa of https://github.com/personal-agent-protocol/personal-agent-protocol
- Last reviewed by this repository: 2026-10-30
- Specification: https://personalagentprotocol.org/docs/0.3/spec
- Guides: https://personalagentprotocol.org/docs/0.3/guides
- Operations extension: version 2
- Mediated Sign-In extension: version 1
- Mediated Sign-In extension page: https://personalagentprotocol.org/docs/0.3/extensions/mediated-sign-in
- Operations extension page: https://personalagentprotocol.org/docs/0.3/extensions/operations

Draft 0.3 is still being written upstream, at /docs/spec; this repository
implements it as of commit ec16efa (the draft states no date of its own, so
its revision is that commit's, 2026-10-30), reviewed on 2026-10-30, and every
later upstream commit is reviewed before a release names it. 3e9bada rewrote 0.3, and
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

The five commits after it, each in the CHANGELOG and the 0.28 → 0.29 migration
page: signed-out Companies with no OAuth issuer, the Company's identifier their
HTTPS domain; Bearer as MCP's baseline, DPoP there only when the MCP server's own
metadata lists it; `scopes_supported` and `auth.scopes` optional; the
`agent.protocols[].access` hint; Session verification required only before
relying on Session claims; a refresh that omits `refresh_token` keeps the old one;
an `authorization` event may carry its challenge on the successful response; the
Operations check order a SHOULD; PS384 a SHOULD for Companies; the browser join
for a browser the agent controls, and what it does to a login the browser has;
operator signatures (Web Bot Auth), a SHOULD this SDK has not built.

Upstream is a draft. Changes are reviewed and released as explicit protocol
profiles; generated code must never change from an unattended documentation
fetch. Draft 0.1 stays readable, frozen, at
https://personalagentprotocol.org/docs/0.1/spec; draft 0.2 is frozen at
https://personalagentprotocol.org/docs/0.2/spec. This repository implements
0.3 only and uses no earlier document.

## Vendored JSON Schemas

`protocol/schemas/` holds JSON Schemas copied unchanged from the upstream
company kit (`kit/company/schemas/`) at commit ec16efa, under the upstream
repository's license (Apache License 2.0). The tests check the shared
fixtures and the reference company's documents against them
(`personal_agent_protocol/__tests__/test_schemas.py`). They are replaced
whole when a later upstream commit is adopted, never edited here.
