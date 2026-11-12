# Upstream protocol snapshot

- Protocol: Personal Agent Protocol (Poppy)
- Profile implemented: 0.4 as published
- Upstream page revision: 2026-11-10
- Upstream source: commit 4803900 of https://github.com/personal-agent-protocol/personal-agent-protocol (the frozen text as of ed47408, which only dropped the word "draft" from it)
- Last reviewed by this repository: 2026-11-12 (through ad20217)
- Specification: https://personalagentprotocol.org/docs/0.4/spec
- Guides: https://personalagentprotocol.org/docs/0.4/guides
- Operations extension: version 3
- Mediated Sign-In extension: version 1
- UCP extension: version 1
- Browser Control extension: version 1
- Mediated Sign-In extension page: https://personalagentprotocol.org/docs/0.4/extensions/mediated-sign-in
- Operations extension page: https://personalagentprotocol.org/docs/0.4/extensions/operations
- Browser Control extension page: https://personalagentprotocol.org/docs/0.4/extensions/browser-control

Version 0.4 was published upstream on 2026-11-10 (commit 4803900, "Publish 0.4
as the 1.0 release candidate"): the specification is frozen at /docs/0.4/spec,
and /docs/spec is now draft 1.0. SDK 0.33 implements 0.4 as published, with no
compatibility with draft 0.4 as of 46beb21, which SDK 0.32 implemented. It
announces and accepts `protocol_version` 0.4 only: draft 1.0 can still change
in ways that are not backward compatible, so a later release follows it once it
is published or changes the wire. What changed between 46beb21 and 4803900,
each in the CHANGELOG and the 0.32 → 0.33 migration page: task coverage per
Session (`tasks.endpoint`, fetched with the Session header and no access token;
`excluded_tasks`, `skill_index` and `feedback` leave `poppy.json`); Operations
version 3 (every approval says `approver`, `user` or `agent`, with an optional
`reference`; `terms` required and `summary` optional; `approval_declined`);
`extension_required` in a JSON body at APIs; Sessions found by `client_id`,
`sid` and User ID; Device Sign-In links only on the issuer's host or
`organization.domain`; sign-ins someone else started (spec 4.2, 10.8, and the
consent page that names the agent); the Session header on website pages
fetched without a browser; scopes in the protected resource metadata; refresh
token lifetimes left to the Company (nothing changes here: the reference
companies keep a fixed lifetime); and where the browser-session endpoint can
be. Not implemented in 0.33, and added in 0.34 (nothing else changes in it):
operations on websites (the `Poppy-Operation` header and the extension's
`endpoint`, Operations 4 and 6) and the Browser Control extension, version 1.
Upstream had no commit after ad20217 when 0.34 was built.

While 0.4 was a draft, at /docs/spec, this repository followed it as of a named
commit, as it followed draft 0.3 in 0.25 to 0.27, each release naming the
commit. SDK 0.32 implemented it as of 46beb21 (2026-11-06), with no
compatibility with 0.3 as published: Direct
Sign-In preferred; several protocol versions (`supported_versions`,
`Poppy-Version`, `version_unsupported`, `Deprecation` and `Sunset`); extensions
as per-version lists in `poppy.json`, declared per request in
`Poppy-Extensions` and no longer in client metadata; conversations across
versions (`version_mismatch`); the browser join scope `poppy:browser-sign-in`,
`web.unscoped` and `web.disabled`; a conversation's state in four fields
(`working`, `handoff`, `responder`, `closed`) and the `working` stream event;
every conversation request with its own `id`, accepted then acted on, with
`request_id_conflict`, `handoff/cancel` and a 202 close; `as_of_request` and
`as_of_cursor`; sign-in's minor changes (auth.disabled for any Company with an
issuer, refresh and revocation unverified when no refresh token was issued, a
DPoP key per User ID, resource metadata only for the URL it was derived from,
`auth.scopes` over an OpenAPI description, a delegated key refused for a second
User ID); Operations' minor changes (`approved_at` and `input_type`, revisions
by terms, any Session of the agent and User approving, requests compared by
meaning); and the guides' changes. The changes are in the CHANGELOG and the
0.31 → 0.32 migration page.

Version 0.3 was published upstream on 2026-11-04 (commit 2289293, "0.3 is
published and won't change"): the specification is frozen at /docs/0.3/spec.
SDK 0.31 implements 0.3 as published. 3e9bada rewrote 0.3, and the SDKs keep no
compatibility with the a95b757 shape 0.27 implements. The changes, each in the
CHANGELOG and the 0.27 → 0.28 migration page: Sessions are separate from OAuth,
with a `Poppy-Session` JWT per request named by a random `sid`, signed with
short-lived delegated keys vouched for by a delegation (no JWT bearer grant,
Session assertion, renewal, or Session Key); `ES256` and `PS384` for client
assertions and delegations, and blind signing; plain OAuth refresh and access
tokens, with DPoP the Company's choice; the issuer from the domain's protected
resource metadata (RFC 9728), `auth` optional; tokens for one service by
`resource`, and MCP tokens the same way (no Token Exchange); the browser join
by `/authorize`; `invalid_session` for a failed header; a 401 challenge when
signed out; rate limits as 429 with `Retry-After` and no body; Operations
version 2; the Mediated Sign-In extension; feedback without `kind`; `poppy:`
scopes no longer reserved.

The commits to ec16efa (0.29 and 0.30): signed-out Companies with no OAuth
issuer, the Company's identifier their HTTPS domain; Bearer as MCP's baseline,
DPoP there only when the MCP server's own metadata lists it; `scopes_supported`
and `auth.scopes` optional; the `agent.protocols[].access` hint; Session
verification required only before relying on Session claims; a refresh that
omits `refresh_token` keeps the old one; an `authorization` event may carry its
challenge on the successful response; PS384 a SHOULD for Companies; the browser
join for a browser the agent controls, and what it does to a login the browser
has; operator signatures (Web Bot Auth).

The 0.3 review and publication, ec16efa to 2289293 (0.31, the 0.30 → 0.31
migration page): delegations typed `poppy-delegation+jwt` in the `poppy_dlg`
header; `session_ended` for a Session the Company ended, the agent starting a
new one once; extension content in `message.extensions`, Operations' content
under `extensions.operations`, and the Links and Disclosures extensions,
version 1; a Company may grant fewer scopes and rejects only missing or unknown
ones with `invalid_scope`; `auth.disabled` and `unauthorized_client`;
Company-first Direct Conversations by `user_requested_event_id`, conversation
ownership as a table, and the four parent errors; the delegation `iat` check
removed, the Operations check order as listed, Session header destinations from
`poppy.json`, Agent IDs only for the operator's agents; `organization.logo_uri`,
`skill_index` at a pinned Agent Skills revision, at least one of `agent`,
`apis`, `web`, and a conversation endpoint at another provider; the guides on
explicit replies, idempotency scoped to agent, User and account, no RS256, and
Session storage. The UCP extension (version 1, `b2b10da`) is implemented since 0.32: the profile, the connection and identity linking, not UCP's commerce.

A published version does not change; a later upstream version is reviewed and
released as an explicit protocol profile, and generated code must never change
from an unattended documentation fetch. Draft 0.1 stays readable, frozen, at
https://personalagentprotocol.org/docs/0.1/spec; draft 0.2 is frozen at
https://personalagentprotocol.org/docs/0.2/spec, and 0.3 at
https://personalagentprotocol.org/docs/0.3/spec. This repository implements
0.4 as published only and uses no earlier document.

## Vendored JSON Schemas

`protocol/schemas/` holds JSON Schemas copied unchanged from the upstream
company kit (`kit/company/schemas/`) at commit ed47408 (0.4 as published), under the upstream
repository's license (Apache License 2.0). The tests check the shared
fixtures and the reference company's documents against them
(`personal_agent_protocol/__tests__/test_schemas.py`). They are replaced
whole when a later upstream commit is adopted, never edited here.
