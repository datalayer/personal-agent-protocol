# Upstream protocol snapshot

- Protocol: Personal Agent Protocol (Poppy)
- Profile implemented: draft 0.2
- Upstream page revision: 2026-10-18
- Upstream source: commit 39b35bd of https://github.com/personal-agent-protocol/personal-agent-protocol
- Last reviewed by this repository: 2026-10-22
- Specification: https://personalagentprotocol.org/docs/0.2/spec
- Guides: https://personalagentprotocol.org/docs/0.2/guides
- Operations extension: version 1
- Operations extension page: https://personalagentprotocol.org/docs/0.2/extensions/operations

Since 30c4764 (implemented in 0.25.0), upstream changed the website only
(692db3c, 93071fb) and clarified the examples and guides to match the spec
(39b35bd, #71) with no new wire behavior: DPoP proofs only on token-endpoint
requests and requests carrying a Session Token, a browser assertion's `aud`
and `typ`, ES256, no token or proof sent to a redirect target, Mediated
credentials discarded when a sign-in ends, `iss` required on a Direct
Sign-In redirect, a reused `jti` rejected at the token endpoint, and
`Idempotency-Key` on API writes in the examples. The upstream page revision
stays 2026-10-18.

Upstream is a draft. Changes are reviewed and released as explicit protocol
profiles; generated code must never change from an unattended documentation
fetch. Draft 0.1 stays readable, frozen, at
https://personalagentprotocol.org/docs/0.1/spec; this repository implements
0.2 only and uses no 0.1 document.
