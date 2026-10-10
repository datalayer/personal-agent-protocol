<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

# 🤖 🌸 Personal Agent Protocol

TypeScript SDK for [Personal Agent Protocol](https://personalagentprotocol.org)
[draft 0.1](https://personalagentprotocol.org/docs/spec).

```typescript
import {
  AgentIdentityClient,
  discoverCompany,
} from "@datalayer/personal-agent-protocol";

const company = await discoverCompany("example.com");
const agent = new AgentIdentityClient();
const metadata = await agent.fetchMetadata("https://agent.example/agent.json");
const jwks = await agent.fetchJwks(metadata.client_id);
```

The current release provides forward-compatible discovery, OAuth, client
metadata, conversation-event, and Operations v1 models; strict
duplicate-member rejection; local Direct Sign-In primitives; signed-out
session start and renewal; safe company discovery; and bound client
metadata/JWKS retrieval built on Datalayer Reactor.

It also provides ES256/RS256 JOSE signing and DPoP through the maintained
`jose` package. Import device-side `JoseDpopProofProvider` from the portable
entry. Import `JoseSigner`, `verifyDpopProof`, replay-cache contracts, and
`NodeUrlSafetyPolicy` from
`@datalayer/personal-agent-protocol/server`; those company/backend APIs are
deliberately excluded from browser bundles.

Use `buildPapReactor(options, plugins)` to install typed transport, URL-policy,
protocol-profile, clock, randomness, signer, DPoP proof, protected-key,
token-store, pairwise-user-ID store, authorization-state store, cache,
browser-handoff, and extension-handler contributions, or pass an existing
Reactor host to `discoverCompany`.

Security-dependent services have no fallback and fail closed when missing or ambiguous.

See the repository [README](https://github.com/datalayer/personal-agent-protocol) for
current limits and security guidance.
