# @datalayer/personal-agent-protocol

TypeScript SDK for Personal Agent Protocol draft 0.1.

```typescript
import { discoverCompany } from "@datalayer/personal-agent-protocol";

const company = await discoverCompany("example.com");
```

The current release provides forward-compatible discovery, OAuth, client
metadata, conversation-event, and Operations v1 models; strict
duplicate-member rejection; local Direct Sign-In primitives; signed-out
session start and renewal; and safe company discovery built on Datalayer
Reactor. It also provides ES256/RS256 JOSE signing and DPoP proof creation and
verification through the maintained `jose` package. Use
`buildPapReactor(options, plugins)` to install typed transport, URL-policy,
protocol-profile, clock, randomness, signer, DPoP proof, protected-key,
token-store, cache, browser-handoff, and extension-handler contributions, or
pass an existing Reactor host to `discoverCompany`. Security-dependent
services have no fallback and fail closed when missing or ambiguous. See the
repository README for current limits and security guidance.
