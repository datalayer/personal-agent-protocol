<!--
  ~ Copyright (c) 2025-2026 Datalayer, Inc.
  ~
  ~ BSD 3-Clause License
-->

[![Datalayer](https://images.datalayer.io/legacy/datalayer-25.svg)](https://datalayer.ai)

# 🤖 🌸 Personal Agent Protocol

Python and TypeScript SDKs for [Personal Agent Protocol](https://personalagentprotocol.org),
currently targeting [draft 0.1](https://personalagentprotocol.org/docs/spec).

The first implemented slice provides:

- forward-compatible discovery, OAuth metadata, client metadata, conversation
  messages/events, and Operations v1 models in Python and TypeScript;
- company discovery at `/.well-known/poppy.json`;
- validation of the requested company domain, OAuth issuer, and
  `poppy_domains` relationship;
- HTTPS-only redirects, bounded response sizes, and a public-address preflight
  guard in the Python discovery client;
- Reactor-backed protocol profiles, discovery transports, URL-safety policies,
  extension handlers, clocks, randomness, signing, protected keys, token
  storage, caches, and browser-handoff contribution points in both SDKs;
- redacted session-token values, random pairwise user-ID generation, PAP 4.2
  assertion claims, and JWT-bearer request forms in both SDKs;
- signed-out session start and renewal over HTTP, with Reactor-provided signing
  and DPoP proof generation, in both SDKs;
- asymmetric ES256/RS256 JOSE signers and RFC 9449 DPoP creation and
  verification, including nonce, request, token-hash, freshness, and replay
  checks, in both SDKs;
- Direct Sign-In state, S256 PKCE, callback validation, and redacted
  authorization-code exchange forms in both SDKs;
- duplicate JSON member rejection at Python and TypeScript trust boundaries;
- a Reactor-extensible `pap` CLI with non-secret profiles, verified company
  discovery, extension diagnostics, versioned JSON, and a safe live-session
  discovery command;
- one shared set of fixtures exercised by both SDKs.

Managed key custody and durable replay storage, browser handoff and Direct
Sign-In token exchange, device/mediated sign-in, conversations, and the
Operations client/server are not implemented yet.

Session requests fail closed unless the host contributes signer and 
DPoP providers backed by suitable key custody.

## Python

```bash
python -m pip install -e '.[test,lint,typing]'
python -m pytest tests
```

```python
import asyncio

from personal_agent_protocol import DiscoveryClient


async def main() -> None:
    async with DiscoveryClient() as client:
        company = await client.discover("example.com")
        print(company.document.organization.name)


asyncio.run(main())
```

`DiscoveryClient(reactor=platform)` accepts an existing Reactor
`PluginPlatform`. The default `build_pap_reactor()` host contributes the HTTPX
transport, public-network safety policy, and PAP 0.1 profile. A plugin can
replace a default by contributing at a lower order; equal highest priorities
fail closed as ambiguous.

The core also contributes UTC time and operating-system randomness. It does
not provide insecure fallbacks for signing, DPoP proof generation, protected
keys, token storage, cache, or browser handoff. A flow requiring one fails
closed until its host contributes it.

### Command line

The Python package installs an extensible `pap` command. Its command groups are
provided through Reactor's `datalayer.reactor.cli` entry-point contract.

```bash
pap config set domain example.com --profile work
pap config show --profile work --json
pap company verify --profile work --json
pap extensions list --profile work
```

Only non-secret settings belong in CLI profiles. See the
[CLI guide](https://personalagentprotocol.org/docs/guides/cli) for precedence,
security boundaries, machine output, and third-party extension examples.

## TypeScript

Source code in [packages/typescript](./tree/main/packages/typescript)

```bash
npm install
npm test
```

```typescript
import { discoverCompany } from "@datalayer/personal-agent-protocol";

const company = await discoverCompany("example.com");
console.log(company.document.organization.name);
```

Use `buildPapReactor(options, plugins)` to assemble the TypeScript host, or
pass an existing `ReactorPlatformView` as `discoverCompany(..., { reactor })`.
The package bundles Reactor's framework-neutral core in its ESM entry so it can
run directly in Node as well as through a browser bundler.

Server-side TypeScript callers should provide `assertSafeUrl` with DNS-aware
SSRF protection. The portable default rejects obvious local/private literal
addresses, but a browser-compatible package cannot verify the address selected
by DNS.

The Python preflight rejects a host if any resolved address is non-public.
Transport-level address pinning, required to close the DNS-rebinding interval,
is still part of the security work before the first beta.

## Protocol sources

- [Overview](https://personalagentprotocol.org/docs/overview)
- [Specification](https://personalagentprotocol.org/docs/spec)
- [Implementation guides](https://personalagentprotocol.org/docs/guides)
- [Operations extension](https://personalagentprotocol.org/docs/extensions/operations)
