---
slug: personal-agent-protocol-0.11
title: 'Personal Agent Protocol 0.11: complete Python and TypeScript SDKs'
authors: [echarles]
tags: [release, python, typescript]
date: 2026-10-12
---

The [Personal Agent Protocol](https://personalagentprotocol.org) (PAP) lets a
person's own agent discover a company's agent and work with it on the
person's behalf, while the company keeps its identity, sign-in, data, and
actions. Version 0.11.0 of our SDKs is the first complete implementation of
PAP in both Python and TypeScript: both roles, the personal agent and the
company, released together at the same version.

<!-- truncate -->

## What 0.11.0 ships

Both SDKs implement [PAP draft 0.1](https://personalagentprotocol.org/docs/spec)
(the specification as of 2026-10-09) and the Operations extension v1. The
same features exist in each language.

**As a personal agent:**

- **Discovery** of a company's `/.well-known/poppy.json` and its OAuth
  metadata, with the domain and issuer relationship checked, strict JSON
  (duplicate members refused), and bounded redirects, bytes, and time.
- **Identity:** your agent's client metadata and keys, signed client and
  Session assertions (ES256 or RS256), and pairwise user IDs so a company never
  learns who the person is elsewhere.
- **Sessions** that start signed out, with DPoP-bound tokens (a fresh proof
  per request and retry) and renewal.
- **Consent:** Direct, Device, and Mediated Sign-In, with the person's
  credentials kept between them and the company (protected input never reaches
  a model), and Account Tokens that rotate on every refresh, narrow, and
  revoke.
- **Conversations** with idempotent messages, ordered event polling, SSE
  streaming, handoff, Direct Conversations, and closing.
- **Operations:** a company proposes a consequential action as a revisioned
  operation; the person approves that exact revision; the agent confirms it,
  and it is performed at most once. Standing permissions, with term-by-term
  bounds, are operations the person approves too.
- **APIs:** OpenAPI and MCP clients; MCP uses a Bearer token bound to that one
  server's URL, DPoP is required everywhere else.

**As a company:**

- A reference company assembled from [Reactor](https://github.com/datalayer/reactor)
  contributions, served over ASGI in Python and `node:http(s)` in TypeScript:
  discovery, Sessions, the three sign-in modes, Account Tokens,
  conversations, an OpenAPI API and an MCP endpoint, browser sessions with
  operation pages, and Operations.
- Everything it remembers lives in one store contract (`pap.company.store`),
  with a kit that checks a backend against it (`check_store`, `checkStore`).
  The replay cache lives in that store, so replicas sharing a store share it.

**For both:**

- **Telemetry**, redacted by construction: one event per discovery, Session,
  sign-in, conversation, and operation stage, to a `pap.telemetry` sink, with
  an OpenTelemetry adapter.
- **Security hardening:** 0.10.0 followed an independent review of both SDKs.
  Its fixes include attempt limits on Mediated Sign-In, a replay cache shared
  through the company store, SSRF defences that resolve and pin every address
  (now in TypeScript too, with `createResolvingFetch`), bounded response reads,
  and no request body re-sent to a redirect. Canary suites in both languages
  check that no credential reaches a log, an error, a URL, a trace, or a
  model. What is still open is listed on [Open security
  points](/security/review/).
- **Conformance:** a requirement ledger of the draft's MUSTs and SHOULDs, a
  conformance runner (`pap conformance run`), and the four language pairings
  (a Python or TypeScript agent with a Python or TypeScript company), each
  passing all 91 cases in the [conformance report](/protocol/conformance-report/).

## Install

```bash
pip install personal-agent-protocol
npm install @datalayer/personal-agent-protocol
```

Python 3.10 or later. The `ui`, `telemetry`, and `server` extras add the
sign-in displays, the OpenTelemetry adapter, and serving over real sockets.

## Both roles in a few lines

A company and a personal agent discovering it, in one process. Python:

```python
import asyncio

import httpx

from personal_agent_protocol import DiscoveryClient
from personal_agent_protocol.company import CompanyConfig, build_company, company_app


async def public_address(host: str) -> list[str]:
    return ["93.184.216.34"]  # a stand-in for DNS in this in-process run


async def main() -> None:
    config = CompanyConfig(
        name="Example Shop",
        domain="shop.example",
        scopes=("orders:read", "orders:write"),
        write_scopes=("orders:write",),
    )
    async with httpx.AsyncClient() as outbound:
        company = company_app(build_company(config, http_client=outbound))
        network = httpx.AsyncClient(transport=httpx.ASGITransport(app=company))
        async with DiscoveryClient(http_client=network, address_resolver=public_address) as client:
            discovered = await client.discover("shop.example")
            print(discovered.document.organization.name)  # Example Shop
            print(discovered.document.auth.issuer)  # https://shop.example


asyncio.run(main())
```

TypeScript (Node), with a `fetch` that hands every request to the company:

```typescript
import { buildPapReactor, discoverCompany } from "@datalayer/personal-agent-protocol";
import { CompanyConfig, buildCompany } from "@datalayer/personal-agent-protocol/server";

const company = buildCompany(
  new CompanyConfig({
    name: "Example Shop",
    domain: "shop.example",
    scopes: ["orders:read", "orders:write"],
    writeScopes: ["orders:write"],
  }),
);

const network = async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const request = new Request(input, init);
  const answer = await company.handle({
    method: request.method,
    url: request.url,
    headers: Object.fromEntries(request.headers),
  });
  return Response.json(answer.body, { status: answer.status, headers: answer.headers });
};

const reactor = buildPapReactor({ fetch: network });
const discovered = await discoverCompany("shop.example", { reactor });
console.log(discovered.document.organization.name); // Example Shop
console.log(discovered.document.auth?.issuer); // https://shop.example
```

A real company adds its account directory, its agent, and one executor per
action as Reactor plugins; a real personal agent adds its signer, token store,
and browser handoff. The [company guide](/guides/company/) and the [personal
agent guide](/guides/personal-agent/) go through each.

## Start here

- [Getting started](/getting-started/), the [Python SDK](/sdk/python/), and
  the [TypeScript SDK](/sdk/typescript/).
- [Examples](/examples/): a user with a company (Ada's agent exchanging a
  jacket at Manzanita, from a first question to a confirmed operation) and two
  companies (Ledgerly paying invoices at Northwind Bank), each runnable with
  [Pydantic AI](https://github.com/datalayer/personal-agent-protocol/tree/main/examples/pydantic-ai)
  and [Agent Runtimes](https://github.com/datalayer/agent-runtimes/tree/main/examples/personal-agent-protocol).
- [Operations](/guides/operations/), [Telemetry](/guides/telemetry/), and
  [Security](/security/).
- The [changelog](https://github.com/datalayer/personal-agent-protocol/blob/main/CHANGELOG.md)
  and [compatibility](/releases/compatibility/). PAP is a draft, so the SDKs
  stay `0.x`: a minor release may change the API, and the [migration
  guide](/releases/migration/) says how.

## In the Datalayer platform

We are now integrating PAP in the Datalayer platform, in its two roles.
Applications built in Datalayer Studio will act as a person's agent at
companies: connect a company by its domain, start signed out, ask the person
to sign in only when needed, and show each consequential action as one
proposal the person approves. And applications published from Datalayer will
be PAP companies: on their own domain, with a company agent, APIs, MCP, and
Operations that personal agents can reach. The [Studio
integration](/studio/integration/) page describes the plan.

Questions and interoperability reports are welcome on
[GitHub](https://github.com/datalayer/personal-agent-protocol/issues).
