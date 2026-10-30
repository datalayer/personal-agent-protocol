/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The shared conformance fixtures the SDK decides alone (a `check`, no company), in
// TypeScript: the same cases as personal_agent_protocol/__tests__/test_fixtures.py.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { decodeJwt, decodeProtectedHeader } from "jose";

import {
  ApiClient,
  ConversationClient,
  DelegatedSessionSigner,
  InMemoryDelegatedKeys,
  InMemoryDpopKeys,
  JoseDpopProver,
  SecretValue,
  SessionClient,
  SessionError,
  SessionFetchClient,
  SessionSigners,
  Signers,
  buildPapReactor,
  conversationEndpoint,
  discoverCompany,
  extensionNameKind,
  extensionRequired,
  knownApis,
  negotiateExtensions,
  parseConversationEventPage,
  parseDiscoveryDocument,
  parseJsonStrict,
  parseMessage,
  parseOperation,
} from "../../lib/index.js";
import { NodeUrlSafetyPolicy } from "../../lib/server.js";
import { agentIdentity } from "./support/world.mjs";

const SUITES = ["protocol", "security", "lifecycle", "conversations", "operations", "dpop"];
const KNOWN_EVENT_TYPES = new Set(["message", "state", "authorization", "user_requested", "direct_opened", "direct_closed"]);

const LOCAL = SUITES.flatMap((suite) =>
  JSON.parse(readFileSync(new URL(`../../protocol/fixtures/conformance/${suite}.json`, import.meta.url), "utf8"))
    .cases.filter((item) => item.check !== undefined),
);

const rejectsWith = (code) => (error) => error.code === code || error.name === code;

/** A network answering fixed responses by URL; a `trickle` body arrives a few bytes at a time. */
function mockNetwork(responses) {
  return async (input) => {
    const answer = responses[String(input)];
    if (answer === undefined) {
      return new Response(JSON.stringify({ error: "not_found" }), { status: 404, headers: { "content-type": "application/json" } });
    }
    const headers = new Headers(answer.headers ?? {});
    let body = null;
    if ("json" in answer) {
      body = JSON.stringify(answer.json) + " ".repeat(answer.padding_bytes ?? 0);
      if (!headers.has("content-type")) headers.set("content-type", answer.content_type ?? "application/json");
    } else if ("text" in answer) {
      body = String(answer.text);
      if (!headers.has("content-type")) headers.set("content-type", answer.content_type ?? "text/plain");
    }
    if (answer.trickle && body !== null) {
      const bytes = new TextEncoder().encode(body);
      const { chunk_bytes: size, interval_seconds: interval } = answer.trickle;
      let offset = 0;
      const stream = new ReadableStream({
        async pull(controller) {
          await new Promise((resolve) => setTimeout(resolve, interval * 1000));
          if (offset >= bytes.length) {
            controller.close();
            return;
          }
          controller.enqueue(bytes.slice(offset, offset + size));
          offset += size;
        },
      });
      return new Response(stream, { status: answer.status, headers });
    }
    return new Response([301, 302, 303, 307, 308].includes(answer.status) ? null : body, { status: answer.status, headers });
  };
}

const CHECKS = {
  discovery_document(given, expect) {
    if (!expect.valid) {
      assert.throws(() => parseDiscoveryDocument(given));
      return;
    }
    const document = parseDiscoveryDocument(given);
    for (const [key, value] of Object.entries(expect.extra ?? {})) assert.deepEqual(document[key], value);
    if ("known_api_types" in expect) assert.deepEqual(knownApis(document).map((api) => api.type), expect.known_api_types);
    if ("conversation_endpoint" in expect) assert.equal(conversationEndpoint(document), expect.conversation_endpoint);
  },

  extension_negotiation(given, expect) {
    const document = (extensions) => parseDiscoveryDocument({ protocol_version: "0.3", organization: { name: "E", domain: "example.com" }, web: {}, extensions });
    assert.deepEqual(negotiateExtensions(document(given.company).extensions, document(given.agent).extensions), expect.negotiated);
  },

  extension_names(given, expect) {
    const kinds = { plain: [], "third-party": [], invalid: [] };
    for (const name of Object.keys(given)) kinds[extensionNameKind(name)].push(name);
    assert.deepEqual(kinds["third-party"].sort(), expect.third_party);
    assert.deepEqual(kinds.plain.sort(), expect.plain);
    assert.deepEqual(kinds.invalid.sort(), [...expect.invalid].sort());
    const preserved = parseDiscoveryDocument({
      protocol_version: "0.3",
      organization: { name: "E", domain: "example.com" },
      web: {},
      extensions: Object.fromEntries(Object.entries(given).filter(([name]) => extensionNameKind(name) !== "invalid")),
    }).extensions;
    assert.equal(preserved["example.com/gift-wrap"].color, "red");
  },

  extension_required(given, expect) {
    assert.equal(extensionRequired(given.status, given.body, given.www_authenticate), expect.extension);
  },

  conversation_page(given, expect) {
    const page = parseConversationEventPage(given);
    assert.deepEqual(page.events.filter((event) => KNOWN_EVENT_TYPES.has(event.type)).map((event) => event.type), expect.known_types);
    assert.deepEqual(page.events.filter((event) => !KNOWN_EVENT_TYPES.has(event.type)).map((event) => event.type), expect.unknown_types);
    assert.equal(page.region, "eu");
  },

  message_context(given) {
    for (const context of given.valid) assert.deepEqual(parseMessage({ id: "msg_ctx", author: { type: "agent" }, context }).context, context);
    for (const context of given.invalid) assert.throws(() => parseMessage({ id: "msg_ctx", author: { type: "agent" }, context }));
  },

  operation(given, expect) {
    const operation = parseOperation(given);
    for (const [key, value] of Object.entries(expect.extra ?? {})) assert.deepEqual(operation[key], value);
  },

  async discovery(given, expect) {
    const options = { fetch: mockNetwork(given.responses), ...(given.timeout_seconds ? { timeoutMs: given.timeout_seconds * 1000 } : {}) };
    if ("error" in expect) {
      await assert.rejects(discoverCompany(given.domain, options), rejectsWith(expect.error));
      return;
    }
    const company = await discoverCompany(given.domain, options);
    if ("issuer" in expect) assert.equal(company.oauthMetadata?.issuer ?? null, expect.issuer);
    if ("organization_domain" in expect) assert.equal(company.document.organization.domain, expect.organization_domain);
    if ("discovery_url" in expect) assert.equal(company.discoveryUrl, expect.discovery_url);
  },

  async url_safety(given, expect) {
    const policy = new NodeUrlSafetyPolicy({ resolver: async () => given.addresses });
    if (expect.safe) {
      await policy.assertSafe(new URL(given.url));
      return;
    }
    await assert.rejects(policy.assertSafe(new URL(given.url)), rejectsWith(expect.error));
  },

  strict_json(given, expect) {
    for (const document of given) assert.throws(() => parseJsonStrict(document), rejectsWith(expect.error));
  },

  async rate_limited(given, expect) {
    const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
    // A 429 has `Retry-After` and no body (§5.6); one sent as JSON all the same reads alike.
    for (const body of [null, JSON.stringify(given.body)]) {
      const headers = { ...given.headers, ...(body === null ? {} : { "content-type": "application/json" }) };
      const fetch = async () => new Response(body, { status: given.status, headers });
      const reactor = buildPapReactor({ fetch }, [
        {
          name: "@tests/rate-limited",
          contributes: [
            { point: Signers, value: identity.signer, options: { id: "signer" } },
            {
              point: SessionSigners,
              value: new DelegatedSessionSigner({ custody: new InMemoryDelegatedKeys(), signer: identity.signer }),
              options: { id: "delegated-keys" },
            },
          ],
        },
      ]);
      const refused = (error) =>
        error.code === expect.error && JSON.stringify(error.details) === JSON.stringify({ retry_after: expect.retry_after });
      const sessions = new SessionClient({ reactor, fetch });
      await assert.rejects(
        sessions.tokenRequest({
          clientId: identity.clientId,
          issuer: "https://shop.example",
          tokenEndpoint: "https://shop.example/oauth/token",
          form: () => ({ grant_type: "refresh_token", refresh_token: "rt_rate_limited" }),
          error: SessionError,
          tenantId: "t",
          dpopSigningAlgs: undefined,
        }),
        refused,
      );
      // An API call is not retried either: the caller is told how long to wait.
      const session = await sessions.start({
        clientId: identity.clientId,
        pairwiseUserId: "usr_rate_limited_0000000",
        issuer: "https://shop.example",
        tenantId: "t",
      });
      const transport = new SessionFetchClient({ reactor, fetch });
      await assert.rejects(new ApiClient({ transport }).call("GET", "https://shop.example/api/orders", { session }), refused);
      const conversations = new ConversationClient({ reactor, transport });
      await assert.rejects(conversations.readEvents("https://shop.example/poppy/conversations", "cnv_rate_limited", { session }), refused);
      reactor.stop();
    }
  },

  async delegated_key_per_user_id(given, expect) {
    const identity = await agentIdentity({ domain: "agent.example", name: "Agent" });
    const signer = new DelegatedSessionSigner({ custody: new InMemoryDelegatedKeys(), signer: identity.signer });
    const keys = new Set();
    const delegations = new Set();
    for (const { sub, issuer } of given.requests) {
      const compact = await signer.sign({
        method: "GET",
        url: `${issuer}/api/orders`,
        tenantId: "t",
        issuer,
        clientId: identity.clientId,
        sid: "c2lkX2Zvcl90aGVfZml4dHVyZQ",
        sub,
      });
      const header = decodeProtectedHeader(compact.reveal());
      keys.add(header.kid);
      delegations.add(decodeJwt(header.pap_dlg).jti);
    }
    assert.equal(keys.size, expect.keys);
    assert.equal(delegations.size, expect.delegations);
  },

  /** Whether a token request proves, and what becomes of its answer (§4.5). */
  async dpop_token_request(given, expect) {
    const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
    for (const [index, { algs, token_type: tokenType }] of given.entries()) {
      const wanted = expect[index];
      const sent = [];
      const answer = { access_token: "t", token_type: tokenType, expires_in: 60 };
      const fetch = async (_url, init) => {
        sent.push(new Headers(init.headers));
        return new Response(JSON.stringify(answer), { status: 200, headers: { "content-type": "application/json" } });
      };
      const reactor = buildPapReactor({ fetch }, [
        { name: "@tests/dpop", contributes: [{ point: Signers, value: identity.signer, options: { id: "signer" } }] },
      ]);
      const request = new SessionClient({ reactor, fetch }).tokenRequest({
        clientId: identity.clientId,
        issuer: "https://shop.example",
        tokenEndpoint: "https://shop.example/oauth/token",
        form: () => ({ grant_type: "refresh_token", refresh_token: "rt" }),
        error: SessionError,
        tenantId: "t",
        dpopSigningAlgs: algs ?? undefined,
      });
      if ("error" in wanted) await assert.rejects(request, rejectsWith(wanted.error));
      else await request;
      assert.equal(sent[0].has("dpop"), wanted.proof);
      reactor.stop();
    }
  },

  /** A proof's header and claims (RFC 9449 §4.2). */
  async dpop_proof_shape(given, expect) {
    const proof = await new JoseDpopProver(new InMemoryDpopKeys()).prove({
      method: given.method,
      url: given.url,
      tenantId: "t",
      issuer: "https://shop.example",
      accessToken: new SecretValue(given.access_token),
      nonce: given.nonce,
    });
    const header = decodeProtectedHeader(proof.reveal());
    assert.equal(header.typ, "dpop+jwt");
    assert.equal(header.alg, "ES256");
    assert.deepEqual(Object.keys(header.jwk).sort(), ["crv", "kty", "x", "y"]);
    const claims = decodeJwt(proof.reveal());
    for (const [name, value] of Object.entries(expect)) assert.equal(claims[name], value);
    assert.ok(claims.jti.length >= 22);
  },
};

for (const fixture of LOCAL) {
  const only = fixture.sdk;
  const skip = only !== undefined && !only.includes("typescript") ? `decided by ${only.join(", ")} only` : false;
  test(`${fixture.id} (${fixture.check})`, { skip }, async () => {
    const check = CHECKS[fixture.check];
    assert.ok(check, `unknown fixture check ${fixture.check}`);
    await check(fixture.input, fixture.expect);
  });
}

test("every check-only fixture case is decided here or marked for another SDK", () => {
  for (const fixture of LOCAL) {
    assert.ok(CHECKS[fixture.check] || (fixture.sdk && !fixture.sdk.includes("typescript")), fixture.id);
  }
});
