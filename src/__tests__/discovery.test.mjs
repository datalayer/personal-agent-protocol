/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DiscoveryTransports,
  DiscoveryError,
  ProtocolValidationError,
  UrlSafetyPolicies,
  JWT_BEARER_GRANT,
  JWT_CLIENT_ASSERTION,
  SessionGrant,
  buildPapReactor,
  buildSessionAssertionClaims,
  discoverCompany,
  generatePairwiseUserId,
  parseClientMetadata,
  parseConversationEventPage,
  parseDiscoveryDocument,
  parseJsonStrict,
  parseMessage,
  parseOperation,
  parseSessionToken,
} from "../../lib/index.js";

const fixture = async (name) =>
  JSON.parse(
    await readFile(new URL(`../../protocol/fixtures/${name}`, import.meta.url), "utf8"),
  );

test("parses the shared discovery fixture and preserves extension fields", async () => {
  const document = parseDiscoveryDocument(await fixture("discovery-valid.json"));
  assert.equal(document.protocol_version, "0.2");
  assert.equal(document.apis[1].type, "mcp");
  assert.equal(document.auth.mediated.fields[1].secret, true);
  assert.equal(document.auth.custom_scopes.addresses, "Manage saved shipping addresses");
  assert.equal(document.extensions.operations.endpoint, "https://api.example.com/poppy/operations");
});

test("discovers and authenticates a company", async () => {
  const discovery = await fixture("discovery-valid.json");
  const metadata = await fixture("oauth-metadata-valid.json");
  const fetch = async (input) => {
    const url = new URL(input);
    const body = url.hostname === "example.com" ? discovery : metadata;
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  const company = await discoverCompany("example.com", { fetch });
  assert.equal(company.document.organization.name, "Example Company");
  assert.equal(company.oauthMetadata.token_endpoint, "https://auth.example.com/oauth/token");
});

test("passes AbortSignal to discovery requests", async () => {
  const discovery = await fixture("discovery-valid.json");
  const metadata = await fixture("oauth-metadata-valid.json");
  const controller = new AbortController();
  const receivedSignals = [];
  const fetch = async (input, init) => {
    receivedSignals.push(init.signal);
    const body = new URL(input).hostname === "example.com" ? discovery : metadata;
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await discoverCompany("example.com", { fetch, signal: controller.signal });

  // Each request is given a signal of its own that follows the caller's
  // (combined with the SDK's deadline), not the caller's object itself.
  assert.equal(receivedSignals.length, 2);
  for (const signal of receivedSignals) {
    assert.ok(signal instanceof AbortSignal);
    assert.equal(signal.aborted, false);
  }

  // The caller aborting while a request is under way aborts that request.
  const stopping = new AbortController();
  let followed;
  const aborting = async (_input, init) => {
    stopping.abort(new Error("stop"));
    followed = init.signal.aborted;
    throw init.signal.reason ?? new Error("aborted");
  };
  await assert.rejects(discoverCompany("example.com", { fetch: aborting, signal: stopping.signal }));
  assert.equal(followed, true);
});

test("rejects an OAuth issuer that does not authorize the company domain", async () => {
  const discovery = await fixture("discovery-valid.json");
  const metadata = {
    ...(await fixture("oauth-metadata-valid.json")),
    poppy_domains: ["attacker.example"],
  };
  const fetch = async (input) => {
    const body = new URL(input).hostname === "example.com" ? discovery : metadata;
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await assert.rejects(
    discoverCompany("example.com", { fetch }),
    (error) => error instanceof DiscoveryError && error.code === "domain_not_authorized",
  );
});

test("discovers through Reactor contributions", async () => {
  const discovery = await fixture("discovery-valid.json");
  const metadata = await fixture("oauth-metadata-valid.json");
  const plugin = {
    name: "pap-test",
    contributes: [
      {
        point: DiscoveryTransports,
        value: {
          fetch: async (input) => {
            const body = input.hostname === "example.com" ? discovery : metadata;
            return new Response(JSON.stringify(body), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          },
        },
      },
      {
        point: UrlSafetyPolicies,
        value: { assertSafe: () => undefined },
      },
    ],
  };
  const reactor = buildPapReactor({}, [plugin]);

  const company = await discoverCompany("example.com", { reactor });

  assert.equal(company.oauthMetadata.issuer, "https://auth.example.com");
});

test("rejects duplicate JSON members at every trust-boundary depth", async () => {
  assert.throws(
    () => parseJsonStrict('{"organization":{"name":"first","name":"second"}}'),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "duplicate_json_member",
  );
  assert.throws(
    () => parseJsonStrict('{"name":1,"n\\u0061me":2}'),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "duplicate_json_member",
  );

  const fetch = async () =>
    new Response(
      '{"protocol_version":"0.1","protocol_version":"0.2",' +
        '"organization":{"name":"Example","domain":"example.com"},' +
        '"auth":{"issuer":"https://auth.example.com"},' +
        '"apis":[{"type":"openapi","url":"https://example.com/openapi.json",' +
        '"description":"Example"}]}',
      { status: 200, headers: { "content-type": "application/json" } },
    );

  await assert.rejects(
    discoverCompany("example.com", { fetch }),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "duplicate_json_member",
  );
});

test("builds redacted PAP session primitives", async () => {
  const randomBytes = (length) => Uint8Array.from({ length }, (_, index) => index);
  const userId = generatePairwiseUserId(randomBytes);
  const claims = buildSessionAssertionClaims({
    clientId: "https://agent.example/agent.json",
    pairwiseUserId: userId,
    issuer: "https://auth.example.com",
    now: new Date("2026-10-10T00:00:00Z"),
    randomBytes,
  });
  const grant = new SessionGrant({
    assertion: "session-assertion",
    clientId: claims.iss,
    clientAssertion: "client-assertion",
    sessionId: "ses_2Lm0",
  });
  const token = parseSessionToken(await fixture("session-token-valid.json"));

  assert.equal(userId, "usr_AAECAwQFBgcICQoLDA0ODw");
  assert.equal(claims.exp - claims.iat, 60);
  assert.equal(claims.jti, "jti_AAECAwQFBgcICQoLDA0ODw");
  assert.equal(grant.toForm().get("grant_type"), JWT_BEARER_GRANT);
  assert.equal(grant.toForm().get("client_assertion_type"), JWT_CLIENT_ASSERTION);
  assert.equal(JSON.stringify(grant).includes("session-assertion"), false);
  assert.equal(token.accessToken.reveal(), "opaque-session-token");
  assert.equal(JSON.stringify(token).includes("opaque-session-token"), false);
  assert.deepEqual(token.scopes, ["poppy:read", "poppy:write"]);
});

test("parses shared client, conversation, and operation fixtures", async () => {
  const client = parseClientMetadata(await fixture("client-metadata-valid.json"));
  const operation = parseOperation(await fixture("operation-valid.json"));
  const page = parseConversationEventPage(
    await fixture("conversation-events-valid.json"),
  );

  assert.equal(client.extensions["example.org/preferences"].mode, "compact");
  assert.equal(operation.user_approval_required, true);
  assert.deepEqual(page.events[0].message.operation, operation);
  assert.equal(page.events[2].type, "example.org/future-event");
  assert.equal(page.events[2].future, true);
});

test("validates known conversation shapes while preserving future events", () => {
  assert.throws(
    () => parseMessage({ id: "msg_empty", sender: "agent" }),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "invalid_message",
  );
  assert.throws(
    () =>
      parseConversationEventPage({
        conversation_id: "cnv_one",
        events: [
          {
            id: "evt_one",
            type: "state",
            created_at: "2026-10-10T17:03:00Z",
            status: "idle",
          },
        ],
        cursor: "evt_one",
        has_more: false,
        status: "idle",
        responder: "agent",
      }),
    (error) => error instanceof ProtocolValidationError && error.code === "invalid_event",
  );
});

test("requires client security URLs to stay on the client ID domain", () => {
  assert.throws(
    () =>
      parseClientMetadata({
        client_id: "https://agent.example/agent.json",
        client_name: "Example Agent",
        jwks_uri: "https://attacker.example/jwks.json",
        redirect_uris: [],
      }),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "client_domain_mismatch",
  );
});
