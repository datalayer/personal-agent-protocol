/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The shared protocol/fixtures, and the same error cases as the Python models
// (personal_agent_protocol/__tests__/test_models.py), case for case.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  accessTokenFromResponse,
  jwkThumbprint,
  parseClientMetadata,
  parseConversationEventPage,
  parseDiscoveryDocument,
  parseJsonStrict,
  parseJsonWebKeySet,
  parseMessage,
  parseOAuthServerMetadata,
  parseProtectedResourceMetadata,
  parseOperation,
  parseTokenResponse,
  messageOperation,
  messageApproval,
  messageLinks,
  messageDisclosures,
  companyExtension,
} from "../../lib/index.js";

const fixtures = new URL("../../protocol/fixtures/", import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, fixtures), "utf8"));
const invalid = (code) => (error) => error.code === code || (code === undefined && error.name === "ProtocolValidationError");

test("discovery fixture round-trips and preserves extensions", () => {
  const document = parseDiscoveryDocument(fixture("discovery-valid.json"));
  assert.equal(document.protocol_version, "0.4");
  assert.equal(document.apis[1].type, "mcp");
  assert.deepEqual(document.extensions.operations.map((entry) => entry.version), ["2"]);
  assert.equal(companyExtension(document, "operations", "2")?.version, "2");
  assert.equal(companyExtension(document, "operations", "1"), undefined);
});

test("auth is optional: the issuer comes from the domain's protected resource metadata", () => {
  const document = parseDiscoveryDocument({
    protocol_version: "0.4",
    organization: { name: "Example", domain: "example.com" },
    apis: [{ type: "openapi", url: "https://api.example.com/openapi.json", description: "Example" }],
  });
  assert.equal(document.auth, undefined);
  assert.equal(parseProtectedResourceMetadata(fixture("protected-resource-metadata-valid.json")).authorization_servers[0], "https://auth.example.com");
});

test("strict JSON rejects duplicate members", () => {
  assert.throws(() => parseJsonStrict('{"issuer":"first","issuer":"second"}'), invalid("duplicate_json_member"));
});

test("an operation's revision is an opaque string, and it has an expiry", () => {
  assert.throws(() => parseOperation({ ...fixture("operation-valid.json"), revision: 2 }), invalid("invalid_type"));
  const { expires_at: _expires, ...without } = fixture("operation-valid.json");
  assert.throws(() => parseOperation(without), /expires_at/);
});

test("shared client, conversation, and operation fixtures", () => {
  const client = parseClientMetadata(fixture("client-metadata-valid.json"));
  const operation = parseOperation(fixture("operation-valid.json"));
  const page = parseConversationEventPage(fixture("conversation-events-valid.json"));
  assert.ok(!("extensions" in client));
  assert.equal(operation.revision, "1791487200-k3Jd9Qx2mW8v");
  assert.equal("user_approval_required" in operation, false);
  // The operation is the Operations extension's content, `extensions.operations` (§8.4).
  assert.deepEqual(messageOperation(page.events[0].message), operation);
  assert.deepEqual(page.events[0].message.extensions, { operations: { operation: fixture("operation-valid.json") } });
  assert.equal(page.events[2].type, "example.org/future-event");
  assert.equal(page.events[2].future, true);
  // Links and Disclosures content, and an extension's content this SDK does not define.
  const linked = page.events[3].message;
  assert.equal(messageOperation(linked), undefined);
  assert.equal(messageApproval(linked), undefined);
  assert.deepEqual(messageLinks(linked), [{ url: "https://example.com/help/returns", title: "Return policy" }]);
  assert.deepEqual(messageDisclosures(linked), [{ text: "Contains peanuts. Made in a facility that also processes tree nuts." }]);
  assert.deepEqual(linked.extensions["example.org/future-content"], { anything: true });
});

test("the JWKS, OAuth metadata, and token response fixtures parse", () => {
  assert.equal(parseJsonWebKeySet(fixture("jwks-valid.json")).keys[0].kid, "agent-signing-2026-10");
  assert.deepEqual(parseOAuthServerMetadata(fixture("oauth-metadata-valid.json")).protected_resources, ["https://example.com", "https://mcp.example.com/mcp"]);
  const response = parseTokenResponse(fixture("token-response-valid.json"));
  assert.equal(response.tokenType, "Bearer");
  assert.equal(response.refreshToken.reveal(), "opaque-refresh-token");
  assert.deepEqual(accessTokenFromResponse(response).scopes, ["orders:read", "orders:write"]);
});

test("the Session JWT fixture's kid is the thumbprint of the delegation's key", async () => {
  const session = fixture("session-jwt-valid.json");
  const delegation = fixture("delegation-valid.json");
  assert.equal(session.header.kid, await jwkThumbprint(delegation.payload.cnf.jwk));
  assert.match(session.payload.ath, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(delegation.payload.exp - delegation.payload.iat <= 24 * 3600);
  assert.deepEqual(Object.keys(delegation.payload).sort(), ["cnf", "exp", "iat", "iss", "jti"]);
});

test("a message requires content", () => {
  assert.throws(() => parseMessage({ id: "msg_empty", author: { type: "agent" } }), (error) => error.code === "invalid_message");
});

test("a known conversation event requires its fields", () => {
  assert.throws(() => parseConversationEventPage({
    conversation_id: "cnv_one",
    events: [{ id: "evt_one", type: "state", created_at: "2026-10-10T17:03:00Z", handoff: "none" }],
    cursor: "evt_one",
    has_more: false,
    working: false,
    handoff: "none",
    responder: "agent",
    closed: false,
  }), /state event requires handoff, responder and closed/);
});

test("client metadata requires the same domain for security URLs", () => {
  assert.throws(() => parseClientMetadata({
    client_id: "https://agent.example/agent.json",
    client_name: "Example Agent",
    jwks_uri: "https://attacker.example/jwks.json",
    redirect_uris: [],
  }));
});

test("optional members serialized as null read as absent, as Python's models do", () => {
  const operation = parseOperation({ ...fixture("operation-valid.json"), terms: null });
  assert.equal("terms" in operation, false);
  // `extensions` too: a company's message with `extensions: null` is a message, not a refusal.
  const message = parseMessage({ id: "msg_1", author: { type: "agent" }, role: null, text: "Hi", data: null, context: null, extensions: null });
  assert.deepEqual(message, { id: "msg_1", author: { type: "agent" }, text: "Hi" });
  // A null where a member is required is still refused.
  assert.throws(() => parseOperation({ ...fixture("operation-valid.json"), summary: null }));
  assert.throws(() => parseOperation({ ...fixture("operation-valid.json"), expires_at: null }));
});
