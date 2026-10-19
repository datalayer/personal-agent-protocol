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
  parseClientMetadata,
  parseConversationEventPage,
  parseDiscoveryDocument,
  parseJsonStrict,
  parseJsonWebKeySet,
  parseMessage,
  parseOAuthServerMetadata,
  parseOperation,
  parseSessionToken,
} from "../../lib/index.js";

const fixtures = new URL("../../protocol/fixtures/", import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, fixtures), "utf8"));
const invalid = (code) => (error) => error.code === code || (code === undefined && error.name === "ProtocolValidationError");

test("discovery fixture round-trips and preserves extensions", () => {
  const document = parseDiscoveryDocument(fixture("discovery-valid.json"));
  assert.equal(document.protocol_version, "0.2");
  assert.equal(document.apis[1].type, "mcp");
  assert.equal(document.extensions.operations.endpoint, "https://api.example.com/poppy/operations");
});

test("discovery requires auth for an API", () => {
  assert.throws(() => parseDiscoveryDocument({
    protocol_version: "0.2",
    organization: { name: "Example", domain: "example.com" },
    apis: [{ type: "openapi", url: "https://api.example.com/openapi.json", description: "Example" }],
  }));
});

test("strict JSON rejects duplicate members", () => {
  assert.throws(() => parseJsonStrict('{"issuer":"first","issuer":"second"}'), invalid("duplicate_json_member"));
});

test("an operation requires the exact current revision", () => {
  assert.throws(() => parseOperation({
    operation_id: "op_123",
    revision: 2,
    state: "in_progress",
    summary: "Change the booking",
    confirmation: { revision: 1, approved_by: "user", confirmed_at: "2026-10-10T10:00:00Z" },
    result: null,
  }), /current revision/);
});

test("shared client, conversation, and operation fixtures", () => {
  const client = parseClientMetadata(fixture("client-metadata-valid.json"));
  const operation = parseOperation(fixture("operation-valid.json"));
  const page = parseConversationEventPage(fixture("conversation-events-valid.json"));
  assert.equal(client.extensions["example.org/preferences"].mode, "compact");
  assert.equal(operation.user_approval_required, true);
  assert.deepEqual(page.events[0].message.operation, operation);
  assert.equal(page.events[2].type, "example.org/future-event");
  assert.equal(page.events[2].future, true);
});

test("the JWKS, OAuth metadata, and Session token fixtures parse", () => {
  assert.equal(parseJsonWebKeySet(fixture("jwks-valid.json")).keys[0].kid, "agent-signing-2026-10");
  assert.deepEqual(parseOAuthServerMetadata(fixture("oauth-metadata-valid.json")).poppy_domains, ["example.com"]);
  const token = parseSessionToken(fixture("session-token-valid.json"));
  assert.equal(token.signedIn, false);
  assert.deepEqual(token.scopes, ["poppy:read", "poppy:write"]);
});

test("a message requires content", () => {
  assert.throws(() => parseMessage({ id: "msg_empty", sender: "agent" }), /requires text, data, context, or operation/);
});

test("a known conversation event requires its fields", () => {
  assert.throws(() => parseConversationEventPage({
    conversation_id: "cnv_one",
    events: [{ id: "evt_one", type: "state", created_at: "2026-10-10T17:03:00Z", status: "idle" }],
    cursor: "evt_one",
    has_more: false,
    status: "idle",
    responder: "agent",
  }), /state event requires status and responder/);
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
  const operation = parseOperation({
    ...fixture("operation-valid.json"),
    state: "cancelled",
    url: null,
    terms: null,
    expires_at: null,
    result: { summary: "Nothing was changed.", data: null },
  });
  assert.equal("url" in operation, false);
  assert.equal("terms" in operation, false);
  assert.equal("expires_at" in operation, false);
  assert.deepEqual(operation.result, { summary: "Nothing was changed." });
  const message = parseMessage({ id: "msg_1", sender: "agent", role: null, text: "Hi", data: null, context: null, operation: null });
  assert.deepEqual(message, { id: "msg_1", sender: "agent", text: "Hi" });
  // A null where a member is required is still refused.
  assert.throws(() => parseOperation({ ...fixture("operation-valid.json"), summary: null }));
  assert.throws(() => parseOperation({ ...fixture("operation-valid.json"), expires_at: null }), /requires expires_at/);
});
