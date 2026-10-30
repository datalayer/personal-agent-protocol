/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The company's OpenAPI API through `ApiClient`: the port of the API parts of
// personal_agent_protocol/__tests__/test_direct_and_api.py, against the TypeScript company
// in one process, and its refusals from a scripted server.
import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiClient,
  ApiError,
  DeviceSignInClient,
  SessionClient,
  SessionFetchClient,
  accessTokenFromResponse,
  discoverCompany,
  openapiUrl,
  parseOperation,
  parseTokenResponse,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const ORDERS = "https://manzanita.example/api/orders";

async function world() {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const transport = new SessionFetchClient({ reactor: host.reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const session = await new SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: metadata.issuer,
    tenantId: TENANT,
  });
  return { clock, fetch, identity, shop, plugin, host, transport, company, metadata, session };
}

async function signIn(w, granted) {
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    organization: { name: "Manzanita", domain: new URL(w.metadata.protected_resources[0]).hostname },
    protectedResources: w.metadata.protected_resources,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada", ...(granted ? { scopes: granted } : {}) });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return done.token;
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  assert.fail("expected an ApiError");
}

test("signed out, then signed in: a read, and an exchange refused until it is approved", async () => {
  const w = await world();
  const api = new ApiClient({ transport: w.transport });
  assert.equal(openapiUrl(w.company.document), "https://manzanita.example/api/openapi.json");

  // Signed out: the API says which scope signing in would give (§7).
  const signedOut = await refusal(api.call("GET", ORDERS, { session: w.session }));
  assert.equal(signedOut.code, "insufficient_scope");
  assert.deepEqual(signedOut.details, { scope: "orders:read" });

  const token = await signIn(w);
  const read = await api.call("GET", ORDERS, { session: w.session, token });
  assert.equal(read.status, 200);
  assert.deepEqual(read.body, { orders: [{ order_id: "ord_7Hk2", item: "Ridge Jacket, size M", status: "delivered" }] });
  assert.equal(read.operation, undefined);

  // A consequential call is refused with an operation: nothing is done.
  const exchange = `${ORDERS}/ord_7Hk2/exchanges`;
  const proposed = await api.call("POST", exchange, { session: w.session, token, body: {} });
  assert.equal(proposed.status, 403);
  assert.ok(proposed.operation.operation_id);
  assert.deepEqual(w.plugin.executor.performed, []);
  const { operation_id, revision } = proposed.operation;
  const done = await api.call("POST", exchange, {
    session: w.session,
    token,
    body: {},
    approval: { operation_id, revision },
  });
  assert.equal(done.status, 200);
  assert.ok(done.body.summary.startsWith("Exchanged"));
  assert.deepEqual(w.plugin.executor.performed, [operation_id]);
});

test("partial consent: a write that was not granted is insufficient_scope", async () => {
  const w = await world();
  const token = await signIn(w, ["orders:read"]);
  const error = await refusal(
    new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/exchanges`, { session: w.session, token, body: {} }),
  );
  assert.equal(error.code, "insufficient_scope");
  assert.equal(error.statusCode, 403);
  assert.deepEqual(w.plugin.executor.performed, []);
});

/** An `ApiClient` over a scripted server answering every request with `answer`. */
async function scripted(answer) {
  const w = await world();
  const transport = new SessionFetchClient({ reactor: w.host.reactor, fetch: async () => answer() });
  return { api: new ApiClient({ transport, maxResponseBytes: 64 }), w };
}

const accessToken = () =>
  accessTokenFromResponse(parseTokenResponse({ access_token: "access-secret", token_type: "Bearer", scope: "orders:read" }));

test("refusals: a challenge, a rate limit, a bad operation, invalid and oversized bodies", async () => {
  // Signed out: a 401 challenge with `scope` and no error code (§7).
  let s = await scripted(() => new Response(null, { status: 401, headers: { "WWW-Authenticate": 'Bearer scope="orders:write"' } }));
  let error = await refusal(s.api.call("GET", ORDERS, { session: s.w.session }));
  assert.equal(error.code, "insufficient_scope");
  assert.deepEqual(error.details, { scope: "orders:write" });

  s = await scripted(() => new Response(null, { status: 401, headers: { "WWW-Authenticate": 'Bearer error="invalid_token", resource_metadata="https://mcp.example/prm"' } }));
  error = await refusal(s.api.call("GET", ORDERS, { session: s.w.session, token: accessToken() }));
  assert.equal(error.code, "invalid_token");
  assert.deepEqual(error.details, { resource_metadata: "https://mcp.example/prm" });

  s = await scripted(() => new Response(null, { status: 403, headers: { "WWW-Authenticate": 'Bearer error="insufficient_scope", scope="orders:write"' } }));
  error = await refusal(s.api.call("GET", ORDERS, { session: s.w.session, token: accessToken() }));
  assert.deepEqual([error.code, error.statusCode, error.details], ["insufficient_scope", 403, { scope: "orders:write" }]);

  // A 429 has `Retry-After` and no body (§5.6).
  s = await scripted(() => new Response(null, { status: 429, headers: { "Retry-After": "7" } }));
  error = await refusal(s.api.call("POST", ORDERS, { session: s.w.session, body: {} }));
  assert.deepEqual([error.code, error.statusCode, error.details], ["rate_limited", 429, { retry_after: "7" }]);

  s = await scripted(() => new Response(null, { status: 503, headers: { "Retry-After": "1" } }));
  error = await refusal(s.api.call("POST", ORDERS, { session: s.w.session, body: {} }));
  assert.deepEqual([error.statusCode, error.details], [503, { retry_after: "1" }]);

  s = await scripted(() => new Response('{"error":"approval_required","operation":{}}', { status: 403 }));
  error = await refusal(s.api.call("POST", ORDERS, { session: s.w.session, body: {} }));
  assert.deepEqual([error.code, error.statusCode], ["invalid_operation", 403]);

  s = await scripted(() => new Response("not json", { status: 200 }));
  assert.equal((await refusal(s.api.call("GET", ORDERS, { session: s.w.session }))).code, "invalid_json");

  s = await scripted(() => new Response(JSON.stringify({ padding: "x".repeat(100) }), { status: 200 }));
  assert.equal((await refusal(s.api.call("GET", ORDERS, { session: s.w.session }))).code, "response_too_large");

  s = await scripted(() => new Response("<html>oops</html>", { status: 500 }));
  assert.equal((await refusal(s.api.call("GET", ORDERS, { session: s.w.session }))).code, "invalid_json");

  s = await scripted(() => new Response('{"detail":"no"}', { status: 500 }));
  error = await refusal(s.api.call("GET", ORDERS, { session: s.w.session }));
  assert.deepEqual([error.code, error.statusCode], ["api_request_failed", 500]);

  s = await scripted(() => new Response(null, { status: 204 }));
  const deleted = await s.api.call("DELETE", ORDERS, { session: s.w.session, idempotencyKey: "del-1" });
  assert.deepEqual(deleted, { status: 204, body: undefined, idempotencyKey: "del-1" });
});

test("approval_required comes back as the operation, not an error", async () => {
  const operation = {
    operation_id: "exc_5Rt2",
    revision: "r1",
    summary: "Exchange it.",
    expires_at: "2026-10-10T18:00:00Z",
  };
  const w = await world();
  const fetch = async () => new Response(JSON.stringify({ error: "approval_required", operation }), { status: 403 });
  const api = new ApiClient({ transport: new SessionFetchClient({ reactor: w.host.reactor, fetch }) });
  const answered = await api.call("POST", ORDERS, { session: w.session, body: {}, idempotencyKey: "key-1" });
  assert.equal(answered.status, 403);
  assert.deepEqual(answered.operation, parseOperation(operation));
  assert.equal(answered.idempotencyKey, "key-1");
});

test("the request: JSON in, host-owned credentials, an approval in its header", async () => {
  const w = await world();
  const seen = [];
  const transport = new SessionFetchClient({
    reactor: w.host.reactor,
    fetch: async (url, init) => {
      seen.push({ url: String(url), init });
      return new Response('{"ok":true}', { status: 200 });
    },
  });
  const api = new ApiClient({ transport });
  const approval = { operation_id: "exc_5Rt2", revision: "r1" };
  const token = accessToken();
  const answered = await api.call("POST", ORDERS, { session: w.session, token, body: { note: "hi" }, approval });
  assert.deepEqual(answered.body, { ok: true });
  const headers = new Headers(seen[0].init.headers);
  assert.equal(headers.get("content-type"), "application/json");
  assert.equal(headers.get("accept"), "application/json");
  assert.equal(headers.get("authorization"), "Bearer access-secret");
  assert.ok(headers.get("poppy-session"));
  assert.equal(headers.get("dpop"), null);
  assert.equal(headers.get("poppy-approval"), 'operation_id="exc_5Rt2", revision="r1"');
  assert.equal(seen[0].init.body, '{"note":"hi"}');
  // Signed out: the Session header alone.
  await api.call("GET", ORDERS, { session: w.session });
  const signedOut = new Headers(seen[1].init.headers);
  assert.equal(signedOut.get("authorization"), null);
  assert.ok(signedOut.get("poppy-session"));
  assert.notEqual(signedOut.get("poppy-session"), headers.get("poppy-session"));
  assert.throws(() => new ApiClient({ transport, maxResponseBytes: 0 }), RangeError);
});
