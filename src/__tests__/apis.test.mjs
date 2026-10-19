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
  DpopFetchClient,
  OperationsClient,
  SessionClient,
  approve,
  discoverCompany,
  openapiUrl,
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
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: metadata.issuer };
  const session = await new SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: metadata.issuer,
    tokenEndpoint: metadata.token_endpoint,
    tenantId: TENANT,
  });
  return { clock, fetch, identity, shop, plugin, host, transport, company, metadata, who, session };
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
    pairwiseUserId: PAIRWISE,
    sessionId: w.session.sessionId,
    organization: { name: "Manzanita", domain: w.metadata.poppy_domains[0] },
    poppyDomains: w.metadata.poppy_domains,
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

test("signed out, then signed in: a read and a proposed exchange", async () => {
  const w = await world();
  const api = new ApiClient({ transport: w.transport });
  assert.equal(openapiUrl(w.company.document), "https://manzanita.example/api/openapi.json");

  // Signed out: the API says which scope signing in would give.
  const signedOut = await refusal(api.call("GET", ORDERS, { ...w.who, token: w.session }));
  assert.equal(signedOut.code, "sign_in_required");
  assert.deepEqual(signedOut.details, { scope: "orders:read" });

  const token = await signIn(w);
  const read = await api.call("GET", ORDERS, { ...w.who, token });
  assert.equal(read.status, 200);
  assert.deepEqual(read.body, { orders: [{ order_id: "ord_7Hk2", item: "Ridge Jacket, size M", status: "delivered" }] });
  assert.equal(read.operation, undefined);

  // A consequential call answers 202 with an operation: proposed, not performed.
  const proposed = await api.call("POST", `${ORDERS}/ord_7Hk2/exchanges`, { ...w.who, token, body: {} });
  assert.equal(proposed.status, 202);
  assert.equal(proposed.operation.state, "proposed");
  assert.deepEqual(w.plugin.executor.performed, []);
  const done = await new OperationsClient({ reactor: w.host.reactor, transport: w.transport }).confirm(
    w.shop.config.operationsEndpoint,
    proposed.operation,
    { ...w.who, token, approval: await approve(proposed.operation) },
  );
  assert.equal(done.operation.state, "succeeded");
  assert.deepEqual(w.plugin.executor.performed, [proposed.operation.operation_id]);
});

test("partial consent: a write that was not granted is insufficient_scope", async () => {
  const w = await world();
  const token = await signIn(w, ["orders:read"]);
  const error = await refusal(new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/exchanges`, { ...w.who, token, body: {} }));
  assert.equal(error.code, "insufficient_scope");
  assert.equal(error.statusCode, 403);
});

/** An `ApiClient` over a scripted server answering every request with `answer`. */
async function scripted(answer) {
  const w = await world();
  const transport = new DpopFetchClient({ reactor: w.host.reactor, fetch: async () => answer() });
  return { api: new ApiClient({ transport, maxResponseBytes: 64 }), w };
}

test("refusals: a challenge only, a rate limit, a bad 202, invalid and oversized bodies", async () => {
  let s = await scripted(() => new Response(null, { status: 401, headers: { "WWW-Authenticate": 'DPoP error="insufficient_scope", scope="orders:write"' } }));
  let error = await refusal(s.api.call("GET", ORDERS, { ...s.w.who, token: s.w.session }));
  assert.equal(error.code, "insufficient_scope");
  assert.deepEqual(error.details, { scope: "orders:write" });

  s = await scripted(() => new Response('{"error":"rate_limited"}', { status: 429, headers: { "Retry-After": "7" } }));
  error = await refusal(s.api.call("POST", ORDERS, { ...s.w.who, token: s.w.session, body: {} }));
  assert.deepEqual([error.code, error.statusCode, error.details], ["rate_limited", 429, { retry_after: "7" }]);

  s = await scripted(() => new Response('{"operation":{"operation_id":"op_1"}}', { status: 202 }));
  error = await refusal(s.api.call("POST", ORDERS, { ...s.w.who, token: s.w.session, body: {} }));
  assert.deepEqual([error.code, error.statusCode], ["invalid_operation", 202]);

  s = await scripted(() => new Response("not json", { status: 200 }));
  assert.equal((await refusal(s.api.call("GET", ORDERS, { ...s.w.who, token: s.w.session }))).code, "invalid_json");

  s = await scripted(() => new Response(JSON.stringify({ padding: "x".repeat(100) }), { status: 200 }));
  assert.equal((await refusal(s.api.call("GET", ORDERS, { ...s.w.who, token: s.w.session }))).code, "response_too_large");

  s = await scripted(() => new Response("<html>oops</html>", { status: 500 }));
  assert.equal((await refusal(s.api.call("GET", ORDERS, { ...s.w.who, token: s.w.session }))).code, "invalid_json");

  s = await scripted(() => new Response('{"detail":"no"}', { status: 500 }));
  error = await refusal(s.api.call("GET", ORDERS, { ...s.w.who, token: s.w.session }));
  assert.deepEqual([error.code, error.statusCode], ["api_request_failed", 500]);

  s = await scripted(() => new Response(null, { status: 204 }));
  assert.deepEqual(await s.api.call("DELETE", ORDERS, { ...s.w.who, token: s.w.session }), { status: 204, body: undefined });
});

test("the request: JSON in, host-owned credentials, no Bearer token", async () => {
  const w = await world();
  const seen = [];
  const transport = new DpopFetchClient({
    reactor: w.host.reactor,
    fetch: async (url, init) => {
      seen.push({ url: String(url), init });
      return new Response('{"ok":true}', { status: 200 });
    },
  });
  const api = new ApiClient({ transport });
  assert.deepEqual((await api.call("POST", ORDERS, { ...w.who, token: w.session, body: { note: "hi" } })).body, { ok: true });
  const headers = new Headers(seen[0].init.headers);
  assert.equal(headers.get("content-type"), "application/json");
  assert.equal(headers.get("accept"), "application/json");
  assert.match(headers.get("authorization"), /^DPoP /);
  assert.ok(headers.get("dpop"));
  assert.equal(seen[0].init.body, '{"note":"hi"}');
  assert.throws(() => new ApiClient({ transport, maxResponseBytes: 0 }), RangeError);
});
