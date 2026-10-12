/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  Clocks,
  DpopFetchClient,
  DpopProofProviders,
  InMemoryStandingPermissionStore,
  OperationsClient,
  SecretValue,
  StandingPermissionStores,
  approve,
  buildPapReactor,
  operationsEndpoint,
  parseClientMetadata,
  parseDiscoveryDocument,
  parseOperation,
} from "../../lib/index.js";

const fixtures = new URL("../../protocol/fixtures/", import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, fixtures), "utf8"));
const endpoint = "https://api.shop.example/poppy/operations";
const now = new Date("2026-10-10T12:00:00Z");
const token = { accessToken: new SecretValue("s"), tokenType: "DPoP", expiresIn: 300, scopes: [], sessionId: "ses_1", signedIn: true };
const who = { token, tenantId: "t", pairwiseUserId: "usr_1", issuer: "https://auth.shop.example" };
const standing = ["https://auth.shop.example", "usr_1", "orders.exchange"];

const proposed = (changes = {}) => parseOperation({ ...fixture("operation-valid.json"), ...changes });
const confirmed = (operation, approvedBy = "user") => ({
  ...operation,
  state: "succeeded",
  confirmation: { revision: operation.revision, approved_by: approvedBy, confirmed_at: "2026-10-10T12:00:05Z" },
  result: { summary: "Exchanged the jacket; USD 70.00 charged." },
});
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const permission = (changes = {}) => ({
  reference: "perm_exchanges",
  company: "https://auth.shop.example",
  account: "usr_1",
  action: "orders.exchange",
  limits: [
    { path: "price_difference.amount", maximum: "100.00" },
    { path: "price_difference.currency", allowed: ["USD"] },
  ],
  expiresAt: new Date("2026-11-10T00:00:00Z"),
  usesRemaining: 1,
  ...changes,
});

function arrange(company, store) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push(`${init.method} ${new URL(String(url)).pathname}`);
    return company(String(url), init);
  };
  const reactor = buildPapReactor({ fetch }, [
    {
      name: "@tests/pap-operations",
      contributes: [
        { point: DpopProofProviders, value: { create: async () => new SecretValue("proof") }, options: { id: "p" } },
        { point: Clocks, value: { now: () => now }, options: { id: "fixed" } },
        ...(store ? [{ point: StandingPermissionStores, value: store, options: { id: "memory" } }] : []),
      ],
    },
  ]);
  return { calls, client: new OperationsClient({ reactor, transport: new DpopFetchClient({ reactor, fetch }) }) };
}

test("operations are used only when both sides list version 1", () => {
  const document = parseDiscoveryDocument({ ...fixture("discovery-valid.json"), extensions: { operations: { version: "1", endpoint } } });
  const metadata = fixture("client-metadata-valid.json");
  assert.equal(operationsEndpoint(document, parseClientMetadata({ ...metadata, extensions: { operations: { version: "1" } } })), endpoint);
  assert.equal(operationsEndpoint(document, parseClientMetadata({ ...metadata, extensions: {} })), undefined);
  assert.equal(operationsEndpoint(document, parseClientMetadata({ ...metadata, extensions: { operations: { version: "2" } } })), undefined);
});

test("the user approves one revision; another revision is refused locally", async () => {
  const operation = proposed();
  const bodies = [];
  const { client } = arrange((_, init) => { bodies.push(JSON.parse(init.body)); return json(200, confirmed(operation)); });
  const outcome = await client.confirm(endpoint, operation, { approval: await approve(operation), ...who });
  assert.deepEqual(bodies, [{ revision: 1, approved_by: "user" }]);
  assert.equal(outcome.operation.state, "succeeded");
  const newer = proposed({ revision: 2, summary: "Exchange for USD 90.00 more." });
  await assert.rejects(client.confirm(endpoint, newer, { approval: await approve(operation), ...who }), (e) => e.code === "approval_mismatch");
});

test("terms_changed returns the new revision and what changed", async () => {
  const operation = proposed();
  const newer = proposed({ revision: 2, terms: { order_id: "ord_7Hk2", price_difference: { amount: "85.00", currency: "USD" } } });
  const { client } = arrange(() => json(409, { error: "terms_changed", operation: newer }));
  const outcome = await client.confirm(endpoint, operation, { approval: await approve(operation), ...who });
  assert.equal(outcome.status, "terms_changed");
  assert.deepEqual(outcome.changed, ["price_difference.amount"]);
});

test("a standing permission covers every term and spends one use; a refusal gives it back", async () => {
  const operation = proposed({ user_approval_required: false });
  const store = new InMemoryStandingPermissionStore([permission()]);
  const ok = arrange(() => json(200, confirmed(operation, "standing_permission")), store);
  assert.equal((await ok.client.confirm(endpoint, operation, { standing, ...who })).status, "confirmed");
  assert.equal(store.permissions.get("perm_exchanges").usesRemaining, 0);

  const again = new InMemoryStandingPermissionStore([permission()]);
  const refused = arrange(() => json(403, { error: "user_approval_required" }), again);
  assert.equal((await refused.client.confirm(endpoint, operation, { standing, ...who })).status, "approval_required");
  assert.equal(again.permissions.get("perm_exchanges").usesRemaining, 1);
});

for (const [label, opChanges, permChanges] of [
  ["over the maximum", { terms: { order_id: "o", price_difference: { amount: "170.00", currency: "USD" } } }, {}],
  ["another currency", { terms: { order_id: "o", price_difference: { amount: "70.00", currency: "EUR" } } }, {}],
  ["a missing term", { terms: { order_id: "o" } }, {}],
  ["another action", {}, { action: "orders.cancel" }],
  ["expired", {}, { expiresAt: now }],
  ["no uses left", {}, { usesRemaining: 0 }],
]) {
  test(`a standing permission does not cover ${label}`, async () => {
    const operation = proposed({ user_approval_required: false, ...opChanges });
    const { client } = arrange(() => json(500, {}), new InMemoryStandingPermissionStore([permission(permChanges)]));
    await assert.rejects(client.confirm(endpoint, operation, { standing, ...who }), (e) => e.code === "no_standing_permission");
  });
}

test("a revision needing the user is never confirmed by a standing permission", async () => {
  const { client } = arrange(() => json(500, {}), new InMemoryStandingPermissionStore([permission()]));
  await assert.rejects(client.confirm(endpoint, proposed(), { standing, ...who }), (e) => e.code === "user_approval_required");
});

test("a lost answer is read back by the same ID, never assumed failed", async () => {
  const operation = proposed();
  const { client, calls } = arrange((_, init) => {
    if (init.method === "POST") throw new TypeError("connection reset");
    return json(200, { ...confirmed(operation), state: "in_progress", result: null });
  });
  const outcome = await client.confirm(endpoint, operation, { approval: await approve(operation), ...who });
  assert.deepEqual(calls, ["POST /poppy/operations/exc_5Rt2/confirm", "GET /poppy/operations/exc_5Rt2"]);
  assert.equal(outcome.operation.state, "in_progress");
});

test("cancel, and extension_required names the extension", async () => {
  const operation = proposed();
  const { client } = arrange((url) =>
    url.endsWith("/cancel")
      ? json(200, { ...operation, state: "cancelled", result: { summary: "Nothing was changed." } })
      : json(403, { error: "extension_required", extension: "operations" }),
  );
  assert.equal((await client.cancel(endpoint, "exc_5Rt2", who)).result.summary, "Nothing was changed.");
  await assert.rejects(client.read(endpoint, "exc_5Rt2", who), (e) => e.code === "extension_required" && e.details.extension === "operations");
});

test("a late confirm of a cancelled operation is not_confirmed, as in Python", async () => {
  const operation = proposed();
  const cancelled = { ...operation, state: "cancelled", result: { summary: "Cancelled; nothing was changed." } };
  const { client } = arrange(() => json(200, cancelled));
  const outcome = await client.confirm(endpoint, operation, { approval: await approve(operation), ...who });
  assert.equal(outcome.status, "not_confirmed");
  assert.equal(outcome.operation.state, "cancelled");
});
