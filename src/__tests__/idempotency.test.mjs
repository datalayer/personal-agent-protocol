/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Idempotency-Key on API writes (guides, *Retries*), from protocol/fixtures: the port of
// personal_agent_protocol/__tests__/test_idempotency.py. `ApiClient` sends a random UUID
// (version 4) on every write, the caller's key on a retry, none on a read; the TypeScript
// reference company runs the fixture's steps.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
  newIdempotencyKey,
} from "../../lib/index.js";
import { CompanyConfig } from "../../lib/server.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const FIXTURE = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures/idempotency-api-writes.json", import.meta.url), "utf8"),
);
const UUID_V4 = new RegExp(FIXTURE.uuid_v4, "u");
const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const URL_ = "https://manzanita.example/api/orders";

async function world(config) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock, ...(config ? { config } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, issuer: metadata.issuer };
  return { clock, fetch, identity, shop, plugin, host, transport, metadata, who };
}

async function session(w) {
  return await new SessionClient({ reactor: w.host.reactor, fetch: w.fetch }).start({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: w.metadata.issuer,
    tokenEndpoint: w.metadata.token_endpoint,
    tenantId: TENANT,
  });
}

async function signIn(w, signedOut) {
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    sessionKey: signedOut.sessionKey,
    organization: { name: "Manzanita", domain: new URL(w.metadata.protected_resources[0]).hostname },
    protectedResources: w.metadata.protected_resources,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
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

/** An `ApiClient` over a scripted server answering every request with `answer`; `sent` records them. */
async function scripted(answer) {
  const w = await world();
  const sent = [];
  const transport = new DpopFetchClient({
    reactor: w.host.reactor,
    fetch: async (input, init) => {
      sent.push(new Request(input, init));
      return answer();
    },
  });
  return { api: new ApiClient({ transport }), sent, w, token: await session(w) };
}

test("every write carries a random UUID v4, and a read none", async () => {
  assert.match(newIdempotencyKey(), UUID_V4);
  assert.equal(
    new CompanyConfig({ name: "x", domain: "x.example", scopes: ["a"], scopeDescriptions: { a: "A" }, operations: false }).idempotencyLifetimeSeconds,
    FIXTURE.default_lifetime_seconds,
  );
  const s = await scripted(() => Response.json({ ok: true }));
  const keys = [];
  for (const method of FIXTURE.write_methods) {
    const answer = await s.api.call(method.toLowerCase(), URL_, { ...s.w.who, token: s.token, body: {} });
    keys.push(s.sent.at(-1).headers.get("Idempotency-Key"));
    assert.match(keys.at(-1), UUID_V4);
    assert.equal(answer.idempotencyKey, keys.at(-1));
  }
  assert.equal(new Set(keys).size, keys.length);
  const read = await s.api.call("GET", URL_, { ...s.w.who, token: s.token });
  assert.equal(s.sent.at(-1).headers.get("Idempotency-Key"), null);
  assert.equal(read.idempotencyKey, undefined);
});

test("a retry sends the caller's key, and a refusal carries it", async () => {
  const s = await scripted(() => Response.json({ error: "temporarily_unavailable" }, { status: 503 }));
  const first = await refusal(s.api.call("POST", URL_, { ...s.w.who, token: s.token, body: { size: "M" } }));
  assert.match(first.idempotencyKey, UUID_V4);
  assert.equal(s.sent.at(-1).headers.get("Idempotency-Key"), first.idempotencyKey);
  const again = await refusal(
    s.api.call("POST", URL_, { ...s.w.who, token: s.token, body: { size: "M" }, idempotencyKey: first.idempotencyKey }),
  );
  assert.equal(again.idempotencyKey, first.idempotencyKey);
  assert.equal(s.sent.at(-1).headers.get("Idempotency-Key"), first.idempotencyKey);
  assert.equal(s.sent.length, 2);
});

test("a bad key, or a key on a read, is the caller's mistake", async () => {
  const s = await scripted(() => Response.json({}));
  for (const bad of FIXTURE.invalid_keys) {
    await assert.rejects(
      s.api.call("POST", URL_, { ...s.w.who, token: s.token, body: {}, idempotencyKey: bad }),
      RangeError,
    );
  }
  await assert.rejects(
    s.api.call("GET", URL_, { ...s.w.who, token: s.token, idempotencyKey: newIdempotencyKey() }),
    RangeError,
  );
  assert.equal(s.sent.length, 0);
});

test("the reference company keeps each key per Session for its lifetime", async () => {
  const w = await world({ idempotencyLifetimeSeconds: FIXTURE.lifetime_seconds });
  const tokens = {};
  for (const name of ["first", "second"]) tokens[name] = await signIn(w, await session(w));
  assert.notEqual(tokens.first.sessionKey, tokens.second.sessionKey);
  const api = new ApiClient({ transport: w.transport });
  const answers = {};
  for (const step of FIXTURE.steps) {
    if (step.confirm !== undefined) {
      const operation = answers[step.confirm].operation;
      await new OperationsClient({ reactor: w.host.reactor, transport: w.transport }).confirm(
        w.shop.config.operationsEndpoint,
        operation,
        { ...w.who, token: tokens.first, approval: await approve(operation) },
      );
      continue;
    }
    w.clock.advance(step.advance_seconds ?? 0);
    const call = api.call("POST", `https://manzanita.example${step.path}`, {
      ...w.who,
      token: tokens[step.session ?? "first"],
      body: step.body,
      idempotencyKey: step.key,
    });
    const expect = step.expect;
    if (expect.error !== undefined) {
      const error = await refusal(call);
      assert.deepEqual([error.statusCode, error.code], [expect.status, expect.error], step.name);
      assert.equal(error.idempotencyKey, step.key);
      continue;
    }
    const answer = await call;
    assert.equal(answer.status, expect.status, step.name);
    assert.equal(answer.idempotencyKey, step.key);
    if (expect.answer === "first") {
      assert.deepEqual(answer.operation, answers.first.operation, step.name);
      assert.equal(answer.operation.state, "proposed");
    } else {
      assert.ok(answer.operation, step.name);
      assert.ok(
        answers.first === undefined || answer.operation.operation_id !== answers.first.operation.operation_id,
        step.name,
      );
    }
    answers[step.name] = answer;
  }
  // The first exchange was performed once, whatever the retries.
  assert.deepEqual(w.plugin.executor.performed, [answers.first.operation.operation_id]);
});

test("a bad key is invalid_request, and a refusal is not remembered", async () => {
  const w = await world();
  const signedOut = await session(w);
  const exchanges = `${URL_}/ord_7Hk2/exchanges`;
  for (const bad of FIXTURE.invalid_keys.filter((key) => /^[\x00-\x7f]*$/u.test(key))) {
    const response = await w.transport.request("POST", exchanges, {
      ...w.who,
      token: signedOut,
      headers: { "Idempotency-Key": bad, "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "invalid_request");
  }
  const api = new ApiClient({ transport: w.transport });
  const key = newIdempotencyKey();
  const refused = await refusal(
    api.call("POST", exchanges, { ...w.who, token: signedOut, body: {}, idempotencyKey: key }),
  );
  assert.equal(refused.code, "insufficient_scope");
  // Signed in, the same key is a new request: the refusal was not kept.
  const token = await signIn(w, signedOut);
  const answer = await api.call("POST", exchanges, { ...w.who, token, body: {}, idempotencyKey: key });
  assert.equal(answer.status, 202);
  assert.ok(answer.operation);
});
