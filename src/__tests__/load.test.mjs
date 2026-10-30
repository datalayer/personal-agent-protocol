/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Bounded load checks, the TypeScript side of personal_agent_protocol/__tests__/test_load.py:
// concurrent replays of one Session JWT, one client assertion and one token request, the
// replay-cache and store kits at concurrency, the memory replay cache bounded by live
// identifiers, and shared budgets under concurrent callers. Sized by PAP_LOAD_SIZE (64 by
// default).
import assert from "node:assert/strict";
import test from "node:test";

import {
  DelegatedSessionSigner,
  DeviceSignInClient,
  InMemoryDelegatedKeys,
  RefreshTokenClient,
  SessionError,
  SharedRateLimitBudget,
  TransportError,
  discoverCompany,
  parseClientMetadata,
  parseJsonWebKeySet,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import {
  MemoryCompanyStore,
  MemoryReplayCache,
  checkReplayCache,
  checkStore,
  verifyAssertion,
  verifySessionJwt,
} from "../../lib/server.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const SIZE = Number(process.env.PAP_LOAD_SIZE ?? 64);
const NOW = new Date("2026-10-11T09:00:00Z");
const ISSUER = "https://manzanita.example";
const ORDERS = "https://manzanita.example/api/orders";
const TOKEN = "https://manzanita.example/oauth/token";
const TENANT = "atlas-demo";

function report(name, numbers) {
  const shown = Object.entries(numbers).map(([key, value]) => `${key}=${value}`).join(", ");
  process.stdout.write(`[load] ${name}: size=${SIZE}, ${shown}\n`);
}

const elapsed = (start) => `${(performance.now() - start).toFixed(1)}ms`;

test("concurrent verifications of one Session JWT and one assertion accept exactly one; the kits pass at concurrency", async () => {
  const clock = { now: () => NOW };
  const atlas = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  const signer = new DelegatedSessionSigner({ custody: new InMemoryDelegatedKeys(), signer: atlas.signer, now: clock.now });
  const sessionJwt = await signer.sign({
    method: "GET",
    url: ORDERS,
    tenantId: TENANT,
    issuer: ISSUER,
    clientId: atlas.clientId,
    sid: "s".repeat(22),
    sub: "usr_ada_at_manzanita_000000",
  });
  const resolved = [parseClientMetadata(atlas.metadata), parseJsonWebKeySet(atlas.jwks)];
  const cache = new MemoryReplayCache({ clock });
  let start = performance.now();
  const sessions = await Promise.allSettled(
    Array.from({ length: SIZE }, () =>
      verifySessionJwt(sessionJwt.reveal(), {
        issuer: ISSUER,
        method: "GET",
        url: ORDERS,
        resolve: async () => resolved,
        replayCache: cache,
        now: NOW,
      }),
    ),
  );
  const proofTime = elapsed(start);
  assert.equal(sessions.filter((outcome) => outcome.status === "fulfilled").length, 1);
  const refused = sessions.filter((outcome) => outcome.status === "rejected");
  assert.equal(refused.length, SIZE - 1);
  assert.ok(refused.every((outcome) => outcome.reason instanceof SessionError && outcome.reason.code === "invalid_session"));

  const issued = Math.floor(NOW.getTime() / 1000);
  const assertion = await atlas.signer.sign(
    { iss: atlas.clientId, sub: atlas.clientId, aud: ISSUER, iat: issued, exp: issued + 60, jti: "jti_one_assertion_many_callers" },
    { purpose: "client_assertion" },
  );
  start = performance.now();
  const assertions = await Promise.allSettled(
    Array.from({ length: SIZE }, () =>
      verifyAssertion(assertion, {
        keys: parseJsonWebKeySet(atlas.jwks),
        issuer: atlas.clientId,
        audience: ISSUER,
        subject: atlas.clientId,
        replayCache: cache,
        now: NOW,
      }),
    ),
  );
  const assertionTime = elapsed(start);
  assert.equal(assertions.filter((outcome) => outcome.status === "fulfilled").length, 1);
  assert.ok(assertions.filter((outcome) => outcome.status === "rejected").every((outcome) => outcome.reason instanceof SessionError));

  start = performance.now();
  await checkReplayCache(() => new MemoryReplayCache({ clock }), { now: clock.now, concurrency: SIZE });
  await checkStore(() => new MemoryCompanyStore({ clock }), { now: clock.now, concurrency: SIZE });
  report("replay", {
    proof: `1 of ${SIZE} accepted in ${proofTime}`,
    assertion: `1 of ${SIZE} accepted in ${assertionTime}`,
    kits: elapsed(start),
  });
});

test("one token request replayed concurrently is accepted once", async () => {
  const clock = new MutableClock();
  const sites = {};
  const network = inProcessFetch(sites);
  const atlas = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = atlas.documents;
  const { service } = manzanita({ fetch: network, clock });
  sites["manzanita.example"] = service;
  // The first refresh is taken off the wire and never reaches the company.
  let captured;
  const fetch = async (input, init = {}) => {
    if (String(input) === TOKEN && captured === undefined && String(init.body).includes("grant_type=refresh_token")) {
      captured = String(init.body);
      return new Response(null, { status: 503 });
    }
    return network(input, init);
  };
  const host = await agentHost({ identity: atlas, fetch, clock });
  const { oauthMetadata: metadata, document } = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const device = new DeviceSignInClient({ reactor: host.reactor, fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    issuer: metadata.issuer,
    clientId: atlas.clientId,
    scopes: ["orders:read"],
    tenantId: TENANT,
    organization: document.organization,
    protectedResources: metadata.protected_resources,
  });
  await service.approveDevice(started.userCode, { accountId: "acct_ada" });
  clock.advance(started.pollInterval);
  const { refreshTokenReference } = await device.poll(started.reference);
  const context = { tokenEndpoint: metadata.token_endpoint, issuer: metadata.issuer, clientId: atlas.clientId, tenantId: TENANT };
  await assert.rejects(new RefreshTokenClient({ reactor: host.reactor, fetch }).refresh(refreshTokenReference, { context }));
  assert.ok(captured);

  const start = performance.now();
  const answers = await Promise.all(
    Array.from({ length: SIZE }, () =>
      network(TOKEN, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" }, body: captured }),
    ),
  );
  const accepted = answers.filter((answer) => answer.status === 200);
  assert.equal(accepted.length, 1);
  const errors = await Promise.all(answers.filter((answer) => answer.status !== 200).map(async (answer) => (await answer.json()).error));
  assert.equal(errors.length, SIZE - 1);
  assert.ok(errors.every((error) => ["invalid_grant", "invalid_client"].includes(error)), String([...new Set(errors)]));
  report("token request replay", { accepted: 1, refused: errors.length, time: elapsed(start) });
});

test("the memory replay cache holds only live identifiers", async () => {
  let now = NOW.getTime();
  const cache = new MemoryReplayCache({ clock: { now: () => new Date(now) } });
  const rounds = 20;
  const perRound = Math.max(SIZE, 1024);
  let largest = 0;
  for (let round = 0; round < rounds; round += 1) {
    const expiresAt = new Date(now + 60_000);
    for (let n = 0; n < perRound; n += 1) assert.ok(await cache.markOnce(`proof:${round}:${n}`, { expiresAt }));
    largest = Math.max(largest, cache.size);
    now += 61_000;
  }
  assert.ok(largest <= 2 * perRound + 1, `largest ${largest}`);
  const expiresAt = new Date(now + 60_000);
  assert.ok(await cache.markOnce("proof:live", { expiresAt }));
  assert.ok(!(await cache.markOnce("proof:live", { expiresAt })));
  report("replay cache", { identifiers: rounds * perRound, largest });
});

test("shared budgets never exceed rate and burst, and refuse turns beyond maxWait at once", async () => {
  const rate = 2000;
  const burst = 8;
  const budget = new SharedRateLimitBudget({ rate, burst, maxWait: 30 });
  const companies = ["a", "b", "c", "d"].map((name) => `https://shop-${name}.example:443`);
  const admitted = new Map(companies.map((company) => [company, []]));
  const asked = new Map();
  const start = performance.now();
  await Promise.all(
    Array.from({ length: SIZE * companies.length }, async (_, n) => {
      const company = companies[(n * 7) % companies.length];
      if (!asked.has(company)) asked.set(company, performance.now() / 1000);
      await budget.acquire(company);
      admitted.get(company).push(performance.now() / 1000);
    }),
  );
  const time = elapsed(start);
  for (const [company, times] of admitted) {
    assert.equal(times.length, SIZE);
    times.sort((a, b) => a - b);
    // The j-th request never goes before the budget, which started when the first asked,
    // had refilled for it.
    for (let j = burst; j < times.length; j += 1) {
      assert.ok(times[j] - asked.get(company) >= (j - burst + 1) / rate - 0.001, `request ${j} went early`);
    }
  }

  // A pause, then more callers than maxWait can serve: the rest are refused at once.
  const paced = new SharedRateLimitBudget({ rate: 1000, burst: 4, maxWait: 0.05 });
  await paced.defer("https://shop.example:443", 0.03);
  const times = [];
  const outcomes = await Promise.allSettled(
    Array.from({ length: SIZE + 64 }, () => {
      times.push(performance.now() / 1000);
      return paced.acquire("https://shop.example:443");
    }),
  );
  const ok = outcomes.filter((outcome) => outcome.status === "fulfilled").length;
  const refused = outcomes.filter((outcome) => outcome.status === "rejected");
  // The burst at the pause's end, then what the rate allows until maxWait (the last
  // callers ask a little later, so their maxWait reaches a little further).
  const spread = Math.floor((Math.max(...times) - Math.min(...times)) * 1000);
  assert.ok(ok >= 4 + 20 - 1 && ok <= 4 + 20 + 1 + spread, `admitted ${ok}, spread ${spread}`);
  assert.ok(refused.every((outcome) => outcome.reason instanceof TransportError && outcome.reason.code === "rate_limited"));
  report("rate budgets", { companies: companies.length, requests: SIZE * companies.length, time, pause: `${ok} admitted, ${refused.length} refused` });
});
