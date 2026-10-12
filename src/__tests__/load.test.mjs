/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Bounded load checks, the TypeScript side of personal_agent_protocol/__tests__/test_load.py:
// concurrent replays of one DPoP proof, the replay-cache and store kits at concurrency, the
// memory replay cache bounded by live identifiers, and shared budgets under concurrent
// callers. Sized by PAP_LOAD_SIZE (64 by default).
import assert from "node:assert/strict";
import test from "node:test";

import { exportJWK, generateKeyPair } from "jose";

import { JoseDpopProofProvider, ProofError, SharedRateLimitBudget, TransportError } from "../../lib/index.js";
import {
  MemoryCompanyStore,
  MemoryReplayCache,
  checkReplayCache,
  checkStore,
  verifyDpopProof,
} from "../../lib/server.js";

const SIZE = Number(process.env.PAP_LOAD_SIZE ?? 64);
const NOW = new Date("2026-10-11T09:00:00Z");

function report(name, numbers) {
  const shown = Object.entries(numbers).map(([key, value]) => `${key}=${value}`).join(", ");
  process.stdout.write(`[load] ${name}: size=${SIZE}, ${shown}\n`);
}

test("concurrent verifications of one DPoP proof accept exactly one; the kits pass at concurrency", async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(keys.publicKey);
  const provider = new JoseDpopProofProvider({ resolveKey: async () => ({ privateKey: keys.privateKey, publicJwk }), now: () => NOW });
  const url = "https://manzanita.example/oauth/token";
  const proof = await provider.create({ method: "POST", url, tenantId: "t", subject: "usr_one", issuer: "https://manzanita.example" });
  const clock = { now: () => NOW };
  const cache = new MemoryReplayCache({ clock });
  const start = performance.now();
  const outcomes = await Promise.allSettled(
    Array.from({ length: SIZE }, () => verifyDpopProof(proof, { method: "POST", url, replayCache: cache, now: NOW })),
  );
  const accepted = outcomes.filter((outcome) => outcome.status === "fulfilled");
  const refused = outcomes.filter((outcome) => outcome.status === "rejected");
  assert.equal(accepted.length, 1);
  assert.ok(refused.every((outcome) => outcome.reason instanceof ProofError && outcome.reason.code === "invalid_dpop_proof"));
  const proofTime = `${(performance.now() - start).toFixed(1)}ms`;
  await checkReplayCache(() => new MemoryReplayCache({ clock }), { now: clock.now, concurrency: SIZE });
  await checkStore(() => new MemoryCompanyStore({ clock }), { now: clock.now, concurrency: SIZE });
  report("replay", { proof: `1 of ${SIZE} accepted in ${proofTime}` });
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
  const elapsed = `${(performance.now() - start).toFixed(1)}ms`;
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
  report("rate budgets", { companies: companies.length, requests: SIZE * companies.length, time: elapsed, pause: `${ok} admitted, ${refused.length} refused` });
});
