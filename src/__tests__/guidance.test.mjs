// Guide-level behaviour: bounded metadata caching, overlapping JWKS, retries, shared budgets
// (the TypeScript side of personal_agent_protocol/__tests__/test_guidance.py).
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AgentIdentityClient,
  Clocks,
  DEFAULT_CACHE_BOUNDS,
  DpopFetchClient,
  DpopProofProviders,
  RateLimitBudgets,
  RetryPolicies,
  RetryPolicy,
  SecretValue,
  SharedRateLimitBudget,
  TransportError,
  buildPapReactor,
  cacheLifetime,
  discoverCompany,
  parseRetryAfter,
} from "../../lib/index.js";
import { IdentityClientResolver } from "../../lib/server.js";

const NOW = new Date("2026-10-11T09:00:00Z");
const clientId = "https://agent.example/agent.json";
const fixture = async (name) =>
  JSON.parse(await readFile(new URL(`../../protocol/fixtures/${name}`, import.meta.url), "utf8"));
const json = (body, headers = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", ...headers },
  });

function mutableClock(start = NOW) {
  let value = start.getTime();
  return { now: () => new Date(value), advance: (seconds) => (value += seconds * 1000) };
}

function host(clock, extra = []) {
  const proofs = [];
  return {
    proofs,
    plugin: {
      name: "@tests/guidance",
      contributes: [
        { point: Clocks, value: clock, options: { id: "clock", order: 10 } },
        {
          point: DpopProofProviders,
          value: {
            async create(request) {
              proofs.push(request);
              return new SecretValue(`proof-${proofs.length}`);
            },
          },
          options: { id: "proofs" },
        },
        ...extra.map(([point, value]) => ({ point, value, options: { id: "test", order: 10 } })),
      ],
    },
  };
}

test("cache lifetime follows Cache-Control within a minute and a day", () => {
  const cases = [
    [undefined, 60],
    ["max-age=3600", 3600],
    ["public, max-age=10", 60],
    ["max-age=172800", 86400],
    ["no-store", undefined],
    ["no-cache", undefined],
    ["max-age=0", undefined],
    ["max-age=soon", undefined],
    ["public", 60],
  ];
  for (const [header, seconds] of cases) {
    assert.equal(cacheLifetime(header, DEFAULT_CACHE_BOUNDS), seconds, String(header));
  }
});

test("discovery and OAuth metadata are cached until they expire", async () => {
  const discovery = await fixture("discovery-valid.json");
  const oauth = await fixture("oauth-metadata-valid.json");
  const fetched = [];
  const fetch = async (input) => {
    const host = new URL(input).hostname;
    fetched.push(host);
    return host === "example.com"
      ? json(discovery, { "cache-control": "max-age=300" })
      : json(oauth, { "cache-control": "max-age=30" });
  };
  const clock = mutableClock();
  const reactor = buildPapReactor({ fetch }, [host(clock).plugin]);
  await discoverCompany("example.com", { reactor });
  await discoverCompany("example.com", { reactor });
  assert.deepEqual(fetched, ["example.com", "auth.example.com"]);
  clock.advance(61);
  await discoverCompany("example.com", { reactor });
  assert.deepEqual(fetched, ["example.com", "auth.example.com", "auth.example.com"]);
  clock.advance(300);
  await discoverCompany("example.com", { reactor });
  assert.deepEqual(fetched.slice(-2), ["example.com", "auth.example.com"]);
  reactor.stop();
});

test("no-store client metadata is fetched every time", async () => {
  const metadata = await fixture("client-metadata-valid.json");
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return json(metadata, { "cache-control": "no-store" });
  };
  const reactor = buildPapReactor({ fetch }, [host(mutableClock()).plugin]);
  const client = new AgentIdentityClient({ reactor });
  await client.fetchMetadata(clientId);
  await client.fetchMetadata(clientId);
  assert.equal(calls, 2);
  reactor.stop();
});

test("an unknown kid refetches the overlapping JWKS, rate-limited", async () => {
  const metadata = await fixture("client-metadata-valid.json");
  const current = await fixture("jwks-valid.json");
  const rotated = { keys: [...current.keys, { ...current.keys[0], kid: "agent-signing-2026-11" }] };
  const sets = [current];
  const fetched = [];
  const fetch = async (input) => {
    const path = new URL(input).pathname;
    fetched.push(path);
    return path === "/agent.json"
      ? json(metadata)
      : json(sets.at(-1), { "cache-control": "max-age=3600" });
  };
  const clock = mutableClock();
  const reactor = buildPapReactor({ fetch }, [host(clock).plugin]);
  const resolver = new IdentityClientResolver(new AgentIdentityClient({ reactor }));
  let [, keys] = await resolver.resolve(clientId, { kid: "agent-signing-2026-10" });
  assert.deepEqual(keys.keys.map((key) => key.kid), ["agent-signing-2026-10"]);
  sets.push(rotated);
  [, keys] = await resolver.resolve(clientId, { kid: "agent-signing-2026-11" });
  assert.deepEqual(keys.keys.map((key) => key.kid), ["agent-signing-2026-10", "agent-signing-2026-11"]);
  await resolver.resolve(clientId, { kid: "agent-signing-2026-10" });
  for (const forged of ["forged-1", "forged-2", "forged-3"]) {
    await resolver.resolve(clientId, { kid: forged });
  }
  assert.equal(fetched.filter((path) => path === "/jwks.json").length, 2);
  clock.advance(61);
  await resolver.resolve(clientId, { kid: "forged-4" });
  assert.equal(fetched.filter((path) => path === "/jwks.json").length, 3);
  reactor.stop();
});

test("the retry policy honours Retry-After, backs off with jitter, and caps", () => {
  const policy = new RetryPolicy({ maxAttempts: 5, baseDelay: 1, maxDelay: 4, maxRetryAfter: 10 });
  assert.equal(policy.delay(1, 3, 0), 3);
  assert.ok(Math.abs(policy.delay(1, 3, 0.999) - 3.999) < 1e-9);
  assert.equal(policy.delay(1, 30, 0.5), undefined);
  for (const [attempts, backoff] of [[1, 1], [2, 2], [3, 4], [4, 4]]) {
    assert.equal(policy.delay(attempts, undefined, 0), backoff / 2);
    assert.ok(Math.abs(policy.delay(attempts, undefined, 0.999999) - backoff) < 1e-5);
  }
  assert.equal(policy.delay(5, undefined, 0.5), undefined);
  assert.equal(policy.delay(5, 1, 0.5), undefined);
});

test("Retry-After parses seconds and HTTP dates", () => {
  assert.equal(parseRetryAfter("120", NOW), 120);
  assert.equal(parseRetryAfter("Sun, 11 Oct 2026 09:00:30 GMT", NOW), 30);
  assert.equal(parseRetryAfter("Sun, 11 Oct 2026 08:00:00 GMT", NOW), 0);
  assert.equal(parseRetryAfter("later", NOW), undefined);
  assert.equal(parseRetryAfter(null, NOW), undefined);
});

function fakeTime() {
  const time = { now: 1000, slept: [] };
  time.monotonic = () => time.now;
  time.sleep = async (seconds) => {
    time.slept.push(Math.round(seconds * 1e6) / 1e6);
    time.now += seconds;
  };
  return time;
}

const session = {
  accessToken: new SecretValue("session-secret"),
  tokenType: "DPoP",
  expiresIn: 300,
  scopes: ["orders:read"],
  sessionId: "ses_example",
  signedIn: true,
};
const who = { token: session, tenantId: "t", pairwiseUserId: "usr_example", issuer: "https://shop.example" };

test("safe requests retry after Retry-After with fresh proofs", async () => {
  const answers = [
    new Response(null, { status: 503, headers: { "retry-after": "2" } }),
    new Response(null, { status: 429, headers: { "retry-after": "1" } }),
    json({ orders: [] }),
  ];
  const seen = [];
  const fetch = async (_input, init) => {
    seen.push(init.headers.DPoP);
    return answers.shift();
  };
  const time = fakeTime();
  const budget = new SharedRateLimitBudget({ sleep: time.sleep, monotonic: time.monotonic });
  const agent = host(mutableClock(), [
    [RateLimitBudgets, budget],
    [RetryPolicies, new RetryPolicy({ baseDelay: 0.5, maxAttempts: 3 })],
  ]);
  const reactor = buildPapReactor({ fetch }, [agent.plugin]);
  const response = await new DpopFetchClient({ reactor, fetch }).request(
    "GET",
    "https://shop.example/api/orders",
    who,
  );
  assert.equal(response.status, 200);
  assert.deepEqual(seen, ["proof-1", "proof-2", "proof-3"]);
  assert.equal(time.slept.length, 2);
  assert.ok(time.slept[0] >= 2 && time.slept[0] <= 2.5);
  assert.ok(time.slept[1] >= 1 && time.slept[1] <= 1.5);
  reactor.stop();
});

test("writes and long pauses go back to the caller, and pauses are shared", async () => {
  const retryAfter = ["5"];
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return new Response(null, { status: 429, headers: { "retry-after": retryAfter.at(-1) } });
  };
  const time = fakeTime();
  const budget = new SharedRateLimitBudget({ sleep: time.sleep, monotonic: time.monotonic, maxWait: 10 });
  const reactor = buildPapReactor({ fetch }, [host(mutableClock(), [[RateLimitBudgets, budget]]).plugin]);
  const client = new DpopFetchClient({ reactor, fetch });
  const refused = await client.request("POST", "https://shop.example/api/orders", { ...who, body: "{}" });
  assert.equal(refused.status, 429);
  assert.equal(calls, 1);
  await budget.acquire("https://shop.example:443");
  assert.deepEqual(time.slept, [5]);
  retryAfter.push("30");
  const again = await client.request("GET", "https://shop.example/api/orders", who);
  assert.equal(again.status, 429);
  assert.equal(calls, 2);
  assert.deepEqual(time.slept, [5]);
  reactor.stop();
});

test("the shared budget paces tasks and refuses long waits", async () => {
  const time = fakeTime();
  const budget = new SharedRateLimitBudget({
    rate: 2,
    burst: 2,
    maxWait: 3,
    sleep: time.sleep,
    monotonic: time.monotonic,
  });
  await Promise.all([1, 2, 3, 4].map(() => budget.acquire("https://shop.example:443")));
  assert.deepEqual(time.slept, [0.5, 0.5]);
  await budget.acquire("https://other.example:443");
  assert.deepEqual(time.slept, [0.5, 0.5]);
  await budget.defer("https://shop.example:443", 60);
  await assert.rejects(
    budget.acquire("https://shop.example:443"),
    (error) =>
      error instanceof TransportError &&
      error.code === "rate_limited" &&
      error.details.retry_after === "60",
  );
});
