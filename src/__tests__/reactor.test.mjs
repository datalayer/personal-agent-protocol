import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationStateStores,
  BrowserHandoffs,
  Caches,
  Clocks,
  DpopProofProviders,
  PairwiseUserIdStores,
  RandomSources,
  Signers,
  TokenStores,
  resolvePairwiseUserId,
  buildPapReactor,
  firstContribution,
} from "../../lib/index.js";

const securityPoints = [
  AuthorizationStateStores,
  Signers,
  TokenStores,
  PairwiseUserIdStores,
  BrowserHandoffs,
  DpopProofProviders,
];

const plugin = (name, point, value, id = name) => ({
  name,
  contributes: [{ point, value, options: { id, order: 10 } }],
});

test("exports aligned infrastructure point IDs and secure defaults", () => {
  assert.equal(AuthorizationStateStores.id, "pap.authorizationStateStore");
  assert.equal(Clocks.id, "pap.clock");
  assert.equal(RandomSources.id, "pap.randomSource");
  assert.equal(Signers.id, "pap.signer");
  assert.equal(TokenStores.id, "pap.tokenStore");
  assert.equal(PairwiseUserIdStores.id, "pap.pairwiseUserIdStore");
  assert.equal(Caches.id, "pap.cache");
  assert.equal(BrowserHandoffs.id, "pap.browserHandoff");
  assert.equal(DpopProofProviders.id, "pap.dpopProofProvider");

  const reactor = buildPapReactor();
  const clock = firstContribution(reactor, Clocks, "clock");
  const random = firstContribution(reactor, RandomSources, "random source");
  assert.ok(clock.now() instanceof Date);
  assert.equal(random.bytes(16).byteLength, 16);
  assert.throws(() => random.bytes(0), RangeError);
  reactor.stop();
});

test("resolves stable pairwise identity through the host store", async () => {
  const store = {
    async getOrCreate(options) {
      assert.deepEqual(options, {
        tenantId: "app-one",
        localUserId: "user-one",
        companyIssuer: "https://auth.example.com",
      });
      return "usr_stable-pairwise-id";
    },
  };
  const reactor = buildPapReactor({}, [plugin("@tests/pairwise", PairwiseUserIdStores, store)]);
  assert.equal(
    await resolvePairwiseUserId(reactor, {
      tenantId: "app-one",
      localUserId: "user-one",
      companyIssuer: "https://auth.example.com",
    }),
    "usr_stable-pairwise-id",
  );
  reactor.stop();
});

test("the core contributes a bounded public-metadata cache a host can replace", async () => {
  const reactor = buildPapReactor();
  const cache = firstContribution(reactor, Caches, "cache");
  await cache.put("k", 1, { expiresAt: new Date() });
  assert.equal(await cache.get("k"), 1);
  reactor.stop();
  const shared = { async put() {}, async get() {}, async delete() {} };
  const replaced = buildPapReactor({}, [plugin("@tests/cache", Caches, shared)]);
  assert.equal(firstContribution(replaced, Caches, "cache"), shared);
  replaced.stop();
});

for (const point of securityPoints) {
  test(`${point.id} fails closed when missing`, () => {
    const reactor = buildPapReactor();
    assert.throws(
      () => firstContribution(reactor, point, point.id),
      /no active/,
    );
    reactor.stop();
  });

  test(`${point.id} fails closed at equal winning priority`, () => {
    const first = plugin(`@tests/${point.id}/first`, point, { provider: "first" }, "first");
    const second = plugin(`@tests/${point.id}/second`, point, { provider: "second" }, "second");
    const reactor = buildPapReactor({}, [first, second]);
    assert.throws(
      () => firstContribution(reactor, point, point.id),
      /ambiguous/,
    );
    reactor.stop();
  });

  test(`${point.id} follows plugin disable and enable`, () => {
    const value = { provider: "lifecycle" };
    const lifecyclePlugin = plugin(
      `@tests/${point.id}/lifecycle`,
      point,
      value,
      "lifecycle",
    );
    const reactor = buildPapReactor({}, [lifecyclePlugin]);
    assert.equal(firstContribution(reactor, point, point.id), value);
    reactor.disable(lifecyclePlugin.name);
    assert.throws(
      () => firstContribution(reactor, point, point.id),
      /no active/,
    );
    reactor.enable(lifecyclePlugin.name);
    assert.equal(firstContribution(reactor, point, point.id), value);
    reactor.stop();
  });
}
