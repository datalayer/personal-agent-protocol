import assert from "node:assert/strict";
import test from "node:test";

import {
  BrowserHandoffs,
  Caches,
  Clocks,
  DpopProofProviders,
  KeyStores,
  RandomSources,
  Signers,
  TokenStores,
  buildPapReactor,
  firstContribution,
} from "../lib/index.js";

const securityPoints = [
  Signers,
  KeyStores,
  TokenStores,
  Caches,
  BrowserHandoffs,
  DpopProofProviders,
];

const plugin = (name, point, value, id = name) => ({
  name,
  contributes: [{ point, value, options: { id, order: 10 } }],
});

test("exports aligned infrastructure point IDs and secure defaults", () => {
  assert.equal(Clocks.id, "pap.clock");
  assert.equal(RandomSources.id, "pap.randomSource");
  assert.equal(Signers.id, "pap.signer");
  assert.equal(KeyStores.id, "pap.keyStore");
  assert.equal(TokenStores.id, "pap.tokenStore");
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
