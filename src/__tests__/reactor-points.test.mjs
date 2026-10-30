/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Every Reactor contribution point, held to protocol/reactor-points.json (as Python's
// test_reactor_points.py holds the Python SDK): the same ids and contracts, each
// default, each point's lifecycle (contributed, replaced by a lower order, gone when its
// plugin is disabled, equal orders failing closed), and the tenant-scoped points.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

import * as portable from "../../lib/index.js";
import * as server from "../../lib/server.js";

const ROOT = new URL("../../", import.meta.url);
const inventory = JSON.parse(readFileSync(new URL("protocol/reactor-points.json", ROOT), "utf8"));
/** The points TypeScript defines: all but those for Python hosts only (`typescript: null`). */
const points = inventory.points.filter((entry) => entry.typescript !== null);

function sources(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const child = new URL(entry.name + (entry.isDirectory() ? "/" : ""), directory);
    if (entry.isDirectory()) return entry.name === "__tests__" ? [] : sources(child);
    return entry.name.endsWith(".ts") ? [readFileSync(child, "utf8")] : [];
  });
}
const SOURCE = sources(new URL("src/", ROOT)).join("\n");

const camel = (name) => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());

/** The members an exported interface or class declares, from its source. */
function members(contract) {
  const start = SOURCE.search(new RegExp(`export (interface|class) ${contract}\\b`));
  assert.ok(start >= 0, `no TypeScript contract ${contract}`);
  const body = SOURCE.slice(SOURCE.indexOf("{", start), SOURCE.indexOf("\n}", start));
  return new Set(
    [...body.matchAll(/^\s{2}(?:readonly\s+|async\s+)?(\w+)\??\s*[(:<]/gm)].map((match) => match[1]),
  );
}

const pointOf = (entry) => (entry.role === "company" ? server : portable)[entry.typescript];

function reactorFor(entry, plugins = []) {
  if (entry.role === "company") {
    const config = new server.CompanyConfig({ name: "Points", domain: "points.example", scopes: ["a:read"], scopeDescriptions: { "a:read": "Read" }, operations: false });
    return server.buildCompany(config, { plugins }).reactor;
  }
  return portable.buildPapReactor({}, plugins);
}

const contributor = (name, point, value, order) => ({
  name,
  contributes: [{ point, value, options: { id: name, order } }],
});

/** What the SDK uses for the point, the way the SDK reads it. */
function resolve(reactor, entry) {
  const point = pointOf(entry);
  if (entry.resolution === "optional") return portable.optionalContribution(reactor, point, entry.id);
  if (entry.resolution === "by-action") {
    const winners = reactor.getContributions(point).filter((c) => c.value.action === "tests.act");
    if (!winners.length) throw new Error("no active executor");
    if (winners[1]?.order === winners[0].order) throw new Error("ambiguous executors");
    return winners[0].value;
  }
  return portable.firstContribution(reactor, point, entry.id);
}

test("the TypeScript SDK exports exactly the inventory's points", () => {
  const exported = new Set();
  for (const module of [portable, server]) {
    for (const [name, value] of Object.entries(module)) {
      if (value && typeof value === "object" && typeof value.id === "string" && value.id.startsWith("pap.")) {
        exported.add(`${name} ${value.id}`);
      }
    }
  }
  assert.deepEqual(
    [...exported].sort(),
    points.map((entry) => `${entry.typescript} ${entry.id}`).sort(),
  );
});

for (const entry of points) {
  test(`${entry.id}: the contract has the inventory's members`, () => {
    const expected = entry.typescript_members ?? entry.members.map(camel);
    const declared = members(entry.contract);
    for (const member of expected) assert.ok(declared.has(member), `${entry.contract}.${member}`);
  });

  test(`${entry.id}: the default is the inventory's`, () => {
    const reactor = reactorFor(entry);
    const defaults = reactor.getContributions(pointOf(entry)).filter((c) => c.order === 100);
    assert.deepEqual(
      defaults.map((c) => c.id),
      entry.default === null ? [] : [entry.default.typescript],
    );
    reactor.stop();
  });

  test(`${entry.id}: follows its plugins' lifecycle`, async () => {
    const point = pointOf(entry);
    const first = { action: "tests.act", provider: "first" };
    const second = { action: "tests.act", provider: "second" };
    const reactor = reactorFor(entry, [contributor("host-first", point, first, 50)]);
    const fallback = entry.default === null ? undefined : reactor.getContributions(point).at(-1).value;
    // Contributed: the host's contribution is the one used.
    assert.equal(resolve(reactor, entry), first);
    // Replaced: a lower order wins.
    await reactor.install(contributor("host-second", point, second, 10));
    assert.equal(resolve(reactor, entry), second);
    // Removed: a disabled plugin's contribution is gone.
    reactor.disable("host-second");
    assert.equal(resolve(reactor, entry), first);
    reactor.disable("host-first");
    if (entry.default !== null) assert.equal(resolve(reactor, entry), fallback);
    else if (entry.resolution === "optional") assert.equal(resolve(reactor, entry), undefined);
    else assert.throws(() => resolve(reactor, entry), /no active/);
    reactor.stop();
    // Ambiguous: two contributions at the winning order fail closed.
    const tied = reactorFor(entry, [
      contributor("host-a", point, first, 5),
      contributor("host-b", point, second, 5),
    ]);
    assert.throws(() => resolve(tied, entry), /ambiguous/);
    tied.stop();
  });
}

test("the tenant-scoped points are the inventory's", () => {
  assert.deepEqual(
    inventory.points.filter((entry) => entry.tenant !== null).map((entry) => entry.id).sort(),
    ["pap.pairwiseUserIdStore", "pap.sessionSigner"],
  );
});

test("pairwise IDs are resolved per tenant and never cross", async () => {
  const ids = new Map();
  const asked = [];
  const store = {
    async getOrCreate({ tenantId, localUserId, companyIssuer }) {
      asked.push(tenantId);
      const key = JSON.stringify([tenantId, localUserId, companyIssuer]);
      if (!ids.has(key)) ids.set(key, `usr_${ids.size}`);
      return ids.get(key);
    },
  };
  const reactor = portable.buildPapReactor({}, [
    contributor("pairwise", portable.PairwiseUserIdStores, store, 10),
  ]);
  const who = { localUserId: "ada", companyIssuer: "https://shop.example" };
  const one = await portable.resolvePairwiseUserId(reactor, { tenantId: "tenant-one", ...who });
  const two = await portable.resolvePairwiseUserId(reactor, { tenantId: "tenant-two", ...who });
  const again = await portable.resolvePairwiseUserId(reactor, { tenantId: "tenant-one", ...who });
  reactor.stop();
  assert.deepEqual(asked, ["tenant-one", "tenant-two", "tenant-one"]);
  assert.equal(one, again);
  assert.notEqual(one, two);
});

test("each Session JWT is asked for the request's own tenant", async () => {
  const asked = [];
  const signer = {
    async sign(request) {
      asked.push([request.tenantId, request.sid]);
      return new portable.SecretValue(`jwt-for-${request.tenantId}`);
    },
  };
  const seen = [];
  const fetch = async (_url, init) => {
    seen.push(new Headers(init.headers).get("poppy-session"));
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  const reactor = portable.buildPapReactor({}, [
    contributor("session-signer", portable.SessionSigners, signer, 10),
  ]);
  const client = new portable.SessionFetchClient({ reactor, fetch });
  const one = "1".repeat(22);
  const two = "2".repeat(22);
  for (const [tenantId, sid] of [["tenant-one", one], ["tenant-two", two]]) {
    const session = new portable.PapSession({
      sid,
      sub: "usr_ada",
      issuer: "https://shop.example",
      clientId: "https://agent.example/agent.json",
      tenantId,
    });
    await client.request("GET", "https://shop.example/api/orders", { session });
  }
  reactor.stop();
  // Each JWT names its tenant, and its Session by its `sid` (§5.2).
  assert.deepEqual(asked, [["tenant-one", one], ["tenant-two", two]]);
  assert.deepEqual(seen, ["jwt-for-tenant-one", "jwt-for-tenant-two"]);
});
