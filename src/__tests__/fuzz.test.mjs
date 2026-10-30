/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Seeded fuzzing of strict JSON, URL safety and the operation state machine (the TypeScript
// side of test_fuzz.py).
// fast-check is not a dependency of this repository: a seeded PRNG keeps every run
// reproducible; PAP_FUZZ_SEED and PAP_FUZZ_ITERATIONS widen a local run.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import test from "node:test";

import { exportJWK, generateKeyPair } from "jose";

import { PersonalAgentProtocolError, parseJsonStrict } from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { NodeUrlSafetyPolicy, isGlobalAddress } from "../../lib/server.js";
import { Context, identityFrom } from "./support/conformance.mjs";
import { MutableClock, inProcessFetch } from "./support/world.mjs";

const SEED = Number(process.env.PAP_FUZZ_SEED ?? 20261011);
const ITERATIONS = Number(process.env.PAP_FUZZ_ITERATIONS ?? 300);

/** mulberry32: a small seeded generator. */
function generator(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  return {
    next,
    int: (low, high) => low + Math.floor(next() * (high - low + 1)),
    pick: (items) => items[Math.floor(next() * items.length)],
  };
}

const ALPHABET = [..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-é ☃"];

function key(rng) {
  return Array.from({ length: rng.int(1, 8) }, () => rng.pick(ALPHABET)).join("");
}

function value(rng, depth) {
  const kind = rng.int(0, depth < 3 ? 5 : 3);
  if (kind === 0) return rng.int(-1e12, 1e12);
  if (kind === 1) return key(rng);
  if (kind === 2) return rng.pick([true, false, null]);
  if (kind === 3) return rng.next() * 1000;
  if (kind === 4) return Array.from({ length: rng.int(0, 4) }, () => value(rng, depth + 1));
  return Object.fromEntries(Array.from({ length: rng.int(0, 4) }, () => [key(rng), value(rng, depth + 1)]));
}

const escape = (name, rng) =>
  [...name].map((c) => (rng.next() < 0.5 && c.codePointAt(0) < 0x10000 ? `\\u${c.codePointAt(0).toString(16).padStart(4, "0")}` : c)).join("");

/** Serialize with one member of one object repeated (possibly escaped), or undefined. */
function withDuplicate(rng, document) {
  const objects = [];
  const collect = (node) => {
    if (Array.isArray(node)) node.forEach(collect);
    else if (node && typeof node === "object") {
      if (Object.keys(node).length) objects.push(node);
      Object.values(node).forEach(collect);
    }
  };
  collect(document);
  if (!objects.length) return undefined;
  const target = rng.pick(objects);
  const name = rng.pick(Object.keys(target));
  const encode = (node) => {
    if (Array.isArray(node)) return `[${node.map(encode).join(",")}]`;
    if (node && typeof node === "object") {
      const members = Object.entries(node).map(([k, v]) => `${JSON.stringify(k)}:${encode(v)}`);
      if (node === target) {
        const repeat = `"${escape(name, rng)}":${JSON.stringify(rng.pick([1, "x", null]))}`;
        if (rng.next() < 0.5) members.unshift(repeat);
        else members.push(repeat);
      }
      return `{${members.join(",")}}`;
    }
    return JSON.stringify(node);
  };
  return encode(document);
}

test("strict JSON accepts every unique document and refuses every duplicate", () => {
  const rng = generator(SEED);
  let refused = 0;
  for (let index = 0; index < ITERATIONS; index += 1) {
    const document = Object.fromEntries(Array.from({ length: rng.int(1, 5) }, () => [key(rng), value(rng, 0)]));
    const text = JSON.stringify(document);
    assert.deepEqual(parseJsonStrict(text), JSON.parse(text));
    const duplicated = withDuplicate(rng, document);
    if (duplicated === undefined) continue;
    assert.throws(() => parseJsonStrict(duplicated), (error) => error.code === "duplicate_json_member", duplicated);
    refused += 1;
  }
  assert.ok(refused > ITERATIONS / 2);
});

test("strict JSON refuses what RFC 8259 does not allow", () => {
  for (const text of ["NaN", "[Infinity]", '{"a": -Infinity}', "", "{", '{"a" 1}', "[1,]"]) {
    assert.throws(() => parseJsonStrict(text), (error) => error.name === "ProtocolValidationError", text);
  }
});

test("strict JSON survives random text", () => {
  const rng = generator(SEED + 1);
  for (let index = 0; index < ITERATIONS; index += 1) {
    const text = Array.from({ length: rng.int(0, 40) }, () => String.fromCharCode(rng.int(0, 255))).join("");
    try {
      parseJsonStrict(text);
    } catch (error) {
      assert.equal(error.name, "ProtocolValidationError", text);
    }
  }
});

const ADDRESSES = [
  "93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "127.0.0.1", "10.1.2.3", "172.16.0.9",
  "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::5", "fe80::1",
  "::ffff:127.0.0.1", "::ffff:93.184.216.34", "224.0.0.1", "255.255.255.255", "2001:db8::1",
];

function url(rng) {
  const scheme = rng.pick(["https", "https", "https", "http", "HTTPS", "ftp", "javascript"]);
  const user = rng.pick(["", "", "", "ada@", "ada:secret@"]);
  const host = rng.pick(["company.example", "a.b.company.example", "localhost", "[::1]", "127.0.0.1", "xn--caf-dma.example"]);
  const port = rng.pick(["", "", ":443", ":8443"]);
  const path = rng.pick(["/.well-known/poppy.json", "", "/a%20b", "?q=1"]);
  return `${scheme}://${user}${host}${port}${path}`;
}

test("URL safety approves only HTTPS URLs whose every address is public", async () => {
  const rng = generator(SEED + 2);
  for (let index = 0; index < ITERATIONS; index += 1) {
    const text = url(rng);
    let parsed;
    try {
      parsed = new URL(text);
    } catch {
      continue;
    }
    const answer = Array.from({ length: rng.int(1, 3) }, () => rng.pick(ADDRESSES));
    const policy = new NodeUrlSafetyPolicy({ resolver: async () => answer });
    try {
      await policy.assertSafe(parsed);
    } catch (error) {
      assert.ok(["unsafe_url", "unsafe_address", "dns_failed"].includes(error.code), `${text}: ${error.code}`);
      continue;
    }
    assert.equal(parsed.protocol, "https:", text);
    assert.equal(parsed.username + parsed.password, "", text);
    const host = parsed.hostname.replace(/^\[|\]$/g, "");
    const checked = isIP(host) ? [host] : answer;
    assert.ok(checked.every(isGlobalAddress), `${text} ${checked}`);
  }
});

// The operation state machine -------------------------------------------------------------

/** What the company's operator is told: too late to revise an operation. */
const OPERATOR_REFUSALS = new Set(["only an operation not yet approved can be revised"]);

async function identity(domain, name) {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return identityFrom({ domain, name, privateJwk: await exportJWK(pair.privateKey) });
}

test("random operation histories keep at most once", async () => {
  // Approvals, stale approvals, revisions and time passing, in any order. An operation is
  // performed at most once, whatever is sent; a revision the company replaced never performs
  // it; the company never answers an approval with the revision it named.
  const rng = generator(SEED + 3);
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const { service, plugin } = manzanita({ fetch, clock });
  sites["manzanita.example"] = service;
  const atlas = await identity("atlas.example", "Atlas");
  sites[atlas.domain] = { "/agent.json": atlas.metadata, "/jwks.json": atlas.jwks };
  const executors = [plugin.executor, plugin.giftWrap, plugin.returns, plugin.repairs];
  const driver = {
    capabilities: new Set(["revise", "performed", "clock"]),
    accounts: ["acct_ada", "acct_ada_business"],
    async approveDevice(userCode, { account }) {
      await service.approveDevice(userCode, { accountId: account });
    },
    async wait(seconds) {
      clock.advance(seconds);
    },
    async revise(operationId) {
      const current = (await service.operationRecord(operationId)).revisions.at(-1);
      await service.revise(operationId, {
        summary: `${current.summary} Ships in 5 days instead of 2.`,
        terms: { ...(current.terms ?? {}), ships_in_days: 5 },
      });
    },
    async performed(operationId) {
      return executors.flatMap((executor) => executor.performed).filter((id) => id === operationId).length;
    },
  };
  const scenario = JSON.parse(readFileSync(new URL("../../protocol/scenarios/manzanita-conformance.json", import.meta.url), "utf8"));
  const ctx = new Context({ baseUrl: "https://manzanita.example", identity: atlas, fetch, scenario, clock, driver });
  await ctx.operationsNegotiated();
  const request = (signed, kind, approval) => {
    const proposal = ctx.proposal(kind);
    return ctx.agent.api.call(proposal.method, ctx.url(proposal.path), {
      session: signed.session,
      token: signed.token,
      body: proposal.body ?? {},
      ...(approval === undefined ? {} : { approval }),
    });
  };
  const named = ({ operation_id, revision }) => ({ operation_id, revision });
  const histories = Math.max(8, Math.floor(ITERATIONS / 30));
  let approvals = 0;
  for (let history = 0; history < histories; history += 1) {
    const user = ctx.newUser();
    const signed = await ctx.signIn(user, await ctx.session(user));
    const kind = rng.pick(["user", "user", "fails", "unknown"]);
    const first = (await request(signed, kind)).operation;
    assert.ok(first, "the action is refused with its operation");
    let latest = first;
    for (let step = rng.int(1, 6); step > 0; step -= 1) {
      const action = rng.pick(["approve", "approve_stale", "ask", "revise", "wait"]);
      try {
        if (action === "approve" || action === "approve_stale") {
          const sent = action === "approve" ? latest : first;
          const answer = await request(signed, kind, named(sent));
          approvals += 1;
          if (answer.operation !== undefined) {
            assert.notEqual(answer.operation.revision, sent.revision);
            latest = answer.operation;
          } else if (action === "approve_stale" && first.revision !== latest.revision) {
            const record = await service.operationRecord(first.operation_id);
            assert.ok(record.approved !== first.revision || !record.revisions.at(-1).withdrawn);
          }
        } else if (action === "ask") {
          latest = (await request(signed, kind)).operation ?? latest;
        } else if (action === "revise") {
          await driver.revise(first.operation_id);
        } else {
          clock.advance(rng.pick([1, 60, 600, 1200]));
        }
      } catch (error) {
        // A refusal is fine; the invariant below is what matters.
        if (!(error instanceof PersonalAgentProtocolError) && !OPERATOR_REFUSALS.has(error.message)) throw error;
      }
      if (action === "wait") {
        const refreshed = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user) });
        if (refreshed.token !== undefined) signed.token = refreshed.token;
      }
      assert.ok((await driver.performed(first.operation_id)) <= 1);
    }
  }
  assert.ok(approvals > 0);
});
