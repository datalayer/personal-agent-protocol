/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What the 1.0 draft changes, both sides, in one process: the port of
// personal_agent_protocol/__tests__/test_draft_10.py.
//
// Protocol version 1.0 (§3.1, §3.4), the version a Personal Agent and a Company use since 0.36
// unless they ask for others: 0.4 as published stays available, used only when named. Lookalike domains (§10.3; guides, Finding a company): the name a
// poppy.json gives is unconfirmed, so the SDK shows the domain with it.
import assert from "node:assert/strict";
import test from "node:test";

import {
  AVAILABLE_PROTOCOL_VERSIONS,
  ConversationClient,
  DEFAULT_PROTOCOL_VERSION,
  DRAFT_PROTOCOL_REVISION,
  DRAFT_PROTOCOL_VERSION,
  PUBLISHED_PROTOCOL_REVISION,
  PUBLISHED_PROTOCOL_VERSION,
  PROTOCOL_PROFILE,
  PapSession,
  SUPPORTED_PROTOCOL_VERSIONS,
  SessionClient,
  SessionFetchClient,
  chosenVersion,
  companyProtocolVersion,
  companySessionVersion,
  discoverCompany,
  implementedProtocolVersions,
  implementedVersionFor,
  organizationLabel,
  parseDiscoveryDocument,
  sessionHeaders,
} from "../../lib/index.js";
import { CompanyConfig } from "../../lib/server.js";
import { CONFIG, CONFIG_OPTIONS, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const CONVERSATIONS = "https://manzanita.example/poppy/conversations";
const BOTH = [DRAFT_PROTOCOL_VERSION, PROTOCOL_PROFILE];

/** Manzanita serving `versions` (its default for none), and Atlas's host on the same network. */
async function world(versions) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const config = versions === undefined ? undefined : new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: versions });
  const { service: shop } = manzanita({ fetch, clock, ...(config ? { config } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const conversations = new ConversationClient({ reactor: host.reactor, transport: new SessionFetchClient({ reactor: host.reactor, fetch }) });
  return { clock, fetch, identity, shop, host, sites, conversations };
}

/** Discovery and a signed-out Session by an agent that implements `versions` (the default for none). */
async function session(w, versions) {
  const company = await discoverCompany("manzanita.example", {
    reactor: w.host.reactor,
    ...(versions === undefined ? {} : { protocolVersions: versions }),
  });
  const started = await new SessionClient({ reactor: w.host.reactor, fetch: w.fetch }).start({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: company.oauthMetadata.issuer,
    tenantId: TENANT,
    company,
  });
  return { company, session: started };
}

let requests = 0;
const hello = () => ({ id: `req_draft10_${String((requests += 1)).padStart(10, "0")}`, author: { type: "human" }, text: "Hello" });

// Protocol version 1.0, the default (§3.1, §3.4) --------------------------------------

test("the draft is the default and the published version is available", () => {
  assert.deepEqual([PROTOCOL_PROFILE, PUBLISHED_PROTOCOL_VERSION, DRAFT_PROTOCOL_VERSION], ["0.4", "1.0", "1.1"]);
  assert.equal(DEFAULT_PROTOCOL_VERSION, DRAFT_PROTOCOL_VERSION);
  assert.deepEqual([PUBLISHED_PROTOCOL_REVISION, DRAFT_PROTOCOL_REVISION], ["2026-11-14", "2026-11-18"]);
  assert.deepEqual([...SUPPORTED_PROTOCOL_VERSIONS], ["1.1"]);
  assert.deepEqual([...AVAILABLE_PROTOCOL_VERSIONS].sort(), ["0.4", "1.0", "1.1"]);
  assert.deepEqual([...implementedProtocolVersions()], ["1.1"]);
  assert.deepEqual([...implementedProtocolVersions(["0.4"])], ["0.4"]);
  assert.deepEqual([...implementedProtocolVersions(["1.0"])], ["1.0"]);
  assert.deepEqual([...implementedProtocolVersions(BOTH)].sort(), ["0.4", "1.1"]);
  for (const unknown of [["0.3"], ["2.0"], ["1.2"], []]) {
    assert.throws(() => implementedProtocolVersions(unknown), RangeError);
  }
  // The version a Session names: the newest implemented, compatible with the chosen one and
  // never later than it.
  assert.equal(implementedVersionFor("1.1"), "1.1");
  assert.equal(implementedVersionFor("1.4"), "1.1");
  assert.equal(implementedVersionFor("1.0"), "1.0");
  assert.equal(implementedVersionFor("1.4", ["1.0"]), "1.0");
  assert.equal(implementedVersionFor("1.1", ["0.4", "1.0"]), "1.0");
  assert.equal(implementedVersionFor("0.4", ["0.4", "1.1"]), "0.4");
  for (const [chosen, mine] of [["0.3", ["0.4", "1.1"]], ["0.4", ["1.1"]], ["1.1", ["0.4"]]]) {
    assert.throws(() => implementedVersionFor(chosen, mine), RangeError);
  }
});

test("a published document is used only by an agent that implements it", () => {
  const published = { protocol_version: "0.4", organization: { name: "Example", domain: "example.com" }, web: {} };
  // A document's version is one the SDK implements; whether an agent uses it is its own.
  assert.throws(() => parseDiscoveryDocument(published, SUPPORTED_PROTOCOL_VERSIONS));
  assert.throws(() => parseDiscoveryDocument({ ...published, protocol_version: "2.0" }));
  const document = parseDiscoveryDocument(published);
  assert.equal(chosenVersion(document), undefined);
  assert.equal(chosenVersion(document, BOTH), "0.4");
  const linked = parseDiscoveryDocument({ ...published, supported_versions: { "1.0": "https://example.com/poppy/1.0.json" } });
  assert.equal(chosenVersion(linked), "1.0");
  assert.equal(chosenVersion(linked, BOTH), "1.0");
  assert.equal(chosenVersion(linked, ["0.4"]), "0.4");
});

test("the reference company serves the draft only by default", async () => {
  assert.deepEqual(CONFIG.protocolVersions, [DEFAULT_PROTOCOL_VERSION]);
  const w = await world();
  const { company, session: started } = await session(w, BOTH);
  assert.deepEqual([companyProtocolVersion(company), started.protocolVersion], ["1.1", "1.1"]);
  assert.deepEqual(company.document.supported_versions, {});
  const headers = await sessionHeaders(w.host.reactor, "POST", CONVERSATIONS, { session: started });
  assert.equal(headers["Poppy-Version"], "1.1");
  const refused = await w.fetch(CONVERSATIONS, {
    method: "POST",
    headers: { ...headers, "Poppy-Version": "0.4", "Content-Type": "application/json" },
    body: JSON.stringify({ id: "req_draft_unserved_0000", message: { author: { type: "human" }, text: "Hi" } }),
  });
  assert.equal(refused.status, 400);
  assert.deepEqual(await refused.json(), { error: "version_unsupported" });
});

test("an agent on the default uses no company that serves only the published version", async () => {
  const w = await world([PROTOCOL_PROFILE]);
  await assert.rejects(session(w), (error) => error.code === "unsupported_protocol_version");
  const { company, session: started } = await session(w, [PROTOCOL_PROFILE]);
  assert.deepEqual([companyProtocolVersion(company), started.protocolVersion], ["0.4", "0.4"]);
  assert.equal(PapSession.fromJson(started.toJson()).protocolVersion, "0.4");
  const receipt = await w.conversations.start(CONVERSATIONS, hello(), { session: started });
  assert.equal((await w.shop.conversationRecord(receipt.conversation_id)).protocolVersion, "0.4");
});

test("a company that serves both versions is used at the newest the agent implements", async () => {
  for (const preferred of [BOTH, [...BOTH].reverse()]) {
    const w = await world(preferred);
    const other = preferred[1];
    const byDefault = await session(w);
    assert.deepEqual([companyProtocolVersion(byDefault.company), byDefault.session.protocolVersion], ["1.1", "1.1"]);
    // poppy.json itself when it is 1.0's, else 1.0's own document, which lists none.
    assert.equal(Object.keys(byDefault.company.document.supported_versions).length > 0, preferred[0] === "1.1");
    const published = await session(w, [PROTOCOL_PROFILE]);
    assert.deepEqual([companyProtocolVersion(published.company), published.session.protocolVersion], ["0.4", "0.4"]);
    assert.equal(companySessionVersion(published.company), "0.4");
    const both = await session(w, BOTH);
    assert.deepEqual([companyProtocolVersion(both.company), both.session.protocolVersion], ["1.1", "1.1"]);
    const served = await (await w.fetch("https://manzanita.example/.well-known/poppy.json")).json();
    assert.equal(served.protocol_version, preferred[0]);
    assert.deepEqual(served.supported_versions, { [other]: `https://manzanita.example/poppy/${other}.json` });
    for (const { session: started } of [byDefault, published]) {
      const receipt = await w.conversations.start(CONVERSATIONS, hello(), { session: started });
      assert.equal((await w.shop.conversationRecord(receipt.conversation_id)).protocolVersion, started.protocolVersion);
    }
  }
});

test("a conversation started in the draft can be refused in the published version", async () => {
  const w = await world(BOTH);
  const draft = await session(w);
  const receipt = await w.conversations.start(CONVERSATIONS, hello(), { session: draft.session });
  w.sites["manzanita.example"] = manzanita({
    fetch: w.fetch,
    clock: w.clock,
    config: new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: BOTH, conversationCarryOver: false }),
    store: w.shop.store,
  }).service;
  const published = await session(w, [PROTOCOL_PROFILE]);
  await assert.rejects(
    w.conversations.send(CONVERSATIONS, receipt.conversation_id, hello(), { session: published.session }),
    (error) => error.code === "version_mismatch" && error.statusCode === 409 && error.details.protocol_version === "1.1",
  );
});

test("a Session names the version given, else the company's, else the default one", async () => {
  const w = await world();
  const sessions = new SessionClient({ reactor: w.host.reactor, fetch: w.fetch });
  const who = { clientId: w.identity.clientId, pairwiseUserId: PAIRWISE, issuer: "https://manzanita.example", tenantId: TENANT };
  assert.equal((await sessions.start(who)).protocolVersion, "1.1");
  assert.equal((await sessions.start({ ...who, protocolVersion: "0.4" })).protocolVersion, "0.4");
  await assert.rejects(sessions.start({ ...who, protocolVersion: "0.3" }));
  assert.throws(() => new PapSession({ sid: "s".repeat(22), sub: PAIRWISE, issuer: who.issuer, clientId: who.clientId, tenantId: TENANT, protocolVersion: "2.0" }));
});

// Lookalike domains (§10.3; guides, Finding a company) ---------------------------------

test("the name is shown with the domain", () => {
  assert.equal(organizationLabel({ name: "Manzanita", domain: "manzanita.example" }), "Manzanita (manzanita.example)");
  assert.equal(organizationLabel({ name: "Manzanita", domain: "manzanita-orders.example" }), "Manzanita (manzanita-orders.example)");
  assert.equal(organizationLabel({ name: "manzanita.example", domain: "manzanita.example" }), "manzanita.example");
});
