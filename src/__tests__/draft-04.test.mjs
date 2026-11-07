/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What draft 0.4 adds, both sides, in one process: the port of
// personal_agent_protocol/__tests__/test_draft_04.py.
//
// Direct Sign-In preferred (§4, P4-01); several protocol versions (§3.4, P4-02); what a
// message took into account (§8.4, P4-08).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ConversationClient,
  DEVICE_CODE_GRANT,
  MEDIATED_GRANT,
  PROTOCOL_PROFILE,
  PapSession,
  SessionClient,
  SessionFetchClient,
  chooseProtocolVersion,
  compatibleVersions,
  discoverCompany,
  parseDiscoveryDocument,
  parseMessage,
  parseOAuthServerMetadata,
  preferredSignIn,
  sessionHeaders,
  signInTypes,
  versionUnsupported,
} from "../../lib/index.js";
import { CompanyConfig } from "../../lib/server.js";
import { CONFIG, CONFIG_OPTIONS, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const CONVERSATIONS = "https://manzanita.example/poppy/conversations";

async function world(config) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop } = manzanita({ fetch, clock, ...(config ? { config } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const session = await sessions.start({
    clientId: identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: company.oauthMetadata.issuer,
    tenantId: TENANT,
  });
  return { clock, fetch, identity, shop, host, sites, company, session };
}

let requests = 0;
const greeting = () => ({ id: `req_0123456789abcdefgh_${(requests += 1)}`, message: { author: { type: "human" }, text: "Hello" } });

const fixtures = new URL("../../protocol/fixtures/", import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, fixtures), "utf8"));

function company(grants, { disabled = false } = {}) {
  const document = fixture("discovery-valid.json");
  if (disabled) document.auth.disabled = true;
  const metadata = fixture("oauth-metadata-valid.json");
  metadata.grant_types_supported = ["refresh_token", ...grants];
  if (!grants.includes("authorization_code")) delete metadata.authorization_endpoint;
  if (!grants.includes(DEVICE_CODE_GRANT)) delete metadata.device_authorization_endpoint;
  return {
    discoveryUrl: "https://example.com/.well-known/poppy.json",
    document: parseDiscoveryDocument(document),
    oauthMetadata: parseOAuthServerMetadata(metadata),
  };
}

// Direct Sign-In preferred (§4) ------------------------------------------------------

test("Direct Sign-In is preferred when offered", () => {
  const everything = company(["authorization_code", DEVICE_CODE_GRANT, MEDIATED_GRANT]);
  assert.deepEqual(signInTypes(everything), ["direct", "device", "mediated"]);
  assert.equal(preferredSignIn(everything), "direct");
  // A Company guarding high-value resources offers Direct only (RFC 10027 §6.2.1.5).
  assert.equal(preferredSignIn(company(["authorization_code"])), "direct");
  const deviceOnly = company([DEVICE_CODE_GRANT, MEDIATED_GRANT]);
  assert.deepEqual(signInTypes(deviceOnly), ["device", "mediated"]);
  assert.equal(preferredSignIn(deviceOnly), "device");
  assert.equal(preferredSignIn(company([MEDIATED_GRANT])), "mediated");
  assert.equal(preferredSignIn(company([])), undefined);
  const disabled = company(["authorization_code", DEVICE_CODE_GRANT], { disabled: true });
  assert.deepEqual(signInTypes(disabled), []);
  assert.equal(preferredSignIn(disabled), undefined);
  const { oauthMetadata: _, ...noIssuer } = everything;
  assert.equal(preferredSignIn(noIssuer), undefined);
});

test("the reference company offers Direct Sign-In", () => {
  assert.ok(CONFIG.direct && CONFIG.device);
  const { service } = manzanita({ fetch: inProcessFetch({}), clock: new MutableClock() });
  const grants = service.oauthMetadata().grant_types_supported;
  assert.ok(grants.includes("authorization_code") && grants.includes(DEVICE_CODE_GRANT));
  const bank = new CompanyConfig({
    name: "Bank",
    domain: "bank.example",
    scopes: ["accounts:read"],
    scopeDescriptions: { "accounts:read": "See your accounts" },
    operations: false,
    device: false,
  });
  assert.ok(bank.direct && !bank.device);
});


// Several protocol versions (§3.4) ---------------------------------------------------

test("versions are compatible by major and, before 1.0, by minor", () => {
  assert.ok(compatibleVersions("0.4", "0.4") && !compatibleVersions("0.4", "0.3"));
  assert.ok(compatibleVersions("1.2", "1.0") && !compatibleVersions("2.0", "1.9"));
  // The newest compatible version, its own or a linked one, else none (§3.4).
  assert.equal(chooseProtocolVersion("0.9", ["0.1", PROTOCOL_PROFILE]), PROTOCOL_PROFILE);
  assert.equal(chooseProtocolVersion(PROTOCOL_PROFILE, ["0.9"]), PROTOCOL_PROFILE);
  assert.equal(chooseProtocolVersion("0.9", ["0.8"]), undefined);
  assert.equal(chooseProtocolVersion("1.3", ["1.1", "1.5"], ["1.0"]), "1.5");
  assert.equal(chooseProtocolVersion("not-a-version", ["1.0"], ["1.0"]), "1.0");
  assert.throws(() =>
    parseDiscoveryDocument({
      protocol_version: "0.9",
      supported_versions: { [PROTOCOL_PROFILE]: "http://example.com/poppy.json" },
      organization: { name: "Example", domain: "example.com" },
      web: {},
    }),
  );
});

test("every request with the Session header names the Session's version", async () => {
  const w = await world();
  assert.equal(w.session.protocolVersion, PROTOCOL_PROFILE);
  assert.equal(PapSession.fromJson(w.session.toJson()).protocolVersion, PROTOCOL_PROFILE);
  const headers = await sessionHeaders(w.host.reactor, "GET", "https://manzanita.example/api/orders", { session: w.session });
  assert.equal(headers["Poppy-Version"], PROTOCOL_PROFILE);
  assert.throws(() => new PapSession({ ...w.session, clientId: w.identity.clientId, protocolVersion: "0.9" }));
});

test("a request without Poppy-Version, or in an unserved one, is refused", async () => {
  const w = await world();
  const signed = await sessionHeaders(w.host.reactor, "POST", CONVERSATIONS, { session: w.session });
  const { "Poppy-Version": _version, ...without } = signed;
  const body = JSON.stringify(greeting());
  const refused = await w.fetch(CONVERSATIONS, { method: "POST", headers: { ...without, "Content-Type": "application/json" }, body });
  assert.equal(refused.status, 400);
  assert.ok(await versionUnsupported(refused));
  assert.deepEqual(await refused.json(), { error: "version_unsupported" });
  const again = await sessionHeaders(w.host.reactor, "POST", CONVERSATIONS, { session: w.session });
  const other = await w.fetch(CONVERSATIONS, { method: "POST", headers: { ...again, "Poppy-Version": "9.0", "Content-Type": "application/json" }, body });
  assert.deepEqual([other.status, await other.json()], [400, { error: "version_unsupported" }]);
  // A company that stopped serving the Session's version: the transport returns the refusal
  // as it is, and choosing again is discovery's (`discoverCompany(domain, { fresh: true })`).
  w.sites["manzanita.example"] = manzanita({ fetch: w.fetch, clock: w.clock, config: new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: ["0.0"] }) }).service;
  const conversations = new ConversationClient({ reactor: w.host.reactor, transport: new SessionFetchClient({ reactor: w.host.reactor, fetch: w.fetch }) });
  await assert.rejects(conversations.start(CONVERSATIONS, greeting().message, { session: w.session }), (error) => error.code === "version_unsupported" && error.statusCode === 400);
});

test("the company serves its other versions' documents", async () => {
  const config = new CompanyConfig({
    ...CONFIG_OPTIONS,
    protocolVersions: [PROTOCOL_PROFILE, "0.0"],
    deprecatedVersions: { "0.0": ["2026-11-01T00:00:00Z", "2027-01-01T00:00:00Z"] },
  });
  const w = await world(config);
  const document = w.company.document;
  assert.equal(document.protocol_version, PROTOCOL_PROFILE);
  assert.deepEqual(document.supported_versions, { "0.0": "https://manzanita.example/poppy/0.0.json" });
  const older = await (await w.fetch("https://manzanita.example/poppy/0.0.json")).json();
  assert.equal(older.protocol_version, "0.0");
  assert.ok(!("supported_versions" in older));
  assert.deepEqual(older.organization, document.organization);
  assert.equal(older.auth.issuer, document.auth.issuer);
  assert.equal((await w.fetch("https://manzanita.example/poppy/0.7.json")).status, 404);
  // A request in the older version is served, with the notice; the current one carries none.
  const body = JSON.stringify(greeting());
  const headers = await sessionHeaders(w.host.reactor, "POST", CONVERSATIONS, { session: w.session });
  const olderAnswer = await w.fetch(CONVERSATIONS, { method: "POST", headers: { ...headers, "Poppy-Version": "0.0", "Content-Type": "application/json" }, body });
  assert.equal(olderAnswer.status, 201);
  assert.equal(olderAnswer.headers.get("deprecation"), `@${Math.floor(Date.parse("2026-11-01T00:00:00Z") / 1000)}`);
  assert.equal(olderAnswer.headers.get("sunset"), "Fri, 01 Jan 2027 00:00:00 GMT");
  const current = await w.fetch(CONVERSATIONS, {
    method: "POST",
    headers: { ...(await sessionHeaders(w.host.reactor, "POST", CONVERSATIONS, { session: w.session })), "Content-Type": "application/json" },
    body,
  });
  assert.equal(current.status, 201);
  assert.equal(current.headers.get("sunset"), null);
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: [PROTOCOL_PROFILE, PROTOCOL_PROFILE] }));
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, deprecatedVersions: { "0.0": ["2026-11-01T00:00:00Z", "2027-01-01T00:00:00Z"] } }));
});


// What a message took into account (§8.4) -------------------------------------------

test("only an AI says what it took into account", () => {
  assert.equal(parseMessage({ author: { type: "agent" }, text: "Medium, please.", as_of_cursor: "evt_c2" }).as_of_cursor, "evt_c2");
  assert.equal(parseMessage({ id: "msg_1", role: "company", author: { type: "agent" }, text: "Done.", as_of_request: "req_1" }).as_of_request, "req_1");
  for (const fields of [
    { author: { type: "human" }, as_of_cursor: "evt_c2" },
    { author: { type: "human" }, as_of_request: "req_1" },
    { author: { type: "agent" }, role: "user", as_of_request: "req_1" },
    { author: { type: "agent" }, role: "company", as_of_cursor: "evt_c2" },
    { author: { type: "agent" }, as_of_cursor: "not valid!" },
  ]) {
    assert.throws(() => parseMessage({ text: "Hello", ...fields }));
  }
});

test("the company agent names the request it answered, and people do not", async () => {
  const w = await world(new CompanyConfig({ ...CONFIG_OPTIONS, humansAvailable: true }));
  const conversations = new ConversationClient({ reactor: w.host.reactor, transport: new SessionFetchClient({ reactor: w.host.reactor, fetch: w.fetch }) });
  const first = { id: "req_first_000000000000", author: { type: "human" }, text: "Hello" };
  let page = await conversations.start(CONVERSATIONS, first, { session: w.session, wait: 0 });
  const replies = page.events.filter((e) => e.message?.role === "company").map((e) => e.message);
  assert.ok(replies.length > 0 && replies.every((reply) => reply.as_of_request === first.id));
  const follow = { id: "req_follow_00000000000", author: { type: "agent" }, text: "And my order?" };
  page = await conversations.send(CONVERSATIONS, page.conversation_id, follow, { session: w.session, asOfCursor: page.cursor, wait: 0 });
  const mine = page.events.filter((e) => e.message?.role === "user").map((e) => e.message);
  assert.ok(mine.at(-1).as_of_cursor?.startsWith("evt") && mine.at(-1).id === follow.id);
  await conversations.handoff(CONVERSATIONS, page.conversation_id, { session: w.session });
  const settled = await conversations.readUntilDone(CONVERSATIONS, page.conversation_id, { session: w.session, wait: 0 });
  const event = await w.shop.staffReply(page.conversation_id, { after: settled.events.at(-1).id, text: "Marta here.", authorName: "Marta" });
  assert.equal(event.message.as_of_request, undefined);
});
