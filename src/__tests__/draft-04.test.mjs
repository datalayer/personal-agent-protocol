/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What draft 0.4 adds, both sides, in one process: the port of
// personal_agent_protocol/__tests__/test_draft_04.py.
//
// Direct Sign-In preferred (§4, P4-01); several protocol versions (§3.4, P4-02); extensions
// declared per request (§3.3, §3.4, P4-03); conversations across versions (§8.2, P4-04); the
// browser join scope and website flags (§3.1, §4.7, §6, P4-05); what a message took into account
// (§8.4, P4-08).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  BROWSER_SIGN_IN_SCOPE,
  BrowserSessionClient,
  ConversationClient,
  DeviceSignInClient,
  DEVICE_CODE_GRANT,
  MEDIATED_GRANT,
  PROTOCOL_PROFILE,
  PapSession,
  SessionClient,
  SessionFetchClient,
  chooseProtocolVersion,
  companyExtension,
  compatibleVersions,
  formatExtensionsHeader,
  negotiateExtensions,
  parseExtensionsHeader,
  discoverCompany,
  browserSignInScopes,
  browserSignInUnscoped,
  browsingDisabled,
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
import { ControlledBrowser } from "./support/controlled-browser.mjs";
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
  const browser = new ControlledBrowser(fetch);
  const host = await agentHost({ identity, fetch, clock, controlledBrowser: browser });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const session = await sessions.start({
    clientId: identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: company.oauthMetadata.issuer,
    tenantId: TENANT,
    company,
  });
  return { clock, fetch, identity, shop, host, sites, company, session, browser };
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


// Extensions declared per request (§3.3, §3.4) ---------------------------------------

test("a Session declares the extensions it uses with the company", async () => {
  const w = await world();
  const session = await new SessionClient({ reactor: w.host.reactor, fetch: w.fetch }).start({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: w.company.oauthMetadata.issuer,
    tenantId: TENANT,
    company: w.company,
  });
  assert.deepEqual(w.company.document.extensions.operations, [{ version: "2" }]);
  assert.equal(companyExtension(w.company.document, "operations", "2")?.version, "2");
  assert.deepEqual(session.extensions, { operations: "2", links: "1", disclosures: "1", "mediated-sign-in": "1" });
  const headers = await sessionHeaders(w.host.reactor, "GET", "https://manzanita.example/api/orders", { session });
  // Mediated Sign-In is recognized from its grant: used, never declared (§3.3).
  assert.equal(headers["Poppy-Extensions"], '"disclosures";v="1", "links";v="1", "operations";v="2"');
  assert.ok(!("extensions" in w.identity.metadata));
  assert.deepEqual(PapSession.fromJson(session.toJson()).extensions, session.extensions);
  // The company reads the declaration per request: a Session declaring nothing gets no extension content.
  const plain = new PapSession({ ...session, clientId: w.identity.clientId, extensions: {} });
  const conversations = new ConversationClient({ reactor: w.host.reactor, transport: new SessionFetchClient({ reactor: w.host.reactor, fetch: w.fetch }) });
  const page = await conversations.start(CONVERSATIONS, { id: "req_plain_000000000000", author: { type: "human" }, text: "Where is my order?" }, { session: plain, wait: 0 });
  const replies = page.events.filter((e) => e.message?.role === "company").map((e) => e.message);
  assert.ok(replies.length > 0 && replies.every((reply) => reply.extensions === undefined));
  assert.deepEqual(negotiateExtensions({ operations: [{ version: "1" }] }), {});
  assert.deepEqual(negotiateExtensions({ operations: [{ version: "1" }, { version: "2" }] }), { operations: "2" });
  assert.equal(formatExtensionsHeader({}), undefined);
  assert.deepEqual(parseExtensionsHeader('"operations";v="2", "links";v="1"'), { operations: "2", links: "1" });
  assert.deepEqual(parseExtensionsHeader('"operations"'), {});
});


// Conversations across versions (§8.2) ---------------------------------------------

test("a conversation not carried over to other versions is version_mismatch", async () => {
  const w = await world(new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: [PROTOCOL_PROFILE, "0.0"] }));
  const conversations = new ConversationClient({ reactor: w.host.reactor, transport: new SessionFetchClient({ reactor: w.host.reactor, fetch: w.fetch }) });
  // Started in "0.0", by hand; the client's Session is in this SDK's version.
  const headers = await sessionHeaders(w.host.reactor, "POST", CONVERSATIONS, { session: w.session });
  const started = await w.fetch(CONVERSATIONS, {
    method: "POST",
    headers: { ...headers, "Poppy-Version": "0.0", "Content-Type": "application/json" },
    body: JSON.stringify({ id: "req_started_in_0_0_0000", message: { author: { type: "human" }, text: "Hi" } }),
  });
  assert.equal(started.status, 201);
  const { conversation_id: conversationId } = await started.json();
  const record = await w.shop.conversationRecord(conversationId);
  // What the request declared (§3.4): the Session's extensions, Mediated Sign-In never declared.
  assert.deepEqual([record.protocolVersion, record.extensions], ["0.0", parseExtensionsHeader(headers["Poppy-Extensions"])]);
  // Carried over by default: a message from this SDK's version is accepted.
  const accepted = await conversations.send(CONVERSATIONS, conversationId, { id: "req_carried_000000000000", author: { type: "human" }, text: "Still there?" }, { session: w.session });
  assert.equal(accepted.conversation_id, conversationId);
  // Not carried over: messages, handoffs and cancels are version_mismatch; reads are not.
  w.sites["manzanita.example"] = manzanita({
    fetch: w.fetch,
    clock: w.clock,
    config: new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: [PROTOCOL_PROFILE, "0.0"], conversationCarryOver: false }),
    store: w.shop.store,
  }).service;
  await assert.rejects(
    conversations.send(CONVERSATIONS, conversationId, { id: "req_refused_000000000000", author: { type: "human" }, text: "And now?" }, { session: w.session }),
    (error) => error.code === "version_mismatch" && error.statusCode === 409 && error.details.protocol_version === "0.0",
  );
  await assert.rejects(conversations.handoff(CONVERSATIONS, conversationId, { session: w.session }), (error) => error.code === "version_mismatch");
  const page = await conversations.readEvents(CONVERSATIONS, conversationId, { session: w.session });
  assert.ok(page.conversation_id === conversationId && page.events.length > 0);
  // A Session in the versions it started in finishes it.
  const again = await w.fetch(`${CONVERSATIONS}/${conversationId}/close`, {
    method: "POST",
    headers: { ...(await sessionHeaders(w.host.reactor, "POST", `${CONVERSATIONS}/${conversationId}/close`, { session: w.session })), "Poppy-Version": "0.0", "Content-Type": "application/json" },
    body: JSON.stringify({ id: "req_close_in_0_0_000000" }),
  });
  assert.equal(again.status, 202);
});

// Browser join scope and website flags (§3.1, §4.7, §6) ------------------------------------------

/** Ada signs Atlas in with Device Sign-In for `scopes`: the access token. */
async function deviceToken(w, scopes) {
  const metadata = w.company.oauthMetadata;
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    issuer: metadata.issuer,
    clientId: w.identity.clientId,
    scopes,
    tenantId: TENANT,
    organization: w.company.document.organization,
    protectedResources: metadata.protected_resources,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return done.token;
}

test("a signed-in browser join needs the poppy:browser-sign-in scope", async () => {
  // A Company listing browser_session_endpoint with sign-in offers the scope and refuses a
  // signed-in join without it with insufficient_scope naming it; the agent then joins signed out,
  // or gets the scope and joins signed in (§4.7, §6).
  const w = await world();
  const { document, oauthMetadata: metadata } = w.company;
  assert.ok(metadata.scopes_supported.includes(BROWSER_SIGN_IN_SCOPE));
  assert.ok(BROWSER_SIGN_IN_SCOPE in document.auth.scopes);
  assert.deepEqual(browserSignInScopes(document), [BROWSER_SIGN_IN_SCOPE]);
  assert.ok(!browserSignInUnscoped(document) && !browsingDisabled(document));
  const endpoint = document.web.browser_session_endpoint;
  const client = new BrowserSessionClient({ reactor: w.host.reactor, transport: new SessionFetchClient({ reactor: w.host.reactor, fetch: w.fetch }) });
  const cookie = () => w.browser.cookies.get("manzanita.example")?.get("__Host-poppy_session");

  const without = await deviceToken(w, ["orders:read"]);
  await assert.rejects(
    client.join({ browserSessionEndpoint: endpoint, session: w.session, token: without }),
    (error) => error.code === "insufficient_scope" && error.statusCode === 403 && error.details.scope === BROWSER_SIGN_IN_SCOPE,
  );
  // The refusal names the scope in its challenge.
  const page = await w.fetch(endpoint, { method: "GET" });
  const code = /name="code" value="([^"]+)"/.exec(await page.text())[1];
  const url = `${endpoint}/authorize`;
  const refused = await w.fetch(url, {
    method: "POST",
    headers: { ...(await sessionHeaders(w.host.reactor, "POST", url, { session: w.session, token: without })), "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  assert.equal(refused.status, 403);
  assert.ok(refused.headers.get("www-authenticate").includes(`scope="${BROWSER_SIGN_IN_SCOPE}"`));
  // The agent can join signed out instead.
  await client.join({ browserSessionEndpoint: endpoint, session: w.session });
  assert.equal((await w.shop.webSession(cookie())).accountId, undefined);
  // With the scope, the join is signed in.
  const withScope = await deviceToken(w, ["orders:read", BROWSER_SIGN_IN_SCOPE]);
  await client.join({ browserSessionEndpoint: endpoint, session: w.session, token: withScope });
  assert.equal((await w.shop.webSession(cookie())).accountId, "acct_ada");
  // The protocol's scope is never one of the company's own.
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, scopes: [...CONFIG.scopes, BROWSER_SIGN_IN_SCOPE] }), RangeError);
});

test("web.unscoped and web.disabled are published and read", async () => {
  // web.unscoped describes poppy:browser-sign-in as full access, hints it as irreversible and
  // needs the endpoint; web.disabled lists no endpoint and asks agents not to browse; a document
  // breaking either rule is refused (§3.1, §6).
  const clock = new MutableClock();
  let { service } = manzanita({ fetch: inProcessFetch({}), clock, config: new CompanyConfig({ ...CONFIG_OPTIONS, web: true, webUnscoped: true }) });
  let document = service.discoveryDocument();
  assert.deepEqual(document.web, { browser_session_endpoint: "https://manzanita.example/poppy/browser-session", unscoped: true });
  assert.equal(document.auth.scopes[BROWSER_SIGN_IN_SCOPE], "Use the website as you, with full access to your account");
  assert.deepEqual(document.auth.scope_hints[BROWSER_SIGN_IN_SCOPE], { changes: "irreversible", personal_data: true });
  let parsed = parseDiscoveryDocument(document);
  assert.ok(browserSignInUnscoped(parsed));
  assert.deepEqual(browserSignInScopes(parsed), [BROWSER_SIGN_IN_SCOPE]);
  ({ service } = manzanita({ fetch: inProcessFetch({}), clock, config: new CompanyConfig({ ...CONFIG_OPTIONS, web: false, webDisabled: true }) }));
  document = service.discoveryDocument();
  assert.deepEqual(document.web, { disabled: true });
  assert.ok(!(BROWSER_SIGN_IN_SCOPE in document.auth.scopes));
  parsed = parseDiscoveryDocument(document);
  assert.ok(browsingDisabled(parsed));
  assert.deepEqual(browserSignInScopes(parsed), []);
  for (const web of [{ disabled: true, browser_session_endpoint: "https://example.com/j" }, { unscoped: true }]) {
    assert.throws(() => parseDiscoveryDocument({ ...document, web }));
  }
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, web: true, webDisabled: true }), RangeError);
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, web: false, webUnscoped: true }), RangeError);
});
