/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The reference company's rules of draft 0.3, each with the personal agent's view of it:
// the port of personal_agent_protocol/__tests__/test_company_rules.py.
//
// A Session signed in on each request (§5.4); what continues after sign-out (§5.5,
// Operations 3); Mediated Sign-In's errors, as OAuth errors of its grant; conversation
// requests (§8.2 to §8.13); a company ending a Session (§5.5); browser join (§6);
// `extension_required` at an API (§3.3).
import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiClient,
  ApiError,
  BrowserSessionClient,
  ConversationClient,
  ConversationError,
  DeviceSignInClient,
  MEDIATED_GRANT,
  MediatedSignInClient,
  RefreshTokenClient,
  SessionClient,
  SessionFetchClient,
  discoverCompany,
  mediatedSignIn,
  parseConversationEventPage,
} from "../../lib/index.js";
import { CompanyApis, CompanyConfig, JOIN_COOKIE, OperationExecutors, SignInRefused, WEB_COOKIE } from "../../lib/server.js";
import { ADA, ADA_CODE, CONFIG_OPTIONS, manzanita } from "../../lib/demo/manzanita.js";
import { ControlledBrowser } from "./support/controlled-browser.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const SHOP = "https://manzanita.example";
const ORDERS = `${SHOP}/api/orders`;
const EXCHANGE = `${ORDERS}/ord_7Hk2/exchanges`;
const JOIN = `${SHOP}/poppy/browser-session`;

async function world({ answers = [], extensions, config, plugins, controlled = false } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas", ...(extensions ? { extensions } : {}) });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock, ...(config ? { config } : {}), ...(plugins ? { plugins } : {}) });
  sites["manzanita.example"] = shop;
  const controlledBrowser = controlled ? new ControlledBrowser(fetch) : undefined;
  const host = await agentHost({ identity, fetch, clock, answers, ...(controlledBrowser ? { controlledBrowser } : {}) });
  const transport = new SessionFetchClient({ reactor: host.reactor, fetch });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const context = {
    tokenEndpoint: metadata.token_endpoint,
    revocationEndpoint: metadata.revocation_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    tenantId: TENANT,
  };
  const tokens = new RefreshTokenClient({ reactor: host.reactor, fetch });
  const message = (text) => ({ id: conversations.generateMessageId(), author: { type: "human" }, text });
  const endpoint = company.document.agent.protocols[0].endpoint;
  const postJson = (session, url, body, token) =>
    transport.request("POST", url, { session, token, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  /** The Mediated Sign-In grant, as a personal agent sends it, with `fields` as given. */
  const mediatedGrant = async (fields) => {
    const answer = await fetch(metadata.token_endpoint, {
      method: "POST",
      body: new URLSearchParams({
        grant_type: MEDIATED_GRANT,
        ...fields,
        ...(await sessions.clientAuthentication({ clientId: identity.clientId, issuer: metadata.issuer })),
      }),
    });
    return [answer.status, await answer.json()];
  };
  return {
    clock, fetch, identity, shop, plugin, host, transport, conversations, company, metadata, sessions, sites,
    context, tokens, message, endpoint, postJson, mediatedGrant, controlledBrowser,
    api: new ApiClient({ transport }),
    start: () => sessions.start({ clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tenantId: TENANT }),
  };
}

/** Device Sign-In, the user approving as `accountId`: it names no Session (§5.4). */
async function deviceSignIn(w, accountId) {
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    organization: w.company.document.organization,
    protectedResources: w.metadata.protected_resources,
  });
  assert.deepEqual([started.organizationName, started.organizationDomain], ["Manzanita Outfitters", "manzanita.example"]);
  await w.shop.approveDevice(started.userCode, { accountId });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  return [done.token, done.refreshTokenReference];
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected a refusal");
}

// A Session is signed in on each request (§5.4) ---------------------------------------------

test("a signed-out Session can use another account's token", async () => {
  // A company never refuses an account change in a Session (§5.4: a MAY it doesn't take).
  const w = await world();
  const session = await w.start();
  const [ada, reference] = await deviceSignIn(w, "acct_ada");
  const page = await w.conversations.start(w.endpoint, w.message("Where is my jacket order?"), { session, token: ada, wait: 0 });
  await w.tokens.revoke(reference, { context: w.context });

  // The same Session, signed out since, signs in to acct_bob.
  const [bob] = await deviceSignIn(w, "acct_bob");
  assert.equal((await w.api.call("GET", ORDERS, { session, token: bob })).status, 200);

  // What used acct_ada stays hers: under acct_bob's token it does not exist.
  const hidden = await refusal(w.conversations.readEvents(w.endpoint, page.conversation_id, { session, token: bob }));
  assert.equal(hidden.code, "conversation_not_found");

  // The same account is welcome back.
  const [back] = await deviceSignIn(w, "acct_ada");
  const again = await w.conversations.readEvents(w.endpoint, page.conversation_id, { session, token: back });
  assert.equal(again.conversation_id, page.conversation_id);
});

test("Mediated Sign-In in a Session another account used signs in", async () => {
  const w = await world({ answers: [{ ...ADA }, { code: ADA_CODE }] });
  await w.start();
  const [, reference] = await deviceSignIn(w, "acct_bob");
  await w.tokens.revoke(reference, { context: w.context });
  const mediated = new MediatedSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await mediated.signIn({ company: w.company, clientId: w.identity.clientId, scopes: ["orders:read"], tenantId: "t" });
  assert.equal(started.status, "code_required");
  const done = await mediated.submitCode(started.reference);
  assert.equal(done.status, "complete");
  // The host asked for the credentials naming the company and its issuer (Mediated Sign-In).
  const [asked] = w.host.input.asked;
  assert.deepEqual([asked.companyName, asked.companyDomain, asked.issuer], ["Manzanita Outfitters", "manzanita.example", "https://manzanita.example"]);
});

// After sign-out (§5.5, §8.11, Operations 3) --------------------------------------------

test("after sign-out what used the account stays and asks for sign-in", async () => {
  const w = await world();
  const session = await w.start();
  const [token, reference] = await deviceSignIn(w, "acct_ada");
  const page = await w.conversations.start(w.endpoint, w.message("Where is my jacket order?"), { session, token, wait: 0 });
  const proposed = await w.api.call("POST", EXCHANGE, { session, token, body: {} });
  assert.ok(proposed.operation);
  await w.tokens.revoke(reference, { context: w.context });
  // The sign-in's access tokens went with it: the agent finds out, and goes on signed out.
  const revoked = await refusal(w.conversations.readEvents(w.endpoint, page.conversation_id, { session, token }));
  assert.ok(revoked instanceof ConversationError);
  assert.deepEqual([revoked.code, revoked.statusCode], ["invalid_token", 401]);
  // The conversation stays open, and a request on it without a token gets the challenge.
  assert.notEqual((await w.shop.conversationRecord(page.conversation_id)).status, "closed");
  const read = await refusal(w.conversations.readEvents(w.endpoint, page.conversation_id, { session }));
  assert.ok(read instanceof ConversationError);
  assert.deepEqual([read.code, read.statusCode], ["insufficient_scope", 401]);
  // The operation belongs to the account: signed out, the same Session is asked to sign in.
  const { operation } = proposed;
  const approval = { operation_id: operation.operation_id, revision: operation.revision };
  const op = await refusal(w.api.call("POST", EXCHANGE, { session, body: {}, approval }));
  assert.ok(op instanceof ApiError);
  assert.deepEqual([op.code, op.statusCode], ["insufficient_scope", 401]);
  // Signed in again to the same account, the Session continues both.
  const [back] = await deviceSignIn(w, "acct_ada");
  const again = await w.conversations.readEvents(w.endpoint, page.conversation_id, { session, token: back });
  assert.equal(again.conversation_id, page.conversation_id);
  // Another account never learns it exists: as if the approval weren't there.
  const stranger = await w.start();
  const [bob] = await deviceSignIn(w, "acct_bob");
  const hidden = await w.api.call("POST", EXCHANGE, { session: stranger, token: bob, body: {}, approval });
  assert.ok(hidden.operation);
  assert.notEqual(hidden.operation.operation_id, operation.operation_id);
  assert.deepEqual(w.plugin.executor.performed, []);
  const done = await w.api.call("POST", EXCHANGE, { session, token: back, body: {}, approval });
  assert.equal(done.status, 200);
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
});

test("an operation returned signed out is approved only in that Session, and signing in changes nothing", async () => {
  const performed = [];
  const notes = {
    description: "Notes",
    openapi: () => ({}),
    handle: async () => ({ operation: { action: "orders.note", summary: "Add a note." } }),
  };
  const executor = {
    action: "orders.note",
    perform: async (operation, accountId) => {
      assert.equal(accountId, undefined);
      performed.push(operation.operation_id);
      return { summary: "Noted." };
    },
  };
  const w = await world({
    plugins: [{
      name: "notes",
      version: "1",
      contributes: [
        { point: CompanyApis, value: notes, options: { id: "notes", order: -1 } },
        { point: OperationExecutors, value: executor, options: { id: "note" } },
      ],
    }],
  });
  const session = await w.start();
  const other = await w.start();
  const url = `${SHOP}/api/notes`;
  const answered = await w.api.call("POST", url, { session, body: {} });
  assert.equal(answered.status, 403);
  const { operation } = answered;
  const approval = { operation_id: operation.operation_id, revision: operation.revision };
  // Another Session of the same agent and user: as if it had no approval.
  const elsewhere = await w.api.call("POST", url, { session: other, body: {}, approval });
  assert.notEqual(elsewhere.operation.operation_id, operation.operation_id);
  assert.deepEqual(performed, []);
  const [token] = await deviceSignIn(w, "acct_ada");
  const done = await w.api.call("POST", url, { session, token, body: {}, approval });
  assert.equal(done.status, 200);
  assert.deepEqual(performed, [operation.operation_id]);
});

// Mediated Sign-In's errors --------------------------------------------------------------------

test("a failed or expired Mediated Sign-In stays so, and an unknown one is invalid_grant", async () => {
  const w = await world();
  const [status, started] = await w.mediatedGrant({ ...ADA, scope: "orders:read" });
  assert.equal(status, 400);
  assert.deepEqual(Object.keys(started).sort(), ["error", "expires_in", "sent_to", "sign_in_id"]);
  assert.equal(started.error, "code_required");
  assert.equal(started.sent_to, "a•••@example.com");
  assert.equal(started.expires_in, 300);
  const errors = [];
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const [code, answer] = await w.mediatedGrant({ sign_in_id: started.sign_in_id, one_time_code: "000000" });
    assert.equal(code, 400);
    errors.push(answer.error);
  }
  assert.deepEqual(errors, ["code_required", "code_required", "invalid_grant", "invalid_grant"]);
  // Even the right code: once failed, the same error again.
  assert.deepEqual(await w.mediatedGrant({ sign_in_id: started.sign_in_id, one_time_code: ADA_CODE }), [400, { error: "invalid_grant" }]);

  const [, expiring] = await w.mediatedGrant({ ...ADA, scope: "orders:read" });
  w.clock.advance(6 * 60);
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assert.deepEqual(await w.mediatedGrant({ sign_in_id: expiring.sign_in_id, one_time_code: ADA_CODE }), [400, { error: "expired_token" }]);
  }
  assert.deepEqual(await w.mediatedGrant({ sign_in_id: "sgn_unknown", one_time_code: ADA_CODE }), [400, { error: "invalid_grant" }]);
  assert.deepEqual(await w.mediatedGrant({ ...ADA, scope: "orders:everything" }), [400, { error: "invalid_scope" }]);
});

test("only the client that started a Mediated Sign-In can finish it", async () => {
  const w = await world();
  const [, started] = await w.mediatedGrant({ ...ADA, scope: "orders:read" });
  const other = await agentIdentity({ domain: "other.example", name: "Other" });
  w.sites["other.example"] = other.documents;
  const host = await agentHost({ identity: other, fetch: w.fetch, clock: w.clock });
  const sessions = new SessionClient({ reactor: host.reactor, fetch: w.fetch });
  const answer = await w.fetch(w.metadata.token_endpoint, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: MEDIATED_GRANT,
      sign_in_id: started.sign_in_id,
      one_time_code: ADA_CODE,
      ...(await sessions.clientAuthentication({ clientId: other.clientId, issuer: SHOP })),
    }),
  });
  assert.deepEqual([answer.status, await answer.json()], [400, { error: "invalid_grant" }]);
  const [status, finished] = await w.mediatedGrant({ sign_in_id: started.sign_in_id, one_time_code: ADA_CODE });
  assert.equal(status, 200);
  assert.ok(finished.refresh_token);
});

test("a Mediated continuation takes no credentials or scope", async () => {
  const w = await world();
  const [, started] = await w.mediatedGrant({ ...ADA, scope: "orders:read" });
  for (const extra of [{ scope: "orders:write" }, { password: ADA.password }]) {
    assert.deepEqual(
      await w.mediatedGrant({ sign_in_id: started.sign_in_id, one_time_code: ADA_CODE, ...extra }),
      [400, { error: "invalid_request" }],
    );
  }
  assert.deepEqual(await w.mediatedGrant({ sign_in_id: started.sign_in_id }), [400, { error: "invalid_request" }]);
  // A missing field of the first request is the same.
  assert.deepEqual(await w.mediatedGrant({ email: ADA.email, scope: "orders:read" }), [400, { error: "invalid_request" }]);
});

test("the company grants only the extension's scopes", async () => {
  const w = await world({ config: { mediatedScopes: ["orders:read"] } });
  assert.deepEqual([...mediatedSignIn(w.company).scopes], ["orders:read"]);
  assert.deepEqual(await w.mediatedGrant({ ...ADA, scope: "orders:read orders:write" }), [400, { error: "invalid_scope" }]);
});

test("a company can refuse a Mediated Sign-In with access_denied", async () => {
  const w = await world();
  w.plugin.accounts.authenticate = async () => {
    throw new SignInRefused();
  };
  assert.deepEqual(await w.mediatedGrant({ ...ADA, scope: "orders:read" }), [400, { error: "access_denied" }]);
});

test("Mediated Sign-In attempts are limited: 429 with Retry-After and no body, the password never checked", async () => {
  const w = await world({ config: { maxSignInFailures: 2, maxClientSignInFailures: 4 } });
  const wrong = { email: ADA.email, password: "nope" };
  for (let attempt = 0; attempt < 2; attempt += 1) {
    assert.deepEqual(await w.mediatedGrant({ ...wrong, scope: "orders:read" }), [400, { error: "invalid_grant" }]);
  }
  let asked = 0;
  const check = w.plugin.accounts.authenticate.bind(w.plugin.accounts);
  w.plugin.accounts.authenticate = (...args) => {
    asked += 1;
    return check(...args);
  };
  const locked = await w.fetch(w.metadata.token_endpoint, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: MEDIATED_GRANT,
      ...ADA,
      scope: "orders:read",
      ...(await w.sessions.clientAuthentication({ clientId: w.identity.clientId, issuer: SHOP })),
    }),
  });
  assert.equal(locked.status, 429);
  assert.ok(Number(locked.headers.get("retry-after")) > 0);
  assert.equal(await locked.text(), "");
  assert.equal(asked, 0);
  // Other accounts count against the client's own limit.
  for (const email of ["a@example.com", "b@example.com"]) {
    assert.deepEqual(await w.mediatedGrant({ email, password: "nope", scope: "orders:read" }), [400, { error: "invalid_grant" }]);
  }
  const everyone = await w.fetch(w.metadata.token_endpoint, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: MEDIATED_GRANT,
      email: "c@example.com",
      password: "nope",
      scope: "orders:read",
      ...(await w.sessions.clientAuthentication({ clientId: w.identity.clientId, issuer: SHOP })),
    }),
  });
  assert.equal(everyone.status, 429);
});

test("an extension used by the request needs no client metadata entry", async () => {
  // Plain lists no extension: the grant type says it uses Mediated Sign-In (§3.3).
  const w = await world();
  const plain = await agentIdentity({ domain: "plain.example", name: "Plain", extensions: [] });
  assert.deepEqual(plain.metadata.extensions, {});
  w.sites["plain.example"] = plain.documents;
  const host = await agentHost({ identity: plain, fetch: w.fetch, clock: w.clock, answers: [{ ...ADA }, { code: ADA_CODE }] });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const client = new MediatedSignInClient({ reactor: host.reactor, fetch: w.fetch });
  const started = await client.signIn({ company, clientId: plain.clientId, scopes: ["orders:read"], tenantId: "t" });
  assert.equal(started.status, "code_required");
  const done = await client.submitCode(started.reference);
  assert.equal(done.status, "complete");
  // The company lists the grant and the extension, and no such refusal exists for it.
  assert.ok(company.oauthMetadata.grant_types_supported.includes(MEDIATED_GRANT));
  assert.ok("mediated-sign-in" in company.document.extensions);
});

test("a company cannot publish a reserved Mediated field", () => {
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, mediatedFields: [["client_id", "Client", false]] }), /reserved/);
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, mediatedScopes: ["nothing:here"] }), /mediatedScopes/);
});

// Conversation requests (§8.2 to §8.13) -----------------------------------------------------

test("wait is a whole number of seconds, and a larger one is capped", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  const events = `${w.endpoint}/${page.conversation_id}/events`;
  for (const wait of ["-1", "1.5", "soon", "", "١"]) {
    const refused = await w.transport.request("GET", `${events}?wait=${encodeURIComponent(wait)}`, { session });
    assert.deepEqual([refused.status, await refused.json()], [400, { error: "invalid_request" }], wait);
  }
  const capped = await w.conversations.readEvents(w.endpoint, page.conversation_id, { session, wait: 86_400 });
  assert.equal(capped.conversation_id, page.conversation_id);
  // A malformed message on the POSTs: none of text, data, context.
  const bad = await w.postJson(session, `${w.endpoint}/${page.conversation_id}/messages`, { message: { id: "msg_x", author: { type: "agent" } } });
  assert.deepEqual([bad.status, await bad.json()], [400, { error: "invalid_request" }]);
  // An ID with characters not allowed is malformed, not unknown (§7.2).
  const odd = await w.transport.request("GET", `${w.endpoint}/cnv.bad/events`, { session });
  assert.deepEqual([odd.status, await odd.json()], [400, { error: "invalid_request" }]);
});

test("a message is recorded as sent, and its role is the company's to set", async () => {
  const w = await world();
  const session = await w.start();
  const started = await w.postJson(session, `${w.endpoint}?wait=0`, {
    message: {
      id: "msg_role_sent",
      author: { type: "agent" },
      role: "company",
      text: "Hi",
      data: { order: "ord_1" },
      context: { locale: "en-US" },
    },
  });
  assert.equal(started.status, 201);
  const page = parseConversationEventPage(await started.json());
  const first = page.events[0].message;
  assert.equal(first.role, "user"); // the company ignores a role sent
  assert.equal(first.text, "Hi");
  assert.deepEqual(first.data, { order: "ord_1" });
  assert.deepEqual(first.context, { locale: "en-US" });
  // A message with only context is recorded too.
  const answer = await w.conversations.send(
    w.endpoint,
    page.conversation_id,
    { id: "msg_only_ctx", author: { type: "agent" }, context: { user_available: true } },
    { session, cursor: page.cursor, wait: 0 },
  );
  const recorded = answer.events.filter((event) => event.type === "message").map((event) => event.message);
  assert.equal(recorded[0].id, "msg_only_ctx");
  assert.deepEqual(recorded[0].context, { user_available: true });
  assert.equal(recorded[0].role, "user");
  // The personal agent never sends a role.
  await assert.rejects(
    w.conversations.send(w.endpoint, page.conversation_id, { id: "msg_with_role", author: { type: "agent" }, role: "user", text: "x" }, { session }),
    /role/,
  );
});

test("a repeated handoff and close change nothing", async () => {
  const w = await world({ config: { humansAvailable: true } });
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("A person, please"), { session, wait: 0 });
  const first = await w.conversations.handoff(w.endpoint, page.conversation_id, { session });
  assert.equal(first.responder, "human");
  let count = (await w.shop.conversationRecord(page.conversation_id)).events.length;
  const again = await w.conversations.handoff(w.endpoint, page.conversation_id, { session });
  assert.deepEqual([again.status, again.responder], [first.status, first.responder]);
  assert.equal((await w.shop.conversationRecord(page.conversation_id)).events.length, count);
  const closed = await w.conversations.close(w.endpoint, page.conversation_id, { session });
  count = (await w.shop.conversationRecord(page.conversation_id)).events.length;
  const closedAgain = await w.conversations.close(w.endpoint, page.conversation_id, { session });
  assert.deepEqual(closedAgain, closed);
  assert.equal(closed.status, "closed");
  assert.equal((await w.shop.conversationRecord(page.conversation_id)).events.length, count);
});

test("Last-Event-ID wins over cursor on a stream", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  await w.conversations.close(w.endpoint, page.conversation_id, { session });
  const ids = page.events.map((event) => event.id);
  const response = await w.transport.request("GET", `${w.endpoint}/${page.conversation_id}/events?cursor=${ids[0]}`, {
    session,
    headers: { Accept: "text/event-stream", "Last-Event-ID": ids.at(-1) },
  });
  const streamed = (await response.text())
    .split("\n")
    .filter((line) => line.startsWith("data:") && line.includes('"type"'))
    .map((line) => JSON.parse(line.slice(5)).id);
  // Only what follows Last-Event-ID; the cursor (the first event) is ignored.
  assert.ok(streamed.length > 0);
  assert.ok(!streamed.includes(ids[1]));
  assert.notEqual(streamed.at(-1), ids.at(-1));
});

test("a read without its fields is refused", () => {
  const base = { conversation_id: "cnv_1", events: [], cursor: "evt_1", has_more: false, status: "idle", responder: "agent" };
  assert.deepEqual(parseConversationEventPage(base).events, []);
  for (const missing of ["conversation_id", "events"]) {
    const { [missing]: _gone, ...rest } = base;
    assert.throws(() => parseConversationEventPage(rest));
  }
});

// A company ending a Session (§5.5) ---------------------------------------------------------

test("a company ending a Session, and the personal agent starting a new one", async () => {
  const w = await world();
  const captured = [];
  const handle = w.shop.handle.bind(w.shop);
  w.shop.handle = async (request) => {
    const answer = await handle(request);
    captured.push(answer);
    return answer;
  };
  const session = await w.start();
  const ended = session.sid;
  await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  assert.equal(await w.shop.endSession(session.clientId, ended), true);
  captured.length = 0;

  // `invalid_session`, HTTP 400, JSON; the request sent once more with a new `sid`.
  await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  assert.deepEqual(captured.map((answer) => answer.status), [400, 201]);
  assert.deepEqual(captured[0].body, { error: "invalid_session" });
  assert.notEqual(session.sid, ended);
});

// Browser join (§6) ------------------------------------------------------------------------

test("the join page: a form with a code, a __Host- cookie, and no way to frame or keep it", async () => {
  const w = await world();
  const page = await w.fetch(JOIN, { method: "GET" });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /<form method="post" action="\/poppy\/browser-session">/);
  assert.match(html, /<input type="hidden" name="code" value="bc_[^"]+">/);
  assert.ok(!html.includes('name="proof"'));
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.match(page.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(page.headers.get("cross-origin-opener-policy"), "same-origin");
  const cookie = page.headers.get("set-cookie");
  assert.ok(cookie.startsWith(`${JOIN_COOKIE}=`));
  for (const attribute of ["Path=/", "Max-Age=60", "Secure", "HttpOnly", "SameSite=Strict"]) assert.ok(cookie.includes(attribute), attribute);
});

test("a browser joins: the cookie acts for the Session, its account and scopes, while they last", async () => {
  const w = await world({ controlled: true });
  const session = await w.start();
  const [token, reference] = await deviceSignIn(w, "acct_ada");
  const joined = await new BrowserSessionClient({ reactor: w.host.reactor, transport: w.transport }).join({
    browserSessionEndpoint: JOIN,
    session,
    token,
  });
  assert.equal(joined.endpoint, JOIN);
  const browser = w.controlledBrowser;
  const web = browser.cookies.get("manzanita.example").get(WEB_COOKIE);
  assert.ok(web);
  assert.equal(browser.cookies.get("manzanita.example").get(JOIN_COOKIE), "");
  const acting = await w.shop.webSession(web);
  assert.deepEqual(
    [acting.sid, acting.accountId, [...acting.scopes], acting.clientId],
    [session.sid, "acct_ada", ["orders:read", "orders:write"], w.identity.clientId],
  );
  // Signed out once its sign-in ends; gone once its Session has.
  await w.tokens.revoke(reference, { context: w.context });
  const out = await w.shop.webSession(web);
  assert.deepEqual([out.sid, out.accountId, out.scopes], [session.sid, undefined, []]);
  await w.shop.endSession(session.clientId, session.sid);
  assert.equal(await w.shop.webSession(web), undefined);
  assert.equal(await w.shop.webSession(web), undefined);
  assert.equal(await w.shop.webSession("nothing"), undefined);
});

test("a signed-out Session can join a browser, and a new sid starts it", async () => {
  const w = await world({ controlled: true });
  const session = await w.start();
  await new BrowserSessionClient({ reactor: w.host.reactor, transport: w.transport }).join({ browserSessionEndpoint: JOIN, session });
  const web = w.controlledBrowser.cookies.get("manzanita.example").get(WEB_COOKIE);
  const acting = await w.shop.webSession(web);
  assert.deepEqual([acting.sid, acting.accountId, acting.scopes], [session.sid, undefined, []]);
});

test("a join code is refused unless issued, unused, authorized, and in its own browser", async () => {
  const w = await world({ controlled: true });
  const session = await w.start();
  const form = (code) => ({ code });
  // A code never issued.
  const unknown = await w.postJson(session, `${JOIN}/authorize`, { code: "bc_never_issued" });
  assert.deepEqual([unknown.status, await unknown.json()], [400, { error: "invalid_request" }]);
  const empty = await w.postJson(session, `${JOIN}/authorize`, {});
  assert.deepEqual([empty.status, await empty.json()], [400, { error: "invalid_request" }]);

  // Not authorized by the agent: no cookie, and the code is used up.
  const browser = w.controlledBrowser;
  const code = (await browser.loadJoinForm(JOIN)).reveal();
  const notAuthorized = await browser.postForm(JOIN, form(code));
  assert.equal(notAuthorized.status, 400);
  assert.equal(browser.cookies.get("manzanita.example").get(WEB_COOKIE), undefined);
  const late = await w.postJson(session, `${JOIN}/authorize`, { code });
  assert.equal(late.status, 400);

  // Authorized twice: the second is refused.
  const twice = (await browser.loadJoinForm(JOIN)).reveal();
  assert.equal((await w.postJson(session, `${JOIN}/authorize`, { code: twice })).status, 204);
  assert.equal((await w.postJson(session, `${JOIN}/authorize`, { code: twice })).status, 400);

  // Another browser, without the cookie, gets nothing, and uses the code up.
  const other = new ControlledBrowser(w.fetch);
  assert.equal((await other.postForm(JOIN, form(twice))).status, 400);
  assert.equal((await browser.postForm(JOIN, form(twice))).status, 400);

  // A code lives 60 seconds.
  const stale = (await browser.loadJoinForm(JOIN)).reveal();
  w.clock.advance(61);
  assert.equal((await w.postJson(session, `${JOIN}/authorize`, { code: stale })).status, 400);

  // Authorizing needs the Session header.
  const fresh = (await browser.loadJoinForm(JOIN)).reveal();
  const bare = await w.fetch(`${JOIN}/authorize`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: fresh }) });
  assert.deepEqual([bare.status, await bare.json()], [400, { error: "invalid_session" }]);
});

test("a join can't outlive the Session it was authorized for", async () => {
  const w = await world({ controlled: true, config: { sessionLifetimeSeconds: 30 } });
  const session = await w.start();
  const browser = w.controlledBrowser;
  const code = (await browser.loadJoinForm(JOIN)).reveal();
  assert.equal((await w.postJson(session, `${JOIN}/authorize`, { code })).status, 204);
  w.clock.advance(31);
  assert.equal((await browser.postForm(JOIN, { code })).status, 400);
});

// extension_required at an API (§3.3) ----------------------------------------------------------

test("extension_required at an API is in the challenge", async () => {
  const w = await world({ extensions: [] });
  const session = await w.start();
  const [token] = await deviceSignIn(w, "acct_ada");
  const response = await w.postJson(session, EXCHANGE, {}, token);
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("www-authenticate"), 'Bearer error="extension_required", extension="operations"');
  const raised = await refusal(w.api.call("POST", EXCHANGE, { session, token, body: {} }));
  assert.ok(raised instanceof ApiError);
  assert.equal(raised.code, "extension_required");
  assert.deepEqual(raised.details, { extension: "operations" });
});
