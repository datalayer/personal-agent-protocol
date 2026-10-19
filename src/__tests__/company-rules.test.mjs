/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The reference company's rules of draft 0.2, each with the personal agent's view of it:
// the port of personal_agent_protocol/__tests__/test_company_rules.py.
//
// A Session tied to the account it was ever signed in to (§4.4, §4.8); what continues
// after sign-out (§4.9, Operations §3.2); Mediated Sign-In's statuses and errors (§4.7);
// conversation requests (§7.3 to §7.13); DPoP nonces in both shapes (§4.3);
// `extension_required` at an API (§3.3).
import assert from "node:assert/strict";
import test from "node:test";

import {
  AccountTokenClient,
  ApiClient,
  ApiError,
  AuthorizationError,
  ConversationClient,
  ConversationError,
  DeviceSignInClient,
  DpopFetchClient,
  MediatedSignInClient,
  OperationError,
  OperationsClient,
  SessionClient,
  discoverCompany,
  parseConversationEventPage,
} from "../../lib/index.js";
import { ADA, ADA_CODE, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const MEDIATED = "https://manzanita.example/poppy/sign-in";
const ORDERS = "https://manzanita.example/api/orders";
const EXCHANGE = "https://manzanita.example/api/orders/ord_7Hk2/exchanges";

async function world({ answers = [], extensions, config } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas", ...(extensions ? { extensions } : {}) });
  sites["atlas.example"] = identity.documents;
  const { service: shop } = manzanita({ fetch, clock, ...(config ? { config } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock, answers });
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: metadata.issuer };
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const request = { clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tokenEndpoint: metadata.token_endpoint, tenantId: TENANT };
  const context = { ...request, revocationEndpoint: metadata.revocation_endpoint };
  delete context.tokenEndpoint;
  const accountContext = { tokenEndpoint: metadata.token_endpoint, ...context };
  const accounts = new AccountTokenClient({ reactor: host.reactor, fetch });
  const message = (text) => ({ id: conversations.generateMessageId(), sender: "human", text });
  const endpoint = company.document.agent.protocols[0].endpoint;
  const postJson = (token, url, body) =>
    transport.request("POST", url, { token, ...who, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return {
    clock, fetch, identity, shop, host, transport, conversations, company, metadata, who, sessions, request,
    context: accountContext, accounts, message, endpoint, postJson,
    start: () => sessions.start(request),
    renew: (sessionId) => sessions.renew({ ...request, sessionId }),
  };
}

/** Device Sign-In of `session`, the user approving as `accountId`: [token, reference, error]. */
async function deviceSignIn(w, session, accountId) {
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
    sessionId: session.sessionId,
    organization: w.company.document.organization,
    poppyDomains: w.metadata.poppy_domains,
  });
  assert.deepEqual([started.organizationName, started.organizationDomain], ["Manzanita Outfitters", "manzanita.example"]);
  await w.shop.approveDevice(started.userCode, { accountId });
  w.clock.advance(started.pollInterval);
  try {
    const done = await device.poll(started.reference);
    return [done.token, done.accountTokenReference, undefined];
  } catch (error) {
    if (error instanceof AuthorizationError) return [undefined, undefined, error];
    throw error;
  }
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected a refusal");
}

// A Session stays tied to its account (§4.4, §4.8) -----------------------------------------

test("a signed-out Session is never signed in to another account", async () => {
  const w = await world();
  const session = await w.start();
  const [token, reference] = await deviceSignIn(w, session, "acct_ada");
  assert.ok(token && reference);
  await w.accounts.revoke(reference, { context: w.context });
  const renewed = await w.renew(session.sessionId);
  assert.equal(renewed.signedIn, false); // it continues signed out (§4.9)

  // Signed out since, it is still tied to acct_ada: the device poll issues nothing.
  const [other, otherReference, refused] = await deviceSignIn(w, renewed, "acct_bob");
  assert.equal(other, undefined);
  assert.equal(otherReference, undefined);
  assert.equal(refused?.code, "account_mismatch");
  assert.equal(refused?.statusCode, 400);

  // An Account Token for acct_bob, from another Session, is refused here too.
  const fresh = await w.start();
  const [bob, bobReference] = await deviceSignIn(w, fresh, "acct_bob");
  assert.ok(bob && bobReference);
  const mismatch = await refusal(w.accounts.refresh(bobReference, { context: w.context, sessionId: session.sessionId }));
  assert.equal(mismatch.code, "account_mismatch");

  // The same account is welcome back.
  const [back, , none] = await deviceSignIn(w, renewed, "acct_ada");
  assert.equal(none, undefined);
  assert.equal(back.sessionId, session.sessionId);
});

test("Mediated Sign-In of a Session tied to another account is account_mismatch", async () => {
  const w = await world({ answers: [{ ...ADA }] });
  let session = await w.start();
  const [, reference] = await deviceSignIn(w, session, "acct_bob");
  await w.accounts.revoke(reference, { context: w.context });
  session = await w.renew(session.sessionId);
  const auth = w.company.document.auth;
  const raised = await refusal(
    new MediatedSignInClient({ reactor: w.host.reactor, fetch: w.fetch }).signIn({
      mediated: auth.mediated,
      organization: w.company.document.organization,
      issuer: auth.issuer,
      scopes: ["orders:read"],
      token: session,
      tenantId: TENANT,
      pairwiseUserId: PAIRWISE,
    }),
  );
  assert.ok(raised instanceof AuthorizationError);
  assert.deepEqual([raised.code, raised.statusCode], ["account_mismatch", 400]);
  // The host asked for the credentials naming the company and its issuer (§4.7).
  const [asked] = w.host.input.asked;
  assert.deepEqual([asked.companyName, asked.companyDomain, asked.issuer], ["Manzanita Outfitters", "manzanita.example", "https://manzanita.example"]);
});

// After sign-out (§4.9, §7.11, Operations §3.2) ---------------------------------------------

test("after sign-out what used the account stays and asks for sign-in", async () => {
  const w = await world();
  const session = await w.start();
  const [token, reference] = await deviceSignIn(w, session, "acct_ada");
  const page = await w.conversations.start(w.endpoint, w.message("Where is my jacket order?"), { token, wait: 0, ...w.who });
  const proposed = await new ApiClient({ transport: w.transport }).call("POST", EXCHANGE, { token, body: {}, ...w.who });
  assert.ok(proposed.operation);
  await w.accounts.revoke(reference, { context: w.context });
  const signedOut = await w.renew(session.sessionId);
  // The conversation stays open, and a signed-out token on it gets sign_in_required.
  assert.notEqual((await w.shop.conversationRecord(page.conversation_id)).status, "closed");
  const read = await refusal(w.conversations.readEvents(w.endpoint, page.conversation_id, { token: signedOut, ...w.who }));
  assert.ok(read instanceof ConversationError);
  assert.deepEqual([read.code, read.statusCode], ["sign_in_required", 403]);
  // The operation belongs to the account: signed out, the same Session is asked to sign in.
  const operations = new OperationsClient({ reactor: w.host.reactor, transport: w.transport });
  const ops = w.shop.config.operationsEndpoint;
  const op = await refusal(operations.read(ops, proposed.operation.operation_id, { token: signedOut, ...w.who }));
  assert.ok(op instanceof OperationError);
  assert.deepEqual([op.code, op.statusCode], ["sign_in_required", 403]);
  // Signed in again to the same account, the Session continues both.
  const [back] = await deviceSignIn(w, signedOut, "acct_ada");
  const again = await w.conversations.readEvents(w.endpoint, page.conversation_id, { token: back, ...w.who });
  assert.equal(again.conversation_id, page.conversation_id);
  const current = await operations.read(ops, proposed.operation.operation_id, { token: back, ...w.who });
  assert.equal(current.operation_id, proposed.operation.operation_id);
  // Another account's Session never learns it exists.
  const [bob] = await deviceSignIn(w, await w.start(), "acct_bob");
  const hidden = await refusal(operations.read(ops, proposed.operation.operation_id, { token: bob, ...w.who }));
  assert.equal(hidden.code, "operation_not_found");
});

// Mediated Sign-In's statuses and errors (§4.7) ---------------------------------------------

test("a failed or expired Mediated Sign-In stays so, and an unknown one is not found", async () => {
  const w = await world();
  const session = await w.start();
  const started = await w.postJson(session, MEDIATED, { credentials: { ...ADA }, scope: "orders:read" });
  const body = await started.json();
  assert.equal(started.status, 200);
  assert.equal(body.status, "code_required");
  const statuses = [];
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const answer = await w.postJson(session, `${MEDIATED}/${body.sign_in_id}`, { code: "000000" });
    assert.equal(answer.status, 200); // every status comes with HTTP 200
    statuses.push((await answer.json()).status);
  }
  assert.deepEqual(statuses, ["code_required", "code_required", "failed", "failed"]);
  // Even the right code: once failed, the same status again.
  const right = await w.postJson(session, `${MEDIATED}/${body.sign_in_id}`, { code: ADA_CODE });
  assert.deepEqual([right.status, await right.json()], [200, { status: "failed" }]);

  const later = await w.start();
  const expiring = (await (await w.postJson(later, MEDIATED, { credentials: { ...ADA }, scope: "orders:read" })).json()).sign_in_id;
  w.clock.advance(6 * 60);
  const renewed = await w.start();
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const answer = await w.postJson(later, `${MEDIATED}/${expiring}`, { code: ADA_CODE });
    assert.deepEqual([answer.status, await answer.json()], [200, { status: "expired" }]);
  }
  // Unknown, or another Session's: the same 404 sign_in_not_found.
  for (const [token, target] of [[renewed, expiring], [later, "si_unknown"]]) {
    const missing = await w.postJson(token, `${MEDIATED}/${target}`, { code: ADA_CODE });
    assert.deepEqual([missing.status, await missing.json()], [404, { error: "sign_in_not_found" }]);
  }
  const unknownScope = await w.postJson(renewed, MEDIATED, { credentials: { ...ADA }, scope: "orders:everything" });
  assert.deepEqual([unknownScope.status, await unknownScope.json()], [400, { error: "invalid_scope" }]);
});

test("the Mediated Sign-In client reads sign_in_not_found", async () => {
  const w = await world({ answers: [{ ...ADA }, { code: ADA_CODE }] });
  const session = await w.start();
  const auth = w.company.document.auth;
  const mediated = new MediatedSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await mediated.signIn({
    mediated: auth.mediated,
    organization: w.company.document.organization,
    issuer: auth.issuer,
    scopes: ["orders:read"],
    token: session,
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
  });
  assert.equal(started.status, "code_required");
  w.clock.advance(16 * 60); // the company no longer keeps it: expired, and kept ten minutes more
  const gone = await refusal(mediated.submitCode(started.reference, { token: session, ...w.who }));
  assert.ok(gone instanceof AuthorizationError);
  assert.deepEqual([gone.code, gone.statusCode], ["sign_in_not_found", 404]);
  // Both asks named the company and its issuer (§4.7).
  assert.deepEqual(w.host.input.asked.map((asked) => [asked.purpose, asked.issuer]), [
    ["credentials", "https://manzanita.example"],
    ["one_time_code", "https://manzanita.example"],
  ]);
});

// Conversation requests (§7.3 to §7.13) -----------------------------------------------------

test("wait is a whole number of seconds, and a larger one is capped", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { token: session, wait: 0, ...w.who });
  const events = `${w.endpoint}/${page.conversation_id}/events`;
  for (const wait of ["-1", "1.5", "soon", "", "١"]) {
    const refused = await w.transport.request("GET", `${events}?wait=${encodeURIComponent(wait)}`, { token: session, ...w.who });
    assert.deepEqual([refused.status, await refused.json()], [400, { error: "invalid_request" }], wait);
  }
  const capped = await w.conversations.readEvents(w.endpoint, page.conversation_id, { token: session, wait: 86_400, ...w.who });
  assert.equal(capped.conversation_id, page.conversation_id);
  // A malformed message on the POSTs: none of text, data, context.
  const bad = await w.postJson(session, `${w.endpoint}/${page.conversation_id}/messages`, { message: { id: "msg_x", sender: "agent" } });
  assert.deepEqual([bad.status, await bad.json()], [400, { error: "invalid_request" }]);
  // An ID with characters not allowed is malformed, not unknown (§7.2).
  const odd = await w.transport.request("GET", `${w.endpoint}/cnv.bad/events`, { token: session, ...w.who });
  assert.deepEqual([odd.status, await odd.json()], [400, { error: "invalid_request" }]);
});

test("a message is recorded as sent, and its role is the company's to set", async () => {
  const w = await world();
  const session = await w.start();
  const started = await w.postJson(session, `${w.endpoint}?wait=0`, {
    message: {
      id: "msg_role_sent",
      sender: "agent",
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
    { id: "msg_only_ctx", sender: "agent", context: { user_available: true } },
    { token: session, cursor: page.cursor, wait: 0, ...w.who },
  );
  const recorded = answer.events.filter((event) => event.type === "message").map((event) => event.message);
  assert.equal(recorded[0].id, "msg_only_ctx");
  assert.deepEqual(recorded[0].context, { user_available: true });
  assert.equal(recorded[0].role, "user");
  // The personal agent never sends a role.
  await assert.rejects(
    w.conversations.send(w.endpoint, page.conversation_id, { id: "msg_with_role", sender: "agent", role: "user", text: "x" }, { token: session, ...w.who }),
    /role/,
  );
});

test("a repeated handoff and close change nothing", async () => {
  const w = await world({ config: { humansAvailable: true } });
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("A person, please"), { token: session, wait: 0, ...w.who });
  const first = await w.conversations.handoff(w.endpoint, page.conversation_id, { token: session, ...w.who });
  assert.equal(first.responder, "human");
  let count = (await w.shop.conversationRecord(page.conversation_id)).events.length;
  const again = await w.conversations.handoff(w.endpoint, page.conversation_id, { token: session, ...w.who });
  assert.deepEqual([again.status, again.responder], [first.status, first.responder]);
  assert.equal((await w.shop.conversationRecord(page.conversation_id)).events.length, count);
  const closed = await w.conversations.close(w.endpoint, page.conversation_id, { token: session, ...w.who });
  count = (await w.shop.conversationRecord(page.conversation_id)).events.length;
  const closedAgain = await w.conversations.close(w.endpoint, page.conversation_id, { token: session, ...w.who });
  assert.deepEqual(closedAgain, closed);
  assert.equal(closed.status, "closed");
  assert.equal((await w.shop.conversationRecord(page.conversation_id)).events.length, count);
});

test("Last-Event-ID wins over cursor on a stream", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { token: session, wait: 0, ...w.who });
  await w.conversations.close(w.endpoint, page.conversation_id, { token: session, ...w.who });
  const ids = page.events.map((event) => event.id);
  const response = await w.transport.request("GET", `${w.endpoint}/${page.conversation_id}/events?cursor=${ids[0]}`, {
    token: session,
    ...w.who,
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

// DPoP nonces, and extension_required at an API (§3.3, §4.3) -----------------------------------

test("a company requiring nonces, and the personal agent retrying with them", async () => {
  const w = await world({ config: { dpopNonce: true } });
  const captured = [];
  const handle = w.shop.handle.bind(w.shop);
  w.shop.handle = async (request) => {
    const answer = await handle(request);
    captured.push({ path: new URL(request.url).pathname, answer });
    return answer;
  };
  const session = await w.start();
  const tokenEndpoint = captured.filter((item) => item.path === "/oauth/token").map((item) => item.answer);
  // At the token endpoint: an OAuth error, HTTP 400, the nonce in DPoP-Nonce; one retry.
  assert.deepEqual(tokenEndpoint.map((answer) => answer.status), [400, 200]);
  assert.deepEqual(tokenEndpoint[0].body, { error: "use_dpop_nonce" });
  assert.ok(tokenEndpoint[0].headers["DPoP-Nonce"]);
  assert.equal(tokenEndpoint[0].headers["WWW-Authenticate"], undefined);
  // At an API: HTTP 401 with the DPoP challenge and DPoP-Nonce; one retry.
  const raised = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { token: session, ...w.who }));
  assert.ok(raised instanceof ApiError);
  assert.equal(raised.code, "sign_in_required");
  const api = captured.filter((item) => item.path === "/api/orders").map((item) => item.answer);
  assert.deepEqual(api.map((answer) => answer.status), [401, 403]);
  assert.equal(api[0].headers["WWW-Authenticate"], 'DPoP error="use_dpop_nonce"');
  assert.ok(api[0].headers["DPoP-Nonce"]);
  // Device Sign-In's poll retries with the token endpoint's nonce too.
  const [token, , error] = await deviceSignIn(w, session, "acct_ada");
  assert.equal(error, undefined);
  assert.equal(token.signedIn, true);
});

test("extension_required at an API is in the challenge", async () => {
  const w = await world({ extensions: [] });
  const session = await w.start();
  const [token] = await deviceSignIn(w, session, "acct_ada");
  const response = await w.postJson(token, EXCHANGE, {});
  assert.equal(response.status, 403);
  assert.equal(response.headers.get("www-authenticate"), 'DPoP error="extension_required", extension="operations"');
  const raised = await refusal(new ApiClient({ transport: w.transport }).call("POST", EXCHANGE, { token, body: {}, ...w.who }));
  assert.ok(raised instanceof ApiError);
  assert.equal(raised.code, "extension_required");
  assert.deepEqual(raised.details, { extension: "operations" });
});
