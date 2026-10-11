// The TypeScript reference company (`./server`), driven by the TypeScript clients in one
// process: the same cases as the Python company's suites.
import assert from "node:assert/strict";
import test from "node:test";

import {
  AccountTokenClient,
  ConversationClient,
  ConversationError,
  DeviceSignInClient,
  DirectSignInClient,
  DpopFetchClient,
  DpopProofProviders,
  MediatedSignInClient,
  OperationsClient,
  SessionClient,
  approve,
  discoverCompany,
  firstContribution,
  operationsEndpoint,
  parseClientMetadata,
} from "../../lib/index.js";
import { ADA, ADA_CODE, manzanita } from "../../lib/demo/manzanita.js";
import { runJourney } from "./support/journey.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";

async function world({ answers = [], extensions, config } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas", ...(extensions ? { extensions } : {}) });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock, ...(config ? { config } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock, answers });
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: metadata.issuer };
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const start = (pairwiseUserId = PAIRWISE) =>
    sessions.start({ clientId: identity.clientId, pairwiseUserId, issuer: metadata.issuer, tokenEndpoint: metadata.token_endpoint, tenantId: TENANT });
  const message = (text) => ({ id: conversations.generateMessageId(), sender: "human", text });
  const endpoint = company.document.agent.protocols[0].endpoint;
  return { clock, fetch, identity, shop, plugin, host, transport, conversations, company, metadata, who, start, message, endpoint, sites };
}

async function directSignIn(w, session, scopes = ["orders:read", "orders:write"], grant) {
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes,
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
    sessionId: session.sessionId,
  });
  const callbackUrl = w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada", ...(grant ? { scopes: grant } : {}) });
  return { client, callbackUrl, result: await client.complete({ callbackUrl }) };
}

test("the shared journey: TypeScript agent and TypeScript company in one process", async () => {
  const clock = new MutableClock(new Date());
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service, plugin } = manzanita({ fetch, clock });
  sites["manzanita.example"] = service;
  const host = await agentHost({ identity, fetch, clock });
  const result = await runJourney({
    reactor: host.reactor,
    fetch,
    browser: host.browser,
    identity,
    company: {
      approveAuthorization: async (requestId, accountId) => service.approveAuthorization(requestId, { accountId }),
      performed: async () => [...plugin.executor.performed],
    },
  });
  assert.equal(result.operation.performed, 1);
});

test("discovery and OAuth metadata publish one issuer on the company's domain", async () => {
  const w = await world();
  assert.equal(w.metadata.issuer, "https://manzanita.example");
  assert.deepEqual(w.metadata.poppy_domains, ["manzanita.example"]);
  assert.equal(w.company.document.auth.mediated.endpoint, "https://manzanita.example/poppy/sign-in");
  assert.equal(w.company.document.apis[0].url, "https://manzanita.example/api/openapi.json");
  assert.deepEqual(w.company.document.extensions.operations, { version: "1", endpoint: "https://manzanita.example/poppy/operations" });
});

test("Device Sign-In paces polling, then signs the Session in; Account Tokens rotate, narrow, revoke", async () => {
  const w = await world();
  const session = await w.start();
  assert.equal(session.signedIn, false);
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
  });
  assert.match(started.userCode, /^[A-Z0-9XY]{4}-[A-Z0-9XY]{4}$/);
  w.clock.advance(started.pollInterval);
  assert.equal((await device.poll(started.reference)).status, "pending");
  w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  assert.equal(done.token.signedIn, true);
  assert.equal(done.token.sessionId, session.sessionId);

  const accounts = new AccountTokenClient({ reactor: w.host.reactor, fetch: w.fetch });
  const context = {
    tokenEndpoint: w.metadata.token_endpoint,
    revocationEndpoint: w.metadata.revocation_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
  };
  const narrowed = await accounts.refresh(done.accountTokenReference, { context, sessionId: session.sessionId, scopes: ["orders:read"] });
  assert.equal(narrowed.status, "signed_in");
  assert.equal(narrowed.rotated, true);
  assert.deepEqual([...narrowed.grantedScopes], ["orders:read"]);
  const wider = await accounts.refresh(done.accountTokenReference, { context, sessionId: session.sessionId, scopes: ["orders:read", "orders:admin"] });
  assert.equal(wider.status, "re_consent_required");
  const revoked = await accounts.revoke(done.accountTokenReference, { context });
  assert.equal(revoked.revoked, true);
  const after = await accounts.refresh(done.accountTokenReference, { context, sessionId: session.sessionId });
  assert.equal(after.status, "signed_out");
});

test("a denied device code is access_denied", async () => {
  const w = await world();
  const session = await w.start();
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const begin = () => device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read"],
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
    sessionId: session.sessionId,
  });
  const started = await begin();
  w.shop.denyDevice(started.userCode);
  w.clock.advance(started.pollInterval);
  await assert.rejects(device.poll(started.reference), (error) => error.code === "access_denied");
});

test("Mediated Sign-In with a one-time code; a wrong code asks again", async () => {
  const w = await world({ answers: [{ ...ADA }, { code: "000000" }, { code: ADA_CODE }] });
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
  assert.equal(started.sentTo, "a•••@example.com");
  const wrong = await mediated.submitCode(started.reference, { token: session, ...w.who });
  assert.equal(wrong.status, "code_required");
  const done = await mediated.submitCode(started.reference, { token: session, ...w.who });
  assert.equal(done.status, "complete");
  assert.deepEqual([...done.grantedScopes], ["orders:read"]);
  assert.deepEqual(w.host.input.asked.map((request) => request.purpose), ["credentials", "one_time_code", "one_time_code"]);
});

test("wrong credentials fail uniformly", async () => {
  const w = await world({ answers: [{ email: ADA.email, password: "nope" }] });
  const session = await w.start();
  const auth = w.company.document.auth;
  const mediated = new MediatedSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const failed = await mediated.signIn({
    mediated: auth.mediated, organization: w.company.document.organization, issuer: auth.issuer,
    scopes: ["orders:read"], token: session, tenantId: TENANT, pairwiseUserId: PAIRWISE,
  });
  assert.equal(failed.status, "failed");
});

test("Direct Sign-In: partial consent, a denial, a code used once, and the consent page", async () => {
  const w = await world();
  const session = await w.start();
  const partial = await directSignIn(w, session, ["orders:read", "orders:write"], ["orders:read"]);
  assert.deepEqual([...partial.result.missingScopes], ["orders:write"]);
  await assert.rejects(partial.client.complete({ callbackUrl: partial.callbackUrl }));
  const write = await w.transport.request("POST", "https://manzanita.example/api/orders/ord_7Hk2/exchanges", {
    ...w.who, token: partial.result.token, headers: { "Content-Type": "application/json" }, body: "{}",
  });
  assert.equal(write.status, 403);
  assert.deepEqual(await write.json(), { error: "insufficient_scope", scope: "orders:write" });

  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint, tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer, clientId: w.identity.clientId, redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read"], tenantId: TENANT, pairwiseUserId: PAIRWISE, sessionId: session.sessionId,
  });
  const denied = w.shop.denyAuthorization(w.host.browser.requestId);
  assert.match(denied, /error=access_denied/);
  await assert.rejects(client.complete({ callbackUrl: denied }), (error) => error.code === "authorization_denied");

  const base = "https://manzanita.example/oauth/authorize";
  const good = `?response_type=code&client_id=${w.identity.clientId}&scope=orders:read&state=s1&code_challenge=c` +
    "&code_challenge_method=S256&redirect_uri=https://atlas.example/oauth/callback";
  const page = await w.fetch(base + good, { method: "GET" });
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  assert.match(page.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  const elsewhere = await w.fetch(base + good.replace("https://atlas.example/oauth/callback", "https://attacker.example/cb"), { method: "GET" });
  assert.equal(elsewhere.status, 400);
  assert.equal(elsewhere.headers.get("location"), null);
  const plain = await w.fetch(base + good.replace("S256", "plain"), { method: "GET" });
  assert.equal(plain.status, 303);
  assert.match(plain.headers.get("location"), /error=invalid_request/);
});

test("the API: signed out says which scope, the OpenAPI description, and a 202 operation", async () => {
  const w = await world();
  const session = await w.start();
  const read = (token) => w.transport.request("GET", "https://manzanita.example/api/orders", { ...w.who, token, headers: { Accept: "application/json" } });
  const out = await read(session);
  assert.equal(out.status, 403);
  assert.deepEqual(await out.json(), { error: "sign_in_required", scope: "orders:read" });
  const openapi = await w.fetch("https://manzanita.example/api/openapi.json", { method: "GET" });
  assert.equal((await openapi.json()).openapi, "3.1.0");
  const { result } = await directSignIn(w, session);
  const proposed = await w.transport.request("POST", "https://manzanita.example/api/orders/ord_7Hk2/exchanges", {
    ...w.who, token: result.token, headers: { "Content-Type": "application/json" }, body: "{}",
  });
  assert.equal(proposed.status, 202);
  const { operation } = await proposed.json();
  assert.equal(operation.state, "proposed");
  assert.equal(operation.url, `https://manzanita.example/operations/${operation.operation_id}`);
  assert.deepEqual(w.plugin.executor.performed, []);
  // The same proposal through another channel is the same operation.
  const again = await w.transport.request("POST", "https://manzanita.example/api/orders/ord_7Hk2/exchanges", {
    ...w.who, token: result.token, headers: { "Content-Type": "application/json" }, body: "{}",
  });
  assert.equal((await again.json()).operation.operation_id, operation.operation_id);
});

test("an agent without the Operations extension is told extension_required", async () => {
  const w = await world({ extensions: [] });
  const session = await w.start();
  const { result } = await directSignIn(w, session);
  const proposed = await w.transport.request("POST", "https://manzanita.example/api/orders/ord_7Hk2/exchanges", {
    ...w.who, token: result.token, headers: { "Content-Type": "application/json" }, body: "{}",
  });
  assert.equal(proposed.status, 403);
  assert.deepEqual(await proposed.json(), { error: "extension_required", extension: "operations" });
});

async function proposeAt(w, token, path) {
  const response = await w.transport.request("POST", `https://manzanita.example/api/orders/ord_7Hk2/${path}`, {
    ...w.who, token, headers: { "Content-Type": "application/json" }, body: "{}",
  });
  assert.equal(response.status, 202);
  return (await response.json()).operation;
}

test("operations: revision races, standing permission refused, failure, unknown outcome, cancel, expiry", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w, session);
  const token = result.token;
  const operations = new OperationsClient({ reactor: w.host.reactor, transport: w.transport });
  const target = operationsEndpoint(w.company.document, parseClientMetadata(w.identity.metadata));

  const exchange = await proposeAt(w, token, "exchanges");
  w.shop.revise(exchange.operation_id, { summary: "Exchange it, USD 75.00 more.", terms: { order_id: "ord_7Hk2", price_difference: { amount: "75.00", currency: "USD" } } });
  const raced = await operations.confirm(target, exchange, { ...w.who, token, approval: await approve(exchange) });
  assert.equal(raced.status, "terms_changed");
  assert.equal(raced.operation.revision, 2);
  assert.ok(raced.changed.includes("price_difference.amount"));

  const returned = await proposeAt(w, token, "returns");
  const failed = await operations.confirm(target, returned, { ...w.who, token, approval: await approve(returned) });
  assert.equal(failed.operation.state, "failed");
  assert.equal(failed.operation.result.data.return_label, "rtn_8Lp3");

  const repair = await proposeAt(w, token, "repairs");
  const unknown = await operations.confirm(target, repair, { ...w.who, token, approval: await approve(repair) });
  assert.equal(unknown.operation.state, "in_progress");
  assert.equal(unknown.retryAfter, 5);
  const settled = w.shop.settle(repair.operation_id, { summary: "The zip was repaired." }, { succeeded: true });
  assert.equal(settled.state, "succeeded");
  assert.equal((await operations.read(target, repair.operation_id, { ...w.who, token })).state, "succeeded");

  const wrap = await proposeAt(w, token, "gift-wrap");
  const cancelled = await operations.cancel(target, wrap.operation_id, { ...w.who, token });
  assert.equal(cancelled.state, "cancelled");
  assert.equal(cancelled.result.summary, "Nothing was changed.");

  const late = await proposeAt(w, token, "gift-wrap");
  w.clock.advance(16 * 60);
  const expired = await operations.read(target, late.operation_id, { ...w.who, token });
  assert.equal(expired.state, "expired");
  assert.deepEqual(w.plugin.giftWrap.performed, []);

  // A Session of another user never sees the operation.
  const stranger = await w.start("usr_somebody_else_000000");
  await assert.rejects(
    operations.read(target, returned.operation_id, { token: stranger, tenantId: TENANT, pairwiseUserId: "usr_somebody_else_000000", issuer: w.who.issuer }),
    (error) => error.code === "operation_not_found",
  );
});

test("standing permission cannot confirm what needs the user's approval", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w, session);
  const exchange = await proposeAt(w, result.token, "exchanges");
  const response = await w.transport.request("POST", `https://manzanita.example/poppy/operations/${exchange.operation_id}/confirm`, {
    ...w.who, token: result.token, headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ revision: 1, approved_by: "standing_permission" }),
  });
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: "user_approval_required" });
});

test("conversations: SSE with text deltas, closing, and a stranger cannot read", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { ...w.who, token: session, wait: 0 });
  assert.equal(page.events.at(-1).message.text, "Hello from Manzanita Outfitters. Ask me about an order.");
  await w.conversations.close(w.endpoint, page.conversation_id, { ...w.who, token: session });
  const items = [];
  for await (const item of w.conversations.stream(w.endpoint, page.conversation_id, { ...w.who, token: session })) items.push(item);
  const deltas = items.filter((item) => item.kind === "text-delta");
  const events = items.filter((item) => item.kind === undefined);
  assert.ok(deltas.length > 0 && deltas.every((delta) => delta.actionable === false));
  assert.equal(events.at(-1).type, "state");
  assert.equal(events.at(-1).status, "closed");

  const other = await w.start("usr_somebody_else_000000");
  await assert.rejects(
    w.conversations.readEvents(w.endpoint, page.conversation_id, { token: other, tenantId: TENANT, pairwiseUserId: "usr_somebody_else_000000", issuer: w.who.issuer }),
    (error) => error instanceof ConversationError && error.code === "conversation_not_found",
  );
});

test("conversations: an idempotent retry, a reused ID, handoff, Direct Conversations, expired cursors", async () => {
  const w = await world();
  const session = await w.start();
  const first = w.message("Hello");
  const page = await w.conversations.start(w.endpoint, first, { ...w.who, token: session, wait: 0 });
  const retried = await w.conversations.start(w.endpoint, first, { ...w.who, token: session, wait: 0 });
  assert.equal(retried.conversation_id, page.conversation_id);
  const conflict = await w.transport.request("POST", w.endpoint, {
    ...w.who, token: session, headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: { ...first, text: "Something else" } }),
  });
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { error: "message_id_conflict" });

  const direct = await w.conversations.start(w.endpoint, w.message("Just us"), { ...w.who, token: session, parentConversationId: page.conversation_id, wait: 0 });
  const blocked = await w.transport.request("POST", `${w.endpoint}/${page.conversation_id}/messages`, {
    ...w.who, token: session, headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: w.message("Still there?") }),
  });
  assert.equal(blocked.status, 409);
  assert.deepEqual(await blocked.json(), { error: "direct_conversation_open", conversation_id: direct.conversation_id });
  await w.conversations.close(w.endpoint, direct.conversation_id, { ...w.who, token: session });
  const parent = await w.conversations.readEvents(w.endpoint, page.conversation_id, { ...w.who, token: session });
  assert.deepEqual(parent.events.slice(-2).map((event) => event.type), ["direct_opened", "direct_closed"]);

  const handed = await w.conversations.handoff(w.endpoint, page.conversation_id, { ...w.who, token: session });
  assert.equal(handed.status, "idle");
  assert.equal(handed.responder, "agent");

  const cursor = parent.events[0].id;
  w.shop.forgetEvents(page.conversation_id, { keep: 1 });
  const gone = await w.transport.request("GET", `${w.endpoint}/${page.conversation_id}/events?cursor=${cursor}`, { ...w.who, token: session });
  assert.equal(gone.status, 410);
  assert.deepEqual(await gone.json(), { error: "cursor_expired" });
});

test("an authorization event, then the signed-in Session continues the conversation", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Where is my jacket order?"), { ...w.who, token: session, wait: 0 });
  assert.deepEqual(page.events.map((event) => event.type), ["message", "message", "authorization"]);
  const { result } = await directSignIn(w, session, ["orders:read"]);
  const narrow = await w.conversations.send(w.endpoint, page.conversation_id, w.message("Exchange it"), { ...w.who, token: result.token, cursor: page.cursor, wait: 0 });
  assert.equal(narrow.events.at(-1).type, "authorization");
  assert.equal(narrow.events.at(-1).error, "insufficient_scope");
  const read = await w.conversations.send(w.endpoint, page.conversation_id, w.message("And my order?"), { ...w.who, token: result.token, cursor: narrow.cursor, wait: 0 });
  assert.equal(read.events.at(-1).message.data.order_id, "ord_7Hk2");
});

test("refusals: no DPoP proof, a replayed proof, a Bearer token, a bad client assertion", async () => {
  const w = await world();
  const session = await w.start();
  const dpop = firstContribution(w.host.reactor, DpopProofProviders, "DPoP");
  const proof = await dpop.create({ method: "GET", url: "https://manzanita.example/api/orders", tenantId: TENANT, subject: PAIRWISE, issuer: w.who.issuer, accessToken: session.accessToken });
  const headers = { Authorization: `DPoP ${session.accessToken.reveal()}`, DPoP: proof.reveal() };
  const once = await w.fetch("https://manzanita.example/api/orders", { method: "GET", headers });
  assert.equal(once.status, 403);
  const replayed = await w.fetch("https://manzanita.example/api/orders", { method: "GET", headers });
  assert.equal(replayed.status, 401);
  assert.deepEqual(await replayed.json(), { error: "invalid_dpop_proof" });
  const noProof = await w.fetch("https://manzanita.example/api/orders", { method: "GET", headers: { Authorization: `DPoP ${session.accessToken.reveal()}` } });
  assert.equal(noProof.status, 401);
  assert.deepEqual(await noProof.json(), { error: "invalid_dpop_proof" });
  const bearer = await w.fetch("https://manzanita.example/api/orders", { method: "GET", headers: { Authorization: `Bearer ${session.accessToken.reveal()}` } });
  assert.equal(bearer.status, 401);
  assert.deepEqual(await bearer.json(), { error: "invalid_token" });
  const form = new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", client_id: w.identity.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: "not-a-jwt" });
  const bad = await w.fetch(w.metadata.token_endpoint, { method: "POST", body: form });
  assert.equal(bad.status, 401);
  assert.deepEqual(await bad.json(), { error: "invalid_client" });
  const unknown = await w.fetch("https://manzanita.example/nowhere", { method: "GET" });
  assert.equal(unknown.status, 404);
});

test("a conversation that used the account stays with it; disconnecting signs Sessions out", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w, session);
  const page = await w.conversations.start(w.endpoint, w.message("Where is my order?"), { ...w.who, token: result.token, wait: 0 });
  assert.equal(page.events.at(-1).message.data.order_id, "ord_7Hk2");
  assert.equal(w.shop.disconnect(w.identity.clientId, "acct_ada"), 1);
  const out = await w.transport.request("GET", `${w.endpoint}/${page.conversation_id}/events`, { ...w.who, token: result.token });
  assert.equal(out.status, 403);
  assert.deepEqual(await out.json(), { error: "sign_in_required" });
  assert.equal(out.headers.get("www-authenticate"), 'DPoP error="sign_in_required"');
  const orders = await w.transport.request("GET", "https://manzanita.example/api/orders", { ...w.who, token: result.token });
  assert.deepEqual(await orders.json(), { error: "sign_in_required", scope: "orders:read" });
});

const DEVICE_PAGE = "https://datalayer.ai/pap/device?slug=orders-helper";
const CONSENT_PAGE = "https://datalayer.ai/pap/consent?slug=orders-helper&request={request_id}";

test("hosted page templates are checked", async () => {
  const { CompanyConfig } = await import("../../lib/server.js");
  const base = { name: "Shop", domain: "shop.example", scopes: ["orders:read"] };
  assert.throws(() => new CompanyConfig({ ...base, consentPage: "https://datalayer.ai/pap/consent" }), /consentPage/);
  assert.throws(() => new CompanyConfig({ ...base, devicePage: "http://datalayer.ai/pap/device" }), /HTTPS/);
});

test("Device Sign-In points at the hosted device page", async () => {
  const w = await world({ config: { devicePage: DEVICE_PAGE } });
  const session = await w.start();
  const started = await new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch }).begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read"],
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
    sessionId: session.sessionId,
  });
  assert.equal(started.verificationUri, DEVICE_PAGE);
  assert.equal(started.verificationUriComplete, `${DEVICE_PAGE}&${new URLSearchParams({ code: started.userCode })}`);
});

test("authorize redirects to the hosted consent page, which reads the request back", async () => {
  const w = await world({ config: { consentPage: CONSENT_PAGE } });
  const session = await w.start();
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const handed = [];
  w.host.browser.open = async (url) => {
    handed.push(await w.fetch(url.reveal(), { method: "GET", redirect: "manual" }));
  };
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
    sessionId: session.sessionId,
  });
  assert.equal(handed[0].status, 303);
  assert.equal(handed[0].headers.get("cache-control"), "no-store");
  const location = new URL(handed[0].headers.get("location"));
  assert.equal(`${location.origin}${location.pathname}`, "https://datalayer.ai/pap/consent");
  assert.equal(location.searchParams.get("slug"), "orders-helper");
  const requestId = location.searchParams.get("request");
  const summary = w.shop.authorizationRequest(requestId);
  assert.deepEqual(w.shop.authorizationRequest(requestId), summary);
  assert.equal(summary.client_name, "Atlas");
  assert.equal(summary.client_domain, "atlas.example");
  assert.deepEqual(summary.scopes, [
    { scope: "orders:read", description: "See your orders" },
    { scope: "orders:write", description: "Exchange and return items" },
  ]);
  assert.match(summary.expires_at, /Z$/);
  assert.deepEqual(Object.keys(summary).sort(), ["client_domain", "client_name", "expires_at", "request_id", "scopes"]);
  const callbackUrl = w.shop.approveAuthorization(requestId, { accountId: "acct_ada" });
  const result = await client.complete({ callbackUrl });
  assert.equal(result.token.signedIn, true);
  assert.throws(() => w.shop.authorizationRequest(requestId));
});

test("an unverified redirect is never sent to the hosted consent page", async () => {
  const w = await world({ config: { consentPage: CONSENT_PAGE } });
  const authorize = (redirectUri, responseType = "code") =>
    `https://manzanita.example/oauth/authorize?${new URLSearchParams({
      response_type: responseType,
      client_id: w.identity.clientId,
      redirect_uri: redirectUri,
      scope: "orders:read",
      state: "s",
      code_challenge: "c".repeat(43),
      code_challenge_method: "S256",
    })}`;
  const refusedPage = await w.fetch(authorize("https://attacker.example/callback"), { method: "GET" });
  assert.equal(refusedPage.status, 400);
  assert.equal(refusedPage.headers.get("location"), null);
  assert.equal(w.shop.store.authorizations.size, 0);
  const back = await w.fetch(authorize("https://atlas.example/oauth/callback", "token"), { method: "GET" });
  assert.equal(back.status, 303);
  assert.ok(back.headers.get("location").startsWith("https://atlas.example/oauth/callback?"));
  assert.equal(w.shop.store.authorizations.size, 0);
});
