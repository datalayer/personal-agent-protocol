/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Release-gate demonstrations, TypeScript agent with the TypeScript Manzanita: the twin of
// personal_agent_protocol/__tests__/test_security_demonstrations.py, one test per property
// of "replay, issuer mix-up, cross-tenant access, stale approval, retries, restart,
// rollback, revocation, and rotation are demonstrated safely". Each runs a real journey in
// one process with real keys, does the unsafe thing, and asserts the safe outcome.
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
  DirectSignInClient,
  DpopFetchClient,
  OperationError,
  OperationsClient,
  SessionClient,
  TokenStores,
  approve,
  discoverCompany,
  firstContribution,
} from "../../lib/index.js";
import { MemoryCompanyStore } from "../../lib/server.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const ORDERS = "https://manzanita.example/api/orders";

/** Atlas with Manzanita; every request recorded; a company that can restart or roll back. */
async function world({ durable = false } = {}) {
  const clock = new MutableClock(new Date());
  const sites = {};
  const network = inProcessFetch(sites);
  const wire = [];
  const lose = { path: undefined };
  const fetch = async (input, init = {}) => {
    const url = String(input instanceof Request ? input.url : input);
    wire.push({ url, init });
    const response = await network(input, init);
    if (lose.path !== undefined && new URL(url).pathname.endsWith(lose.path)) {
      lose.path = undefined;
      throw new TypeError("the answer was lost");
    }
    return response;
  };
  const store = durable ? new MemoryCompanyStore({ clock }) : undefined;
  const w = { clock, sites, network, fetch, wire, lose, store };
  /** Manzanita (re)started over the same store: the default replay cache is in it. */
  w.deploy = async (config) => {
    const { service, plugin } = manzanita({ fetch, clock, ...(store ? { store } : {}), ...(config ? { config } : {}) });
    sites["manzanita.example"] = service;
    w.shop = service;
    w.plugin = plugin;
  };
  await w.deploy();
  w.identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = w.identity.documents;
  w.host = await agentHost({ identity: w.identity, fetch, clock });
  w.transport = new DpopFetchClient({ reactor: w.host.reactor, fetch });
  w.conversations = new ConversationClient({ reactor: w.host.reactor, transport: w.transport });
  w.operations = new OperationsClient({ reactor: w.host.reactor, transport: w.transport });
  w.accounts = new AccountTokenClient({ reactor: w.host.reactor, fetch });
  w.company = await discoverCompany("manzanita.example", { reactor: w.host.reactor });
  w.metadata = w.company.oauthMetadata;
  w.who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: w.metadata.issuer };
  w.endpoint = w.company.document.agent.protocols[0].endpoint;
  w.ops = w.company.document.extensions.operations.endpoint;
  w.context = {
    tokenEndpoint: w.metadata.token_endpoint,
    revocationEndpoint: w.metadata.revocation_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
  };
  w.tokens = firstContribution(w.host.reactor, TokenStores, "token store");
  w.start = (pairwiseUserId = PAIRWISE, reactor = w.host.reactor, clientId = w.identity.clientId) =>
    new SessionClient({ reactor, fetch }).start({
      clientId,
      pairwiseUserId,
      issuer: w.metadata.issuer,
      tokenEndpoint: w.metadata.token_endpoint,
      tenantId: TENANT,
    });
  w.message = (text, id = w.conversations.generateMessageId()) => ({ id, sender: "human", text });
  w.last = (method, path) =>
    [...wire].reverse().find((item) => (item.init.method ?? "GET") === method && new URL(item.url).pathname === path);
  w.resend = (item) => network(item.url, item.init);
  return w;
}

async function probe(w, token, who = w.who) {
  try {
    return (await new ApiClient({ transport: w.transport }).call("GET", ORDERS, { token, ...who })).status;
  } catch (error) {
    if (error instanceof ApiError) return error.statusCode;
    throw error;
  }
}

async function deviceSignIn(w, session) {
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
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return { token: done.token, reference: done.accountTokenReference };
}

async function proposal(w, token) {
  const page = await w.conversations.start(w.endpoint, w.message("Exchange it for something warmer"), { token, wait: 0, ...w.who });
  const operation = page.events.at(-1).message.operation;
  assert.equal(operation.state, "proposed");
  return operation;
}

async function beginDirect(w, session) {
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read"],
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
    sessionId: session.sessionId,
  });
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  return { client, callbackUrl };
}

test("replay is refused", async () => {
  const w = await world();
  const { token } = await deviceSignIn(w, await w.start());
  assert.equal(await probe(w, token), 200);
  const tokenRequest = await w.resend(w.last("POST", "/oauth/token"));
  assert.ok([400, 401].includes(tokenRequest.status), String(tokenRequest.status));
  const read = await w.resend(w.last("GET", "/api/orders"));
  assert.equal(read.status, 401);
  const operation = await proposal(w, token);
  await w.operations.confirm(w.ops, operation, { approval: await approve(operation), token, ...w.who });
  const confirm = await w.resend(w.last("POST", `/poppy/operations/${operation.operation_id}/confirm`));
  assert.equal(confirm.status, 401);
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
  assert.equal(await probe(w, token), 200);
});

test("issuer mix-up is refused", async () => {
  const w = await world();
  const session = await w.start();
  const { client, callbackUrl } = await beginDirect(w, session);
  const iss = encodeURIComponent("https://manzanita.example");
  assert.ok(callbackUrl.includes(`iss=${iss}`));
  const exchanged = w.wire.filter((item) => new URL(item.url).pathname === "/oauth/token").length;
  const mixedUp = callbackUrl.replace(`iss=${iss}`, `iss=${encodeURIComponent("https://northwind.example")}`);
  await assert.rejects(client.complete({ callbackUrl: mixedUp }), (error) => error instanceof AuthorizationError && error.code === "issuer_mismatch");
  assert.equal(w.wire.filter((item) => new URL(item.url).pathname === "/oauth/token").length, exchanged);
  await assert.rejects(client.complete({ callbackUrl }), (error) => error instanceof AuthorizationError && error.code === "invalid_or_expired_state");
  assert.equal(await probe(w, session), 403);
  const again = await beginDirect(w, session);
  const result = await again.client.complete({ callbackUrl: again.callbackUrl });
  assert.equal(await probe(w, result.token), 200);
});

test("cross-tenant access is refused", async () => {
  const w = await world();
  const { token } = await deviceSignIn(w, await w.start());
  const page = await w.conversations.start(w.endpoint, w.message("Where is my jacket order?"), { token, wait: 0, ...w.who });
  const other = { ...w.who, tenantId: "another-tenant" };
  assert.equal(await probe(w, token, other), 401);
  await assert.rejects(
    w.conversations.readEvents(w.endpoint, page.conversation_id, { token, ...other }),
    (error) => error instanceof ConversationError && error.statusCode === 401,
  );
  const stranger = "usr_somebody_else_000000";
  const theirs = await w.start(stranger);
  await assert.rejects(
    w.conversations.readEvents(w.endpoint, page.conversation_id, { token: theirs, ...w.who, pairwiseUserId: stranger }),
    (error) => error instanceof ConversationError && error.code === "conversation_not_found",
  );
  assert.equal(await probe(w, token), 200);
});

test("stale approval is refused", async () => {
  const w = await world();
  const { token } = await deviceSignIn(w, await w.start());
  const operation = await proposal(w, token);
  const stale = await approve(operation);
  await w.shop.revise(operation.operation_id, {
    summary: "Exchange for USD 85.00 more.",
    terms: { order_id: "ord_7Hk2", price_difference: { amount: "85.00", currency: "USD" } },
  });
  const outcome = await w.operations.confirm(w.ops, operation, { approval: stale, token, ...w.who });
  assert.equal(outcome.status, "terms_changed");
  const newer = outcome.operation;
  assert.equal(newer.revision, 2);
  await assert.rejects(
    w.operations.confirm(w.ops, newer, { approval: stale, token, ...w.who }),
    (error) => error instanceof OperationError && error.code === "approval_mismatch",
  );
  assert.deepEqual([...w.plugin.executor.performed], []);
  const done = await w.operations.confirm(w.ops, newer, { approval: await approve(newer), token, ...w.who });
  assert.equal(done.operation.state, "succeeded");
  await assert.rejects(w.operations.confirm(w.ops, operation, { approval: stale, token, ...w.who }), OperationError);
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
});

test("retries are safe", async () => {
  const w = await world();
  const { token } = await deviceSignIn(w, await w.start());
  const message = w.message("Hello", "msg_retry_demo_0000000001");
  const first = await w.conversations.start(w.endpoint, message, { token, ...w.who });
  const again = await w.conversations.start(w.endpoint, message, { token, ...w.who });
  assert.equal(again.conversation_id, first.conversation_id);
  const page = await w.conversations.readEvents(w.endpoint, first.conversation_id, { token, ...w.who });
  assert.equal(page.events.filter((event) => event.message?.id === message.id).length, 1);

  const operation = await proposal(w, token);
  w.lose.path = `/${operation.operation_id}/confirm`;
  const recovered = await w.operations.confirm(w.ops, operation, { approval: await approve(operation), token, ...w.who });
  assert.equal(recovered.status, "confirmed");
  assert.equal(recovered.operation.state, "succeeded");
  const retried = await w.operations.confirm(w.ops, operation, { approval: await approve(operation), token, ...w.who });
  assert.equal(retried.operation.state, "succeeded");
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
});

test("restart is safe", async () => {
  const w = await world({ durable: true });
  const { token } = await deviceSignIn(w, await w.start());
  const operation = await proposal(w, token);
  assert.equal(await probe(w, token), 200);
  const captured = w.last("GET", "/api/orders");
  await w.deploy();
  assert.equal((await w.resend(captured)).status, 401);
  assert.equal(await probe(w, token), 200);
  const done = await w.operations.confirm(w.ops, operation, { approval: await approve(operation), token, ...w.who });
  assert.equal(done.operation.state, "succeeded");
  const performed = [...w.plugin.executor.performed];
  await w.deploy();
  const again = await w.operations.confirm(w.ops, operation, { approval: await approve(operation), token, ...w.who });
  assert.equal(again.operation.state, "succeeded");
  assert.deepEqual(performed, [operation.operation_id]);
  assert.deepEqual([...w.plugin.executor.performed], []);
});

test("rollback is safe", async () => {
  const w = await world({ durable: true });
  const session = await w.start();
  const { reference } = await deviceSignIn(w, session);
  const before = await w.tokens.get(reference);
  const refreshed = await w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId });
  assert.equal(refreshed.rotated, true);
  const rotated = await w.tokens.get(reference);
  const operation = await proposal(w, refreshed.token);
  const done = await w.operations.confirm(w.ops, operation, { approval: await approve(operation), token: refreshed.token, ...w.who });
  assert.equal(done.operation.state, "succeeded");

  // The previous release (no website yet), over the same store (and so its replay cache).
  await w.deploy({ web: false });
  await w.tokens.put(reference, before);
  assert.equal((await w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId })).status, "signed_out");
  await w.tokens.put(reference, rotated);
  const current = await w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId });
  assert.equal(current.status, "signed_in");
  const again = await w.operations.confirm(w.ops, operation, { approval: await approve(operation), token: current.token, ...w.who });
  assert.equal(again.operation.state, "succeeded");
  assert.deepEqual([...w.plugin.executor.performed], []);
  assert.equal(await probe(w, current.token), 200);
});

test("revocation is safe", async () => {
  const w = await world();
  const session = await w.start();
  const { token, reference } = await deviceSignIn(w, session);
  const second = await w.start();
  const other = await w.accounts.refresh(reference, { context: w.context, sessionId: second.sessionId });
  assert.equal(other.status, "signed_in");
  const revoked = await w.accounts.revoke(reference, { context: w.context });
  assert.equal(revoked.revoked, true);
  assert.equal(await probe(w, token), 403);
  assert.equal(await probe(w, other.token), 403);
  assert.equal((await w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId })).status, "signed_out");
  const renewed = await new SessionClient({ reactor: w.host.reactor, fetch: w.fetch }).renew({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: w.metadata.issuer,
    tokenEndpoint: w.metadata.token_endpoint,
    tenantId: TENANT,
    sessionId: session.sessionId,
  });
  assert.equal(renewed.signedIn, false);
  assert.equal(await probe(w, renewed), 403);
});

test("rotation is safe", async () => {
  const w = await world();
  const session = await w.start();
  const { reference } = await deviceSignIn(w, session);
  const first = await w.tokens.get(reference);
  const results = await Promise.all([
    w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId }),
    w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId }),
  ]);
  assert.deepEqual(results.map((r) => [r.status, r.rotated]), [["signed_in", true], ["signed_in", true]]);
  const live = await w.tokens.get(reference);
  assert.notEqual(live.reveal(), first.reveal());
  await w.tokens.put(reference, first);
  assert.equal((await w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId })).status, "signed_out");
  await w.tokens.put(reference, live);
  assert.equal((await w.accounts.refresh(reference, { context: w.context, sessionId: session.sessionId })).status, "signed_in");

  // The agent's signing key: both keys published during the overlap, then the old retired.
  const newer = await agentIdentity({ domain: "atlas.example", name: "Atlas", kid: "key-2" });
  const newerHost = await agentHost({ identity: newer, fetch: w.fetch, clock: w.clock });
  const documents = w.identity.documents;
  documents["/jwks.json"] = { keys: [...w.identity.documents["/jwks.json"].keys, ...newer.documents["/jwks.json"].keys] };
  assert.equal((await w.start(PAIRWISE, newerHost.reactor, newer.clientId)).signedIn, false);
  assert.equal((await w.start()).signedIn, false);
  documents["/jwks.json"] = { keys: [...newer.documents["/jwks.json"].keys] };
  w.clock.advance(24 * 3600);
  await assert.rejects(w.start(), (error) => error.code === "invalid_client");
  assert.equal((await w.start(PAIRWISE, newerHost.reactor, newer.clientId)).signedIn, false);
});
