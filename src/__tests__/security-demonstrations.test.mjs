/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Release-gate demonstrations, TypeScript agent with the TypeScript Manzanita: the twin of
// personal_agent_protocol/__tests__/test_security_demonstrations.py, one test per property
// of "replay, issuer mix-up, cross-tenant access, stale approval, retries, restart,
// rollback, revocation, and rotation are demonstrated safely", then the attacks draft 0.3
// names: on the browser join (§10.6), on Session JWTs and their delegations (§5.2, §10.7),
// on a service's stale metadata (§4.5), and on approvals (Operations). Each runs a real
// journey in one process with real keys, does the unsafe thing, and asserts the safe outcome.
import assert from "node:assert/strict";
import test from "node:test";

import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair } from "jose";

import {
  ApiClient,
  ApiError,
  AuthorizationError,
  BrowserSessionClient,
  ConversationClient,
  ConversationError,
  DeviceSignInClient,
  DirectSignInClient,
  McpClient,
  OperationsClient,
  PapSession,
  RefreshTokenClient,
  SESSION_JWT_ALGORITHM,
  SESSION_JWT_TYPE,
  ServiceTokens,
  SessionClient,
  SessionFetchClient,
  TokenStores,
  delegationClaims,
  discoverCompany,
  firstContribution,
  sessionHeaders,
  sessionJwtClaims,
  staleResourceMetadata,
} from "../../lib/index.js";
import { MemoryCompanyStore, RecordKinds } from "../../lib/server.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { ControlledBrowser } from "./support/controlled-browser.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const STRANGER = "usr_somebody_else_000000";
const ORDERS = "https://manzanita.example/api/orders";
const EXCHANGE = "https://manzanita.example/api/orders/ord_7Hk2/exchanges";
const BROWSER_SESSION = "https://manzanita.example/poppy/browser-session";
const MCP = "https://manzanita.example/mcp";
const HOUR = 3600;

/** Atlas's website, whose key set a demonstration rotates, with a `max-age`. */
function rotatingSite(identity, maxAge) {
  const site = {
    keys: [...identity.jwks.keys],
    async handle(request) {
      const path = new URL(request.url).pathname;
      return {
        status: 200,
        body: path === "/jwks.json" ? { keys: site.keys } : identity.metadata,
        headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${maxAge}` },
      };
    },
  };
  return site;
}

/** Atlas with Manzanita; every request recorded; a company that can restart or roll back. */
async function world({ durable = false, maxAge } = {}) {
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
  w.site = maxAge === undefined ? w.identity.documents : rotatingSite(w.identity, maxAge);
  sites["atlas.example"] = w.site;
  w.browser = new ControlledBrowser(network);
  w.host = await agentHost({ identity: w.identity, fetch, clock, controlledBrowser: w.browser });
  w.transport = new SessionFetchClient({ reactor: w.host.reactor, fetch });
  w.conversations = new ConversationClient({ reactor: w.host.reactor, transport: w.transport });
  w.api = new ApiClient({ transport: w.transport });
  w.operations = new OperationsClient({ reactor: w.host.reactor, sleep: async () => {} });
  w.accounts = new RefreshTokenClient({ reactor: w.host.reactor, fetch });
  w.company = await discoverCompany("manzanita.example", { reactor: w.host.reactor });
  w.metadata = w.company.oauthMetadata;
  w.endpoint = w.company.document.agent.protocols[0].endpoint;
  w.context = {
    tokenEndpoint: w.metadata.token_endpoint,
    revocationEndpoint: w.metadata.revocation_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    tenantId: TENANT,
  };
  w.tokens = firstContribution(w.host.reactor, TokenStores, "token store");
  w.start = (pairwiseUserId = PAIRWISE, reactor = w.host.reactor, clientId = w.identity.clientId) =>
    new SessionClient({ reactor, fetch }).start({ clientId, pairwiseUserId, issuer: w.metadata.issuer, tenantId: TENANT });
  w.message = (text, id = w.conversations.generateMessageId()) => ({ id, author: { type: "human" }, text });
  w.last = (method, path) =>
    [...wire].reverse().find((item) => (item.init.method ?? "GET") === method && new URL(item.url).pathname === path);
  w.resend = (item) => network(item.url, item.init);
  return w;
}

/** Read Ada's orders: 200, or the status the company refused with. */
async function probe(w, session, token) {
  try {
    return (await w.api.call("GET", ORDERS, { session, token })).status;
  } catch (error) {
    if (error instanceof ApiError) return error.statusCode;
    throw error;
  }
}

/** Device Sign-In, Ada approving: the access token and its refresh token's reference. */
async function deviceSignIn(w) {
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
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return { token: done.token, reference: done.refreshTokenReference };
}

/** Ada asks for a warmer jacket: Manzanita returns the exchange, performing nothing. */
async function proposal(w, session, token) {
  const answer = await w.api.call("POST", EXCHANGE, { session, token, body: {} });
  assert.equal(answer.status, 403);
  assert.ok(answer.operation);
  return answer.operation;
}

/** The same request again, with the approval of this revision. */
const approveIt = (w, operation, session, token) =>
  w.api.call("POST", EXCHANGE, {
    session,
    token,
    body: {},
    approval: { operation_id: operation.operation_id, revision: operation.revision },
  });

async function beginDirect(w) {
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read"],
    tenantId: TENANT,
  });
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  return { client, callbackUrl };
}

test("replay is refused", async () => {
  // A captured token request or API call, sent again byte for byte, is refused.
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  assert.equal(await probe(w, session, token), 200);
  // The token request (its client assertion, its device code): each is one-time.
  const tokenRequest = await w.resend(w.last("POST", "/oauth/token"));
  assert.ok([400, 401].includes(tokenRequest.status), String(tokenRequest.status));
  assert.ok(["invalid_client", "invalid_grant"].includes((await tokenRequest.json()).error));
  // The API call: its Session JWT's ID was seen.
  const read = await w.resend(w.last("GET", "/api/orders"));
  assert.equal(read.status, 400);
  assert.deepEqual(await read.json(), { error: "invalid_session" });
  // A request with an approval, replayed, performs nothing more.
  const operation = await proposal(w, session, token);
  await approveIt(w, operation, session, token);
  const approved = await w.resend(w.last("POST", "/api/orders/ord_7Hk2/exchanges"));
  assert.equal(approved.status, 400);
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
  // The agent itself carries on: a fresh Session JWT every time.
  assert.equal(await probe(w, session, token), 200);
});

test("issuer mix-up is refused", async () => {
  const w = await world();
  const session = await w.start();
  const { client, callbackUrl } = await beginDirect(w);
  const iss = encodeURIComponent("https://manzanita.example");
  assert.ok(callbackUrl.includes(`iss=${iss}`));
  const exchanged = w.wire.filter((item) => new URL(item.url).pathname === "/oauth/token").length;
  const mixedUp = callbackUrl.replace(`iss=${iss}`, `iss=${encodeURIComponent("https://northwind.example")}`);
  await assert.rejects(client.complete({ callbackUrl: mixedUp }), (error) => error instanceof AuthorizationError && error.code === "issuer_mismatch");
  assert.equal(w.wire.filter((item) => new URL(item.url).pathname === "/oauth/token").length, exchanged);
  await assert.rejects(client.complete({ callbackUrl }), (error) => error instanceof AuthorizationError && error.code === "invalid_or_expired_state");
  assert.equal(await probe(w, session), 401); // still signed out
  const again = await beginDirect(w);
  const result = await again.client.complete({ callbackUrl: again.callbackUrl });
  assert.equal(await probe(w, session, result.token), 200);
});

test("cross-tenant access is refused", async () => {
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const page = await w.conversations.start(w.endpoint, w.message("Where is my jacket order?"), { session, token, wait: 0 });
  assert.equal(await probe(w, session, token), 200);
  // Another tenant of Atlas has another User ID, and another delegated key (§5.2). Naming
  // Ada's `sid` it is another User in her Session: `invalid_session`, not a way in (§5.3).
  const other = new PapSession({ sid: session.sid, sub: STRANGER, issuer: session.issuer, clientId: session.clientId, tenantId: "another-tenant" });
  const refused = await w.fetch(ORDERS, { method: "GET", headers: await sessionHeaders(w.host.reactor, "GET", ORDERS, { session: other }) });
  assert.equal(refused.status, 400);
  assert.deepEqual(await refused.json(), { error: "invalid_session" });
  const theirs = await w.host.delegatedKeys.current({ tenantId: "another-tenant", issuer: session.issuer, sub: STRANGER });
  const ours = await w.host.delegatedKeys.current({ tenantId: TENANT, issuer: session.issuer, sub: session.sub });
  assert.notEqual(theirs.thumbprint, ours.thumbprint);
  // Another user of the same tenant gets a Session of their own, which sees nothing of Ada's.
  const strangers = await w.start(STRANGER);
  await assert.rejects(
    w.conversations.readEvents(w.endpoint, page.conversation_id, { session: strangers }),
    (error) => error instanceof ConversationError && error.code === "conversation_not_found",
  );
  assert.equal(await probe(w, session, token), 200);
});

test("stale approval is refused", async () => {
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const operation = await proposal(w, session, token);
  await w.shop.revise(operation.operation_id, {
    summary: "Exchange for USD 85.00 more.",
    terms: { order_id: "ord_7Hk2", price_difference: { amount: "85.00", currency: "USD" } },
  });
  // The approval of the replaced revision performs nothing: the new one comes back.
  const newer = (await approveIt(w, operation, session, token)).operation;
  assert.equal(newer.operation_id, operation.operation_id);
  assert.notEqual(newer.revision, operation.revision);
  assert.ok(newer.summary.startsWith("Exchange for USD 85"));
  assert.deepEqual([...w.plugin.executor.performed], []);
  const done = await approveIt(w, newer, session, token);
  assert.equal(done.status, 200);
  // The approval of the first revision, presented once more, gets the response given.
  const late = await approveIt(w, operation, session, token);
  assert.deepEqual(late.body, done.body);
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
});

test("retries are safe", async () => {
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const message = w.message("Hello", "msg_retry_demo_0000000001");
  const first = await w.conversations.start(w.endpoint, message, { session, token });
  const again = await w.conversations.start(w.endpoint, message, { session, token });
  assert.equal(again.conversation_id, first.conversation_id);
  const page = await w.conversations.readEvents(w.endpoint, first.conversation_id, { session, token });
  assert.equal(page.events.filter((event) => event.message?.id === message.id).length, 1);

  // The approval reaches Manzanita, which performs it; its answer is lost on the way back.
  const operation = await proposal(w, session, token);
  w.lose.path = "/api/orders/ord_7Hk2/exchanges";
  const sent = await w.operations.send(
    (approval) => w.api.call("POST", EXCHANGE, { session, token, body: {}, approval }),
    { operation_id: operation.operation_id, revision: operation.revision },
  );
  // Sent again with the same approval, never assumed failed, and not performed twice.
  assert.equal(sent.status, "answered");
  assert.equal(sent.answer.status, 200);
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
});

test("restart is safe", async () => {
  const w = await world({ durable: true });
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const operation = await proposal(w, session, token);
  assert.equal(await probe(w, session, token), 200);
  const captured = w.last("GET", "/api/orders");
  await w.deploy();
  // A Session JWT seen before the restart is still refused after it.
  assert.equal((await w.resend(captured)).status, 400);
  // The Session, the proposal and its single performance carry over.
  assert.equal(await probe(w, session, token), 200);
  const done = await approveIt(w, operation, session, token);
  assert.equal(done.status, 200);
  const performed = [...w.plugin.executor.performed];
  await w.deploy();
  const again = await approveIt(w, operation, session, token);
  assert.deepEqual(again.body, done.body);
  assert.deepEqual(performed, [operation.operation_id]);
  assert.deepEqual([...w.plugin.executor.performed], []);
});

test("rollback is safe", async () => {
  const w = await world({ durable: true });
  const session = await w.start();
  const { reference } = await deviceSignIn(w);
  const before = await w.tokens.get(reference);
  const refreshed = await w.accounts.refresh(reference, { context: w.context });
  assert.equal(refreshed.rotated, true);
  const rotated = await w.tokens.get(reference);
  const operation = await proposal(w, session, refreshed.token);
  const done = await approveIt(w, operation, session, refreshed.token);
  assert.equal(done.status, 200);
  assert.deepEqual(w.store.keys(RecordKinds.device), []); // the code was taken

  // The previous release (no website yet), over the same store (and so its replay cache).
  await w.deploy({ web: false });
  await w.tokens.put(reference, before);
  assert.equal((await w.accounts.refresh(reference, { context: w.context })).status, "signed_out");
  await w.tokens.put(reference, rotated);
  const current = await w.accounts.refresh(reference, { context: w.context });
  assert.equal(current.status, "signed_in");
  const again = await approveIt(w, operation, session, current.token);
  assert.deepEqual(again.body, done.body);
  assert.deepEqual([...w.plugin.executor.performed], []);
  assert.equal(await probe(w, session, current.token), 200);
});

test("revocation is safe", async () => {
  const w = await world();
  const session = await w.start();
  const { token, reference } = await deviceSignIn(w);
  assert.equal(await probe(w, session, token), 200);
  const second = await w.start();
  const other = await w.accounts.refresh(reference, { context: w.context });
  assert.equal(other.status, "signed_in");
  assert.equal(await probe(w, second, other.token), 200);
  const revoked = await w.accounts.revoke(reference, { context: w.context });
  assert.ok(revoked.revoked && revoked.deletedLocally);
  // Both tokens of that sign-in stop right away, not at expiry: `invalid_token`.
  for (const [used, stopped] of [[session, token], [second, other.token]]) {
    await assert.rejects(
      w.api.call("GET", ORDERS, { session: used, token: stopped }),
      (error) => error instanceof ApiError && error.code === "invalid_token" && error.statusCode === 401,
    );
  }
  // The refresh token is gone locally and refused at the company.
  assert.equal((await w.accounts.refresh(reference, { context: w.context })).status, "signed_out");
  // The Sessions continue signed out, sending no token: asked to sign in, not refused.
  await assert.rejects(w.api.call("GET", ORDERS, { session }), (error) => error.code === "insufficient_scope");
});

test("rotation is safe", async () => {
  const w = await world({ maxAge: 600 });
  await w.start();
  const { reference } = await deviceSignIn(w);
  const first = await w.tokens.get(reference);
  const results = await Promise.all([
    w.accounts.refresh(reference, { context: w.context }),
    w.accounts.refresh(reference, { context: w.context }),
  ]);
  assert.deepEqual(results.map((r) => [r.status, r.rotated]), [["signed_in", true], ["signed_in", true]]);
  const live = await w.tokens.get(reference);
  assert.notEqual(live.reveal(), first.reveal());
  await w.tokens.put(reference, first);
  assert.equal((await w.accounts.refresh(reference, { context: w.context })).status, "signed_out");
  await w.tokens.put(reference, live);
  assert.equal((await w.accounts.refresh(reference, { context: w.context })).status, "signed_in");

  // The agent's signing key: both keys published during the overlap, then the old retired.
  // Each host is a new delegated key, so a delegation the company hasn't seen.
  const accepted = async (identity) => {
    const agent = await agentHost({ identity, fetch: w.fetch, clock: w.clock });
    const fresh = await w.start(PAIRWISE, agent.reactor, identity.clientId);
    const answer = await w.fetch(ORDERS, { method: "GET", headers: await sessionHeaders(agent.reactor, "GET", ORDERS, { session: fresh }) });
    return answer.status === 401; // signed out: the Session is good
  };
  assert.ok(await accepted(w.identity));
  const newer = await agentIdentity({ domain: "atlas.example", name: "Atlas", kid: "key-2" });
  w.site.keys = [...w.identity.jwks.keys, ...newer.jwks.keys];
  assert.ok(await accepted(newer));
  assert.ok(await accepted(w.identity));
  w.site.keys = [...newer.jwks.keys];
  w.clock.advance(601); // the company's cached key set expires
  assert.equal(await accepted(w.identity), false);
  assert.ok(await accepted(newer));
});

// The browser join (§6, §10.6) --------------------------------------------------------------

const noSessionCookie = (response) => !response.headers.getSetCookie().some((line) => line.startsWith("__Host-poppy_session=") && !line.includes("Max-Age=0"));

const codeOf = (page) => /name="code" value="([^"]+)"/u.exec(page.text)[1];

const authorize = async (w, session, code) => {
  const url = `${BROWSER_SESSION}/authorize`;
  return w.fetch(url, {
    method: "POST",
    headers: { ...(await sessionHeaders(w.host.reactor, "POST", url, { session })), "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
};

test("§10.6: an attacker's code, authorized in its own browser, joins nobody else's", async () => {
  // A malicious agent signs in to an account it controls and has a victim's browser post the
  // code from a page that submits itself: the victim would use the attacker's account.
  const w = await world();
  const attacker = await w.start();
  await deviceSignIn(w);
  const attackersBrowser = new ControlledBrowser(w.network);
  const code = codeOf(await attackersBrowser.get(BROWSER_SESSION));
  assert.equal((await authorize(w, attacker, code)).status, 204);

  // A refused form sets no cookie, not even a cleared one (§6).
  const cookieless = await w.fetch(BROWSER_SESSION, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "code=bc_never_issued",
  });
  assert.equal(cookieless.status, 400);
  assert.deepEqual(cookieless.headers.getSetCookie(), []);

  // The victim's browser has no join cookie: the code alone joins nothing.
  const victim = new ControlledBrowser(w.network);
  const forged = await victim.postForm(BROWSER_SESSION, { code });
  assert.equal(forged.status, 400);
  assert.ok(noSessionCookie(forged));
  assert.equal(victim.cookies.get("manzanita.example")?.has("__Host-poppy_session") ?? false, false);

  // A join cookie of the victim's own doesn't fit another browser's code either.
  await victim.get(BROWSER_SESSION);
  const crossed = await victim.postForm(BROWSER_SESSION, { code });
  assert.equal(crossed.status, 400);
  assert.ok(noSessionCookie(crossed));

  // That first use spent the code, whatever the result: the attacker's browser can't either.
  const used = await attackersBrowser.postForm(BROWSER_SESSION, { code });
  assert.equal(used.status, 400);
  assert.ok(noSessionCookie(used));

  // The page holding the code can't be framed or kept by whoever opened it.
  const page = await w.network(BROWSER_SESSION, { method: "GET" });
  assert.match(page.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(page.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(page.headers.get("cache-control"), "no-store");
  const cookie = page.headers.getSetCookie().find((line) => line.startsWith("__Host-poppy_join="));
  for (const attribute of ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"]) assert.ok(cookie.includes(attribute), attribute);
  // A code the agent never authorized joins nothing, in the browser it was issued to.
  const browser = new ControlledBrowser(w.network);
  const unauthorized = await browser.postForm(BROWSER_SESSION, { code: codeOf(await browser.get(BROWSER_SESSION)) });
  assert.equal(unauthorized.status, 400);
  assert.ok(noSessionCookie(unauthorized));
});

test("§10.6: a code from someone else's browser is never authorized, only one from the agent's own", async () => {
  // Consent phishing (RFC 10027): a code from another browser, sent to the agent in a message.
  // The victim's browser would join the User's Session, so the SDK has no way to take one.
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const phisher = new ControlledBrowser(w.network);
  const phished = codeOf(await phisher.get(BROWSER_SESSION));
  const join = new BrowserSessionClient({ reactor: w.host.reactor, transport: w.transport });
  await join.join({ browserSessionEndpoint: BROWSER_SESSION, session, token, code: phished });

  // The code authorized was the one in the agent's own browser, which joined.
  const authorized = w.wire.filter((item) => item.url === `${BROWSER_SESSION}/authorize`);
  assert.equal(authorized.length, 1);
  assert.notEqual(JSON.parse(authorized[0].init.body).code, phished);
  assert.ok(w.browser.cookies.get("manzanita.example").has("__Host-poppy_session"));
  // The phisher's browser joined nothing: its code was never authorized.
  const submitted = await phisher.postForm(BROWSER_SESSION, { code: phished });
  assert.equal(submitted.status, 400);
  assert.ok(noSessionCookie(submitted));

  // A host with no browser of its own can't join at all.
  const bare = await agentHost({ identity: w.identity, fetch: w.fetch, clock: w.clock });
  const refused = new BrowserSessionClient({ reactor: bare.reactor, transport: new SessionFetchClient({ reactor: bare.reactor, fetch: w.fetch }) });
  await assert.rejects(refused.join({ browserSessionEndpoint: BROWSER_SESSION, session, token, code: phished }));
  assert.equal(w.wire.filter((item) => item.url === `${BROWSER_SESSION}/authorize`).length, 1);
});

// Session JWTs and delegations (§5.2, §5.3, §10.7) ------------------------------------------

/** A Session JWT with a delegated key of its own, `change` made to its delegation. */
async function delegatedJwt(w, session, change = {}) {
  const delegated = await generateKeyPair("ES256", { extractable: true });
  const { kty, crv, x, y } = await exportJWK(delegated.publicKey);
  const publicKey = { kty, crv, x, y };
  const issuedAt = w.clock.now();
  const claims = delegationClaims({ clientId: session.clientId, publicKey, issuedAt, lifetimeSeconds: 3600 });
  const delegation = await w.identity.signer.sign({ ...claims, ...change }, { purpose: "delegation" });
  return new SignJWT(await sessionJwtClaims(jwtRequest(session), { issuedAt }))
    .setProtectedHeader({
      alg: SESSION_JWT_ALGORITHM,
      typ: SESSION_JWT_TYPE,
      kid: await calculateJwkThumbprint(publicKey, "sha256"),
      pap_dlg: delegation.reveal(),
    })
    .sign(delegated.privateKey);
}

const jwtRequest = (session) => ({
  method: "GET",
  url: ORDERS,
  tenantId: session.tenantId,
  issuer: session.issuer,
  clientId: session.clientId,
  sid: session.sid,
  sub: session.sub,
});

const read = (w, sessionJwt, token) =>
  w.fetch(ORDERS, {
    method: "GET",
    headers: { "Poppy-Session": sessionJwt, ...(token === undefined ? {} : { Authorization: `Bearer ${token.accessToken.reveal()}` }) },
  });

async function assertInvalidSession(response) {
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "invalid_session" });
}

test("a Session JWT signed directly with a key in jwks_uri is refused", async () => {
  // A key in `jwks_uri` signs client assertions and delegations, never a Session JWT (§5.2).
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const issuedAt = w.clock.now();
  const claims = await sessionJwtClaims({ ...jwtRequest(session), accessToken: token.accessToken }, { issuedAt });
  const direct = await new SignJWT(claims)
    .setProtectedHeader({ alg: "ES256", typ: SESSION_JWT_TYPE, kid: "key-1" })
    .sign(w.identity.privateKey);
  await assertInvalidSession(await read(w, direct, token));
});

test("an expired delegation is refused", async () => {
  // The delegation's lifetime is what limits a stolen delegated key (§10.7): it ended.
  const w = await world();
  const session = await w.start();
  assert.equal((await read(w, await delegatedJwt(w, session))).status, 401); // the control: good
  const now = Math.floor(w.clock.now().getTime() / 1000);
  await assertInvalidSession(await read(w, await delegatedJwt(w, session, { iat: now - 2 * HOUR, exp: now - HOUR })));
});

test("a delegation over 24 hours is refused", async () => {
  const w = await world();
  const session = await w.start();
  const now = Math.floor(w.clock.now().getTime() / 1000);
  assert.equal((await read(w, await delegatedJwt(w, session, { iat: now, exp: now + 24 * HOUR }))).status, 401);
  await assertInvalidSession(await read(w, await delegatedJwt(w, session, { iat: now, exp: now + 24 * HOUR + 1 })));
});

test("a delegated key is never shared across User IDs, and one that is opens no account", async () => {
  // Nothing in a delegation ties it to a User, so each User ID has its own key (§5.2, §10.7).
  const w = await world();
  const ada = await w.start();
  const { token } = await deviceSignIn(w);
  const stranger = await w.start(STRANGER);
  const headersOf = async (session) => {
    const { "Poppy-Session": jwt } = await sessionHeaders(w.host.reactor, "GET", ORDERS, { session });
    return JSON.parse(Buffer.from(jwt.split(".")[0], "base64url"));
  };
  const [adas, strangers] = [await headersOf(ada), await headersOf(stranger)];
  assert.notEqual(adas.kid, strangers.kid);
  assert.notEqual(adas.pap_dlg, strangers.pap_dlg);
  assert.equal((await headersOf(ada)).kid, adas.kid); // one User ID keeps its key
  assert.equal(w.host.delegatedKeys.size, 2);

  // Whoever does hold Ada's delegated key signs for any User ID it knows, and is signed out:
  // a Session JWT never grants account access (§5.3, §10.7).
  const key = await w.host.delegatedKeys.current({ tenantId: TENANT, issuer: ada.issuer, sub: ada.sub });
  const stolen = async (session) =>
    new SignJWT(await sessionJwtClaims(jwtRequest(session), { issuedAt: w.clock.now() }))
      .setProtectedHeader({ alg: SESSION_JWT_ALGORITHM, typ: SESSION_JWT_TYPE, kid: key.thumbprint, pap_dlg: key.delegation.reveal() })
      .sign(key.privateKey);
  assert.equal((await read(w, await stolen(stranger))).status, 401);
  // The access token still works only where it was: it is what opens the account.
  assert.equal(await probe(w, ada, token), 200);
});

// Stale resource metadata (§4.5) ------------------------------------------------------------

test("a token for the wrong resource is refused, and the view of the service read again", async () => {
  const w = await world();
  const session = await w.start();
  const { token, reference } = await deviceSignIn(w);
  // The agent's view is stale: it takes the default token to a service that wants its own.
  // The MCP client refuses to send it; any other request reaches the server, which refuses it.
  assert.throws(
    () => new McpClient({ url: MCP, session, reactor: w.host.reactor, token, fetch: w.fetch }),
    (error) => error.code === "token_not_for_this_url",
  );
  const refused = await w.api.call("POST", MCP, { session, token, body: { jsonrpc: "2.0", id: 1, method: "tools/list" } }).then(
    () => assert.fail("a token not issued for the service"),
    (error) => error,
  );
  assert.equal(refused.code, "invalid_token");
  assert.equal(refused.statusCode, 401);
  assert.equal(staleResourceMetadata(refused), true);

  // The metadata named in the refusal, read again, and a token for the server's `url`.
  const tokens = new ServiceTokens({ company: w.company, refresh: w.accounts, reference, context: w.context, discovery: { reactor: w.host.reactor } });
  const fresh = await tokens.tokenFor(MCP, { fresh: true });
  const client = new McpClient({ url: MCP, session, reactor: w.host.reactor, token: fresh, fetch: w.fetch });
  assert.ok((await client.listTools()).length > 0);
  // That token is good at its server only (§4.5).
  await assert.rejects(w.api.call("GET", ORDERS, { session, token: fresh }), (error) => error.code === "invalid_token");
});

// Approvals (Operations) --------------------------------------------------------------------

test("a retry before the outcome is 503 with Retry-After, after it the original response", async () => {
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const operation = await proposal(w, session, token);
  const { perform } = w.plugin.executor;
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  w.plugin.executor.perform = async (...args) => {
    await held;
    return perform.apply(w.plugin.executor, args);
  };
  const first = approveIt(w, operation, session, token);
  while ((await w.shop.operationRecord(operation.operation_id)).status !== "performing") {
    await new Promise((resolve) => setImmediate(resolve));
  }
  // Before the outcome: the company is still at it. Nothing is performed twice, nothing failed.
  await assert.rejects(
    approveIt(w, operation, session, token),
    (error) => error instanceof ApiError && error.statusCode === 503 && Number(error.details.retry_after) > 0,
  );
  assert.deepEqual([...w.plugin.executor.performed], []);
  release();
  const done = await first;
  assert.equal(done.status, 200);
  // After the outcome: the response the first request got, and it is performed once.
  const retried = await approveIt(w, operation, session, token);
  assert.equal(retried.status, 200);
  assert.deepEqual(retried.body, done.body);
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
});

test("an approval of a revision the Company never returned performs nothing", async () => {
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const operation = await proposal(w, session, token);
  const forged = await approveIt(w, { ...operation, revision: "rev_never_returned" }, session, token);
  // A failed check: the operation as it stands, never the revision the approval named.
  assert.equal(forged.status, 403);
  assert.deepEqual(forged.operation, operation);
  assert.deepEqual([...w.plugin.executor.performed], []);
  const record = await w.shop.operationRecord(operation.operation_id);
  assert.equal(record.approved, undefined);
  // The revision the Company did return still needs the user's approval, and gets it.
  assert.equal((await approveIt(w, forged.operation, session, token)).status, 200);
  assert.deepEqual([...w.plugin.executor.performed], [operation.operation_id]);
});
