/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The TypeScript reference company (`./server`), driven by the TypeScript clients in one
// process: the same cases as the Python company's suites.
import assert from "node:assert/strict";
import test from "node:test";

import { SignJWT, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair } from "jose";

import {
  ApiClient,
  ApiError,
  AuthorizationError,
  BlindJoseSigner,
  ConversationClient,
  ConversationError,
  DeviceSignInClient,
  DirectSignInClient,
  McpClient,
  MEDIATED_GRANT,
  MediatedSignInClient,
  OperationsClient,
  RefreshTokenClient,
  RsaBlindSigningKey,
  SecretValue,
  SessionClient,
  SessionFetchClient,
  SessionSigners,
  approvalHeader,
  discoverCompany,
  firstContribution,
  mcpApi,
  sessionHeaders,
  tokenHash,
  parseProtectedResourceMetadata,
} from "../../lib/index.js";
import { CompanyAccounts, CompanyApis, CompanyMcps, CompanyRateLimits, StaleConversationError } from "../../lib/server.js";
import { ADA, ADA_CODE, manzanita } from "../../lib/demo/manzanita.js";
import { runJourney } from "./support/journey.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const ORDERS = "https://manzanita.example/api/orders";
const ORDER = `${ORDERS}/ord_7Hk2`;
const REDIRECT = "https://atlas.example/oauth/callback";

async function world({ answers = [], extensions, config, plugins, algorithm, blind = false } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({
    domain: "atlas.example",
    name: "Atlas",
    ...(extensions ? { extensions } : {}),
    ...(algorithm ? { algorithm } : {}),
  });
  sites["atlas.example"] = identity.documents;
  if (blind) {
    const [publicKey] = identity.jwks.keys;
    const key = new RsaBlindSigningKey(await exportJWK(identity.privateKey));
    identity.signer = new BlindJoseSigner({ key, publicKey, keyId: publicKey.kid });
  }
  const { service: shop, plugin } = manzanita({ fetch, clock, ...(config ? { config } : {}), ...(plugins ? { plugins } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock, answers });
  const transport = new SessionFetchClient({ reactor: host.reactor, fetch });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const start = (pairwiseUserId = PAIRWISE, agentId) =>
    sessions.start({
      clientId: identity.clientId,
      pairwiseUserId,
      issuer: metadata.issuer,
      tenantId: TENANT,
      ...(agentId === undefined ? {} : { agentId }),
    });
  const message = (text) => ({ id: conversations.generateMessageId(), author: { type: "human" }, text });
  const endpoint = company.document.agent.protocols[0].endpoint;
  const context = {
    tokenEndpoint: metadata.token_endpoint,
    revocationEndpoint: metadata.revocation_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    tenantId: TENANT,
  };
  const tokens = new RefreshTokenClient({ reactor: host.reactor, fetch });
  const api = new ApiClient({ transport });
  const operations = new OperationsClient({ reactor: host.reactor });
  return { clock, fetch, identity, shop, plugin, host, transport, conversations, company, metadata, start, message, endpoint, sites, context, tokens, api, operations, sessions };
}

async function directSignIn(w, scopes = ["orders:read", "orders:write"], grant) {
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: REDIRECT,
    scopes,
    tenantId: TENANT,
  });
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada", ...(grant ? { scopes: grant } : {}) });
  return { client, callbackUrl, result: await client.complete({ callbackUrl }) };
}

function beginDevice(w, scopes = ["orders:read", "orders:write"]) {
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  return device
    .begin({
      deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
      tokenEndpoint: w.metadata.token_endpoint,
      issuer: w.metadata.issuer,
      clientId: w.identity.clientId,
      scopes,
      tenantId: TENANT,
      organization: { name: "Manzanita", domain: new URL(w.metadata.protected_resources[0]).hostname },
      protectedResources: w.metadata.protected_resources,
    })
    .then((started) => ({ device, started }));
}

async function deviceSignIn(w, scopes) {
  const { device, started } = await beginDevice(w, scopes);
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  return device.poll(started.reference);
}

/** A write at Manzanita's API, as the wire has it, with the approval when given. */
function post(w, session, token, path, approval) {
  return w.transport.request("POST", `${ORDER}/${path}`, {
    session,
    token,
    headers: { "Content-Type": "application/json", ...(approval ? { "Poppy-Approval": approvalHeader(approval) } : {}) },
    body: "{}",
  });
}

async function operationAt(w, session, token, path) {
  const response = await post(w, session, token, path);
  assert.equal(response.status, 403);
  const body = await response.json();
  assert.equal(body.error, "approval_required");
  return body.operation;
}

const approvalOf = (operation) => ({ operation_id: operation.operation_id, revision: operation.revision });

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

test("discovery and OAuth metadata publish one issuer, plain OAuth, and the two extensions", async () => {
  const w = await world();
  assert.equal(w.metadata.issuer, "https://manzanita.example");
  assert.deepEqual(w.metadata.protected_resources, ["https://manzanita.example", "https://manzanita.example/mcp"]);
  assert.deepEqual(w.company.document.auth.scopes, {
    "orders:read": "See your orders, returns and exchanges",
    "orders:write": "Exchange or return items in your orders",
  });
  assert.equal(w.company.document.apis[0].url, "https://manzanita.example/api/openapi.json");
  assert.deepEqual(w.company.document.extensions.operations, { version: "2" });
  assert.deepEqual(w.company.document.extensions["mediated-sign-in"], {
    version: "1",
    fields: [
      { name: "email", label: "Email", secret: false },
      { name: "password", label: "Password", secret: true },
    ],
    scopes: ["orders:read", "orders:write"],
  });
  assert.equal(w.company.document.auth.mediated, undefined);
  assert.ok(w.metadata.grant_types_supported.includes(MEDIATED_GRANT));
  assert.ok(!w.metadata.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:jwt-bearer"));
  assert.ok(!w.metadata.grant_types_supported.includes("urn:ietf:params:oauth:grant-type:token-exchange"));
  const raw = await (await w.fetch("https://manzanita.example/.well-known/oauth-authorization-server", { method: "GET" })).json();
  assert.equal(raw.dpop_signing_alg_values_supported, undefined);
  const mcp = await (await w.fetch("https://manzanita.example/.well-known/oauth-protected-resource/mcp", { method: "GET" })).json();
  assert.equal(mcp.dpop_signing_alg_values_supported, undefined);
  assert.equal(mcp.resource, "https://manzanita.example/mcp");
});

test("an alias publishes the company's discovery, its issuer listing it, and answers nothing else", async () => {
  assert.throws(() => manzanita({ config: { aliases: ["manzanita.example"] } }), /another domain/);
  assert.throws(() => manzanita({ config: { aliases: ["Shop.Example"] } }), /small letters/);
  const { service } = manzanita({ config: { aliases: ["shop.example"] } });
  const at = (host, path, method = "GET") =>
    service.handle({ method, url: `https://manzanita.example${path}`, headers: { host }, body: new Uint8Array() });
  const discovery = await at("shop.example", "/.well-known/poppy.json");
  assert.equal(discovery.status, 200);
  assert.equal(discovery.body.organization.domain, "shop.example");
  assert.equal(discovery.body.auth.issuer, "https://manzanita.example");
  const own = await at("manzanita.example", "/.well-known/poppy.json");
  assert.equal(own.body.organization.domain, "manzanita.example");
  // Every document naming the issuer has the same auth, which describes it (§3.2).
  assert.deepEqual(discovery.body.auth, own.body.auth);
  const metadata = await at("manzanita.example", "/.well-known/oauth-authorization-server");
  assert.deepEqual(metadata.body.protected_resources.slice(0, 2), ["https://manzanita.example", "https://shop.example"]);
  assert.equal((await at("shop.example", "/.well-known/oauth-authorization-server")).status, 404);
  assert.equal((await at("shop.example", "/oauth/token", "POST")).status, 404);
  assert.throws(() => service.discoveryDocument("elsewhere.example"), /not one of this company's domains/);
});

test("Device Sign-In paces polling, then gives plain OAuth tokens that rotate, narrow, revoke", async () => {
  const w = await world();
  const session = await w.start();
  const { device, started } = await beginDevice(w);
  assert.match(started.userCode, /^[A-Z0-9XY]{4}-[A-Z0-9XY]{4}$/);
  w.clock.advance(started.pollInterval);
  assert.equal((await device.poll(started.reference)).status, "pending");
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  assert.deepEqual([...done.token.scopes], ["orders:read", "orders:write"]);
  assert.equal((await w.api.call("GET", ORDERS, { session, token: done.token })).status, 200);

  const narrowed = await w.tokens.refresh(done.refreshTokenReference, { context: w.context, scopes: ["orders:read"] });
  assert.equal(narrowed.status, "signed_in");
  assert.equal(narrowed.rotated, true);
  assert.deepEqual([...narrowed.grantedScopes], ["orders:read"]);
  const wider = await w.tokens.refresh(done.refreshTokenReference, { context: w.context, scopes: ["orders:read", "orders:admin"] });
  assert.equal(wider.status, "re_consent_required");
  const revoked = await w.tokens.revoke(done.refreshTokenReference, { context: w.context });
  assert.equal(revoked.revoked, true);
  const after = await w.tokens.refresh(done.refreshTokenReference, { context: w.context });
  assert.equal(after.status, "signed_out");
});

test("the token endpoint answers plain OAuth: Bearer, no refresh_token_expires_in, and an unknown resource is invalid_target", async () => {
  const w = await world();
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: REDIRECT,
    scopes: ["orders:read"],
    tenantId: TENANT,
  });
  const handle = w.shop.handle.bind(w.shop);
  const answers = [];
  w.shop.handle = async (request) => {
    const answer = await handle(request);
    if (new URL(request.url).pathname === "/oauth/token") answers.push(answer);
    return answer;
  };
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  const { refreshTokenReference: reference } = await client.complete({ callbackUrl });
  const [issued] = answers;
  assert.equal(issued.body.token_type, "Bearer");
  assert.equal(issued.body.expires_in, 3600);
  assert.ok(issued.body.refresh_token);
  assert.equal(issued.body.refresh_token_expires_in, undefined);
  assert.equal(issued.body.session_id, undefined);
  assert.equal(issued.body.scope, undefined); // exactly what was asked for

  await assert.rejects(
    w.tokens.refresh(reference, { context: w.context, resource: "https://elsewhere.example" }),
    (error) => error instanceof AuthorizationError && error.code === "invalid_target",
  );
  // The issuer's own domain is the default token's resource.
  const own = await w.tokens.refresh(reference, { context: w.context, resource: "https://manzanita.example" });
  assert.equal(own.status, "signed_in");
});

test("a scope no longer offered ends the access tokens holding it; the refresh token serves within what is offered", async () => {
  // A company rolled back to a version that no longer offers a scope.
  const w = await world();
  const session = await w.start();
  const done = await deviceSignIn(w);
  await w.conversations.start(w.endpoint, w.message("hi"), { session, token: done.token, wait: 0 });

  // Rolled back: the version now served offers no `orders:write`, so no operations either.
  const before = w.shop.config;
  w.shop.config = Object.assign(Object.create(Object.getPrototypeOf(before)), before, {
    scopes: ["orders:read"],
    writeScopes: [],
    operations: false,
  });
  await assert.rejects(
    w.conversations.start(w.endpoint, w.message("hi"), { session, token: done.token, wait: 0 }),
    (error) => error instanceof ConversationError && error.statusCode === 401 && error.code === "invalid_token",
  );

  const all = await w.tokens.refresh(done.refreshTokenReference, { context: w.context });
  assert.equal(all.status, "re_consent_required");
  const within = await w.tokens.refresh(done.refreshTokenReference, { context: w.context, scopes: ["orders:read"] });
  assert.equal(within.status, "signed_in");
  await w.conversations.start(w.endpoint, w.message("hi"), { session, token: within.token, wait: 0 });
});

test("a password reset ends the sign-ins from before it; signing in again works", async () => {
  // An account's sign-ins all end at a password reset: the directory says since when
  // (`signedOutBefore`), as Python's `AccountSignOuts` does.
  const before = new Map();
  const directory = {
    authenticate: async () => undefined,
    checkCode: async () => false,
    signedOutBefore: async (accountId) => before.get(accountId),
  };
  const w = await world({
    plugins: [{ name: "resets", version: "1", contributes: [{ point: CompanyAccounts, value: directory, options: { id: "resets", order: -1 } }] }],
  });
  const session = await w.start();
  const done = await deviceSignIn(w, ["orders:read"]);
  await w.conversations.start(w.endpoint, w.message("hi"), { session, token: done.token, wait: 0 });
  // Another person's reset ends nothing of Ada's.
  before.set("acct_bob", w.clock.now());
  await w.conversations.start(w.endpoint, w.message("hi"), { session, token: done.token, wait: 0 });

  w.clock.advance(60);
  before.set("acct_ada", w.clock.now());
  await assert.rejects(
    w.conversations.start(w.endpoint, w.message("hi"), { session, token: done.token, wait: 0 }),
    (error) => error instanceof ConversationError && error.statusCode === 401 && error.code === "invalid_token",
  );
  const refreshed = await w.tokens.refresh(done.refreshTokenReference, { context: w.context });
  assert.equal(refreshed.status, "signed_out");
  // Ended whole: its access token stays refused, even once nothing is said ended any more.
  before.clear();
  await assert.rejects(
    w.conversations.start(w.endpoint, w.message("hi"), { session, token: done.token, wait: 0 }),
    (error) => error instanceof ConversationError && error.code === "invalid_token",
  );
  // The Session continues signed out.
  await w.conversations.start(w.endpoint, w.message("hi"), { session, wait: 0 });

  before.set("acct_ada", w.clock.now());
  w.clock.advance(1);
  const again = await deviceSignIn(w, ["orders:read"]);
  await w.conversations.start(w.endpoint, w.message("hi"), { session, token: again.token, wait: 0 });
});

test("a denied device code is access_denied", async () => {
  const w = await world();
  const { device, started } = await beginDevice(w, ["orders:read"]);
  await w.shop.denyDevice(started.userCode);
  w.clock.advance(started.pollInterval);
  await assert.rejects(device.poll(started.reference), (error) => error.code === "access_denied");
});

test("polling too fast is slow_down, and the interval grows", async () => {
  const w = await world();
  const { device, started } = await beginDevice(w, ["orders:read"]);
  const [key] = w.shop.store.keys("device");
  const entry = await w.shop.store.get("device", key);
  w.clock.advance(started.pollInterval);
  await w.shop.store.put("device", key, { ...entry.value, lastPoll: w.clock.now().toISOString() }, { expiresAt: entry.expiresAt });
  assert.equal((await device.poll(started.reference)).status, "pending");
  const after = await w.shop.store.get("device", key);
  assert.equal(after.value.interval, started.pollInterval + 5);
});

test("Mediated Sign-In with a one-time code; a wrong code asks again", async () => {
  const w = await world({ answers: [{ ...ADA }, { code: "000000" }, { code: ADA_CODE }] });
  const mediated = new MediatedSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await mediated.signIn({ company: w.company, clientId: w.identity.clientId, scopes: ["orders:read"], tenantId: "t" });
  assert.equal(started.status, "code_required");
  assert.equal(started.sentTo, "a•••@example.com");
  const wrong = await mediated.submitCode(started.reference);
  assert.equal(wrong.status, "code_required");
  const done = await mediated.submitCode(started.reference);
  assert.equal(done.status, "complete");
  assert.deepEqual([...done.grantedScopes], ["orders:read"]);
  assert.deepEqual(w.host.input.asked.map((request) => request.purpose), ["credentials", "one_time_code", "one_time_code"]);
});

test("wrong credentials fail uniformly", async () => {
  const w = await world({ answers: [{ email: ADA.email, password: "nope" }, { email: "nobody@example.com", password: "nope" }] });
  const mediated = new MediatedSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  for (let attempt = 0; attempt < 2; attempt += 1) {
    await assert.rejects(
      mediated.signIn({ company: w.company, clientId: w.identity.clientId, scopes: ["orders:read"], tenantId: "t" }),
      (error) => error instanceof AuthorizationError && error.code === "invalid_grant",
    );
  }
});

test("Direct Sign-In: partial consent, a denial, a code used once, and the consent page", async () => {
  const w = await world();
  const session = await w.start();
  const partial = await directSignIn(w, ["orders:read", "orders:write"], ["orders:read"]);
  assert.deepEqual([...partial.result.missingScopes], ["orders:write"]);
  await assert.rejects(partial.client.complete({ callbackUrl: partial.callbackUrl }));
  const write = await post(w, session, partial.result.token, "exchanges");
  assert.equal(write.status, 403);
  assert.deepEqual(await write.json(), { error: "insufficient_scope", scope: "orders:write" });
  assert.equal(write.headers.get("www-authenticate"), 'Bearer error="insufficient_scope", scope="orders:write"');

  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint, tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer, clientId: w.identity.clientId, redirectUri: REDIRECT,
    scopes: ["orders:read"], tenantId: TENANT,
  });
  const denied = await w.shop.denyAuthorization(w.host.browser.requestId);
  assert.match(denied, /error=access_denied/);
  await assert.rejects(client.complete({ callbackUrl: denied }), (error) => error.code === "authorization_denied");

  const base = "https://manzanita.example/oauth/authorize";
  const good = `?response_type=code&client_id=${w.identity.clientId}&scope=orders:read&state=s1&code_challenge=c` +
    `&code_challenge_method=S256&redirect_uri=${REDIRECT}`;
  const page = await w.fetch(base + good, { method: "GET" });
  assert.equal(page.status, 200); // no dpop_jkt is asked for
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  assert.match(page.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  const elsewhere = await w.fetch(base + good.replace(REDIRECT, "https://attacker.example/cb"), { method: "GET" });
  assert.equal(elsewhere.status, 400);
  assert.equal(elsewhere.headers.get("location"), null);
  const plain = await w.fetch(base + good.replace("S256", "plain"), { method: "GET" });
  assert.equal(plain.status, 303);
  assert.match(plain.headers.get("location"), /error=invalid_request/);
});

test("the API: a 401 challenge with scope and no body signed out, the OpenAPI description, and 403 approval_required", async () => {
  const w = await world();
  const session = await w.start();
  const out = await w.transport.request("GET", ORDERS, { session, headers: { Accept: "application/json" } });
  assert.equal(out.status, 401);
  assert.equal(await out.text(), "");
  assert.equal(out.headers.get("www-authenticate"), 'Bearer scope="orders:read"');
  await assert.rejects(
    w.api.call("GET", ORDERS, { session }),
    (error) => error instanceof ApiError && error.code === "insufficient_scope" && error.statusCode === 401 && error.details.scope === "orders:read",
  );
  const openapi = await w.fetch("https://manzanita.example/api/openapi.json", { method: "GET" });
  assert.equal((await openapi.json()).openapi, "3.1.0");
  const { result } = await directSignIn(w);
  const operation = await operationAt(w, session, result.token, "exchanges");
  assert.deepEqual(Object.keys(operation).sort(), ["expires_at", "operation_id", "revision", "summary", "terms"]);
  assert.deepEqual(w.plugin.executor.performed, []);
  // The same request again is the same operation, at the same revision.
  assert.deepEqual(await operationAt(w, session, result.token, "exchanges"), operation);
});

test("an agent without the Operations extension is told extension_required", async () => {
  const w = await world({ extensions: [] });
  const session = await w.start();
  const { result } = await directSignIn(w);
  const refused = await post(w, session, result.token, "exchanges");
  assert.equal(refused.status, 403);
  assert.deepEqual(await refused.json(), { error: "extension_required", extension: "operations" });
  assert.equal(refused.headers.get("www-authenticate"), 'Bearer error="extension_required", extension="operations"');
});

test("an agent without the extension gets no operations in a conversation", async () => {
  const w = await world({ extensions: [] });
  const session = await w.start();
  const { result } = await directSignIn(w);
  const page = await w.conversations.start(w.endpoint, w.message("Exchange it for something warmer"), { session, token: result.token, wait: 0 });
  assert.ok(page.events.every((event) => event.message?.operation === undefined));
});

test("an operation's approval is performed once, repeats get the original response, and the revision is opaque", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const operation = await operationAt(w, session, token, "exchanges");
  assert.ok(!/^\d+$/.test(operation.revision));
  const approval = await w.operations.askUser(operation, { organization: w.company.document.organization, tenantId: TENANT });
  assert.equal(w.host.approvals.asked.at(-1).summary, operation.summary);
  const done = await post(w, session, token, "exchanges", approval);
  assert.equal(done.status, 200);
  const body = await done.json();
  assert.ok(body.summary.startsWith("Exchanged the Ridge Jacket"));
  assert.deepEqual(body.data.order_id, "ord_7Hk2");
  // A repeat, from any Session of the same agent and user signed in to the account.
  const other = await w.start();
  const again = await post(w, other, token, "exchanges", approval);
  assert.equal(again.status, 200);
  assert.deepEqual(await again.json(), body);
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
  const record = await w.shop.operationRecord(operation.operation_id);
  assert.equal(record.status, "performed");
  assert.equal(record.approved, operation.revision);
});

test("a stale, expired, or other-request approval gets a new revision, and nothing is performed", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const operation = await operationAt(w, session, token, "exchanges");
  // A revision the company never returned.
  const forged = await post(w, session, token, "exchanges", { ...approvalOf(operation), revision: "rev_never_returned" });
  assert.equal(forged.status, 403);
  // The approval of one action on a request for another.
  const wrap = await operationAt(w, session, token, "gift-wrap");
  const crossed = await post(w, session, token, "exchanges", approvalOf(wrap));
  assert.equal(crossed.status, 403);
  assert.equal((await crossed.json()).operation.operation_id, operation.operation_id);
  assert.deepEqual(w.plugin.giftWrap.performed, []);
  // Terms the company changed: earlier revisions are withdrawn.
  const revised = await w.shop.revise(operation.operation_id, {
    summary: "Exchange it, USD 75.00 more.",
    terms: { order_id: "ord_7Hk2", price_difference: { amount: "75.00", currency: "USD" } },
  });
  assert.notEqual(revised.revision, operation.revision);
  const raced = await post(w, session, token, "exchanges", approvalOf(operation));
  assert.equal(raced.status, 403);
  const told = (await raced.json()).operation;
  assert.equal(told.operation_id, operation.operation_id);
  assert.equal(told.summary, "Exchange it, USD 75.00 more.");
  assert.notEqual(told.revision, operation.revision);
  assert.deepEqual(w.plugin.executor.performed, []);
  // Past its expiry, the approval gets a new revision too; that one is performed.
  w.clock.advance(16 * 60);
  const expired = await post(w, session, token, "exchanges", approvalOf(told));
  assert.equal(expired.status, 403);
  const fresh = (await expired.json()).operation;
  assert.notEqual(fresh.revision, told.revision);
  assert.equal((await post(w, session, token, "exchanges", approvalOf(fresh))).status, 200);
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
  // Malformed, the header is ignored whole: the operation is asked for again.
  const malformed = await w.transport.request("POST", `${ORDER}/gift-wrap`, {
    session, token, headers: { "Content-Type": "application/json", "Poppy-Approval": "not a dictionary" }, body: "{}",
  });
  assert.equal(malformed.status, 403);
  assert.equal((await malformed.json()).error, "approval_required");
});

test("a call says whether it carries an approval", async () => {
  // A company's API and tools tell a retry from a first ask, without reading the header.
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const companyApi = w.shop.reactor.getContributions(CompanyApis).at(0).value;
  const answerApi = companyApi.handle.bind(companyApi);
  const seen = [];
  companyApi.handle = async (call) => {
    seen.push(call.carriesApproval);
    return answerApi(call);
  };
  const operation = await operationAt(w, session, token, "exchanges");
  assert.equal((await post(w, session, token, "exchanges", approvalOf(operation))).status, 200);
  assert.deepEqual(seen, [false, true]);

  const companyMcp = w.shop.reactor.getContributions(CompanyMcps).at(0).value;
  const answerTool = companyMcp.call.bind(companyMcp);
  const tools = [];
  companyMcp.call = async (name, args, call) => {
    tools.push(call.carriesApproval);
    return answerTool(name, args, call);
  };
  const url = mcpApi(w.company.document).url;
  const mcpToken = await w.tokens.tokenForMcp(result.refreshTokenReference, { context: w.context, server: parseProtectedResourceMetadata({ resource: url }) });
  const client = new McpClient({ url, session, reactor: w.host.reactor, fetch: w.fetch, token: mcpToken.token });
  const asked = await client.callTool("exchange_jacket", { order_id: "ord_other" });
  await client.callTool("exchange_jacket", { order_id: "ord_other" }, { approval: approvalOf(asked.operation) });
  assert.deepEqual(tools, [false, true]);
});

test("a failure says what changed, an unknown outcome is 503 until settled", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const returned = await operationAt(w, session, token, "returns");
  const refused = await w.api
    .call("POST", `${ORDER}/returns`, { session, token, body: {}, approval: approvalOf(returned) })
    .catch((error) => error);
  // The company's own words, for the host to show; never in the error's text.
  assert.deepEqual([refused.code, refused.statusCode], ["action_failed", 422]);
  assert.equal(refused.body.data.return_label, "rtn_8Lp3");
  assert.ok(!String(refused).includes(refused.body.summary));
  const failed = await post(w, session, token, "returns", approvalOf(returned));
  assert.equal(failed.status, 422);
  const told = await failed.json();
  assert.equal(told.error, "action_failed");
  assert.equal(told.data.return_label, "rtn_8Lp3");
  const repeat = await post(w, session, token, "returns", approvalOf(returned));
  assert.deepEqual([repeat.status, await repeat.json()], [422, told]);
  assert.equal(w.plugin.returns.performed.length, 1);

  const repair = await operationAt(w, session, token, "repairs");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const unknown = await post(w, session, token, "repairs", approvalOf(repair));
    assert.equal(unknown.status, 503);
    assert.equal(unknown.headers.get("retry-after"), "5");
  }
  assert.equal(w.plugin.repairs.performed.length, 1);
  const settled = await w.shop.settle(repair.operation_id, { summary: "The zip was repaired." }, { succeeded: true });
  assert.equal(settled.status, "performed");
  const after = await post(w, session, token, "repairs", approvalOf(repair));
  assert.deepEqual([after.status, await after.json()], [200, { summary: "The zip was repaired." }]);
  await assert.rejects(w.shop.settle(repair.operation_id, { summary: "Again" }, { succeeded: true }), /being performed/);
  await assert.rejects(w.shop.revise(repair.operation_id, { summary: "x", terms: {} }), /not yet approved/);
});

test("concurrent approvals perform once: the others get 503 while it is performed", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const operation = await operationAt(w, session, token, "exchanges");
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  const perform = w.plugin.executor.perform.bind(w.plugin.executor);
  w.plugin.executor.perform = async (...args) => {
    await held;
    return perform(...args);
  };
  const first = post(w, session, token, "exchanges", approvalOf(operation));
  while ((await w.shop.operationRecord(operation.operation_id)).status !== "performing") await new Promise((resolve) => setImmediate(resolve));
  const second = await post(w, session, token, "exchanges", approvalOf(operation));
  assert.equal(second.status, 503);
  assert.equal(second.headers.get("retry-after"), "5");
  release();
  assert.equal((await first).status, 200);
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
});

test("an operation in a conversation: a message's approval, a new revision for one that doesn't cover the terms, and text alone never approves", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const page = await w.conversations.start(w.endpoint, w.message("Exchange it for something warmer"), { session, token, wait: 0 });
  const proposal = page.events.filter((e) => e.type !== "state").at(-1).message.operation;
  assert.ok(proposal);
  const yes = await w.conversations.send(w.endpoint, page.conversation_id, w.message("yes, I approve"), { session, token, cursor: page.cursor, wait: 0 });
  assert.deepEqual(w.plugin.executor.performed, []);
  await w.shop.revise(proposal.operation_id, {
    summary: "Exchange for USD 85.00 more.",
    terms: { order_id: "ord_7Hk2", price_difference: { amount: "85.00", currency: "USD" } },
  });
  const approving = async (operation) => {
    const answer = await w.conversations.send(
      w.endpoint,
      page.conversation_id,
      { id: w.conversations.generateMessageId(), author: { type: "agent" }, approval: approvalOf(operation) },
      { session, token, cursor: yes.cursor, wait: 0 },
    );
    return answer.events.filter((event) => event.message?.role === "company").at(-1)?.message;
  };
  const told = await approving(proposal);
  const newer = told.operation;
  assert.equal(newer.operation_id, proposal.operation_id);
  assert.notEqual(newer.revision, proposal.revision);
  assert.equal(newer.summary, "Exchange for USD 85.00 more.");
  assert.deepEqual(w.plugin.executor.performed, []);
  const done = await approving(newer);
  assert.equal(done.operation, undefined);
  assert.ok(done.text.startsWith("Exchanged"));
  assert.deepEqual(w.plugin.executor.performed, [proposal.operation_id]);
  // Again: already performed, a new message adds nothing.
  const again = await w.conversations.send(
    w.endpoint,
    page.conversation_id,
    { id: w.conversations.generateMessageId(), author: { type: "agent" }, approval: approvalOf(newer) },
    { session, token, wait: 0 },
  );
  assert.equal(again.events.filter((event) => event.message?.text?.startsWith("Exchanged")).length, 1);
  assert.deepEqual(w.plugin.executor.performed, [proposal.operation_id]);
});

test("an operation at MCP: an error result with the operation, _meta approves, and the token is by resource", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const url = mcpApi(w.company.document).url;
  const mcpToken = await w.tokens.tokenForMcp(result.refreshTokenReference, { context: w.context, server: parseProtectedResourceMetadata({ resource: url }) });
  assert.equal(mcpToken.status, "signed_in");
  assert.equal(mcpToken.token.resource, url);
  const client = new McpClient({ url, session, reactor: w.host.reactor, fetch: w.fetch, token: mcpToken.token });
  assert.deepEqual((await client.listTools()).map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
  const asked = await client.callTool("exchange_jacket");
  assert.equal(asked.isError, true);
  assert.ok(asked.operation.summary);
  assert.deepEqual(w.plugin.executor.performed, []);
  const done = await client.callTool("exchange_jacket", {}, { approval: approvalOf(asked.operation) });
  assert.equal(done.isError, false);
  assert.ok(done.text.startsWith("Exchanged"));
  const repeat = await client.callTool("exchange_jacket", {}, { approval: approvalOf(asked.operation) });
  assert.equal(repeat.text, done.text);
  assert.deepEqual(w.plugin.executor.performed, [asked.operation.operation_id]);

  // The default token doesn't work there, nor the MCP token anywhere else: `invalid_token`.
  const wrong = await new McpClient({ url, session, reactor: w.host.reactor, fetch: w.fetch })
    .auth.fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
  assert.equal(wrong.status, 200); // signed out, the server still answers a ping
  const headers = await sessionHeaders(w.host.reactor, "POST", url, { session, token: result.token });
  const refused = await w.fetch(url, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
  assert.equal(refused.status, 401);
  assert.equal(
    refused.headers.get("www-authenticate"),
    'Bearer error="invalid_token", resource_metadata="https://manzanita.example/.well-known/oauth-protected-resource/mcp"',
  );
  const elsewhere = await w.api.call("GET", ORDERS, { session, token: mcpToken.token }).catch((error) => error);
  assert.deepEqual([elsewhere.code, elsewhere.statusCode], ["invalid_token", 401]);
  assert.equal(elsewhere.details.resource_metadata, "https://manzanita.example/.well-known/oauth-protected-resource");

  // Signed out, a call with an approval gets the challenge for the account.
  const outsider = new McpClient({ url, session: await w.start(), reactor: w.host.reactor, fetch: w.fetch });
  const challenged = await outsider.callTool("exchange_jacket", {}, { approval: approvalOf(asked.operation) }).catch((error) => error);
  assert.deepEqual([challenged.code, challenged.statusCode], ["insufficient_scope", 401]);
  assert.deepEqual(w.plugin.executor.performed, [asked.operation.operation_id]);

  // Signed out, a tool of the account is the challenge with `scope`, no error code.
  const out = await new McpClient({ url, session, reactor: w.host.reactor, fetch: w.fetch }).auth.fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_orders", arguments: {} } }),
  });
  assert.equal(out.status, 401);
  assert.equal(await out.text(), "");
  assert.equal(
    out.headers.get("www-authenticate"),
    'Bearer scope="orders:read", resource_metadata="https://manzanita.example/.well-known/oauth-protected-resource/mcp"',
  );
});

test("taken down: open operations settled, saying so; performed ones untouched; every sign-in ended", async () => {
  const w = await world();
  const session = await w.start();
  const done = await deviceSignIn(w);
  const token = done.token;
  const reason = "The company was taken down.";
  const proposal = await operationAt(w, session, token, "exchanges");
  const stored = await w.shop.operationRecord(proposal.operation_id);
  const copy = (id, update) => w.shop.store.put("operation", id, { ...stored, operationId: id, ...update });
  // One being performed when the company stopped, one finished, one past its expiry.
  await copy("op_performing", { status: "performing" });
  const finished = { summary: "Exchanged.", succeeded: true };
  await copy("op_finished", { status: "performed", outcome: finished });
  const gone = { ...stored.revisions[0], expiresAt: new Date(w.clock.now().getTime() - 1000).toISOString() };
  await copy("op_stale", { revisions: [gone] });

  const work = await w.shop.openWork();
  assert.deepEqual(work.operations.map((operation) => operation.operation_id), [proposal.operation_id, "op_performing"].sort());
  assert.deepEqual(work.signIns, [[w.identity.clientId, "acct_ada"]]);

  await assert.rejects(w.shop.settleOpenOperations("  "), /say why/);
  assert.equal(await w.shop.settleOpenOperations(reason), 2);
  assert.equal((await w.shop.operationRecord(proposal.operation_id)).status, "withdrawn");
  const performing = await w.shop.operationRecord("op_performing");
  assert.equal(performing.status, "performed");
  assert.equal(performing.outcome.succeeded, false);
  assert.ok(performing.outcome.summary.startsWith("It was stopped before it finished"));
  assert.ok(performing.outcome.summary.includes("whatever it changed until then stands"));
  assert.ok(performing.outcome.summary.endsWith(reason));
  assert.deepEqual((await w.shop.operationRecord("op_finished")).outcome, finished);
  assert.equal((await w.shop.operationRecord("op_stale")).status, "open");

  assert.equal(await w.shop.endSignIns(), 1);
  assert.deepEqual(await w.shop.openWork(), { operations: [], signIns: [] });
  const refreshed = await w.tokens.refresh(done.refreshTokenReference, { context: w.context });
  assert.equal(refreshed.status, "signed_out");

  assert.equal(await w.shop.settleOpenOperations(reason), 0);
  assert.equal(await w.shop.endSignIns(), 0);
});

test("conversations: SSE with text deltas, closing, and a stranger cannot read", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  assert.equal(page.events.filter((e) => e.type !== "state").at(-1).message.text, "Hello from Manzanita Outfitters. Ask me about an order.");
  await w.conversations.close(w.endpoint, page.conversation_id, { session });
  const items = [];
  for await (const item of w.conversations.stream(w.endpoint, page.conversation_id, { session })) items.push(item);
  const deltas = items.filter((item) => item.kind === "text-delta");
  const events = items.filter((item) => item.kind === undefined);
  assert.ok(deltas.length > 0 && deltas.every((delta) => delta.actionable === false));
  assert.equal(events.at(-1).type, "state");
  assert.equal(events.at(-1).status, "closed");

  const other = await w.start("usr_somebody_else_000000");
  await assert.rejects(
    w.conversations.readEvents(w.endpoint, page.conversation_id, { session: other }),
    (error) => error instanceof ConversationError && error.code === "conversation_not_found",
  );
});

test("conversations: an idempotent retry, a reused ID, handoff, Direct Conversations, expired cursors", async () => {
  const w = await world();
  const session = await w.start();
  const first = w.message("Hello");
  const page = await w.conversations.start(w.endpoint, first, { session, wait: 0 });
  const retried = await w.conversations.start(w.endpoint, first, { session, wait: 0 });
  assert.equal(retried.conversation_id, page.conversation_id);
  const conflict = await w.transport.request("POST", w.endpoint, {
    session, headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: { ...first, text: "Something else" } }),
  });
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { error: "message_id_conflict" });

  const direct = await w.conversations.start(w.endpoint, w.message("Just us"), { session, parentConversationId: page.conversation_id, wait: 0 });
  const blocked = await w.transport.request("POST", `${w.endpoint}/${page.conversation_id}/messages`, {
    session, headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message: w.message("Still there?") }),
  });
  assert.equal(blocked.status, 409);
  assert.deepEqual(await blocked.json(), { error: "direct_conversation_open", conversation_id: direct.conversation_id });
  await w.conversations.close(w.endpoint, direct.conversation_id, { session });
  const parent = await w.conversations.readEvents(w.endpoint, page.conversation_id, { session });
  assert.deepEqual(parent.events.slice(-2).map((event) => event.type), ["direct_opened", "direct_closed"]);

  const handed = await w.conversations.handoff(w.endpoint, page.conversation_id, { session });
  assert.equal(handed.status, "idle");
  assert.equal(handed.responder, "agent");

  const cursor = parent.events[0].id;
  await w.shop.forgetEvents(page.conversation_id, { keep: 1 });
  const gone = await w.transport.request("GET", `${w.endpoint}/${page.conversation_id}/events?cursor=${cursor}`, { session });
  assert.equal(gone.status, 410);
  assert.deepEqual(await gone.json(), { error: "cursor_expired" });
});

test("one of the company's people answers over what they read", async () => {
  const w = await world({ config: { humansAvailable: true } });
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  const id = page.conversation_id;
  let read = await w.shop.conversationRecord(id);
  await assert.rejects(w.shop.staffReply(id, { after: read.events.at(-1).id, text: "Marta here." }), /not handed/);

  await w.conversations.handoff(w.endpoint, id, { session });
  read = await w.shop.conversationRecord(id);
  assert.equal(read.responder, "human");
  const took = await w.shop.staffReply(id, { after: read.events.at(-1).id, text: "Marta here." });
  assert.deepEqual([took.message.author.type, took.message.role], ["human", "company"]);
  const named = await w.shop.staffReply(id, { after: took.id, text: "Rosa here too.", authorName: "Rosa", authorId: "staff_rosa" });
  assert.deepEqual(named.message.author, { type: "human", id: "staff_rosa", name: "Rosa" });

  // The person writes while Marta answers from what she read before: hers is refused.
  await w.conversations.send(w.endpoint, id, w.message("Is it shipped?"), { session });
  await assert.rejects(w.shop.staffReply(id, { after: took.id, text: "Anything else?" }), StaleConversationError);
  read = await w.shop.conversationRecord(id);
  const answered = await w.shop.staffReply(id, { after: read.events.at(-1).id, text: "It is.", data: { order_id: "ord_7Hk2" } });

  const seen = await w.conversations.readEvents(w.endpoint, id, { session });
  const written = seen.events.filter((e) => e.type === "message").map((e) => [e.message.author.type, e.message.role, e.message.text]);
  assert.deepEqual(written.slice(-3), [["human", "company", "Rosa here too."], ["human", "user", "Is it shipped?"], ["human", "company", "It is."]]);
  assert.equal(seen.events.at(-1).id, answered.id);
  assert.deepEqual([seen.status, seen.responder], ["idle", "human"]);

  await w.conversations.close(w.endpoint, id, { session });
  read = await w.shop.conversationRecord(id);
  await assert.rejects(w.shop.staffReply(id, { after: read.events.at(-1).id, text: "Bye." }), /closed/);
  await assert.rejects(w.shop.staffReply(id, { after: read.events.at(-1).id }), /says something/);
  await assert.rejects(w.shop.staffReply("cnv_nobody", { after: "evt_none", text: "Hello?" }), /unknown conversation/);
});

test("an authorization event, then the signed-in Session continues the conversation", async () => {
  const w = await world();
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("Where is my jacket order?"), { session, wait: 0 });
  assert.deepEqual(page.events.map((event) => event.type), ["message", "state", "message", "authorization", "state"]);
  const { result } = await directSignIn(w, ["orders:read"]);
  const token = result.token;
  const narrow = await w.conversations.send(w.endpoint, page.conversation_id, w.message("Exchange it"), { session, token, cursor: page.cursor, wait: 0 });
  assert.equal(narrow.events.filter((e) => e.type !== "state").at(-1).type, "authorization");
  assert.equal(narrow.events.filter((e) => e.type !== "state").at(-1).error, "insufficient_scope");
  const read = await w.conversations.send(w.endpoint, page.conversation_id, w.message("And my order?"), { session, token, cursor: narrow.cursor, wait: 0 });
  assert.equal(read.events.filter((e) => e.type !== "state").at(-1).message.data.order_id, "ord_7Hk2");
});

/** A Session header for this request, as the wire has it: the agent's own, or with changes. */
async function header(w, session, url, { method = "GET", token, claims = {}, protect = {}, key } = {}) {
  const signer = firstContribution(w.host.reactor, SessionSigners, "signer");
  const genuine = (await sessionHeaders(w.host.reactor, method, url, { session, ...(token ? { token } : {}) }))["Poppy-Session"];
  const held = key ?? (await signer.keyFor({ tenantId: session.tenantId, issuer: session.issuer, clientId: session.clientId, sub: session.sub }, w.clock.now())).privateKey;
  const { pap_dlg: delegation, kid, typ, alg } = decodeProtectedHeader(genuine);
  return new SignJWT({ ...decodeJwt(genuine), jti: crypto.randomUUID().replaceAll("-", ""), ...claims })
    .setProtectedHeader({ alg, typ, kid, pap_dlg: delegation, ...protect })
    .sign(held);
}

test("refusals: no Session header, a replayed JWT, a token without its header, a bad client assertion", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const access = result.token.accessToken.reveal();
  const noHeader = await w.fetch(ORDERS, { method: "GET", headers: { Authorization: `Bearer ${access}` } });
  assert.deepEqual([noHeader.status, await noHeader.json()], [400, { error: "invalid_session" }]);
  const nothing = await w.fetch(ORDERS, { method: "GET" });
  assert.deepEqual([nothing.status, await nothing.json()], [400, { error: "invalid_session" }]);
  const headers = await sessionHeaders(w.host.reactor, "GET", ORDERS, { session, token: result.token });
  const once = await w.fetch(ORDERS, { method: "GET", headers });
  assert.equal(once.status, 200);
  const replayed = await w.fetch(ORDERS, { method: "GET", headers });
  assert.deepEqual([replayed.status, await replayed.json()], [400, { error: "invalid_session" }]);
  const scheme = await w.fetch(ORDERS, { method: "GET", headers: { ...(await sessionHeaders(w.host.reactor, "GET", ORDERS, { session, token: result.token })), Authorization: `DPoP ${access}` } });
  assert.deepEqual([scheme.status, (await scheme.json()).error], [401, "invalid_token"]);
  const stranger = { ...result.token, accessToken: new SecretValue("at_unknown") };
  const answer = await w.fetch(ORDERS, { method: "GET", headers: await sessionHeaders(w.host.reactor, "GET", ORDERS, { session, token: stranger }) });
  assert.deepEqual([answer.status, (await answer.json()).error], [401, "invalid_token"]);
  assert.equal(answer.headers.get("www-authenticate"), 'Bearer error="invalid_token"');
  const form = new URLSearchParams({ grant_type: "refresh_token", client_id: w.identity.clientId, client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", client_assertion: "not-a-jwt" });
  const bad = await w.fetch(w.metadata.token_endpoint, { method: "POST", body: form });
  assert.equal(bad.status, 401);
  assert.deepEqual(await bad.json(), { error: "invalid_client" });
  const nowhere = await w.fetch("https://manzanita.example/nowhere", { method: "GET" });
  assert.equal(nowhere.status, 404);
  for (const removed of ["/poppy/sign-in", "/poppy/operations/op_1", "/poppy/operations/op_1/confirm", "/operations/op_1"]) {
    const gone = await w.fetch(`https://manzanita.example${removed}`, { method: "POST" });
    assert.equal(gone.status, 404, removed);
  }
});

test("the JWT bearer and token exchange grants are unsupported", async () => {
  const w = await world();
  const auth = await w.sessions.clientAuthentication({ clientId: w.identity.clientId, issuer: w.metadata.issuer });
  for (const grant of ["urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:token-exchange"]) {
    const answer = await w.fetch(w.metadata.token_endpoint, { method: "POST", body: new URLSearchParams({ ...auth, grant_type: grant }) });
    assert.deepEqual([answer.status, await answer.json()], [400, { error: "unsupported_grant_type" }]);
    Object.assign(auth, await w.sessions.clientAuthentication({ clientId: w.identity.clientId, issuer: w.metadata.issuer }));
  }
});

test("a Session JWT fails on each check of §5.3, and always as invalid_session", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const send = async (value, access = token.accessToken.reveal()) => {
    const answer = await w.fetch(ORDERS, { method: "GET", headers: { "Poppy-Session": value, ...(access ? { Authorization: `Bearer ${access}` } : {}) } });
    return [answer.status, await answer.json()];
  };
  const refused = [400, { error: "invalid_session" }];
  const signed = (changes) => header(w, session, ORDERS, { token, ...changes });
  assert.equal((await w.fetch(ORDERS, { method: "GET", headers: { "Poppy-Session": await signed({}), Authorization: `Bearer ${token.accessToken.reveal()}` } })).status, 200);
  // Signed with another key, but naming the delegated one.
  const { privateKey } = await generateKeyPair("ES256");
  assert.deepEqual(await send(await signed({ key: privateKey })), refused);
  const now = Math.floor(w.clock.now().getTime() / 1000);
  for (const claims of [
    { aud: "https://other.example" },
    { aud: ["https://manzanita.example"] },
    { htm: "POST" },
    { htu: "https://manzanita.example/api/other" },
    { iat: now - 120 },
    { iat: now + 120 },
    { iat: "soon" },
    { sid: "short" },
    { sub: "" },
    { agent_id: "not an id!" },
    { jti: "short" },
    { ath: "AAAA" },
    { ath: undefined },
    { iss: "https://other.example/agent.json" },
  ]) {
    assert.deepEqual(await send(await signed({ claims })), refused, JSON.stringify(claims));
  }
  // The wrong typ, or a kid that isn't the delegated key's thumbprint.
  assert.deepEqual(await send(await signed({ protect: { typ: "JWT" } })), refused);
  assert.deepEqual(await send(await signed({ protect: { kid: "A".repeat(43) } })), refused);
  // No access token: `ath` must be absent.
  assert.deepEqual(await send(await signed({}), ""), refused);
  // Not one compact JWT: a repeated header is joined.
  const value = await signed({});
  assert.deepEqual(await send(`${value}, ${value}`), refused);
  assert.deepEqual(await send("not-a-jwt"), refused);
  // The query string isn't part of `htu`.
  const query = `${ORDERS}?page=2`;
  const ok = await w.fetch(query, { method: "GET", headers: await sessionHeaders(w.host.reactor, "GET", query, { session, token }) });
  assert.equal(ok.status, 200);
});

/** A delegation for `publicJwk`, signed with the agent's key, with changes. */
async function delegation(w, publicJwk, { claims = {}, signer } = {}) {
  const iat = Math.floor(w.clock.now().getTime() / 1000);
  const body = { iss: w.identity.clientId, cnf: { jwk: publicJwk }, iat, exp: iat + 3600, jti: "dlg_0123456789abcdef", ...claims };
  return (await (signer ?? w.identity.signer).sign(body, { purpose: "delegation" })).reveal();
}

async function delegated(w, session, url, makeDelegation, { iat } = {}) {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const { kty, crv, x, y } = await exportJWK(publicKey);
  const jwk = { kty, crv, x, y };
  const now = Math.floor(w.clock.now().getTime() / 1000);
  return new SignJWT({
    iss: w.identity.clientId, aud: w.metadata.issuer, sid: session.sid, sub: session.sub,
    htm: "GET", htu: url, iat: iat ?? now, jti: crypto.randomUUID().replaceAll("-", ""),
  })
    .setProtectedHeader({
      alg: "ES256", typ: "poppy-session+jwt",
      kid: await calculateJwkThumbprint(jwk, "sha256"),
      pap_dlg: await makeDelegation(jwk),
    })
    .sign(privateKey);
}

test("a delegation is checked: typ, iss, lifetime, the key, cnf.jwk; a JWT signed directly by a jwks key is refused", async () => {
  const w = await world();
  const session = await w.start();
  const send = async (value) => {
    const answer = await w.fetch(ORDERS, { method: "GET", headers: { "Poppy-Session": value } });
    return [answer.status, await answer.text()];
  };
  const accepted = [401, ""]; // the Session header held: signed out, the challenge
  const refused = [400, '{"error":"invalid_session"}'];
  const now = Math.floor(w.clock.now().getTime() / 1000);
  assert.deepEqual(await send(await delegated(w, session, ORDERS, (jwk) => delegation(w, jwk))), accepted);
  for (const claims of [
    { iss: "https://other.example/agent.json" },
    { iat: now - 7200, exp: now - 3600 },
    { iat: now, exp: now + 24 * 3600 + 1 },
    { exp: now - 1, iat: now - 2 },
    { iat: "now" },
  ]) {
    assert.deepEqual(await send(await delegated(w, session, ORDERS, (jwk) => delegation(w, jwk, { claims }))), refused, JSON.stringify(claims));
  }
  // Exactly 24 hours is allowed.
  assert.deepEqual(await send(await delegated(w, session, ORDERS, (jwk) => delegation(w, jwk, { claims: { iat: now, exp: now + 24 * 3600 } }))), accepted);
  // cnf.jwk with private members, or not P-256.
  assert.deepEqual(await send(await delegated(w, session, ORDERS, (jwk) => delegation(w, jwk, { claims: { cnf: { jwk: { ...jwk, d: "AAAA" } } } }))), refused);
  assert.deepEqual(await send(await delegated(w, session, ORDERS, (jwk) => delegation(w, jwk, { claims: { cnf: { jwk: { ...jwk, crv: "P-384" } } } }))), refused);
  // Not signed by a key of the agent's jwks_uri.
  const stranger = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  assert.deepEqual(await send(await delegated(w, session, ORDERS, (jwk) => delegation(w, jwk, { signer: stranger.signer }))), refused);
  // Naming a key jwks_uri doesn't have, or the wrong typ.
  const other = await agentIdentity({ domain: "atlas.example", name: "Atlas", kid: "key-unknown" });
  assert.deepEqual(await send(await delegated(w, session, ORDERS, (jwk) => delegation(w, jwk, { signer: other.signer }))), refused);
  // A delegation of a different type, with a typ that isn't a delegation's: a client assertion.
  assert.deepEqual(
    await send(await delegated(w, session, ORDERS, async (jwk) => (await w.identity.signer.sign({ iss: w.identity.clientId, cnf: { jwk }, iat: now, exp: now + 60, jti: "dlg_0123456789abcdef" }, { purpose: "client_assertion" })).reveal())),
    refused,
  );
  // A JWT signed directly by a key from jwks_uri: no delegation at all.
  const direct = await new SignJWT({ iss: w.identity.clientId, aud: w.metadata.issuer, sid: session.sid, sub: session.sub, htm: "GET", htu: ORDERS, iat: now, jti: crypto.randomUUID().replaceAll("-", "") })
    .setProtectedHeader({ alg: "ES256", typ: "poppy-session+jwt", kid: "key-1" })
    .sign(w.identity.privateKey);
  assert.deepEqual(await send(direct), refused);
});

test("a JWT signed after its delegation's exp is refused; verified delegations are cached until then", async () => {
  const w = await world();
  const session = await w.start();
  const now = Math.floor(w.clock.now().getTime() / 1000);
  // Its delegation expired before the JWT's iat, though the clock still allows the iat.
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const { kty, crv, x, y } = await exportJWK(publicKey);
  const jwk = { kty, crv, x, y };
  const compact = await delegation(w, jwk, { claims: { iat: now - 100, exp: now + 10 } });
  const sign = (iat) =>
    calculateJwkThumbprint(jwk, "sha256").then((kid) =>
      new SignJWT({ iss: w.identity.clientId, aud: w.metadata.issuer, sid: session.sid, sub: session.sub, htm: "GET", htu: ORDERS, iat, jti: crypto.randomUUID().replaceAll("-", "") })
        .setProtectedHeader({ alg: "ES256", typ: "poppy-session+jwt", kid, pap_dlg: compact })
        .sign(privateKey));
  const answer = async (value) => (await w.fetch(ORDERS, { method: "GET", headers: { "Poppy-Session": value } })).status;
  assert.equal(await answer(await sign(now)), 401);
  assert.equal(w.shop.delegations.size, 1);
  assert.equal(await answer(await sign(now + 11)), 400); // iat past the delegation's exp
  assert.equal(await answer(await sign(now)), 401); // the same delegation, cached
  w.clock.advance(11);
  assert.equal(await answer(await sign(now + 5)), 400); // the delegation has expired
});

test("PS384 client assertions and delegations", async () => {
  const w = await world({ algorithm: "PS384" });
  const session = await w.start();
  const { result } = await directSignIn(w);
  const headers = await sessionHeaders(w.host.reactor, "GET", ORDERS, { session, token: result.token });
  assert.equal(decodeProtectedHeader(decodeProtectedHeader(headers["Poppy-Session"]).pap_dlg).alg, "PS384");
  assert.equal((await w.api.call("GET", ORDERS, { session, token: result.token })).status, 200);
});

test("a key that signs blindly: its PS384 client assertions and delegations are ordinary ones here", async () => {
  const w = await world({ algorithm: "PS384", blind: true });
  const session = await w.start();
  const { result } = await directSignIn(w);
  assert.equal((await w.api.call("GET", ORDERS, { session, token: result.token })).status, 200);
});

test("Sessions are kept by client_id and sid: unknown starts one, a known one keeps its User and Agent ID, an ended one is remembered", async () => {
  const w = await world();
  const session = await w.start(PAIRWISE, "agt_one");
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  assert.ok(page.conversation_id);
  assert.equal(w.shop.store.keys("session").length, 1);
  // The same sid under another User ID, or Agent ID, is refused.
  const mixed = Object.assign(await w.start("usr_somebody_else_000000", "agt_one"), { sid: session.sid });
  const other = await sessionHeaders(w.host.reactor, "GET", ORDERS, { session: mixed });
  const answer = await w.fetch(ORDERS, { method: "GET", headers: other });
  assert.deepEqual([answer.status, await answer.json()], [400, { error: "invalid_session" }]);
  const agent = Object.assign(await w.start(PAIRWISE, "agt_two"), { sid: session.sid });
  const another = await w.fetch(ORDERS, { method: "GET", headers: await sessionHeaders(w.host.reactor, "GET", ORDERS, { session: agent }) });
  assert.deepEqual([another.status, await another.json()], [400, { error: "invalid_session" }]);
  const none = Object.assign(await w.start(PAIRWISE), { sid: session.sid });
  const without = await w.fetch(ORDERS, { method: "GET", headers: await sessionHeaders(w.host.reactor, "GET", ORDERS, { session: none }) });
  assert.deepEqual([without.status, await without.json()], [400, { error: "invalid_session" }]);

  // The company ends it: remembered, and the agent starts a new one, once.
  const ended = session.sid;
  assert.equal(await w.shop.endSession(session.clientId, ended), true);
  assert.equal(await w.shop.endSession(session.clientId, ended), false);
  const stale = await sessionHeaders(w.host.reactor, "GET", ORDERS, { session });
  const refused = await w.fetch(ORDERS, { method: "GET", headers: stale });
  assert.deepEqual([refused.status, await refused.json()], [400, { error: "invalid_session" }]);
  await w.conversations.start(w.endpoint, w.message("Hello"), { session, wait: 0 });
  assert.notEqual(session.sid, ended);

  // Past its lifetime it has ended too.
  const later = await w.start();
  await w.conversations.start(w.endpoint, w.message("Hello"), { session: later, wait: 0 });
  w.clock.advance(24 * 60 * 60 + 1);
  const headers = await sessionHeaders(w.host.reactor, "GET", ORDERS, { session: later });
  const expired = await w.fetch(ORDERS, { method: "GET", headers });
  assert.deepEqual([expired.status, await expired.json()], [400, { error: "invalid_session" }]);
});

test("a token of another agent in a Session is refused", async () => {
  const w = await world();
  const { result } = await directSignIn(w);
  const stranger = await agentIdentity({ domain: "other.example", name: "Other" });
  w.sites["other.example"] = stranger.documents;
  const host = await agentHost({ identity: stranger, fetch: w.fetch, clock: w.clock });
  const session = await new SessionClient({ reactor: host.reactor, fetch: w.fetch }).start({
    clientId: stranger.clientId, pairwiseUserId: PAIRWISE, issuer: w.metadata.issuer, tenantId: TENANT,
  });
  const headers = await sessionHeaders(host.reactor, "GET", ORDERS, { session, token: result.token });
  const answer = await w.fetch(ORDERS, { method: "GET", headers });
  assert.deepEqual([answer.status, await answer.json()], [400, { error: "invalid_session" }]);
  assert.equal(decodeJwt(headers["Poppy-Session"]).ath, await tokenHash(result.token.accessToken));
});

test("a conversation that used the account stays with it; disconnecting signs Sessions out", async () => {
  const w = await world();
  const session = await w.start();
  const { result } = await directSignIn(w);
  const token = result.token;
  const page = await w.conversations.start(w.endpoint, w.message("Where is my order?"), { session, token, wait: 0 });
  assert.equal(page.events.filter((e) => e.type !== "state").at(-1).message.data.order_id, "ord_7Hk2");
  assert.equal(await w.shop.disconnect(w.identity.clientId, "acct_ada"), 1);
  // The access token went with the sign-in: `invalid_token`; without it, the challenge.
  const revoked = await w.transport.request("GET", `${w.endpoint}/${page.conversation_id}/events`, { session, token });
  assert.equal(revoked.status, 401);
  assert.equal(revoked.headers.get("www-authenticate"), 'Bearer error="invalid_token"');
  const out = await w.transport.request("GET", `${w.endpoint}/${page.conversation_id}/events`, { session });
  assert.equal(out.status, 401);
  assert.equal(out.headers.get("www-authenticate"), 'Bearer scope="orders:read"');
  assert.equal(await out.text(), "");
  const orders = await w.transport.request("GET", ORDERS, { session });
  assert.equal(orders.headers.get("www-authenticate"), 'Bearer scope="orders:read"');
});

const DEVICE_PAGE = "https://pap.manzanita.example/device?slug=orders-helper";
const CONSENT_PAGE = "https://datalayer.ai/pap/consent?slug=orders-helper&request={request_id}";

test("hosted page templates are checked", async () => {
  const { CompanyConfig } = await import("../../lib/server.js");
  const base = { name: "Shop", domain: "shop.example", scopes: ["orders:read"], operations: false };
  assert.throws(() => new CompanyConfig({ ...base, consentPage: "https://datalayer.ai/pap/consent" }), /consentPage/);
  assert.throws(() => new CompanyConfig({ ...base, devicePage: "http://pap.shop.example/device" }), /HTTPS/);
  // A device page off the company's domains is a link personal agents refuse (§4.6).
  assert.throws(() => new CompanyConfig({ ...base, devicePage: "https://datalayer.ai/pap/device" }), /company's domain/);
});

test("Device Sign-In points at the hosted device page", async () => {
  const w = await world({ config: { devicePage: DEVICE_PAGE } });
  const { started } = await beginDevice(w, ["orders:read"]);
  assert.equal(started.verificationUri, DEVICE_PAGE);
  assert.equal(started.verificationUriComplete, `${DEVICE_PAGE}&${new URLSearchParams({ code: started.userCode })}`);
});

test("authorize redirects to the hosted consent page, which reads the request back", async () => {
  const w = await world({ config: { consentPage: CONSENT_PAGE } });
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
    redirectUri: REDIRECT,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
  });
  assert.equal(handed[0].status, 303);
  assert.equal(handed[0].headers.get("cache-control"), "no-store");
  const location = new URL(handed[0].headers.get("location"));
  assert.equal(`${location.origin}${location.pathname}`, "https://datalayer.ai/pap/consent");
  assert.equal(location.searchParams.get("slug"), "orders-helper");
  const requestId = location.searchParams.get("request");
  const summary = await w.shop.authorizationRequest(requestId);
  assert.deepEqual(await w.shop.authorizationRequest(requestId), summary);
  assert.equal(summary.client_name, "Atlas");
  assert.equal(summary.client_domain, "atlas.example");
  assert.deepEqual(summary.scopes, [
    { scope: "orders:read", description: "See your orders, returns and exchanges" },
    { scope: "orders:write", description: "Exchange or return items in your orders" },
  ]);
  assert.match(summary.expires_at, /Z$/);
  assert.deepEqual(Object.keys(summary).sort(), ["client_domain", "client_name", "expires_at", "request_id", "scopes"]);
  const callbackUrl = await w.shop.approveAuthorization(requestId, { accountId: "acct_ada" });
  const result = await client.complete({ callbackUrl });
  assert.ok(result.token);
  await assert.rejects(() => w.shop.authorizationRequest(requestId));
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
  assert.deepEqual(w.shop.store.keys("authorization"), []);
  const back = await w.fetch(authorize("https://atlas.example/oauth/callback", "token"), { method: "GET" });
  assert.equal(back.status, 303);
  assert.ok(back.headers.get("location").startsWith("https://atlas.example/oauth/callback?"));
  assert.deepEqual(w.shop.store.keys("authorization"), []);
});

test("the host's rate limit refuses with when to ask again, 429 and no body (pap.company.rateLimit)", async () => {
  const admitted = [];
  const limit = {
    async admit(clientId, accountId) {
      admitted.push([clientId, accountId]);
      return admitted.length === 1 ? undefined : 42;
    },
  };
  const w = await world({
    plugins: [{ name: "limit", version: "1", contributes: [{ point: CompanyRateLimits, value: limit, options: { id: "limit" } }] }],
  });
  const session = await w.start();
  const started = await w.conversations.start(w.endpoint, w.message("hi"), { session, wait: 0 });
  assert.ok(started.conversation_id);
  await assert.rejects(
    w.conversations.start(w.endpoint, w.message("hi again"), { session, wait: 0 }),
    (error) => error instanceof ConversationError && error.statusCode === 429 && error.code === "rate_limited" && error.details.retry_after === "42",
  );
  assert.deepEqual(admitted, [[w.identity.clientId, undefined], [w.identity.clientId, undefined]]);
  const headers = await sessionHeaders(w.host.reactor, "GET", ORDERS, { session });
  const limited = await w.fetch(ORDERS, { method: "GET", headers });
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "42");
  assert.equal(await limited.text(), "");
  // A forged request is refused before it is ever counted.
  const counted = admitted.length;
  const forged = await w.fetch(w.endpoint, { method: "POST", headers: { Authorization: "Bearer forged" } });
  assert.deepEqual([forged.status, await forged.json()], [400, { error: "invalid_session" }]);
  assert.equal(admitted.length, counted);
});
