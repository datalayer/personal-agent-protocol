/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What upstream's unpublished draft 1.1 adds to 1.0 (589743a, 2026-11-18), both sides, in one
// process; it ports `personal_agent_protocol/__tests__/test_draft_11.py`.
//
// 1.0 as published stays the default version, and draft 1.1 is used only when named: from 1.0
// each side sends only what the other's version defines (§3.4). Each addition is off until a
// caller turns it on. `offline_access` (§4.4, §4.7), operator
// signatures at the authorization server (§5.3), replacing a User ID (§5.1), and listed tasks
// in feedback (§9, §9.3).
import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationError,
  ConversationClient,
  DerivedPairwiseUserIds,
  DeviceSignInClient,
  DirectSignInClient,
  FeedbackClient,
  FeedbackError,
  InMemoryDpopKeys,
  MediatedSignInClient,
  OFFLINE_ACCESS_SCOPE,
  OperatorSigners,
  PairwiseUserIdStores,
  PapSession,
  ProtocolValidationError,
  RefreshTokenClient,
  SecretValue,
  SessionClient,
  SessionFetchClient,
  TasksClient,
  USER_ID_UNUSED_AFTER_SECONDS,
  UserIdError,
  WebBotAuthSigner,
  acceptSignature,
  accessTokenFromResponse,
  buildDirectSignInRequest,
  checkOperatorSignatureRequest,
  companyProtocolVersion,
  contentDigest,
  derivePairwiseUserId,
  discoverCompany,
  listedReport,
  listsOfflineAccess,
  mayReplaceUnused,
  newOperatorKey,
  operatorDirectory,
  parseFeedbackReport,
  parseTasksResponse,
  replaceUserId,
  requestScope,
  scopesSupported,
  sessionHeaders,
  signOauthRequest,
  signOperatorRequest,
  verifyOperatorSignature,
  versionDefines,
} from "../../lib/index.js";
import { ClientPolicies, CompanyConfig, OperatorVerifiedAgents, RecordKinds } from "../../lib/server.js";
import { ADA, CONFIG_OPTIONS, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const SHOP = "https://manzanita.example";
const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const FEEDBACK_URL = `${SHOP}/poppy/feedback`;
const TASKS_URL = `${SHOP}/poppy/tasks`;
const OPERATOR = "https://atlas.example/operator-keys.json";
const LISTED = [
  { id: "installments", task: "Pay in installments" },
  { id: "split-payment", task: "Split a payment across two cards" },
];

/**
 * Atlas and Manzanita on one network. `sent` is every request the agent sends; `signing` has
 * Atlas sign as its operator, with the key its website publishes; `extra` are more
 * contributions of the agent's host.
 */
async function world({ config, plugins, signing = false, answers = [], extra = [] } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const sent = [];
  const network = inProcessFetch(sites);
  const fetch = async (input, init = {}) => {
    const body = init.body instanceof URLSearchParams ? init.body.toString() : init.body;
    const headers = Object.fromEntries([...new Headers(init.headers ?? {})].map(([name, value]) => [name.toLowerCase(), value]));
    sent.push({ url: new URL(String(input)), method: init.method ?? "GET", headers, body: body === undefined ? "" : String(body) });
    return network(input, init);
  };
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  const operatorKey = await newOperatorKey();
  sites["atlas.example"] = { ...identity.documents, "/operator-keys.json": operatorDirectory([operatorKey]) };
  const w = { clock, sites, sent, fetch, network, identity, operatorKey, answers, extra, plugins };
  serving(w, config);
  await hosted(w, signing);
  return w;
}

/** Manzanita, again, configured by `config`. */
function serving(w, config) {
  const { service } = manzanita({
    fetch: w.network,
    clock: w.clock,
    ...(config ? { config } : {}),
    ...(w.plugins ? { plugins: w.plugins } : {}),
  });
  w.shop = service;
  w.sites["manzanita.example"] = service;
}

/**
 * The agent's host, built again: signing as its operator or not. `true` signs its requests
 * with the Session header and, turned on, those to the OAuth endpoints; `"session"` only the
 * first, as 1.0 has it.
 */
async function hosted(w, signing) {
  const operator = new WebBotAuthSigner(w.operatorKey, {
    signatureAgent: OPERATOR,
    now: () => w.clock.now(),
    oauthEndpoints: signing === true,
  });
  w.host = await agentHost({
    identity: w.identity,
    fetch: w.fetch,
    clock: w.clock,
    answers: w.answers,
    extra: [...w.extra, ...(signing ? [{ point: OperatorSigners, value: operator, options: { id: "operator-key" } }] : [])],
  });
  w.reactor = w.host.reactor;
  w.transport = new SessionFetchClient({ reactor: w.reactor, fetch: w.fetch });
  w.accounts = new RefreshTokenClient({ reactor: w.reactor, fetch: w.fetch });
}

const form = (request) => Object.fromEntries(new URLSearchParams(request.body));
const at = (w, path) => w.sent.filter((request) => request.url.pathname === path);

/** Discovery and a signed-out Session by an agent that implements `versions`. */
async function session(w, { versions, sub = PAIRWISE } = {}) {
  const company = await discoverCompany("manzanita.example", {
    reactor: w.reactor,
    fresh: true,
    ...(versions === undefined ? {} : { protocolVersions: versions }),
  });
  w.company = company;
  w.metadata = company.oauthMetadata;
  return new SessionClient({ reactor: w.reactor, fetch: w.fetch }).start({
    clientId: w.identity.clientId,
    pairwiseUserId: sub,
    issuer: company.oauthMetadata.issuer,
    tenantId: TENANT,
    company,
  });
}

async function deviceSignIn(w, more = {}) {
  const device = new DeviceSignInClient({ reactor: w.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    organization: w.company.document.organization,
    ...more,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  return device.poll(started.reference);
}

const context = (w, more = {}) => ({
  tokenEndpoint: w.metadata.token_endpoint,
  revocationEndpoint: w.metadata.revocation_endpoint,
  issuer: w.metadata.issuer,
  clientId: w.identity.clientId,
  tenantId: TENANT,
  ...more,
});

const directArguments = (w, more = {}) => ({
  authorizationEndpoint: w.metadata.authorization_endpoint,
  tokenEndpoint: w.metadata.token_endpoint,
  issuer: w.metadata.issuer,
  clientId: w.identity.clientId,
  redirectUri: "https://atlas.example/oauth/callback",
  scopes: ["orders:read"],
  tenantId: TENANT,
  ...more,
});

const clientAuthentication = (w) =>
  new SessionClient({ reactor: w.reactor, fetch: w.fetch }).clientAuthentication({ clientId: w.identity.clientId, issuer: SHOP });

const rejectsWith = (code) => (error) => error.code === code;

// 1.0, the default, and draft 1.1 when named (§3.4) ---------------------------------------

test("a version defines what an earlier minor added", () => {
  assert.ok(versionDefines("1.1", "1.1") && versionDefines("1.4", "1.1"));
  assert.ok(!versionDefines("1.0", "1.1"));
  assert.ok(!versionDefines("0.4", "1.1") && !versionDefines("2.1", "1.1"));
  const config = new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: ["1.1", "0.4"] });
  assert.ok(config.defines("1.1", "1.1") && config.defines("1.3", "1.1"));
  assert.ok(!config.defines("1.0", "1.1") && !config.defines("0.4", "1.1"));
  assert.ok(!config.defines(undefined, "1.1") && !config.defines("one", "1.1"));
  // A company that serves only 1.0 handles a 1.1 request as 1.0 defines.
  assert.ok(!new CompanyConfig({ ...CONFIG_OPTIONS, protocolVersions: ["1.0"] }).defines("1.1", "1.1"));
});

test("1.0 stays the default and the draft is used when both sides name it", async () => {
  // Nothing announces 1.1 unless asked. An agent on the default names 1.0 at every company;
  // one that names the draft uses it only where the company's document is 1.1, so nothing of
  // 1.1 goes to a 1.0 peer (§3.4).
  const w = await world();
  assert.deepEqual(w.shop.config.protocolVersions, ["1.0"]);
  let byDefault = await session(w);
  assert.deepEqual([companyProtocolVersion(w.company), byDefault.protocolVersion], ["1.0", "1.0"]);
  let drafted = await session(w, { versions: ["1.1"] });
  assert.deepEqual([companyProtocolVersion(w.company), drafted.protocolVersion], ["1.0", "1.0"]);
  // A request that names 1.1 is compatible with 1.0, and handled as 1.0 defines (§3.4).
  const newer = PapSession.fromJson({ ...byDefault.toJson(), protocol_version: "1.1" });
  const answer = await w.transport.request("GET", TASKS_URL, { session: newer });
  assert.equal(answer.status, 200);
  assert.ok(!("tasks" in (await answer.json()).feedback));

  serving(w, { protocolVersions: ["1.1"] });
  byDefault = await session(w);
  assert.deepEqual([companyProtocolVersion(w.company), byDefault.protocolVersion], ["1.1", "1.0"]);
  const headers = await sessionHeaders(w.reactor, "GET", TASKS_URL, { session: byDefault });
  assert.equal(headers["Poppy-Version"], "1.0");
  drafted = await session(w, { versions: ["1.1"] });
  assert.deepEqual([companyProtocolVersion(w.company), drafted.protocolVersion], ["1.1", "1.1"]);
  for (const one of [byDefault, drafted]) {
    assert.equal((await w.transport.request("GET", TASKS_URL, { session: one })).status, 200);
  }
});

// `offline_access` (§4.4, §4.7, §4.8) -------------------------------------------------------

test("offline_access is requested when the issuer lists it and never granted", async () => {
  assert.equal(requestScope(["orders:read"], undefined), "orders:read");
  assert.equal(requestScope(["orders:read"], ["orders:read"]), "orders:read");
  const listed = ["orders:read", OFFLINE_ACCESS_SCOPE];
  assert.equal(requestScope(["orders:read"], listed), "orders:read offline_access");
  // Named by the caller, it is still sent once, and only when the issuer lists it.
  assert.equal(requestScope(["orders:read", "offline_access"], listed), "orders:read offline_access");
  assert.equal(requestScope(["orders:read", "offline_access"], undefined), "orders:read");
  assert.throws(() => requestScope(["offline_access"], listed), AuthorizationError);

  for (const [supported, sentScope] of [[listed, "orders:read offline_access"], [undefined, "orders:read"]]) {
    const request = await buildDirectSignInRequest({
      authorizationEndpoint: `${SHOP}/oauth/authorize`,
      issuer: SHOP,
      clientId: "https://atlas.example/client.json",
      redirectUri: "https://atlas.example/oauth/callback",
      scopes: ["orders:read"],
      scopesSupported: supported,
    });
    assert.equal(new URL(request.authorizationUrl.reveal()).searchParams.get("scope"), sentScope);
    assert.equal(new URLSearchParams(request.parameters.reveal()).get("scope"), sentScope); // pushed too
    assert.deepEqual([...request.scopes], ["orders:read"]);
  }

  const response = (scope) => ({ accessToken: new SecretValue("at"), tokenType: "Bearer", ...(scope === undefined ? {} : { scope }) });
  // It is none of the scopes granted, and alone it is a decline (§4.7).
  assert.deepEqual([...accessTokenFromResponse(response("orders:read offline_access")).scopes], ["orders:read"]);
  for (const declined of ["offline_access", "", " "]) {
    assert.throws(() => accessTokenFromResponse(response(declined)), ProtocolValidationError);
  }
  const leftOut = accessTokenFromResponse(response(undefined), { requestedScopes: ["orders:read"] });
  assert.deepEqual([...leftOut.scopes], ["orders:read"]);
  assert.ok(!listsOfflineAccess({}));
  assert.ok(!listsOfflineAccess({ scopes_supported: ["orders:read"] }));
  assert.ok(listsOfflineAccess({ scopes_supported: listed }));
});

test("a company whose refresh tokens need offline_access", async () => {
  // It lists the scope in its issuer's metadata and nowhere else; a sign-in that asks for it
  // gets a refresh token, one that doesn't gets an access token alone.
  const w = await world({ config: { offlineAccess: true } });
  await session(w);
  assert.ok(listsOfflineAccess(w.metadata));
  // Not a scope a Personal Agent requests for account access, nor one a resource lists.
  assert.ok(!scopesSupported(w.company).includes(OFFLINE_ACCESS_SCOPE));
  assert.ok(!w.company.resourceMetadata.scopes_supported.includes(OFFLINE_ACCESS_SCOPE));
  assert.ok(!w.shop.protectedResourceMetadata().scopes_supported.includes(OFFLINE_ACCESS_SCOPE));
  assert.ok(!JSON.stringify(w.company.document).includes("offline_access"));

  w.sent.length = 0;
  const done = await deviceSignIn(w, { scopesSupported: w.metadata.scopes_supported });
  assert.equal(form(w.sent[0]).scope, "orders:read orders:write offline_access");
  assert.ok(done.status === "complete" && done.refreshTokenReference !== undefined);
  assert.deepEqual([[...done.grantedScopes], [...done.missingScopes]], [["orders:read", "orders:write"], []]);
  assert.deepEqual([...done.token.scopes], ["orders:read", "orders:write"]);
  // The sign-in is kept with the account scopes only.
  const grants = await w.shop.store.records(RecordKinds.refreshToken);
  assert.ok(grants.length > 0 && grants.every((grant) => !grant.value.scopes.includes(OFFLINE_ACCESS_SCOPE)));

  // A narrowed refresh names it too, and the scopes granted leave it out.
  const withListed = context(w, { scopesSupported: w.metadata.scopes_supported });
  w.sent.length = 0;
  const narrowed = await w.accounts.refresh(done.refreshTokenReference, { context: withListed, scopes: ["orders:read"] });
  assert.equal(form(w.sent[0]).scope, "orders:read offline_access");
  assert.ok(narrowed.status === "signed_in" && narrowed.rotated);
  assert.deepEqual([[...narrowed.grantedScopes], [...narrowed.missingScopes]], [["orders:read"], []]);
  // A refresh that names no scope sends none.
  w.sent.length = 0;
  const whole = await w.accounts.refresh(done.refreshTokenReference, { context: withListed });
  assert.ok(!("scope" in form(w.sent[0])));
  assert.deepEqual([...whole.grantedScopes], ["orders:read", "orders:write"]);

  // An agent that leaves it out gets no refresh token: Device Sign-In fails for it.
  await assert.rejects(deviceSignIn(w), rejectsWith("missing_refresh_token"));
  // `offline_access` alone asks for no account access: no sign-in starts (§4.7).
  const refused = await w.fetch(w.metadata.device_authorization_endpoint, {
    method: "POST",
    body: new URLSearchParams({ scope: OFFLINE_ACCESS_SCOPE, ...(await clientAuthentication(w)) }),
  });
  assert.deepEqual([refused.status, (await refused.json()).error], [400, "invalid_scope"]);
});

test("offline_access in a pushed request, a Mediated Sign-In, and no challenge", async () => {
  const w = await world({ config: { offlineAccess: true, pushedAuthorizationRequests: "required" } });
  const started = await session(w);
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  const begun = await client.begin(
    directArguments(w, {
      pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint,
      requirePushedAuthorizationRequests: true,
      scopesSupported: w.metadata.scopes_supported,
    }),
  );
  assert.equal(form(at(w, "/oauth/par")[0]).scope, "orders:read offline_access");
  assert.deepEqual([...begun.requestedScopes], ["orders:read"]);
  // The consent page shows the account scope, and nothing about a refresh token.
  const browser = w.host.browser;
  assert.ok(!browser.pages.at(-1).includes("offline_access"));
  const shown = await w.shop.authorizationRequest(browser.requestId);
  assert.deepEqual(shown.scopes.map((entry) => entry.scope), ["orders:read"]);
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  const done = await client.complete({ callbackUrl });
  assert.ok(done.refreshTokenReference !== undefined);
  assert.deepEqual([[...done.grantedScopes], [...done.missingScopes]], [["orders:read"], []]);

  // Mediated Sign-In is a sign-in request too.
  const mediated = await world({ config: { offlineAccess: true }, answers: [{ ...ADA }] });
  await session(mediated);
  await new MediatedSignInClient({ reactor: mediated.reactor, fetch: mediated.fetch }).signIn({
    company: mediated.company,
    clientId: mediated.identity.clientId,
    scopes: ["orders:read"],
    tenantId: TENANT,
    offlineAccess: true,
  });
  assert.equal(form(at(mediated, "/oauth/token")[0]).scope, "orders:read offline_access");

  // A resource never names it in a challenge, nor the Company Agent in an `authorization`
  // event: a refresh token isn't something a resource requires.
  const challenged = await w.transport.request("GET", `${SHOP}/api/orders`, { session: started });
  assert.equal(challenged.status, 401);
  assert.ok(!challenged.headers.get("www-authenticate").includes("offline_access"));
  const conversations = new ConversationClient({ reactor: w.reactor, transport: w.transport });
  const page = await conversations.start(
    w.company.document.agent.protocols[0].endpoint,
    { id: conversations.generateRequestId(), author: { type: "human" }, text: "Where is my jacket order?" },
    { session: started, wait: 0 },
  );
  const asked = page.events.filter((event) => event.type === "authorization");
  assert.ok(asked.length > 0 && asked.every((event) => !String(event.scope ?? "").includes(OFFLINE_ACCESS_SCOPE)));
});

test("offline_access is an unknown scope where refresh tokens need none", async () => {
  const w = await world();
  await session(w);
  assert.ok(!listsOfflineAccess(w.metadata));
  w.sent.length = 0;
  // The agent reads the issuer's metadata: nothing listed, nothing added.
  const done = await deviceSignIn(w, { scopesSupported: w.metadata.scopes_supported });
  assert.equal(form(w.sent[0]).scope, "orders:read orders:write");
  assert.ok(done.refreshTokenReference !== undefined);
  const refused = await w.fetch(w.metadata.device_authorization_endpoint, {
    method: "POST",
    body: new URLSearchParams({ scope: "orders:read offline_access", ...(await clientAuthentication(w)) }),
  });
  assert.deepEqual([refused.status, (await refused.json()).error], [400, "invalid_scope"]);
});

// Operator signatures at the authorization server (§5.3) -----------------------------------

test("an operator signature covers the Session header or the content digest", async () => {
  const digest = await contentDigest("grant_type=refresh_token");
  assert.ok(digest.startsWith("sha-256=:") && digest.endsWith(":"));
  assert.equal(digest, await contentDigest(new TextEncoder().encode("grant_type=refresh_token")));
  const who = { method: "POST", url: `${SHOP}/oauth/token`, tenantId: TENANT };
  checkOperatorSignatureRequest({ ...who, contentDigest: digest });
  checkOperatorSignatureRequest({ ...who, sessionJwt: new SecretValue("a.b.c") });
  for (const neitherOrBoth of [{}, { contentDigest: digest, sessionJwt: new SecretValue("a.b.c") }]) {
    assert.throws(() => checkOperatorSignatureRequest({ ...who, ...neitherOrBoth }), RangeError);
  }
  assert.throws(
    () => checkOperatorSignatureRequest({ ...who, contentDigest: digest, authorization: new SecretValue("Bearer x") }),
    RangeError,
  );
  const key = await newOperatorKey();
  await assert.rejects(
    signOperatorRequest(who, key, { signatureAgent: OPERATOR, created: 1, expires: 2, nonce: "n" }),
    RangeError,
  );
  assert.ok(acceptSignature({}, { oauth: true }).includes('"content-digest"'));
  assert.ok(!acceptSignature({ authorization: "x" }, { oauth: true }).includes('"poppy-session"'));
  assert.ok(acceptSignature({}).includes('"poppy-session"'));
});

test("a signature over the content digest binds the body", async () => {
  const now = new Date("2026-10-11T09:00:00Z");
  const stamp = Math.floor(now.getTime() / 1000);
  const key = await newOperatorKey();
  const url = `${SHOP}/oauth/token`;
  const encode = (text) => new TextEncoder().encode(text);
  const body = encode("grant_type=refresh_token&client_assertion=a.b.c");
  const fetched = [];
  const keys = async (agent) => {
    fetched.push(agent);
    return operatorDirectory([key]).keys;
  };
  const signed = async (content, options = {}) => {
    const digest = await contentDigest(content);
    const signature = await signOperatorRequest(
      { method: "POST", url, tenantId: TENANT, contentDigest: digest },
      key,
      { signatureAgent: OPERATOR, created: stamp, expires: stamp + 60, nonce: "nonce", ...options },
    );
    return {
      "content-digest": digest,
      "signature-agent": signature.signatureAgent,
      "signature-input": signature.signatureInput,
      signature: signature.signature,
    };
  };
  const verdict = async (headers, content = body, more = {}) =>
    (await verifyOperatorSignature({ method: "POST", url, headers, keys, now, content, ...more })).outcome;

  const good = await signed(body);
  assert.ok(good["signature-input"].includes('"content-digest"'));
  assert.equal(await verdict(good), "verified");
  // Another body than the one signed: the client assertion in it is not the one bound.
  assert.equal(await verdict(good, encode("grant_type=refresh_token&client_assertion=x.y.z")), "invalid");
  // A digest of the new body under the old signature fails the signature.
  assert.equal(await verdict({ ...good, "content-digest": await contentDigest("other") }, encode("other")), "invalid");
  // Without the digest covered, nothing binds the body.
  const bare = await signed(body, { components: ["@authority", "signature-agent", "@method", "@path"] });
  assert.equal(await verdict(bare), "invalid");
  assert.equal(await verdict({ ...good, "content-digest": "md5=:AAAA:" }), "invalid");
  const { "content-digest": _dropped, ...withoutDigest } = good;
  assert.equal(await verdict(withoutDigest), "invalid");
  // At a resource it would have to cover the Session header instead.
  assert.equal(await verifyOperatorSignature({ method: "POST", url, headers: good, keys, now }).then((v) => v.outcome), "invalid");
  assert.equal(await verdict({}), "absent");

  // An operator the company doesn't know: `unverified`, and its directory is never read.
  fetched.length = 0;
  assert.equal(await verdict(good, body, { trusts: async () => false }), "unverified");
  assert.deepEqual(fetched, []);
  assert.equal(await verdict(good, body, { trusts: async (agent) => agent === OPERATOR }), "verified");
  assert.deepEqual(fetched, [OPERATOR]);
});

test("the agent signs its requests to the four OAuth endpoints", async () => {
  const w = await world({ config: { pushedAuthorizationRequests: "offered" } });
  await session(w);
  w.sent.length = 0;
  // No operator signer: nothing is signed, and no digest is added.
  await deviceSignIn(w);
  assert.ok(w.sent.every((request) => !("signature" in request.headers) && !("content-digest" in request.headers)));
  // A signer that isn't told to: the Session header's requests only, as 1.0 has it.
  await hosted(w, "session");
  w.sent.length = 0;
  await deviceSignIn(w);
  await w.transport.request("GET", TASKS_URL, { session: await session(w) });
  assert.deepEqual(
    w.sent.filter((request) => "signature" in request.headers).map((request) => request.url.pathname),
    ["/poppy/tasks"],
  );
  assert.ok(w.sent.every((request) => !("content-digest" in request.headers)));

  await hosted(w, true);
  w.sent.length = 0;
  const done = await deviceSignIn(w);
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  await client.begin(
    directArguments(w, { pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint }),
  );
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  await client.complete({ callbackUrl });
  await w.accounts.refresh(done.refreshTokenReference, { context: context(w) });
  await w.accounts.revoke(done.refreshTokenReference, { context: context(w) });
  const paths = ["/oauth/device", "/oauth/par", "/oauth/revoke", "/oauth/token"];
  const oauth = w.sent.filter((request) => paths.includes(request.url.pathname));
  assert.deepEqual([...new Set(oauth.map((request) => request.url.pathname))].sort(), paths);
  for (const request of oauth) {
    // Every one of them, each with its own signature over its own body.
    assert.equal(request.headers["content-digest"], await contentDigest(request.body));
    assert.ok(request.headers["signature-input"].includes('"content-digest"'));
    assert.ok(!request.headers["signature-input"].includes('"poppy-session"'));
    assert.ok(!("poppy-session" in request.headers));
    const verdict = await verifyOperatorSignature({
      method: "POST",
      url: request.url.toString(),
      headers: request.headers,
      keys: async (agent) => {
        assert.equal(agent, OPERATOR);
        return operatorDirectory([w.operatorKey]).keys;
      },
      now: w.clock.now(),
      content: new TextEncoder().encode(request.body),
    });
    assert.deepEqual([verdict.outcome, verdict.operator], ["verified", OPERATOR]);
  }
  assert.equal(new Set(oauth.map((request) => request.headers.signature)).size, oauth.length);
});

const policyPlugin = (policy) => ({
  name: "test-policy",
  contributes: [{ point: ClientPolicies, value: policy, options: { id: "test", order: 1 } }],
});

test("the policy that accepts the agents a verified operator speaks for", async () => {
  const [atlas, other] = ["https://atlas.example/client.json", "https://other.example/client.json"];
  const policy = new OperatorVerifiedAgents({
    agents: ["https://known.example/client.json"],
    operators: { [OPERATOR]: null, "https://edge.example/keys": [other] },
    blocked: ["https://atlas.example/blocked.json"],
  });
  assert.ok(await policy.allows("https://known.example/client.json"));
  assert.ok(!(await policy.allows(atlas)));
  // Every `client_id` on the host of the operator's directory, or the ones named.
  assert.ok(await policy.allowsOperator(atlas, OPERATOR));
  assert.ok(!(await policy.allowsOperator(other, OPERATOR)));
  assert.ok(!(await policy.allowsOperator("https://atlas.example.evil.example/c.json", OPERATOR)));
  assert.ok(await policy.allowsOperator(other, "https://edge.example/keys"));
  assert.ok(!(await policy.allowsOperator(atlas, "https://edge.example/keys")));
  assert.ok(!(await policy.allowsOperator(atlas, "https://unknown.example/keys")));
  // A blocked `client_id` is refused whatever speaks for it.
  assert.ok(!(await policy.allowsOperator("https://atlas.example/blocked.json", OPERATOR)));
  assert.throws(() => new OperatorVerifiedAgents({ operators: { "http://atlas.example/keys": null } }), RangeError);
});

test("a company accepts an agent by its verified operator signature", async () => {
  // Beside its allowlist, with PAR required so it decides before its sign-in page is shown;
  // the client assertion and the Session JWT are verified all the same.
  const w = await world({
    config: { pushedAuthorizationRequests: "required" },
    plugins: [policyPlugin(new OperatorVerifiedAgents({ operators: { [OPERATOR]: null } }))],
  });
  // Discovery needs no acceptance: the documents are public.
  const started = await session(w);
  const pushed = directArguments(w, {
    pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint,
    requirePushedAuthorizationRequests: true,
  });

  // Not on the allowlist, and nothing signed: refused everywhere.
  await assert.rejects(deviceSignIn(w), rejectsWith("invalid_client"));
  await assert.rejects(new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch }).begin(pushed), rejectsWith("invalid_client"));
  const refused = await w.transport.request("GET", TASKS_URL, { session: started });
  assert.deepEqual([refused.status, (await refused.json()).error], [400, "invalid_session"]);

  // Signed by the operator the company trusts: accepted at each endpoint.
  await hosted(w, true);
  assert.equal((await w.transport.request("GET", TASKS_URL, { session: started })).status, 200);
  const done = await deviceSignIn(w);
  assert.ok(done.status === "complete" && done.refreshTokenReference !== undefined);
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  await client.begin(pushed);
  // The browser's request has no signature: the push was decided on, and its page shows.
  const browser = w.host.browser;
  assert.ok(browser.requestId !== undefined && browser.pages.at(-1).includes('name="request_id"'));
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  assert.ok((await client.complete({ callbackUrl })).refreshTokenReference !== undefined);
  const refreshed = await w.accounts.refresh(done.refreshTokenReference, { context: context(w) });
  assert.ok(refreshed.status === "signed_in" && refreshed.token !== undefined);
  const orders = await w.transport.request("GET", `${SHOP}/api/orders`, { session: started, token: refreshed.token });
  assert.equal(orders.status, 200);

  // The signature doesn't replace the client assertion: a forged one is still refused.
  const device = w.metadata.device_authorization_endpoint;
  const send = async (body, headers) => {
    const response = await w.fetch(device, { method: "POST", headers, body });
    return [response.status, (await response.json()).error];
  };
  const forged = await signOauthRequest(w.reactor, {
    url: device,
    tenantId: TENANT,
    headers: {},
    body: new URLSearchParams({
      scope: "orders:read",
      client_id: w.identity.clientId,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: "forged.assertion.value",
    }),
  });
  const [forgedStatus, forgedError] = await send(forged.body, forged.headers);
  assert.ok([400, 401].includes(forgedStatus) && forgedError === "invalid_client");

  // A body changed after signing: the signature no longer speaks for the request.
  const genuine = { scope: "orders:read", ...(await clientAuthentication(w)) };
  const signed = await signOauthRequest(w.reactor, {
    url: device,
    tenantId: TENANT,
    headers: {},
    body: new URLSearchParams(genuine),
  });
  const tampered = new URLSearchParams({ ...genuine, scope: "orders:read orders:write" }).toString();
  assert.deepEqual(await send(tampered, signed.headers), [401, "invalid_client"]);
});

test("an operator the company does not trust accepts no one", async () => {
  const policy = new OperatorVerifiedAgents({ operators: { "https://edge.example/keys": null } });
  const asked = [];
  const decide = policy.allowsOperator.bind(policy);
  policy.allowsOperator = async (clientId, operator) => {
    asked.push([clientId, operator]);
    return decide(clientId, operator);
  };
  const w = await world({ plugins: [policyPlugin(policy)], signing: true });
  const started = await session(w);
  w.sent.length = 0;
  const refused = await w.transport.request("GET", TASKS_URL, { session: started });
  assert.deepEqual([refused.status, (await refused.json()).error], [400, "invalid_session"]);
  // Asked once for the request, with the signature's own Signature-Agent, and its directory
  // is never read.
  assert.deepEqual(asked, [[w.identity.clientId, OPERATOR]]);
  assert.deepEqual(at(w, "/operator-keys.json"), []);
  // The allowlist stays beside it: an allowed agent needs no signature.
  const listed = await world({ plugins: [policyPlugin(new OperatorVerifiedAgents({ agents: ["https://atlas.example/agent.json"] }))] });
  assert.equal((await listed.transport.request("GET", TASKS_URL, { session: await session(listed) })).status, 200);
});

// Replacing a User ID (§5.1) ---------------------------------------------------------------

const WHO = { tenantId: TENANT, localUserId: "user-ada", companyIssuer: SHOP };

/** Counters in memory, for a test: a host's are durable. */
class Counters {
  values = new Map();
  key = (who) => JSON.stringify([who.tenantId, who.localUserId, who.companyIssuer]);
  async get(who) {
    return this.values.get(this.key(who)) ?? 0;
  }
  async increase(who) {
    const next = (await this.get(who)) + 1;
    this.values.set(this.key(who), next);
    return next;
  }
}

test("a keyed hash replaces one user's ID with a counter", async () => {
  const key = Uint8Array.from({ length: 32 }, (_, index) => index);
  const first = await derivePairwiseUserId(key, WHO);
  // The same bytes as the Python SDK hashes: its value for these inputs.
  assert.equal(first, "usr_koXMIxlfvD5bkjji1QVtaLn_0A7wdtFy3NdyvTIUQEw");
  assert.equal(await derivePairwiseUserId(key, { ...WHO, counter: 1 }), "usr_2UgCpqTlhzV6-n8FMdPHp3b485yhJOFNmH4Xk3vtui4");
  assert.equal(first, await derivePairwiseUserId(key, WHO));
  assert.equal(first.length, 4 + 43);
  const different = [
    await derivePairwiseUserId(key, { ...WHO, counter: 1 }),
    await derivePairwiseUserId(Uint8Array.from({ length: 32 }, (_, index) => index + 1), WHO),
    await derivePairwiseUserId(key, { ...WHO, localUserId: "user-bo" }),
    await derivePairwiseUserId(key, { ...WHO, companyIssuer: "https://other.example" }),
    await derivePairwiseUserId(key, { ...WHO, tenantId: "another" }),
    // No two inputs share their bytes.
    await derivePairwiseUserId(key, { ...WHO, tenantId: `${TENANT}u`, localUserId: "ser-ada" }),
  ];
  assert.equal(new Set([first, ...different]).size, 7);
  for (const bad of [{ key: new Uint8Array(5) }, { counter: -1 }, { counter: 1.5 }, { companyIssuer: "http://manzanita.example" }, { localUserId: "" }]) {
    const { key: badKey = key, ...rest } = bad;
    await assert.rejects(derivePairwiseUserId(badKey, { ...WHO, ...rest }), RangeError);
  }

  const counters = new Counters();
  const ids = new DerivedPairwiseUserIds(key, { counters });
  assert.equal(await ids.getOrCreate(WHO), first);
  const replaced = await ids.replace(WHO);
  assert.equal(replaced, await derivePairwiseUserId(key, { ...WHO, counter: 1 }));
  assert.notEqual(replaced, first);
  // Another process over the same counters derives the new ID.
  assert.equal(await new DerivedPairwiseUserIds(key, { counters }).getOrCreate(WHO), replaced);
  assert.equal(await ids.getOrCreate({ ...WHO, localUserId: "user-bo" }), different[2]);
  assert.throws(() => new DerivedPairwiseUserIds(new Uint8Array(5), { counters }), RangeError);
});

test("an unused ID ages out after 28 days and never with a refresh token", () => {
  const now = new Date("2026-10-11T09:00:00Z");
  assert.equal(USER_ID_UNUSED_AFTER_SECONDS, 28 * 24 * 60 * 60);
  const may = (days, held = false) =>
    mayReplaceUnused({ lastUsed: new Date(now.getTime() - days * 24 * 60 * 60 * 1000), now, holdsRefreshToken: held });
  assert.ok(may(28) && may(400));
  assert.ok(!may(27.99) && !may(0));
  assert.ok(!may(28, true) && !may(4000, true));
});

/** The host's side of a replacement: what it held under the old ID. */
const hostData = (calls, { busy = false, fails = false } = {}) => ({
  discarded: [],
  async inUse() {
    calls.push("in_use");
    return busy;
  },
  async discard(user) {
    calls.push("discard");
    if (fails) throw new Error("the browser profile could not be cleared");
    this.discarded.push(user);
  },
});

/** A store of random IDs that can replace one, contributed to the agent with its DPoP keys. */
async function replaceable(calls) {
  const ids = new Map();
  let made = 0;
  const key = (who) => JSON.stringify([who.tenantId, who.localUserId, who.companyIssuer]);
  const fresh = () => `usr_random_${String((made += 1)).padStart(12, "0")}`;
  const store = {
    async getOrCreate(who) {
      if (!ids.has(key(who))) ids.set(key(who), fresh());
      return ids.get(key(who));
    },
    async replace(who) {
      calls.push("replace");
      ids.set(key(who), fresh());
      return ids.get(key(who));
    },
  };
  const dpopKeys = new InMemoryDpopKeys();
  const w = await world({ extra: [{ point: PairwiseUserIdStores, value: store, options: { id: "test" } }] });
  return { w, store, dpopKeys, old: await store.getOrCreate(WHO) };
}

test("replacing a User ID signs out first and discards what the old one held", async () => {
  const calls = [];
  const { w, store, dpopKeys, old } = await replaceable(calls);
  const started = await session(w, { sub: old });
  const done = await deviceSignIn(w, { pairwiseUserId: old });
  const reference = done.refreshTokenReference;
  // Keys the old ID holds: its delegated key (made by the Session JWT) and its DPoP key.
  const who = { tenantId: TENANT, issuer: SHOP, sub: old };
  const dpopKey = await dpopKeys.keyFor(who);
  await w.transport.request("GET", TASKS_URL, { session: started });
  assert.ok((await w.host.delegatedKeys.current(who)) !== undefined);
  const user = { tenantId: TENANT, localUserId: "user-ada", company: SHOP, pairwiseUserId: old };
  const data = hostData(calls);
  w.sent.length = 0;

  const replaced = await replaceUserId(w.reactor, {
    user,
    data,
    dpopKeys,
    delegatedKeys: w.host.delegatedKeys,
    reason: "user_request",
    refreshTokenReferences: [reference, reference],
    accounts: w.accounts,
    context: context(w),
  });
  // Between tasks, the sign-out, then the old ID's things, and the new ID last.
  assert.deepEqual(calls, ["in_use", "discard", "replace"]);
  assert.deepEqual(w.sent.map((request) => request.url.pathname), ["/oauth/revoke"]);
  assert.deepEqual([replaced.signedOut, replaced.revoked], [true, 1]);
  assert.notEqual(replaced.pairwiseUserId, old);
  assert.equal(replaced.pairwiseUserId, await store.getOrCreate(WHO));
  assert.equal(w.host.tokens.get(reference), undefined);
  assert.equal(await w.host.delegatedKeys.current(who), undefined);
  assert.notEqual(await dpopKeys.keyFor(who), dpopKey); // forgotten: a new one is made
  assert.deepEqual(data.discarded, [user]);
  // The Company signed the account out, and sees a new User: nothing links the two.
  assert.equal((await w.accounts.refresh(reference, { context: context(w) })).status, "signed_out");
  const fresh = await session(w, { sub: replaced.pairwiseUserId });
  assert.equal((await w.transport.request("GET", TASKS_URL, { session: fresh })).status, 200);
  assert.ok(fresh.sid !== started.sid && fresh.sub !== started.sub);
  assert.ok((await w.host.delegatedKeys.current({ ...who, sub: replaced.pairwiseUserId })) !== undefined);
});

test("what stops a replacement leaves the old ID in place", async () => {
  const calls = [];
  const { w, store, dpopKeys, old } = await replaceable(calls);
  await session(w, { sub: old });
  const done = await deviceSignIn(w, { pairwiseUserId: old });
  const reference = done.refreshTokenReference;
  const user = { tenantId: TENANT, localUserId: "user-ada", company: SHOP, pairwiseUserId: old };
  const now = w.clock.now();
  const daysAgo = (days) => new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
  const replaceIt = (more = {}) =>
    replaceUserId(w.reactor, {
      user,
      data: hostData(calls),
      dpopKeys,
      delegatedKeys: w.host.delegatedKeys,
      reason: "user_request",
      refreshTokenReferences: [reference],
      accounts: w.accounts,
      context: context(w),
      ...more,
    });
  const unchanged = async () => {
    assert.equal(await store.getOrCreate(WHO), old);
    assert.ok(w.host.tokens.get(reference) !== undefined);
    assert.ok(!calls.includes("replace") && !calls.includes("discard"));
  };

  // In the middle of a task.
  await assert.rejects(replaceIt({ data: hostData(calls, { busy: true }) }), rejectsWith("user_id_in_use"));
  await unchanged();
  // On its own, never while it holds a refresh token, however long the ID went unused.
  await assert.rejects(replaceIt({ reason: "unused", lastUsed: daysAgo(4000) }), rejectsWith("refresh_token_held"));
  await assert.rejects(replaceIt({ reason: "unused" }), RangeError);
  await assert.rejects(replaceIt({ reason: "whenever" }), RangeError);
  // A refresh token is held: signing out needs the client and where to revoke.
  await assert.rejects(replaceIt({ accounts: undefined }), RangeError);
  await unchanged();
  // The Company doesn't acknowledge the sign-out: the account would link the two IDs.
  await assert.rejects(
    replaceIt({ context: context(w, { revocationEndpoint: `${SHOP}/nowhere` }) }),
    (error) => error instanceof UserIdError && error.code === "sign_out_failed",
  );
  await unchanged();

  // Signed out, the 28 days apply.
  await w.accounts.signOut([reference], { context: context(w) });
  await assert.rejects(replaceIt({ reason: "unused", lastUsed: daysAgo(27) }), rejectsWith("user_id_recently_used"));
  assert.equal(await store.getOrCreate(WHO), old);
  // What the host can't discard stops it too, before the ID changes.
  await assert.rejects(
    replaceIt({ reason: "unused", lastUsed: daysAgo(28), data: hostData(calls, { fails: true }) }),
    /could not be cleared/,
  );
  assert.equal(await store.getOrCreate(WHO), old);
  calls.length = 0;
  const aged = await replaceIt({ reason: "unused", lastUsed: daysAgo(28) });
  assert.deepEqual([aged.signedOut, aged.revoked], [false, 0]);
  assert.notEqual(aged.pairwiseUserId, old);
  assert.deepEqual(calls, ["in_use", "discard", "replace"]);

  // A store that can't replace an ID is refused before anything is done.
  const plain = await world({
    extra: [{ point: PairwiseUserIdStores, value: { getOrCreate: async () => "usr_fixed" }, options: { id: "test" } }],
  });
  await assert.rejects(
    replaceUserId(plain.reactor, {
      user,
      data: hostData([]),
      dpopKeys,
      delegatedKeys: plain.host.delegatedKeys,
      reason: "user_request",
    }),
    TypeError,
  );
});

test("a company limits new User IDs by client_id and links none to an account", async () => {
  const w = await world({ config: { newUserIdsPerClient: 2, newUserIdWindowSeconds: 600 } });
  const get = async (sub) => {
    const started = await session(w, { sub });
    const headers = await sessionHeaders(w.reactor, "GET", TASKS_URL, { session: started });
    return w.fetch(TASKS_URL, { method: "GET", headers });
  };
  assert.equal((await get("usr_one_0000000000000000")).status, 200);
  assert.equal((await get("usr_two_0000000000000000")).status, 200);
  const limited = await get("usr_three_00000000000000");
  assert.deepEqual([limited.status, await limited.text()], [429, ""]);
  const wait = Number(limited.headers.get("retry-after"));
  assert.ok(wait > 0 && wait <= 600);
  // A User ID it has seen is served, in a new Session too: only new ones are counted.
  assert.equal((await get("usr_one_0000000000000000")).status, 200);
  assert.equal(w.shop.store.keys(RecordKinds.userId).length, 2);
  // A forged Session JWT counts against no one.
  const forged = await w.fetch(TASKS_URL, { method: "GET", headers: { "Poppy-Session": "a.b.c", "Poppy-Version": "1.1" } });
  assert.equal(forged.status, 400);
  w.clock.advance(601);
  assert.equal((await get("usr_three_00000000000000")).status, 200);
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, newUserIdsPerClient: 0 }), RangeError);

  // One account under two User IDs: a replaced ID is a new User, signed in again.
  const open = await world();
  for (const sub of ["usr_before_0000000000000", "usr_after_00000000000000"]) {
    const started = await session(open, { sub });
    const done = await deviceSignIn(open);
    const orders = await open.transport.request("GET", `${SHOP}/api/orders`, { session: started, token: done.token });
    assert.equal(orders.status, 200);
  }
});

// Listed tasks in feedback (§9, §9.3) -------------------------------------------------------

test("listed tasks as a personal agent reads them", () => {
  const feedback = (tasks) => parseTasksResponse({ feedback: { endpoint: FEEDBACK_URL, ...(tasks === undefined ? {} : { tasks }) } }).feedback;
  assert.equal(feedback().tasks, undefined);
  assert.deepEqual(feedback(LISTED).tasks, LISTED);
  // More than 50: the first 50. Two with one ID: the first.
  const many = Array.from({ length: 60 }, (_, n) => ({ id: `task-${n}`, task: `Task ${n}` }));
  assert.deepEqual(feedback(many).tasks.map((task) => task.id), many.slice(0, 50).map((task) => task.id));
  const again = feedback([...LISTED, { id: "installments", task: "Something else" }]).tasks;
  assert.deepEqual(again.map((task) => task.task), ["Pay in installments", LISTED[1].task]);
  for (const bad of [
    { id: "Installments", task: "x" },
    { id: "a b", task: "x" },
    { id: "x".repeat(65), task: "x" },
    { id: "", task: "x" },
    { id: "ok", task: "" },
    { id: "ok", task: "x".repeat(201) },
    { id: "ok" },
  ]) {
    assert.throws(() => feedback([bad]), ProtocolValidationError);
  }
  assert.throws(() => feedback("installments"), ProtocolValidationError);

  // A report has one form or the other.
  assert.deepEqual(listedReport("installments", "split-payment"), { task_ids: ["installments", "split-payment"] });
  assert.deepEqual(parseFeedbackReport({ task: "Pay", description: "Why" }), { task: "Pay", description: "Why" });
  for (const badReport of [
    {},
    { task: "Pay" },
    { description: "Why" },
    { task_ids: [] },
    { task_ids: ["installments", "installments"] },
    { task_ids: ["Not An ID"] },
    { task_ids: ["installments"], task: "Pay", description: "Why" },
    { task_ids: ["installments"], task: "Pay" },
    { task_ids: "installments" },
  ]) {
    assert.throws(() => parseFeedbackReport(badReport), ProtocolValidationError);
  }
});

test("what a company may list", () => {
  const config = (more) => new CompanyConfig({ ...CONFIG_OPTIONS, ...more });
  assert.deepEqual(config({ feedbackTasks: LISTED }).feedbackTasks, LISTED);
  const fifty = Array.from({ length: 50 }, (_, n) => ({ id: `task-${n}`, task: `Task ${n}` }));
  config({ feedbackTasks: fifty });
  for (const bad of [
    [...fifty, { id: "one-more", task: "One more" }],
    [{ id: "Installments", task: "Pay in installments" }],
    [{ id: "x".repeat(65), task: "Pay in installments" }],
    [{ id: "installments", task: "" }],
    [{ id: "installments", task: "x".repeat(201) }],
    [{ id: "installments" }],
    [{ id: "installments", task: "Pay in installments", more: "x" }],
    [LISTED[0], { id: "installments", task: "Another" }],
    // Never also excluded (§9.1), nor answered with an alternative (§9.2).
    [{ id: "resize", task: "change the size of an item after it has shipped" }],
    [{ id: "gift-card", task: "Pay with a gift card" }],
  ]) {
    assert.throws(() => config({ feedbackTasks: bad }), RangeError);
  }
  assert.throws(() => config({ feedbackTasks: LISTED, feedback: false }), RangeError);
});

test("a listed task is reported by its ID", async () => {
  const w = await world({ config: { feedbackTasks: LISTED, protocolVersions: ["1.1"] } });
  const started = await session(w, { versions: ["1.1"] });
  const tasks = await new TasksClient({ transport: w.transport }).get(w.company, { session: started });
  assert.deepEqual(tasks.listedTasks.map((task) => [task.id, task.task]), LISTED.map((task) => [task.id, task.task]));
  // Never both listed and excluded.
  const excluded = new Set(tasks.excludedTasks.map((task) => task.task));
  assert.ok(!tasks.listedTasks.some((task) => excluded.has(task.task)));
  const feedback = new FeedbackClient({ transport: w.transport });
  const endpoint = tasks.feedbackEndpoint;
  // Several in one report, an ID the company no longer lists among them: 202.
  assert.equal(await feedback.report(endpoint, listedReport("installments", "split-payment", "gone"), { session: started }), undefined);
  assert.equal(await feedback.report(endpoint, listedReport("installments"), { session: started }), undefined);
  assert.equal(await feedback.report(endpoint, { task_ids: ["only-unknown"] }, { session: started }), undefined);
  assert.deepEqual(await w.shop.feedbackTaskCounts(), { installments: 2, "split-payment": 1 });
  const reports = await w.shop.feedbackReports();
  assert.deepEqual(reports.map((report) => [...report.taskIds]).sort(), [["installments"], ["installments", "split-payment"]]);
  assert.ok(reports.every((report) => report.task === undefined && report.description === undefined));
  // Free text still works beside it, and still gets its alternative.
  const alternative = await feedback.report(
    endpoint,
    { task: "Pay with a gift card", description: "No gift card field." },
    { session: started },
  );
  assert.ok(alternative !== undefined);
  assert.equal(w.shop.store.keys(RecordKinds.feedback).length, 3);

  const raw = async (body) => {
    const headers = await sessionHeaders(w.reactor, "POST", endpoint, { session: started });
    return w.fetch(endpoint, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  };
  for (const malformed of [
    { task_ids: ["installments"], task: "Pay", description: "Why" }, // both forms
    { task_ids: ["installments"], task: "Pay" },
    {}, // neither
    { task_ids: [] },
    { task_ids: "installments" },
    { task_ids: [1] },
    { task_ids: ["installments", "installments"] },
    { task_ids: ["Not An ID"] },
    { task_ids: null },
  ]) {
    const refused = await raw(malformed);
    assert.deepEqual([refused.status, await refused.json()], [400, { error: "invalid_request" }], JSON.stringify(malformed));
  }
  assert.equal((await raw({ task_ids: ["installments"] })).status, 202);
  await assert.rejects(
    feedback.report(`${SHOP}/poppy/nowhere`, listedReport("installments"), { session: started }),
    FeedbackError,
  );
});

test("nothing of listed tasks goes to a peer at 1.0", async () => {
  const w = await world({ config: { feedbackTasks: LISTED, protocolVersions: ["1.1"] } });
  // A 1.0 agent at the 1.1 company: no `feedback.tasks`, and its reports are 1.0's.
  const published = await session(w);
  const answer = await w.transport.request("GET", TASKS_URL, { session: published });
  assert.deepEqual((await answer.json()).feedback, { endpoint: FEEDBACK_URL });
  const tasks = await new TasksClient({ transport: w.transport }).get(w.company, { session: published });
  assert.deepEqual([tasks.listedTasks, tasks.feedbackEndpoint], [[], FEEDBACK_URL]);
  const feedback = new FeedbackClient({ transport: w.transport });
  await assert.rejects(
    feedback.report(FEEDBACK_URL, listedReport("installments"), { session: published }),
    (error) => error instanceof RangeError && /1\.1/.test(error.message),
  );
  const raw = async (body) => {
    const headers = await sessionHeaders(w.reactor, "POST", FEEDBACK_URL, { session: published });
    return w.fetch(FEEDBACK_URL, { method: "POST", headers: { ...headers, "Content-Type": "application/json" }, body: JSON.stringify(body) });
  };
  // As 1.0 defines: a report needs `task` and `description`, and other members are ignored.
  assert.equal((await raw({ task_ids: ["installments"] })).status, 400);
  assert.equal((await raw({ task_ids: ["installments"], task: "Pay", description: "Why" })).status, 202);
  assert.deepEqual(await w.shop.feedbackTaskCounts(), { installments: 0, "split-payment": 0 });
  assert.deepEqual(w.shop.tasksDocument("1.0").feedback, { endpoint: FEEDBACK_URL });
  assert.deepEqual(w.shop.tasksDocument().feedback.tasks, LISTED);

  // A company that serves only 1.0 lists none, whatever the request names.
  serving(w, { feedbackTasks: LISTED });
  const started = await session(w, { versions: ["1.1"] });
  assert.equal(started.protocolVersion, "1.0");
  const newer = PapSession.fromJson({ ...started.toJson(), protocol_version: "1.1" });
  const served = await w.transport.request("GET", TASKS_URL, { session: newer });
  assert.ok(!("tasks" in (await served.json()).feedback));

  // A document at 1.0 whose tasks response lists tasks all the same: the agent reads it as
  // 1.0 defines, and reports nothing by ID.
  const document = { ...w.company.document, protocol_version: "1.0" };
  serving(w, { feedbackTasks: LISTED, protocolVersions: ["1.1"] });
  const wrong = await new TasksClient({ transport: w.transport }).get(document, { session: newer });
  assert.ok(wrong.available);
  assert.deepEqual([wrong.listedTasks, wrong.feedbackEndpoint], [[], FEEDBACK_URL]);
});
