/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Public clients: clients that are no personal agents (MCP clients) sign in with PKCE alone.
// Off by default. On, a public client is verified by its domain (a client ID metadata document
// that names no key) or registered itself (RFC 7591); it gets tokens for one service, rotated
// at every refresh, and nothing of the protocol: no Session, no default token, no approval.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  AgentIdentityClient,
  DeviceSignInClient,
  DiscoveryError,
  RefreshTokenClient,
  SecretValue,
  SessionClient,
  SessionFetchClient,
  discoverCompany,
  firstContribution,
  negotiateExtensions,
} from "../../lib/index.js";
import {
  isPublicLoopbackRedirect,
  parsePublicClientMetadata,
  publicClientName,
  publicRedirectUri,
  publicRedirectUriMatches,
  redirectHost,
} from "../../lib/models.js";
import { ClientPolicies, ClientResolvers, CompanyConfig, CompanyRateLimits } from "../../lib/server.js";
import { CONFIG_OPTIONS, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const SHOP = "https://manzanita.example";
const MCP = `${SHOP}/mcp`;
/** The company's MCP server on a host of its own. */
const ELSEWHERE = "https://mcp.manzanita.example/mcp";
/** A public client verified by its domain: its client ID metadata document. */
const VERIFIED = "https://client.example/oauth/client.json";
const VERIFIED_REDIRECT = "https://client.example/callback";
const LOOPBACK = "http://127.0.0.1/callback";
const LIST_TOOLS = { jsonrpc: "2.0", id: 1, method: "tools/list" };
const VERIFIER = "v".repeat(43);
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");
const DAY = 24 * 3600;

const document = (changes = {}) => ({
  client_id: VERIFIED,
  client_name: "Deskmate",
  redirect_uris: [VERIFIED_REDIRECT, LOOPBACK, "https://elsewhere.example/callback"],
  token_endpoint_auth_method: "none",
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  ...changes,
});

/** Manzanita with public clients and registration on, a verified client's site, and Atlas. */
async function world({ site, plugins, off = false, ...config } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  sites["client.example"] = { "/oauth/client.json": site ?? document() };
  const settings = off
    ? config
    : { publicClients: true, clientRegistration: true, resourceServers: [ELSEWHERE], ...config };
  const { service: shop } = manzanita({ fetch, clock, config: settings, ...(plugins ? { plugins } : {}) });
  sites["manzanita.example"] = shop;
  const call = async (method, path, { form, json, headers = {}, raw, clientAddress = "127.0.0.1" } = {}) => {
    const body = raw ?? (form ? new URLSearchParams(form).toString() : json ? JSON.stringify(json) : undefined);
    return shop.handle({
      method,
      url: path.startsWith("https://") ? path : `${SHOP}${path}`,
      headers,
      ...(body === undefined ? {} : { body }),
      ...(clientAddress === null ? {} : { clientAddress }),
    });
  };
  const w = { clock, sites, fetch, identity, shop, call };
  w.register = (changes = {}, options = {}) =>
    call("POST", "/oauth/register", {
      json: {
        client_name: "Pocket MCP",
        redirect_uris: [LOOPBACK, "https://pocket.example/callback"],
        token_endpoint_auth_method: "none",
        ...changes,
      },
      ...options,
    });
  w.registered = async (changes = {}) => {
    const answer = await w.register(changes);
    assert.equal(answer.status, 201, JSON.stringify(answer.body));
    return answer.body.client_id;
  };
  w.authorize = (clientId, redirectUri, changes = {}) => {
    const query = {
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      scope: "orders:read",
      state: "st-1",
      code_challenge: CHALLENGE,
      code_challenge_method: "S256",
      resource: MCP,
      ...changes,
    };
    for (const [name, value] of Object.entries(query)) if (value === null) delete query[name];
    return call("GET", `/oauth/authorize?${new URLSearchParams(query)}`);
  };
  w.token = (form) => call("POST", "/oauth/token", { form });
  w.codeFor = async (clientId, redirectUri, changes = {}) => {
    const shown = await w.authorize(clientId, redirectUri, changes);
    const back = await shop.approveAuthorization(requestIdOf(shown), { accountId: "acct_ada" });
    return new URL(back).searchParams.get("code");
  };
  w.signIn = async (clientId, redirectUri = LOOPBACK, { resource = MCP, scope = "orders:read" } = {}) => {
    const code = await w.codeFor(clientId, redirectUri, { resource, scope });
    const answer = await w.token({
      grant_type: "authorization_code",
      client_id: clientId,
      code,
      redirect_uri: redirectUri,
      code_verifier: VERIFIER,
      resource,
    });
    assert.equal(answer.status, 200, JSON.stringify(answer.body));
    return answer.body;
  };
  w.refresh = (clientId, refreshToken, more = {}) =>
    w.token({ grant_type: "refresh_token", client_id: clientId, refresh_token: refreshToken, resource: MCP, ...more });
  w.mcp = (accessToken, message) =>
    call("POST", "/mcp", { json: message, headers: { authorization: `Bearer ${accessToken}` } });
  return w;
}

function requestIdOf(shown) {
  assert.equal(shown.status, 200, String(shown.body));
  return /data-request-id="([^"]+)"/.exec(shown.body)[1];
}

const refusedPage = (answer) => answer.status === 400 && answer.headers.Location === undefined;

/** Atlas, a personal agent, with a Session at the company, and signed in when asked. */
async function personalAgent(w, { signIn = false } = {}) {
  const host = await agentHost({ identity: w.identity, fetch: w.fetch, clock: w.clock });
  const reactor = host.reactor;
  const company = await discoverCompany("manzanita.example", { reactor });
  const metadata = company.oauthMetadata;
  const sessions = new SessionClient({ reactor, fetch: w.fetch });
  const session = await sessions.start({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: metadata.issuer,
    tenantId: TENANT,
    extensions: negotiateExtensions(company.document.extensions, w.identity.supportedExtensions),
  });
  const transport = new SessionFetchClient({ reactor, fetch: w.fetch });
  const agent = { host, reactor, metadata, sessions, session, transport };
  if (signIn) {
    const device = new DeviceSignInClient({ reactor, fetch: w.fetch });
    const started = await device.begin({
      deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: w.identity.clientId,
      scopes: ["orders:read", "orders:write"],
      tenantId: TENANT,
      organization: company.document.organization,
    });
    await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
    w.clock.advance(started.pollInterval);
    const done = await device.poll(started.reference);
    assert.equal(done.status, "complete");
    const context = {
      tokenEndpoint: metadata.token_endpoint,
      revocationEndpoint: metadata.revocation_endpoint,
      issuer: metadata.issuer,
      clientId: w.identity.clientId,
      tenantId: TENANT,
    };
    agent.reference = done.refreshTokenReference;
    agent.refreshed = () =>
      new RefreshTokenClient({ reactor, fetch: w.fetch }).refresh(done.refreshTokenReference, { context });
  }
  return agent;
}

// Off by default ------------------------------------------------------------------------

test("off, a company answers as before", async () => {
  const w = await world({ off: true });
  assert.equal(w.shop.config.publicClients, false);
  assert.equal(w.shop.config.clientRegistration, false);
  assert.equal(w.shop.config.publicClientRefreshLifetimeSeconds, 30 * DAY);
  const metadata = w.shop.oauthMetadata();
  assert.deepEqual(metadata.token_endpoint_auth_methods_supported, ["private_key_jwt"]);
  assert.ok(!("registration_endpoint" in metadata));
  assert.ok(!("authorization_response_iss_parameter_supported" in metadata));
  assert.equal((await w.register()).status, 404);
  // A public client's document is no personal agent's: nothing verifies it.
  assert.ok(refusedPage(await w.authorize(VERIFIED, VERIFIED_REDIRECT)));
  // A token request with no assertion is `invalid_client`, as it always was.
  const refused = await w.refresh(VERIFIED, "rt_x");
  assert.deepEqual([refused.status, refused.body.error], [401, "invalid_client"]);
});

test("the settings are checked", () => {
  const config = (changes) => new CompanyConfig({ ...CONFIG_OPTIONS, ...changes });
  assert.throws(() => config({ publicClients: true, direct: false, ucp: false }), /direct/);
  assert.throws(() => config({ clientRegistration: true }), /publicClients is on/);
  assert.throws(() => config({ publicClients: true, pushedAuthorizationRequests: "required" }), /push/);
  assert.throws(() => config({ publicClients: true, publicClientScopes: ["poppy:browser-sign-in"] }), /publicClientScopes/);
  assert.throws(() => config({ publicClients: true, publicClientScopes: [] }), /publicClientScopes/);
  assert.throws(() => config({ publicClientRefreshLifetimeSeconds: 0 }), /positive/);
  assert.throws(() => config({ clientRegistrationsPerHour: 0 }), /at least 1/);
});

test("on, the issuer says so", async () => {
  const w = await world();
  const metadata = w.shop.oauthMetadata();
  assert.deepEqual(metadata.token_endpoint_auth_methods_supported, ["private_key_jwt", "none"]);
  assert.equal(metadata.registration_endpoint, `${SHOP}/oauth/register`);
  assert.equal(metadata.authorization_response_iss_parameter_supported, true);
  assert.deepEqual(metadata.code_challenge_methods_supported, ["S256"]);
  // Public clients without registration: `none`, and no endpoint to register at.
  const without = await world({ clientRegistration: false });
  assert.ok(without.shop.oauthMetadata().token_endpoint_auth_methods_supported.includes("none"));
  assert.ok(!("registration_endpoint" in without.shop.oauthMetadata()));
  assert.equal((await without.register()).status, 404);
});

// The two ways to be a public client ---------------------------------------------------------

test("a client verified by its domain signs in and calls the MCP server", async () => {
  const w = await world();
  const shown = await w.authorize(VERIFIED, VERIFIED_REDIRECT);
  const requestId = requestIdOf(shown);
  // The page is never framed, and says where the browser goes back to.
  assert.equal(shown.headers["X-Frame-Options"], "DENY");
  assert.match(shown.headers["Content-Security-Policy"], /frame-ancestors 'none'/);
  assert.match(shown.body, /<strong>client\.example<\/strong>/);
  assert.doesNotMatch(shown.body, /Unverified/);
  assert.match(shown.body, /Only continue if you asked Deskmate to do this just now\./);

  const summary = await w.shop.authorizationRequest(requestId);
  assert.equal(summary.client_class, "public_client");
  assert.equal(summary.verified, true);
  assert.equal(summary.client_name, "Deskmate");
  assert.equal(summary.client_domain, "client.example");
  assert.equal(summary.redirect_host, "client.example");
  assert.equal(summary.resource, MCP);
  assert.ok(!("state" in summary) && !("code_challenge" in summary));

  const back = new URL(await w.shop.approveAuthorization(requestId, { accountId: "acct_ada" }));
  // The answer names the issuer and gives the state back (RFC 9207, RFC 6749 §4.1.2).
  assert.equal(`${back.origin}${back.pathname}`, VERIFIED_REDIRECT);
  assert.equal(back.searchParams.get("iss"), SHOP);
  assert.equal(back.searchParams.get("state"), "st-1");

  const answer = await w.token({
    grant_type: "authorization_code",
    client_id: VERIFIED,
    code: back.searchParams.get("code"),
    redirect_uri: VERIFIED_REDIRECT,
    code_verifier: VERIFIER,
    resource: MCP,
  });
  assert.equal(answer.status, 200, JSON.stringify(answer.body));
  assert.equal(answer.body.token_type, "Bearer");
  assert.ok(answer.body.refresh_token && answer.body.access_token);
  assert.equal(answer.headers["Cache-Control"], "no-store");

  // At the MCP server: its token alone, and no Session header.
  const listed = await w.mcp(answer.body.access_token, LIST_TOOLS);
  assert.equal(listed.status, 200);
  assert.ok(listed.body.result.tools.length > 0);
  const called = await w.mcp(answer.body.access_token, {
    jsonrpc: "2.0",
    id: 2,
    method: "tools/call",
    params: { name: "list_orders" },
  });
  assert.equal(called.status, 200);
  assert.ok(!("isError" in called.body.result));
});

test("a client that registered itself is shown as unverified", async () => {
  const w = await world();
  const clientId = await w.registered();
  assert.match(clientId, /^mcpc_[A-Za-z0-9_-]{22}$/);
  const shown = await w.authorize(clientId, "http://127.0.0.1:49152/callback", { resource: ELSEWHERE });
  assert.match(shown.body, /Unverified app\./);
  assert.match(shown.body, /<strong>127\.0\.0\.1:49152<\/strong>/);
  const summary = await w.shop.authorizationRequest(requestIdOf(shown));
  assert.equal(summary.client_class, "public_client");
  assert.equal(summary.verified, false);
  assert.equal(summary.client_domain, "");
  assert.equal(summary.redirect_host, "127.0.0.1:49152");
  assert.equal(summary.resource, ELSEWHERE);

  const tokens = await w.signIn(clientId, "http://127.0.0.1:49152/callback", { resource: ELSEWHERE });
  // The service at a URL of its own reads the token's record, which says whose it is.
  const record = await w.shop.accessTokenFor(tokens.access_token, ELSEWHERE);
  assert.equal(record.public, true);
  assert.deepEqual([record.clientId, record.accountId], [clientId, "acct_ada"]);
  assert.deepEqual(record.scopes, ["orders:read"]);
  assert.equal(record.dpopJkt, undefined);
  // Issued for that service, it is nothing at the company's own MCP server.
  assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 401);
});

test("a personal agent's request says its class too", async () => {
  const w = await world();
  const shown = await w.authorize(w.identity.clientId, "https://atlas.example/oauth/callback", { resource: null });
  const summary = await w.shop.authorizationRequest(requestIdOf(shown));
  assert.equal(summary.client_class, "personal_agent");
  assert.equal(summary.verified, true);
  assert.equal(summary.redirect_host, "atlas.example");
  assert.ok(!("resource" in summary));
});

// The protocol's boundaries --------------------------------------------------------------------

test("a public client's token is refused at every endpoint of the protocol", async () => {
  const w = await world();
  const agent = await personalAgent(w);
  const clientId = await w.registered();
  const tokens = await w.signIn(clientId, LOOPBACK, { scope: "orders:read orders:write" });
  const endpoints = [
    ["POST", "/poppy/conversations", '{"message": {"text": "Hello"}}'],
    ["GET", "/poppy/conversations/conv_1", undefined],
    ["POST", "/poppy/operations", "{}"],
    ["GET", "/poppy/tasks", undefined],
    ["POST", "/poppy/feedback", '{"task": "Pay with a gift card"}'],
    ["POST", "/poppy/browser-session/authorize", "{}"],
    ["GET", "/api/orders", undefined],
  ];
  const borrowedToken = { accessToken: new SecretValue(tokens.access_token), tokenType: "Bearer" };
  for (const [method, path, body] of endpoints) {
    // Alone, as a public client sends it: there is no Session, so nothing is served.
    const alone = await w.call(method, path, {
      raw: body,
      headers: { authorization: `Bearer ${tokens.access_token}`, "content-type": "application/json" },
    });
    assert.ok([400, 401].includes(alone.status), `${path} ${alone.status}`);
    assert.ok(["invalid_session", "invalid_token"].includes(alone.body.error), `${path} ${alone.body.error}`);
    // In a personal agent's Session: a public client's token signs no Session in.
    const borrowed = await agent.transport.request(method, `${SHOP}${path}`, {
      session: agent.session,
      token: borrowedToken,
      headers: { "content-type": "application/json" },
      ...(body === undefined ? {} : { body }),
    });
    assert.ok([400, 401].includes(borrowed.status), `${path} ${borrowed.status}`);
    assert.ok(["invalid_session", "invalid_token"].includes((await borrowed.json()).error), path);
  }
  // The same at the MCP server once a Session header comes with it.
  const withSession = await agent.transport.request("POST", MCP, {
    session: agent.session,
    token: borrowedToken,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(LIST_TOOLS),
  });
  assert.equal(withSession.status, 401);
  // And no Session was started for the client, signed in or out.
  const sessions = await w.shop.store.records("session");
  assert.ok(sessions.every((record) => record.value.clientId !== clientId));
});

test("a public client never gets the default token", async () => {
  const w = await world();
  const clientId = await w.registered();
  for (const resource of [null, SHOP, `${SHOP}/poppy/conversations`, "https://other.example/mcp"]) {
    assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK, { resource })), String(resource));
  }
  const code = await w.codeFor(clientId, LOOPBACK);
  const form = {
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: LOOPBACK,
    code_verifier: VERIFIER,
  };
  // No `resource`, the default token's, or a service it was not asked for: nothing.
  assert.equal((await w.token(form)).body.error, "invalid_target");
  assert.equal((await w.token({ ...form, resource: SHOP })).body.error, "invalid_target");
  assert.equal((await w.token({ ...form, resource: ELSEWHERE })).body.error, "invalid_target");
  // The code named the MCP server: asked for another service, it is spent and gives nothing.
  assert.equal((await w.token({ ...form, resource: MCP })).body.error, "invalid_grant");

  const tokens = await w.signIn(clientId);
  assert.equal((await w.refresh(clientId, tokens.refresh_token, { resource: SHOP })).body.error, "invalid_target");
  assert.equal(
    (await w.refresh(clientId, tokens.refresh_token, { resource: ELSEWHERE })).body.error,
    "invalid_target",
  );
  // A token for the MCP server is nothing at the other service.
  assert.equal(await w.shop.accessTokenFor(tokens.access_token, ELSEWHERE), undefined);
});

test("a public client gets only its own grants and scopes", async () => {
  const w = await world();
  const clientId = await w.registered();
  // `poppy:browser-sign-in` is a personal agent's: never asked, never granted.
  assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK, { scope: "orders:read poppy:browser-sign-in" })));
  // The device and mediated grants are a personal agent's.
  for (const grant of [
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:poppy:params:oauth:grant-type:mediated",
    "client_credentials",
  ]) {
    const refused = await w.token({ grant_type: grant, client_id: clientId, resource: MCP });
    assert.equal(refused.status, 400);
    assert.ok(["unauthorized_client", "unsupported_grant_type"].includes(refused.body.error));
  }
  const device = await w.call("POST", "/oauth/device", { form: { client_id: clientId, scope: "orders:read" } });
  assert.deepEqual([device.status, device.body.error], [401, "invalid_client"]);

  const narrowed = await world({ publicClientScopes: ["orders:read"] });
  const narrowClient = await narrowed.registered();
  assert.ok(refusedPage(await narrowed.authorize(narrowClient, LOOPBACK, { scope: "orders:read orders:write" })));
  assert.equal((await narrowed.authorize(narrowClient, LOOPBACK)).status, 200);
});

test("a public client approves no operation", async () => {
  const w = await world();
  const clientId = await w.registered();
  const tokens = await w.signIn(clientId, LOOPBACK, { scope: "orders:read orders:write" });
  const called = await w.mcp(tokens.access_token, {
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: {
      name: "exchange_jacket",
      arguments: {},
      // An approval a personal agent would send: read from no public client.
      _meta: { "poppy/approval": { operation_id: "op_1", revision: 1 } },
    },
  });
  const result = called.body.result;
  assert.equal(result.isError, true);
  assert.ok(!("structuredContent" in result));
  assert.match(result.content[0].text, /personal agent/);
  assert.deepEqual(await w.shop.store.records("operation"), []);
});

test("a personal agent cannot become a public client", async () => {
  // Its assertion is never skipped: its sign-ins, codes and document stay its own.
  const w = await world();
  const agent = await personalAgent(w, { signIn: true });
  const kept = agent.host.tokens.get(agent.reference);
  const agentRefresh = typeof kept === "string" ? kept : kept.reveal();
  const clientId = await w.registered();

  // Its own `client_id`, no assertion: its document names its keys, so it is no public client.
  const bare = await w.refresh(w.identity.clientId, agentRefresh);
  assert.deepEqual([bare.status, bare.body.error], [401, "invalid_client"]);
  // Its refresh token under a public client's `client_id`: not that class of sign-in.
  const borrowed = await w.refresh(clientId, agentRefresh);
  assert.deepEqual([borrowed.status, borrowed.body.error], [400, "invalid_grant"]);
  // Neither attempt ended its sign-in: it refreshes as before.
  assert.ok((await agent.refreshed()).token);

  // Its authorization code is exchanged with its assertion only.
  const shown = await w.authorize(w.identity.clientId, "https://atlas.example/oauth/callback", { resource: null });
  const back = await w.shop.approveAuthorization(requestIdOf(shown), { accountId: "acct_ada" });
  const agentCode = new URL(back).searchParams.get("code");
  for (const claimed of [w.identity.clientId, clientId]) {
    const refused = await w.token({
      grant_type: "authorization_code",
      client_id: claimed,
      code: agentCode,
      redirect_uri: "https://atlas.example/oauth/callback",
      code_verifier: VERIFIER,
      resource: MCP,
    });
    assert.ok([400, 401].includes(refused.status));
    assert.ok(["invalid_client", "invalid_grant"].includes(refused.body.error));
  }

  // Someone who only intercepted the code and posts it without an assertion gets nothing, and
  // spent it: the agent's own exchange finds it used.
  const owned = await w.token({
    grant_type: "authorization_code",
    code: agentCode,
    redirect_uri: "https://atlas.example/oauth/callback",
    code_verifier: VERIFIER,
    ...(await agent.sessions.clientAuthentication({ clientId: w.identity.clientId, issuer: SHOP })),
  });
  assert.deepEqual([owned.status, owned.body.error], [400, "invalid_grant"]);

  // And a public client's code is nothing to a personal agent with a valid assertion.
  const publicCode = await w.codeFor(clientId, LOOPBACK);
  const crossed = await w.token({
    grant_type: "authorization_code",
    code: publicCode,
    redirect_uri: LOOPBACK,
    code_verifier: VERIFIER,
    ...(await agent.sessions.clientAuthentication({ clientId: w.identity.clientId, issuer: SHOP })),
  });
  assert.deepEqual([crossed.status, crossed.body.error], [400, "invalid_grant"]);
});

test("a document is one class of client and never both", async () => {
  const both = document({ jwks_uri: "https://client.example/jwks.json" });
  assert.throws(() => parsePublicClientMetadata(both));
  assert.throws(() => parsePublicClientMetadata(document({ token_endpoint_auth_method: "private_key_jwt" })));
  // Said, never assumed: a document that leaves the method out is no public client's.
  const { token_endpoint_auth_method: _method, ...silent } = document();
  assert.throws(() => parsePublicClientMetadata(silent));
  assert.throws(() => parsePublicClientMetadata(document({ client_secret: "s3cret" })));
  assert.throws(() => parsePublicClientMetadata(document({ grant_types: ["client_credentials"] })));
  assert.throws(() => parsePublicClientMetadata(document({ client_name: "a‮b" })));
  const w = await world({ site: both });
  assert.ok(refusedPage(await w.authorize(VERIFIED, VERIFIED_REDIRECT)));

  // A redirect on another host than the document's is never matched; loopback is.
  const plain = await world();
  assert.ok(refusedPage(await plain.authorize(VERIFIED, "https://elsewhere.example/callback")));
  assert.equal((await plain.authorize(VERIFIED, "http://127.0.0.1:8123/callback")).status, 200);
});

test("a document at a private address is never fetched", async () => {
  const fetched = [];
  const fetch = async (input) => {
    fetched.push(String(input));
    return new Response(JSON.stringify(document()), { headers: { "content-type": "application/json" } });
  };
  // The portable check refuses what a URL says of itself; where a name resolves is the
  // company's transport's to check on Node (`createResolvingFetch`), or the host's policy.
  const refusing = new AgentIdentityClient({
    fetch,
    assertSafeUrl: () => {
      throw new DiscoveryError("unsafe_address", "resolves to a private address");
    },
  });
  await assert.rejects(refusing.fetchPublicMetadata(VERIFIED));
  const identity = new AgentIdentityClient({ fetch });
  for (const literal of [
    "https://127.0.0.1/client.json",
    "https://169.254.169.254/latest/meta-data",
    "https://[::1]/client.json",
    "https://10.0.0.7/client.json",
    "https://localhost/client.json",
    "https://client.internal/client.json",
    "http://client.example/oauth/client.json",
  ]) {
    await assert.rejects(identity.fetchPublicMetadata(literal), literal);
  }
  assert.deepEqual(fetched, []);
});

test("a document that redirects or names another URL is refused", async () => {
  const redirecting = async () => new Response(null, { status: 302, headers: { location: "https://10.0.0.7/c.json" } });
  const another = async () =>
    new Response(JSON.stringify(document({ client_id: "https://other.example/client.json" })), {
      headers: { "content-type": "application/json" },
    });
  for (const fetch of [redirecting, another]) {
    const identity = new AgentIdentityClient({ fetch });
    await assert.rejects(identity.fetchPublicMetadata(VERIFIED));
  }
});

// PKCE, codes, redirects -----------------------------------------------------------------------

test("PKCE is the only proof and is never skipped", async () => {
  const w = await world();
  const clientId = await w.registered();
  for (const changes of [
    { code_challenge: null },
    { code_challenge_method: null },
    { code_challenge_method: "plain" },
    { code_challenge: "short" },
    { response_type: "token" },
  ]) {
    // An unverified client is answered a page, never a redirect.
    assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK, changes)), JSON.stringify(changes));
  }
  const form = { grant_type: "authorization_code", client_id: clientId, redirect_uri: LOOPBACK, resource: MCP };
  for (const verifier of [undefined, "", "w".repeat(43), "v".repeat(42), "v".repeat(129), `${"v".repeat(42)}!`]) {
    const code = await w.codeFor(clientId, LOOPBACK);
    const refused = await w.token({ ...form, code, ...(verifier === undefined ? {} : { code_verifier: verifier }) });
    assert.deepEqual([refused.status, refused.body.error], [400, "invalid_grant"], String(verifier));
    // A refused exchange spent the code: the right verifier gets nothing after it.
    assert.equal((await w.token({ ...form, code, code_verifier: VERIFIER })).body.error, "invalid_grant");
  }
  // A code is the client's it was issued to, for the redirect it was issued for, once.
  const other = await w.registered({ client_name: "Another" });
  let code = await w.codeFor(clientId, LOOPBACK);
  assert.equal(
    (await w.token({ ...form, client_id: other, code, code_verifier: VERIFIER })).body.error,
    "invalid_grant",
  );
  code = await w.codeFor(clientId, LOOPBACK);
  const moved = await w.token({ ...form, code, code_verifier: VERIFIER, redirect_uri: "http://127.0.0.1:1/callback" });
  assert.equal(moved.body.error, "invalid_grant");
  code = await w.codeFor(clientId, LOOPBACK);
  assert.equal((await w.token({ ...form, code, code_verifier: VERIFIER })).status, 200);
  assert.equal((await w.token({ ...form, code, code_verifier: VERIFIER })).body.error, "invalid_grant");
});

test("a redirect URI is loopback or HTTPS and nothing else", () => {
  for (const accepted of [
    "https://client.example/callback",
    "https://client.example:8443/callback?tenant=1",
    "https://xn--bcher-kva.example/cb",
    "http://127.0.0.1/callback",
    "http://127.0.0.1:53211/callback",
    "http://[::1]:53211/callback",
    "http://localhost:53211/callback",
  ]) {
    assert.equal(publicRedirectUri(accepted), accepted);
  }
  for (const refused of [
    "",
    "HTTPS://client.example/callback",
    "https:/client.example/callback",
    "https://client.example.:443/callback",
    "http://client.example/callback",
    "https://user@client.example/callback",
    "https://user:pw@client.example/callback",
    "https://client.example@evil.example/callback",
    "https://client.example/callback#fragment",
    "https://client.example/callback#",
    "https://Client.example/callback",
    "https://client.example\\@evil.example/callback",
    "https://client.example /callback",
    "https://client.example/call\tback",
    "https://client.example/call\nback",
    "https:///callback",
    "https://client.example:0/callback",
    "https://client.example:70000/callback",
    "https://[::1]/callback",
    "https://bücher.example/cb",
    "http://127.0.0.1.evil.example/callback",
    "http://127.0.0.1:80@evil.example/callback",
    "http://localhost.evil.example/callback",
    "http://127.1/callback",
    "http://2130706433/callback",
    "http://0.0.0.0/callback",
    "http://10.0.0.1/callback",
    "http://localhost:99999/callback",
    "cursor://callback",
    "javascript:alert(1)",
    "data:text/html,x",
    "//client.example/callback",
    `https://client.example/${"a".repeat(2000)}`,
    7,
    undefined,
  ]) {
    assert.throws(() => publicRedirectUri(refused), RangeError, String(refused));
  }
  assert.ok(isPublicLoopbackRedirect("http://localhost/cb"));
  assert.ok(!isPublicLoopbackRedirect("https://localhost/cb"));
});

test("a redirect URI matches exactly but for a loopback port", () => {
  const https = "https://client.example/callback";
  assert.ok(publicRedirectUriMatches(https, https));
  for (const other of [
    "https://client.example/callback/",
    "https://client.example/callback?next=https://evil.example",
    "https://client.example/callback/../evil",
    "https://client.example:8443/callback",
    "https://client.example/Callback",
    "https://client.example.evil.example/callback",
    "https://evil.example/callback",
    "https://client.example/callback#x",
    "https://client.example/callback%2f..",
  ]) {
    assert.ok(!publicRedirectUriMatches(https, other), other);
  }
  const loopback = "http://127.0.0.1/callback";
  assert.ok(publicRedirectUriMatches(loopback, "http://127.0.0.1:53211/callback"));
  for (const other of [
    "http://127.0.0.1:53211/other",
    "http://127.0.0.1:53211/callback?x=1",
    "http://localhost:53211/callback",
    "http://[::1]:53211/callback",
    "https://127.0.0.1:53211/callback",
    "http://127.0.0.1:53211@evil.example/callback",
    "http://127.0.0.1:99999/callback",
  ]) {
    assert.ok(!publicRedirectUriMatches(loopback, other), other);
  }
});

test("a request with another redirect is never redirected", async () => {
  const w = await world();
  const clientId = await w.registered({ redirect_uris: ["https://pocket.example/callback"] });
  for (const redirectUri of [
    "https://pocket.example/callback?next=https://evil.example",
    "https://pocket.example/callback/..%2fevil",
    "https://user@pocket.example/callback",
    "https://pocket.example.evil.example/callback",
    "https://pocket.example/callback#x",
    "https://evil.example/callback",
    "http://127.0.0.1/callback",
    "",
  ]) {
    assert.ok(refusedPage(await w.authorize(clientId, redirectUri)), redirectUri);
  }
});

test("an unverified client's errors are pages and a verified one's redirects", async () => {
  // Anyone registers any HTTPS redirect: answered with no one's consent, an error would make
  // the authorization endpoint an open redirector (RFC 9700 §4.11.2).
  const w = await world();
  const clientId = await w.registered({ redirect_uris: ["https://pocket.example/callback"] });
  for (const changes of [{ scope: "nothing:here" }, { scope: "" }, { resource: SHOP }]) {
    assert.ok(
      refusedPage(await w.authorize(clientId, "https://pocket.example/callback", changes)),
      JSON.stringify(changes),
    );
  }
  // A client verified by its domain is answered at its own domain, with state and issuer.
  const answered = await w.authorize(VERIFIED, VERIFIED_REDIRECT, { scope: "nothing:here" });
  assert.equal(answered.status, 303);
  const location = new URL(answered.headers.Location);
  assert.equal(`${location.origin}${location.pathname}`, VERIFIED_REDIRECT);
  assert.deepEqual(Object.fromEntries(location.searchParams), {
    error: "invalid_scope",
    state: "st-1",
    iss: SHOP,
  });
  // A refusal by the person reaches either, after they decided.
  const shown = await w.authorize(clientId, "https://pocket.example/callback");
  const denied = new URL(await w.shop.denyAuthorization(requestIdOf(shown)));
  assert.deepEqual(Object.fromEntries(denied.searchParams), { error: "access_denied", state: "st-1", iss: SHOP });
});

test("a decision counts once and the name is shown as text", async () => {
  const w = await world();
  const clientId = await w.registered({ client_name: "<img src=x onerror=alert(1)>" });
  const shown = await w.authorize(clientId, LOOPBACK);
  assert.doesNotMatch(shown.body, /<img/);
  assert.match(shown.body, /&lt;img/);
  const requestId = requestIdOf(shown);
  await w.shop.approveAuthorization(requestId, { accountId: "acct_ada" });
  await assert.rejects(w.shop.approveAuthorization(requestId, { accountId: "acct_ada" }));
  await assert.rejects(w.shop.denyAuthorization(requestId));
});

// Refresh tokens -------------------------------------------------------------------------------

test("a refresh token is rotated and one used twice ends the sign-in", async () => {
  const w = await world();
  // Whatever the setting says for personal agents.
  assert.equal(w.shop.config.refreshReuseRevokes, false);
  const clientId = await w.registered();
  const tokens = await w.signIn(clientId);
  const first = await w.refresh(clientId, tokens.refresh_token);
  assert.equal(first.status, 200, JSON.stringify(first.body));
  const rotated = first.body;
  assert.notEqual(rotated.refresh_token, tokens.refresh_token);
  assert.equal(rotated.token_type, "Bearer");
  assert.equal((await w.mcp(rotated.access_token, LIST_TOOLS)).status, 200);

  // The first one again: whoever holds a copy, the whole sign-in ends.
  const replayed = await w.refresh(clientId, tokens.refresh_token);
  assert.deepEqual([replayed.status, replayed.body.error], [400, "invalid_grant"]);
  assert.equal((await w.refresh(clientId, rotated.refresh_token)).body.error, "invalid_grant");
  for (const accessToken of [tokens.access_token, rotated.access_token]) {
    assert.equal((await w.mcp(accessToken, LIST_TOOLS)).status, 401);
  }
  assert.deepEqual(await w.shop.publicClientSignIns(), []);
});

test("a refresh token is its client's and lasts thirty days", async () => {
  const w = await world();
  const clientId = await w.registered();
  const other = await w.registered({ client_name: "Another" });
  const tokens = await w.signIn(clientId);
  assert.equal((await w.refresh(other, tokens.refresh_token)).body.error, "invalid_grant");
  const unknown = await w.refresh("mcpc_AAAAAAAAAAAAAAAAAAAAAA", tokens.refresh_token);
  assert.deepEqual([unknown.status, unknown.body.error], [401, "invalid_client"]);
  // Narrower scopes only.
  assert.equal(
    (await w.refresh(clientId, tokens.refresh_token, { scope: "orders:write" })).body.error,
    "invalid_scope",
  );
  w.clock.advance(29 * DAY);
  const kept = await w.refresh(clientId, tokens.refresh_token);
  assert.equal(kept.status, 200);
  // Thirty days from the sign-in, not from the last refresh.
  w.clock.advance(2 * DAY);
  assert.equal((await w.refresh(clientId, kept.body.refresh_token)).body.error, "invalid_grant");
});

test("no token of a sign-in outlives it", async () => {
  // Thirty days from the consent, exactly: refreshed a minute before they end, the access
  // token ends with them. Once the sign-in is over its owner can no longer list or revoke it.
  const w = await world();
  const clientId = await w.registered();
  const tokens = await w.signIn(clientId, LOOPBACK, { resource: ELSEWHERE });
  assert.equal(tokens.expires_in, 3600);
  w.clock.advance(30 * DAY - 60);
  const last = await w.refresh(clientId, tokens.refresh_token, { resource: ELSEWHERE });
  assert.equal(last.status, 200);
  assert.ok(last.body.expires_in > 0 && last.body.expires_in <= 60);
  const late = last.body.access_token;
  const record = await w.shop.accessTokenFor(late, ELSEWHERE);
  assert.equal(record.expiresAt, (await w.shop.publicClientSignIns())[0].expiresAt);
  w.clock.advance(59);
  assert.ok(await w.shop.accessTokenFor(late, ELSEWHERE));
  // The deadline: refused at the resource server, and nothing is left to list.
  w.clock.advance(1);
  assert.equal(await w.shop.accessTokenFor(late, ELSEWHERE), undefined);
  assert.deepEqual(await w.shop.publicClientSignIns(), []);
  const after = await w.refresh(clientId, last.body.refresh_token, { resource: ELSEWHERE });
  assert.equal(after.body.error, "invalid_grant");
  // The same at the company's own MCP server.
  const own = await w.signIn(clientId);
  w.clock.advance(30 * DAY - 60);
  const lastOwn = (await w.refresh(clientId, own.refresh_token)).body;
  assert.ok(lastOwn.expires_in > 0 && lastOwn.expires_in <= 60);
  assert.equal((await w.mcp(lastOwn.access_token, LIST_TOOLS)).status, 200);
  w.clock.advance(60);
  assert.equal((await w.mcp(lastOwn.access_token, LIST_TOOLS)).status, 401);
});

test("a token whose sign-in record is gone is refused", async () => {
  // Whatever the token's own record says: it is held to its sign-in, which the owner lists
  // and revokes.
  for (const kind of ["refresh_token", "account_family"]) {
    const w = await world();
    const clientId = await w.registered();
    const elsewhere = await w.signIn(clientId, LOOPBACK, { resource: ELSEWHERE });
    const own = await w.signIn(clientId);
    assert.ok(await w.shop.accessTokenFor(elsewhere.access_token, ELSEWHERE));
    assert.equal((await w.mcp(own.access_token, LIST_TOOLS)).status, 200);
    for (const entry of await w.shop.publicClientSignIns()) await w.shop.store.delete(kind, entry.signInId);
    assert.equal(await w.shop.accessTokenFor(elsewhere.access_token, ELSEWHERE), undefined, kind);
    assert.equal((await w.mcp(own.access_token, LIST_TOOLS)).status, 401, kind);
  }
});

test("a public client revokes its own sign-in", async () => {
  const w = await world();
  const clientId = await w.registered();
  const other = await w.registered({ client_name: "Another" });
  const tokens = await w.signIn(clientId);
  // Another client's request ends nothing.
  await w.call("POST", "/oauth/revoke", { form: { client_id: other, token: tokens.refresh_token } });
  assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 200);
  const done = await w.call("POST", "/oauth/revoke", { form: { client_id: clientId, token: tokens.refresh_token } });
  assert.equal(done.status, 200);
  assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 401);
  assert.equal((await w.refresh(clientId, tokens.refresh_token)).body.error, "invalid_grant");
});

// Registration ---------------------------------------------------------------------------------

test("only a public client registers", async () => {
  const w = await world({ clientRegistrationsPerHour: 1000 });
  const accepted = await w.register();
  assert.equal(accepted.status, 201);
  assert.equal(accepted.headers["Cache-Control"], "no-store");
  assert.equal(accepted.body.token_endpoint_auth_method, "none");
  assert.deepEqual(accepted.body.grant_types, ["authorization_code", "refresh_token"]);
  assert.deepEqual(accepted.body.response_types, ["code"]);
  assert.ok(!("client_secret" in accepted.body) && !("registration_access_token" in accepted.body));
  assert.equal((await w.register({ client_name: null })).status, 400);
  // Another method, a null one, or a key or a secret of its own: told exactly what to send.
  for (const changes of [
    { token_endpoint_auth_method: "private_key_jwt" },
    { token_endpoint_auth_method: null },
    { client_secret: "s3cret" },
  ]) {
    const told = (await w.register(changes)).body;
    assert.equal(told.error, "invalid_client_metadata");
    assert.match(told.error_description, /"token_endpoint_auth_method": "none"/);
  }

  const refusals = [
    [{ token_endpoint_auth_method: "tls_client_auth" }, "invalid_client_metadata"],
    [{ token_endpoint_auth_method: "NONE" }, "invalid_client_metadata"],
    [{ token_endpoint_auth_method: "client_secret_jwt" }, "invalid_client_metadata"],
    [{ token_endpoint_auth_method: "private_key_jwt" }, "invalid_client_metadata"],
    [{ token_endpoint_auth_method: null }, "invalid_client_metadata"],
    [{ jwks_uri: "https://pocket.example/jwks.json" }, "invalid_client_metadata"],
    [{ jwks: { keys: [] } }, "invalid_client_metadata"],
    [{ client_secret: "s3cret" }, "invalid_client_metadata"],
    [{ grant_types: ["client_credentials"] }, "invalid_client_metadata"],
    [{ grant_types: ["refresh_token"] }, "invalid_client_metadata"],
    [
      { grant_types: ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"] },
      "invalid_client_metadata",
    ],
    [{ grant_types: ["authorization_code", {}] }, "invalid_client_metadata"],
    [{ grant_types: ["authorization_code", ["refresh_token"]] }, "invalid_client_metadata"],
    [{ grant_types: { authorization_code: 1 } }, "invalid_client_metadata"],
    [{ response_types: ["token"] }, "invalid_client_metadata"],
    [{ response_types: [{}] }, "invalid_client_metadata"],
    [{ redirect_uris: [{}] }, "invalid_redirect_uri"],
    [{ redirect_uris: [[LOOPBACK]] }, "invalid_redirect_uri"],
    [{ client_name: "" }, "invalid_client_metadata"],
    [{ client_name: "x".repeat(101) }, "invalid_client_metadata"],
    [{ client_name: "Claude‮ (verified)" }, "invalid_client_metadata"],
    [{ client_name: "Claude\u0000" }, "invalid_client_metadata"],
    [{ client_name: 7 }, "invalid_client_metadata"],
    [{ redirect_uris: [] }, "invalid_redirect_uri"],
    [{ redirect_uris: "https://pocket.example/callback" }, "invalid_redirect_uri"],
    [{ redirect_uris: [LOOPBACK, LOOPBACK] }, "invalid_redirect_uri"],
    [{ redirect_uris: Array.from({ length: 11 }, (_, n) => `https://pocket.example/${n}`) }, "invalid_redirect_uri"],
    [{ redirect_uris: ["http://pocket.example/callback"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["cursor://callback"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["https://user@pocket.example/cb"] }, "invalid_redirect_uri"],
    [{ redirect_uris: ["https://pocket.example/cb#x"] }, "invalid_redirect_uri"],
    [{ redirect_uris: [LOOPBACK, 7] }, "invalid_redirect_uri"],
  ];
  for (const [changes, error] of refusals) {
    const refused = await w.register(changes);
    assert.deepEqual([refused.status, refused.body.error], [400, error], JSON.stringify(changes));
  }
  for (const raw of ["[]", "not json", '{"a": 1, "a": 2}', " ".repeat(16 * 1024 + 1)]) {
    const refused = await w.call("POST", "/oauth/register", { raw });
    assert.equal(refused.status, 400, raw.slice(0, 10));
  }
});

test("whatever method a registration asks for, it is registered as public", async () => {
  // RFC 7591 §3.2.1: the server may replace what was requested, and the client uses what is
  // returned. Left out, `none`, or a method that only says how a secret would be sent: a public
  // client each time, told so, with no secret.
  const w = await world({ clientRegistrationsPerHour: 1000 });
  for (const method of [
    {},
    { token_endpoint_auth_method: "none" },
    { token_endpoint_auth_method: "client_secret_post" },
    { token_endpoint_auth_method: "client_secret_basic" },
  ]) {
    const answer = await w.call("POST", "/oauth/register", {
      json: { client_name: "Pocket MCP", redirect_uris: [LOOPBACK], ...method },
    });
    assert.equal(answer.status, 201, JSON.stringify(method));
    assert.equal(answer.body.token_endpoint_auth_method, "none", JSON.stringify(method));
    assert.ok(!("client_secret" in answer.body) && !("client_secret_expires_at" in answer.body));
    assert.deepEqual(answer.body.grant_types, ["authorization_code", "refresh_token"]);
    // It signs in as any public client does: PKCE, and no secret.
    const tokens = await w.signIn(answer.body.client_id);
    assert.equal(tokens.token_type, "Bearer");
    assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 200);
  }
  // None of them is anything but a public client's record.
  for (const record of await w.shop.store.records("public_client")) {
    assert.deepEqual(Object.keys(record.value).sort(), ["clientId", "clientName", "redirectUris", "registeredAt"]);
  }
});

test("a secret sent at the token endpoint is refused, never taken", async () => {
  // No client has one. A request that sends one, in its form or as HTTP Basic, is refused and
  // told why: never served as if the secret had been right, and it spends nothing.
  const w = await world();
  const clientId = await w.registered({ token_endpoint_auth_method: "client_secret_post" });
  const code = await w.codeFor(clientId, LOOPBACK);
  const form = {
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: LOOPBACK,
    code_verifier: VERIFIER,
    resource: MCP,
  };
  const basic = { authorization: `Basic ${Buffer.from(`${clientId}:guess`).toString("base64")}` };
  for (const refused of [
    await w.token({ ...form, client_secret: "guess" }),
    await w.call("POST", "/oauth/token", { form, headers: basic }),
  ]) {
    assert.deepEqual([refused.status, refused.body.error], [401, "invalid_client"]);
    assert.match(refused.body.error_description, /no secret/);
  }
  // The code was not spent: the same request without a secret signs in.
  const signedIn = await w.token(form);
  assert.equal(signedIn.status, 200, JSON.stringify(signedIn.body));
  const tokens = signedIn.body;
  const withSecret = await w.refresh(clientId, tokens.refresh_token, { client_secret: "guess" });
  assert.deepEqual([withSecret.status, withSecret.body.error], [401, "invalid_client"]);
  const revoking = await w.call("POST", "/oauth/revoke", {
    form: { client_id: clientId, token: tokens.refresh_token, client_secret: "guess" },
  });
  assert.equal(revoking.status, 401);
  // Neither spent the refresh token nor ended the sign-in.
  assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 200);
  assert.equal((await w.refresh(clientId, tokens.refresh_token)).status, 200);
});

test("a malformed registration is the caller's mistake, never an error of ours", async () => {
  // Nobody signed the body: whatever is in it, the answer is 400 and says so.
  const w = await world({ clientRegistrationsPerHour: 1000 });
  const odd = [null, true, 7, 1.5, "text", [], {}, [[]], [{}], { a: { b: [] } }, [null]];
  for (const member of [
    "token_endpoint_auth_method",
    "grant_types",
    "response_types",
    "redirect_uris",
    "client_name",
    "scope",
    "jwks",
    "jwks_uri",
    "client_secret",
  ]) {
    for (const value of odd) {
      if (value === "text" && (member === "scope" || member === "client_name")) continue;
      const answer = await w.register({ [member]: value });
      assert.equal(answer.status, 400, `${member} ${JSON.stringify(value)}`);
      assert.ok(["invalid_client_metadata", "invalid_redirect_uri"].includes(answer.body.error), member);
    }
  }
  // Members a public client may send and the company does not read: taken, whatever they are.
  for (const member of ["contacts", "client_uri", "logo_uri", "tos_uri", "software_id", "unknown"]) {
    for (const value of odd) {
      assert.equal((await w.register({ [member]: value })).status, 201, `${member} ${JSON.stringify(value)}`);
    }
  }
  // Entries of the wrong type, too many, too long.
  for (const changes of [
    { redirect_uris: [LOOPBACK, null] },
    { redirect_uris: [LOOPBACK, { uri: LOOPBACK }] },
    { redirect_uris: [LOOPBACK, LOOPBACK] },
    { redirect_uris: [`https://pocket.example/${"a".repeat(2000)}`] },
    { redirect_uris: { 0: LOOPBACK } },
    { grant_types: ["authorization_code", null] },
    { grant_types: [["authorization_code"]] },
    { response_types: ["code", "code"] },
    { response_types: [null] },
    { client_name: ["Pocket"] },
  ]) {
    assert.equal((await w.register(changes)).status, 400, JSON.stringify(changes));
  }
  // Bodies that are no registration, nested deeper than anything reads.
  const deep = "[".repeat(8000) + "]".repeat(8000);
  for (const raw of [
    "",
    "null",
    "7",
    '"text"',
    "[]",
    "{",
    '{"token_endpoint_auth_method": "none", "token_endpoint_auth_method": "none"}',
    '{"redirect_uris": NaN}',
    deep,
    `{"redirect_uris": ${deep}, "token_endpoint_auth_method": "none"}`,
    " ".repeat(16 * 1024 + 1),
    new Uint8Array([0xff, 0xfe]),
  ]) {
    const answer = await w.call("POST", "/oauth/register", { raw });
    assert.equal(answer.status, 400, String(raw).slice(0, 20));
    assert.equal(answer.body.error, "invalid_client_metadata", String(raw).slice(0, 20));
  }
});

test("what no check foresaw is refused and logged", async (t) => {
  const w = await world();
  const logged = [];
  t.mock.method(console, "error", (...said) => logged.push(said));
  // A store that fails where the registration is kept: a bug, or an outage, of ours.
  const put = w.shop.store.put.bind(w.shop.store);
  w.shop.store.put = async (kind, ...rest) => {
    if (kind === "public_client") throw new TypeError("a bug of ours");
    return put(kind, ...rest);
  };
  const answer = await w.register();
  assert.deepEqual([answer.status, answer.body.error], [400, "invalid_client_metadata"]);
  assert.equal(logged.length, 1);
  assert.match(String(logged[0][1]), /a bug of ours/);
});

test("a document of any shape is refused, not thrown", async () => {
  for (const changes of [
    { redirect_uris: "https://client.example/callback" },
    { redirect_uris: [7, null, {}] },
    { redirect_uris: [] },
    { client_name: 7 },
    { client_name: null },
    { client_id: 7 },
    { grant_types: "authorization_code" },
    { grant_types: [{}] },
    { response_types: [[]] },
    { token_endpoint_auth_method: ["none"] },
    { logo_uri: 7 },
  ]) {
    assert.throws(() => parsePublicClientMetadata(document(changes)), JSON.stringify(changes));
    const w = await world({ site: document(changes) });
    assert.ok(refusedPage(await w.authorize(VERIFIED, VERIFIED_REDIRECT)), JSON.stringify(changes));
  }
  for (const site of [[], "text", 7, null, [document()]]) {
    const w = await world();
    w.sites["client.example"] = { "/oauth/client.json": site };
    assert.ok(refusedPage(await w.authorize(VERIFIED, VERIFIED_REDIRECT)), JSON.stringify(site));
    assert.equal((await w.refresh(VERIFIED, "rt_x")).status, 401, JSON.stringify(site));
  }
});

test("registration is limited by address", async () => {
  const w = await world({ clientRegistrationsPerHour: 3 });
  for (let n = 0; n < 3; n += 1) assert.equal((await w.register()).status, 201);
  const limited = await w.register();
  assert.equal(limited.status, 429);
  const wait = Number(limited.headers["Retry-After"]);
  assert.ok(wait > 0 && wait <= 3600);
  // A refused registration counts too: the limit is on asking, not on succeeding.
  assert.equal((await w.register({ redirect_uris: [] })).status, 429);
  w.clock.advance(3601);
  assert.equal((await w.register()).status, 201);
  // Another address has its own count; a request that names none shares one.
  const statuses = [];
  for (const clientAddress of ["203.0.113.5", "203.0.113.5", null, null]) {
    statuses.push((await w.register({}, { clientAddress })).status);
  }
  assert.deepEqual(statuses, [201, 201, 201, 201]);
});

test("the host's rate limit is asked by address before anything is read", async () => {
  const asked = [];
  const limit = {
    admit: async (clientId, accountId) => {
      asked.push([clientId, accountId]);
      return clientId.startsWith("registration:") ? 120 : undefined;
    },
  };
  const w = await world({
    plugins: [{ name: "limit", version: "1", contributes: [{ point: CompanyRateLimits, value: limit }] }],
  });
  const refused = await w.call("POST", "/oauth/register", { raw: "not json" });
  assert.equal(refused.status, 429);
  assert.equal(refused.headers["Retry-After"], "120");
  assert.deepEqual(asked, [["registration:127.0.0.1", undefined]]);
  assert.deepEqual(await w.shop.store.records("public_client"), []);
});

test("a registration is kept briefly until it is used, and long after", async () => {
  const w = await world();
  // Never used: gone an hour after it registered, so registering alone fills nothing.
  const unused = await w.registered({ client_name: "Never used" });
  w.clock.advance(3599);
  assert.equal((await w.authorize(unused, LOOPBACK)).status, 200);
  w.clock.advance(2);
  assert.ok(refusedPage(await w.authorize(unused, LOOPBACK)));
  assert.deepEqual(await w.shop.store.records("public_client"), []);

  // Signed in within the hour: kept ninety days from then, outliving the sign-in it gave.
  const clientId = await w.registered();
  w.clock.advance(1800);
  const tokens = await w.signIn(clientId);
  w.clock.advance(20 * DAY);
  assert.equal((await w.refresh(clientId, tokens.refresh_token)).status, 200);
  w.clock.advance(69 * DAY);
  assert.ok((await w.signIn(clientId)).access_token);
  w.clock.advance(91 * DAY);
  assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK)));
});

test("requests without an assertion are limited by address", async () => {
  // Each may make the company read a client's document: the host's limit is asked first, by
  // address, never by the `client_id` the request invents.
  const asked = [];
  let refusing = true;
  const limit = {
    admit: async (clientId, accountId) => {
      asked.push([clientId, accountId]);
      return refusing && clientId.startsWith("public:") ? 30 : undefined;
    },
  };
  const w = await world({
    plugins: [{ name: "limit", version: "1", contributes: [{ point: CompanyRateLimits, value: limit }] }],
  });
  const fetched = [];
  const site = w.sites["client.example"];
  w.sites["client.example"] = new Proxy(site, {
    get: (target, path) => {
      fetched.push(path);
      return target[path];
    },
  });
  const limited = await w.refresh(VERIFIED, "rt_x");
  assert.equal(limited.status, 429);
  assert.equal(limited.headers["Retry-After"], "30");
  const revoked = await w.call("POST", "/oauth/revoke", {
    form: { client_id: "https://anything.example/c", token: "rt_x" },
  });
  assert.equal(revoked.status, 429);
  assert.deepEqual(asked, [
    ["public:127.0.0.1", undefined],
    ["public:127.0.0.1", undefined],
  ]);
  // Refused before the client was looked at: nothing was fetched for it.
  assert.deepEqual(fetched, []);
  refusing = false;
  assert.equal((await w.refresh(VERIFIED, "rt_x")).body.error, "invalid_grant");
  assert.ok(fetched.includes("/oauth/client.json"));
});

// The client policy, and what the company gives now -------------------------------------------

function policyOf(w) {
  const policy = firstContribution(w.shop.reactor, ClientPolicies, "policy");
  const state = { blocked: new Set(), noSignIn: new Set(), noResource: new Set() };
  policy.allows = async (clientId) => !state.blocked.has(clientId);
  policy.allowsSignIn = async (clientId) => !state.noSignIn.has(clientId);
  policy.allowsResource = async (clientId, resource) => !state.noResource.has(`${clientId} ${resource}`);
  return state;
}

test("the client policy is asked each time and before anything is fetched", async () => {
  const w = await world();
  const policy = policyOf(w);
  const clientId = await w.registered();
  const own = await w.signIn(clientId);
  const elsewhere = await w.signIn(clientId, LOOPBACK, { resource: ELSEWHERE });
  assert.ok(await w.shop.accessTokenFor(elsewhere.access_token, ELSEWHERE));

  // Left out of one service: its token for it stops at once, the other still works.
  policy.noResource.add(`${clientId} ${ELSEWHERE}`);
  assert.equal(await w.shop.accessTokenFor(elsewhere.access_token, ELSEWHERE), undefined);
  assert.equal((await w.mcp(own.access_token, LIST_TOOLS)).status, 200);
  assert.equal(
    (await w.refresh(clientId, elsewhere.refresh_token, { resource: ELSEWHERE })).body.error,
    "invalid_target",
  );
  assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK, { resource: ELSEWHERE })));
  policy.noResource.clear();

  // Refused sign-in: nothing new, and a code already issued gives nothing.
  const code = await w.codeFor(clientId, LOOPBACK);
  policy.noSignIn.add(clientId);
  assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK)));
  const late = await w.token({
    grant_type: "authorization_code",
    client_id: clientId,
    code,
    redirect_uri: LOOPBACK,
    code_verifier: VERIFIER,
    resource: MCP,
  });
  assert.equal(late.body.error, "unauthorized_client");
  policy.noSignIn.clear();

  // Blocked: every token stops at once, everywhere.
  policy.blocked.add(clientId);
  assert.equal((await w.mcp(own.access_token, LIST_TOOLS)).status, 401);
  assert.equal(await w.shop.accessTokenFor(elsewhere.access_token, ELSEWHERE), undefined);
  const blocked = await w.refresh(clientId, own.refresh_token);
  assert.deepEqual([blocked.status, blocked.body.error], [401, "invalid_client"]);
  assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK)));

  // A blocked URL is never fetched: the policy answers before the resolver is asked.
  const fresh = await world();
  const fetched = [];
  fresh.sites["client.example"] = new Proxy(
    {},
    {
      get: (_target, path) => {
        fetched.push(path);
        return undefined;
      },
    },
  );
  policyOf(fresh).blocked.add(VERIFIED);
  assert.ok(refusedPage(await fresh.authorize(VERIFIED, VERIFIED_REDIRECT)));
  assert.equal((await fresh.refresh(VERIFIED, "rt_x")).status, 401);
  assert.deepEqual(fetched, []);
});

test("a verified client is read again at each token request", async () => {
  // A document that became a personal agent's, or went away, gets nothing more.
  const w = await world();
  const tokens = await w.signIn(VERIFIED, VERIFIED_REDIRECT);
  assert.equal((await w.refresh(VERIFIED, tokens.refresh_token)).status, 200);
  const changed = await world({ site: document({ jwks_uri: "https://client.example/jwks.json" }) });
  const refused = await changed.refresh(VERIFIED, "rt_anything");
  assert.deepEqual([refused.status, refused.body.error], [401, "invalid_client"]);
  const gone = await world();
  delete gone.sites["client.example"];
  assert.equal((await gone.refresh(VERIFIED, "rt_anything")).status, 401);
});

test("a company without a public resolver verifies none by domain", async () => {
  const plain = { resolve: async () => Promise.reject(new Error("none here")) };
  const w = await world({
    plugins: [
      {
        name: "plain",
        version: "1",
        contributes: [{ point: ClientResolvers, value: plain, options: { id: "plain", order: -10 } }],
      },
    ],
  });
  assert.ok(refusedPage(await w.authorize(VERIFIED, VERIFIED_REDIRECT)));
  const clientId = await w.registered();
  assert.equal((await w.authorize(clientId, LOOPBACK)).status, 200);
});

test("sign-in turned off for personal agents leaves public clients", async () => {
  const w = await world({ signInDisabled: true, mediatedFields: [], ucp: false });
  const clientId = await w.registered();
  const tokens = await w.signIn(clientId);
  assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 200);
  // A personal agent is still refused there.
  const answered = await w.authorize(w.identity.clientId, "https://atlas.example/oauth/callback", { resource: null });
  assert.equal(answered.status, 303);
  assert.equal(new URL(answered.headers.Location).searchParams.get("error"), "unauthorized_client");
});

// The owner's list -----------------------------------------------------------------------------

test("the owner lists and revokes public clients' sign-ins", async () => {
  const w = await world();
  const agent = await personalAgent(w, { signIn: true }); // A personal agent's sign-in is none of them.
  const clientId = await w.registered();
  const start = w.clock.now().toISOString();
  const registeredTokens = await w.signIn(clientId, "http://127.0.0.1:5000/callback");
  const verifiedTokens = await w.signIn(VERIFIED, VERIFIED_REDIRECT, {
    resource: ELSEWHERE,
    scope: "orders:read orders:write",
  });
  const byClient = async () => Object.fromEntries((await w.shop.publicClientSignIns()).map((e) => [e.clientId, e]));
  const listed = await byClient();
  assert.deepEqual(Object.keys(listed).sort(), [clientId, VERIFIED].sort());
  const unverified = listed[clientId];
  assert.deepEqual([unverified.clientName, unverified.verified], ["Pocket MCP", false]);
  assert.equal(unverified.redirectHost, "127.0.0.1:5000");
  assert.deepEqual([unverified.resource, unverified.accountId], [MCP, "acct_ada"]);
  assert.deepEqual(unverified.scopes, ["orders:read"]);
  assert.deepEqual([unverified.signedInAt, unverified.lastUsedAt], [start, start]);
  assert.equal(new Date(unverified.expiresAt) - new Date(start), 30 * DAY * 1000);
  const verified = listed[VERIFIED];
  assert.deepEqual([verified.clientName, verified.verified], ["Deskmate", true]);
  assert.deepEqual([verified.redirectHost, verified.resource], ["client.example", ELSEWHERE]);
  assert.deepEqual(verified.scopes, ["orders:read", "orders:write"]);

  // A refresh is its last use.
  w.clock.advance(1800);
  const rotated = (await w.refresh(clientId, registeredTokens.refresh_token)).body;
  const again = await byClient();
  assert.equal(new Date(again[clientId].lastUsedAt) - new Date(start), 1800 * 1000);
  assert.equal(again[clientId].signInId, unverified.signInId);
  assert.equal(again[VERIFIED].lastUsedAt, start);

  assert.equal(await w.shop.revokePublicClientSignIn(unverified.signInId), true);
  assert.equal(await w.shop.revokePublicClientSignIn(unverified.signInId), false);
  assert.equal(await w.shop.revokePublicClientSignIn("nothing"), false);
  assert.equal((await w.mcp(rotated.access_token, LIST_TOOLS)).status, 401);
  assert.equal((await w.refresh(clientId, rotated.refresh_token)).body.error, "invalid_grant");
  // The other one, and the personal agent's, go on.
  assert.deepEqual((await w.shop.publicClientSignIns()).map((entry) => entry.clientId), [VERIFIED]);
  assert.ok(await w.shop.accessTokenFor(verifiedTokens.access_token, ELSEWHERE));
  assert.ok((await agent.refreshed()).token);
  // A personal agent's sign-in is never ended from this list.
  const families = (await w.shop.store.records("account_family")).map((record) => record.value);
  const personal = families.find((family) => family.public === undefined);
  assert.equal(await w.shop.revokePublicClientSignIn(personal.tokens[0]), false);
  assert.ok((await agent.refreshed()).token);
  // A personal agent's records name no public client.
  assert.ok(!("public" in personal) && !("lastUsedAt" in personal));
});

test("a policy may answer for public clients apart", async () => {
  // A company that lists the personal agents it serves takes public clients all the same, or
  // none: `allowsPublic`, where `allows` answers for personal agents.
  const w = await world();
  const policy = firstContribution(w.shop.reactor, ClientPolicies, "policy");
  let takesPublic = true;
  policy.allows = async (clientId) => clientId === w.identity.clientId;
  policy.allowsPublic = async () => takesPublic;
  const clientId = await w.registered();
  const tokens = await w.signIn(clientId);
  const verified = await w.signIn(VERIFIED, VERIFIED_REDIRECT, { resource: ELSEWHERE });
  assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 200);
  assert.ok(await w.shop.accessTokenFor(verified.access_token, ELSEWHERE));
  // The listed personal agent is one still.
  const shown = await w.authorize(w.identity.clientId, "https://atlas.example/oauth/callback", { resource: null });
  assert.equal((await w.shop.authorizationRequest(requestIdOf(shown))).client_class, "personal_agent");
  // Public clients turned away: their tokens stop at once, the personal agent goes on.
  takesPublic = false;
  assert.equal((await w.mcp(tokens.access_token, LIST_TOOLS)).status, 401);
  assert.equal(await w.shop.accessTokenFor(verified.access_token, ELSEWHERE), undefined);
  assert.equal((await w.refresh(clientId, tokens.refresh_token)).status, 401);
  assert.ok(refusedPage(await w.authorize(clientId, LOOPBACK)));
  assert.ok(refusedPage(await w.authorize(VERIFIED, VERIFIED_REDIRECT)));
  const again = await w.authorize(w.identity.clientId, "https://atlas.example/oauth/callback", { resource: null });
  assert.equal(again.status, 200);
});

test("the return host is shown with its port", () => {
  assert.equal(redirectHost("https://client.example/callback"), "client.example");
  assert.equal(redirectHost("https://client.example:8443/callback?x=1"), "client.example:8443");
  assert.equal(redirectHost("http://127.0.0.1:49152/callback"), "127.0.0.1:49152");
  assert.equal(redirectHost("http://[::1]:49152/callback"), "[::1]:49152");
  assert.equal(redirectHost("http://localhost/callback"), "localhost");
});

test("a name holds nothing that hides or reorders text", () => {
  assert.equal(publicClientName("  Pocket MCP "), "Pocket MCP");
  for (const refused of ["", "   ", "x".repeat(101), "a‮b", "a⁦b", "a​b", "a\nb", "a\x7fb", null, 3]) {
    assert.throws(() => publicClientName(refused), RangeError, String(refused));
  }
});
