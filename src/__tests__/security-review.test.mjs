/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Regression tests for the findings of the 0.10.0 security review (docs: security/review):
// each is a reviewer's probe turned into an assertion, failing before its fix.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { connect } from "node:net";
import test from "node:test";

import { SignJWT, generateKeyPair } from "jose";

import {
  ConversationClient,
  DeviceSignInClient,
  MEDIATED_GRANT,
  McpClient,
  MediatedSignInClient,
  RateLimitBudgets,
  RefreshTokenClient,
  SESSION_HEADER,
  SESSION_JWT_ALGORITHM,
  SESSION_JWT_TYPE,
  SecretValue,
  SessionClient,
  SessionError,
  SessionFetchClient,
  SessionSigners,
  discoverCompany,
  firstContribution,
  sessionHeaders,
  sessionJwtClaims,
  parseProtectedResourceMetadata,
} from "../../lib/index.js";
import {
  ClientPolicies,
  ClientResolvers,
  CompanyConfig,
  MemoryCompanyStore,
  NodeUrlSafetyPolicy,
  StoreReplayCache,
  WEB_COOKIE,
  checkReplayCache,
  companyRequestListener,
  isGlobalAddress,
} from "../../lib/server.js";
import { ADA, ADA_CODE, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const TOKEN = "https://manzanita.example/oauth/token";
const MCP = "https://manzanita.example/mcp";
const ORDERS = "https://manzanita.example/api/orders";
const BROWSER_SESSION = "https://manzanita.example/poppy/browser-session";
const LIST_TOOLS = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" });

async function world({ plugins, config, durable = false } = {}) {
  const clock = new MutableClock();
  const store = durable ? new MemoryCompanyStore({ clock }) : undefined;
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const built = { fetch, clock, ...(plugins ? { plugins } : {}), ...(config ? { config } : {}), ...(store ? { store } : {}) };
  const { service: shop, plugin } = manzanita(built);
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const transport = new SessionFetchClient({ reactor: host.reactor, fetch });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const start = () => sessions.start({ clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tenantId: TENANT });
  const message = (text) => ({ id: conversations.generateMessageId(), author: { type: "human" }, text });
  const endpoint = company.document.agent.protocols[0].endpoint;
  const postJson = (session, url, body, token) =>
    transport.request("POST", url, { session, token, headers: { "content-type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) });
  const context = {
    tokenEndpoint: metadata.token_endpoint,
    revocationEndpoint: metadata.revocation_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    tenantId: TENANT,
  };
  const accounts = new RefreshTokenClient({ reactor: host.reactor, fetch });
  /** The grant sent straight to the token endpoint: this test counts the company's refusals. */
  const mediatedGrant = async (form) =>
    fetch(TOKEN, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: MEDIATED_GRANT,
        ...form,
        ...(await sessions.clientAuthentication({ clientId: identity.clientId, issuer: metadata.issuer })),
      }).toString(),
    });
  /** A replica of the same deployment takes over, over the same store. */
  const restart = () => {
    sites["manzanita.example"] = manzanita(built).service;
  };
  return { clock, fetch, identity, shop, plugin, host, transport, conversations, company, metadata, sessions, start, message, endpoint, postJson, context, accounts, mediatedGrant, restart };
}

/** Device Sign-In, Ada approving. */
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
  return device.poll(started.reference);
}

/** Sign in, and take a token for the MCP server: a refresh with its `url` (§4.5, §7). */
async function forMcp(w) {
  const done = await deviceSignIn(w);
  const result = await w.accounts.tokenForMcp(done.refreshTokenReference, { context: w.context, server: parseProtectedResourceMetadata({ resource: MCP }) });
  assert.equal(result.token.resource, MCP);
  return result.token;
}

/** A sign-in's token is the default one, for no resource; the MCP server's own is kept. */
async function assertTheDefaultToken(w, session, token, mcpToken) {
  assert.equal(token.resource, undefined);
  const refused = await w.fetch(MCP, {
    method: "POST",
    headers: { ...(await sessionHeaders(w.host.reactor, "POST", MCP, { session, token })), "content-type": "application/json" },
    body: LIST_TOOLS,
  });
  assert.equal(refused.status, 401);
  const kept = new McpClient({ url: MCP, session, reactor: w.host.reactor, token: mcpToken, fetch: w.fetch });
  assert.ok((await kept.listTools()).length > 0);
}

/** A Session JWT from the agent's delegated key, with some of it changed. */
async function sessionJwt(w, session, method, url, { token, claims = {}, without = [], headers = {}, key } = {}) {
  const signer = firstContribution(w.host.reactor, SessionSigners, "signer");
  const request = {
    method,
    url,
    tenantId: session.tenantId,
    issuer: session.issuer,
    clientId: session.clientId,
    sid: session.sid,
    sub: session.sub,
    ...(token === undefined ? {} : { accessToken: token.accessToken }),
  };
  const now = w.clock.now();
  const delegated = await signer.keyFor(request, now);
  const payload = { ...(await sessionJwtClaims(request, { issuedAt: now })), ...claims };
  for (const name of without) delete payload[name];
  const protectedHeader = {
    alg: SESSION_JWT_ALGORITHM,
    typ: SESSION_JWT_TYPE,
    kid: delegated.thumbprint,
    pap_dlg: delegated.delegation.reveal(),
    ...headers,
  };
  for (const [name, value] of Object.entries(protectedHeader)) if (value === undefined) delete protectedHeader[name];
  return new SignJWT(payload).setProtectedHeader(protectedHeader).sign(key ?? delegated.privateKey);
}

test("finding 1: a device sign-in after an MCP token issues the default token", async () => {
  const w = await world();
  const mcpToken = await forMcp(w);
  const session = await w.start();
  const done = await deviceSignIn(w);
  assert.equal(done.status, "complete");
  assert.equal(done.token.tokenType, "Bearer");
  await assertTheDefaultToken(w, session, done.token, mcpToken);
});

test("finding 1: a mediated sign-in after an MCP token issues the default token", async () => {
  const w = await world();
  const mcpToken = await forMcp(w);
  const session = await w.start();
  const started = await (await w.mediatedGrant({ ...ADA, scope: "orders:read" })).json();
  const answer = await w.mediatedGrant({ sign_in_id: started.sign_in_id, one_time_code: ADA_CODE });
  assert.equal(answer.status, 200);
  const body = await answer.json();
  assert.equal(body.token_type, "Bearer");
  await assertTheDefaultToken(w, session, { accessToken: new SecretValue(body.access_token) }, mcpToken);
});

test("finding 3: a retried start answers only who may read the conversation", async () => {
  const w = await world();
  const signed = await w.start();
  const { token } = await deviceSignIn(w);
  const message = w.message("Where is my jacket order?");
  await w.conversations.start(w.endpoint, message, { session: signed, token, wait: 0 });
  const signedOut = await w.start();
  const retried = await w.postJson(signedOut, `${w.endpoint}?wait=0`, { message });
  // Signed out: the challenge with `scope`, no error code and no body (§7).
  assert.equal(retried.status, 401);
  assert.equal(await retried.text(), "");
  assert.equal(retried.headers.get("www-authenticate"), 'Bearer scope="orders:read"');
});

test("finding 5: operations without a write scope is a configuration error", () => {
  assert.throws(
    () => new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["orders:read"], scopeDescriptions: { "orders:read": "See orders" } }),
    /writeScopes/,
  );
  assert.throws(
    () => new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["a:read"], writeScopes: ["a:write"], scopeDescriptions: { "a:read": "Read" } }),
    /among scopes/,
  );
  new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["orders:read"], scopeDescriptions: { "orders:read": "See orders" }, operations: false });
});

test("finding 5: an operation records and requires its scopes", async () => {
  const w = await world();
  const session = await w.start();
  const done = await deviceSignIn(w);
  const page = await w.conversations.start(w.endpoint, w.message("Exchange my jacket for a warmer one"), { session, token: done.token, wait: 0 });
  const proposal = page.events.find((event) => event.message?.operation).message.operation;
  assert.deepEqual([...(await w.shop.operationRecord(proposal.operation_id)).scopes], ["orders:write"]);
  const narrowed = await w.accounts.refresh(done.refreshTokenReference, { context: w.context, scopes: ["orders:read"] });
  const answer = await w.postJson(
    session,
    `${w.endpoint}/${page.conversation_id}/messages`,
    {
      message: {
        id: w.message("x").id,
        author: { type: "agent" },
        approval: { operation_id: proposal.operation_id, revision: proposal.revision },
      },
    },
    narrowed.token,
  );
  assert.equal(answer.status, 403);
  assert.ok(answer.headers.get("www-authenticate").includes('error="insufficient_scope"'));
  assert.deepEqual([...w.plugin.executor.performed], []);
});

for (const scope of ["orders:read bogus:scope", undefined, "", "admin:all", "7"]) {
  test(`finding 8: mediated sign-in refuses the scope ${JSON.stringify(scope)}`, async () => {
    const w = await world();
    const response = await w.mediatedGrant({ ...ADA, ...(scope === undefined ? {} : { scope }) });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "invalid_scope" });
  });
}

for (const body of ["[]", '"text"', "{", '{"message": {"id": 3}}', '{"message": []}']) {
  test(`finding 10: the conversation body ${body} is a 400`, async () => {
    const w = await world();
    const session = await w.start();
    const response = await w.postJson(session, w.endpoint, body);
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "invalid_request" });
  });
}

/** One raw HTTP/1.1 request to the company's Node listener: the answer as text. */
async function rawRequest(w, request) {
  const server = createServer(companyRequestListener(w.shop));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await new Promise((resolve, reject) => {
      const socket = connect(server.address().port, "127.0.0.1");
      let answer = "";
      socket.on("data", (chunk) => (answer += chunk));
      socket.on("end", () => resolve(answer));
      socket.on("error", reject);
      socket.end(request);
    });
  } finally {
    server.close();
  }
}

test("finding 10: a repeated Session header is invalid_session", async () => {
  // Exactly one Session header, holding one JWT (§5.2, §5.3).
  const w = await world();
  const session = await w.start();
  const url = "https://manzanita.example/poppy/conversations";
  const raw = await rawRequest(
    w,
    "POST /poppy/conversations HTTP/1.1\r\nHost: manzanita.example\r\n" +
      `poppy-session: ${await sessionJwt(w, session, "POST", url)}\r\n` +
      `poppy-session: ${await sessionJwt(w, session, "POST", url)}\r\n` +
      "Content-Length: 2\r\nConnection: close\r\n\r\n{}",
  );
  assert.match(raw, /^HTTP\/1\.1 400 /);
  assert.match(raw, /\{"error":"invalid_session"\}/);
});

test("finding 10: a repeated authorization header is refused by the Node adapter", async () => {
  const w = await world();
  const raw = await rawRequest(
    w,
    "POST /poppy/conversations HTTP/1.1\r\nHost: manzanita.example\r\n" +
      "authorization: Bearer one\r\nauthorization: Bearer two\r\n" +
      "Content-Length: 2\r\nConnection: close\r\n\r\n{}",
  );
  assert.match(raw, /^HTTP\/1\.1 400 /);
  assert.match(raw, /"error":"invalid_request"/);
});

function unsigned(claims) {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${part({ alg: "ES256", typ: "JWT" })}.${part(claims)}.${part("sig")}`;
}

test("finding 11: a blocked agent is never resolved, and its tokens stop at once", async () => {
  const blocked = new Set();
  const w = await world({
    plugins: [
      {
        name: "blocklist",
        contributes: [{ point: ClientPolicies, value: { allows: async (id) => !blocked.has(id) }, options: { id: "blocklist", order: 10 } }],
      },
    ],
  });
  const session = await w.start();
  // A join the agent authorized before it was blocked.
  const page = await w.fetch(BROWSER_SESSION, { method: "GET" });
  const cookie = page.headers.getSetCookie().find((line) => line.startsWith("__Host-poppy_join=")).split(";")[0];
  const code = /name="code" value="([^"]+)"/u.exec(await page.text())[1];
  assert.equal((await w.postJson(session, `${BROWSER_SESSION}/authorize`, { code })).status, 204);

  const resolver = firstContribution(w.shop.reactor, ClientResolvers, "client");
  const resolved = [];
  const resolve = resolver.resolve.bind(resolver);
  resolver.resolve = async (...args) => {
    resolved.push(args[0]);
    return resolve(...args);
  };
  blocked.add(w.identity.clientId);
  // A refused agent gets `invalid_session`, in the new Session it starts too (§4.1, §7).
  const started = await w.postJson(session, w.endpoint, { message: w.message("hi") });
  assert.equal(started.status, 400);
  assert.equal((await started.json()).error, "invalid_session");
  const forged = await w.fetch(ORDERS, { method: "GET", headers: { [SESSION_HEADER]: unsigned({ iss: w.identity.clientId }) } });
  assert.equal(forged.status, 400);
  assert.equal((await forged.json()).error, "invalid_session");
  const authorize = new URL("https://manzanita.example/oauth/authorize");
  for (const [name, value] of Object.entries({
    client_id: w.identity.clientId,
    redirect_uri: "https://atlas.example/oauth/callback",
    response_type: "code",
    scope: "orders:read",
    code_challenge: "x".repeat(43),
    code_challenge_method: "S256",
  })) authorize.searchParams.set(name, value);
  assert.equal((await w.fetch(authorize, { method: "GET" })).status, 400);
  const browser = await w.fetch(BROWSER_SESSION, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", cookie },
    body: new URLSearchParams({ code }).toString(),
  });
  assert.equal(browser.status, 400);
  assert.deepEqual(resolved, []);
});

test("finding 17: the web cookie is a __Host- cookie", () => {
  assert.equal(WEB_COOKIE, "__Host-poppy_session");
});

test("finding 2: wrong passwords lock the account out, with backoff", async () => {
  const w = await world();
  const seen = [];
  const authenticate = w.plugin.accounts.authenticate.bind(w.plugin.accounts);
  w.plugin.accounts.authenticate = async (credentials, context) => {
    seen.push(context);
    return authenticate(credentials, context);
  };
  const wrong = { email: ADA.email, password: "wrong", scope: "orders:read" };
  const answers = [];
  for (let i = 0; i < 8; i += 1) answers.push(await w.mediatedGrant(wrong));
  assert.deepEqual(answers.map((a) => a.status), [400, 400, 400, 400, 400, 429, 429, 429]);
  for (const answer of answers.slice(0, 5)) assert.equal((await answer.json()).error, "invalid_grant");
  assert.equal(await answers[5].text(), "");
  assert.equal(answers[5].headers.get("retry-after"), String(15 * 60));
  assert.equal(seen.length, 5);
  // Locked out: the directory is not asked, even with the right password.
  const right = await w.mediatedGrant({ ...ADA, scope: "orders:read" });
  assert.equal(right.status, 429);
  assert.equal(seen.length, 5);
  // The directory hears which agent each attempt came from.
  assert.equal(seen[0].clientId, w.identity.clientId);
  // Once the lockout ends, the next failure locks the account out twice as long.
  w.clock.advance(15 * 60);
  assert.equal((await w.mediatedGrant(wrong)).status, 400);
  const doubled = await w.mediatedGrant(wrong);
  assert.equal(doubled.status, 429);
  assert.equal(doubled.headers.get("retry-after"), String(30 * 60));
});

test("finding 2: wrong codes count per account across sign-ins", async () => {
  const w = await world();
  let last;
  for (let round = 0; round < 5 && last === undefined; round += 1) {
    const started = await w.mediatedGrant({ ...ADA, scope: "orders:read orders:write" });
    if (started.status === 429) {
      last = started;
      break;
    }
    const { sign_in_id: signInId } = await started.json();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const answer = await w.mediatedGrant({ sign_in_id: signInId, one_time_code: `00000${attempt}` });
      if ((await answer.json()).error === "invalid_grant") break;
    }
  }
  assert.ok(last !== undefined);
  assert.equal(last.status, 429);
  assert.equal(await last.text(), "");
  // Past the lockout, the right code signs in.
  w.clock.advance(15 * 60);
  const started = await (await w.mediatedGrant({ ...ADA, scope: "orders:read" })).json();
  const done = await w.mediatedGrant({ sign_in_id: started.sign_in_id, one_time_code: ADA_CODE });
  assert.equal(done.status, 200);
  assert.ok((await done.json()).access_token);
});

test("finding 4: a Session JWT replayed at another replica over the same store is refused", async () => {
  const w = await world({ durable: true });
  const session = await w.start();
  const page = await w.conversations.start(w.endpoint, w.message("hello"), { session, wait: 0 });
  const url = `${w.endpoint}/${page.conversation_id}/events`;
  const headers = await sessionHeaders(w.host.reactor, "GET", url, { session });
  assert.equal((await w.fetch(url, { method: "GET", headers })).status, 200);
  w.restart(); // another replica over the same store, with the default replay cache
  const replayed = await w.fetch(url, { method: "GET", headers });
  assert.equal(replayed.status, 400);
  assert.equal((await replayed.json()).error, "invalid_session");
});

test("finding 4: the memory store forgets expired records; the store replay cache conforms", async () => {
  const clock = new MutableClock();
  const store = new MemoryCompanyStore({ clock });
  const cache = new StoreReplayCache(() => store);
  for (let index = 0; index < 5000; index += 1) {
    assert.equal(await cache.markOnce(`jti-${index}`, { expiresAt: new Date(clock.now().getTime() + 60_000) }), true);
    if (index % 100 === 99) clock.advance(61);
  }
  assert.ok(store.size < 2100, `the store holds ${store.size} records`);
  await checkReplayCache(() => {
    const one = new MemoryCompanyStore();
    return new StoreReplayCache(() => one);
  });
});

test("finding 9: the demo agent reads no order without orders:read", async () => {
  const { ManzanitaAgent } = await import("../../lib/demo/manzanita.js");
  const turn = (text, scopes) => ({ conversationId: "cnv_1", text, author: "human", accountId: "acct_ada", scopes, clientId: "https://atlas.example/agent.json", isDirect: false, supportsOperations: true });
  assert.deepEqual(await new ManzanitaAgent().respond(turn("Where is my order?", ["orders:write"])), [{ authorization: ["insufficient_scope", "orders:read"] }]);
  assert.ok((await new ManzanitaAgent().respond(turn("Where is my order?", ["orders:read"])))[0].data);
});

for (const [address, global] of [
  ["64:ff9b::7f00:1", false],
  ["64:ff9b::a9fe:a9fe", false],
  ["::7f00:1", false],
  ["::a9fe:a9fe", false],
  ["::ffff:127.0.0.1", false],
  ["2002:7f00:1::", false],
  ["64:ff9b:1::808:808", false],
  ["fd00:ec2::254", false],
  ["100.100.100.200", false],
  ["::", false],
  ["64:ff9b::808:808", true],
  ["2606:4700::1111", true],
  ["8.8.8.8", true],
]) {
  test(`finding 13: ${address} is ${global ? "global" : "not global"}: an IPv4 address inside IPv6 is judged as IPv4`, () => {
    assert.equal(isGlobalAddress(address), global);
  });
}

test("finding 13: a host resolving to NAT64 loopback is refused", async () => {
  const policy = new NodeUrlSafetyPolicy({ resolver: async () => ["64:ff9b::a9fe:a9fe"] });
  await assert.rejects(policy.assertSafe(new URL("https://metadata.example/agent.json")), (error) => error.code === "unsafe_address");
});

const UNSAFE = [
  "https://localhost./x",
  "https://0.0.0.0/x",
  "https://0/x",
  "https://[::]/x",
  "https://[::ffff:127.0.0.1]/x",
  "https://[::ffff:169.254.169.254]/x",
  "https://[fd00:ec2::254]/x",
  "https://[fe80::1]/x",
  "https://100.100.100.200/x",
  "https://2130706433/x",
  "https://[0:0:0:0:0:0:0:1]/x",
  "https://metadata.google.internal/x",
  "https://169.254.169.254/x",
  "https://[64:ff9b::7f00:1]/x",
];

test("finding 12: the portable URL check refuses every non-global literal and local name", async () => {
  const { UrlSafetyPolicies, buildPapReactor: build } = await import("../../lib/index.js");
  const reactor = build({ fetch: async () => assert.fail("never fetched") });
  const policy = firstContribution(reactor, UrlSafetyPolicies, "policy");
  for (const url of UNSAFE) {
    await assert.rejects(Promise.resolve().then(() => policy.assertSafe(new URL(url))), (error) => error.code === "unsafe_address", url);
  }
  await policy.assertSafe(new URL("https://agent.example/agent.json"));
  await policy.assertSafe(new URL("https://[2606:4700::1111]/agent.json"));
});

test("finding 12: the resolving fetch refuses a name with any non-global address, before dialling", async () => {
  const { createResolvingFetch } = await import("../../lib/server.js");
  for (const answer of [["93.184.216.34", "10.0.0.1"], ["::ffff:127.0.0.1"], ["100.100.100.200"], ["fd00:ec2::254"]]) {
    const fetch = createResolvingFetch({ resolver: async () => answer });
    await assert.rejects(fetch("https://agent.example/agent.json"), (error) => error.code === "unsafe_address", String(answer));
  }
});

test("finding 12: the resolving fetch dials only the vetted address, with the URL's name for TLS", async () => {
  const { createServer: createTlsServer } = await import("node:https");
  const { certificates } = await import("./support/world.mjs");
  const { createResolvingFetch } = await import("../../lib/server.js");
  const tls = certificates(["agent.example"]);
  const seen = [];
  const server = createTlsServer({ key: tls.key, cert: tls.cert }, (request, response) => {
    seen.push({ host: request.headers.host, servername: request.socket.servername });
    response.writeHead(200, { "content-type": "application/json" }).end('{"ok":true}');
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    let resolutions = 0;
    // The first answer is vetted; a rebinding second answer would never be asked for.
    const fetch = createResolvingFetch({
      ca: tls.ca,
      allowPrivateNetworks: true,
      resolver: async () => (resolutions++ === 0 ? ["127.0.0.1"] : ["10.9.9.9"]),
    });
    const response = await fetch(`https://agent.example:${server.address().port}/agent.json`, { redirect: "manual" });
    assert.deepEqual(await response.json(), { ok: true });
    assert.equal(resolutions, 1);
    assert.deepEqual(seen, [{ host: `agent.example:${server.address().port}`, servername: "agent.example" }]);
  } finally {
    server.close();
  }
});

test("finding 12: the Node company fetches over the resolving transport by default", async () => {
  const { hostname } = await import("node:os");
  const { DiscoveryTransports } = await import("../../lib/index.js");
  const { buildCompany } = await import("../../lib/server.js");
  const service = buildCompany(new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["a:read"], scopeDescriptions: { "a:read": "Read" }, operations: false }));
  const transport = firstContribution(service.reactor, DiscoveryTransports, "transport");
  // This machine's own name resolves (through /etc/hosts) to a loopback or private address.
  await assert.rejects(transport.fetch(new URL(`https://${hostname()}/agent.json`), {}), (error) => ["unsafe_address", "dns_failed"].includes(error.code));
  await assert.rejects(transport.fetch(new URL("https://127.0.0.1/agent.json"), {}), (error) => error.code === "unsafe_address");
});

test("finding 14: a metadata deadline aborts the request itself, and a redirect's body is cancelled", async () => {
  const { discoverCompany: discover } = await import("../../lib/index.js");
  const signals = [];
  const hanging = (_input, init) =>
    new Promise((_, reject) => {
      signals.push(init.signal);
      init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
    });
  await assert.rejects(discover("slow.example", { fetch: hanging, timeoutMs: 30 }), (error) => error.code === "metadata_timeout");
  assert.equal(signals.length, 1);
  assert.equal(signals[0].aborted, true);

  // The caller's own signal aborts the request too.
  const caller = new AbortController();
  const pending = discover("slow.example", { fetch: hanging, timeoutMs: 60_000, signal: caller.signal });
  await new Promise((resolve) => setTimeout(resolve, 5));
  caller.abort(new Error("stop"));
  await assert.rejects(pending);
  assert.equal(signals[1].aborted, true);

  let cancelled = 0;
  const redirecting = async (input) => {
    if (new URL(String(input)).pathname === "/.well-known/poppy.json" && cancelled === 0) {
      const body = new ReadableStream({ cancel: () => void (cancelled += 1) });
      return new Response(body, { status: 302, headers: { location: "https://slow.example/moved.json" } });
    }
    return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
  };
  await assert.rejects(discover("slow.example", { fetch: redirecting }));
  assert.equal(cancelled, 1);
});

/** A JSON response whose body never ends, counting the chunks pulled from it. */
function endless() {
  const counter = { pulled: 0, cancelled: false };
  const body = new ReadableStream({
    pull(controller) {
      counter.pulled += 1;
      controller.enqueue(new Uint8Array(65536).fill(32));
    },
    cancel() {
      counter.cancelled = true;
    },
  });
  return { counter, response: () => new Response(body, { status: 200, headers: { "content-type": "application/json" } }) };
}

test("finding 15: a token response is read only up to its limit", async () => {
  const w = await world();
  const { counter, response } = endless();
  const sessions = new SessionClient({ reactor: w.host.reactor, fetch: async () => response(), maxResponseBytes: 100 * 1024 });
  await assert.rejects(
    sessions.tokenRequest({
      clientId: w.identity.clientId,
      issuer: w.metadata.issuer,
      tokenEndpoint: w.metadata.token_endpoint,
      form: () => ({ grant_type: "refresh_token", refresh_token: "x" }),
      error: SessionError,
      tenantId: "t",
      dpopSigningAlgs: undefined,
    }),
    (error) => error.code === "response_too_large",
  );
  assert.ok(counter.pulled <= 4, `pulled ${counter.pulled}`);
  assert.equal(counter.cancelled, true);
});

test("finding 15: an MCP response is read only up to its limit", async () => {
  const w = await world();
  const token = await forMcp(w);
  const session = await w.start();
  const { counter, response } = endless();
  const mcp = new McpClient({ url: MCP, session, reactor: w.host.reactor, token, fetch: async () => response(), maxResponseBytes: 100 * 1024 });
  await assert.rejects(mcp.listTools(), (error) => error.code === "response_too_large");
  assert.ok(counter.pulled <= 4, `pulled ${counter.pulled}`);
});

for (const status of [301, 302, 307, 308]) {
  test(`finding 7: a body is never sent to a ${status} redirect`, async () => {
    const w = await world();
    const session = await w.start();
    const seen = [];
    const transport = new SessionFetchClient({
      reactor: w.host.reactor,
      fetch: async (input) => {
        seen.push(new URL(String(input)).pathname);
        return new Response(null, { status, headers: { location: "/collect-credentials" } });
      },
    });
    await assert.rejects(
      transport.request("POST", ORDERS, { session, body: '{"note":"x"}' }),
      (error) => error.code === "redirect_refused",
    );
    assert.deepEqual(seen, ["/api/orders"]);
  });
}

test("finding 7: the mediated client sends credentials once, to the token endpoint, and follows no redirect", async () => {
  const w = await world();
  w.host.input.answers.push({ ...ADA });
  const seen = [];
  const client = new MediatedSignInClient({
    reactor: w.host.reactor,
    fetch: async (input) => {
      seen.push(String(input));
      return new Response(null, { status: 307, headers: { location: "/collect-credentials" } });
    },
  });
  await assert.rejects(client.signIn({ company: w.company, clientId: w.identity.clientId, scopes: ["orders:read"], tenantId: "t" }), (error) => error.code === "redirect_refused");
  assert.deepEqual(seen, [TOKEN]);
});

test("finding 11 and O7: an unfetchable client_id is fetched once, and the refetch table is bounded", async () => {
  const { AgentIdentityClient } = await import("../../lib/index.js");
  const fetched = [];
  const client = new AgentIdentityClient({
    fetch: async (input) => {
      fetched.push(String(input));
      return new Response('{"error":"not_found"}', { status: 404, headers: { "content-type": "application/json" } });
    },
  });
  for (let i = 0; i < 5; i += 1) await assert.rejects(client.fetchMetadata("https://gone.example/agent.json"));
  assert.equal(fetched.length, 1);
  // Thousands of distinct unfetchable IDs: each is remembered, the table stays bounded (no throw, no growth).
  for (let i = 0; i < 3000; i += 1) await assert.rejects(client.fetchMetadata(`https://gone-${i}.example/agent.json`));
  assert.equal(fetched.length, 3001);
});

// The external interoperability exercise --------------------------------------------------

async function signedInWithProposal(w) {
  const session = await w.start();
  const done = await deviceSignIn(w);
  const page = await w.conversations.start(w.endpoint, w.message("Exchange my jacket for a warmer one"), { session, token: done.token, wait: 0 });
  return { token: done.token, page, proposal: page.events.find((event) => event.message?.operation).message.operation };
}

test("O1: an operation has no null members", async () => {
  const w = await world();
  const { proposal } = await signedInWithProposal(w);
  assert.deepEqual(Object.keys(proposal).sort(), ["expires_at", "operation_id", "revision", "summary", "terms"]);
  assert.deepEqual(Object.entries(proposal).filter(([, value]) => value === null), []);
});

async function assertion(w, audience, { lifetime = 60, jti } = {}) {
  const now = Math.floor(w.clock.now().getTime() / 1000);
  const signed = await w.identity.signer.sign(
    { iss: w.identity.clientId, sub: w.identity.clientId, aud: audience, iat: now, exp: now + lifetime, jti: jti ?? `jti_${crypto.randomUUID()}` },
    { purpose: "client_assertion" },
  );
  return signed.reveal();
}

async function deviceWith(w, clientAssertion) {
  return w.fetch("https://manzanita.example/oauth/device", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: w.identity.clientId,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: clientAssertion,
      scope: "orders:read",
    }).toString(),
  });
}

for (const [audience, status] of [
  // The issuer, compared character for character, and nothing else (§4.1, §9.4).
  ["https://manzanita.example/oauth/device", 401],
  ["https://manzanita.example/oauth/token", 401],
  ["https://manzanita.example/", 401],
  ["https://Manzanita.example", 401],
  ["https://manzanita.example", 200],
  ["https://other.example/oauth/token", 401],
]) {
  test(`O2: a client assertion for ${audience} at /oauth/device is ${status}`, async () => {
    const w = await world();
    assert.equal((await deviceWith(w, await assertion(w, audience))).status, status);
  });
}

for (const [lifetime, jti, status] of [[600, undefined, 401], [301, undefined, 401], [300, undefined, 200], [60, "short-jti", 401]]) {
  test(`O7: an assertion living ${lifetime}s with jti ${jti ?? "long"} is ${status}`, async () => {
    const w = await world();
    assert.equal((await deviceWith(w, await assertion(w, "https://manzanita.example", { lifetime, jti }))).status, status);
  });
}

test("O7: a Session JWT with a short jti is refused", async () => {
  const w = await world();
  const session = await w.start();
  const answer = await w.fetch(ORDERS, { method: "GET", headers: { [SESSION_HEADER]: await sessionJwt(w, session, "GET", ORDERS, { claims: { jti: "short" } }) } });
  assert.equal(answer.status, 400);
  assert.equal((await answer.json()).error, "invalid_session");
});

test("a copied access token is worth nothing without the agent's Session JWT", async () => {
  // `ath` ties a Session JWT to its token, and the delegation ties its key to the agent's
  // `jwks_uri` (§5.2, §5.3). Each forgery is `invalid_session`.
  const w = await world();
  const session = await w.start();
  const { token } = await deviceSignIn(w);
  const bearer = { authorization: `Bearer ${token.accessToken.reveal()}` };
  const other = { accessToken: new SecretValue("another-access-token") };
  const someone = (await generateKeyPair("ES256")).privateKey;
  const now = Math.floor(w.clock.now().getTime() / 1000);
  const forged = {
    "no ath": await sessionJwt(w, session, "GET", ORDERS),
    "another token's ath": await sessionJwt(w, session, "GET", ORDERS, { token: other }),
    "another method": await sessionJwt(w, session, "POST", ORDERS, { token }),
    "another url": await sessionJwt(w, session, "GET", `${ORDERS}/x`, { token }),
    "another company": await sessionJwt(w, session, "GET", ORDERS, { token, claims: { aud: "https://other.example" } }),
    "an old iat": await sessionJwt(w, session, "GET", ORDERS, { token, claims: { iat: now - 61 } }),
    "no jti": await sessionJwt(w, session, "GET", ORDERS, { token, without: ["jti"] }),
    "another key": await sessionJwt(w, session, "GET", ORDERS, { token, key: someone }),
    "no delegation": await sessionJwt(w, session, "GET", ORDERS, { token, headers: { pap_dlg: undefined } }),
    "signed by the agent's own key": await sessionJwt(w, session, "GET", ORDERS, { token, headers: { pap_dlg: undefined }, key: w.identity.privateKey }),
  };
  for (const [what, value] of Object.entries(forged)) {
    const answer = await w.fetch(ORDERS, { method: "GET", headers: { ...bearer, [SESSION_HEADER]: value } });
    assert.equal(answer.status, 400, what);
    assert.equal((await answer.json()).error, "invalid_session", what);
  }
  const copied = await w.fetch(ORDERS, { method: "GET", headers: bearer });
  assert.equal(copied.status, 400);
  assert.equal((await copied.json()).error, "invalid_session");
  // The genuine one, and that same one only once.
  const headers = { ...bearer, [SESSION_HEADER]: await sessionJwt(w, session, "GET", ORDERS, { token }) };
  assert.equal((await w.fetch(ORDERS, { method: "GET", headers })).status, 200);
  const replayed = await w.fetch(ORDERS, { method: "GET", headers });
  assert.equal(replayed.status, 400);
  assert.equal((await replayed.json()).error, "invalid_session");
});

test("O3: a token-endpoint refusal is an OAuth error", async () => {
  // At the token endpoint, an OAuth error with HTTP 400; at APIs a 401 challenge (§4.4, §7).
  const w = await world();
  const session = await w.start();
  const response = await w.fetch(TOKEN, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: w.identity.clientId,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: await assertion(w, "https://manzanita.example"),
      refresh_token: "x",
    }).toString(),
  });
  assert.equal(response.status, 400);
  assert.deepEqual(await response.json(), { error: "invalid_grant" });
  assert.equal(response.headers.get("www-authenticate"), null);
  const token = { accessToken: new SecretValue("unknown") };
  const api = await w.fetch(ORDERS, { method: "GET", headers: await sessionHeaders(w.host.reactor, "GET", ORDERS, { session, token }) });
  assert.equal(api.status, 401);
  assert.equal((await api.json()).error, "invalid_token");
  assert.ok(api.headers.get("www-authenticate").startsWith('Bearer error="invalid_token"'));
});

test("O4: a token in the query is refused even beside a valid header", async () => {
  const w = await world();
  const token = await forMcp(w);
  const session = await w.start();
  for (const query of [`access_token=${token.accessToken.reveal()}`, "access_token="]) {
    const url = `${MCP}?${query}`;
    const response = await w.fetch(url, {
      method: "POST",
      headers: { ...(await sessionHeaders(w.host.reactor, "POST", url, { session, token })), "content-type": "application/json" },
      body: LIST_TOOLS,
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "invalid_request");
  }
});

test("O8: a reply is framed by working and idle state events", async () => {
  const w = await world();
  const page = await w.conversations.start(w.endpoint, w.message("Hello"), { session: await w.start(), wait: 0 });
  assert.deepEqual(page.events.map((event) => `${event.type}${event.status ? `:${event.status}` : ""}`), ["message", "state:working", "message", "state:idle"]);
  assert.equal(page.status, "idle");
});

test("O9: the demo promises no operation to an agent without Operations", async () => {
  const { ManzanitaAgent } = await import("../../lib/demo/manzanita.js");
  const replies = await new ManzanitaAgent().respond({
    conversationId: "cnv_1", text: "Exchange it for something warmer", author: "human", accountId: "acct_ada",
    scopes: ["orders:read", "orders:write"], clientId: "https://atlas.example/agent.json", isDirect: false, supportsOperations: false,
  });
  assert.equal(replies.length, 1);
  assert.equal(replies[0].operation, undefined);
  assert.equal(replies[0].text.includes("Here is the exchange"), false);
});
