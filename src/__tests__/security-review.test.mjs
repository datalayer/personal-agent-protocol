// Regression tests for the findings of the 0.10.0 security review (docs: security/review):
// each is a reviewer's probe turned into an assertion, failing before its fix.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { connect } from "node:net";
import test from "node:test";

import {
  AccountTokenClient,
  ConversationClient,
  DeviceSignInClient,
  DpopFetchClient,
  OperationsClient,
  RateLimitBudgets,
  SessionClient,
  approve,
  discoverCompany,
  firstContribution,
} from "../../lib/index.js";
import {
  ClientPolicies,
  ClientResolvers,
  CompanyConfig,
  MemoryCompanyStore,
  StoreReplayCache,
  WEB_COOKIE,
  checkReplayCache,
  companyRequestListener,
} from "../../lib/server.js";
import { ADA, ADA_CODE, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const MEDIATED = "https://manzanita.example/poppy/sign-in";

async function world({ plugins } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock, ...(plugins ? { plugins } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: metadata.issuer };
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const start = () =>
    sessions.start({ clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tokenEndpoint: metadata.token_endpoint, tenantId: TENANT });
  const message = (text) => ({ id: conversations.generateMessageId(), sender: "human", text });
  const endpoint = company.document.agent.protocols[0].endpoint;
  const postJson = (token, url, body) =>
    transport.request("POST", url, { token, ...who, headers: { "content-type": "application/json" }, body: typeof body === "string" ? body : JSON.stringify(body) });
  return { clock, fetch, identity, shop, plugin, host, transport, conversations, company, metadata, who, sessions, start, message, endpoint, postJson };
}

async function deviceSignIn(w, session, { bearerFirst = false } = {}) {
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
  if (bearerFirst) await bearer(w, session);
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  return device.poll(started.reference);
}

async function bearer(w, session) {
  const token = await w.sessions.bearerForMcp({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: w.metadata.issuer,
    tokenEndpoint: w.metadata.token_endpoint,
    tenantId: TENANT,
    sessionId: session.sessionId,
    resource: "https://manzanita.example/mcp",
  });
  assert.equal(token.tokenType, "Bearer");
  return token;
}

async function assertSignedInDpop(w, sessionId, accessToken) {
  const stored = (await w.shop.store.get("session", sessionId)).value;
  const kinds = Object.values(stored.tokens)
    .map((t) => `${t.tokenType ?? "DPoP"}:${t.accountId !== undefined}:${t.resource ?? "-"}`)
    .sort();
  // The signed-in token is DPoP and for no resource; the MCP Bearer token is kept, signed out.
  assert.deepEqual(kinds, ["Bearer:false:https://manzanita.example/mcp", "DPoP:true:-"]);
  const used = await w.fetch("https://manzanita.example/mcp", {
    method: "POST",
    headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(used.status, 401);
}

/** Every token response the company sends, read on the way (a spy on `fetch`). */
function spyTokens(w) {
  const bodies = [];
  const handle = w.shop.handle.bind(w.shop);
  w.shop.handle = async (request) => {
    const answer = await handle(request);
    if (new URL(request.url).pathname === "/oauth/token") bodies.push(answer.body);
    return answer;
  };
  return bodies;
}

test("finding 1: a device sign-in after an MCP Bearer token stays DPoP", async () => {
  const w = await world();
  const session = await w.start();
  const bodies = spyTokens(w);
  const done = await deviceSignIn(w, session, { bearerFirst: true });
  assert.equal(done.status, "complete");
  assert.equal(done.token.tokenType, "DPoP");
  await assertSignedInDpop(w, session.sessionId, bodies.at(-1).access_token);
});

test("finding 1: a mediated sign-in after an MCP Bearer token stays DPoP", async () => {
  const w = await world();
  const session = await w.start();
  await bearer(w, session);
  const started = await (await w.postJson(session, MEDIATED, { credentials: ADA, scope: "orders:read" })).json();
  const done = await (await w.postJson(session, `${MEDIATED}/${started.sign_in_id}`, { code: ADA_CODE })).json();
  assert.equal(done.status, "complete");
  assert.equal(done.token_type, "DPoP");
  await assertSignedInDpop(w, session.sessionId, done.access_token);
});

test("finding 3: a retried start answers only who may read the conversation", async () => {
  const w = await world();
  const signedIn = (await deviceSignIn(w, await w.start())).token;
  const message = w.message("Where is my jacket order?");
  await w.conversations.start(w.endpoint, message, { token: signedIn, wait: 0, ...w.who });
  const signedOut = await w.start();
  const retried = await w.postJson(signedOut, `${w.endpoint}?wait=0`, { message });
  assert.equal(retried.status, 403);
  assert.deepEqual(await retried.json(), { error: "sign_in_required" });
});

test("finding 5: operations without a write scope is a configuration error", () => {
  assert.throws(() => new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["orders:read"] }), /writeScopes/);
  assert.throws(
    () => new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["a:read"], writeScopes: ["a:write"] }),
    /among scopes/,
  );
  new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["orders:read"], operations: false });
});

test("finding 5: an operation records and requires its scopes", async () => {
  const w = await world();
  const session = await w.start();
  const done = await deviceSignIn(w, session);
  const page = await w.conversations.start(w.endpoint, w.message("Exchange my jacket for a warmer one"), { token: done.token, wait: 0, ...w.who });
  const proposal = page.events.find((event) => event.message?.operation).message.operation;
  assert.deepEqual([...(await w.shop.operationRecord(proposal.operation_id)).scopes], ["orders:write"]);
  const accounts = new AccountTokenClient({ reactor: w.host.reactor, fetch: w.fetch });
  const narrowed = await accounts.refresh(done.accountTokenReference, {
    context: {
      tokenEndpoint: w.metadata.token_endpoint,
      revocationEndpoint: w.metadata.revocation_endpoint,
      issuer: w.metadata.issuer,
      clientId: w.identity.clientId,
      tenantId: TENANT,
      pairwiseUserId: PAIRWISE,
    },
    sessionId: session.sessionId,
    scopes: ["orders:read"],
  });
  const operations = new OperationsClient({ reactor: w.host.reactor, transport: w.transport });
  await assert.rejects(
    operations.confirm(w.company.document.extensions.operations.endpoint, proposal, { approval: await approve(proposal), token: narrowed.token, ...w.who }),
    (error) => error.code === "insufficient_scope",
  );
});

for (const scope of ["orders:read bogus:scope", undefined, "", "admin:all", 7]) {
  test(`finding 8: mediated sign-in refuses the scope ${JSON.stringify(scope)}`, async () => {
    const w = await world();
    const session = await w.start();
    const response = await w.postJson(session, MEDIATED, { credentials: ADA, ...(scope === undefined ? {} : { scope }) });
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

for (const name of ["authorization", "dpop"]) {
  test(`finding 10: a repeated ${name} header is refused by the Node adapter`, async () => {
    const w = await world();
    const server = createServer(companyRequestListener(w.shop));
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    try {
      const raw = await new Promise((resolve, reject) => {
        const socket = connect(server.address().port, "127.0.0.1");
        let answer = "";
        socket.on("data", (chunk) => (answer += chunk));
        socket.on("end", () => resolve(answer));
        socket.on("error", reject);
        socket.end(
          "POST /poppy/conversations HTTP/1.1\r\nHost: manzanita.example\r\n" +
            `${name}: DPoP one\r\n${name}: DPoP two\r\n` +
            "Content-Length: 2\r\nConnection: close\r\n\r\n{}",
        );
      });
      assert.match(raw, /^HTTP\/1\.1 400 /);
      assert.match(raw, /"error":"invalid_request"/);
    } finally {
      server.close();
    }
  });
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
  const mcpToken = await bearer(w, session);
  const resolver = firstContribution(w.shop.reactor, ClientResolvers, "client");
  const resolved = [];
  const resolve = resolver.resolve.bind(resolver);
  resolver.resolve = async (...args) => {
    resolved.push(args[0]);
    return resolve(...args);
  };
  blocked.add(w.identity.clientId);
  const started = await w.postJson(session, w.endpoint, { message: w.message("hi") });
  assert.equal(started.status, 401);
  const mcp = await w.fetch("https://manzanita.example/mcp", {
    method: "POST",
    headers: { authorization: `Bearer ${mcpToken.accessToken.reveal()}`, "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.equal(mcp.status, 401);
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
  const part = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const assertion = `${part({ alg: "ES256" })}.${part({ iss: w.identity.clientId })}.${part("sig")}`;
  const browser = await w.fetch("https://manzanita.example/poppy/browser-session", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ assertion }).toString(),
  });
  assert.equal(browser.status, 400);
  assert.deepEqual(resolved, []);
});

test("finding 17: the web cookie is a __Host- cookie", () => {
  assert.equal(WEB_COOKIE, "__Host-poppy_session");
});

/** A transport that asks the company even while it said to wait: these tests count refusals. */
function eagerPost(w) {
  const view = { getContributions: (point) => (point === RateLimitBudgets ? [] : w.host.reactor.getContributions(point)) };
  const eager = new DpopFetchClient({ reactor: view, fetch: w.fetch });
  return (token, url, body) =>
    eager.request("POST", url, { token, ...w.who, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
}

test("finding 2: wrong passwords lock the account out, with backoff", async () => {
  const w = await world();
  const session = await w.start();
  const post = eagerPost(w);
  const seen = [];
  const authenticate = w.plugin.accounts.authenticate.bind(w.plugin.accounts);
  w.plugin.accounts.authenticate = async (credentials, context) => {
    seen.push(context);
    return authenticate(credentials, context);
  };
  const wrong = { email: ADA.email, password: "wrong" };
  const answers = [];
  for (let i = 0; i < 8; i += 1) answers.push(await post(session, MEDIATED, { credentials: wrong, scope: "orders:read" }));
  assert.deepEqual(answers.map((a) => a.status), [200, 200, 200, 200, 200, 429, 429, 429]);
  assert.deepEqual(await answers[5].json(), { error: "rate_limited" });
  assert.equal(answers[5].headers.get("retry-after"), String(15 * 60));
  assert.equal(seen.length, 5);
  // Locked out: the directory is not asked, even with the right password.
  const right = await post(session, MEDIATED, { credentials: ADA, scope: "orders:read" });
  assert.equal(right.status, 429);
  assert.equal(seen.length, 5);
  assert.deepEqual(seen[0], { clientId: w.identity.clientId, sessionId: session.sessionId });
  // Once the lockout ends, the next failure locks the account out twice as long.
  w.clock.advance(15 * 60);
  assert.equal((await post(session, MEDIATED, { credentials: wrong, scope: "orders:read" })).status, 200);
  const doubled = await post(session, MEDIATED, { credentials: wrong, scope: "orders:read" });
  assert.equal(doubled.status, 429);
  assert.equal(doubled.headers.get("retry-after"), String(30 * 60));
});

test("finding 2: wrong codes count per account across sign-ins", async () => {
  const w = await world();
  const session = await w.start();
  const post = eagerPost(w);
  let last;
  for (let round = 0; round < 5 && last === undefined; round += 1) {
    const started = await post(session, MEDIATED, { credentials: ADA, scope: "orders:read orders:write" });
    if (started.status === 429) {
      last = started;
      break;
    }
    const { sign_in_id: signInId } = await started.json();
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const answer = await (await post(session, `${MEDIATED}/${signInId}`, { code: `00000${attempt}` })).json();
      if (answer.status === "failed") break;
    }
  }
  assert.ok(last !== undefined);
  assert.deepEqual(await last.json(), { error: "rate_limited" });
  w.clock.advance(15 * 60);
  const started = await (await post(session, MEDIATED, { credentials: ADA, scope: "orders:read" })).json();
  const done = await (await post(session, `${MEDIATED}/${started.sign_in_id}`, { code: ADA_CODE })).json();
  assert.equal(done.status, "complete");
});

test("finding 4: a proof replayed at another replica over the same store is refused", async () => {
  const clock = new MutableClock();
  const store = new MemoryCompanyStore({ clock });
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  sites["manzanita.example"] = manzanita({ fetch, clock, store }).service;
  const host = await agentHost({ identity, fetch, clock });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const session = await new SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tokenEndpoint: metadata.token_endpoint, tenantId: TENANT,
  });
  const captured = [];
  const spying = async (input, init = {}) => {
    captured.push({ url: String(input), init });
    return fetch(input, init);
  };
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch: spying });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: metadata.issuer };
  const endpoint = company.document.agent.protocols[0].endpoint;
  const page = await conversations.start(endpoint, { id: conversations.generateMessageId(), sender: "human", text: "hello" }, { token: session, wait: 0, ...who });
  await conversations.readEvents(endpoint, page.conversation_id, { token: session, ...who });
  const read = captured.find((request) => (request.init.method ?? "GET") === "GET");
  // Another replica over the same store, with the default replay cache.
  sites["manzanita.example"] = manzanita({ fetch, clock, store }).service;
  const replayed = await fetch(read.url, read.init);
  assert.equal(replayed.status, 401);
  assert.equal((await replayed.json()).error, "invalid_dpop_proof");
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
  const turn = (scopes) => ({ conversationId: "cnv_1", text: "Where is my order?", sender: "human", accountId: "acct_ada", scopes, clientId: "https://atlas.example/agent.json", isDirect: false });
  assert.deepEqual(await new ManzanitaAgent().respond(turn(["orders:write"])), [{ authorization: ["insufficient_scope", "orders:read"] }]);
  assert.ok((await new ManzanitaAgent().respond(turn(["orders:read"])))[0].data);
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
  const service = buildCompany(new CompanyConfig({ name: "Shop", domain: "shop.example", scopes: ["a:read"], operations: false }));
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
