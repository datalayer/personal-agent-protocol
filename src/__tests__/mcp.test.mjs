/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// One operation through MCP and a joined browser; a token for the MCP server only there. The
// TypeScript clients against the TypeScript company in one process.
import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiClient,
  BrowserSessionClient,
  DeviceSignInClient,
  McpClient,
  McpError,
  McpSessionAuth,
  PapSession,
  PersonalAgentProtocolError,
  RefreshTokenClient,
  SessionClient,
  SessionFetchClient,
  TransportError,
  accessTokenFromResponse,
  discoverCompany,
  fetchMcpServerMetadata,
  mcpApi,
  operationFrom,
  parseTokenResponse,
  sessionHeaders,
  parseProtectedResourceMetadata,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { ControlledBrowser } from "./support/controlled-browser.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const MCP = "https://manzanita.example/mcp";
const ORDERS = "https://manzanita.example/api/orders";
const BROWSER_SESSION = "https://manzanita.example/poppy/browser-session";
const LIST_TOOLS = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}';

async function world({ extensions } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas", ...(extensions ? { extensions } : {}) });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock });
  sites["manzanita.example"] = shop;
  const browser = new ControlledBrowser(fetch);
  const host = await agentHost({ identity, fetch, clock, controlledBrowser: browser });
  const reactor = host.reactor;
  const transport = new SessionFetchClient({ reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor });
  const metadata = company.oauthMetadata;
  const sessions = new SessionClient({ reactor, fetch });
  const start = () =>
    sessions.start({ clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tenantId: TENANT });
  const context = {
    tokenEndpoint: metadata.token_endpoint,
    revocationEndpoint: metadata.revocation_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    tenantId: TENANT,
  };
  const accounts = new RefreshTokenClient({ reactor, fetch });
  return { clock, fetch, identity, shop, plugin, host, reactor, browser, transport, company, metadata, start, context, accounts };
}

/** A Session, signed in by Device Sign-In with Ada approving, and its refresh token's reference. */
async function signedIn(w) {
  const session = await w.start();
  const device = new DeviceSignInClient({ reactor: w.reactor, fetch: w.fetch });
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
  return { session, token: done.token, reference: done.refreshTokenReference };
}

/** A token for the MCP server: a refresh with `resource`, its `url` (§4.5, §7). */
async function mcpToken(w, reference, url = MCP) {
  const result = await w.accounts.tokenForMcp(reference, { context: w.context, server: parseProtectedResourceMetadata({ resource: url }) });
  assert.equal(result.status, "signed_in");
  return result.token;
}

const mcpClient = (w, session, token) =>
  new McpClient({ url: MCP, session, reactor: w.reactor, fetch: w.fetch, ...(token === undefined ? {} : { token }) });

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    if (error instanceof PersonalAgentProtocolError) return error;
    throw error;
  }
  assert.fail("expected a refusal");
}

const signedHeaders = async (w, method, url, session, token) => ({
  "Content-Type": "application/json",
  ...(await sessionHeaders(w.reactor, method, url, { session, ...(token === undefined ? {} : { token }) })),
});

test("the company advertises its MCP server and its issuer", async () => {
  const w = await world();
  const session = await w.start();
  assert.equal(mcpApi(w.company.document)?.url, MCP);
  const served = await fetchMcpServerMetadata(MCP, { issuer: session.issuer, fetch: w.fetch });
  assert.equal(served.resource, MCP);
  const metadata = await (await w.fetch("https://manzanita.example/.well-known/oauth-protected-resource/mcp")).json();
  assert.equal(metadata.resource, MCP);
  assert.ok(metadata.authorization_servers.includes(w.metadata.issuer));
  // Tokens are Bearer tokens: nothing here speaks of DPoP (§4.5).
  assert.equal("dpop_signing_alg_values_supported" in metadata, false);

  // A client with no Session header and no token gets where to read the metadata (§7).
  const bare = await w.fetch(MCP, { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
  assert.equal(bare.status, 401);
  assert.match(bare.headers.get("www-authenticate"), /resource_metadata=/);
  assert.doesNotMatch(bare.headers.get("www-authenticate"), /error=/);

  // An invented token is `invalid_token`, whatever else the request lacks (§7).
  const invented = await w.fetch(MCP, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer invented" },
    body: '{"jsonrpc":"2.0","id":1,"method":"ping"}',
  });
  assert.equal(invented.status, 401);
  assert.match(invented.headers.get("www-authenticate"), /error="invalid_token"/);
  assert.match(invented.headers.get("www-authenticate"), /resource_metadata=/);

  // A token not issued for the server: one Bearer challenge with `resource_metadata` (§7).
  const { session: mine, token } = await signedIn(w);
  const refused = await w.fetch(MCP, { method: "POST", headers: await signedHeaders(w, "POST", MCP, mine, token), body: LIST_TOOLS });
  assert.equal(refused.status, 401);
  const challenge = refused.headers.get("www-authenticate");
  assert.deepEqual([...challenge.matchAll(/(?:^|, )(Bearer|DPoP) error=/gu)].map((match) => match[1]), ["Bearer"]);
  assert.equal(challenge.split("resource_metadata=").length - 1, 1);

  const wrong = await refusal(fetchMcpServerMetadata(MCP, { issuer: "https://other.example", fetch: w.fetch }));
  assert.equal(wrong.code, "invalid_resource_metadata");
});

test("a signed-in MCP token reads and proposes the same operation", async () => {
  const w = await world();
  const { session, token, reference } = await signedIn(w);
  const before = w.host.tokens.get(reference).reveal();
  const forMcp = await mcpToken(w, reference);
  // A Bearer token for the server's url, the refresh token rotated, stored, never returned.
  assert.equal(forMcp.tokenType, "Bearer");
  assert.equal(forMcp.resource, MCP);
  assert.notEqual(w.host.tokens.get(reference).reveal(), before);

  const mcp = mcpClient(w, session, forMcp);
  assert.deepEqual((await mcp.listTools()).map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
  const orders = await mcp.callTool("list_orders");
  assert.deepEqual(orders.structuredContent, {
    orders: [{ order_id: "ord_7Hk2", item: "Ridge Jacket, size M", status: "delivered" }],
  });
  assert.equal(orders.isError, false);

  // The default token still works: a Session can use both.
  const proposed = await new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/exchanges`, { session, token, body: {} });
  const throughMcp = await mcp.callTool("exchange_jacket");
  assert.ok(throughMcp.operation);
  assert.equal(throughMcp.isError, true);
  assert.match(throughMcp.text, /Not done yet/);
  // One operation across interfaces, each with its own revision: its own request.
  assert.equal(throughMcp.operation.operation_id, proposed.operation.operation_id);
  assert.deepEqual(throughMcp.operation.terms, proposed.operation.terms);
  assert.deepEqual(operationFrom({ structuredContent: { operation: throughMcp.operation } }), throughMcp.operation);
  const { operation_id, revision } = throughMcp.operation;
  const done = await mcp.callTool("exchange_jacket", {}, { approval: { operation_id, revision } });
  assert.equal(done.isError, false);
  assert.ok(done.text.startsWith("Exchanged"));
  assert.deepEqual(w.plugin.executor.performed, [operation_id]);
});

test("an MCP token is refused everywhere but its MCP server", async () => {
  const w = await world();
  const { session, token, reference } = await signedIn(w);
  const forMcp = await mcpToken(w, reference);
  const secret = forMcp.accessToken.reveal();

  // The SDK never sends it elsewhere: refused before any request is made.
  let sent = 0;
  const counting = async (input, init) => {
    sent += 1;
    return w.fetch(input, init);
  };
  const auth = new McpSessionAuth(MCP, { session, token: forMcp, reactor: w.reactor, fetch: counting });
  for (const url of [
    "https://manzanita.example/api/orders",
    "https://manzanita.example/mcp/other",
    "https://evil.example/mcp",
    "http://manzanita.example/mcp",
    "https://manzanita.example:8443/mcp",
  ]) {
    const error = await refusal(auth.fetch(url));
    assert.ok(error instanceof TransportError);
    assert.equal(error.code, "token_not_for_this_url");
  }
  assert.equal(sent, 0);
  // And an MCP server takes only a token issued for its url.
  assert.throws(
    () => new McpSessionAuth(MCP, { session, token, reactor: w.reactor }),
    (error) => error instanceof TransportError && error.code === "token_not_for_this_url",
  );
  assert.throws(
    () => new McpSessionAuth("http://manzanita.example/mcp", { session, reactor: w.reactor }),
    (error) => error.code === "invalid_url",
  );
  const refusedApi = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { session, token: forMcp }));
  assert.equal(refusedApi.code, "invalid_token");

  // The company refuses it at every other endpoint, in a valid Session (§4.5).
  for (const [method, url] of [
    ["GET", ORDERS],
    ["POST", "https://manzanita.example/poppy/conversations"],
    ["POST", "https://manzanita.example/poppy/feedback"],
  ]) {
    const body = method === "GET" ? {} : { body: "{}" };
    const response = await w.fetch(url, { method, headers: await signedHeaders(w, method, url, session, forMcp), ...body });
    assert.equal(response.status, 401, `${method} ${url}`);
    const challenge = response.headers.get("www-authenticate");
    assert.ok(challenge.includes("invalid_token") && challenge.includes("resource_metadata="));
    assert.ok(!(await response.text()).includes(secret));
    // Copied without the Session header it is worth nothing at all (§5.3).
    const copied = await w.fetch(url, {
      method,
      headers: { Authorization: `Bearer ${secret}`, "Content-Type": "application/json" },
      ...body,
    });
    assert.equal(copied.status, 400, `${method} ${url}`);
    const text = await copied.text();
    assert.equal(JSON.parse(text).error, "invalid_session");
    assert.ok(!text.includes(secret));
  }

  // The MCP server refuses the default token: it was not issued for the server.
  const refused = await w.fetch(MCP, { method: "POST", headers: await signedHeaders(w, "POST", MCP, session, token), body: LIST_TOOLS });
  assert.equal(refused.status, 401);
  assert.ok(refused.headers.get("www-authenticate").includes('error="invalid_token"'));
});

test("a token for the MCP server comes from a refresh with its url", async () => {
  // A refresh with `resource`, the server's `url`, and nothing else: another `resource` is
  // `invalid_target`. Signed out, the Session header alone (§4.5, §7).
  const w = await world();
  const session = await w.start();
  const mcp = mcpClient(w, session);
  assert.deepEqual((await mcp.listTools()).map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
  const refused = await refusal(mcp.callTool("list_orders"));
  assert.ok(refused instanceof McpError);
  assert.deepEqual([refused.code, refused.statusCode], ["insufficient_scope", 401]);
  assert.equal(refused.details.scope, "orders:read");
  // A signed-out call for the account's action is refused the same way.
  assert.equal((await refusal(mcp.callTool("exchange_jacket"))).code, "insufficient_scope");

  const { reference } = await signedIn(w);
  const plain = await refusal(w.accounts.tokenForMcp(reference, { context: w.context, server: { resource: "http://manzanita.example/mcp" } }));
  assert.equal(plain.code, "invalid_url");
  const elsewhere = await refusal(w.accounts.tokenForMcp(reference, { context: w.context, server: parseProtectedResourceMetadata({ resource: "https://elsewhere.example/mcp" }) }));
  assert.equal(elsewhere.code, "invalid_target");
  const token = await mcpToken(w, reference);
  assert.equal(token.resource, MCP);
  assert.ok((await mcpClient(w, session, token).callTool("list_orders")).structuredContent);

  // The Session's own footing is untouched by the request for the MCP server.
  const still = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { session }));
  assert.equal(still.code, "insufficient_scope");
});

test("a refresh for a resource needs an HTTPS URL: nothing is sent for another", async () => {
  const w = await world();
  const { reference } = await signedIn(w);
  let sent = 0;
  const accounts = new RefreshTokenClient({
    reactor: w.reactor,
    fetch: async (input, init) => {
      sent += 1;
      return w.fetch(input, init);
    },
  });
  for (const resource of ["http://manzanita.example/mcp", "https://user:pw@manzanita.example/mcp", "not a url"]) {
    const error = await refusal(accounts.refresh(reference, { context: w.context, resource }));
    assert.equal(error.code, "invalid_url");
  }
  assert.equal(sent, 0);
});

test("an MCP server that ends the Session gets a new one, once", async () => {
  // `invalid_session` starts a new Session once, then stops, wherever it comes from (§7).
  const w = await world();
  const session = await w.start();
  const mcp = mcpClient(w, session);
  assert.ok((await mcp.listTools()).length);
  const ended = session.sid;
  assert.ok(await w.shop.endSession(session.clientId, ended));
  assert.deepEqual((await mcp.listTools()).map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
  assert.notEqual(session.sid, ended);
});

test("a second invalid_session from an MCP server stops", async () => {
  const w = await world();
  const session = await w.start();
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return Response.json({ error: "invalid_session" }, { status: 400 });
  };
  const refused = await refusal(new McpClient({ url: MCP, session, reactor: w.reactor, fetch }).listTools());
  assert.ok(refused instanceof McpError);
  assert.deepEqual([refused.code, refused.statusCode], ["invalid_session", 400]);
  assert.equal(calls, 2);
});

test("signing out reaches the MCP server at once", async () => {
  const w = await world();
  const { session, reference } = await signedIn(w);
  const mcp = mcpClient(w, session, await mcpToken(w, reference));
  assert.ok((await mcp.callTool("list_orders")).structuredContent);
  await w.accounts.revoke(reference, { context: w.context });
  // The sign-in's access tokens are gone with it (§5.5).
  assert.equal((await refusal(mcp.callTool("list_orders"))).code, "invalid_token");
  // The Session goes on signed out, the Session header alone.
  assert.equal((await refusal(mcpClient(w, session).callTool("list_orders"))).code, "insufficient_scope");
});

test("an agent without operations gets a tool error through MCP", async () => {
  // A tool can't answer `extension_required`, which refuses the agent entirely (§7): a
  // tool that needs the Operations extension returns an ordinary tool error.
  const w = await world({ extensions: [] });
  const { session, reference } = await signedIn(w);
  const mcp = mcpClient(w, session, await mcpToken(w, reference));
  const answer = await mcp.callTool("exchange_jacket");
  assert.equal(answer.isError, true);
  assert.equal(answer.operation, undefined);
  assert.match(answer.text, /Operations extension/);
  assert.ok((await mcp.callTool("list_orders")).structuredContent);
});

test("a Session holds a token for the MCP server and its default token", async () => {
  // One account's tokens: one for each server that asks for its own, and the default one for
  // its other APIs, each used only where it works (§4.5).
  const w = await world();
  const { session, reference } = await signedIn(w);
  const forMcp = await mcpToken(w, reference);
  const own = await w.accounts.refresh(reference, { context: w.context });
  assert.equal(own.status, "signed_in");
  assert.equal(own.token.resource, undefined);
  await new ApiClient({ transport: w.transport }).call("GET", ORDERS, { session, token: own.token });
  // The token for the MCP server still works there.
  assert.ok((await mcpClient(w, session, forMcp).callTool("list_orders")).structuredContent);
});

/** A signed-out Session and a Bearer token for the MCP server, without a company. */
async function scripted() {
  const w = await world();
  const session = new PapSession({
    sid: "S".repeat(22),
    sub: PAIRWISE,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    tenantId: TENANT,
  });
  const token = accessTokenFromResponse(
    parseTokenResponse({ access_token: "sat_test", token_type: "Bearer", expires_in: 60, scope: "orders:read" }),
    { resource: MCP },
  );
  return { reactor: w.reactor, session, token };
}

test("an MCP answer over SSE, a JSON-RPC error and a malformed operation", async () => {
  const { reactor, session, token } = await scripted();
  const answers = [];
  const fetch = async (_url, init) => {
    const message = JSON.parse(init.body);
    const headers = new Headers(init.headers);
    assert.equal(headers.get("authorization"), "Bearer sat_test");
    assert.ok(headers.get("poppy-session"));
    if (message.id === undefined) return new Response(null, { status: 202 });
    return answers.shift()(message);
  };
  const sse = (payload) =>
    new Response(`: keep-alive\n\nevent: message\ndata: ${JSON.stringify(payload)}\n\n`, { status: 200, headers: { "Content-Type": "text/event-stream", "Mcp-Session-Id": "mcp_1" } });
  answers.push((message) => sse({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2025-06-18" } }));
  answers.push((message) => sse({ jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] } }));
  answers.push((message) => sse({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } }));
  answers.push((message) => sse({ jsonrpc: "2.0", id: message.id, result: { content: [], structuredContent: { operation: { operation_id: "op_1" } } } }));
  const mcp = new McpClient({ token, url: MCP, session, reactor, fetch });
  const result = await mcp.callTool("anything");
  assert.equal(result.text, "a\nb");
  assert.equal(result.operation, undefined);
  assert.equal((await refusal(mcp.callTool("missing"))).code, "jsonrpc_error");
  assert.equal((await refusal(mcp.callTool("odd"))).code, "invalid_operation");
});

test("an MCP 429 is rate_limited with its Retry-After, and says when to retry", async () => {
  const { reactor, session, token } = await scripted();
  const refusals = [];
  const fetch = async (_url, init) => {
    const message = JSON.parse(init.body);
    if (message.id === undefined) return new Response(null, { status: 202 });
    if (message.method === "initialize") return Response.json({ jsonrpc: "2.0", id: message.id, result: {} });
    return refusals.shift();
  };
  const mcp = new McpClient({ token, url: MCP, session, reactor, fetch });

  refusals.push(Response.json({ error: "slow" }, { status: 429, headers: { "Retry-After": "30" } }));
  let refused = await refusal(mcp.callTool("orders"));
  assert.ok(refused instanceof McpError);
  assert.equal(refused.code, "rate_limited");
  assert.equal(refused.statusCode, 429);
  assert.deepEqual(refused.details, { retry_after: "30" });
  assert.equal(String(refused), "rate_limited: the MCP server is rate limited, retry after 30 s");

  const when = new Date(Date.now() + 90_000).toUTCString();
  refusals.push(new Response(null, { status: 429, headers: { "Retry-After": when } }));
  refused = await refusal(mcp.listTools());
  assert.equal(refused.code, "rate_limited");
  assert.deepEqual(refused.details, { retry_after: when });
  assert.match(String(refused), /^rate_limited: the MCP server is rate limited, retry after (89|90) s$/u);

  refusals.push(new Response(null, { status: 429 }));
  refused = await refusal(mcp.listTools());
  assert.equal(refused.code, "rate_limited");
  assert.deepEqual(refused.details, {});
  assert.equal(String(refused), "rate_limited: the MCP server is rate limited");

  refusals.push(new Response(null, { status: 503, headers: { "Retry-After": "30" } }));
  refused = await refusal(mcp.listTools());
  assert.deepEqual([refused.code, refused.statusCode, refused.details], ["temporarily_unavailable", 503, { retry_after: "30" }]);
});

// The website (§6) ------------------------------------------------------------------------------

/** Join the agent's browser to the Session (§6), then open `page` in it. */
async function join(w, session, token, page) {
  await new BrowserSessionClient({ reactor: w.reactor, transport: w.transport }).join({
    browserSessionEndpoint: w.company.document.web.browser_session_endpoint,
    session,
    token,
  });
  await w.browser.get(page);
}

function setCookies(headers) {
  return typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [headers.get("set-cookie")].filter(Boolean);
}

const noSessionCookie = (response) => !setCookies(response.headers).some((cookie) => cookie.startsWith("__Host-poppy_session="));

test("the company lists its browser-session endpoint", async () => {
  const w = await world();
  assert.deepEqual(w.company.document.web, { browser_session_endpoint: BROWSER_SESSION });
});

test("a joined browser follows the Session", async () => {
  const w = await world();
  const { session, token, reference } = await signedIn(w);
  await join(w, session, token, "https://manzanita.example/");
  const cookie = w.browser.cookies.get("manzanita.example").get("__Host-poppy_session");
  assert.ok(cookie);
  const joined = await w.shop.webSession(cookie);
  assert.equal(joined.accountId, "acct_ada");
  assert.equal(joined.sid, session.sid);

  // Signing out reaches the website on its next request: the Session continues signed out.
  await w.accounts.revoke(reference, { context: w.context });
  const signedOut = await w.shop.webSession(cookie);
  assert.ok(signedOut);
  assert.equal(signedOut.accountId, undefined);

  // Ending the Session ends the browser's cookie with it (§6).
  assert.ok(await w.shop.endSession(session.clientId, session.sid));
  assert.equal(await w.shop.webSession(cookie), undefined);
});

test("the join page is one-time, tied to its browser, and never framed", async () => {
  // Step 1 of §6: a form with a one-time code, a `__Host-` cookie that ties the code to this
  // browser, no caching, no framing, no opener.
  const w = await world();
  const page = await w.fetch(BROWSER_SESSION, { method: "GET" });
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.equal(page.headers.get("content-security-policy"), "frame-ancestors 'none'");
  assert.equal(page.headers.get("cross-origin-opener-policy"), "same-origin");
  const cookie = page.headers.get("set-cookie");
  for (const part of ["__Host-poppy_join=", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=60"]) assert.ok(cookie.includes(part), part);
  const text = await page.text();
  const code = /name="code" value="([^"]+)"/.exec(text)[1];
  // The code alone: the browser never holds anything of the Session's (§6).
  assert.ok(code.length >= 22);
  assert.ok(!text.includes('name="proof"'));
});

async function joinForm(w) {
  const browser = new ControlledBrowser(w.fetch);
  const page = await browser.get(BROWSER_SESSION);
  return { browser, code: /name="code" value="([^"]+)"/.exec(page.text)[1] };
}

/** Step 2 of §6, one request as it goes on the wire: no new Session on a refusal. */
async function authorize(w, session, code) {
  const url = `${BROWSER_SESSION}/authorize`;
  return w.fetch(url, {
    method: "POST",
    headers: await signedHeaders(w, "POST", url, session),
    body: JSON.stringify({ code }),
  });
}

const errorOf = async (response) => (await response.json()).error;

test("a join needs its own browser, its code once, and a live Session", async () => {
  // Step 3 of §6 and both attacks of §10.6: a code submitted from another browser, a code used
  // twice, a code the agent never authorized, a Session that has ended.
  const w = await world();
  const session = await w.start();

  let { browser, code } = await joinForm(w);
  assert.equal((await authorize(w, session, code)).status, 204);
  // Authorized once only.
  assert.equal(await errorOf(await authorize(w, session, code)), "invalid_request");
  // Another browser (no join cookie): an attacker's code can't make it join (§10.6).
  const stolen = await new ControlledBrowser(w.fetch).postForm(BROWSER_SESSION, { code });
  assert.ok(stolen.status === 400 && noSessionCookie(stolen));
  // The code was used by that first request, whatever the result: gone.
  assert.equal((await browser.postForm(BROWSER_SESSION, { code })).status, 400);
  assert.equal(await errorOf(await authorize(w, session, code)), "invalid_request");

  // A code the agent never authorized sets no cookie, in the browser it was issued to.
  ({ browser, code } = await joinForm(w));
  const unauthorized = await browser.postForm(BROWSER_SESSION, { code });
  assert.ok(unauthorized.status === 400 && noSessionCookie(unauthorized));

  // A code that was never issued can't be authorized.
  assert.equal(await errorOf(await authorize(w, session, `bc_${"x".repeat(22)}`)), "invalid_request");

  // Without the Session header, or with one for an ended Session, nothing is authorized.
  ({ browser, code } = await joinForm(w));
  const bare = await w.fetch(`${BROWSER_SESSION}/authorize`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  assert.equal(bare.status, 400);
  assert.equal(await errorOf(bare), "invalid_session");
  const ended = await w.start();
  assert.equal((await authorize(w, ended, `bc_${"y".repeat(22)}`)).status, 400);
  assert.ok(await w.shop.endSession(ended.clientId, ended.sid));
  const refused = await authorize(w, ended, code);
  assert.equal(refused.status, 400);
  assert.equal(await errorOf(refused), "invalid_session");

  assert.equal((await authorize(w, session, code)).status, 204);
  const joined = await browser.postForm(BROWSER_SESSION, { code });
  assert.equal(joined.status, 303);
  const cookies = setCookies(joined.headers);
  assert.ok(cookies.some((cookie) => cookie.startsWith("__Host-poppy_session=") && cookie.includes("SameSite=Strict")));
  assert.ok(cookies.some((cookie) => cookie.startsWith("__Host-poppy_join=;") && cookie.includes("Max-Age=0")));
});

test("the join form has no proof field, and an agent's own browser joins with the code", async () => {
  const w = await world();
  const session = await w.start();
  await join(w, session, undefined, "https://manzanita.example/");
  assert.ok(w.browser.cookies.get("manzanita.example").get("__Host-poppy_session"));
});
