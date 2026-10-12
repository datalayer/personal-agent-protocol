/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// One operation through MCP and the website; a Bearer token only at its MCP server. The
// TypeScript clients against the TypeScript company in one process: the port of
// personal_agent_protocol/__tests__/test_mcp_and_web.py.
import assert from "node:assert/strict";
import test from "node:test";

import {
  AccountTokenClient,
  ApiClient,
  BrowserSessionClient,
  DeviceSignInClient,
  DpopFetchClient,
  McpBearerAuth,
  McpClient,
  McpError,
  OperationError,
  OperationsClient,
  PersonalAgentProtocolError,
  SessionClient,
  TransportError,
  approve,
  buildBrowserAssertionClaims,
  discoverCompany,
  mcpApi,
  operationFrom,
  operationPage,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { ControlledBrowser } from "./support/controlled-browser.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const MCP = "https://manzanita.example/mcp";
const ORDERS = "https://manzanita.example/api/orders";

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
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: metadata.issuer };
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const request = {
    clientId: identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: metadata.issuer,
    tokenEndpoint: metadata.token_endpoint,
    tenantId: TENANT,
  };
  const context = {
    tokenEndpoint: metadata.token_endpoint,
    revocationEndpoint: metadata.revocation_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
  };
  const accounts = new AccountTokenClient({ reactor: host.reactor, fetch });
  return { clock, fetch, identity, shop, plugin, host, browser, transport, company, metadata, who, sessions, request, context, accounts };
}

/** A signed-in Session (Device Sign-In, Ada approving) and its Account Token reference. */
async function signedIn(w) {
  const session = await w.sessions.start(w.request);
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

async function bearer(w, token, reference) {
  const result = await w.accounts.bearerForMcp(reference, { context: w.context, sessionId: token.sessionId, resource: MCP });
  assert.equal(result.status, "signed_in");
  return result.token;
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    if (error instanceof PersonalAgentProtocolError) return error;
    throw error;
  }
  assert.fail("expected a refusal");
}

test("the company advertises its MCP server and its issuer", async () => {
  const w = await world();
  await w.sessions.start(w.request);
  assert.equal(mcpApi(w.company.document)?.url, MCP);
  const metadata = await (await w.fetch("https://manzanita.example/.well-known/oauth-protected-resource/mcp")).json();
  assert.equal(metadata.resource, MCP);
  assert.ok(metadata.authorization_servers.includes(w.metadata.issuer));
  const bare = await w.fetch(MCP, { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
  assert.equal(bare.status, 401);
  assert.match(bare.headers.get("www-authenticate"), /resource_metadata=/);
});

test("a signed-in Bearer reads and proposes through MCP the same operation", async () => {
  const w = await world();
  const { token, reference } = await signedIn(w);
  const before = w.host.tokens.get(reference).reveal();
  const result = await w.accounts.bearerForMcp(reference, { context: w.context, sessionId: token.sessionId, resource: MCP });
  assert.equal(result.status, "signed_in");
  assert.equal(result.token.tokenType, "Bearer");
  assert.equal(result.token.signedIn, true);
  assert.equal(result.token.accountToken, undefined); // rotated, stored, never returned
  assert.notEqual(w.host.tokens.get(reference).reveal(), before);

  const mcp = new McpClient({ token: result.token, url: MCP, fetch: w.fetch });
  assert.deepEqual((await mcp.listTools()).map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
  const orders = await mcp.callTool("list_orders");
  assert.deepEqual(orders.structuredContent, {
    orders: [{ order_id: "ord_7Hk2", item: "Ridge Jacket, size M", status: "delivered" }],
  });
  assert.equal(orders.isError, false);

  // The DPoP token of the same Session still works: a Session holds both.
  const proposed = await new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/exchanges`, { ...w.who, token, body: {} });
  const throughMcp = await mcp.callTool("exchange_jacket");
  assert.ok(throughMcp.operation);
  assert.match(throughMcp.text, /Not done until confirmed/);
  assert.deepEqual(throughMcp.operation, proposed.operation); // one record across channels
  assert.deepEqual(operationFrom({ structuredContent: { operation: throughMcp.operation } }), operationFrom({ operation: proposed.operation }));
  const done = await new OperationsClient({ reactor: w.host.reactor, transport: w.transport }).confirm(
    w.shop.config.operationsEndpoint,
    throughMcp.operation,
    { ...w.who, token, approval: await approve(throughMcp.operation) },
  );
  assert.equal(done.operation.state, "succeeded");
  assert.deepEqual(w.plugin.executor.performed, [throughMcp.operation.operation_id]);
});

test("a Bearer token is refused everywhere but its MCP server", async () => {
  const w = await world();
  const { token, reference } = await signedIn(w);
  const issued = await bearer(w, token, reference);
  const secret = issued.accessToken.reveal();

  // The SDK never sends it elsewhere: refused before any request is made.
  let sent = 0;
  const counting = async (input, init) => {
    sent += 1;
    return w.fetch(input, init);
  };
  const auth = new McpBearerAuth(issued, MCP, { fetch: counting });
  for (const url of [
    "https://manzanita.example/api/orders",
    "https://manzanita.example/mcp/other",
    "https://evil.example/mcp",
    "http://manzanita.example/mcp",
    "https://manzanita.example:8443/mcp",
  ]) {
    const error = await refusal(auth.fetch(url));
    assert.ok(error instanceof TransportError);
    assert.equal(error.code, "bearer_not_for_this_url");
  }
  assert.equal(sent, 0);
  assert.equal((await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { ...w.who, token: issued }))).code, "unexpected_token_type");
  assert.throws(() => new McpBearerAuth(token, MCP), (error) => error.code === "unexpected_token_type");
  assert.throws(() => new McpBearerAuth(issued, "http://manzanita.example/mcp"), (error) => error.code === "invalid_url");

  // The company refuses it at every non-MCP endpoint, as Bearer or as DPoP.
  for (const [method, url] of [
    ["GET", "https://manzanita.example/api/orders"],
    ["POST", "https://manzanita.example/poppy/conversations"],
    ["GET", "https://manzanita.example/poppy/operations/op_any"],
    ["POST", "https://manzanita.example/poppy/sign-in"],
  ]) {
    for (const scheme of ["Bearer", "DPoP"]) {
      const response = await w.fetch(url, {
        method,
        headers: { Authorization: `${scheme} ${secret}`, "Content-Type": "application/json" },
        ...(method === "GET" ? {} : { body: "{}" }),
      });
      assert.equal(response.status, 401, `${method} ${url} ${scheme}`);
      assert.ok(!(await response.text()).includes(secret));
    }
  }

  // And the MCP server refuses a DPoP token sent as Bearer.
  const dpopAtMcp = await w.fetch(MCP, {
    method: "POST",
    headers: { Authorization: `Bearer ${token.accessToken.reveal()}`, "Content-Type": "application/json" },
    body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
  });
  assert.equal(dpopAtMcp.status, 401);
});

test("a Bearer is issued only for the MCP url and an existing Session", async () => {
  const w = await world();
  const session = await w.sessions.start(w.request);
  const elsewhere = await refusal(w.sessions.bearerForMcp({ ...w.request, sessionId: session.sessionId, resource: "https://manzanita.example/api" }));
  assert.equal(elsewhere.code, "invalid_dpop_proof"); // DPoP is required everywhere else
  const http = await refusal(w.sessions.bearerForMcp({ ...w.request, sessionId: session.sessionId, resource: "http://manzanita.example/mcp" }));
  assert.equal(http.code, "invalid_url");
  const fragment = await refusal(w.sessions.bearerForMcp({ ...w.request, sessionId: session.sessionId, resource: `${MCP}#tools` }));
  assert.equal(fragment.code, "invalid_url");

  const signedOut = await w.sessions.bearerForMcp({ ...w.request, sessionId: session.sessionId, resource: MCP });
  assert.equal(signedOut.tokenType, "Bearer");
  assert.equal(signedOut.signedIn, false);
  assert.equal(signedOut.sessionId, session.sessionId);
  const refused = await refusal(new McpClient({ token: signedOut, url: MCP, fetch: w.fetch }).callTool("list_orders"));
  assert.ok(refused instanceof McpError);
  assert.equal(refused.code, "sign_in_required");
  assert.equal(refused.statusCode, 403);
  assert.deepEqual(refused.details, { scope: "orders:read" });
  // The DPoP token is untouched by the Bearer request.
  const still = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { ...w.who, token: session }));
  assert.equal(still.code, "sign_in_required");
});

test("a signed-in Bearer needs the MCP url: the Account Token is never sent for another", async () => {
  const w = await world();
  const { token, reference } = await signedIn(w);
  let sent = 0;
  const accounts = new AccountTokenClient({
    reactor: w.host.reactor,
    fetch: async (input, init) => {
      sent += 1;
      return w.fetch(input, init);
    },
  });
  for (const resource of ["http://manzanita.example/mcp", `${MCP}#x`, "https://user:pw@manzanita.example/mcp", "not a url"]) {
    const error = await refusal(accounts.bearerForMcp(reference, { context: w.context, sessionId: token.sessionId, resource }));
    assert.equal(error.code, "invalid_url");
  }
  assert.equal(sent, 0);
});

test("signing out reaches the MCP server at once", async () => {
  const w = await world();
  const { token, reference } = await signedIn(w);
  const mcp = new McpClient({ token: await bearer(w, token, reference), url: MCP, fetch: w.fetch });
  assert.ok((await mcp.callTool("list_orders")).structuredContent);
  await w.accounts.revoke(reference, { context: w.context });
  assert.equal((await refusal(mcp.callTool("list_orders"))).code, "sign_in_required");
});

test("an agent without operations gets no operation through MCP", async () => {
  const w = await world({ extensions: [] });
  const { token, reference } = await signedIn(w);
  const mcp = new McpClient({ token: await bearer(w, token, reference), url: MCP, fetch: w.fetch });
  const error = await refusal(mcp.callTool("exchange_jacket"));
  assert.equal(error.code, "extension_required");
  assert.deepEqual(error.details, { extension: "operations" });
});

test("an MCP answer over SSE, a JSON-RPC error and a malformed operation", async () => {
  const issued = { accessToken: { reveal: () => "sat_test" }, tokenType: "Bearer", expiresIn: 60, scopes: [], sessionId: "ses_1", signedIn: true };
  const answers = [];
  const fetch = async (_url, init) => {
    const message = JSON.parse(init.body);
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer sat_test");
    if (message.id === undefined) return new Response(null, { status: 202 });
    const answer = answers.shift()(message);
    return answer;
  };
  const sse = (payload) =>
    new Response(`: keep-alive\n\nevent: message\ndata: ${JSON.stringify(payload)}\n\n`, { status: 200, headers: { "Content-Type": "text/event-stream", "Mcp-Session-Id": "mcp_1" } });
  answers.push((message) => sse({ jsonrpc: "2.0", id: message.id, result: { protocolVersion: "2025-06-18" } }));
  answers.push((message) => {
    return sse({ jsonrpc: "2.0", id: message.id, result: { content: [{ type: "text", text: "a" }, { type: "text", text: "b" }] } });
  });
  answers.push((message) => sse({ jsonrpc: "2.0", id: message.id, error: { code: -32601, message: "Method not found" } }));
  answers.push((message) => sse({ jsonrpc: "2.0", id: message.id, result: { content: [], structuredContent: { operation: { operation_id: "op_1" } } } }));
  const mcp = new McpClient({ token: issued, url: MCP, fetch });
  const result = await mcp.callTool("anything");
  assert.equal(result.text, "a\nb");
  assert.equal(result.operation, undefined);
  assert.equal((await refusal(mcp.callTool("missing"))).code, "jsonrpc_error");
  assert.equal((await refusal(mcp.callTool("odd"))).code, "invalid_operation");
});

// The website (§5, Operations §4.4) -------------------------------------------------------

async function join(w, sessionId, returnTo) {
  return new BrowserSessionClient({ reactor: w.host.reactor }).join({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    browserSessionEndpoint: w.company.document.web.browser_session_endpoint,
    sessionId,
    returnTo,
    companyDomain: "manzanita.example",
  });
}

test("the company lists its browser-session endpoint", async () => {
  const w = await world();
  assert.deepEqual(w.company.document.web, { browser_session_endpoint: "https://manzanita.example/poppy/browser-session" });
});

test("the operation confirmed on the website is the same operation, once", async () => {
  const w = await world();
  const { token } = await signedIn(w);
  const proposed = await new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/exchanges`, { ...w.who, token, body: {} });
  const operation = proposed.operation;
  const pageUrl = operationPage(operation, w.company.document.organization.domain);
  assert.equal(pageUrl, `https://manzanita.example/operations/${operation.operation_id}`);

  await join(w, token.sessionId, pageUrl);
  const page = w.browser.page;
  assert.equal(page.status, 200);
  assert.equal(page.url, pageUrl);
  assert.ok(page.text.includes(operation.summary) && page.text.includes('data-state="proposed"'));
  const cookie = page.history[0].headers.get("set-cookie");
  assert.equal(page.history[0].status, 303);
  assert.ok(cookie.includes("Secure") && cookie.includes("HttpOnly") && cookie.includes("SameSite=Lax"));
  assert.ok(!cookie.includes("Max-Age") && !cookie.includes("Expires"));
  assert.equal(page.headers.get("x-frame-options"), "DENY");

  const confirmed = await w.browser.submit(pageUrl, { action: "confirm", revision: String(operation.revision), approved_by: "user" });
  assert.ok(confirmed.text.includes('data-state="succeeded"'));

  const operations = new OperationsClient({ reactor: w.host.reactor, transport: w.transport });
  const endpoint = w.shop.config.operationsEndpoint;
  const read = await operations.read(endpoint, operation.operation_id, { ...w.who, token });
  assert.equal(read.state, "succeeded");
  assert.equal(read.confirmation.approved_by, "user");
  const again = await operations.confirm(endpoint, operation, { ...w.who, token, approval: await approve(operation) });
  assert.deepEqual(again.operation, read); // confirming at the endpoint too changes nothing
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
});

test("a form from another site, or without the page's token, decides nothing", async () => {
  const w = await world();
  const { token } = await signedIn(w);
  const { operation } = await new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/exchanges`, { ...w.who, token, body: {} });
  await join(w, token.sessionId, operation.url);
  const jar = [...w.browser.cookies.get("manzanita.example")].map(([name, value]) => `${name}=${value}`).join("; ");
  const post = (headers, form) =>
    w.fetch(operation.url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: jar, ...headers },
      body: new URLSearchParams(form).toString(),
      redirect: "manual",
    });
  const confirm = { action: "confirm", revision: String(operation.revision), approved_by: "user" };
  assert.equal((await post({ "Sec-Fetch-Site": "cross-site" }, confirm)).status, 403);
  assert.equal((await post({ Origin: "https://evil.example" }, confirm)).status, 403);
  assert.equal((await post({}, { ...confirm, csrf: "forged" })).status, 403);
  assert.deepEqual(w.plugin.executor.performed, []);
  // Without its cookie, the page is not shown.
  assert.equal((await w.fetch(operation.url)).status, 401);
});

test("the website follows the Session and refuses bad assertions", async () => {
  const w = await world();
  const { token, reference } = await signedIn(w);
  const { operation } = await new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/gift-wrap`, { ...w.who, token, body: {} });
  assert.ok(operation.url);
  await join(w, token.sessionId, operation.url);
  assert.equal(w.browser.page.status, 200);

  // Signing out reaches the website on its next request: the account's operation is gone.
  await w.accounts.revoke(reference, { context: w.context });
  assert.equal((await w.browser.get(operation.url)).status, 404);

  // A browser assertion is refused off the company's domain, replayed, or as a Session one.
  assert.equal((await refusal(join(w, token.sessionId, "https://evil.example/"))).code, "invalid_return_to");
  const endpoint = "https://manzanita.example/poppy/browser-session";
  const session = await w.sessions.start(w.request);
  const claims = buildBrowserAssertionClaims({
    clientId: w.identity.clientId,
    pairwiseUserId: PAIRWISE,
    browserSessionEndpoint: endpoint,
    sessionId: session.sessionId,
    returnTo: "https://manzanita.example/",
    companyDomain: "manzanita.example",
    now: w.clock.now(),
  });
  const assertion = (await w.identity.signer.sign({ ...claims }, { purpose: "browser_assertion" })).reveal();
  const post = (value) =>
    w.fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ assertion: value }).toString(),
      redirect: "manual",
    });
  const first = await post(assertion);
  assert.equal(first.status, 303);
  assert.ok(first.headers.get("set-cookie"));
  const replayed = await post(assertion);
  assert.equal(replayed.status, 400);
  assert.equal(replayed.headers.get("set-cookie"), null);
  const iat = Math.floor(w.clock.now().getTime() / 1000);
  const sessionAssertion = await w.identity.signer.sign(
    {
      iss: w.identity.clientId,
      sub: PAIRWISE,
      aud: endpoint,
      session_id: session.sessionId,
      return_to: "https://manzanita.example/",
      iat,
      exp: iat + 60,
      jti: "J".repeat(22),
    },
    { purpose: "session_assertion" },
  );
  const typed = await post(sessionAssertion.reveal());
  assert.equal(typed.status, 400);
  assert.equal(typed.headers.get("set-cookie"), null);
});

test("an operation page off the company's domain is refused", () => {
  const operation = operationFrom({
    operation: {
      operation_id: "op_1",
      revision: 1,
      state: "proposed",
      summary: "Gift wrap.",
      expires_at: "2026-10-11T10:00:00Z",
      url: "https://pay.elsewhere.example/op_1",
      confirmation: null,
      result: null,
    },
  });
  assert.throws(() => operationPage(operation, "manzanita.example"), (error) => error instanceof OperationError && error.code === "foreign_operation_page");
  assert.equal(operationPage({ ...operation, url: "https://shop.manzanita.example/op_1" }, "manzanita.example"), "https://shop.manzanita.example/op_1");
  assert.throws(() => operationPage({ ...operation, url: undefined }, "manzanita.example"), (error) => error.code === "no_operation_page");
  assert.throws(() => operationFrom({ text: "nothing" }), (error) => error.code === "invalid_operation");
});
