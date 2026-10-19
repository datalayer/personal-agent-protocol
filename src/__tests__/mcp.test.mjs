/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// One operation through MCP and the website; a token for the MCP server only there. The
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
  McpDpopAuth,
  McpError,
  OperationError,
  OperationsClient,
  PersonalAgentProtocolError,
  SessionClient,
  TransportError,
  approve,
  buildBrowserAssertionClaims,
  discoverCompany,
  fetchMcpServerMetadata,
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

async function world({ extensions, config } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas", ...(extensions ? { extensions } : {}) });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock, ...(config === undefined ? {} : { config }) });
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
    organization: { name: "Manzanita", domain: w.metadata.poppy_domains[0] },
    poppyDomains: w.metadata.poppy_domains,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return { token: done.token, reference: done.accountTokenReference };
}

async function mcpToken(w, token, reference, dpop) {
  const result = await w.accounts.tokenForMcp(reference, { context: w.context, sessionId: token.sessionId, resource: MCP, dpop });
  assert.equal(result.status, "signed_in");
  return result.token;
}

function mcpClient(w, token) {
  return new McpClient({ token, url: MCP, fetch: w.fetch, reactor: w.host.reactor, who: w.who });
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

for (const dpop of [true, false]) {
  test(`the company advertises its MCP server and its issuer (DPoP: ${dpop})`, async () => {
    const w = await world({ config: { mcpDpop: dpop } });
    await w.sessions.start(w.request);
    assert.equal(mcpApi(w.company.document)?.url, MCP);
    const served = await fetchMcpServerMetadata(MCP, { issuer: w.who.issuer, fetch: w.fetch });
    assert.equal(served.resource, MCP);
    assert.equal(served.supportsDpop, dpop);
    const metadata = await (await w.fetch("https://manzanita.example/.well-known/oauth-protected-resource/mcp")).json();
    assert.equal(metadata.resource, MCP);
    assert.ok(metadata.authorization_servers.includes(w.metadata.issuer));
    if (dpop) {
      // It supports DPoP, ES256 among its algorithms (§4.3, RFC 9728 §2).
      assert.ok(metadata.dpop_signing_alg_values_supported.includes("ES256"));
    } else {
      assert.equal("dpop_signing_alg_values_supported" in metadata, false);
    }
    const bare = await w.fetch(MCP, { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
    assert.equal(bare.status, 401);
    const challenge = bare.headers.get("www-authenticate");
    // One challenge per scheme it accepts, each with resource_metadata (§6).
    const schemes = [...challenge.matchAll(/(?:^|, )(Bearer|DPoP) error=/gu)].map((match) => match[1]);
    assert.deepEqual(schemes, dpop ? ["Bearer", "DPoP"] : ["Bearer"]);
    assert.equal(challenge.split("resource_metadata=").length - 1, schemes.length);
    const wrong = await refusal(fetchMcpServerMetadata(MCP, { issuer: "https://other.example", fetch: w.fetch }));
    assert.equal(wrong.code, "invalid_resource_metadata");
  });

  test(`a signed-in MCP token reads and proposes the same operation (DPoP: ${dpop})`, async () => {
    const w = await world({ config: { mcpDpop: dpop } });
    const { token, reference } = await signedIn(w);
    const before = w.host.tokens.get(reference).reveal();
    const issued = await mcpToken(w, token, reference, dpop);
    // The scheme the server takes: DPoP with proofs, or a Bearer token for its url (§4.3).
    assert.equal(issued.tokenType, dpop ? "DPoP" : "Bearer");
    assert.equal(issued.signedIn, true);
    assert.equal(issued.accountToken, undefined); // rotated, stored, never returned
    assert.notEqual(w.host.tokens.get(reference).reveal(), before);

    const mcp = mcpClient(w, issued);
    assert.deepEqual((await mcp.listTools()).map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
    const orders = await mcp.callTool("list_orders");
    assert.deepEqual(orders.structuredContent, {
      orders: [{ order_id: "ord_7Hk2", item: "Ridge Jacket, size M", status: "delivered" }],
    });
    assert.equal(orders.isError, false);

    // The Session's own DPoP token still works: a Session holds both.
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

  test(`an MCP token is refused everywhere but its MCP server (DPoP: ${dpop})`, async () => {
    const w = await world({ config: { mcpDpop: dpop } });
    const { token, reference } = await signedIn(w);
    const issued = await mcpToken(w, token, reference, dpop);
    const secret = issued.accessToken.reveal();

    // The SDK never sends it elsewhere: refused before any request is made.
    let sent = 0;
    const counting = async (input, init) => {
      sent += 1;
      return w.fetch(input, init);
    };
    const auth = dpop
      ? new McpDpopAuth(issued, MCP, { reactor: w.host.reactor, who: w.who, fetch: counting })
      : new McpBearerAuth(issued, MCP, { fetch: counting });
    for (const url of [
      "https://manzanita.example/api/orders",
      "https://manzanita.example/mcp/other",
      "https://evil.example/mcp",
      "http://manzanita.example/mcp",
      "https://manzanita.example:8443/mcp",
    ]) {
      const error = await refusal(auth.fetch(url));
      assert.ok(error instanceof TransportError);
      assert.equal(error.code, dpop ? "token_not_for_this_url" : "bearer_not_for_this_url");
    }
    assert.equal(sent, 0);
    assert.ok(await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { ...w.who, token: issued })));
    assert.throws(() => new McpBearerAuth(token, MCP), (error) => error.code === "unexpected_token_type");
    if (!dpop) {
      assert.throws(() => new McpDpopAuth(issued, MCP, { reactor: w.host.reactor, who: w.who }), (error) => error.code === "unexpected_token_type");
      assert.throws(() => new McpBearerAuth(issued, "http://manzanita.example/mcp"), (error) => error.code === "invalid_url");
    }

    // The company refuses it at every other endpoint, as Bearer or as DPoP (§4.3).
    for (const [method, url] of [
      ["GET", "https://manzanita.example/api/orders"],
      ["POST", "https://manzanita.example/poppy/conversations"],
      ["GET", "https://manzanita.example/poppy/operations/op_any"],
      ["POST", "https://manzanita.example/poppy/sign-in"],
      ["POST", "https://manzanita.example/poppy/feedback"],
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

    // The MCP server refuses the Session's own DPoP token, in either scheme: it was not
    // issued for the server; and a DPoP token is never accepted as a Bearer token.
    const own = token.accessToken.reveal();
    for (const value of [`Bearer ${own}`, ...(dpop ? [`Bearer ${secret}`] : [])]) {
      const refused = await w.fetch(MCP, {
        method: "POST",
        headers: { Authorization: value, "Content-Type": "application/json" },
        body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
      });
      assert.equal(refused.status, 401);
    }
  });

  test(`signing out reaches the MCP server at once (DPoP: ${dpop})`, async () => {
    const w = await world({ config: { mcpDpop: dpop } });
    const { token, reference } = await signedIn(w);
    const mcp = mcpClient(w, await mcpToken(w, token, reference, dpop));
    assert.ok((await mcp.callTool("list_orders")).structuredContent);
    await w.accounts.revoke(reference, { context: w.context });
    assert.equal((await refusal(mcp.callTool("list_orders"))).code, "sign_in_required");
  });

  test(`a Session started for the MCP server gets its own token too (DPoP: ${dpop})`, async () => {
    // A Session can hold a token for each MCP server and one for its other APIs (§4.3).
    const w = await world({ config: { mcpDpop: dpop } });
    await w.sessions.start(w.request);
    const forMcp = await w.sessions.tokenForMcp({ ...w.request, resource: MCP, dpop });
    const own = await w.sessions.renew({ ...w.request, sessionId: forMcp.sessionId });
    assert.equal(own.sessionId, forMcp.sessionId);
    assert.equal(own.tokenType, "DPoP");
    const needsSignIn = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { ...w.who, token: own }));
    assert.equal(needsSignIn.code, "sign_in_required");
    // The token for the MCP server still works there.
    const signedOut = await refusal(mcpClient(w, forMcp).callTool("list_orders"));
    assert.equal(signedOut.code, "sign_in_required");
  });
}

test("the token type is chosen by the MCP server", async () => {
  // DPoP server: a request without a proof is refused, never answered with Bearer. Server
  // without DPoP: a Bearer token for its url even when the request has a proof (§4.3).
  for (const dpop of [true, false]) {
    const w = await world({ config: { mcpDpop: dpop } });
    const session = await w.sessions.start(w.request);
    const elsewhere = await refusal(
      w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: "https://manzanita.example/api", dpop: false }),
    );
    assert.equal(elsewhere.code, "invalid_dpop_proof"); // DPoP is required everywhere else
    const http = await refusal(w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: "http://manzanita.example/mcp", dpop }));
    assert.equal(http.code, "invalid_url");
    const fragment = await refusal(w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: `${MCP}#tools`, dpop }));
    assert.equal(fragment.code, "invalid_url");
    const withProof = await w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: MCP, dpop: true });
    assert.equal(withProof.tokenType, dpop ? "DPoP" : "Bearer");
    if (dpop) {
      const noProof = await refusal(w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: MCP, dpop: false }));
      assert.equal(noProof.code, "invalid_dpop_proof");
    }
    // A new Session can start for the MCP server alone (§4.3: the request that starts one).
    const started = await w.sessions.tokenForMcp({ ...w.request, resource: MCP, dpop });
    assert.notEqual(started.sessionId, session.sessionId);
    assert.equal(started.signedIn, false);

    const signedOut = await w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: MCP, dpop });
    assert.equal(signedOut.tokenType, dpop ? "DPoP" : "Bearer");
    assert.equal(signedOut.signedIn, false);
    assert.equal(signedOut.sessionId, session.sessionId);
    const refused = await refusal(mcpClient(w, signedOut).callTool("list_orders"));
    assert.ok(refused instanceof McpError);
    assert.equal(refused.code, "sign_in_required");
    assert.equal(refused.statusCode, 403);
    assert.deepEqual(refused.details, { scope: "orders:read" });
    // The Session's own token is untouched by the request for the MCP server.
    const still = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { ...w.who, token: session }));
    assert.equal(still.code, "sign_in_required");
  }
});

test("a DPoP MCP server retries once with its nonce", async () => {
  const w = await world({ config: { mcpDpop: true, dpopNonce: true } });
  const session = await w.sessions.start(w.request);
  const token = await w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: MCP, dpop: true });
  const tools = await mcpClient(w, token).listTools();
  assert.deepEqual(tools.map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
});

test("a DPoP token for MCP needs the host's reactor and who", async () => {
  const w = await world();
  const session = await w.sessions.start(w.request);
  const token = await w.sessions.tokenForMcp({ ...w.request, sessionId: session.sessionId, resource: MCP, dpop: true });
  assert.throws(() => new McpClient({ token, url: MCP, fetch: w.fetch }), (error) => error.code === "dpop_unavailable");
});

test("a signed-in MCP token needs the MCP url: the Account Token is never sent for another", async () => {
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
    const error = await refusal(accounts.tokenForMcp(reference, { context: w.context, sessionId: token.sessionId, resource, dpop: true }));
    assert.equal(error.code, "invalid_url");
  }
  assert.equal(sent, 0);
});

test("an agent without operations gets a tool error through MCP", async () => {
  // A tool can't answer `extension_required`, which refuses the agent entirely (§6): a
  // tool that needs the Operations extension returns an ordinary tool error.
  const w = await world({ extensions: [] });
  const { token, reference } = await signedIn(w);
  const mcp = mcpClient(w, await mcpToken(w, token, reference, true));
  const answer = await mcp.callTool("exchange_jacket");
  assert.equal(answer.isError, true);
  assert.equal(answer.operation, undefined);
  assert.match(answer.text, /Operations extension/);
  assert.ok((await mcp.callTool("list_orders")).structuredContent);
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

test("an MCP 429 is rate_limited with its Retry-After, and says when to retry", async () => {
  // As the API and conversation clients do (PAP_DATALAYER release gates, decided 2026-10-14).
  const issued = { accessToken: { reveal: () => "sat_test" }, tokenType: "Bearer", expiresIn: 60, scopes: [], sessionId: "ses_1", signedIn: true };
  const refusals = [];
  const fetch = async (_url, init) => {
    const message = JSON.parse(init.body);
    if (message.id === undefined) return new Response(null, { status: 202 });
    if (message.method === "initialize") return Response.json({ jsonrpc: "2.0", id: message.id, result: {} });
    return refusals.shift();
  };
  const mcp = new McpClient({ token: issued, url: MCP, fetch });

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
  assert.equal(refused.code, "http_error");
  assert.equal(refused.statusCode, 503);
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
