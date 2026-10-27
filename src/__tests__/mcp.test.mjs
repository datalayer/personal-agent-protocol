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
  DpopProofProviders,
  approve,
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
  const who = { tenantId: TENANT, issuer: metadata.issuer };
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
    sessionKey: session.sessionKey,
    organization: { name: "Manzanita", domain: new URL(w.metadata.protected_resources[0]).hostname },
    protectedResources: w.metadata.protected_resources,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return { token: done.token, reference: done.accountTokenReference };
}

/**
 * A signed-in token for the MCP server (§4.3).
 *
 * A server that supports DPoP: the Account Token request, with `resource`, gives a DPoP
 * token. One that doesn't: the signed-in DPoP Session Token is exchanged for a Bearer one,
 * for that server alone.
 */
async function mcpToken(w, token, reference, dpop) {
  if (dpop) {
    const result = await w.accounts.refresh(reference, { context: w.context, sessionKey: token.sessionKey, resource: MCP });
    assert.equal(result.status, "signed_in");
    return result.token;
  }
  return exchanged(w, token);
}

function exchanged(w, token, resource = MCP) {
  return w.sessions.tokenForMcp({
    clientId: w.identity.clientId,
    issuer: w.metadata.issuer,
    tokenEndpoint: w.metadata.token_endpoint,
    tenantId: TENANT,
    sessionKey: token.sessionKey,
    subjectToken: token.accessToken,
    resource,
  });
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
    assert.equal(issued.accountToken, undefined);
    if (dpop) {
      assert.notEqual(w.host.tokens.get(reference).reveal(), before); // rotated, stored, never returned
    } else {
      // Token Exchange uses the Session Token: the Account Token is not touched (§4.3).
      assert.equal(w.host.tokens.get(reference).reveal(), before);
    }

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
    assert.equal((await refusal(mcp.callTool("list_orders"))).code, "insufficient_scope");
  });

  test(`a Session started for the MCP server gets its own token too (DPoP: ${dpop})`, async () => {
    // A Session can hold a token for each MCP server and one for its other APIs (§4.3).
    const w = await world({ config: { mcpDpop: dpop } });
    await w.sessions.start(w.request);
    // With DPoP, the request that starts a Session, for the MCP server alone.
    const forMcp = dpop
      ? await w.sessions.start({ ...w.request, resource: MCP })
      : await exchanged(w, await w.sessions.start(w.request));
    const own = await w.sessions.renew({ ...w.request, sessionKey: forMcp.sessionKey });
    assert.equal(own.sessionKey, forMcp.sessionKey);
    assert.equal(own.tokenType, "DPoP");
    const needsSignIn = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { ...w.who, token: own }));
    assert.equal(needsSignIn.code, "insufficient_scope");
    // The token for the MCP server still works there.
    const signedOut = await refusal(mcpClient(w, forMcp).callTool("list_orders"));
    assert.equal(signedOut.code, "insufficient_scope");
  });
}

test("the token type is chosen by the MCP server", async () => {
  // A DPoP server: a DPoP token from the request that renews the Session, with `resource`.
  // A server without DPoP: a Bearer token by Token Exchange alone. Each other way is
  // `invalid_target` (§4.3).
  for (const dpop of [true, false]) {
    const w = await world({ config: { mcpDpop: dpop } });
    const session = await w.sessions.start(w.request);
    const renew = (resource) => w.sessions.renew({ ...w.request, sessionKey: session.sessionKey, resource });
    const http = await refusal(renew("http://manzanita.example/mcp"));
    assert.equal(http.code, "invalid_url");
    const fragment = await refusal(renew(`${MCP}#tools`));
    assert.equal(fragment.code, "invalid_url");
    // Token Exchange is only for an MCP server without DPoP.
    const elsewhere = await refusal(exchanged(w, session, "https://manzanita.example/"));
    assert.equal(elsewhere.code, "invalid_target");
    let signedOut;
    if (dpop) {
      const wrong = await refusal(exchanged(w, session));
      assert.equal(wrong.code, "invalid_target");
      signedOut = await renew(MCP);
      assert.equal(signedOut.tokenType, "DPoP");
    } else {
      // Its tokens come from Token Exchange, never from another grant.
      const wrong = await refusal(renew(MCP));
      assert.equal(wrong.code, "invalid_target");
      signedOut = await exchanged(w, session);
      assert.equal(signedOut.tokenType, "Bearer");
    }
    assert.equal(signedOut.signedIn, false);
    assert.equal(signedOut.sessionKey, session.sessionKey);
    const refused = await refusal(mcpClient(w, signedOut).callTool("list_orders"));
    assert.ok(refused instanceof McpError);
    assert.equal(refused.code, "insufficient_scope");
    assert.equal(refused.statusCode, 403);
    assert.deepEqual(refused.details, { scope: "orders:read" });
    // The Session's own token is untouched by the request for the MCP server.
    const still = await refusal(new ApiClient({ transport: w.transport }).call("GET", ORDERS, { ...w.who, token: session }));
    assert.equal(still.code, "insufficient_scope");
  }
});

test("a DPoP MCP server retries once with its nonce", async () => {
  const w = await world({ config: { mcpDpop: true, dpopNonce: true } });
  const session = await w.sessions.start(w.request);
  const token = await w.sessions.renew({ ...w.request, sessionKey: session.sessionKey, resource: MCP });
  const tools = await mcpClient(w, token).listTools();
  assert.deepEqual(tools.map((tool) => tool.name), ["list_orders", "exchange_jacket"]);
});

test("a DPoP token for MCP needs the host's reactor and who", async () => {
  const w = await world();
  const session = await w.sessions.start(w.request);
  const token = await w.sessions.renew({ ...w.request, sessionKey: session.sessionKey, resource: MCP });
  assert.throws(() => new McpClient({ token, url: MCP, fetch: w.fetch }), (error) => error.code === "dpop_unavailable");
});

test("an Account Token request for a resource needs an HTTPS URL: nothing is sent for another", async () => {
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
  for (const resource of ["http://manzanita.example/mcp", "https://user:pw@manzanita.example/mcp", "not a url"]) {
    const error = await refusal(accounts.refresh(reference, { context: w.context, sessionKey: token.sessionKey, resource }));
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
  const issued = { accessToken: { reveal: () => "sat_test" }, tokenType: "Bearer", expiresIn: 60, scopes: [], sessionKey: "K".repeat(43), signedIn: true };
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
  const issued = { accessToken: { reveal: () => "sat_test" }, tokenType: "Bearer", expiresIn: 60, scopes: [], sessionKey: "K".repeat(43), signedIn: true };
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

const JOIN = "https://manzanita.example/poppy/browser-session";

/** Join the agent's browser to the Session (§5), then open `page` in it. */
async function join(w, sessionKey, page) {
  await new BrowserSessionClient({ reactor: w.host.reactor }).join({
    browserSessionEndpoint: w.company.document.web.browser_session_endpoint,
    tenantId: TENANT,
    issuer: w.metadata.issuer,
    sessionKey,
  });
  const joined = w.browser.page;
  await w.browser.get(page);
  return joined;
}

function setCookies(headers) {
  return typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [headers.get("set-cookie")].filter(Boolean);
}

async function joinForm(w) {
  const browser = new ControlledBrowser(w.fetch);
  const page = await browser.get(JOIN);
  return { browser, code: /name="code" value="([^"]+)"/.exec(page.text)[1] };
}

function provider(w) {
  return w.host.reactor.getContributions(DpopProofProviders)[0].value;
}

async function proof(w, sessionKey, code) {
  return (
    await provider(w).create({ method: "POST", url: JOIN, tenantId: TENANT, issuer: w.metadata.issuer, sessionKey, nonce: code })
  ).reveal();
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

  const joined = await join(w, token.sessionKey, pageUrl);
  const page = w.browser.page;
  assert.equal(page.status, 200);
  assert.equal(page.url, pageUrl);
  assert.ok(page.text.includes(operation.summary) && page.text.includes('data-state="proposed"'));
  assert.equal(joined.history[0].status, 303);
  assert.ok(w.browser.cookies.get("manzanita.example").get("__Host-poppy_session"));
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
  await join(w, token.sessionKey, operation.url);
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

test("the website follows the Session", async () => {
  const w = await world();
  const { token, reference } = await signedIn(w);
  const { operation } = await new ApiClient({ transport: w.transport }).call("POST", `${ORDERS}/ord_7Hk2/gift-wrap`, { ...w.who, token, body: {} });
  assert.ok(operation.url);
  await join(w, token.sessionKey, operation.url);
  assert.equal(w.browser.page.status, 200);

  // Signing out reaches the website on its next request: the account's operation is gone.
  await w.accounts.revoke(reference, { context: w.context });
  assert.equal((await w.browser.get(operation.url)).status, 404);

});

test("the join page is one-time, tied to its browser, and never framed", async () => {
  // Step 1 of §5: a form with a one-time code, a `__Host-` cookie that ties the code to
  // this browser, no caching, no framing, no opener.
  const w = await world();
  const page = await w.fetch(JOIN, { method: "GET" });
  assert.equal(page.status, 200);
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.equal(page.headers.get("content-security-policy"), "frame-ancestors 'none'");
  assert.equal(page.headers.get("cross-origin-opener-policy"), "same-origin");
  const cookie = page.headers.get("set-cookie");
  for (const part of ["__Host-poppy_join=", "Secure", "HttpOnly", "SameSite=Strict", "Max-Age=60"]) assert.ok(cookie.includes(part), part);
  const text = await page.text();
  const code = /name="code" value="([^"]+)"/.exec(text)[1];
  assert.ok(code.length >= 22 && text.includes('name="proof"'));
});

test("a join needs its own browser, its code once, and a live Session's key", async () => {
  // Step 3 of §5 and both attacks of §9.6: a code submitted from another browser, a code
  // used twice, a proof over another code, a key that names no Session.
  const w = await world();
  const session = await w.sessions.start(w.request);
  const joinedNone = (response) => !setCookies(response.headers).some((c) => c.startsWith("__Host-poppy_session="));

  let { browser, code } = await joinForm(w);
  const signed = await proof(w, session.sessionKey, code);
  // Another browser (no join cookie): an attacker's code can't make it join (§9.6).
  const stolen = await new ControlledBrowser(w.fetch).postForm(JOIN, { code, proof: signed });
  assert.ok(stolen.status === 400 && joinedNone(stolen));
  // The code was used by that first request, whatever the result: gone.
  assert.equal((await browser.postForm(JOIN, { code, proof: signed })).status, 400);

  ({ browser, code } = await joinForm(w));
  const other = await proof(w, session.sessionKey, `bc_${"x".repeat(22)}`);
  assert.equal((await browser.postForm(JOIN, { code, proof: other })).status, 400);

  ({ browser, code } = await joinForm(w));
  const unknown = await provider(w).newSessionKey({ tenantId: TENANT, issuer: w.metadata.issuer });
  // A key the company doesn't know is an error here, never a new Session.
  assert.equal((await browser.postForm(JOIN, { code, proof: await proof(w, unknown, code) })).status, 400);

  ({ browser, code } = await joinForm(w));
  const joined = await browser.postForm(JOIN, { code, proof: await proof(w, session.sessionKey, code) });
  assert.equal(joined.status, 303);
  const cookies = setCookies(joined.headers);
  assert.ok(cookies.some((c) => c.startsWith("__Host-poppy_session=") && c.includes("SameSite=Strict")));
  assert.ok(cookies.some((c) => c.startsWith("__Host-poppy_join=;") && c.includes("Max-Age=0")));
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
