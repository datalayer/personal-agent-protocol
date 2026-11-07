/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The UCP extension, version 1, both sides in one process: Manzanita is the test shop. The port of
// personal_agent_protocol/__tests__/test_ucp.py.
import assert from "node:assert/strict";
import test from "node:test";

import {
  DeviceSignInClient,
  SessionClient,
  SessionFetchClient,
  UCP_AGENT_HEADER,
  UcpClient,
  discoverCompany,
  fetchUcpProfile,
  negotiateExtensions,
  parseExtensionsHeader,
  parseUcpProfile,
  sessionHeaders,
  speaksUcp,
  ucpAgentHeader,
  ucpEndpoint,
  ucpIdentityLinkingScopes,
  ucpOffers,
  ucpProfileUrl,
  ucpScopes,
} from "../../lib/index.js";
import { CompanyConfig } from "../../lib/server.js";
import { CONFIG_OPTIONS, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PLATFORM = "https://atlas.example/ucp/profile.json";

async function world(config) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop } = manzanita({ fetch, clock, ...(config ? { config } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  let users = 0;
  const start = () =>
    sessions.start({
      clientId: identity.clientId,
      pairwiseUserId: `usr_ucp_user_${(users += 1)}_000000000000`,
      issuer: company.oauthMetadata?.issuer ?? `https://${company.document.organization.domain}`,
      tenantId: TENANT,
      company,
    });
  const transport = new SessionFetchClient({ reactor: host.reactor, fetch });
  return { clock, fetch, identity, shop, host, company, start, transport };
}

/** Ada signs Atlas in with Device Sign-In for `scopes`: the access token. */
async function signedIn(w, scopes) {
  const metadata = w.company.oauthMetadata;
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    issuer: metadata.issuer,
    clientId: w.identity.clientId,
    scopes,
    tenantId: TENANT,
    organization: w.company.document.organization,
    protectedResources: metadata.protected_resources,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return done.token;
}

async function client(w) {
  const profile = await fetchUcpProfile(w.company, { fetch: w.fetch });
  const endpoint = ucpEndpoint(profile);
  assert.equal(endpoint, "https://manzanita.example/ucp");
  return { profile, endpoint, ucp: new UcpClient({ transport: w.transport, platformProfile: PLATFORM, profile }) };
}

test("a company that speaks UCP lists it and serves its profile on its domain", async () => {
  const w = await world();
  assert.ok(speaksUcp(w.company.document));
  assert.equal(w.company.document.extensions.ucp[0].version, "1");
  assert.equal(ucpProfileUrl(w.company), "https://manzanita.example/.well-known/ucp");
  const { profile } = await client(w);
  assert.ok(ucpOffers(profile, "dev.ucp.shopping.catalog.search") && ucpOffers(profile, "dev.ucp.shopping.order"));
  assert.deepEqual(ucpIdentityLinkingScopes(profile), ["orders:read"]);
  for (const scope of ucpIdentityLinkingScopes(profile)) assert.ok(w.company.oauthMetadata.scopes_supported.includes(scope));
  assert.ok(w.shop.oauthMetadata().token_endpoint_auth_methods_supported.includes("private_key_jwt"));
  assert.deepEqual(ucpScopes(profile, ["orders:read"]), []);
  const plain = await world(new CompanyConfig({ ...CONFIG_OPTIONS, ucp: false }));
  assert.ok(!speaksUcp(plain.company.document));
  await assert.rejects(fetchUcpProfile(plain.company, { fetch: plain.fetch }), (error) => error.code === "ucp_not_offered");
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, direct: false }), RangeError);
});

test("a UCP profile is never fetched through a redirect or used malformed", async () => {
  const w = await world();
  const answers = {
    redirect_refused: () => new Response(null, { status: 302, headers: { location: "https://cdn.example.net/ucp" } }),
    invalid_ucp_profile: () => new Response(JSON.stringify({ ucp: { services: {} } }), { status: 200 }),
    ucp_profile_unavailable: () => new Response(JSON.stringify({ error: "not_found" }), { status: 404 }),
  };
  for (const [code, answer] of Object.entries(answers)) {
    await assert.rejects(fetchUcpProfile(w.company, { fetch: async () => answer() }), (error) => error.code === code);
  }
});

test("the UCP-Agent header names one HTTPS platform profile", () => {
  assert.equal(ucpAgentHeader(PLATFORM), `profile="${PLATFORM}"`);
  for (const bad of ["http://atlas.example/p", 'https://atlas.example/"p"', "https://a.example/ p"]) {
    assert.throws(() => ucpAgentHeader(bad), RangeError);
  }
  const profile = parseUcpProfile({ ucp: { version: "2026-04-08", services: { "dev.ucp.shopping": [{ transport: "mcp", endpoint: "https://x" }] } } });
  assert.equal(ucpEndpoint(profile), undefined);
  assert.deepEqual(ucpIdentityLinkingScopes(profile), []);
});

test("a signed-out UCP request carries the Session header and the platform profile", async () => {
  const w = await world();
  const session = await w.start();
  const { ucp, endpoint } = await client(w);
  const sent = [];
  const spying = new SessionFetchClient({
    reactor: w.host.reactor,
    fetch: async (url, init) => {
      sent.push(new Headers(init.headers));
      return w.fetch(url, init);
    },
  });
  const spy = new UcpClient({ transport: spying, platformProfile: PLATFORM, profile: ucp.profile });
  const found = await spy.call("POST", `${endpoint}/catalog/search`, { session, body: { query: "stormline" } });
  assert.deepEqual(found.products.map((product) => product.id), ["stormline-insulated-m", "stormline-insulated-l"]);
  assert.equal(sent.at(-1).get(UCP_AGENT_HEADER), `profile="${PLATFORM}"`);
  assert.ok(sent.at(-1).has("poppy-session") && !sent.at(-1).has("authorization"));
  assert.ok(await w.shop.endSession(session.clientId, session.sid));
});

test("UCP without this extension, and its refusals", async () => {
  const w = await world();
  const url = "https://manzanita.example/ucp/catalog/search";
  const post = (headers, body = {}) =>
    w.fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
  const agent = { [UCP_AGENT_HEADER]: ucpAgentHeader(PLATFORM) };
  const independent = await post(agent, { query: "shell" });
  assert.equal(independent.status, 200);
  assert.deepEqual((await independent.json()).products.map((p) => p.id), ["trailhead-shell-m"]);
  const anonymous = await post({});
  assert.deepEqual([anonymous.status, (await anonymous.json()).code], [400, "invalid_profile_url"]);
  const copied = await post({ ...agent, Authorization: "Bearer at_copied" });
  assert.deepEqual([copied.status, (await copied.json()).code], [401, "invalid_token"]);
});

test("orders need identity linking through this protocol's sign-in", async () => {
  const w = await world();
  const session = await w.start();
  const { ucp, endpoint } = await client(w);
  await assert.rejects(
    ucp.call("GET", `${endpoint}/orders`, { session }),
    (error) => error.code === "identity_required" && error.details.scopes.join() === "orders:read",
  );
  const narrow = await signedIn(w, ["orders:write"]);
  await assert.rejects(
    ucp.call("GET", `${endpoint}/orders`, { session, token: narrow }),
    (error) => error.code === "insufficient_scope" && error.details.scope === "orders:read",
  );
  const token = await signedIn(w, ["orders:read"]);
  assert.equal(token.tokenType, "Bearer");
  const orders = await ucp.call("GET", `${endpoint}/orders`, { session, token });
  assert.ok(orders.orders[0].order_id);
});

test("Session errors at UCP endpoints are UCP responses", async () => {
  const w = await world();
  const session = await w.start();
  const { ucp, endpoint } = await client(w);
  await ucp.call("POST", `${endpoint}/catalog/search`, { session, body: {} });
  const first = session.sid;
  assert.ok(await w.shop.endSession(session.clientId, session.sid));
  await ucp.call("POST", `${endpoint}/catalog/search`, { session, body: {} });
  assert.notEqual(session.sid, first);
  const headers = await sessionHeaders(w.host.reactor, "POST", "https://elsewhere.example/", { session });
  const refused = await w.fetch(`${endpoint}/catalog/search`, {
    method: "POST",
    headers: { ...headers, [UCP_AGENT_HEADER]: ucpAgentHeader(PLATFORM), "Content-Type": "application/json" },
    body: "{}",
  });
  assert.deepEqual([refused.status, (await refused.json()).code], [400, "invalid_session"]);
});

test("a personal agent declares ucp in Poppy-Extensions", async () => {
  const w = await world();
  const declared = negotiateExtensions(w.company.document.extensions, { ucp: "1", operations: "2" });
  assert.equal(declared.ucp, "1");
  const session = await w.start();
  const headers = await sessionHeaders(w.host.reactor, "GET", "https://manzanita.example/", { session: { ...session, extensions: declared, protocolVersion: session.protocolVersion } });
  assert.equal(parseExtensionsHeader(headers["Poppy-Extensions"]).ucp, "1");
});
