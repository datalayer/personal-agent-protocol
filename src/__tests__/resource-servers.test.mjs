/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// A service of the company at a URL of its own: listed, issued for, verified (§4.5, §7).
import assert from "node:assert/strict";
import test from "node:test";

import {
  DeviceSignInClient,
  RefreshTokenClient,
  SessionClient,
  discoverCompany,
  firstContribution,
  negotiateExtensions,
  parseOAuthServerMetadata,
  parseProtectedResourceMetadata,
} from "../../lib/index.js";
// The helper discovery and `fetchMcpServerMetadata` read the metadata at.
import { protectedResourceMetadataUrl } from "../../lib/models.js";
import { ClientPolicies, CompanyConfig, resourceMetadataUrl } from "../../lib/server.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const MCP = "https://manzanita.example/mcp";
/** The company's MCP server on a host of its own. */
const ELSEWHERE = "https://mcp.manzanita.example/mcp";

/** Ada signed in at Manzanita by Device Sign-In, the company configured with `config`. */
async function signedInWorld(config) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop } = manzanita({ fetch, clock, ...(config === undefined ? {} : { config }) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const reactor = host.reactor;
  const company = await discoverCompany("manzanita.example", { reactor });
  const metadata = company.oauthMetadata;
  await new SessionClient({ reactor, fetch }).start({
    clientId: identity.clientId,
    pairwiseUserId: PAIRWISE,
    issuer: metadata.issuer,
    tenantId: TENANT,
    extensions: negotiateExtensions(company.document.extensions, identity.supportedExtensions),
  });
  const device = new DeviceSignInClient({ reactor, fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    organization: company.document.organization,
  });
  await shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  const context = {
    tokenEndpoint: metadata.token_endpoint,
    revocationEndpoint: metadata.revocation_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    tenantId: TENANT,
  };
  const accounts = new RefreshTokenClient({ reactor, fetch });
  const tokenFor = (resource) =>
    accounts.tokenForMcp(done.refreshTokenReference, { context, server: parseProtectedResourceMetadata({ resource }) });
  return { clock, shop, identity, metadata, token: done.token, tokenFor };
}

test("without any, the issuer lists and issues as before", async () => {
  const w = await signedInWorld();
  assert.deepEqual(w.shop.config.resourceServers, []);
  assert.ok(!w.metadata.protected_resources.includes(ELSEWHERE));
  const refused = await w.tokenFor(ELSEWHERE).catch((error) => error);
  assert.equal(refused.code, "invalid_target");
});

test("the issuer lists it and issues a Bearer token for it, which only it takes", async () => {
  // §3.2: `protected_resources` MAY list the company's MCP servers. §4.5: a token request names
  // one `resource` and gets a token for that service; §7: the token's `resource` is the MCP
  // server's `url`, and the company accepts it only there.
  const w = await signedInWorld({ resourceServers: [ELSEWHERE] });
  const listed = w.metadata.protected_resources;
  assert.equal(listed[0], "https://manzanita.example");
  assert.ok(listed.includes(ELSEWHERE) && listed.includes(MCP));

  const { token } = await w.tokenFor(ELSEWHERE);
  assert.deepEqual([token.resource, token.tokenType], [ELSEWHERE, "Bearer"]);
  const issued = await w.shop.accessTokenFor(token.accessToken.reveal(), ELSEWHERE);
  assert.deepEqual([issued.accountId, issued.clientId], ["acct_ada", w.identity.clientId]);
  assert.deepEqual([...issued.scopes].sort(), ["orders:read", "orders:write"]);

  assert.equal(await w.shop.accessTokenFor(w.token.accessToken.reveal(), ELSEWHERE), undefined);
  const own = (await w.tokenFor(MCP)).token;
  assert.equal(await w.shop.accessTokenFor(own.accessToken.reveal(), ELSEWHERE), undefined);
  assert.equal(await w.shop.accessTokenFor("invented", ELSEWHERE), undefined);
  await assert.rejects(w.shop.accessTokenFor(token.accessToken.reveal(), "https://other.example/mcp"), RangeError);

  // It stops working there when it expires.
  w.clock.advance(w.shop.config.accessTokenLifetimeSeconds + 1);
  assert.equal(await w.shop.accessTokenFor(token.accessToken.reveal(), ELSEWHERE), undefined);
});

test("a blocked agent's token stops working there at once", async () => {
  // The client policy is asked when the token is presented, not only when it was issued: an
  // agent the company blocks, or a service it leaves out for that agent (§4.5), and its
  // unexpired token is refused.
  const w = await signedInWorld({ resourceServers: [ELSEWHERE] });
  const token = (await w.tokenFor(ELSEWHERE)).token.accessToken.reveal();
  assert.ok(await w.shop.accessTokenFor(token, ELSEWHERE));
  const policy = firstContribution(w.shop.reactor, ClientPolicies, "policy");
  policy.allowsResource = async (_clientId, resource) => resource !== ELSEWHERE;
  assert.equal(await w.shop.accessTokenFor(token, ELSEWHERE), undefined);
  delete policy.allowsResource;
  assert.ok(await w.shop.accessTokenFor(token, ELSEWHERE));
  policy.allows = async () => false;
  assert.equal(await w.shop.accessTokenFor(token, ELSEWHERE), undefined);
});

test("it gets Bearer tokens from an issuer that binds its own", async () => {
  // §7: a company whose MCP server doesn't accept DPoP returns Bearer tokens for it.
  const w = await signedInWorld({ resourceServers: [ELSEWHERE], dpopBinding: "optional" });
  assert.equal((await w.tokenFor(ELSEWHERE)).token.tokenType, "Bearer");
});

test("its metadata is published where discovery reads it", () => {
  // RFC 9728 §3.1, and one implementation: what a service publishes at is what a Personal Agent
  // fetches (`fetchMcpServerMetadata`), a trailing slash included.
  for (const [resource, published] of [
    [ELSEWHERE, "https://mcp.manzanita.example/.well-known/oauth-protected-resource/mcp"],
    ["https://mcp.manzanita.example/mcp/", "https://mcp.manzanita.example/.well-known/oauth-protected-resource/mcp"],
    ["https://mcp.manzanita.example/", "https://mcp.manzanita.example/.well-known/oauth-protected-resource"],
    ["https://mcp.manzanita.example", "https://mcp.manzanita.example/.well-known/oauth-protected-resource"],
    ["https://api.manzanita.example/v2/mcp", "https://api.manzanita.example/.well-known/oauth-protected-resource/v2/mcp"],
  ]) {
    assert.equal(resourceMetadataUrl(resource), published);
    assert.equal(resourceMetadataUrl(resource), protectedResourceMetadataUrl(resource));
  }
});

const BASE = { name: "Shop", domain: "shop.example", scopes: ["orders:read"], agentDescription: "Orders", scopeDescriptions: { "orders:read": "Read orders" }, operations: false };
const ACCEPTED = [
  ELSEWHERE,
  "https://mcp.shop.example:8443/mcp",
  "https://xn--mnchen-3ya.example/mcp",
  "https://api.shop.example/v2/mcp",
  "https://mcp.shop.example/mcp/",
];

test("every accepted one reads back through the metadata parser", async () => {
  // Each is published in `protected_resources`: one entry a Personal Agent's parser refuses
  // would fail discovery for the whole company.
  const w = await signedInWorld({ resourceServers: ACCEPTED });
  const parsed = parseOAuthServerMetadata(w.shop.oauthMetadata());
  for (const resource of ACCEPTED) assert.ok(parsed.protected_resources.includes(resource), resource);
  assert.deepEqual(new CompanyConfig({ ...BASE, resourceServers: ACCEPTED }).resourceServers, ACCEPTED);
});

test("anything else is refused when the company is configured", () => {
  for (const server of [
    "http://mcp.shop.example/mcp",
    "https://user:pass@mcp.shop.example/mcp",
    "https://user@mcp.shop.example/mcp",
    "https:///mcp",
    "https://",
    "https://not a host/mcp",
    "https://mcp.shop.example:port/mcp",
    "https://mcp.shop.example:65536/mcp",
    "https://mcp.shop.example:99999/mcp",
    "https://münchen.example/mcp",
    "https://MCP.shop.example/mcp",
    "https://mcp.shop.example/mcp?x=1",
    "https://mcp.shop.example/mcp?",
    "https://mcp.shop.example/mcp#x",
    "https://[::1/mcp",
    "mcp.shop.example/mcp",
    "https://shop.example",
    "https://shop.example/mcp",
  ]) {
    assert.throws(() => new CompanyConfig({ ...BASE, resourceServers: [server] }), RangeError, server);
  }
  assert.throws(() => new CompanyConfig({ ...BASE, resourceServers: [ELSEWHERE, ELSEWHERE] }), RangeError);
  assert.throws(() => new CompanyConfig({ ...BASE, oauth: false, scopes: [], scopeDescriptions: {}, device: false, direct: false, resourceServers: [ELSEWHERE] }), RangeError);
});
