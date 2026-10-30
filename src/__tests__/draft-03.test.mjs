/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What draft 0.3 adds, both sides, over HTTP in one process: the port of
// personal_agent_protocol/__tests__/test_draft_03.py.
//
// Session Keys (§4.2, §4.3), codes bound to them (§4.5, §4.6), scopes and their hints
// (§3.1, §4.4), excluded tasks and alternatives (§8), and the sign-in rules that changed.
import assert from "node:assert/strict";
import test from "node:test";

import {
  DeviceSignInClient,
  DirectSignInClient,
  DpopProofProviders,
  SessionClient,
  SessionError,
  Signers,
  buildClientAssertionClaims,
  discoverCompany,
  effectiveChanges,
  excludedTasks,
  firstContribution,
  listsResource,
  offersDevice,
  offersDirect,
  offersTokenExchange,
  parseAlternative,
  parseDiscoveryDocument,
  parseOAuthServerMetadata,
  usableReferences,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const ISSUER = "https://manzanita.example";
const TOKEN = "https://manzanita.example/oauth/token";
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";

async function world() {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop } = manzanita({ fetch, clock });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const who = { clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: ISSUER, tokenEndpoint: TOKEN, tenantId: TENANT };
  return { clock, fetch, identity, shop, host, company, metadata: company.oauthMetadata, sessions, who };
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected a refusal");
}

// Session Keys -----------------------------------------------------------------------------

test("a new key starts a Session and the same key renews it", async () => {
  const w = await world();
  const first = await w.sessions.start(w.who);
  const second = await w.sessions.start(w.who);
  // Each Session has its own key, which names it (§4.3).
  assert.notEqual(first.sessionKey, second.sessionKey);
  const renewed = await w.sessions.renew({ ...w.who, sessionKey: first.sessionKey });
  assert.equal(renewed.sessionKey, first.sessionKey);
  assert.equal(renewed.signedIn, false);
});

test("an ended Session's key is refused, not a new Session", async () => {
  // A Company remembers the keys of Sessions it ended (§4.2, SHOULD).
  const w = await world();
  const session = await w.sessions.start(w.who);
  // Long past the end of anything that could renew it.
  const config = w.shop.config;
  w.clock.advance(config.sessionLifetimeSeconds + config.accountTokenLifetimeSeconds + 24 * 3600);
  const ended = await refusal(w.sessions.renew({ ...w.who, sessionKey: session.sessionKey }));
  assert.ok(ended instanceof SessionError);
  assert.equal(ended.code, "invalid_grant");
  // The agent never uses that key again: it is gone from its custody (§4.2).
  assert.equal(await w.host.sessionKeys.get({ tenantId: TENANT, issuer: ISSUER, thumbprint: session.sessionKey }), undefined);
});

test("a Session keeps the Agent ID it started with", async () => {
  const w = await world();
  for (const other of ["agt_shopping", undefined]) {
    const session = await w.sessions.start({ ...w.who, agentId: "agt_travel" });
    await w.sessions.renew({ ...w.who, sessionKey: session.sessionKey, agentId: "agt_travel" });
    const changed = await refusal(
      w.sessions.renew({ ...w.who, sessionKey: session.sessionKey, ...(other === undefined ? {} : { agentId: other }) }),
    );
    assert.equal(changed.code, "invalid_grant");
  }
});

test("a device code is bound to the key of its first poll", async () => {
  const w = await world();
  const session = await w.sessions.start(w.who);
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read"],
    tenantId: TENANT,
    sessionKey: session.sessionKey,
    organization: w.company.document.organization,
    protectedResources: w.metadata.protected_resources,
  });
  w.clock.advance(started.pollInterval);
  assert.equal((await device.poll(started.reference)).status, "pending");
  // Opening the link approves nothing by itself (§4.6): still pending.
  const page = await w.fetch(started.verificationUriComplete ?? started.verificationUri, { method: "GET" });
  assert.ok([200, 404].includes(page.status));
  w.clock.advance(started.pollInterval);
  assert.equal((await device.poll(started.reference)).status, "pending");

  // A poll with another key: refused, the code being bound to the first poll's.
  const other = await w.sessions.start(w.who);
  // The device code is host state, never the model's: read it where the host keeps it.
  const code = [...w.host.state.values()].find((value) => value?.deviceCode !== undefined).deviceCode.reveal();
  const provider = firstContribution(w.host.reactor, DpopProofProviders, "DPoP");
  const proof = await provider.create({ method: "POST", url: TOKEN, tenantId: TENANT, issuer: ISSUER, sessionKey: other.sessionKey });
  const signer = firstContribution(w.host.reactor, Signers, "signer");
  const assertion = await signer.sign(
    { ...buildClientAssertionClaims({ clientId: w.identity.clientId, issuer: ISSUER, now: w.clock.now() }) },
    { purpose: "client_assertion" },
  );
  w.clock.advance(started.pollInterval);
  const stolen = await w.fetch(TOKEN, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded", DPoP: proof.reveal() },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: code,
      client_id: w.identity.clientId,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion.reveal(),
    }).toString(),
  });
  assert.equal(stolen.status, 400);
  assert.equal((await stolen.json()).error, "invalid_grant");
});

test("an authorization code needs dpop_jkt and the key it names", async () => {
  const w = await world();
  const session = await w.sessions.start(w.who);
  const base =
    "https://manzanita.example/oauth/authorize?response_type=code" +
    `&client_id=${w.identity.clientId}&scope=orders:read&state=s1` +
    "&code_challenge=c&code_challenge_method=S256" +
    "&redirect_uri=https://atlas.example/oauth/callback";
  // Without the Session Key's thumbprint the request is refused back to the agent (§4.5).
  const refused = await w.fetch(base, { method: "GET" });
  assert.ok([302, 303].includes(refused.status));
  assert.equal(new URL(refused.headers.get("location")).searchParams.get("error"), "invalid_request");

  // With it, the code is redeemed only with a proof from that key: another Session's
  // proof is refused, and the code is gone (§4.5, RFC 9449 §10).
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read"],
    tenantId: TENANT,
    sessionKey: session.sessionKey,
  });
  assert.equal(new URL(w.host.browser.urls.at(-1)).searchParams.get("dpop_jkt"), session.sessionKey);
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  const other = await w.sessions.start(w.who);
  const another = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await another.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read"],
    tenantId: TENANT,
    sessionKey: other.sessionKey,
  });
  // The first request's code, presented with the second Session's state and key.
  const otherState = new URL(w.host.browser.urls.at(-1)).searchParams.get("state");
  const swapped = new URL(callbackUrl);
  swapped.searchParams.set("state", otherState);
  const wrongKey = await refusal(another.complete({ callbackUrl: swapped.toString() }));
  assert.equal(wrongKey.code, "invalid_grant");
});

// Discovery and scopes -----------------------------------------------------------------------

test("the issuer lists the grants and scopes it offers", () => {
  const base = {
    issuer: "https://auth.example.com",
    token_endpoint: "https://auth.example.com/oauth/token",
    revocation_endpoint: "https://auth.example.com/oauth/revoke",
    protected_resources: ["https://example.com"],
  };
  // grant_types_supported is required, with the refresh grant (§3.2).
  assert.throws(() => parseOAuthServerMetadata({ ...base, grant_types_supported: [JWT_BEARER] }), /refresh_token/);
  assert.throws(() => parseOAuthServerMetadata(base), /grant_types_supported/);
  assert.throws(
    () => parseOAuthServerMetadata({ ...base, grant_types_supported: [JWT_BEARER, "refresh_token", "authorization_code"] }),
    /authorization_endpoint/,
  );
  const plain = parseOAuthServerMetadata({ ...base, grant_types_supported: [JWT_BEARER, "refresh_token"] });
  // No sign-in grant: signed-out Sessions only (§4.4).
  assert.deepEqual([offersDirect(plain), offersDevice(plain), offersTokenExchange(plain)], [false, false, false]);
  assert.ok(listsResource(plain, "EXAMPLE.com"));
  const slashed = parseOAuthServerMetadata({
    ...base,
    grant_types_supported: [JWT_BEARER, "refresh_token"],
    protected_resources: ["https://example.com/"],
  });
  assert.equal(listsResource(slashed, "example.com"), false);
});

test("scopes are the company's and described; poppy: is no longer reserved", () => {
  const document = {
    protocol_version: "0.3",
    organization: { name: "Example", domain: "example.com" },
    auth: { issuer: "https://auth.example.com", scopes: { "poppy:read": "Read" } },
    web: {},
  };
  assert.equal(parseDiscoveryDocument(document).auth.scopes["poppy:read"], "Read");
  assert.throws(() => parseDiscoveryDocument({ ...document, auth: { issuer: "https://auth.example.com", scopes: { a: "" } } }));
});

test("an unknown changes hint is read as irreversible", () => {
  // Later versions may add values: until then, the most careful reading (§4.4).
  assert.equal(effectiveChanges({ changes: "permanent", personal_data: false }), "irreversible");
  assert.equal(effectiveChanges({ changes: "none", personal_data: true }), "none");
  const document = (hint) => ({
    protocol_version: "0.3",
    organization: { name: "Example", domain: "example.com" },
    auth: { issuer: "https://auth.example.com", scopes: { a: "A" }, scope_hints: { a: hint } },
    web: {},
  });
  // Both fields, always.
  assert.throws(() => parseDiscoveryDocument(document({ changes: "none" })));
  assert.deepEqual(parseDiscoveryDocument(document({ changes: "reversible", personal_data: false })).auth.scope_hints.a, {
    changes: "reversible",
    personal_data: false,
  });
});

test("the excluded tasks are read and their alternatives filtered", async () => {
  const w = await world();
  assert.equal(w.company.document.excluded_tasks.url, "https://manzanita.example/poppy/excluded-tasks.json");
  const excluded = await excludedTasks(w.company, { reactor: w.host.reactor });
  assert.deepEqual(excluded.tasks.map((task) => task.task), ["Change the size of an item after it has shipped"]);
  const alternative = parseAlternative({
    instructions: "Use the API.",
    references: [
      { type: "openapi", url: "https://manzanita.example/api/openapi.json", operation_id: "list" },
      { type: "openapi", url: "https://other.example/openapi.json", operation_id: "x" },
      { type: "app", url: "https://manzanita.example/app" },
      { type: "web", url: "https://manzanita.example/help" },
    ],
  });
  // Only the company's own listed APIs, and only types the agent knows (§8.2).
  assert.deepEqual(
    usableReferences(alternative, w.company.document).map((reference) => [reference.type, reference.url]),
    [
      ["openapi", "https://manzanita.example/api/openapi.json"],
      ["web", "https://manzanita.example/help"],
    ],
  );
  assert.throws(() => parseAlternative({}), (error) => error.code === "invalid_alternative");
  assert.throws(() => parseAlternative({ references: [{ type: "mcp", url: "https://manzanita.example/mcp" }] }));
});

test("a signed-in token response leaves out scope only when exact", async () => {
  const w = await world();
  const session = await w.sessions.start(w.who);
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const answers = [];
  const handle = w.shop.handle.bind(w.shop);
  w.shop.handle = async (request) => {
    const answer = await handle(request);
    if (new URL(request.url).pathname === "/oauth/token") answers.push(answer.body);
    return answer;
  };
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    sessionKey: session.sessionKey,
    organization: w.company.document.organization,
    protectedResources: w.metadata.protected_resources,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  // Ada approved both scopes asked for: the response left `scope` out, and the SDK read it
  // as exactly those (§4.4, RFC 6749 §5.1).
  assert.equal("scope" in answers.at(-1), false);
  assert.equal(done.token.signedIn, true);
  assert.deepEqual(new Set(done.token.scopes), new Set(["orders:read", "orders:write"]));
  // The Account Token's lifetime is sent, so expired tells from revoked (guides).
  assert.equal(done.token.accountTokenExpiresIn, 90 * 24 * 3600);
});

test("a discovery document off the well-known path is refused", async () => {
  const fetch = async (input) => {
    const url = new URL(String(input));
    if (url.pathname === "/.well-known/poppy.json") {
      return new Response(null, { status: 302, headers: { location: "https://example.com/uploads/p.json" } });
    }
    return Response.json({});
  };
  const error = await refusal(discoverCompany("example.com", { fetch }));
  assert.equal(error.code, "invalid_discovery_location");
});
