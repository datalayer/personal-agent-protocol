/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What draft 0.3 adds, both sides, over HTTP in one process: the port of
// personal_agent_protocol/__tests__/test_draft_03.py.
//
// Sessions kept by `sid` (§5.2, §5.3, §5.5), sign-in as plain OAuth (§4.2, §4.3), scopes and
// their hints (§3.1, §4.7), excluded tasks and alternatives (§9.1, §9.2).
import assert from "node:assert/strict";
import test from "node:test";

import {
  DeviceSignInClient,
  PapSession,
  SessionClient,
  buildClientAssertionClaims,
  discoverCompany,
  effectiveChanges,
  excludedTasks,
  listsResource,
  offersDevice,
  offersDirect,
  parseAlternative,
  parseDiscoveryDocument,
  parseOAuthServerMetadata,
  sessionHeaders,
  usableReferences,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { RecordKinds } from "../../lib/server.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const ISSUER = "https://manzanita.example";
const TOKEN = "https://manzanita.example/oauth/token";
const FEEDBACK = "https://manzanita.example/poppy/feedback";

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
  const who = { clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: ISSUER, tenantId: TENANT };
  return { clock, fetch, identity, shop, host, sites, company, metadata: company.oauthMetadata, sessions, who };
}

/** One request straight to the company, so `invalid_session` starts no new Session. */
async function report(w, session) {
  const signed = await sessionHeaders(w.host.reactor, "POST", FEEDBACK, { session });
  return w.fetch(FEEDBACK, {
    method: "POST",
    headers: { ...signed, "Content-Type": "application/json" },
    body: JSON.stringify({ task: "Track a parcel", description: "No tracking anywhere." }),
  });
}

async function refusedWith(response, status, body) {
  assert.deepEqual([response.status, await response.json()], [status, body]);
}

function deviceBegin(w, device, scopes) {
  return device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes,
    tenantId: TENANT,
    organization: w.company.document.organization,
    protectedResources: w.metadata.protected_resources,
  });
}

/** Ada signs in with Device Sign-In: the token the polling agent gets. */
async function signedIn(w, scopes = ["orders:read", "orders:write"]) {
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await deviceBegin(w, device, scopes);
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  return device.poll(started.reference);
}

async function refusal(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  assert.fail("expected a refusal");
}

// Sessions -----------------------------------------------------------------------------------

test("a new sid starts a Session and the same sid continues it", async () => {
  const w = await world();
  const first = await w.sessions.start(w.who);
  const second = await w.sessions.start(w.who);
  // A Session is local: each has its own `sid`, and the company has heard of neither (§5.2).
  assert.notEqual(first.sid, second.sid);
  assert.deepEqual(w.shop.store.keys(RecordKinds.session), []);
  assert.equal((await report(w, first)).status, 202);
  assert.equal((await report(w, first)).status, 202);
  assert.equal(w.shop.store.keys(RecordKinds.session).length, 1);
  assert.equal((await report(w, second)).status, 202);
  assert.equal(w.shop.store.keys(RecordKinds.session).length, 2);
  // One delegated key per User ID signs them all: a key doesn't name a Session (§5.2).
  assert.equal(w.host.delegatedKeys.size, 1);
});

test("an ended Session's sid is refused, not a new Session", async () => {
  // A Company remembers the `sid`s of Sessions it ended, and may forget them (§5.5).
  const w = await world();
  const session = await w.sessions.start(w.who);
  assert.equal((await report(w, session)).status, 202);
  assert.equal(await w.shop.endSession(session.clientId, session.sid), true);
  assert.equal(await w.shop.endSession(session.clientId, session.sid), false);
  await refusedWith(await report(w, session), 400, { error: "invalid_session" });

  // A Session past the lifetime the company gives it has ended the same way.
  const lapsing = await w.sessions.start(w.who);
  assert.equal((await report(w, lapsing)).status, 202);
  const { config } = w.shop;
  w.clock.advance(config.sessionLifetimeSeconds);
  await refusedWith(await report(w, lapsing), 400, { error: "invalid_session" });

  // Once forgotten, the same `sid` starts a new Session (§5.5: a Company can forget).
  w.clock.advance(config.endedSessionMemorySeconds + 1);
  assert.equal((await report(w, lapsing)).status, 202);
});

/** The same `sid` with something changed: what the SDK would never send. */
const changed = (session, change) =>
  new PapSession({
    sid: session.sid,
    sub: session.sub,
    issuer: session.issuer,
    clientId: session.clientId,
    tenantId: session.tenantId,
    ...change,
  });

test("a Session keeps the Agent ID it started with", async () => {
  const w = await world();
  for (const other of ["agt_shopping", undefined]) {
    const session = await w.sessions.start({ ...w.who, agentId: "agt_travel" });
    assert.equal((await report(w, session)).status, 202);
    await refusedWith(await report(w, changed(session, other === undefined ? {} : { agentId: other })), 400, { error: "invalid_session" });
  }
});

test("a Session keeps the User ID it started with", async () => {
  const w = await world();
  const session = await w.sessions.start(w.who);
  assert.equal((await report(w, session)).status, 202);
  await refusedWith(await report(w, changed(session, { sub: "usr_somebody_else_000000" })), 400, { error: "invalid_session" });
});

test("an access token without the Session header is invalid_session", async () => {
  // A copied access token is useless without the agent's key (§5.3).
  const w = await world();
  const { token } = await signedIn(w);
  const bare = await w.fetch(FEEDBACK, {
    method: "POST",
    headers: { Authorization: `Bearer ${token.accessToken.reveal()}`, "Content-Type": "application/json" },
    body: JSON.stringify({ task: "x", description: "y" }),
  });
  await refusedWith(bare, 400, { error: "invalid_session" });
});

// Sign-in ------------------------------------------------------------------------------------

test("a device code works only for the agent it was issued to", async () => {
  const w = await world();
  const device = new DeviceSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  const started = await deviceBegin(w, device, ["orders:read"]);
  w.clock.advance(started.pollInterval);
  assert.equal((await device.poll(started.reference)).status, "pending");
  // Opening the link approves nothing by itself (§4.3): still pending.
  const page = await w.fetch(started.verificationUriComplete ?? started.verificationUri, { method: "GET" });
  assert.ok([200, 404].includes(page.status));
  w.clock.advance(started.pollInterval);
  assert.equal((await device.poll(started.reference)).status, "pending");

  // A poll from another agent, with its own good assertion: refused.
  const other = await agentIdentity({ domain: "other.example", name: "Other" });
  w.sites[other.domain] = other.documents;
  // The device code is host state, never the model's: read it where the host keeps it.
  const code = [...w.host.state.values()].find((value) => value?.deviceCode !== undefined).deviceCode.reveal();
  const assertion = await other.signer.sign(
    { ...buildClientAssertionClaims({ clientId: other.clientId, issuer: ISSUER, now: w.clock.now() }) },
    { purpose: "client_assertion" },
  );
  w.clock.advance(started.pollInterval);
  const stolen = await w.fetch(TOKEN, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: code,
      client_id: other.clientId,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      client_assertion: assertion.reveal(),
    }).toString(),
  });
  assert.equal(stolen.status, 400);
  assert.equal((await stolen.json()).error, "invalid_grant");
});

test("an authorization request needs PKCE", async () => {
  const w = await world();
  const base =
    "https://manzanita.example/oauth/authorize?response_type=code" +
    `&client_id=${w.identity.clientId}&scope=orders:read&state=s1` +
    "&redirect_uri=https://atlas.example/oauth/callback";
  // Without an S256 code challenge the request is refused back to the agent (§4.2).
  const refused = await w.fetch(base, { method: "GET" });
  assert.ok([302, 303].includes(refused.status));
  assert.equal(new URL(refused.headers.get("location")).searchParams.get("error"), "invalid_request");
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
  assert.throws(() => parseOAuthServerMetadata({ ...base, grant_types_supported: ["authorization_code"] }), /refresh_token/);
  assert.throws(() => parseOAuthServerMetadata(base), /grant_types_supported/);
  assert.throws(
    () => parseOAuthServerMetadata({ ...base, grant_types_supported: ["refresh_token", "authorization_code"] }),
    /authorization_endpoint/,
  );
  const plain = parseOAuthServerMetadata({ ...base, grant_types_supported: ["refresh_token"] });
  // No sign-in grant: signed-out Sessions only (§5.4).
  assert.deepEqual([offersDirect(plain), offersDevice(plain)], [false, false]);
  assert.ok(listsResource(plain, "EXAMPLE.com"));
  const slashed = parseOAuthServerMetadata({
    ...base,
    grant_types_supported: ["refresh_token"],
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
  // Later versions may add values: until then, the most careful reading (§4.7).
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
  // Only the company's own listed APIs, and only types the agent knows (§9.2).
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
  const answers = [];
  const handle = w.shop.handle.bind(w.shop);
  w.shop.handle = async (request) => {
    const answer = await handle(request);
    if (new URL(request.url).pathname === "/oauth/token") answers.push(answer.body);
    return answer;
  };
  const done = await signedIn(w);
  // Ada approved both scopes asked for: the response left `scope` out, and the SDK read it
  // as exactly those (§4.7, RFC 6749 §5.1).
  assert.equal("scope" in answers.at(-1), false);
  assert.deepEqual(new Set(done.token.scopes), new Set(["orders:read", "orders:write"]));
  assert.equal(done.token.tokenType, "Bearer");
  assert.equal(done.token.expiresIn, 3600);
  // The refresh token stays behind its reference, in the host's store.
  assert.ok(done.refreshTokenReference);
  assert.ok(w.host.tokens.has(done.refreshTokenReference));
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
