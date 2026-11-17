/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Version 1.0 as published (upstream 8c02b42, frozen 2026-11-14): what changed after the draft
// as of c71f515, both sides, in one process; the port of
// personal_agent_protocol/__tests__/test_published_10.py.
//
// Conversation protocol descriptions, Pushed Authorization Requests, minor versions, PS384,
// consent for scopes granted before, the same DPoP key at refresh, UCP scope requests, ports in
// `organization.domain`, client assertion lifetimes, one sign-in for every resource, clearing
// context, room to extend conversations, what `working` means, unknown sign-in errors, and the
// Mediated Sign-In retirement date. 0.4 as published is unchanged.
import assert from "node:assert/strict";
import { constants, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";

import { exportJWK, generateKeyPair } from "jose";

import {
  AuthorizationStateStores,
  AuthorizationError,
  ConversationClient,
  ConversationError,
  DirectSignInClient,
  DeviceSignInClient,
  DpopProvers,
  KNOWN_CONVERSATION_ERRORS,
  MEDIATED_RETIREMENT_DATE,
  PROMPT_CONSENT,
  PapSession,
  ServiceTokens,
  SessionClient,
  UCP_IDENTITY_LINKING,
  buildClientAssertionClaims,
  buildDirectSignInRequest,
  clearsContext,
  delegationClaims,
  discoverCompany,
  effectiveContext,
  fetchMcpServerMetadata,
  firstContribution,
  knownConversationError,
  pageCarriesSession,
  parseConversationEvent,
  parseDiscoveryDocument,
  parseMessage,
  parseOAuthServerMetadata,
  signInScopes,
  splitDomain,
  ucpScopes,
  urlDomain,
  listsResource,
  verificationHostAllowed,
} from "../../lib/index.js";
import {
  ClientPolicies,
  CompanyAgents,
  CompanyConfig,
  JoseSigner,
  MemoryReplayCache,
  RSA_KEY_BITS,
  verifyAssertion,
  verifyDelegation,
} from "../../lib/server.js";
import { CONFIG, CONFIG_OPTIONS, manzanita } from "../../lib/demo/manzanita.js";
import { Context, identityFrom } from "./support/conformance.mjs";
import { SHOP, TENANT, mockTransport, rejection, shopWorld, signedIn } from "./support/shop.mjs";
import { MutableClock, inProcessFetch } from "./support/world.mjs";

const AGENT = "https://atlas.example/agent.json";
const REDIRECT = "https://atlas.example/oauth/callback";
const scenario = JSON.parse(readFileSync(new URL("../../protocol/scenarios/manzanita-conformance.json", import.meta.url), "utf8"));

const DOCUMENT = {
  protocol_version: "1.0",
  organization: { name: "Example", domain: "example.com" },
  agent: {
    protocols: [
      { type: "poppy", endpoint: "https://example.com/poppy/conversations", description: "Anything about your orders" },
    ],
  },
};
const entry = () => ({ type: "poppy", endpoint: "https://example.com/poppy/conversations" });
const withoutDescription = (version) => ({ ...DOCUMENT, protocol_version: version, agent: { protocols: [entry()] } });

/**
 * Atlas and Manzanita, configured by `config`; the user's browser opens only the company's pages
 * and records every URL handed to it, the agent's own pages unopened.
 */
async function recordingWorld(config) {
  const w = await shopWorld(config === undefined ? {} : { config });
  const browser = w.host.browser;
  const open = browser.open.bind(browser);
  browser.open = async (url) => {
    if (url.reveal().startsWith(SHOP)) return open(url);
    browser.urls.push(url.reveal());
  };
  return { w, browser };
}

function directArguments(w, more = {}) {
  return {
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    redirectUri: REDIRECT,
    scopes: ["orders:read"],
    tenantId: TENANT,
    ...more,
  };
}

/** Manzanita in process, configured by `config`, and a conformance context of Atlas that signs in directly. */
async function binding(config) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const { service } = manzanita({ fetch, clock, ...(config === undefined ? {} : { config }) });
  sites["manzanita.example"] = service;
  const pair = await generateKeyPair("ES256", { extractable: true });
  const atlas = await identityFrom({ domain: "atlas.example", name: "Atlas", privateJwk: await exportJWK(pair.privateKey) });
  sites[atlas.domain] = { "/agent.json": atlas.metadata, "/jwks.json": atlas.jwks };
  const driver = {
    capabilities: new Set(["clock", "direct_sign_in"]),
    accounts: ["acct_ada", "acct_ada_business"],
    async approveAuthorization(url, { account, scopes }) {
      const page = await (await fetch(url, { method: "GET" })).text();
      const requestId = page.split('name="request_id" value="')[1].split('"')[0];
      return service.approveAuthorization(requestId, { accountId: account, ...(scopes ? { scopes } : {}) });
    },
    async approveDevice(userCode, { account }) {
      await service.approveDevice(userCode, { accountId: account });
    },
    async wait(seconds) {
      clock.advance(seconds);
    },
  };
  const ctx = new Context({ baseUrl: SHOP, identity: atlas, fetch, scenario, clock, driver });
  ctx.service = service;
  return ctx;
}

async function signedInUser(ctx) {
  const user = ctx.newUser();
  return ctx.signIn(user, await ctx.session(user));
}

const prover = (ctx) => firstContribution(ctx.agent.reactor, DpopProvers, "DPoP prover");

// Conversation protocol descriptions (§3.1, §8.1) ------------------------------------------

test("a 1.0 document needs a description for each conversation protocol", () => {
  assert.equal(parseDiscoveryDocument(DOCUMENT).agent.protocols[0].description, "Anything about your orders");
  assert.throws(() => parseDiscoveryDocument(withoutDescription("1.0")), /description/);
  assert.throws(() => parseDiscoveryDocument({ ...DOCUMENT, agent: { protocols: [{ ...entry(), description: "" }] } }));
  // 0.4 doesn't define it: a 0.4 document without one is valid, as published.
  assert.equal(parseDiscoveryDocument(withoutDescription("0.4")).agent.protocols[0].description, undefined);
});

test("the reference company describes its agent at 1.0 and not at 0.4", async () => {
  const w = await shopWorld();
  const [described] = w.shop.discoveryDocument().agent.protocols;
  assert.equal(described.description, CONFIG.agentDescription);
  const both = await shopWorld({ config: { protocolVersions: ["1.0", "0.4"] } });
  assert.ok(!("description" in both.shop.discoveryDocument(undefined, "0.4").agent.protocols[0]));
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, agentDescription: " " }), /agentDescription/);
});

// Pushed Authorization Requests (§3.2, §4.2, §4.8) ----------------------------------------

test("a company offers or requires PAR and the agent pushes", async () => {
  const { w, browser } = await recordingWorld({ pushedAuthorizationRequests: "offered" });
  assert.equal(w.metadata.pushed_authorization_request_endpoint, `${SHOP}/oauth/par`);
  assert.equal(w.metadata.require_pushed_authorization_requests, false);
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  await client.begin(directArguments(w, { pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint }));
  // The browser gets only client_id and request_uri (RFC 9126 §4).
  const opened = new URL(browser.urls.at(-1));
  assert.deepEqual([...opened.searchParams.keys()].sort(), ["client_id", "request_uri"]);
  assert.ok(opened.searchParams.get("request_uri").startsWith("urn:ietf:params:oauth:request_uri:"));
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  const done = await client.complete({ callbackUrl });
  assert.deepEqual(done.token.scopes, ["orders:read"]);
  // A request_uri is used once.
  assert.equal((await w.fetch(browser.urls.at(-1), { method: "GET" })).status, 400);
});

test("a company that requires PAR takes nothing else", async () => {
  const { w, browser } = await recordingWorld({ pushedAuthorizationRequests: "required" });
  assert.equal(w.metadata.require_pushed_authorization_requests, true);
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  // Not pushed: the company's page refuses the request.
  await client.begin(directArguments(w));
  assert.ok(browser.pages.at(-1).includes("not valid") && !browser.pages.at(-1).includes('name="request_id"'));
  // A required push needs the endpoint, refused before anything is sent.
  await assert.rejects(client.begin(directArguments(w, { requirePushedAuthorizationRequests: true })), /PAR/);
  const raw = w.shop.oauthMetadata();
  assert.throws(() => parseOAuthServerMetadata({ ...raw, pushed_authorization_request_endpoint: undefined }));
  // Pushed, the sign-in completes.
  await client.begin(
    directArguments(w, {
      pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint,
      requirePushedAuthorizationRequests: true,
    }),
  );
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  assert.ok((await client.complete({ callbackUrl })).token !== undefined);
  // A push is checked as an authorization request: an unknown redirect is refused.
  const sessions = new SessionClient({ reactor: w.reactor, fetch: w.fetch });
  const form = new URLSearchParams({
    response_type: "code",
    client_id: w.identity.clientId,
    redirect_uri: "https://elsewhere.example/cb",
    scope: "orders:read",
    code_challenge: "x".repeat(43),
    code_challenge_method: "S256",
    ...(await sessions.clientAuthentication({ clientId: w.identity.clientId, issuer: SHOP })),
  });
  const refused = await w.fetch(`${SHOP}/oauth/par`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  assert.deepEqual([refused.status, (await refused.json()).error], [400, "invalid_request"]);
  assert.throws(
    () => new CompanyConfig({ ...CONFIG_OPTIONS, ucp: false, pushedAuthorizationRequests: "offered", direct: false }),
    /direct/,
  );
});

test("a link opened later goes to the agent's page, which pushes then", async () => {
  const { w, browser } = await recordingWorld({ pushedAuthorizationRequests: "required" });
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  await client.begin(
    directArguments(w, {
      pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint,
      requirePushedAuthorizationRequests: true,
      crossDevice: true,
      linkPage: "https://atlas.example/sign-in/{link}",
    }),
  );
  // The handoff got the agent's own page: nothing was pushed yet.
  const linkUrl = browser.urls.at(-1);
  assert.ok(linkUrl.startsWith("https://atlas.example/sign-in/"));
  const link = linkUrl.split("/").at(-1);
  // Opened much later: the page pushes now, so the request_uri is fresh.
  w.clock.advance(120);
  const authorizationUrl = await client.openLink(link);
  assert.ok(authorizationUrl.reveal().includes("request_uri="));
  await browser.open(authorizationUrl);
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  assert.ok((await client.complete({ callbackUrl })).token !== undefined);
  await assert.rejects(client.openLink(link), AuthorizationError); // the sign-in is done
  await assert.rejects(client.openLink("unknown"), AuthorizationError);
  await assert.rejects(client.begin(directArguments(w, { linkPage: "https://atlas.example/no-link" })), RangeError);
});

test("a push with a DPoP proof binds the code to its key", async () => {
  const ctx = await binding({ dpopBinding: "required", pushedAuthorizationRequests: "required" });
  const metadata = await ctx.metadata();
  assert.equal(metadata.require_pushed_authorization_requests, true);
  const signed = await signedInUser(ctx); // the conformance agent pushes, with a proof
  assert.equal(signed.token.tokenType, "DPoP");
  // Pushed with one key, exchanged with another: the code is bound to the first.
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const client = new DirectSignInClient({ reactor: ctx.agent.reactor, fetch: ctx.fetch });
  await client.begin({
    authorizationEndpoint: metadata.authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    issuer: metadata.issuer,
    clientId: ctx.agent.identity.clientId,
    redirectUri: ctx.agent.identity.metadata.redirect_uris[0],
    scopes: scenario.scopes,
    tenantId: ctx.tenantId,
    dpopSigningAlgs: metadata.dpop_signing_alg_values_supported,
    pairwiseUserId: session.sub,
    pushedAuthorizationRequestEndpoint: metadata.pushed_authorization_request_endpoint,
    requirePushedAuthorizationRequests: true,
  });
  const callbackUrl = await ctx.driver.approveAuthorization(ctx.agent.userBrowser.urls.at(-1), { account: ctx.driver.accounts[0] });
  await prover(ctx).keys.forget({ tenantId: ctx.tenantId, issuer: metadata.issuer, sub: session.sub });
  const refused = await rejection(client.complete({ callbackUrl }));
  assert.equal(refused.code, "invalid_grant");
});

// Minor versions (§3.4) --------------------------------------------------------------------

test("nothing of 1.0 goes into a 0.4 exchange", async () => {
  // A 0.4 document has no description, and a 0.4 Session sends no `null` context.
  const w = await shopWorld();
  const { service: published } = manzanita({ fetch: w.fetch, clock: w.clock, config: { protocolVersions: ["0.4"] } });
  const document = published.discoveryDocument();
  assert.equal(document.protocol_version, "0.4");
  assert.ok(document.agent.protocols.every((item) => !("description" in item)));
  const sent = [];
  const transport = mockTransport(w, async (_url, init) => {
    sent.push(JSON.parse(init.body));
    throw new TypeError("not sent further");
  });
  const conversations = new ConversationClient({ reactor: w.reactor, transport });
  const session = (protocolVersion) =>
    new PapSession({ sid: `sid_${"a".repeat(22)}`, sub: "u", issuer: SHOP, clientId: AGENT, tenantId: TENANT, protocolVersion });
  const clearing = { id: "req_clear_0000000000000000", author: { type: "agent" }, context: { locale: null } };
  assert.ok(clearsContext(clearing));
  const refused = await rejection(conversations.start(`${SHOP}/poppy/conversations`, clearing, { session: session("0.4") }));
  assert.equal(refused.code, "context_clear_unsupported");
  assert.equal(sent.length, 0);
  await rejection(conversations.start(`${SHOP}/poppy/conversations`, clearing, { session: session("1.0") }));
  assert.deepEqual(sent.at(-1).message.context, { locale: null });
});

// PS384 required, RSA 2048 to 4096 bits (§4.1, §5.2, §10.7) --------------------------------

const rsaJwks = (jwk, kid) => ({ keys: [{ ...jwk, kid, alg: "PS384" }] });
const NOW = new Date("2026-11-17T09:00:00Z");

/** A client assertion signed by `privateKey`, lasting `lifetime` seconds. */
async function assertion(privateKey, { lifetime = 60 } = {}) {
  const claims = buildClientAssertionClaims({ clientId: AGENT, issuer: SHOP, now: NOW, lifetimeSeconds: Math.min(lifetime, 300) });
  const signer = new JoseSigner({ privateKey, algorithm: "PS384", keyId: "k" });
  return (await signer.sign({ ...claims, exp: claims.iat + lifetime }, { purpose: "client_assertion" })).reveal();
}

for (const bits of [2048, 3072, 4096]) {
  test(`companies accept PS384 assertions and delegations (${bits} bits)`, async () => {
    const { privateKey, publicKey } = await generateKeyPair("PS384", { modulusLength: bits, extractable: true });
    const keys = rsaJwks(await exportJWK(publicKey), "k");
    const claims = await verifyAssertion(await assertion(privateKey), {
      keys,
      issuer: AGENT,
      subject: AGENT,
      audience: SHOP,
      replayCache: new MemoryReplayCache(),
      now: NOW,
    });
    assert.equal(claims.aud, SHOP);
    const delegated = await generateKeyPair("ES256", { extractable: true });
    const { d: _d, ...publicJwk } = await exportJWK(delegated.privateKey);
    const signer = new JoseSigner({ privateKey, algorithm: "PS384", keyId: "k" });
    const delegation = await signer.sign(
      delegationClaims({ clientId: AGENT, publicKey: publicJwk, issuedAt: NOW, lifetimeSeconds: 3600 }),
      { purpose: "delegation" },
    );
    const verified = await verifyDelegation(delegation.reveal(), {
      clientId: AGENT,
      resolve: async () => [undefined, keys],
      now: NOW,
    });
    assert.equal(verified.clientId, AGENT);
  });
}

test("an RSA key outside 2048 to 4096 bits is refused", async () => {
  assert.deepEqual([...RSA_KEY_BITS], [2048, 4096]);
  // Signed by hand: jose refuses to sign with a key this weak, as it should.
  const weak = generateKeyPairSync("rsa", { modulusLength: 1024 });
  const claims = buildClientAssertionClaims({ clientId: AGENT, issuer: SHOP, now: NOW, lifetimeSeconds: 60 });
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const input = `${encode({ alg: "PS384", typ: "JWT", kid: "k" })}.${encode(claims)}`;
  const signature = nodeSign("sha384", Buffer.from(input), {
    key: weak.privateKey,
    padding: constants.RSA_PKCS1_PSS_PADDING,
    saltLength: 48,
  });
  const refused = await rejection(
    verifyAssertion(`${input}.${signature.toString("base64url")}`, {
      keys: rsaJwks(weak.publicKey.export({ format: "jwk" }), "k"),
      issuer: AGENT,
      audience: SHOP,
      replayCache: new MemoryReplayCache(),
      now: NOW,
    }),
  );
  assert.equal(refused.code, "invalid_client");
});

// Client assertion lifetime (§4.1) ---------------------------------------------------------

test("an assertion lasts at most five minutes, and one that does is accepted", async () => {
  assert.throws(() => buildClientAssertionClaims({ clientId: AGENT, issuer: SHOP, lifetimeSeconds: 301 }));
  const { privateKey, publicKey } = await generateKeyPair("PS384", { modulusLength: 2048, extractable: true });
  const keys = rsaJwks(await exportJWK(publicKey), "k");
  for (const [lifetime, accepted] of [[300, true], [301, false]]) {
    const verify = verifyAssertion(await assertion(privateKey, { lifetime }), {
      keys,
      issuer: AGENT,
      audience: SHOP,
      replayCache: new MemoryReplayCache(),
      now: NOW,
    });
    if (accepted) await verify;
    else await assert.rejects(verify, (error) => error.code === "invalid_client");
  }
});

// Consent for scopes granted before (§4.2, §4.3, §10.8) ------------------------------------

test("a direct sign-in asks for consent unless the redirect stays on the device", async () => {
  const options = {
    authorizationEndpoint: `${SHOP}/oauth/authorize?prompt=none`,
    issuer: SHOP,
    clientId: AGENT,
    redirectUri: REDIRECT,
    scopes: ["orders:read"],
  };
  const query = new URL((await buildDirectSignInRequest(options)).authorizationUrl.reveal()).searchParams;
  assert.deepEqual(query.getAll("prompt"), [PROMPT_CONSENT]);
  assert.equal(PROMPT_CONSENT, "consent");
  assert.ok(!query.has("resource")); // one sign-in for every resource (§4.5)
  const sameDevice = await buildDirectSignInRequest({ ...options, promptConsent: false });
  assert.ok(!new URL(sameDevice.authorizationUrl.reveal()).searchParams.has("prompt"));
});

test("the consent page lists every scope and marks the earlier ones", async () => {
  const w = await shopWorld();
  const begin = async (scopes) => {
    const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
    await client.begin(directArguments(w, { scopes }));
    return client;
  };
  const client = await begin(["orders:read"]);
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  await client.complete({ callbackUrl });
  // Every scope again, the earlier one included: the page is shown all the same.
  await begin(["orders:read", "orders:write"]);
  const shown = w.host.browser.pages.at(-1);
  assert.ok(shown.includes('name="request_id"') && shown.includes("See your orders"));
  const requestId = w.host.browser.requestId;
  const summary = await w.shop.authorizationRequest(requestId, { accountId: "acct_ada" });
  assert.equal(summary.prompt, "consent");
  assert.deepEqual(
    summary.scopes.map((item) => [item.scope, item.granted_before]),
    [
      ["orders:read", true],
      ["orders:write", false],
    ],
  );
  const unmarked = await w.shop.authorizationRequest(requestId);
  assert.ok(unmarked.scopes.every((item) => !("granted_before" in item)));
  // Another account granted nothing.
  const other = await w.shop.authorizationRequest(requestId, { accountId: "acct_bob" });
  assert.ok(!other.scopes.some((item) => item.granted_before));
});

test("every device sign-in shows its page with the earlier scopes marked", async () => {
  const w = await shopWorld();
  await signedIn(w, ["orders:read"]);
  const started = await new DeviceSignInClient({ reactor: w.reactor, fetch: w.fetch }).begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    organization: w.company.document.organization,
  });
  const shown = await w.shop.deviceRequest(started.userCode, { accountId: "acct_ada" });
  assert.deepEqual(
    shown.scopes.map((item) => [item.scope, item.granted_before]),
    [
      ["orders:read", true],
      ["orders:write", false],
    ],
  );
});

// Same DPoP key at refresh (§4.4, §4.5, §10.7) ---------------------------------------------

test("a bound refresh token refreshes only with its key", async () => {
  assert.throws(() => new CompanyConfig({ ...CONFIG_OPTIONS, bindRefreshTokens: true }), /bindRefreshTokens/);
  const ctx = await binding({ dpopBinding: "required", bindRefreshTokens: true });
  const signed = await signedInUser(ctx);
  const context = await ctx.accountContext(signed.session.sub);
  // The same key, twice: the rotated token stays bound to it.
  for (let turn = 0; turn < 2; turn += 1) {
    const refreshed = await ctx.agent.accounts.refresh(signed.reference, { context });
    assert.ok(refreshed.status === "signed_in" && refreshed.rotated);
  }
  const metadata = await ctx.metadata();
  await prover(ctx).keys.forget({ tenantId: ctx.tenantId, issuer: metadata.issuer, sub: signed.session.sub });
  // Another key: invalid_grant, so the copy is useless and the agent signs in again.
  const lost = await ctx.agent.accounts.refresh(signed.reference, { context });
  assert.equal(lost.status, "signed_out");
});

test("without binding a refresh with a new key still works", async () => {
  const ctx = await binding({ dpopBinding: "required" });
  const signed = await signedInUser(ctx);
  const metadata = await ctx.metadata();
  await prover(ctx).keys.forget({ tenantId: ctx.tenantId, issuer: metadata.issuer, sub: signed.session.sub });
  const context = await ctx.accountContext(signed.session.sub);
  assert.equal((await ctx.agent.accounts.refresh(signed.reference, { context })).status, "signed_in");
  assert.ok(ctx.url(scenario.read_path).startsWith("https://"));
});

// UCP scope requests name every scope (UCP 4, 11) ------------------------------------------

test("a UCP sign-in requests every scope and gets only those", async () => {
  const held = ["orders:write"];
  const needed = ["orders:read"];
  const profile = { capabilities: { [UCP_IDENTITY_LINKING]: [{ config: { scopes: { "orders:read": {} } } }] } };
  assert.deepEqual(ucpScopes(profile, held, { needed }), ["orders:write", "orders:read"]);
  assert.deepEqual(ucpScopes(profile, held), ["orders:write", "orders:read"]);
  // 0.4 kept UCP's incremental authorization: only the missing scopes.
  assert.deepEqual(ucpScopes(profile, held, { needed, protocolVersion: "0.4" }), ["orders:read"]);
  // The company grants only the scopes a sign-in names, whatever was granted before.
  const w = await shopWorld();
  await signedIn(w, ["orders:read", "orders:write"]);
  const narrower = await signedIn(w, ["orders:read"]);
  assert.deepEqual(narrower.token.scopes, ["orders:read"]);
});

// Ports in organization.domain (§3.1, §3.2) ------------------------------------------------

test("a domain names its port when that isn't 443, from 1.0 only", () => {
  assert.deepEqual(splitDomain("shop.example:8443"), ["shop.example", 8443]);
  const organization = (domain) => parseDiscoveryDocument({ ...DOCUMENT, organization: { name: "Shop", domain } }).organization;
  assert.equal(organization("Shop.Example:8443").domain, "shop.example:8443");
  for (const invalid of ["shop.example:443", "shop.example:0", "shop.example:99999", "x.example:y"]) {
    assert.throws(() => organization(invalid), invalid);
  }
  const onAPort = { ...DOCUMENT, organization: { name: "Shop", domain: "shop.example:8443" } };
  assert.equal(parseDiscoveryDocument(onAPort).organization.domain, "shop.example:8443");
  assert.throws(() => parseDiscoveryDocument({ ...onAPort, protocol_version: "0.4" }), /port/);
  assert.equal(urlDomain("https://shop.example:8443/x"), "shop.example:8443");
  assert.equal(urlDomain("https://shop.example:443/x"), "shop.example");
  assert.ok(pageCarriesSession("https://shop.example:8443/page", "shop.example:8443"));
  assert.ok(!pageCarriesSession("https://shop.example/page", "shop.example:8443"));
  assert.ok(verificationHostAllowed("https://shop.example/device", { issuer: "https://auth.example", domain: "shop.example:8443" }));
  const metadata = parseOAuthServerMetadata({
    issuer: "https://shop.example:8443",
    token_endpoint: "https://shop.example:8443/oauth/token",
    revocation_endpoint: "https://shop.example:8443/oauth/revoke",
    grant_types_supported: ["refresh_token"],
    protected_resources: ["https://shop.example:8443"],
  });
  assert.ok(listsResource(metadata, "shop.example:8443"));
  assert.ok(!listsResource(metadata, "shop.example"));
  // A company serves a domain with a port at 1.0 only.
  new CompanyConfig({ ...CONFIG_OPTIONS, domain: "manzanita.example:8443" });
  assert.throws(
    () => new CompanyConfig({ ...CONFIG_OPTIONS, domain: "manzanita.example:8443", protocolVersions: ["1.0", "0.4"] }),
    /port/,
  );
});

/** A network answering a company on shop.example:8443, whose poppy.json names `organization`. */
function portNetwork(organization) {
  const base = "https://shop.example:8443";
  const answers = {
    [`${base}/.well-known/poppy.json`]: {
      ...DOCUMENT,
      organization: { name: "Shop", domain: organization },
      agent: { protocols: [{ ...entry(), endpoint: `${base}/poppy`, description: "All" }] },
    },
    [`${base}/.well-known/oauth-protected-resource`]: { resource: base, authorization_servers: [base] },
    [`${base}/.well-known/oauth-authorization-server`]: {
      issuer: base,
      token_endpoint: `${base}/oauth/token`,
      revocation_endpoint: `${base}/oauth/revoke`,
      grant_types_supported: ["refresh_token"],
      protected_resources: [base],
    },
  };
  return async (input) => {
    const body = answers[String(input)];
    return new Response(JSON.stringify(body ?? { error: "not_found" }), {
      status: body ? 200 : 404,
      headers: { "content-type": "application/json" },
    });
  };
}

test("an agent uses a company on another port only when configured to", async () => {
  const fetch = portNetwork("shop.example:8443");
  await assert.rejects(discoverCompany("shop.example:8443", { fetch }), (error) => error.code === "port_not_allowed");
  const company = await discoverCompany("shop.example:8443", { fetch, allowPorts: true });
  assert.equal(company.document.organization.domain, "shop.example:8443");
  // A document on shop.example:8443 speaks for shop.example:8443, not shop.example.
  await assert.rejects(
    discoverCompany("shop.example:8443", { fetch: portNetwork("shop.example"), allowPorts: true }),
    (error) => error.code === "organization_domain_mismatch",
  );
});

// One sign-in for every resource (§4.5, §4.7, §4.8, §7) ------------------------------------

test("a service left out is invalid_target and used signed out", async () => {
  const w = await shopWorld();
  const { reference } = await signedIn(w);
  const mcp = `${SHOP}/mcp`;
  // Signed in with no resource: a token for the MCP server, added or not.
  const result = await w.accounts.refresh(reference, { context: w.context, resource: mcp });
  assert.equal(result.status, "signed_in");
  assert.equal(result.token.resource, mcp);
  // The client policy leaves the MCP server out for this agent (`allowsResource`).
  const policy = firstContribution(w.shop.reactor, ClientPolicies, "policy");
  policy.allowsResource = async (_clientId, resource) => resource !== mcp;
  const refused = await rejection(w.accounts.refresh(reference, { context: w.context, resource: mcp }));
  assert.ok(refused instanceof AuthorizationError);
  assert.equal(refused.code, "invalid_target");
  // The default token still comes; the agent uses the server signed out.
  assert.equal((await w.accounts.refresh(reference, { context: w.context })).status, "signed_in");
  const tokens = new ServiceTokens({
    refresh: w.accounts,
    reference,
    context: w.context,
    company: w.company,
    discovery: { reactor: w.reactor },
  });
  assert.equal(await tokens.tokenFor(mcp), undefined);
  assert.ok((await tokens.tokenFor(SHOP)) !== undefined);
});

// Clearing context, room to extend conversations (§8.4, §8.6, §8.13) -----------------------

test("null clears a context field as if never shared", () => {
  const messages = [
    { locale: "fr", time_zone: "Europe/Paris" },
    { user_available: true },
    { locale: null },
  ].map((context) => parseMessage({ author: { type: "agent" }, context }));
  assert.deepEqual(effectiveContext(messages), { time_zone: "Europe/Paris", user_available: true });
});

test("the company agent sees the context cleared", async () => {
  const w = await shopWorld();
  const { session, token } = await signedIn(w);
  const seen = [];
  const agent = firstContribution(w.shop.reactor, CompanyAgents, "company agent");
  const original = agent.respond.bind(agent);
  agent.respond = async (turn) => {
    seen.push({ ...turn.context });
    return original(turn);
  };
  const message = (text, context) => ({ id: w.conversations.generateRequestId(), author: { type: "agent" }, text, context });
  const started = await w.conversations.start(w.endpoint, message("Hello", { locale: "fr" }), { session, token, wait: 5 });
  await w.conversations.send(w.endpoint, started.conversation_id, message("Again", { locale: null }), { session, token, wait: 5 });
  assert.deepEqual(seen, [{ locale: "fr" }, {}]);
});

test("unknown roles and author types are read safely", () => {
  const message = parseMessage({ author: { type: "organization" }, role: "system", text: "Hi" });
  assert.deepEqual([message.role, message.author.type], ["company", "agent"]);
});

test("the company ignores author fields on the agent's messages", async () => {
  const w = await shopWorld();
  const session = await w.start();
  const body = {
    id: `req_${"a".repeat(22)}`,
    message: { author: { type: "agent", id: "pretend", name: "Support", image: `${SHOP}/i` }, text: "Hello" },
  };
  const response = await w.transport.request("POST", w.endpoint, {
    session,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  assert.equal(response.status, 201);
  const page = await w.conversations.readEvents(w.endpoint, (await response.json()).conversation_id, { session });
  assert.deepEqual(page.events[0].message.author, { type: "agent" });
});

test("a stream skips event names it doesn't know", async () => {
  const w = await shopWorld();
  const session = await w.start();
  const state = { id: "evt_1", type: "state", created_at: "2026-11-17T09:00:00Z", handoff: "none", responder: "agent", closed: true };
  const lines =
    'event: working\ndata: {"working":true}\n\n' +
    'event: future-thing\ndata: {"anything":1}\n\n' +
    `id: evt_1\ndata: ${JSON.stringify(state)}\n\n`;
  const transport = mockTransport(w, async () => new Response(lines, { status: 200, headers: { "content-type": "text/event-stream" } }));
  const conversations = new ConversationClient({ reactor: w.reactor, transport });
  const items = [];
  for await (const item of conversations.stream(`${SHOP}/poppy`, "cnv_1", { session })) items.push(item);
  assert.deepEqual(
    items.map((item) => item.kind ?? item.type),
    ["working", "state"],
  );
});

test("an unknown error code is handled by its HTTP status", async () => {
  assert.equal(knownConversationError("conversation_closed"), "conversation_closed");
  assert.equal(knownConversationError("stronger_sign_in_needed"), "conversation_request_failed");
  assert.ok(KNOWN_CONVERSATION_ERRORS.has("conversation_closed"));
  const w = await shopWorld();
  const session = await w.start();
  const transport = mockTransport(
    w,
    async () => new Response(JSON.stringify({ error: "something_new" }), { status: 409, headers: { "content-type": "application/json" } }),
  );
  const refused = await rejection(new ConversationClient({ reactor: w.reactor, transport }).readEvents(`${SHOP}/poppy`, "cnv_1", { session }));
  assert.ok(refused instanceof ConversationError);
  assert.deepEqual([refused.code, refused.statusCode, refused.details], ["conversation_request_failed", 409, { error: "something_new" }]);
});

// What working means, unknown sign-in errors (§8.7, §8.11) ---------------------------------

test("working is false once the reply is written", async () => {
  const w = await shopWorld();
  const { session, token } = await signedIn(w);
  const page = await w.conversations.start(
    w.endpoint,
    { id: w.conversations.generateRequestId(), author: { type: "agent" }, text: "Exchange my jacket for a size L" },
    { session, token, wait: 5 },
  );
  // The reply proposes an exchange the User has yet to approve: not `working`.
  assert.equal(page.working ?? false, false);
});

test("an unknown authorization error signs in again for its scopes", () => {
  const event = parseConversationEvent({
    id: "evt_1",
    type: "authorization",
    created_at: "2026-11-17T09:00:00Z",
    error: "stronger_sign_in",
    scope: "orders:read orders:write orders:read",
  });
  assert.equal(event.error, "stronger_sign_in");
  assert.deepEqual([...signInScopes(event)], ["orders:read", "orders:write"]);
});

// Mediated Sign-In retirement date ---------------------------------------------------------

test("Mediated Sign-In is retired on 17 March 2027", () => {
  assert.equal(MEDIATED_RETIREMENT_DATE, "2027-03-17");
});

// 0.37.1 -----------------------------------------------------------------------------------

test("a bound refresh gets a Bearer token for a Bearer-only MCP server", async () => {
  // The refresh proves with the refresh token's key whatever token it asks for (§4.4), and a
  // server that takes only Bearer gets Bearer (§4.5): the sign-in is kept.
  const ctx = await binding({ dpopBinding: "required", bindRefreshTokens: true });
  const signed = await signedInUser(ctx);
  const plain = { ...ctx.service.protectedResourceMetadata() };
  delete plain.dpop_signing_alg_values_supported;
  ctx.service.protectedResourceMetadata = () => plain;
  const metadata = await ctx.metadata();
  const server = await fetchMcpServerMetadata(ctx.service.config.mcpUrl, { issuer: metadata.issuer, fetch: ctx.fetch });
  assert.equal(server.dpop_signing_alg_values_supported, undefined);
  const context = await ctx.accountContext(signed.session.sub);
  const result = await ctx.agent.accounts.tokenForMcp(signed.reference, { context, server });
  assert.equal(result.status, "signed_in");
  assert.equal(result.token.tokenType, "Bearer");
  // The refresh token was kept: the next refresh, by the same key, works.
  assert.equal((await ctx.agent.accounts.refresh(signed.reference, { context })).status, "signed_in");
});

test("opening a link never takes the callback state", async () => {
  const { w, browser } = await recordingWorld({ pushedAuthorizationRequests: "required" });
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  await client.begin(
    directArguments(w, {
      pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint,
      requirePushedAuthorizationRequests: true,
      linkPage: "https://atlas.example/sign-in/{link}",
    }),
  );
  const link = browser.urls.at(-1).split("/").at(-1);
  const store = firstContribution(w.reactor, AuthorizationStateStores, "authorization state store");
  const taken = [];
  const take = store.take.bind(store);
  store.take = async (reference) => {
    taken.push(reference);
    return take(reference);
  };
  await browser.open(await client.openLink(link));
  // Read with the store's `get`: an opening consumes nothing, the link's record included.
  assert.deepEqual(taken, []);
  // Opened twice, then completed: complete() alone consumes the state, once.
  await client.openLink(link);
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  assert.ok((await client.complete({ callbackUrl })).token !== undefined);
  await assert.rejects(client.openLink(link), AuthorizationError);
});

test("a context field named __proto__ is a field, never the prototype", () => {
  const context = JSON.parse('{"__proto__": {"polluted": true}, "locale": "fr"}');
  const shared = effectiveContext([{ context }]);
  assert.deepEqual(Object.keys(shared).sort(), ["__proto__", "locale"]);
  assert.deepEqual(shared.__proto__, { polluted: true });
  assert.equal(shared.polluted, undefined);
  assert.equal({}.polluted, undefined);
});

test("an empty event name is the default message event", async () => {
  const w = await shopWorld();
  const session = await w.start();
  const state = { id: "evt_1", type: "state", created_at: "2026-11-17T09:00:00Z", handoff: "none", responder: "agent", closed: true };
  const lines = `event:\nid: evt_1\ndata: ${JSON.stringify(state)}\n\n`;
  const transport = mockTransport(w, async () => new Response(lines, { status: 200, headers: { "content-type": "text/event-stream" } }));
  const conversations = new ConversationClient({ reactor: w.reactor, transport });
  const items = [];
  for await (const item of conversations.stream(`${SHOP}/poppy`, "cnv_1", { session })) items.push(item);
  assert.deepEqual(
    items.map((item) => item.kind ?? item.type),
    ["state"],
  );
});

async function pushedLink(w, browser) {
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  const start = await client.begin(
    directArguments(w, {
      pushedAuthorizationRequestEndpoint: w.metadata.pushed_authorization_request_endpoint,
      requirePushedAuthorizationRequests: true,
      linkPage: "https://atlas.example/sign-in/{link}",
    }),
  );
  return { client, link: browser.urls.at(-1).split("/").at(-1), start };
}

const hex = async (prefix, value) =>
  `${prefix}:${Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;

test("an opening paused while the callback completes never restores the link", async () => {
  // Copilot's review of 0.37.1: an opening paused between reading the link and writing it back,
  // while complete() consumed the sign-in, restored a link whose callbacks could not succeed.
  const { w, browser } = await recordingWorld({ pushedAuthorizationRequests: "required" });
  const { client, link } = await pushedLink(w, browser);
  await browser.open(await client.openLink(link));
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  const store = firstContribution(w.reactor, AuthorizationStateStores, "authorization state store");
  const get = store.get.bind(store);
  let read;
  let resume;
  const wasRead = new Promise((resolve) => (read = resolve));
  const resumed = new Promise((resolve) => (resume = resolve));
  store.get = async (reference) => {
    const value = await get(reference);
    read();
    await resumed;
    return value;
  };
  const opening = client.openLink(link);
  await wasRead;
  store.get = get;
  assert.ok((await client.complete({ callbackUrl })).token !== undefined);
  resume();
  await opening; // it read before the sign-in completed
  await assert.rejects(client.openLink(link), AuthorizationError);
});

test("a link begun by 0.37.0 opens after an upgrade without consuming its state", async () => {
  const { w, browser } = await recordingWorld({ pushedAuthorizationRequests: "required" });
  const { client, link, start } = await pushedLink(w, browser);
  const store = firstContribution(w.reactor, AuthorizationStateStores, "authorization state store");
  const reference = await hex("direct", start.state.reveal());
  await store.put(await hex("direct-link", link), reference, { expiresAt: new Date(Date.now() + 300_000) });
  await browser.open(await client.openLink(link));
  assert.ok((await store.get(reference)) !== undefined); // the state is still there
  const callbackUrl = await w.shop.approveAuthorization(browser.requestId, { accountId: "acct_ada" });
  assert.ok((await client.complete({ callbackUrl })).token !== undefined);
  await assert.rejects(client.openLink(link), AuthorizationError);
});

test("a store without get is read by taking and putting back", async () => {
  const { w, browser } = await recordingWorld({ pushedAuthorizationRequests: "offered" });
  const { client, link } = await pushedLink(w, browser);
  const store = firstContribution(w.reactor, AuthorizationStateStores, "authorization state store");
  store.get = undefined; // a store written before 0.37.2
  assert.ok((await client.openLink(link)).reveal().includes("request_uri="));
  assert.ok((await client.openLink(link)).reveal().includes("request_uri="));
});

test("the start names the state the callback carries", async () => {
  const { w, browser } = await recordingWorld();
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  const start = await client.begin(directArguments(w, { linkPage: "https://atlas.example/sign-in/{link}" }));
  const opened = await client.openLink(browser.urls.at(-1).split("/").at(-1));
  assert.equal(new URL(opened.reveal()).searchParams.get("state"), start.state.reveal());
});
