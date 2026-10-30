/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Guide-level behaviour at the TypeScript reference company: overlapping JWKS
// (operational-limits.mdx) and the consent page's CSRF binding and framing (company.mdx).
import assert from "node:assert/strict";
import test from "node:test";

import { DirectSignInClient, SessionClient, discoverCompany, sessionHeaders } from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { CONSENT_COOKIE } from "../../lib/server.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const AUTHORIZE = "https://manzanita.example/oauth/authorize";
const ORDERS = "https://manzanita.example/api/orders";
const HIDDEN = /<input type="hidden" name="([^"]+)" value="([^"]*)">/g;

/** Atlas's website, whose key set a spec rotates; it counts JWKS fetches. */
function rotatingSite(identity, maxAge) {
  const site = {
    keys: [...identity.jwks.keys],
    jwksFetches: 0,
    async handle(request) {
      const path = new URL(request.url).pathname;
      if (path === "/jwks.json") site.jwksFetches += 1;
      return {
        status: 200,
        body: path === "/jwks.json" ? { keys: site.keys } : identity.metadata,
        headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${maxAge}` },
      };
    },
  };
  return site;
}

async function world(maxAge) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const atlas = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  const site = rotatingSite(atlas, maxAge);
  sites["atlas.example"] = site;
  const { service: shop } = manzanita({ fetch, clock });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity: atlas, fetch, clock });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  /**
   * One signed-out request in a new Session, whose delegation `identity`'s key signed.
   *
   * Each call is a new host, so a new delegated key and delegation: a delegation is verified
   * against the agent's keys when it is first seen (§5.2).
   */
  const accepted = async (identity) => {
    const agent = await agentHost({ identity, fetch, clock });
    const session = await new SessionClient({ reactor: agent.reactor, fetch }).start({
      clientId: identity.clientId,
      pairwiseUserId: PAIRWISE,
      issuer: metadata.issuer,
      tenantId: TENANT,
    });
    const answer = await fetch(ORDERS, { method: "GET", headers: await sessionHeaders(agent.reactor, "GET", ORDERS, { session }) });
    if (answer.status === 400) {
      assert.equal((await answer.json()).error, "invalid_session");
      return false;
    }
    // Signed out: the Session is good, and the account needs a sign-in (§7).
    assert.equal(answer.status, 401);
    return true;
  };
  const rotated = (kid) => agentIdentity({ domain: "atlas.example", name: "Atlas", kid });
  return { clock, fetch, atlas, site, shop, host, metadata, accepted, rotated };
}

test("overlapping JWKS: either key verifies during the overlap, the retired one after it is refused", async () => {
  const w = await world(600);
  assert.ok(await w.accepted(w.atlas)); // the company caches [key-1]
  assert.equal(w.site.jwksFetches, 1);
  const newer = await w.rotated("key-2");

  // The overlap: both keys are published; the agent signs delegations with the new one.
  w.site.keys = [...w.atlas.jwks.keys, ...newer.jwks.keys];
  assert.ok(await w.accepted(newer));
  assert.equal(w.site.jwksFetches, 2); // the unknown kid fetched the set again, at once
  // Delegations signed with the old key still verify during the overlap, from the cache.
  assert.ok(await w.accepted(w.atlas));
  assert.ok(await w.accepted(newer));
  assert.equal(w.site.jwksFetches, 2);

  // Retired: still verified until the cached set expires (its max-age), refused after.
  w.site.keys = [...newer.jwks.keys];
  w.clock.advance(599);
  assert.ok(await w.accepted(w.atlas));
  w.clock.advance(2);
  assert.equal(await w.accepted(w.atlas), false);
  assert.ok(await w.accepted(newer));
});

test("unknown kids fetch the set again at most once a minute", async () => {
  const w = await world(3600);
  assert.ok(await w.accepted(w.atlas));
  assert.equal(w.site.jwksFetches, 1);
  // Delegations naming keys that were never published: refused, one fetch for all of them.
  for (let index = 0; index < 20; index += 1) {
    assert.equal(await w.accepted(await w.rotated(`forged-${index}`)), false);
  }
  assert.equal(w.site.jwksFetches, 2);
  // A real rotation inside that minute waits for the next refetch: then it verifies.
  const newer = await w.rotated("key-2");
  w.site.keys = [...w.atlas.jwks.keys, ...newer.jwks.keys];
  assert.equal(await w.accepted(newer), false);
  assert.equal(w.site.jwksFetches, 2);
  w.clock.advance(61);
  assert.ok(await w.accepted(newer));
  assert.equal(w.site.jwksFetches, 3);
});

function hidden(page) {
  return Object.fromEntries([...page.matchAll(HIDDEN)].map((match) => [match[1], match[2]]));
}

function post(form, { cookie, headers = {} } = {}) {
  const sent = { origin: "https://manzanita.example", "sec-fetch-site": "same-origin", ...headers };
  if (cookie !== undefined) sent.cookie = `${CONSENT_COOKIE}=${cookie}`;
  for (const [name, value] of Object.entries(sent)) if (value === undefined) delete sent[name];
  return { method: "POST", url: AUTHORIZE, headers: sent, body: new URLSearchParams(form).toString() };
}

/** One browser: the page it was shown and the consent cookie it was given. */
async function open(shop, url, cookie) {
  const answer = await shop.handle({ method: "GET", url, headers: cookie ? { cookie: `${CONSENT_COOKIE}=${cookie}` } : {} });
  const setCookie = answer.headers["Set-Cookie"];
  return { answer, setCookie, cookie: setCookie.split(";", 1)[0].split("=").slice(1).join("="), form: hidden(answer.body) };
}

test("the consent form is bound to the browser that was shown it", async () => {
  const w = await world(600);
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.atlas.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read"],
    tenantId: TENANT,
  });
  const url = w.host.browser.urls.at(-1);
  const ours = await open(w.shop, url);
  const theirs = await open(w.shop, url);
  for (const shown of [ours, theirs]) {
    assert.equal(shown.answer.status, 200);
    assert.equal(shown.answer.headers["X-Frame-Options"], "DENY");
    assert.match(shown.answer.headers["Content-Security-Policy"], /frame-ancestors 'none'/);
    assert.equal(shown.answer.headers["Cache-Control"], "no-store");
    assert.ok(shown.setCookie.startsWith(`${CONSENT_COOKIE}=`));
    for (const attribute of ["Path=/", "Secure", "HttpOnly", "SameSite=Strict"]) assert.ok(shown.setCookie.includes(attribute));
  }
  assert.deepEqual(Object.keys(ours.form).sort(), ["csrf", "request_id"]);
  assert.notEqual(ours.form.request_id, theirs.form.request_id);
  assert.ok(ours.answer.body.includes(`action="${AUTHORIZE}"`));
  assert.notEqual(ours.cookie, theirs.cookie);

  const allow = { ...ours.form, decision: "allow" };
  const refused = {
    "a cross-site POST": post(allow, { cookie: ours.cookie, headers: { "sec-fetch-site": "cross-site" } }),
    "a same-site but not same-origin POST": post(allow, { cookie: ours.cookie, headers: { "sec-fetch-site": "same-site" } }),
    "another origin": post(allow, { cookie: ours.cookie, headers: { origin: "https://evil.example" } }),
    "an opaque origin": post(allow, { cookie: ours.cookie, headers: { origin: "null" } }),
    "no consent cookie": post(allow),
    "no CSRF token": post({ ...allow, csrf: "" }, { cookie: ours.cookie }),
    "a wrong CSRF token": post({ ...allow, csrf: theirs.form.csrf }, { cookie: ours.cookie }),
    "the form replayed from another browser": post(allow, { cookie: theirs.cookie }),
    "another browser's form for this request": post({ ...theirs.form, request_id: ours.form.request_id, decision: "allow" }, { cookie: theirs.cookie }),
    "no decision": post(ours.form, { cookie: ours.cookie }),
    "an unknown request": post({ ...allow, request_id: "authz_unknown" }, { cookie: ours.cookie }),
  };
  for (const [what, request] of Object.entries(refused)) {
    await assert.rejects(w.shop.consentDecision(request), /did not come from the page/, what);
  }
  await assert.rejects(w.shop.consentDecision({ method: "GET", url: AUTHORIZE, headers: { cookie: `${CONSENT_COOKIE}=${ours.cookie}` } }));

  const decision = await w.shop.consentDecision(post(allow, { cookie: ours.cookie }));
  assert.deepEqual(decision, { requestId: ours.form.request_id, allow: true });
  const callbackUrl = await w.shop.approveAuthorization(decision.requestId, { accountId: "acct_ada" });
  assert.deepEqual((await client.complete({ callbackUrl })).token.scopes, ["orders:read"]);
  await assert.rejects(w.shop.consentDecision(post(allow, { cookie: ours.cookie })));
  // A browser that already has the cookie keeps it.
  const again = await open(w.shop, url, ours.cookie);
  assert.equal(again.cookie, ours.cookie);
  assert.equal((await w.shop.consentDecision(post({ ...again.form, decision: "deny" }, { cookie: ours.cookie }))).allow, false);
});

test("a hosted consent page gets no binding and no built-in decision", async () => {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const atlas = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = atlas.documents;
  const { service: shop } = manzanita({ fetch, clock, config: { consentPage: "https://hosted.example/consent?request={request_id}" } });
  sites["manzanita.example"] = shop;
  const query = new URLSearchParams({
    response_type: "code",
    client_id: atlas.clientId,
    scope: "orders:read",
    state: "s1",
    code_challenge: "c",
    code_challenge_method: "S256",
    redirect_uri: "https://atlas.example/oauth/callback",
  });
  const answer = await shop.handle({ method: "GET", url: `${AUTHORIZE}?${query}`, headers: {} });
  assert.equal(answer.status, 303);
  assert.equal(answer.headers["Set-Cookie"], undefined);
  const requestId = answer.headers.Location.split("=").at(-1);
  await assert.rejects(shop.consentDecision(post({ request_id: requestId, csrf: "x", decision: "allow" }, { cookie: "c" })));
});
