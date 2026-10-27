/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Guide-level behaviour at the TypeScript reference company: overlapping JWKS
// (operational-limits.mdx) and the consent page's CSRF binding and framing (company.mdx).
import assert from "node:assert/strict";
import test from "node:test";

import { DirectSignInClient, SessionClient, discoverCompany } from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { CONSENT_COOKIE } from "../../lib/server.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const AUTHORIZE = "https://manzanita.example/oauth/authorize";
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
  /** A Session started by an agent signing with `identity`'s key (on `agent`, else its own host). */
  const start = async (identity, agent) => {
    agent ??= await agentHost({ identity, fetch, clock });
    return new SessionClient({ reactor: agent.reactor, fetch }).start({
      clientId: identity.clientId,
      pairwiseUserId: PAIRWISE,
      issuer: metadata.issuer,
      tokenEndpoint: metadata.token_endpoint,
      tenantId: TENANT,
    });
  };
  const rotated = (kid) => agentIdentity({ domain: "atlas.example", name: "Atlas", kid });
  return { clock, fetch, atlas, site, shop, host, metadata, start, rotated };
}

test("overlapping JWKS: either key verifies during the overlap, the retired one after it is refused", async () => {
  const w = await world(600);
  await w.start(w.atlas); // signed with key-1: the company caches [key-1]
  assert.equal(w.site.jwksFetches, 1);
  const newer = await w.rotated("key-2");

  w.site.keys = [...w.atlas.jwks.keys, ...newer.jwks.keys];
  assert.equal((await w.start(newer)).signedIn, false);
  assert.equal(w.site.jwksFetches, 2); // the unknown kid fetched the set again, at once
  assert.equal((await w.start(w.atlas)).signedIn, false);
  assert.equal((await w.start(newer)).signedIn, false);
  assert.equal(w.site.jwksFetches, 2);

  // Retired: still verified until the cached set expires (its max-age), refused after.
  w.site.keys = [...newer.jwks.keys];
  w.clock.advance(599);
  assert.equal((await w.start(w.atlas)).signedIn, false);
  w.clock.advance(2);
  await assert.rejects(w.start(w.atlas), (error) => error.code === "invalid_client");
  assert.equal((await w.start(newer)).signedIn, false);
});

test("unknown kids fetch the set again at most once a minute", async () => {
  const w = await world(3600);
  await w.start(w.atlas);
  assert.equal(w.site.jwksFetches, 1);
  for (let index = 0; index < 20; index += 1) {
    await assert.rejects(w.start(await w.rotated(`forged-${index}`)), (error) => error.code === "invalid_client");
  }
  assert.equal(w.site.jwksFetches, 2);
  const newer = await w.rotated("key-2");
  w.site.keys = [...w.atlas.jwks.keys, ...newer.jwks.keys];
  await assert.rejects(w.start(newer));
  assert.equal(w.site.jwksFetches, 2);
  w.clock.advance(61);
  assert.equal((await w.start(newer)).signedIn, false);
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
  // On the host that signs in: the Session Key is that host's (§4.3).
  const session = await w.start(w.atlas, w.host);
  const client = new DirectSignInClient({ reactor: w.host.reactor, fetch: w.fetch });
  await client.begin({
    authorizationEndpoint: w.metadata.authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.atlas.clientId,
    redirectUri: "https://atlas.example/oauth/callback",
    scopes: ["orders:read"],
    tenantId: TENANT,
    sessionKey: session.sessionKey,
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
  assert.equal((await client.complete({ callbackUrl })).token.signedIn, true);
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
