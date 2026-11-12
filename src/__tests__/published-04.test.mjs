/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Version 0.4 as published (upstream 4803900): what changed after draft 0.4 as of 46beb21,
// apart from Operations version 3 (operations-v3.test.mjs).
//
// Task coverage per Session, the Session header on website pages fetched without a browser,
// sign-ins someone else started, scopes in the protected resource metadata, the issuer's
// client ID metadata document flag, and the tasks endpoint as a Session header destination.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  AuthorizationError,
  CROSS_DEVICE_LIFETIME_SECONDS,
  DeviceSignInClient,
  DirectSignInClient,
  FeedbackClient,
  PageClient,
  PapSession,
  TasksClient,
  TasksError,
  TransportError,
  fetchSkill,
  pageCarriesSession,
  parseDiscoveryDocument,
  parseOAuthServerMetadata,
  parseProtectedResourceMetadata,
  parseTasksResponse,
  scopesSupported,
  sessionHeaders,
  tasksEndpoint,
  usableSkills,
} from "../../lib/index.js";
import { CompanyConfig, connectCaution, connectHeading } from "../../lib/server.js";
import { CONFIG_OPTIONS } from "../../lib/demo/manzanita.js";
import { TENANT, counting, mockTransport, rejection, shopWorld, signedIn } from "./support/shop.mjs";

const TASKS = "https://manzanita.example/poppy/tasks";
const FEEDBACK = "https://manzanita.example/poppy/feedback";
const SKILL = "---\nname: exchange-a-jacket\n---\nAsk for the order, then POST an exchange.\n";
const REDIRECT = "https://atlas.example/oauth/callback";

const fixture = (name) => JSON.parse(readFileSync(new URL(`../../protocol/fixtures/${name}`, import.meta.url), "utf8"));
const withSkills = () => shopWorld({ config: { skills: [["exchange-a-jacket", "Exchange a jacket for another size.", SKILL]] } });
const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const lower = (headers) => Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value]));

/** The same Session with something changed: what the SDK would never send. */
const changed = (session, change) =>
  new PapSession({
    sid: session.sid,
    sub: session.sub,
    issuer: session.issuer,
    clientId: session.clientId,
    tenantId: session.tenantId,
    extensions: session.extensions,
    ...change,
  });

// Task coverage per Session (§9) --------------------------------------------------------------

test("poppy.json names a tasks endpoint and nothing it moved", async () => {
  const w = await withSkills();
  const document = w.shop.discoveryDocument();
  assert.deepEqual(document.tasks, { endpoint: TASKS });
  for (const moved of ["excluded_tasks", "skill_index", "feedback"]) assert.equal(moved in document, false, moved);
  assert.equal(tasksEndpoint(w.company.document), TASKS);
  assert.deepEqual(Object.keys(w.shop.tasksDocument()).sort(), ["excluded_tasks", "feedback", "skill_index"]);
  // A company with nothing to say there lists no endpoint and serves none.
  const quiet = await shopWorld({ config: { excludedTasks: [], feedback: false } });
  assert.equal(quiet.shop.config.servesTasks, false);
  assert.equal("tasks" in quiet.shop.discoveryDocument(), false);
  assert.equal(tasksEndpoint(quiet.company.document), undefined);
  assert.equal((await quiet.fetch(TASKS)).status, 404);
  // What it served before is gone.
  assert.equal((await w.fetch("https://manzanita.example/poppy/excluded-tasks.json")).status, 404);
});

test("the tasks response is fetched with the Session header and no token", async () => {
  // `GET {tasks.endpoint}` with the Session header, never an access token, also in a signed-in
  // Session; the response lists excluded tasks, skills and the feedback endpoint, a skill's
  // `url` resolved against `tasks.endpoint` (§9, §9.4).
  const w = await withSkills();
  const { session, token } = await signedIn(w);
  const seen = [];
  const watching = mockTransport(w, (url, init) => {
    seen.push([init.method, url.toString(), new Headers(init.headers)]);
    return w.fetch(url, init);
  });
  const sent = counting(watching);
  const tasks = await new TasksClient({ transport: watching }).get(w.company, { session });
  assert.deepEqual(sent, [["GET", TASKS, false]]);
  const [[, , headers]] = seen;
  assert.ok(headers.has("poppy-session") && headers.get("poppy-version") === "0.4");
  assert.equal(headers.has("authorization"), false);
  assert.deepEqual([tasks.available, tasks.session, tasks.endpoint], [true, session.sid, TASKS]);
  assert.deepEqual(tasks.excludedTasks.map((task) => task.task), ["Change the size of an item after it has shipped"]);
  const [skill] = tasks.skills;
  assert.equal(tasks.skills.length, 1);
  assert.equal(skill.url, "https://manzanita.example/poppy/skills/exchange-a-jacket/SKILL.md");
  assert.equal(new TextDecoder().decode(await fetchSkill(skill, { reactor: w.reactor })), SKILL);
  assert.equal(tasks.feedbackEndpoint, FEEDBACK);
  // The feedback endpoint from the response is a Session header destination (§5.2).
  await new FeedbackClient({ transport: w.transport }).report(
    tasks.feedbackEndpoint,
    { task: "Track a parcel", description: "No tracking anywhere." },
    { session, token },
  );
  // The company marks it private: a shared cache never hands it to another Session.
  const raw = await w.transport.request("GET", TASKS, { session });
  assert.equal(raw.status, 200);
  assert.equal(raw.headers.get("cache-control"), "private, max-age=300");
  const response = parseTasksResponse(await raw.json());
  assert.ok(response.feedback !== undefined);
  assert.deepEqual(response, w.shop.tasksDocument());
  // The same document through the company or its discovery document.
  assert.deepEqual((await new TasksClient({ transport: w.transport }).get(w.company.document, { session })).response, tasks.response);
});

test("a tasks response is kept for its Session and never used in another", async () => {
  const w = await shopWorld();
  const first = await w.start();
  const second = await w.start();
  assert.notEqual(first.sid, second.sid);
  const sent = counting(w.transport);
  const client = new TasksClient({ transport: w.transport });
  const one = await client.get(w.company, { session: first });
  assert.equal(await client.get(w.company, { session: first }), one);
  // Reused in its Session, as its caching headers allow.
  assert.equal(sent.length, 1);
  const two = await client.get(w.company, { session: second });
  assert.notEqual(two, one);
  assert.deepEqual([two.session, sent.length], [second.sid, 2]);
  // `fresh` reads it again; so does the end of what `Cache-Control` allowed (max-age=300).
  await client.get(w.company, { session: first, fresh: true });
  assert.equal(sent.length, 3);
  w.clock.advance(301);
  await client.get(w.company, { session: first });
  assert.equal(sent.length, 4);
  // Another User ID with the same `sid` is another Session too.
  await client.get(w.company, { session: changed(first, { sub: "usr_somebody_else_000000" }) });
  assert.equal(sent.length, 5);
  client.forget(first);
  await client.get(w.company, { session: first });
  assert.equal(sent.length, 6);
  // Forgetting one Session leaves the other's.
  await client.get(w.company, { session: second });
  assert.equal(sent.length, 7); // its own five minutes had passed
  await client.get(w.company, { session: second });
  client.forget(first);
  await client.get(w.company, { session: second });
  assert.equal(sent.length, 7);
});

for (const [name, answer] of [
  ["404", () => json({ error: "not_found" }, 404)],
  ["500", () => new Response(null, { status: 500 })],
  ["a body that is not JSON", () => new Response("<html>not json</html>", { status: 200 })],
  ["a body that is not an object", () => json(["not", "an", "object"])],
  ["a malformed task", () => json({ excluded_tasks: [{ task: "" }] })],
  ["a feedback endpoint that is not HTTPS", () => json({ feedback: { endpoint: "http://manzanita.example/poppy/feedback" } })],
  ["a redirect", () => new Response(null, { status: 302, headers: { Location: "https://elsewhere.example/tasks" } })],
  ["429", () => new Response(null, { status: 429, headers: { "Retry-After": "30" } })],
  ["a network failure", () => { throw new TypeError("the network is down"); }],
]) {
  test(`with no response the agent carries on as if nothing were listed: ${name}`, async () => {
    // No excluded tasks, no skills, no feedback (§9); a redirect is refused, never followed
    // (§3): nothing is sent to the new URL.
    const w = await shopWorld();
    const session = await w.start();
    const seen = [];
    const client = new TasksClient({
      transport: mockTransport(w, (url) => {
        seen.push(url.toString());
        return answer();
      }),
    });
    const tasks = await client.get(w.company, { session });
    assert.deepEqual([tasks.session, tasks.endpoint, tasks.available], [session.sid, TASKS, false]);
    assert.deepEqual([tasks.excludedTasks, tasks.skills, tasks.feedbackEndpoint], [[], [], undefined]);
    assert.deepEqual(tasks.response, { excluded_tasks: [] });
    assert.deepEqual([...new Set(seen)], [TASKS]);
    // Nothing is kept of an answer that was none: the next task asks again, though never
    // sooner than a `Retry-After` the company gave (§5.6).
    const again = await client.get(w.company, { session });
    assert.equal(again.available, false);
    assert.equal(seen.length, name === "429" ? 1 : 2);
  });
}

test("a refused Session header at the tasks endpoint is raised", async () => {
  const w = await shopWorld();
  const session = await w.start();
  for (const error of ["invalid_session", "version_unsupported"]) {
    const client = new TasksClient({ transport: mockTransport(w, () => json({ error }, 400)) });
    const raised = await rejection(client.get(w.company, { session }));
    assert.ok(raised instanceof TasksError);
    assert.deepEqual([raised.code, raised.statusCode], [error, 400]);
  }
  // The company's own: a header signed for another URL fails its checks.
  const wrong = await sessionHeaders(w.reactor, "GET", FEEDBACK, { session });
  const refused = await w.fetch(TASKS, { headers: wrong });
  assert.deepEqual([refused.status, await refused.json()], [400, { error: "invalid_session" }]);
  // No header at all.
  assert.equal((await w.fetch(TASKS)).status, 400);
});

test("a company with no tasks endpoint gives an empty answer without a request", async () => {
  const document = parseDiscoveryDocument({ protocol_version: "0.4", organization: { name: "X", domain: "x.example" }, web: {} });
  assert.equal(tasksEndpoint(document), undefined);
  const w = await shopWorld();
  const session = await w.start();
  const client = new TasksClient({ transport: mockTransport(w, () => assert.fail("no request is made")) });
  const tasks = await client.get(document, { session });
  assert.deepEqual([tasks.session, tasks.endpoint, tasks.available], [session.sid, undefined, false]);
  assert.deepEqual([tasks.excludedTasks, tasks.skills, tasks.feedbackEndpoint], [[], [], undefined]);
  // What poppy.json carried before is not read from it.
  const old = parseDiscoveryDocument({
    protocol_version: "0.4",
    organization: { name: "X", domain: "x.example" },
    web: {},
    feedback: { endpoint: "https://x.example/poppy/feedback" },
    excluded_tasks: { url: "https://x.example/poppy/excluded-tasks.json" },
    skill_index: fixture("tasks-valid.json").skill_index,
  });
  assert.equal(tasksEndpoint(old), undefined);
  assert.equal((await client.get(old, { session })).available, false);
  assert.deepEqual(usableSkills(parseTasksResponse(fixture("tasks-valid.json")), TASKS).map((skill) => skill.name), ["manage-bookings"]);
});

// Website pages fetched without a browser (§5.2) ----------------------------------------------

for (const [url, carries] of [
  ["https://manzanita.example/help/returns", true],
  ["https://MANZANITA.example/help", true],
  ["https://manzanita.example:443/help", true],
  ["https://www.manzanita.example/help", false], // another host on its domain
  ["https://help.manzanita.example/", false],
  ["https://manzanita.example:8443/help", false],
  ["http://manzanita.example/help", false],
  ["https://manzanita.example.evil.example/help", false],
  ["https://user@manzanita.example/help", false],
  ["not a url", false],
]) {
  test(`only pages on the host that served poppy.json carry the header: ${url}`, () => {
    assert.equal(pageCarriesSession(url, "manzanita.example"), carries);
  });
}

/** Manzanita's website, with the company verifying the Session header when one is sent. */
function site(w) {
  const requests = [];
  const sessions = [];
  const handler = async (url, init) => {
    const headers = new Headers(init.headers);
    requests.push({ url: url.toString(), headers });
    if (url.hostname === "manzanita.example") {
      const checked = await w.shop.pageSession({ method: init.method ?? "GET", url: url.toString(), headers: Object.fromEntries(headers) });
      if (checked !== undefined && "status" in checked) return json(checked.body, checked.status);
      sessions.push(checked);
      if (url.pathname === "/old-returns") return new Response(null, { status: 301, headers: { Location: "/help/returns" } });
      if (url.pathname === "/blog") return new Response(null, { status: 302, headers: { Location: "https://blog.example/returns" } });
      return new Response("<h1>Returns</h1>", { status: 200, headers: { "content-type": "text/html" } });
    }
    if (url.hostname === "blog.example") return new Response("<h1>The blog</h1>", { status: 200 });
    return new Response(null, { status: 404 });
  };
  return { requests, sessions, pages: new PageClient({ transport: mockTransport(w, handler) }) };
}

test("a page fetched without a browser carries the Session header, signed out", async () => {
  // The header, `Poppy-Version` and no access token, even in a signed-in Session; the company
  // verifies it and reads the request as signed out (§5.2, §5.3).
  const w = await shopWorld();
  const { session } = await signedIn(w);
  const { requests, sessions, pages } = site(w);
  const page = await pages.fetch("https://manzanita.example/help/returns", { session, company: w.company });
  assert.deepEqual(
    [page.url, page.statusCode, new TextDecoder().decode(page.content), page.sessionHeaderSent, page.invalidSession],
    ["https://manzanita.example/help/returns", 200, "<h1>Returns</h1>", true, false],
  );
  assert.equal(page.headers["content-type"], "text/html");
  const [request] = requests;
  assert.equal(requests.length, 1);
  assert.ok(request.headers.has("poppy-session"));
  assert.equal(request.headers.get("poppy-version"), "0.4");
  assert.equal(request.headers.has("authorization"), false);
  assert.equal(request.headers.has("dpop"), false);
  const [caller] = sessions;
  assert.deepEqual([caller.sid, caller.accountId, [...caller.scopes]], [session.sid, undefined, []]);
  // No header, no Session: an ordinary visitor.
  assert.equal(await w.shop.pageSession({ method: "GET", url: "https://manzanita.example/help", headers: {} }), undefined);
});

test("a redirect gets a new Session JWT only on the same host", async () => {
  const w = await shopWorld();
  const session = await w.start();
  const { requests, sessions, pages } = site(w);
  const same = await pages.fetch("https://manzanita.example/old-returns", { session, company: w.company.document });
  assert.deepEqual([same.url, same.sessionHeaderSent], ["https://manzanita.example/help/returns", true]);
  const [first, second] = requests;
  // Each signed for its own URL: the second would fail the company's check otherwise.
  assert.notEqual(first.headers.get("poppy-session"), second.headers.get("poppy-session"));
  assert.equal(sessions.length, 2);

  requests.length = 0;
  const away = await pages.fetch("https://manzanita.example/blog", { session, company: w.company });
  assert.deepEqual([away.url, away.sessionHeaderSent], ["https://blog.example/returns", false]);
  const [atCompany, elsewhere] = requests;
  assert.ok(atCompany.headers.has("poppy-session"));
  assert.equal(elsewhere.headers.has("poppy-session"), false);
  assert.equal(elsewhere.headers.has("poppy-version"), false);

  // A page on another host is an ordinary fetch: no header from the start.
  requests.length = 0;
  const other = await pages.fetch("https://blog.example/x", { session, company: w.company });
  assert.equal(other.sessionHeaderSent, false);
  assert.equal(requests[0].headers.has("poppy-session"), false);
  for (const url of ["http://manzanita.example/help", "https://user@manzanita.example/help", "not a url"]) {
    const raised = await rejection(pages.fetch(url, { session, company: w.company }));
    assert.ok(raised instanceof TransportError);
    assert.equal(raised.code, "invalid_url");
  }
  // Every hop passes the host's URL safety policy, and redirects end somewhere.
  const local = await rejection(pages.fetch("https://127.0.0.1/help", { session, company: w.company }));
  assert.ok(local instanceof Error);
  const looping = new PageClient({
    transport: mockTransport(w, (url) => new Response(null, { status: 302, headers: { Location: `${url.pathname}x` } })),
    maxRedirects: 2,
  });
  assert.equal((await rejection(looping.fetch("https://blog.example/a", { session, company: w.company }))).code, "too_many_redirects");
  const nowhere = new PageClient({ transport: mockTransport(w, () => new Response(null, { status: 302 })) });
  assert.equal((await rejection(nowhere.fetch("https://blog.example/a", { session, company: w.company }))).code, "invalid_redirect");
  const large = new PageClient({ transport: mockTransport(w, () => new Response("x".repeat(65))), maxResponseBytes: 64 });
  assert.equal((await rejection(large.fetch("https://blog.example/a", { session, company: w.company }))).code, "response_too_large");
  assert.throws(() => new PageClient({ transport: w.transport, maxRedirects: -1 }), RangeError);
});

test("discovery and description documents and OAuth endpoints never carry the header", async () => {
  // The header is for website pages, "not the documents above" (§5.2): poppy.json, protected
  // resource and issuer metadata, an API's description, and the issuer's endpoints are fetched
  // without it, on the company's own host too.
  const w = await shopWorld();
  const session = await w.start();
  const carried = [];
  const pages = new PageClient({
    transport: mockTransport(w, (url, init) => {
      carried.push([url.pathname, new Headers(init.headers).has("poppy-session")]);
      return new Response("{}", { status: 200 });
    }),
  });
  const openapi = w.company.document.apis.find((api) => api.type === "openapi").url;
  for (const url of [
    "https://manzanita.example/.well-known/poppy.json",
    "https://manzanita.example/.well-known/oauth-protected-resource",
    "https://manzanita.example/.well-known/oauth-authorization-server",
    `${openapi}?v=2`,
    w.metadata.token_endpoint,
    w.metadata.authorization_endpoint,
  ]) {
    const page = await pages.fetch(url, { session, company: w.company });
    assert.equal(page.sessionHeaderSent, false, url);
  }
  assert.ok(carried.every(([, header]) => header === false));
  // A page beside them carries it.
  assert.equal((await pages.fetch("https://manzanita.example/api-docs", { session, company: w.company })).sessionHeaderSent, true);
});

test("invalid_session from a page is reported, and the page fetched again on request", async () => {
  // A page that verifies the header answers a failed check with `invalid_session`, so the agent
  // learns of its mistake; it MAY then fetch the page again without the header (§5.2). The
  // client never leaves the header out on its own.
  const w = await shopWorld();
  const session = await w.start();
  const seen = [];
  const pages = new PageClient({
    transport: mockTransport(w, (_url, init) => {
      const carried = new Headers(init.headers).has("poppy-session");
      seen.push(carried);
      return carried ? json({ error: "invalid_session" }, 400) : new Response("<h1>Returns</h1>", { status: 200 });
    }),
  });
  const url = "https://manzanita.example/help/returns";
  const told = await pages.fetch(url, { session, company: w.company });
  assert.deepEqual([told.statusCode, told.invalidSession, told.sessionHeaderSent], [400, true, true]);
  assert.deepEqual(seen, [true]);
  const again = await pages.fetch(url, { session, company: w.company, againWithoutHeader: true });
  assert.deepEqual([again.statusCode, again.invalidSession, again.sessionHeaderSent], [200, true, false]);
  assert.deepEqual(seen, [true, true, false]);
});

test("the company answers a bad page header with invalid_session", async () => {
  const w = await shopWorld();
  const { session, token } = await signedIn(w);
  const url = "https://manzanita.example/help/returns";
  const other = await sessionHeaders(w.reactor, "GET", "https://manzanita.example/x", { session });
  const refused = await w.shop.pageSession({ method: "GET", url, headers: lower(other) });
  assert.deepEqual([refused.status, refused.body], [400, { error: "invalid_session" }]);
  // An access token never goes with a page: a Session JWT made with one carries `ath`, and
  // without the token the company can't match it.
  const withToken = await sessionHeaders(w.reactor, "GET", url, { session, token });
  const mismatched = await w.shop.pageSession({ method: "GET", url, headers: lower(withToken) });
  assert.deepEqual([mismatched.status, mismatched.body], [400, { error: "invalid_session" }]);
  // A Session the company ended says so.
  const fine = await sessionHeaders(w.reactor, "GET", url, { session });
  assert.equal((await w.shop.pageSession({ method: "GET", url, headers: lower(fine) })).sid, session.sid);
  assert.equal(await w.shop.endSession(session.clientId, session.sid, session.sub), true);
  const later = await sessionHeaders(w.reactor, "GET", url, { session });
  const ended = await w.shop.pageSession({ method: "GET", url, headers: lower(later) });
  assert.deepEqual([ended.status, ended.body], [400, { error: "session_ended" }]);
});

// Sessions found by client_id, sid and User ID (§5.3) -----------------------------------------

test("a known sid with another User ID is another Session, signed out", async () => {
  const w = await shopWorld();
  const { session, token } = await signedIn(w);
  const ORDERS = "https://manzanita.example/api/orders";
  assert.equal((await w.api.call("GET", ORDERS, { session, token })).status, 200);
  const known = w.shop.store.keys("session").length;
  const other = changed(session, { sub: "usr_somebody_else_000000" });
  const answered = await w.fetch(ORDERS, { headers: await sessionHeaders(w.reactor, "GET", ORDERS, { session: other }) });
  // Answered as any new signed-out Session is: the challenge for the account, no error.
  assert.equal(answered.status, 401);
  assert.equal(await answered.text(), "");
  assert.equal(w.shop.store.keys("session").length, known + 1);
  // Ending one leaves the other (§5.5).
  assert.equal(await w.shop.endSession(other.clientId, other.sid, other.sub), true);
  assert.equal((await w.api.call("GET", ORDERS, { session, token })).status, 200);
  assert.equal(session.sid, other.sid);
  assert.equal(await w.shop.endSession(session.clientId, session.sid, "usr_nobody_at_all_0000000"), false);
});

// Device Sign-In link hosts (§4.3) ------------------------------------------------------------

test("a company's device page is on its own domain, not an alias", () => {
  const config = (devicePage, more = {}) => new CompanyConfig({ ...CONFIG_OPTIONS, devicePage, ...more });
  assert.equal(config("https://manzanita.example/device").devicePage, "https://manzanita.example/device");
  assert.equal(config("https://id.manzanita.example/device").devicePage, "https://id.manzanita.example/device");
  // An agent that found the company at an alias knows only that alias as its domain.
  assert.throws(() => config("https://manzanita.shop/device", { aliases: ["manzanita.shop"] }), RangeError);
  assert.throws(() => config("https://elsewhere.example/device"), RangeError);
});

// Sign-ins someone else started (§4.2, §10.8) -------------------------------------------------

function begin(w, more = {}) {
  const client = new DirectSignInClient({ reactor: w.reactor, fetch: w.fetch });
  return client
    .begin({
      authorizationEndpoint: w.metadata.authorization_endpoint,
      tokenEndpoint: w.metadata.token_endpoint,
      issuer: w.metadata.issuer,
      clientId: w.identity.clientId,
      redirectUri: REDIRECT,
      scopes: ["orders:read"],
      tenantId: TENANT,
      ...more,
    })
    .then((started) => ({ client, started }));
}

test("the company's page names the agent and says when to continue", async () => {
  // The sign-in and consent page starts with a heading that names the personal agent and says
  // it wants to connect, never "Sign in with …", and tells the person to continue only if they
  // just asked that agent (§10.8; guides, consent pages).
  const w = await shopWorld();
  await begin(w);
  const page = w.host.browser.pages.at(-1);
  assert.ok(page.includes("<h1>Atlas wants to connect to your Manzanita Outfitters account</h1>"));
  assert.ok(page.includes("<p>Only continue if you asked Atlas to do this just now.</p>"));
  assert.ok(!page.includes("Sign in with") && page.includes("<title>Connect</title>"));
  assert.ok(page.indexOf("<h1>") < page.indexOf("asks to:"));
  // A hosted consent page gets the same words to show.
  const request = await w.shop.authorizationRequest(w.host.browser.requestId);
  assert.equal(request.heading, connectHeading("Atlas", "Manzanita Outfitters"));
  assert.equal(request.caution, connectCaution("Atlas"));
});

test("a device verification page can name the agent too", async () => {
  const w = await shopWorld();
  const started = await new DeviceSignInClient({ reactor: w.reactor, fetch: w.fetch }).begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes: ["orders:read"],
    tenantId: TENANT,
    organization: w.company.document.organization,
  });
  const request = await w.shop.deviceRequest(started.userCode);
  assert.equal(request.heading, "Atlas wants to connect to your Manzanita Outfitters account");
  assert.equal(request.caution, "Only continue if you asked Atlas to do this just now.");
  assert.deepEqual([request.client_name, request.client_domain], ["Atlas", "atlas.example"]);
  assert.deepEqual(request.scopes, [{ scope: "orders:read", description: "See your orders, returns and exchanges" }]);
  assert.match(request.expires_at, /Z$/);
  // Not consumed by reading it.
  assert.deepEqual(await w.shop.deviceRequest(started.userCode), request);
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  await assert.rejects(w.shop.deviceRequest(started.userCode), /unknown, used, or expired user code/);
  await assert.rejects(w.shop.deviceRequest("NOPE-NOPE"), /unknown, used, or expired user code/);
});

test("a redirect that arrives for another User gets no tokens", async () => {
  // A host that can tell which of its Users is in the browser at `redirect_uri` checks it is
  // the one who started the sign-in: a forwarded link then fails (§4.2, §10.8).
  const w = await shopWorld();
  const { client } = await begin(w);
  const callbackUrl = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  const raised = await rejection(client.complete({ callbackUrl, completedBy: "somebody-else" }));
  assert.ok(raised instanceof AuthorizationError);
  assert.equal(raised.code, "sign_in_started_by_another_user");
  // The state is used up: the same redirect can't be completed afterwards either.
  assert.equal((await rejection(client.complete({ callbackUrl, completedBy: TENANT }))).code, "invalid_or_expired_state");

  const { client: second } = await begin(w);
  const callback = await w.shop.approveAuthorization(w.host.browser.requestId, { accountId: "acct_ada" });
  const done = await second.complete({ callbackUrl: callback, completedBy: TENANT });
  assert.ok(done.token !== undefined);
});

test("a Direct Sign-In opened on another device is short-lived", async () => {
  // Opened on another device, Direct Sign-In is a cross-device flow (§4.2): its request lives
  // at most `CROSS_DEVICE_LIFETIME_SECONDS` (RFC 10027 §2).
  const w = await shopWorld();
  const seconds = (started) => (started.expiresAt.getTime() - w.clock.now().getTime()) / 1000;
  const { started } = await begin(w, { crossDevice: true });
  assert.equal(started.crossDevice, true);
  assert.deepEqual([seconds(started), CROSS_DEVICE_LIFETIME_SECONDS], [300, 300]);
  await assert.rejects(begin(w, { crossDevice: true, lifetimeSeconds: 600 }), RangeError);
  assert.equal(seconds((await begin(w, { crossDevice: true, lifetimeSeconds: 120 })).started), 120);
  const { started: sameDevice } = await begin(w);
  assert.equal(sameDevice.crossDevice, false);
  assert.equal(seconds(sameDevice), 600);
  await assert.rejects(begin(w, { lifetimeSeconds: 901 }), RangeError);
});

// Scopes, and what the issuer says for other clients (§3.2, §4.7) -----------------------------

test("the scopes a company lists come from either metadata, or both", async () => {
  // `scopes_supported` in the issuer's metadata, in the domain's protected resource metadata,
  // or in both: the agent uses the scopes in either list (§4.7).
  const w = await shopWorld();
  const oauthMetadata = parseOAuthServerMetadata({
    ...w.shop.oauthMetadata(),
    issuer: "https://auth.example.com",
    scopes_supported: ["orders:read", "poppy:browser-sign-in"],
  });
  const company = {
    discoveryUrl: "https://example.com/.well-known/poppy.json",
    document: parseDiscoveryDocument(fixture("discovery-valid.json")),
    oauthMetadata,
    resourceMetadata: parseProtectedResourceMetadata({
      resource: "https://example.com",
      authorization_servers: ["https://auth.example.com"],
      scopes_supported: ["orders:read", "orders:write", "addresses"],
    }),
  };
  assert.deepEqual(scopesSupported(company), ["orders:read", "poppy:browser-sign-in", "orders:write", "addresses"]);
  const { scopes_supported: _listed, ...unlisted } = oauthMetadata;
  assert.deepEqual(scopesSupported({ ...company, oauthMetadata: unlisted }), ["orders:read", "orders:write", "addresses"]);
  const { resourceMetadata: _resource, ...onlyIssuer } = company;
  assert.deepEqual(scopesSupported(onlyIssuer), ["orders:read", "poppy:browser-sign-in"]);
  assert.deepEqual(scopesSupported({ discoveryUrl: company.discoveryUrl, document: company.document }), []);
});

test("the reference company lists its scopes in both and says it reads client ID metadata documents", async () => {
  const w = await shopWorld();
  const issuer = w.shop.oauthMetadata();
  const resource = w.shop.domainResourceMetadata();
  assert.deepEqual(issuer.scopes_supported, resource.scopes_supported);
  assert.deepEqual([...scopesSupported(w.company)].sort(), [...issuer.scopes_supported].sort());
  // For other clients, such as MCP clients (guides; the CIMD draft's §8).
  assert.equal(issuer.client_id_metadata_document_supported, true);
  assert.equal(w.company.oauthMetadata.client_id_metadata_document_supported, true);
});
