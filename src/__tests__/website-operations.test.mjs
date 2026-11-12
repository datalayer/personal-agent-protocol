/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Operations on a website: `Poppy-Operation`, the operations endpoint (Operations 4, 6, 7).
import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiClient,
  BROWSER_SIGN_IN_SCOPE,
  BrowserSessionClient,
  DeviceSignInClient,
  OPERATION_HEADER,
  OperationError,
  OperationsClient,
  PapSession,
  PersonalAgentProtocolError,
  SessionClient,
  SessionFetchClient,
  WebsiteOperations,
  agentInstruction,
  discoverCompany,
  negotiateExtensions,
  operationReferenceHeader,
  operationsEndpoint,
  parseOperationHeader,
} from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { ControlledBrowser } from "./support/controlled-browser.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const EXCHANGE_PAGE = "https://manzanita.example/orders/ord_7Hk2/exchange";
const ENDPOINT = "https://manzanita.example/poppy/operations";
const BROWSER_SESSION = "https://manzanita.example/poppy/browser-session";
/** The scopes for a signed-in browser join: poppy:browser-sign-in with the task's (§6). */
const BROWSE = ["orders:read", "orders:write", BROWSER_SIGN_IN_SCOPE];

async function world() {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock });
  sites["manzanita.example"] = shop;
  const browser = new ControlledBrowser(fetch);
  const host = await agentHost({ identity, fetch, clock, controlledBrowser: browser });
  const reactor = host.reactor;
  const transport = new SessionFetchClient({ reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor });
  const metadata = company.oauthMetadata;
  const sessions = new SessionClient({ reactor, fetch });
  const start = () =>
    sessions.start({
      clientId: identity.clientId,
      pairwiseUserId: PAIRWISE,
      issuer: metadata.issuer,
      tenantId: TENANT,
      extensions: negotiateExtensions(company.document.extensions, identity.supportedExtensions),
    });
  return { clock, fetch, identity, shop, plugin, reactor, browser, transport, company, metadata, start };
}

async function signedIn(w, scopes = BROWSE) {
  const session = await w.start();
  const device = new DeviceSignInClient({ reactor: w.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes,
    tenantId: TENANT,
    organization: w.company.document.organization,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return { session, token: done.token };
}

/** Sign in, then join the agent's browser to the Session (§6). */
async function joined(w, { signedIn: withToken = true, session: given } = {}) {
  const { session: started, token } = await signedIn(w);
  const session = given ? given(started) : started;
  const joins = new BrowserSessionClient({ reactor: w.reactor, transport: w.transport });
  await joins.join({
    browserSessionEndpoint: w.company.document.web.browser_session_endpoint,
    session,
    ...(withToken ? { token } : {}),
  });
  return { session, token, joins };
}

const website = (w, operations) =>
  new WebsiteOperations({
    api: new ApiClient({ transport: w.transport }),
    document: w.company.document,
    ...(operations === undefined ? {} : { operations }),
  });

async function pressExchange(browser) {
  await browser.get(EXCHANGE_PAGE);
  return browser.submit(EXCHANGE_PAGE, {});
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

test("the header is a Dictionary of two Strings", () => {
  const value = 'sid="ses_Hq3vT8nW2kLm9xRb", ref="exc_5Rt2.1791487200.k3Jd9Qx2mW8v"';
  assert.deepEqual(parseOperationHeader(value), { sid: "ses_Hq3vT8nW2kLm9xRb", ref: "exc_5Rt2.1791487200.k3Jd9Qx2mW8v" });
  const reference = { sid: "s", ref: "a.b" };
  assert.deepEqual(parseOperationHeader(operationReferenceHeader(reference)), reference);
  // Other members are ignored; anything that isn't a Dictionary is ignored whole.
  assert.deepEqual(parseOperationHeader('sid="s", ref="r", x=1'), { sid: "s", ref: "r" });
  for (const invalid of [
    undefined,
    null,
    "",
    'sid="s"',
    'ref="r"',
    "sid=s, ref=r",
    'sid="s", ref="has space"',
    'sid="s", ref="sl/ash"',
    `sid="s", ref="${"a".repeat(2049)}"`,
    'sid="s", ref="r",',
  ]) {
    assert.equal(parseOperationHeader(invalid), undefined, String(invalid));
  }
  assert.notEqual(parseOperationHeader(`sid="s", ref="${"a".repeat(2048)}"`), undefined);
  assert.throws(() => operationReferenceHeader({ sid: "s", ref: "no spaces" }), RangeError);
});

test("the company lists the endpoint with its browser-session endpoint", async () => {
  const w = await world();
  const document = w.company.document;
  assert.deepEqual(document.extensions.operations, [{ version: "3", endpoint: ENDPOINT }]);
  assert.equal(operationsEndpoint(document), ENDPOINT);
  // Without the browser-session endpoint the endpoint is not one to use (Operations 2).
  assert.equal(operationsEndpoint({ ...document, web: undefined }), undefined);
  const plain = { ...document, extensions: { ...document.extensions, operations: [{ version: "3" }] } };
  assert.equal(operationsEndpoint(plain), undefined);
  assert.equal(operationsEndpoint({ ...document, extensions: { operations: [{ version: "3", endpoint: "http://x.example/o" }] } }), undefined);
  assert.throws(
    () => new WebsiteOperations({ api: new ApiClient({ transport: w.transport }), document: plain }),
    (error) => error instanceof OperationError && error.code === "no_operations_endpoint",
  );
});

test("a website operation is approved at the endpoint and performed once", async () => {
  const w = await world();
  const { session, token, joins } = await joined(w);
  const page = await pressExchange(w.browser);
  // The website performs nothing: 403, a page for the browser, the reference in the header.
  assert.equal(page.status, 403);
  assert.ok(page.text.includes("waiting for your approval"));
  assert.equal(page.headers.get("cache-control"), "no-store");
  assert.deepEqual(w.plugin.executor.performed, []);
  const sites = website(w);
  const reference = WebsiteOperations.reference(page.headers, { joined: joins.joinedSessions(BROWSER_SESSION) });
  assert.equal(reference?.sid, session.sid);

  // The agent gets the operation at the endpoint, with the Session header and its token.
  const operation = await sites.operation(reference, { session, token });
  assert.deepEqual(operation.terms.price_difference, { amount: "70.00", currency: "USD" });
  const approval = await new OperationsClient({ reactor: w.reactor }).askUser(operation, {
    organization: w.company.document.organization,
    tenantId: session.tenantId,
    inputType: "tap",
  });
  const recorded = await sites.record(reference, approval, { session, token });
  assert.equal(recorded.status, 204);
  assert.equal(recorded.operation, undefined);
  // Recording performs nothing; a lookup says it is approved.
  assert.deepEqual(w.plugin.executor.performed, []);
  assert.equal(await sites.status(reference, { session, token }), "approved");
  // The same approval again is answered the same way.
  assert.equal((await sites.record(reference, approval, { session, token })).status, 204);

  // The browser makes the request again: performed once, with the approval recorded first.
  const done = await w.browser.submit(EXCHANGE_PAGE, { replacement: "ridge-insulated-m" });
  assert.equal(done.status, 200);
  assert.ok(done.text.includes("Exchanged the Ridge Jacket"));
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
  assert.equal(await sites.status(reference, { session, token }), "performed");
  const stored = await w.shop.operationRecord(operation.operation_id);
  assert.equal(stored.website, true);
  assert.deepEqual(stored.approval, { approver: "user", approved_at: approval.approved_at, input_type: "tap" });
  assert.equal(await sites.beforeApprovingAgain(reference, { session, token }), "performed");

  // The next request for it is a new action: a new operation, nothing performed twice.
  const after = await w.browser.submit(EXCHANGE_PAGE, { replacement: "ridge-insulated-m" });
  assert.equal(after.status, 403);
  const fresh = WebsiteOperations.reference(after.headers, { joined: [session.sid] });
  assert.ok(fresh !== undefined && fresh.ref !== reference.ref);
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
});

test("a page script gets JSON and the reference", async () => {
  const w = await world();
  const { session } = await joined(w);
  await w.browser.get(EXCHANGE_PAGE);
  const jar = w.browser.cookies.get("manzanita.example");
  const answer = await w.fetch(EXCHANGE_PAGE, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Origin: "https://manzanita.example",
      Cookie: [...jar].map(([name, value]) => `${name}=${value}`).join("; "),
    },
    body: "replacement=ridge-insulated-m",
  });
  assert.equal(answer.status, 403);
  assert.deepEqual(await answer.json(), { error: "approval_required" });
  assert.equal(parseOperationHeader(answer.headers.get(OPERATION_HEADER))?.sid, session.sid);
});

test("a reference is taken only from a joined Session", async () => {
  const w = await world();
  const { session } = await joined(w);
  const page = await pressExchange(w.browser);
  // A header naming a Session the agent didn't join this browser to is ignored.
  assert.equal(WebsiteOperations.reference(page.headers, { joined: ["another-sid"] }), undefined);
  assert.equal(WebsiteOperations.reference({}, { joined: [session.sid] }), undefined);
  assert.deepEqual(
    WebsiteOperations.reference({ "poppy-operation": page.headers.get(OPERATION_HEADER) }, { joined: [session.sid] }),
    parseOperationHeader(page.headers.get(OPERATION_HEADER)),
  );
});

test("the endpoint refuses what the Session cannot use", async () => {
  const w = await world();
  const { session, token, joins } = await joined(w);
  const page = await pressExchange(w.browser);
  const sites = website(w);
  const reference = WebsiteOperations.reference(page.headers, { joined: [session.sid] });
  assert.ok(reference !== undefined);
  for (const ref of ["op_unknown.rev_unknown", `${reference.ref.split(".")[0]}.rev_none`]) {
    const unusable = await refusal(sites.operation({ sid: session.sid, ref }, { session, token }));
    assert.equal(unusable.code, "invalid_reference");
  }
  // An API's operation is never approved at the endpoint (Operations 6).
  const asked = await new ApiClient({ transport: w.transport }).call(
    "POST",
    "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
    { session, token, body: {} },
  );
  assert.ok(asked.operation !== undefined);
  const apiRef = `${asked.operation.operation_id}.${asked.operation.revision}`;
  const foreign = await refusal(sites.operation({ sid: session.sid, ref: apiRef }, { session, token }));
  assert.equal(foreign.code, "invalid_reference");
  // A signed-out Session of the same agent and User gets a challenge for the account.
  const challenged = await refusal(sites.operation(reference, { session }));
  assert.equal(challenged.statusCode, 401);
  // Once its revision expired, the reference is unusable, and a lookup knows nothing of it.
  w.clock.advance(16 * 60);
  const expired = await refusal(sites.operation(reference, { session, token }));
  assert.equal(expired.code, "invalid_reference");
  assert.equal(await sites.status(reference, { session, token }), undefined);
  assert.deepEqual([...joins.joinedSessions(BROWSER_SESSION)], [session.sid]);
});

test("a website approval is never accepted at the API", async () => {
  const w = await world();
  const { session, token } = await joined(w);
  const page = await pressExchange(w.browser);
  const sites = website(w);
  const reference = WebsiteOperations.reference(page.headers, { joined: [session.sid] });
  const operation = await sites.operation(reference, { session, token });
  const answer = await new ApiClient({ transport: w.transport }).call(
    "POST",
    "https://manzanita.example/api/orders/ord_7Hk2/exchanges",
    { session, token, body: {}, approval: { operation_id: operation.operation_id, revision: operation.revision, approver: "user" } },
  );
  // Handled as a request without an approval: a new operation, nothing performed.
  assert.ok(answer.operation !== undefined);
  assert.notEqual(answer.operation.operation_id, operation.operation_id);
  assert.deepEqual(w.plugin.executor.performed, []);
});

test("an approval of another revision gets the operation, and nothing is recorded", async () => {
  const w = await world();
  const { session, token } = await joined(w);
  const page = await pressExchange(w.browser);
  const sites = website(w);
  const reference = WebsiteOperations.reference(page.headers, { joined: [session.sid] });
  const operation = await sites.operation(reference, { session, token });
  const wrong = { operation_id: operation.operation_id, revision: "rev_never", approver: "user" };
  const answered = await sites.record(reference, wrong, { session, token });
  assert.equal(answered.operation?.revision, operation.revision);
  assert.equal(await sites.status(reference, { session, token }), undefined);
  // The browser's request without a recorded approval asks again: nothing performed.
  const retried = await w.browser.submit(EXCHANGE_PAGE, { replacement: "ridge-insulated-m" });
  assert.equal(retried.status, 403);
  assert.deepEqual(w.plugin.executor.performed, []);
});

test("an agent approval makes the next revision the User's", async () => {
  const w = await world();
  const { session, token } = await joined(w);
  const page = await pressExchange(w.browser);
  const operations = new OperationsClient({ reactor: w.reactor });
  const sites = website(w, operations);
  const reference = WebsiteOperations.reference(page.headers, { joined: [session.sid] });
  const operation = await sites.operation(reference, { session, token });
  const instruction = agentInstruction("Go ahead with exchanges under $100", () => true);
  const approval = await operations.approveAsAgent(operation, { instruction });
  const sent = await operations.send((approved) => sites.record(reference, approved, { session, token }), approval);
  assert.equal(sent.status, "answered");
  assert.equal(sent.answer.status, 204);
  assert.ok(operations.userOnly.has(operation.operation_id));
  const refused = await refusal(operations.approveAsAgent(operation, { instruction }));
  assert.equal(refused.code, "ask_user");
});

test("a browser without Operations gets the website's own flow", async () => {
  const w = await world();
  // A join whose Session declares no Operations extension.
  await joined(w, { session: (started) => new PapSession({ ...started, extensions: {} }) });
  const page = await pressExchange(w.browser);
  assert.equal(page.status, 403);
  assert.equal(page.headers.get(OPERATION_HEADER), null);
  assert.ok(page.text.includes("Confirm the exchange on manzanita.example"));
  // A visitor that never joined is sent to sign in.
  const visitor = new ControlledBrowser(w.fetch);
  await visitor.get(EXCHANGE_PAGE);
  const refused = await visitor.submit(EXCHANGE_PAGE, {});
  assert.equal(refused.status, 401);
  assert.deepEqual(w.plugin.executor.performed, []);
});

test("the endpoint needs the Operations declaration", async () => {
  const w = await world();
  const { session, token } = await joined(w);
  const page = await pressExchange(w.browser);
  const reference = parseOperationHeader(page.headers.get(OPERATION_HEADER));
  const plain = new PapSession({ ...session, extensions: {} });
  const refused = await refusal(website(w).operation(reference, { session: plain, token }));
  assert.equal(refused.code, "operations_not_declared");
  const raw = await w.transport.request("POST", ENDPOINT, {
    session: plain,
    token,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ref: reference.ref }),
  });
  assert.equal(raw.status, 403);
  assert.equal((await raw.json()).error, "extension_required");
});
