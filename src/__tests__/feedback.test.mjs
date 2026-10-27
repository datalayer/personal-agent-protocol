/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Feedback (§8): a task the protocol can't do, reported once, as data. The port of
// personal_agent_protocol/__tests__/test_feedback.py.
import assert from "node:assert/strict";
import test from "node:test";

import {
  DeviceSignInClient,
  DpopFetchClient,
  FEEDBACK_DESCRIPTION_MAX_LENGTH,
  FEEDBACK_TASK_MAX_LENGTH,
  FeedbackClient,
  FeedbackError,
  SessionClient,
  discoverCompany,
  feedbackEndpoint,
  parseDiscoveryDocument,
  parseFeedbackReport,
  usableReferences,
} from "../../lib/index.js";
import { CompanyRateLimits } from "../../lib/server.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";
const FEEDBACK = "https://manzanita.example/poppy/feedback";
const GIFT_CARD = {
  task: "Pay with a gift card",
  description:
    "The User wanted to pay for a new order with a gift card they were given. Neither the API nor the Company Agent can apply a gift card.",
};

async function world({ config, plugins } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const { service: shop } = manzanita({ fetch, clock, ...(config ? { config } : {}), ...(plugins ? { plugins } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, issuer: metadata.issuer };
  const sessions = new SessionClient({ reactor: host.reactor, fetch });
  const start = () =>
    sessions.start({ clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tokenEndpoint: metadata.token_endpoint, tenantId: TENANT });
  return { clock, fetch, identity, shop, host, transport, company, metadata, who, start };
}

async function signedIn(w) {
  const session = await w.start();
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
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  return (await device.poll(started.reference)).token;
}

test("a report is missing, task and description only", () => {
  assert.deepEqual(parseFeedbackReport(GIFT_CARD), { kind: "missing", ...GIFT_CARD });
  // Personal agents MUST NOT send other kinds; nothing else rides along (§8).
  for (const report of [
    { kind: "error", task: "x", description: "y" },
    { task: "x", description: "y", user: "Ada" },
    { task: "x".repeat(FEEDBACK_TASK_MAX_LENGTH + 1), description: "y" },
    { task: "x", description: "y".repeat(FEEDBACK_DESCRIPTION_MAX_LENGTH + 1) },
    { task: "", description: "y" },
  ]) {
    assert.throws(() => parseFeedbackReport(report), (error) => error.code === "invalid_feedback");
  }
  assert.equal(parseFeedbackReport({ task: "x".repeat(200), description: "y".repeat(2000) }).task, "x".repeat(200));
});

test("feedback is listed with an HTTPS endpoint, and needs auth", () => {
  const base = { protocol_version: "0.3", organization: { name: "Example", domain: "example.com" }, web: {} };
  const listed = parseDiscoveryDocument({ ...base, auth: { issuer: "https://example.com" }, feedback: { endpoint: "https://example.com/poppy/feedback" } });
  assert.equal(feedbackEndpoint(listed), "https://example.com/poppy/feedback");
  assert.equal(feedbackEndpoint(parseDiscoveryDocument(base)), undefined);
  assert.throws(() => parseDiscoveryDocument({ ...base, feedback: { endpoint: "https://example.com/poppy/feedback" } }), /auth is required/);
  assert.throws(() =>
    parseDiscoveryDocument({ ...base, auth: { issuer: "https://example.com" }, feedback: { endpoint: "http://example.com/poppy/feedback" } }),
  );
});

test("a signed-out and a signed-in Session report, with no scope", async () => {
  const w = await world();
  const session = await w.start();
  const endpoint = feedbackEndpoint(w.company.document);
  assert.equal(endpoint, FEEDBACK);
  const client = new FeedbackClient({ transport: w.transport });
  // The task can be done after all: 200 and an alternative, content from the company (§8.3).
  const alternative = await client.report(endpoint, GIFT_CARD, { token: session, ...w.who });
  assert.ok(alternative.instructions);
  assert.deepEqual(usableReferences(alternative, w.company.document).map((reference) => reference.type), ["web"]);
  const token = await signedIn(w);
  assert.equal(
    await client.report(endpoint, { task: "Return a jacket", description: "No return option in any channel." }, { token, ...w.who }),
    undefined,
  );
  const reports = await w.shop.feedbackReports();
  assert.deepEqual(reports.map((report) => [report.kind, report.task]), [
    ["missing", "Pay with a gift card"],
    ["missing", "Return a jacket"],
  ]);
  // The Session says which personal agent and which user sent it; the report doesn't.
  assert.deepEqual([...new Set(reports.map((report) => report.clientId))], [w.identity.clientId]);
  assert.deepEqual([...new Set(reports.map((report) => report.pairwiseUserId))], [PAIRWISE]);
});

test("the company accepts an unknown kind and refuses a malformed report", async () => {
  const w = await world();
  const session = await w.start();
  const post = (body) =>
    w.transport.request("POST", FEEDBACK, { token: session, ...w.who, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  // A kind it doesn't recognize is accepted, so later versions can add kinds (§8).
  const accepted = await post({ kind: "slow", task: "Track a parcel", description: "Took ages." });
  assert.equal(accepted.status, 202);
  assert.equal(await accepted.text(), "");
  assert.equal((await w.shop.feedbackReports())[0].kind, "slow");
  for (const body of [
    { kind: "missing", task: "x".repeat(201), description: "too long a task" },
    { kind: "missing", task: "x", description: "y".repeat(2001) },
    { kind: "missing", task: "x" },
    { task: "x", description: "y" },
    ["not", "an", "object"],
  ]) {
    const refused = await post(body);
    assert.deepEqual([refused.status, await refused.json()], [400, { error: "invalid_request" }]);
  }
  // Only with a Session Token.
  const bare = await w.fetch(FEEDBACK, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(GIFT_CARD) });
  assert.equal(bare.status, 401);
  assert.equal((await w.shop.feedbackReports()).length, 1);
});

test("feedback refusals carry their code and Retry-After", async () => {
  const w = await world({
    plugins: [{ name: "limit", contributes: [{ point: CompanyRateLimits, value: { admit: async () => 30 }, options: { id: "limit" } }] }],
  });
  const session = await w.start();
  await assert.rejects(new FeedbackClient({ transport: w.transport }).report(FEEDBACK, GIFT_CARD, { token: session, ...w.who }), (error) => {
    assert.ok(error instanceof FeedbackError);
    assert.deepEqual([error.code, error.statusCode, error.details], ["rate_limited", 429, { retry_after: "30" }]);
    return true;
  });
});

test("a company without feedback neither lists nor accepts it", async () => {
  const w = await world({ config: { feedback: false } });
  const session = await w.start();
  assert.equal(feedbackEndpoint(w.company.document), undefined);
  await assert.rejects(new FeedbackClient({ transport: w.transport }).report(FEEDBACK, GIFT_CARD, { token: session, ...w.who }), (error) => {
    assert.ok(error instanceof FeedbackError);
    assert.equal(error.statusCode, 404);
    return true;
  });
});

test("a feedback endpoint answering with a redirect gets nothing", async () => {
  const w = await world();
  const session = await w.start();
  const sent = [];
  const transport = new DpopFetchClient({
    reactor: w.host.reactor,
    fetch: async (input) => {
      sent.push(String(input));
      return new Response(null, { status: 307, headers: { Location: "https://elsewhere.example/feedback" } });
    },
  });
  await assert.rejects(
    new FeedbackClient({ transport }).report(FEEDBACK, GIFT_CARD, { token: session, ...w.who }),
    (error) => error.code === "redirect_refused",
  );
  assert.deepEqual(sent, [FEEDBACK]);
});
