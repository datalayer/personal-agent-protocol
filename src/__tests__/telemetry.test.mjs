/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The SDK's telemetry: one event per protocol stage, attributes from an allowlist (the
// TypeScript twin of personal_agent_protocol/__tests__/test_telemetry.py). The shared
// journey with Manzanita runs with a `pap.telemetry` sink; the OpenTelemetry adapter makes
// the same events spans. That no credential of a real run reaches an event is
// canaries.test.mjs's.
import assert from "node:assert/strict";
import test from "node:test";

import * as pap from "../../lib/index.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { CompanyRateLimits } from "../../lib/server.js";
import { runJourney } from "./support/journey.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const FORBIDDEN = [
  "token", "assertion", "proof", "code", "cookie", "password", "secret", "credential",
  "mediated", "key", "session_key", "user_id", "pairwise", "url",
];

/** Every event, as personal_agent_protocol/telemetry.py names it. */
const EVENTS = {
  "pap.discovery.discover": "discovery",
  "pap.session.start": "session",
  "pap.sign_in.direct.begin": "sign_in",
  "pap.sign_in.direct.complete": "sign_in",
  "pap.sign_in.device.begin": "sign_in",
  "pap.sign_in.device.poll": "sign_in",
  "pap.sign_in.mediated.sign_in": "sign_in",
  "pap.sign_in.mediated.submit_code": "sign_in",
  "pap.sign_in.refresh_token.refresh": "sign_in",
  "pap.sign_in.refresh_token.revoke": "sign_in",
  "pap.conversation.start": "conversation",
  "pap.conversation.send": "conversation",
  "pap.conversation.read_events": "conversation",
  "pap.conversation.start_direct": "conversation",
  "pap.conversation.handoff": "conversation",
  "pap.conversation.close": "conversation",
  "pap.operation.ask_user": "operation",
  "pap.operation.send": "operation",
  "pap.company.identity.check": "company",
  "pap.company.session.start": "company",
  "pap.company.interface.switch": "company",
  "pap.company.sign_out": "company",
  "pap.company.refused": "company",
};

/** Every attribute, as personal_agent_protocol/telemetry.py names it. */
const ATTRIBUTES = [
  "pap.client.id",
  "pap.company.domain",
  "pap.company.issuer",
  "pap.company.route",
  "pap.conversation.events",
  "pap.conversation.status",
  "pap.error",
  "pap.http.status",
  "pap.interface",
  "pap.operation.status",
  "pap.outcome",
  "pap.replayed",
  "pap.scopes.granted",
  "pap.scopes.missing",
  "pap.session.signed_in",
  "pap.sign_in.method",
  "pap.sign_in.status",
  "pap.stage",
];

test("the event and attribute names are Python's", () => {
  assert.deepEqual({ ...pap.TELEMETRY_EVENTS }, EVENTS);
  assert.deepEqual(Object.keys(pap.TELEMETRY_ATTRIBUTES).sort(), ATTRIBUTES);
  assert.deepEqual([...pap.TELEMETRY_STAGES], ["discovery", "session", "sign_in", "conversation", "operation", "company"]);
});

const sinkPlugin = (name, sink, order = 50) => ({
  name,
  contributes: [{ point: pap.TelemetrySinks, value: sink, options: { id: name, order } }],
});

async function journey(...plugins) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const { service, plugin } = manzanita({ fetch, clock });
  sites["manzanita.example"] = service;
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const host = await agentHost({ identity, fetch, clock });
  for (const item of plugins) await host.reactor.install(item);
  await runJourney({
    reactor: host.reactor,
    fetch,
    browser: host.browser,
    identity,
    company: {
      approveAuthorization: async (requestId, accountId) => service.approveAuthorization(requestId, { accountId }),
      performed: async () => [...plugin.executor.performed],
    },
  });
  return { host, fetch, clock };
}

test("each stage of the journey is one event, its attributes allowlisted", async () => {
  const sink = new pap.RecordingTelemetrySink();
  await journey(sinkPlugin("tests", sink));
  const stages = new Set(sink.events.map((event) => event.stage));
  assert.deepEqual([...stages].sort(), ["conversation", "discovery", "operation", "session", "sign_in"]);
  // The session stage asks the company nothing: a Session is local (§5.2).
  const names = new Set(sink.events.filter((e) => e.outcome === "ok").map((e) => e.name));
  for (const name of [
    "pap.discovery.discover",
    "pap.session.start",
    "pap.sign_in.direct.begin",
    "pap.sign_in.direct.complete",
    "pap.conversation.start",
    "pap.conversation.send",
    "pap.operation.ask_user",
  ]) {
    assert.ok(names.has(name), name);
  }
  const discovered = sink.events.find((e) => e.name === "pap.discovery.discover");
  assert.deepEqual(discovered.attributes, {
    "pap.company.domain": "manzanita.example",
    "pap.company.issuer": "https://manzanita.example",
  });
  const approved = sink.events.find((e) => e.name === "pap.operation.ask_user");
  assert.deepEqual({ ...approved.attributes }, { "pap.operation.status": "approved" });
  for (const event of sink.events) {
    assert.ok(event.durationMs >= 0);
    for (const name of Object.keys(event.attributes)) assert.ok(name in pap.TELEMETRY_ATTRIBUTES, name);
    assert.equal(event.asAttributes()["pap.stage"], pap.TELEMETRY_EVENTS[event.name]);
    assert.deepEqual(JSON.parse(JSON.stringify(event)).attributes, { ...event.attributes });
  }
});

test("a company reports what it did and refused: identity, Sessions, replays", async () => {
  const sink = new pap.RecordingTelemetrySink();
  const clock = new MutableClock();
  const sites = {};
  const inProcess = inProcessFetch(sites);
  const tokenRequests = [];
  const fetch = async (input, init = {}) => {
    if (String(input).endsWith("/oauth/token")) tokenRequests.push([String(input), init]);
    return inProcess(input, init);
  };
  const { service, plugin } = manzanita({ fetch, clock, plugins: [sinkPlugin("company-tests", sink)] });
  sites["manzanita.example"] = service;
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const host = await agentHost({ identity, fetch, clock });
  let approved;
  await runJourney({
    reactor: host.reactor,
    fetch,
    browser: host.browser,
    identity,
    company: {
      approveAuthorization: async (requestId, accountId) => {
        approved = accountId;
        return service.approveAuthorization(requestId, { accountId });
      },
      performed: async () => [...plugin.executor.performed],
    },
  });
  const company = sink.events.filter((event) => event.stage === "company");
  const checks = company.filter((event) => event.name === "pap.company.identity.check");
  assert.equal(checks.length, 1, "verified once: later requests of the same agent are not checks again");
  assert.deepEqual({ ...checks[0].attributes }, {
    "pap.company.issuer": "https://manzanita.example",
    "pap.company.domain": "manzanita.example",
    // A Session needs no OAuth endpoint: its first request is a conversation.
    "pap.company.route": "poppy_conversations",
    "pap.client.id": identity.clientId,
  });
  const started = company.find((event) => event.name === "pap.company.session.start");
  assert.equal(started.attributes["pap.session.signed_in"], false);
  assert.equal(company.filter((event) => event.name === "pap.company.refused").length, 0);

  // The first token request sent again: refused, and said to be a replay.
  const [url, init] = tokenRequests[0];
  const replay = await inProcess(url, init);
  const refused = sink.events.filter((event) => event.name === "pap.company.refused");
  assert.equal(refused.length, 1);
  assert.equal(refused[0].outcome, "error");
  assert.equal(refused[0].attributes["pap.error"], (await replay.json()).error);
  assert.equal(refused[0].attributes["pap.http.status"], replay.status);
  assert.equal(refused[0].attributes["pap.replayed"], true);
  assert.equal(refused[0].attributes["pap.company.route"], "oauth_token");

  // The person disconnects the agent in their account settings: the sign-in ends, said
  // outside any request (no route, no agent).
  assert.ok((await service.disconnect(identity.clientId, approved)) > 0);
  const signedOut = sink.events.filter((event) => event.name === "pap.company.sign_out");
  assert.equal(signedOut.length, 1);
  assert.deepEqual({ ...signedOut[0].attributes }, {
    "pap.company.issuer": "https://manzanita.example",
    "pap.company.domain": "manzanita.example",
    "pap.session.signed_in": false,
  });

  // A path the company does not serve is nobody's refusal, and a path's words never leave.
  await inProcess("https://manzanita.example/oauth/secret-path-words");
  assert.equal(sink.events.filter((event) => event.name === "pap.company.refused").length, 1);
  for (const event of sink.events) {
    for (const name of Object.keys(event.attributes)) assert.ok(name in pap.TELEMETRY_ATTRIBUTES, name);
    assert.ok(!JSON.stringify(event).includes("secret"));
  }
});

test("a forged Session JWT is no identity check, and names no agent", async () => {
  const sink = new pap.RecordingTelemetrySink();
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const { service } = manzanita({ fetch, clock, plugins: [sinkPlugin("company-tests", sink)] });
  sites["manzanita.example"] = service;
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  // Another key under the agent's `client_id`, its `kid`, and its documents left in place.
  const impostor = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  const host = await agentHost({ identity: impostor, fetch, clock });
  const session = await new pap.SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: identity.clientId,
    pairwiseUserId: "usr_ada_at_manzanita_000000",
    issuer: "https://manzanita.example",
    tenantId: "atlas-demo",
  });
  const url = "https://manzanita.example/poppy/conversations";
  const refused = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await pap.sessionHeaders(host.reactor, "POST", url, { session })) },
    body: "{}",
  });
  assert.deepEqual([refused.status, await refused.json()], [400, { error: "invalid_session" }]);
  assert.deepEqual(sink.events.filter((event) => event.name === "pap.company.identity.check"), []);
  const [event] = sink.events.filter((item) => item.name === "pap.company.refused");
  assert.equal(event.attributes["pap.error"], "invalid_session");
  assert.equal("pap.client.id" in event.attributes, false);
});

test("a rate limit is reported with its code", async () => {
  // A 429 has no body (§5.6), so its report's code is the company's alone to name.
  const sink = new pap.RecordingTelemetrySink();
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const limit = { point: CompanyRateLimits, value: { admit: async () => 30 }, options: { id: "limit" } };
  const { service } = manzanita({
    fetch,
    clock,
    plugins: [sinkPlugin("company-tests", sink), { name: "limit", version: "1", contributes: [limit] }],
  });
  sites["manzanita.example"] = service;
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  const host = await agentHost({ identity, fetch, clock });
  const session = await new pap.SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: identity.clientId,
    pairwiseUserId: "usr_ada_at_manzanita_000000",
    issuer: "https://manzanita.example",
    tenantId: "atlas-demo",
  });
  const url = "https://manzanita.example/poppy/conversations";
  const refused = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(await pap.sessionHeaders(host.reactor, "POST", url, { session })) },
    body: "{}",
  });
  assert.equal(refused.status, 429);
  const [event] = sink.events.filter((item) => item.name === "pap.company.refused");
  assert.equal(event.attributes["pap.error"], "rate_limited");
  assert.equal(event.attributes["pap.http.status"], 429);
});

test("a refusal is an error event carrying its code only", async () => {
  const sink = new pap.RecordingTelemetrySink();
  const { host, fetch } = await journey(sinkPlugin("tests", sink));
  const conversations = new pap.ConversationClient({
    reactor: host.reactor,
    transport: new pap.SessionFetchClient({ reactor: host.reactor, fetch }),
  });
  const session = await new pap.SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: "https://atlas.example/agent.json",
    pairwiseUserId: "usr_a_stranger_0000000000",
    issuer: "https://manzanita.example",
    tenantId: "atlas-demo",
  });
  await assert.rejects(conversations.readEvents("https://manzanita.example/poppy/conversations", "conv_unknown", { session }));
  const refused = sink.events.at(-1);
  assert.equal(refused.name, "pap.conversation.read_events");
  assert.equal(refused.outcome, "error");
  assert.deepEqual({ ...refused.attributes }, { "pap.company.domain": "manzanita.example", "pap.error": "conversation_not_found" });
});

test("a send's status, whatever came of it", async () => {
  const sink = new pap.RecordingTelemetrySink();
  const reactor = pap.buildPapReactor({}, [sinkPlugin("tests", sink)]);
  const client = new pap.OperationsClient({ reactor });
  const approval = { operation_id: "exc_5Rt2", revision: "r1" };
  await client.send(async () => ({ status: 200, body: {} }), approval);
  await client.send(async () => { throw new pap.TransportError("request_failed", "lost"); }, approval, { attempts: 1 });
  reactor.stop();
  const sends = sink.events.filter((e) => e.name === "pap.operation.send");
  assert.deepEqual(sends.map((e) => e.attributes["pap.operation.status"]), ["answered", "unknown"]);
});

test("a refresh says how it ended", async () => {
  const sink = new pap.RecordingTelemetrySink();
  const answers = [
    Response.json({ access_token: "t", token_type: "Bearer", scope: "orders:read" }),
    Response.json({ error: "invalid_scope" }, { status: 400 }),
    Response.json({ error: "invalid_grant" }, { status: 400 }),
  ];
  const fetch = async () => answers.shift();
  const tokens = new Map([["ref", new pap.SecretValue("refresh-token")]]);
  const reactor = pap.buildPapReactor({ fetch }, [
    sinkPlugin("tests", sink),
    {
      name: "vault",
      contributes: [
        { point: pap.Signers, value: { sign: async () => new pap.SecretValue("assertion") }, options: { id: "signer" } },
        {
          point: pap.TokenStores,
          value: {
            async put(reference, token) { tokens.set(reference, token); },
            async get(reference) { return tokens.get(reference); },
            async delete(reference) { tokens.delete(reference); },
          },
          options: { id: "vault" },
        },
      ],
    },
  ]);
  const client = new pap.RefreshTokenClient({ reactor, fetch });
  const context = {
    tokenEndpoint: "https://shop.example/oauth/token",
    issuer: "https://shop.example",
    clientId: "https://agent.example/agent.json",
    tenantId: "t",
  };
  await client.refresh("ref", { context, scopes: ["orders:read"] });
  await client.refresh("ref", { context, scopes: ["orders:write"] });
  await client.refresh("ref", { context });
  reactor.stop();
  const refreshes = sink.events.filter((e) => e.name === "pap.sign_in.refresh_token.refresh");
  assert.deepEqual(refreshes.map((e) => e.attributes["pap.sign_in.status"]), ["signed_in", "re_consent_required", "signed_out"]);
  assert.deepEqual(refreshes.map((e) => e.outcome), ["ok", "ok", "ok"]);
  assert.equal(refreshes[0].attributes["pap.sign_in.method"], "refresh_token");
});

test("no allowlisted attribute names a secret", () => {
  for (const name of Object.keys(pap.TELEMETRY_ATTRIBUTES)) {
    assert.ok(name.startsWith("pap."));
    for (const word of FORBIDDEN) assert.ok(!name.includes(word), `${name} names ${word}`);
  }
});

test("a value that fails its rule is dropped; a name outside the allowlist is refused", () => {
  for (const [name, value] of [
    ["pap.company.issuer", "https://manzanita.example/?token=CANARY"],
    ["pap.company.issuer", "https://user:pw@manzanita.example"],
    ["pap.company.issuer", "https://manzanita.example/#frag"],
    ["pap.company.issuer", "http://manzanita.example"],
    ["pap.company.domain", "00000001CANARYAAAA.example"],
    ["pap.company.domain", "manzanita.example/path"],
    ["pap.error", "00000001CANARYAAAAAAAAAAAAAAAA"],
    ["pap.error", "invalid grant: eyJhbGciOi"],
    ["pap.sign_in.status", new pap.SecretValue("signed_in")],
    ["pap.operation.status", "x".repeat(49)],
    ["pap.conversation.events", -1],
    ["pap.conversation.events", true],
    ["pap.session.signed_in", "yes"],
    ["pap.sign_in.method", "password"],
  ]) {
    assert.deepEqual(pap.safeAttributes({ [name]: value }), {}, `${name}=${String(value)}`);
  }
  // The attributes of the withdrawn operation shape are gone with it.
  for (const name of ["pap.session.token", "pap.operation.id", "pap.operation.state", "pap.operation.revision", "authorization", "pap.url"]) {
    assert.throws(() => pap.safeAttributes({ [name]: "x" }), /not a telemetry attribute/);
  }
  assert.throws(
    () => new pap.TelemetryEvent({ name: "pap.session.start", outcome: "ok", durationMs: 1, attributes: { "pap.company.issuer": "https://a.example/?code=1" } }),
    /failed its rule/,
  );
  assert.throws(() => new pap.TelemetryEvent({ name: "pap.tokens.dump", outcome: "ok", durationMs: 1 }), /not a telemetry event/);
});

test("a failing sink never fails the protocol", async () => {
  const warned = [];
  const warn = console.warn;
  console.warn = (line) => warned.push(line);
  try {
    await journey(sinkPlugin("broken", { record(event) { throw new Error(`cannot export ${JSON.stringify(event)}`); } }));
  } finally {
    console.warn = warn;
  }
  assert.ok(warned.length > 0);
  assert.deepEqual([...new Set(warned)], ["The telemetry sink failed: Error"]);
});

test("two sinks at one order fail closed", async () => {
  await assert.rejects(
    journey(sinkPlugin("a", new pap.RecordingTelemetrySink(), 5), sinkPlugin("b", new pap.RecordingTelemetrySink(), 5)),
    /ambiguous telemetry sink/,
  );
});

test("the OpenTelemetry adapter makes each event a span", async () => {
  const spans = [];
  const tracer = {
    startSpan(name, options) {
      const span = { name, attributes: options.attributes, startTime: options.startTime, status: undefined, endTime: undefined };
      spans.push(span);
      return { setStatus: (status) => void (span.status = status), end: (time) => void (span.endTime = time) };
    },
  };
  const recording = new pap.RecordingTelemetrySink();
  const otel = pap.openTelemetrySink(tracer);
  await journey(sinkPlugin("both", { record(event) { recording.record(event); otel.record(event); } }));
  assert.deepEqual(spans.map((span) => span.name), recording.events.map((event) => event.name));
  spans.forEach((span, index) => {
    const event = recording.events[index];
    assert.deepEqual(span.attributes, { ...event.asAttributes() });
    assert.ok(span.endTime >= span.startTime);
    assert.deepEqual(span.status, event.outcome === "error" ? { code: 2 } : undefined);
  });
});
