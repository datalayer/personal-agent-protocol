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
import { runJourney } from "./support/journey.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const FORBIDDEN = [
  "token", "assertion", "proof", "code", "cookie", "password", "secret", "credential",
  "mediated", "key", "session_id", "user_id", "pairwise", "url",
];

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
  const names = new Set(sink.events.filter((e) => e.outcome === "ok").map((e) => e.name));
  for (const name of [
    "pap.discovery.discover",
    "pap.session.start",
    "pap.sign_in.direct.begin",
    "pap.sign_in.direct.complete",
    "pap.conversation.start",
    "pap.operation.confirm",
  ]) {
    assert.ok(names.has(name), name);
  }
  const discovered = sink.events.find((e) => e.name === "pap.discovery.discover");
  assert.deepEqual(discovered.attributes, {
    "pap.company.domain": "manzanita.example",
    "pap.company.issuer": "https://manzanita.example",
  });
  const confirm = sink.events.find((e) => e.name === "pap.operation.confirm" && e.outcome === "ok");
  assert.equal(confirm.attributes["pap.operation.status"], "confirmed");
  assert.equal(confirm.attributes["pap.operation.state"], "succeeded");
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
    "pap.company.route": "oauth_token",
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

test("a refusal is an error event carrying its code only", async () => {
  const sink = new pap.RecordingTelemetrySink();
  const { host, fetch } = await journey(sinkPlugin("tests", sink));
  const conversations = new pap.ConversationClient({
    reactor: host.reactor,
    transport: new pap.DpopFetchClient({ reactor: host.reactor, fetch }),
  });
  const token = { accessToken: new pap.SecretValue("not-a-token"), tokenType: "DPoP", expiresIn: 60, scopes: [], sessionKey: "K".repeat(43), signedIn: false };
  await assert.rejects(
    conversations.readEvents("https://manzanita.example/poppy/conversations", "conv_unknown", {
      token,
      tenantId: "atlas-demo",
      issuer: "https://manzanita.example",
    }),
  );
  const refused = sink.events.at(-1);
  assert.equal(refused.name, "pap.conversation.read_events");
  assert.equal(refused.outcome, "error");
  assert.deepEqual(Object.keys(refused.attributes).sort(), ["pap.company.domain", "pap.error"]);
  assert.match(refused.attributes["pap.error"], /^[a-z][a-z0-9_]*$/);
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
    ["pap.operation.state", "x".repeat(49)],
    ["pap.operation.revision", -1],
    ["pap.operation.revision", true],
    ["pap.session.signed_in", "yes"],
    ["pap.sign_in.method", "password"],
  ]) {
    assert.deepEqual(pap.safeAttributes({ [name]: value }), {}, `${name}=${String(value)}`);
  }
  for (const name of ["pap.session.token", "pap.operation.id", "authorization", "pap.url"]) {
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
