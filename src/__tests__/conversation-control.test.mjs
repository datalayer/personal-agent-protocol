/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  ConversationClient,
  ConversationError,
  PapSession,
  SecretValue,
  SessionFetchClient,
  SessionSigners,
  accessTokenFromResponse,
  buildPapReactor,
  parseTokenResponse,
} from "../../lib/index.js";

const endpoint = "https://api.example/conversations";
const session = () =>
  new PapSession({
    sid: "s".repeat(22),
    sub: "usr_ada",
    issuer: "https://auth.example",
    clientId: "https://agent.example/agent.json",
    tenantId: "tenant",
  });
const token = (secret) =>
  accessTokenFromResponse(parseTokenResponse({ access_token: secret, token_type: "Bearer", scope: "orders:read" }));

function arrange(company) {
  const seen = [];
  const fetch = async (url, init) => {
    seen.push({ url: String(url), init });
    return company(String(url), init, seen.length);
  };
  const reactor = buildPapReactor({ fetch }, [
    {
      name: "@tests/pap-conversation-control",
      contributes: [
        { point: SessionSigners, value: { sign: async () => new SecretValue("session-jwt") }, options: { id: "jwts" } },
      ],
    },
  ]);
  return { seen, client: new ConversationClient({ reactor, transport: new SessionFetchClient({ reactor, fetch }) }) };
}

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const sse = (...frames) => new Response(frames.join(""), { status: 200, headers: { "content-type": "text/event-stream" } });
const event = (id, fields) => ({ id, created_at: "2026-10-11T10:00:00Z", ...fields });
const frame = (data, name) =>
  `${name ? `event: ${name}\n` : ""}${data.id && !name ? `id: ${data.id}\n` : ""}data: ${JSON.stringify(data)}\n\n`;

test("stream yields deltas as non-actionable and stops at closed", async () => {
  const { client } = arrange(() =>
    sse(
      ": keep-alive\n\n",
      frame({ message_id: "msg_r1", text: "Your order" }, "text-delta"),
      frame(event("evt_1", { type: "message", message: { id: "msg_r1", author: { type: "agent" }, role: "company", text: "Your order shipped." } })),
      frame(event("evt_2", { type: "state", status: "closed", responder: "agent" })),
    ),
  );
  const items = [];
  for await (const item of client.stream(endpoint, "cnv_1", { session: session() })) items.push(item);
  assert.equal(items[0].kind, "text-delta");
  assert.equal(items[0].actionable, false);
  assert.deepEqual(items.slice(1).map((i) => i.id), ["evt_1", "evt_2"]);
});

test("a closed stream reopens from Last-Event-ID and drops partial text", async () => {
  const { client, seen } = arrange((_, __, call) =>
    call === 1
      ? sse(
          frame(event("evt_1", { type: "state", status: "working", responder: "agent" })),
          frame({ message_id: "msg_cut", text: "Half a" }, "text-delta"),
        )
      : sse(
          frame(event("evt_1", { type: "state", status: "working", responder: "agent" })),
          frame(event("evt_2", { type: "state", status: "closed", responder: "agent" })),
        ),
  );
  const items = [];
  for await (const item of client.stream(endpoint, "cnv_1", { session: session() })) items.push(item);
  assert.equal(seen[1].init.headers["Last-Event-ID"], "evt_1");
  assert.deepEqual(items.find((i) => i.kind === "reconnected"), {
    kind: "reconnected", lastEventId: "evt_1", discardedMessageIds: ["msg_cut"],
  });
  assert.deepEqual(items.filter((i) => i.type).map((i) => i.id), ["evt_1", "evt_2"]);
});

test("a company that does not stream says so", async () => {
  const { client } = arrange(() => json(200, { conversation_id: "cnv_1", events: [], cursor: "c_1", has_more: false, status: "idle", responder: "agent" }));
  await assert.rejects(
    (async () => { for await (const _ of client.stream(endpoint, "cnv_1", { session: session() })); })(),
    (error) => error.code === "sse_unsupported",
  );
});

test("handoff and close post empty objects", async () => {
  const { client, seen } = arrange((url) =>
    url.endsWith("/handoff")
      ? json(202, { conversation_id: "cnv_1", status: "queued", responder: "agent" })
      : json(200, { conversation_id: "cnv_1", status: "closed", responder: "human" }),
  );
  assert.equal((await client.handoff(endpoint, "cnv_1", { session: session() })).status, "queued");
  assert.equal((await client.close(endpoint, "cnv_1", { session: session() })).responder, "human");
  assert.deepEqual(seen.map((s) => [new URL(s.url).pathname, s.init.body]), [
    ["/conversations/cnv_1/handoff", "{}"],
    ["/conversations/cnv_1/close", "{}"],
  ]);
});

test("a Direct Conversation names its parent; the parent points to it", async () => {
  const { client, seen } = arrange((url) =>
    url.endsWith("/messages")
      ? json(409, { error: "direct_conversation_open", conversation_id: "cnv_direct" })
      : json(201, { conversation_id: "cnv_direct", status: "idle", responder: "agent" }),
  );
  const opened = await client.startDirect(endpoint, "cnv_1", { id: "msg_d1", author: { type: "human" }, text: "It's me" }, { session: session() });
  assert.equal(JSON.parse(seen[0].init.body).parent_conversation_id, "cnv_1");
  assert.equal(opened.conversation_id, "cnv_direct");
  await assert.rejects(
    client.send(endpoint, "cnv_1", { id: "msg_p2", author: { type: "agent" }, text: "Still there?" }, { session: session() }),
    (error) => error.code === "direct_conversation_open" && error.details.conversation_id === "cnv_direct",
  );
});

test("a stream that keeps closing empty gives up", async () => {
  const { client, seen } = arrange(() => sse(": nothing\n\n"));
  await assert.rejects(
    (async () => { for await (const _ of client.stream(endpoint, "cnv_1", { session: session(), maxReconnects: 2 })); })(),
    (error) => error instanceof ConversationError && error.code === "stream_unavailable",
  );
  assert.ok(seen.length > 1);
});

test("signing in mid-conversation keeps its ID", async () => {
  const { client, seen } = arrange(() => json(202, { conversation_id: "cnv_1", status: "working", responder: "agent" }));
  const mine = session();
  const first = await client.send(endpoint, "cnv_1", { id: "msg_1", author: { type: "agent" }, text: "Show my order" }, { session: mine });
  const second = await client.send(endpoint, "cnv_1", { id: "msg_2", author: { type: "agent" }, text: "Signed in" }, { session: mine, token: token("signed-in") });
  assert.equal(first.conversation_id, second.conversation_id);
  // Signed out, the Session header alone; signed in, the access token with it, in one Session.
  assert.deepEqual(seen.map((s) => s.init.headers.Authorization), [undefined, "Bearer signed-in"]);
  assert.deepEqual(seen.map((s) => s.init.headers["Poppy-Session"]), ["session-jwt", "session-jwt"]);
});
