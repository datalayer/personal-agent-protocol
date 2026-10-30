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
  buildPapReactor,
} from "../../lib/index.js";

const session = () =>
  new PapSession({
    sid: "s".repeat(22),
    sub: "usr_ada",
    issuer: "https://auth.example",
    clientId: "https://agent.example/agent.json",
    tenantId: "tenant",
  });

function setup(fetch) {
  const plugin = {
    name: "@tests/pap-conversations",
    contributes: [
      {
        point: SessionSigners,
        value: { sign: async (request) => new SecretValue(`jwt-for-${request.method.toLowerCase()}`) },
        options: { id: "jwts" },
      },
    ],
  };
  const reactor = buildPapReactor({ fetch }, [plugin]);
  return {
    reactor,
    client: new ConversationClient({
      reactor,
      transport: new SessionFetchClient({ reactor, fetch }),
    }),
  };
}

const request = { session: session() };

test("starts and continues with distinct user-global message IDs", async () => {
  const calls = [];
  const fetch = async (input, init) => {
    calls.push({ url: input.toString(), body: JSON.parse(init.body), headers: init.headers });
    return new Response(
      JSON.stringify({
        conversation_id: "cnv_one",
        status: "working",
        responder: "agent",
      }),
      { status: calls.length === 1 ? 201 : 202 },
    );
  };
  const { reactor, client } = setup(fetch);
  const first = {
    id: client.generateMessageId(),
    author: { type: "agent" },
    text: "Return the jacket",
  };
  const started = await client.start(
    "https://api.example/conversations",
    first,
    request,
  );
  const followUp = {
    id: client.generateMessageId(),
    author: { type: "agent" },
    context: { user_available: false },
  };
  const continued = await client.send(
    "https://api.example/conversations",
    started.conversation_id,
    followUp,
    request,
  );
  reactor.stop();
  assert.equal(continued.conversation_id, "cnv_one");
  assert.notEqual(first.id, followUp.id);
  assert.equal(calls[0].body.message.id, first.id);
  assert.equal(calls[1].body.message.id, followUp.id);
  // Signed out: the Session header alone.
  assert.equal(calls[0].headers["Poppy-Session"], "jwt-for-post");
  assert.ok(!("Authorization" in calls[0].headers));
});

test("surfaces message ID conflicts without response body details", async () => {
  const fetch = async () =>
    new Response(
      JSON.stringify({ error: "message_id_conflict", secret: "omit" }),
      { status: 409 },
    );
  const { reactor, client } = setup(fetch);
  await assert.rejects(
    client.start(
      "https://api.example/conversations",
      { id: "msg_same", author: { type: "agent" }, text: "different content" },
      request,
    ),
    (error) =>
      error instanceof ConversationError &&
      error.code === "message_id_conflict" &&
      !error.toString().includes("secret"),
  );
  reactor.stop();
});

test("recovers an expired cursor, drains pages, and suppresses duplicates", async () => {
  const urls = [];
  let recovered = 0;
  const event = (id, text) => ({
    id,
    type: "message",
    created_at: "2026-10-10T12:00:00Z",
    message: {
      id: `msg_${id}`,
      author: { type: "agent" },
      role: "company",
      text,
    },
  });
  const fetch = async (input) => {
    urls.push(input.toString());
    if (urls.length === 1) {
      return new Response(JSON.stringify({ error: "cursor_expired" }), {
        status: 410,
      });
    }
    if (urls.length === 2) {
      return new Response(
        JSON.stringify({
          conversation_id: "cnv_one",
          events: [event("evt_one", "one"), event("evt_two", "two")],
          cursor: "evt_two",
          has_more: true,
          status: "working",
          responder: "agent",
        }),
        { status: 200 },
      );
    }
    return new Response(
      JSON.stringify({
        conversation_id: "cnv_one",
        events: [event("evt_two", "two"), event("evt_three", "three")],
        cursor: "evt_three",
        has_more: false,
        status: "closed",
        responder: "agent",
      }),
      { status: 200 },
    );
  };
  const { reactor, client } = setup(fetch);
  const events = [];
  for await (const item of client.events(
    "https://api.example/conversations",
    "cnv_one",
    {
      ...request,
      cursor: "evt_saved",
      wait: 30,
      onCursorExpired: () => {
        recovered += 1;
      },
    },
  )) {
    events.push(item);
  }
  reactor.stop();

  assert.deepEqual(
    events.map((item) => item.id),
    ["evt_one", "evt_two", "evt_three"],
  );
  assert.equal(recovered, 1);
  assert.match(urls[0], /cursor=evt_saved&wait=30$/);
  assert.match(urls[1], /\/events\?wait=30$/);
  assert.match(urls[2], /cursor=evt_two&wait=0$/);
});

test("rejects event pages for a different conversation", async () => {
  const fetch = async () =>
    new Response(
      JSON.stringify({
        conversation_id: "cnv_other",
        events: [],
        cursor: "evt_zero",
        has_more: false,
        status: "idle",
        responder: "agent",
      }),
      { status: 200 },
    );
  const { reactor, client } = setup(fetch);
  await assert.rejects(
    client.readEvents("https://api.example/conversations", "cnv_one", request),
    (error) =>
      error instanceof ConversationError &&
      error.code === "conversation_mismatch",
  );
  reactor.stop();
});

test("a conversation refusal reads its code from the body or the challenge, and its extension", async () => {
  const answers = [
    () => new Response(null, { status: 401, headers: { "WWW-Authenticate": 'Bearer error="invalid_token"' } }),
    () =>
      new Response(JSON.stringify({ error: "extension_required", extension: "operations" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      }),
    () =>
      new Response(JSON.stringify({ error: "invalid_request" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      }),
  ];
  const { reactor, client } = setup(async () => answers.shift()());
  const read = () => client.readEvents("https://shop.example/poppy/conversations", "cnv_example", request);
  // A token error may come only in WWW-Authenticate (§7).
  await assert.rejects(read(), (error) => error instanceof ConversationError && error.code === "invalid_token" && error.statusCode === 401);
  // extension_required names its extension in the JSON body at a conversation (§3.3).
  await assert.rejects(read(), (error) => error.code === "extension_required" && error.details.extension === "operations");
  await assert.rejects(read(), (error) => error.code === "invalid_request" && error.statusCode === 400);
  reactor.stop();
});

test("an unknown status reads as working, and an unknown responder as human", async () => {
  const fetch = async () =>
    new Response(
      JSON.stringify({
        conversation_id: "cnv_one",
        events: [
          { id: "evt_one", type: "state", created_at: "2026-10-10T12:00:00Z", status: "paused", responder: "robot" },
        ],
        cursor: "evt_one",
        has_more: false,
        status: "paused",
        responder: "robot",
      }),
      { status: 200 },
    );
  const { reactor, client } = setup(fetch);
  const page = await client.readEvents("https://api.example/conversations", "cnv_one", request);
  reactor.stop();
  assert.deepEqual([page.status, page.responder], ["working", "human"]);
  assert.deepEqual([page.events[0].status, page.events[0].responder], ["working", "human"]);
});

test("an invalid_session while sending starts a new Session once, and the message goes again", async () => {
  const bodies = [];
  const fetch = async (_input, init) => {
    bodies.push(JSON.parse(init.body));
    return bodies.length === 1
      ? new Response('{"error":"invalid_session"}', { status: 400 })
      : new Response('{"conversation_id":"cnv_one","status":"working","responder":"agent"}', { status: 202 });
  };
  const { reactor, client } = setup(fetch);
  const mine = session();
  const before = mine.sid;
  const message = { id: client.generateMessageId(), author: { type: "agent" }, text: "Hello" };
  await client.send("https://api.example/conversations", "cnv_one", message, { session: mine });
  reactor.stop();
  assert.notEqual(mine.sid, before);
  assert.deepEqual(bodies[0], bodies[1]);
});
