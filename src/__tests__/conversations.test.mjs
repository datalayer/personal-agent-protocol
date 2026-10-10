import assert from "node:assert/strict";
import test from "node:test";

import {
  ConversationClient,
  ConversationError,
  DpopFetchClient,
  DpopProofProviders,
  SecretValue,
  buildPapReactor,
} from "../../lib/index.js";

const token = {
  accessToken: new SecretValue("session-secret"),
  tokenType: "DPoP",
  expiresIn: 300,
  scopes: [],
  sessionId: "ses_example",
  signedIn: false,
};

function setup(fetch) {
  const plugin = {
    name: "@tests/pap-conversations",
    contributes: [
      {
        point: DpopProofProviders,
        value: { create: async () => new SecretValue("proof") },
        options: { id: "proofs" },
      },
    ],
  };
  const reactor = buildPapReactor({ fetch }, [plugin]);
  return {
    reactor,
    client: new ConversationClient({
      reactor,
      transport: new DpopFetchClient({ reactor, fetch }),
    }),
  };
}

const request = {
  token,
  tenantId: "tenant",
  pairwiseUserId: "usr_example",
  issuer: "https://auth.example",
};

test("starts and continues with distinct user-global message IDs", async () => {
  const calls = [];
  const fetch = async (input, init) => {
    calls.push({ url: input.toString(), body: JSON.parse(init.body) });
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
    sender: "agent",
    text: "Return the jacket",
  };
  const started = await client.start(
    "https://api.example/conversations",
    first,
    request,
  );
  const followUp = {
    id: client.generateMessageId(),
    sender: "agent",
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
      { id: "msg_same", sender: "agent", text: "different content" },
      request,
    ),
    (error) =>
      error instanceof ConversationError &&
      error.code === "message_id_conflict" &&
      !error.toString().includes("secret"),
  );
  reactor.stop();
});
