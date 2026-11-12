/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// An operation to approve and a company's replies as reactor.ui displays: the examples the
// Python tests write (test_ui.py), read and checked by the TypeScript SDK.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import * as pap from "../../lib/index.js";
import {
  PAP_CONFIRM_TYPE,
  PAP_CONFIRM_VERSION,
  PAP_REPLIES_TYPE,
  inertSummary,
  isPapConfirm,
  isPapConfirmData,
  isPapReplies,
  isPapSessionShown,
  papConfirmDisplay,
  papConfirmText,
  papRepliesDisplay,
  papRepliesText,
  papLinkHost,
  PAP_REPLIES_VERSION,
} from "../../lib/index.js";

const example = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures/pap-confirm-display.json", import.meta.url), "utf8"),
);

test("the Python SDK's display is an operation to approve, its text said the same", () => {
  assert.equal(PAP_CONFIRM_VERSION, 3);
  assert.equal(example.type, PAP_CONFIRM_TYPE);
  assert.equal(example.version, 3);
  assert.ok(isPapConfirm(example));
  assert.equal(papConfirmText(example.data), example.text);
  assert.deepEqual(papConfirmDisplay(example.id, example.data), example);
});

test("another type, another version, or data that says less or other is not one", () => {
  const changed = (data) => ({ ...example, data: { ...example.data, ...data } });
  assert.equal(isPapConfirm({ ...example, type: "application/vnd.datalayer.pap.sign-in+json" }), false);
  assert.equal(isPapConfirm({ ...example, version: 2 }), false);
  assert.equal(isPapConfirm({ ...example, version: 4 }), false);
  for (const data of [
    { company: " " },
    { summary: "" },
    { operation_ref: "" },
    { revision: "" },
    { revision: 2 },
    { revision: "not an id" },
    { does: "spend" },
    { terms: [] },
    { expires_at: null },
    { expires_at: "tomorrow" },
    { differences: "none" },
    { differences: [1] },
    { was: { revision: 2, terms: {} } },
    { was: { revision: example.data.revision, terms: {} } },
    { only_the_person: "yes" },
    { token: "secret" },
    { summary: null, terms: {} },
    { approved_by: "company" },
    { approved_by: "agent" },
    { approved_by: "agent", instruction: "  " },
    { approved_by: "user", instruction: "anything" },
    { instruction: "anything" },
    { declined: "no" },
    { declined: { reason: 1, instructions: null } },
    { declined: { reason: null } },
  ]) {
    assert.equal(isPapConfirm(changed(data)), false, JSON.stringify(data));
  }
  const { session: _, ...withoutSession } = example.data;
  assert.equal(isPapConfirmData(withoutSession), false);
  const { terms: _terms, ...withoutTerms } = example.data;
  assert.equal(isPapConfirmData(withoutTerms), false);
});

test("a confirm without a summary shows every value of the terms", () => {
  // `terms` are required and `summary` optional (Operations 3): the text then says the terms'
  // values, still as inert text.
  const data = { ...example.data, summary: null, was: null };
  assert.ok(isPapConfirmData(data));
  assert.ok(
    papConfirmText(data).startsWith(
      "manzanita.example asks you to approve: price_difference.amount: 70.00; " +
        "price_difference.currency: USD; ships_in_days: 5 (revision rev_k3Jd9Qx2mW8v",
    ),
  );
  assert.throws(() => papConfirmDisplay("c1", { ...data, terms: {} }), TypeError);
  const hostile = papConfirmText({ ...data, terms: { note: "see [here](https://evil.example)" } });
  assert.ok(!hostile.includes("[here](") && hostile.includes("\\[here\\]"));
});

test("a confirm says who approved and what a company declined", () => {
  // An agent approval shows the instruction it rested on; a decline says nothing was done, with
  // the company's reason as text (Operations 5, 6).
  const confirm = (changes) => ({ ...example.data, ...changes });
  const byAgent = confirm({ approved_by: "agent", instruction: "Go ahead with any exchange under $100" });
  assert.ok(isPapConfirmData(byAgent));
  assert.ok(
    papConfirmText(byAgent).startsWith(
      'Approved for you at manzanita.example, on your instruction "Go ahead with any exchange under $100": Exchange the Ridge Jacket',
    ),
  );
  assert.ok(papConfirmText(byAgent).endsWith("(revision rev_k3Jd9Qx2mW8v)"));
  assert.ok(papConfirmText(confirm({ approved_by: "user" })).startsWith("You approved at manzanita.example:"));
  const declined = confirm({
    approved_by: "agent",
    instruction: "Return everything in this order",
    declined: { reason: "Only you can approve a return. <b>Call us</b>", instructions: "Approve it yourself." },
  });
  assert.ok(isPapConfirmData(declined));
  const text = papConfirmDisplay("c1", declined).text;
  assert.ok(text.startsWith("manzanita.example declined the approval: nothing was done."));
  assert.ok(text.includes("It says: Only you can approve a return.") && !text.includes("<b>"));
  assert.ok(text.endsWith("Another way, it says: Approve it yourself."));
});

test("the Session is a one-way reference and whether the person is signed in, nothing else", () => {
  const session = (value) => ({ ...example.data, session: value });
  assert.ok(isPapConfirmData(session(null)));
  assert.ok(isPapConfirmData(session({ ref: "0123456789ab", signed_in: false })));
  // A Session's ID, or a reference with anything beside it, is refused.
  assert.equal(isPapConfirmData(session({ ref: "ses_8c1f0e6a2b4d4f0e9a7c3d5b1e2f4a6c", signed_in: true })), false);
  assert.equal(isPapConfirmData(session({ ref: "2efc4a6dcd6f", signed_in: true, token: "t" })), false);
  assert.equal(isPapConfirmData(session({ ref: "2efc4a6dcd6f" })), false);
  assert.ok(isPapSessionShown(example.data.session));
  assert.equal(isPapSessionShown({ ref: "ses_8c1f0e6a2b4d4f0e9a7c3d5b1e2f4a6c", signed_in: true }), false);
});

test("a display is made only of an operation to approve", () => {
  const data = { ...example.data, was: null, session: null, does: null };
  const display = papConfirmDisplay("c1", data);
  assert.ok(isPapConfirm(display));
  assert.equal(
    display.text,
    `${data.company} asks you to approve: ${data.summary} (revision ${data.revision}, until 2026-10-12T18:00:00+00:00)`,
  );
  assert.throws(() => papConfirmDisplay("c1", { ...data, revision: 0 }), TypeError);
  assert.throws(() => papConfirmDisplay("", data), TypeError);
});

test("the summary is shown as text, its links, images and HTML inert", () => {
  // Operations 3: a summary can't send the User elsewhere or load content while they decide.
  const summary =
    "**Exchange** it: [details](https://evil.example/x) " +
    "![pixel](https://evil.example/p.png) <img src=x> www.evil.example a@evil.example";
  const said = papConfirmText({ ...example.data, was: null, summary });
  assert.ok(said.includes("\\[details\\](https\\://evil.example/x)"));
  assert.ok(said.includes("!\\[pixel\\](https\\://evil.example/p.png)"));
  assert.ok(said.includes("\\<img src=x\\>"));
  assert.ok(said.includes("www\\.evil.example") && said.includes("a\\@evil.example"));
  // Emphasis, paragraphs and lists stay: a host MAY render them.
  assert.ok(said.includes("**Exchange**"));
  // The company's words stay verbatim for a page that shows them as text.
  const display = papConfirmDisplay("c1", { ...example.data, was: null, summary });
  assert.equal(display.data.summary, summary);
  assert.equal(inertSummary("a\\b [x]"), "a\\\\b \\[x\\]");
});

test("the terms check is pointed out with what is asked", () => {
  const differences = ["The terms say 90.00, the summary doesn't."];
  const said = papConfirmText({ ...example.data, was: null, differences });
  assert.ok(said.endsWith("Check: The terms say 90.00, the summary doesn't."));
});

test("the outcome display is withdrawn", () => {
  for (const name of ["PAP_OUTCOME_TYPE", "PAP_OUTCOME_VERSION", "isPapOutcome", "isPapOutcomeData", "papOutcomeDisplay", "papOutcomeText"]) {
    assert.equal(name in pap, false, name);
  }
  assert.equal(existsSync(new URL("../../protocol/fixtures/pap-outcome-display.json", import.meta.url)), false);
});

const replies = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures/pap-replies-display.json", import.meta.url), "utf8"),
);

test("the Python SDK's replies are one, each with who wrote it, word for word", () => {
  assert.equal(replies.type, PAP_REPLIES_TYPE);
  assert.equal(replies.version, PAP_REPLIES_VERSION);
  assert.ok(isPapReplies(replies));
  assert.equal(papRepliesText(replies.data), replies.text);
  // The pages a reply refers to and the notices it marks apart (version 4).
  assert.deepEqual(replies.data.replies[0].links, [{ url: "https://manzanita.example/orders/ord_7Hk2/tracking", title: "Tracking for order ord_7Hk2" }]);
  assert.equal(papLinkHost(replies.data.replies[0].links[0]), "manzanita.example");
  assert.deepEqual(replies.data.replies[1].disclosures, ["Exchanged items ship once the original jacket is received."]);
  assert.ok(replies.text.includes("  Link: Tracking for order ord_7Hk2 (manzanita.example)"));
  assert.ok(replies.text.includes("  Notice: Exchanged items ship once the original jacket is received."));
  assert.deepEqual(
    replies.data.replies.map((reply) => [reply.author, reply.name]),
    [["agent", null], ["human", "Rosa"]],
  );
  assert.deepEqual(papRepliesDisplay(replies.id, replies.data), replies);
});

test("replies that say less or other are not one", () => {
  const changed = (data) => ({ ...replies, data: { ...replies.data, ...data } });
  assert.equal(isPapReplies({ ...replies, type: PAP_CONFIRM_TYPE }), false);
  // Version 1 named no conversation, 2 said `sender`, 3 carried no links or disclosures:
  // refused, not read as 4.
  assert.equal(isPapReplies({ ...replies, version: 1 }), false);
  assert.equal(isPapReplies({ ...replies, version: 2 }), false);
  assert.equal(isPapReplies({ ...replies, version: 3 }), false);
  assert.equal(replies.data.conversation, "conv_4Kp9");
  for (const data of [
    { company: " " },
    { conversation: "" },
    { conversation: "has space" },
    { conversation: undefined },
    { replies: [] },
    { replies: [{ author: "model", name: null, text: "Hello" }] },
    { replies: [{ sender: "agent", text: "Hello" }] },
    { replies: [{ author: "agent", text: "Hello" }] },
    { replies: [{ author: "agent", name: " ", text: "Hello" }] },
    { replies: [{ author: "agent", name: null, text: " " }] },
    { replies: [{ author: "agent", name: null, text: "Hello", token: "secret" }] },
    { replies: [{ author: "agent", name: null, text: "Hello" }] },
    { replies: [{ author: "agent", name: null, text: "Hello", links: [], disclosures: [" "] }] },
    { replies: [{ author: "agent", name: null, text: "Hello", links: [{ url: "http://x.example/", title: null }], disclosures: [] }] },
    { replies: [{ author: "agent", name: null, text: "Hello", links: [{ url: "https://x.example/", title: "" }], disclosures: [] }] },
    { replies: [{ author: "agent", name: null, text: "Hello", links: [{ url: "https://x.example/" }], disclosures: [] }] },
    { status: 1 },
    { responder: 1 },
    { token: "secret" },
  ]) {
    assert.equal(isPapReplies(changed(data)), false, JSON.stringify(data));
  }
  assert.throws(() => papRepliesDisplay("r1", { ...replies.data, replies: [] }), TypeError);
});

test("an unknown handoff reads as pending and an unknown responder as human", () => {
  // Later versions may add values (§8.7): read as the most careful known one.
  const shown = papRepliesDisplay("r1", { ...replies.data, handoff: "paused", responder: "robot" });
  assert.deepEqual([shown.data.handoff, shown.data.responder], ["pending", "human"]);
  assert.ok(isPapReplies(shown));
  assert.deepEqual(
    [papRepliesDisplay("r1", { ...replies.data, working: null, handoff: null, responder: null, closed: null }).data.handoff],
    [null],
  );
  assert.throws(() => papRepliesDisplay("r1", { ...replies.data, working: "later" }), TypeError);
});
