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
} from "../../lib/index.js";

const example = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures/pap-confirm-display.json", import.meta.url), "utf8"),
);

test("the Python SDK's display is an operation to approve, its text said the same", () => {
  assert.equal(PAP_CONFIRM_VERSION, 2);
  assert.equal(example.type, PAP_CONFIRM_TYPE);
  assert.equal(example.version, 2);
  assert.ok(isPapConfirm(example));
  assert.equal(papConfirmText(example.data), example.text);
  assert.deepEqual(papConfirmDisplay(example.id, example.data), example);
});

test("another type, another version, or data that says less or other is not one", () => {
  const changed = (data) => ({ ...example, data: { ...example.data, ...data } });
  assert.equal(isPapConfirm({ ...example, type: "application/vnd.datalayer.pap.sign-in+json" }), false);
  assert.equal(isPapConfirm({ ...example, version: 1 }), false);
  assert.equal(isPapConfirm({ ...example, version: 3 }), false);
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
  ]) {
    assert.equal(isPapConfirm(changed(data)), false, JSON.stringify(data));
  }
  const { session: _, ...withoutSession } = example.data;
  assert.equal(isPapConfirmData(withoutSession), false);
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
  assert.ok(isPapReplies(replies));
  assert.equal(papRepliesText(replies.data), replies.text);
  assert.deepEqual(
    replies.data.replies.map((reply) => [reply.author, reply.name]),
    [["agent", null], ["human", "Rosa"]],
  );
  assert.deepEqual(papRepliesDisplay(replies.id, replies.data), replies);
});

test("replies that say less or other are not one", () => {
  const changed = (data) => ({ ...replies, data: { ...replies.data, ...data } });
  assert.equal(isPapReplies({ ...replies, type: PAP_CONFIRM_TYPE }), false);
  // Version 1 named no conversation, 2 said `sender`: refused, not read as 3.
  assert.equal(isPapReplies({ ...replies, version: 1 }), false);
  assert.equal(isPapReplies({ ...replies, version: 2 }), false);
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
    { status: 1 },
    { responder: 1 },
    { token: "secret" },
  ]) {
    assert.equal(isPapReplies(changed(data)), false, JSON.stringify(data));
  }
  assert.throws(() => papRepliesDisplay("r1", { ...replies.data, replies: [] }), TypeError);
});

test("an unknown status reads as working and an unknown responder as human", () => {
  // Later versions may add values (§8.7): read as the most careful known one.
  const shown = papRepliesDisplay("r1", { ...replies.data, status: "paused", responder: "robot" });
  assert.deepEqual([shown.data.status, shown.data.responder], ["working", "human"]);
  assert.ok(isPapReplies(shown));
  assert.deepEqual(
    [papRepliesDisplay("r1", { ...replies.data, status: null, responder: null }).data.status],
    [null],
  );
});
