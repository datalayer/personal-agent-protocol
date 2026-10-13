/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// An operation to confirm and what it came to as reactor.ui displays: the
// examples the Python tests write (test_ui.py), read and checked by the
// TypeScript SDK.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  PAP_CONFIRM_TYPE,
  PAP_OUTCOME_TYPE,
  PAP_REPLIES_TYPE,
  isPapConfirm,
  isPapConfirmData,
  isPapOutcome,
  isPapReplies,
  papConfirmDisplay,
  papConfirmText,
  papOutcomeDisplay,
  papOutcomeText,
  papRepliesDisplay,
  papRepliesText,
} from "../../lib/index.js";

const example = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures/pap-confirm-display.json", import.meta.url), "utf8"),
);

test("the Python SDK's display is an operation to confirm, its text said the same", () => {
  assert.equal(example.type, PAP_CONFIRM_TYPE);
  assert.ok(isPapConfirm(example));
  assert.equal(papConfirmText(example.data), example.text);
  assert.deepEqual(papConfirmDisplay(example.id, example.data), example);
});

test("another type, another version, or data that says less or other is not one", () => {
  const changed = (data) => ({ ...example, data: { ...example.data, ...data } });
  assert.equal(isPapConfirm({ ...example, type: "application/vnd.datalayer.pap.sign-in+json" }), false);
  assert.equal(isPapConfirm({ ...example, version: 2 }), false);
  for (const data of [
    { company: " " },
    { summary: "" },
    { operation_ref: "" },
    { revision: 0 },
    { revision: 1.5 },
    { does: "spend" },
    { terms: [] },
    { expires_at: "tomorrow" },
    { was: { revision: 2, terms: {} } },
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
});

test("a display is made only of an operation to confirm", () => {
  const data = { ...example.data, was: null, session: null };
  const display = papConfirmDisplay("c1", data);
  assert.ok(isPapConfirm(display));
  assert.equal(display.text, `${data.company} asks you to confirm: ${data.summary} (version 2)`);
  assert.throws(() => papConfirmDisplay("c1", { ...data, revision: 0 }), TypeError);
  assert.throws(() => papConfirmDisplay("", data), TypeError);
});

const outcome = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures/pap-outcome-display.json", import.meta.url), "utf8"),
);

test("the Python SDK's outcome is one, the company's result word for word", () => {
  assert.equal(outcome.type, PAP_OUTCOME_TYPE);
  assert.ok(isPapOutcome(outcome));
  assert.equal(papOutcomeText(outcome.data), outcome.text);
  assert.ok(outcome.text.includes(outcome.data.result));
  assert.deepEqual(papOutcomeDisplay(outcome.id, outcome.data), outcome);
});

test("an outcome that says less or other is not one", () => {
  const changed = (data) => ({ ...outcome, data: { ...outcome.data, ...data } });
  assert.equal(isPapOutcome({ ...outcome, type: PAP_CONFIRM_TYPE }), false);
  assert.equal(isPapOutcome({ ...outcome, version: 2 }), false);
  for (const data of [
    { company: " " },
    { summary: "" },
    { operation_ref: "" },
    { revision: 0 },
    { state: "proposed" },
    { result: null },
    { result: " " },
    { state: "in_progress" },
    { approved_by: "rule" },
    { token: "secret" },
  ]) {
    assert.equal(isPapOutcome(changed(data)), false, JSON.stringify(data));
  }
});

test("in progress, the company's words for the operation and that the outcome is not known yet", () => {
  const data = { ...outcome.data, state: "in_progress", result: null, approved_by: null };
  const display = papOutcomeDisplay("o1", data);
  assert.equal(
    display.text,
    `Still in progress at ${data.company}: ${data.summary} (version 2) The outcome is not known yet.`,
  );
  assert.throws(() => papOutcomeDisplay("o1", { ...data, result: "done" }), TypeError);
});

const replies = JSON.parse(
  readFileSync(new URL("../../protocol/fixtures/pap-replies-display.json", import.meta.url), "utf8"),
);

test("the Python SDK's replies are one, each with who wrote it, word for word", () => {
  assert.equal(replies.type, PAP_REPLIES_TYPE);
  assert.ok(isPapReplies(replies));
  assert.equal(papRepliesText(replies.data), replies.text);
  assert.deepEqual(
    replies.data.replies.map((reply) => reply.sender),
    ["agent", "human"],
  );
  assert.deepEqual(papRepliesDisplay(replies.id, replies.data), replies);
});

test("replies that say less or other are not one", () => {
  const changed = (data) => ({ ...replies, data: { ...replies.data, ...data } });
  assert.equal(isPapReplies({ ...replies, type: PAP_OUTCOME_TYPE }), false);
  // Version 1 named no conversation: refused, not read as 2.
  assert.equal(isPapReplies({ ...replies, version: 1 }), false);
  assert.equal(replies.data.conversation, "conv_4Kp9");
  for (const data of [
    { company: " " },
    { conversation: "" },
    { conversation: "has space" },
    { conversation: undefined },
    { replies: [] },
    { replies: [{ sender: "model", text: "Hello" }] },
    { replies: [{ sender: "agent", text: " " }] },
    { replies: [{ sender: "agent", text: "Hello", token: "secret" }] },
    { status: "waiting" },
    { responder: "company" },
    { token: "secret" },
  ]) {
    assert.equal(isPapReplies(changed(data)), false, JSON.stringify(data));
  }
  assert.throws(() => papRepliesDisplay("r1", { ...replies.data, replies: [] }), TypeError);
});
