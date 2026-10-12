/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// An operation to confirm as a reactor.ui display: the example the Python
// tests write (test_ui.py), read and checked by the TypeScript SDK.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  PAP_CONFIRM_TYPE,
  isPapConfirm,
  isPapConfirmData,
  papConfirmDisplay,
  papConfirmText,
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
