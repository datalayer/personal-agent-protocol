/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Both SDKs name the same PAP draft and Operations version (as Python's test_profile.py
// checks the repository's other statements of it): Python's constants are read from its
// source here, so either side changing alone fails.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { OPERATIONS_VERSION, PROTOCOL_PROFILE, PROTOCOL_REVISION } from "../../lib/index.js";

const ROOT = new URL("../../", import.meta.url);

function python(module, name) {
  const source = readFileSync(new URL(`personal_agent_protocol/${module}`, ROOT), "utf8");
  const match = source.match(new RegExp(`^${name} = "([^"]+)"$`, "m"));
  assert.ok(match, `${module} defines no ${name}`);
  return match[1];
}

test("the Python SDK declares the same profile, revision, and Operations version", () => {
  assert.equal(PROTOCOL_PROFILE, python("profile.py", "PROTOCOL_PROFILE"));
  assert.equal(PROTOCOL_REVISION, python("profile.py", "PROTOCOL_REVISION"));
  assert.equal(OPERATIONS_VERSION, python("operations.py", "OPERATIONS_VERSION"));
});

test("the npm package states the profile and the Operations version", () => {
  const { description } = JSON.parse(readFileSync(new URL("package.json", ROOT), "utf8"));
  assert.equal(
    description,
    `TypeScript SDK for Personal Agent Protocol draft ${PROTOCOL_PROFILE} (${PROTOCOL_REVISION}) and its Operations extension v${OPERATIONS_VERSION}`,
  );
});
