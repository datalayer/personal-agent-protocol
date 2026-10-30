/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The shared fixtures, and what the TypeScript reference company publishes, against
// upstream's JSON Schemas: the same as personal_agent_protocol/__tests__/test_schemas.py.
// Formats are annotations here, as in Python's validator.
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";

import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentIdentity, inProcessFetch } from "./support/world.mjs";

const read = (path) => JSON.parse(readFileSync(new URL(`../../protocol/${path}`, import.meta.url), "utf8"));

const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: false });
const SCHEMAS = readdirSync(new URL("../../protocol/schemas/", import.meta.url)).filter((name) => name.endsWith(".schema.json"));
for (const name of SCHEMAS) ajv.addSchema(read(`schemas/${name}`), name);

function errors(schema, document) {
  const validate = ajv.getSchema(`${schema}.schema.json`);
  assert.ok(validate, `no schema ${schema}`);
  return validate(document) ? [] : validate.errors.map((item) => `${item.instancePath} ${item.message}`);
}

/** Each shared fixture and the upstream schema it is an instance of. */
const FIXTURE_SCHEMAS = {
  "discovery-valid.json": "poppy",
  "oauth-metadata-valid.json": "authorization-server-metadata",
  "protected-resource-metadata-valid.json": "protected-resource-metadata",
  "client-metadata-valid.json": "client-metadata",
  "feedback-report-valid.json": "feedback-report",
  "alternative-valid.json": "alternative",
  "token-response-valid.json": "token-response",
  "session-jwt-valid.json": "session-jwt",
  "delegation-valid.json": "delegation",
  "invalid-session-valid.json": "oauth-error",
  "operation-valid.json": "operation",
  "conversation-events-valid.json": "events-response",
};

for (const [fixture, schema] of Object.entries(FIXTURE_SCHEMAS)) {
  test(`${fixture} is valid by the upstream ${schema} schema`, () => {
    assert.deepEqual(errors(schema, read(`fixtures/${fixture}`)), []);
  });
}

test("the schemas refuse what they should", () => {
  assert.notDeepEqual(errors("poppy", { protocol_version: "0.3" }), []);
  assert.notDeepEqual(errors("token-response", { token_type: "Bearer" }), []);
});

test("each positive discovery case is valid by the upstream schema", () => {
  const cases = read("fixtures/conformance/protocol.json").cases.filter(
    (item) => item.check === "discovery_document" && item.kind === "positive",
  );
  assert.ok(cases.length > 0);
  for (const item of cases) assert.deepEqual(errors("poppy", item.input), [], item.id);
});

test("what the reference company publishes is valid by the upstream schemas", async () => {
  const sites = {};
  const fetch = inProcessFetch(sites);
  const { service } = manzanita({ fetch, clock: new MutableClock() });
  sites["manzanita.example"] = service;
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  const published = {
    "https://manzanita.example/.well-known/poppy.json": "poppy",
    "https://manzanita.example/.well-known/oauth-authorization-server": "authorization-server-metadata",
    "https://manzanita.example/.well-known/oauth-protected-resource": "protected-resource-metadata",
  };
  for (const [url, schema] of Object.entries(published)) {
    const response = await fetch(url);
    assert.equal(response.status, 200, url);
    assert.deepEqual(errors(schema, await response.json()), [], url);
  }
  assert.deepEqual(errors("client-metadata", identity.metadata), []);
});
