/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// What draft 0.4 adds, both sides, in one process: the port of
// personal_agent_protocol/__tests__/test_draft_04.py.
//
// Direct Sign-In preferred (§4, P4-01).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  DEVICE_CODE_GRANT,
  MEDIATED_GRANT,
  parseDiscoveryDocument,
  parseOAuthServerMetadata,
  preferredSignIn,
  signInTypes,
} from "../../lib/index.js";
import { CompanyConfig } from "../../lib/server.js";
import { CONFIG, manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, inProcessFetch } from "./support/world.mjs";

const fixtures = new URL("../../protocol/fixtures/", import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, fixtures), "utf8"));

function company(grants, { disabled = false } = {}) {
  const document = fixture("discovery-valid.json");
  if (disabled) document.auth.disabled = true;
  const metadata = fixture("oauth-metadata-valid.json");
  metadata.grant_types_supported = ["refresh_token", ...grants];
  if (!grants.includes("authorization_code")) delete metadata.authorization_endpoint;
  if (!grants.includes(DEVICE_CODE_GRANT)) delete metadata.device_authorization_endpoint;
  return {
    discoveryUrl: "https://example.com/.well-known/poppy.json",
    document: parseDiscoveryDocument(document),
    oauthMetadata: parseOAuthServerMetadata(metadata),
  };
}

// Direct Sign-In preferred (§4) ------------------------------------------------------

test("Direct Sign-In is preferred when offered", () => {
  const everything = company(["authorization_code", DEVICE_CODE_GRANT, MEDIATED_GRANT]);
  assert.deepEqual(signInTypes(everything), ["direct", "device", "mediated"]);
  assert.equal(preferredSignIn(everything), "direct");
  // A Company guarding high-value resources offers Direct only (RFC 10027 §6.2.1.5).
  assert.equal(preferredSignIn(company(["authorization_code"])), "direct");
  const deviceOnly = company([DEVICE_CODE_GRANT, MEDIATED_GRANT]);
  assert.deepEqual(signInTypes(deviceOnly), ["device", "mediated"]);
  assert.equal(preferredSignIn(deviceOnly), "device");
  assert.equal(preferredSignIn(company([MEDIATED_GRANT])), "mediated");
  assert.equal(preferredSignIn(company([])), undefined);
  const disabled = company(["authorization_code", DEVICE_CODE_GRANT], { disabled: true });
  assert.deepEqual(signInTypes(disabled), []);
  assert.equal(preferredSignIn(disabled), undefined);
  const { oauthMetadata: _, ...noIssuer } = everything;
  assert.equal(preferredSignIn(noIssuer), undefined);
});

test("the reference company offers Direct Sign-In", () => {
  assert.ok(CONFIG.direct && CONFIG.device);
  const { service } = manzanita({ fetch: inProcessFetch({}), clock: new MutableClock() });
  const grants = service.oauthMetadata().grant_types_supported;
  assert.ok(grants.includes("authorization_code") && grants.includes(DEVICE_CODE_GRANT));
  const bank = new CompanyConfig({
    name: "Bank",
    domain: "bank.example",
    scopes: ["accounts:read"],
    scopeDescriptions: { "accounts:read": "See your accounts" },
    operations: false,
    device: false,
  });
  assert.ok(bank.direct && !bank.device);
});
