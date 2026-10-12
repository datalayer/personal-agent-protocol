/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import { decodeProtectedHeader, generateKeyPair } from "jose";

import {
  BROWSER_ASSERTION_TYPE,
  BrowserFormPosts,
  BrowserSessionClient,
  BrowserSessionError,
  Clocks,
  Signers,
  buildBrowserAssertionClaims,
  buildPapReactor,
} from "../../lib/index.js";
import { JoseSigner, verifyBrowserAssertion } from "../../lib/server.js";

const now = new Date("2026-10-10T12:00:00Z");
const fixedRandom = length => Uint8Array.from({ length }, (_, index) => index);
const options = {
  clientId: "https://agent.example/agent.json",
  pairwiseUserId: "usr_example",
  browserSessionEndpoint: "https://shop.example/poppy/browser-session",
  sessionId: "ses_example",
  returnTo: "https://orders.shop.example/current",
  companyDomain: "shop.example",
};

class ReplayCache {
  keys = new Set();

  async markOnce(key, { expiresAt }) {
    assert.ok(expiresAt > now);
    if (this.keys.has(key)) return false;
    this.keys.add(key);
    return true;
  }
}

test("builds company-bound browser claims with at most 60 seconds", () => {
  const claims = buildBrowserAssertionClaims({ ...options, now, randomBytes: fixedRandom });
  assert.equal(claims.exp - claims.iat, 60);
  assert.equal(claims.jti, "jti_AAECAwQFBgcICQoLDA0ODw");
  assert.throws(
    () => buildBrowserAssertionClaims({ ...options, returnTo: "https://attacker.example", now }),
    error => error instanceof BrowserSessionError && error.code === "invalid_return_to",
  );
  assert.throws(
    () => buildBrowserAssertionClaims({ ...options, lifetimeSeconds: 61, now }),
    error => error instanceof BrowserSessionError && error.code === "invalid_lifetime",
  );
});

test("posts and verifies a browser assertion once", async () => {
  const keys = await generateKeyPair("ES256");
  const posts = [];
  const plugin = {
    name: "@tests/pap-browser-session",
    contributes: [
      {
        point: Clocks,
        value: { now: () => now },
        options: { id: "fixed", order: 0 },
      },
      {
        point: Signers,
        value: new JoseSigner({ privateKey: keys.privateKey, keyId: "agent-key" }),
        options: { id: "signer" },
      },
      {
        point: BrowserFormPosts,
        value: {
          async post(endpoint, fields) {
            posts.push({ endpoint, fields });
          },
        },
        options: { id: "controlled-browser" },
      },
    ],
  };
  const reactor = buildPapReactor({}, [plugin]);
  const started = await new BrowserSessionClient({ reactor }).join(options);
  reactor.stop();

  assert.equal(started.returnTo, options.returnTo);
  assert.equal(posts.length, 1);
  const [{ endpoint, fields }] = posts;
  assert.equal(endpoint.toString(), options.browserSessionEndpoint);
  assert.equal(endpoint.search, "");
  assert.equal(decodeProtectedHeader(fields.assertion.reveal()).typ, BROWSER_ASSERTION_TYPE);

  const replayCache = new ReplayCache();
  const verifyOptions = {
    publicKey: keys.publicKey,
    expectedEndpoint: options.browserSessionEndpoint,
    companyDomain: options.companyDomain,
    expectedClientId: options.clientId,
    expectedPairwiseUserId: options.pairwiseUserId,
    expectedSessionId: options.sessionId,
    replayCache,
    now,
  };
  const verified = await verifyBrowserAssertion(fields.assertion, verifyOptions);
  assert.equal(verified.sessionId, options.sessionId);
  await assert.rejects(
    verifyBrowserAssertion(fields.assertion, verifyOptions),
    error => error instanceof BrowserSessionError && /already been used/.test(error.message),
  );
});
