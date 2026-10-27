/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Joining the agent's own browser (§5): the port of personal_agent_protocol/__tests__/test_browser.py.
import assert from "node:assert/strict";
import test from "node:test";

import { decodeJwt } from "jose";

import {
  BrowserJoins,
  BrowserSessionClient,
  BrowserSessionError,
  Clocks,
  DpopProofProviders,
  InMemorySessionKeys,
  JoseDpopProofProvider,
  SecretValue,
  buildPapReactor,
} from "../../lib/index.js";
import { verifyDpopProof } from "../../lib/server.js";

const NOW = new Date("2026-10-10T12:00:00Z");
const ENDPOINT = "https://shop.example/poppy/browser-session";
const ISSUER = "https://shop.example";
const CODE = "bc_Vn3qT8xLw2Rk9mZ4yHc1Ad";

class ReplayCache {
  keys = new Set();

  async markOnce(key) {
    if (this.keys.has(key)) return false;
    this.keys.add(key);
    return true;
  }
}

/** The agent's own browser: the page it loaded holds the code; it submits the proof. */
class Browser {
  constructor(code = CODE) {
    this.code = code;
    this.loaded = [];
    this.submitted = [];
  }

  async loadJoinForm(endpoint) {
    this.loaded.push(String(endpoint));
    return new SecretValue(this.code);
  }

  async submitJoinForm(proof) {
    this.submitted.push(proof);
  }
}

async function joined(browser) {
  const provider = new JoseDpopProofProvider({ keys: new InMemorySessionKeys(), now: () => NOW });
  const reactor = buildPapReactor({}, [
    {
      name: "@tests/pap-browser-join",
      contributes: [
        { point: BrowserJoins, value: browser, options: { id: "browser" } },
        { point: DpopProofProviders, value: provider, options: { id: "keys" } },
        { point: Clocks, value: { now: () => NOW }, options: { id: "fixed", order: 0 } },
      ],
    },
  ]);
  const sessionKey = await provider.newSessionKey({ tenantId: "t", issuer: ISSUER });
  try {
    const started = await new BrowserSessionClient({ reactor }).join({
      browserSessionEndpoint: ENDPOINT,
      tenantId: "t",
      issuer: ISSUER,
      sessionKey,
    });
    assert.deepEqual(started, { endpoint: ENDPOINT, joinedAt: NOW });
  } finally {
    reactor.stop();
  }
  return { sessionKey, browser };
}

test("signs the page's code with the Session Key and submits it", async () => {
  const { sessionKey, browser } = await joined(new Browser());
  assert.deepEqual(browser.loaded, [ENDPOINT]);
  assert.equal(browser.submitted.length, 1);
  const proof = browser.submitted[0];
  const payload = decodeJwt(proof.reveal());
  // POST to the endpoint, the code as its nonce, no `ath`: no Session Token (§5).
  assert.deepEqual([payload.htm, payload.htu, payload.nonce], ["POST", ENDPOINT, CODE]);
  assert.equal("ath" in payload, false);
  const verified = await verifyDpopProof(proof, {
    method: "POST",
    url: ENDPOINT,
    replayCache: new ReplayCache(),
    nonce: CODE,
    now: NOW,
  });
  // Signed with the Session's own key, which names it (§4.3).
  assert.equal(verified.keyThumbprint, sessionKey);
});

test("a proof over another code is refused", async () => {
  const { browser } = await joined(new Browser());
  await assert.rejects(
    verifyDpopProof(browser.submitted[0], {
      method: "POST",
      url: ENDPOINT,
      replayCache: new ReplayCache(),
      nonce: "bc_someone_elses_code_000000",
      now: NOW,
    }),
    /nonce/,
  );
});

test("a code too short to be one-time is never signed", async () => {
  const browser = new Browser("short");
  await assert.rejects(
    joined(browser),
    (error) => error instanceof BrowserSessionError && error.code === "invalid_join_code",
  );
  assert.deepEqual(browser.submitted, []);
});
