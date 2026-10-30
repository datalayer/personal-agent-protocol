/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Joining the agent's own browser (§6): load the form, authorize its code, submit it.
import assert from "node:assert/strict";
import test from "node:test";

import { decodeJwt, generateKeyPair } from "jose";

import {
  BrowserJoins,
  BrowserSessionClient,
  BrowserSessionError,
  Clocks,
  DelegatedSessionSigner,
  InMemoryDelegatedKeys,
  PapSession,
  SecretValue,
  SessionFetchClient,
  SessionSigners,
  accessTokenFromResponse,
  buildPapReactor,
  parseTokenResponse,
  tokenHash,
} from "../../lib/index.js";
import { JoseSigner } from "../../lib/server.js";

const NOW = new Date("2026-10-10T12:00:00Z");
const ENDPOINT = "https://shop.example/poppy/browser-session";
const AUTHORIZE = `${ENDPOINT}/authorize`;
const ISSUER = "https://shop.example";
const CODE = "bc_Vn3qT8xLw2Rk9mZ4yHc1Ad";
const SESSION = new PapSession({
  sid: "S".repeat(22),
  sub: "usr_pairwise",
  issuer: ISSUER,
  clientId: "https://agent.example/agent.json",
  tenantId: "t",
});

/** The agent's own browser: the page it loaded holds the code; it submits the form. */
class Browser {
  constructor(code = CODE) {
    this.code = code;
    this.loaded = [];
    this.submitted = 0;
  }

  async loadJoinForm(endpoint) {
    this.loaded.push(String(endpoint));
    return new SecretValue(this.code);
  }

  async submitJoinForm() {
    this.submitted += 1;
  }
}

async function joined(browser, { company = () => new Response(null, { status: 204 }), token } = {}) {
  const sent = [];
  const fetch = async (input, init) => {
    sent.push({ url: String(input), ...init });
    return company(input, init);
  };
  const { privateKey } = await generateKeyPair("ES256");
  const signer = new DelegatedSessionSigner({
    custody: new InMemoryDelegatedKeys(),
    signer: new JoseSigner({ privateKey, keyId: "agent-key" }),
    now: () => NOW,
  });
  const reactor = buildPapReactor({ fetch }, [
    {
      name: "@tests/pap-browser-join",
      contributes: [
        { point: BrowserJoins, value: browser, options: { id: "browser" } },
        { point: SessionSigners, value: signer, options: { id: "delegated-keys" } },
        { point: Clocks, value: { now: () => NOW }, options: { id: "fixed", order: 0 } },
      ],
    },
  ]);
  try {
    const started = await new BrowserSessionClient({
      reactor,
      transport: new SessionFetchClient({ reactor, fetch }),
    }).join({ browserSessionEndpoint: ENDPOINT, session: SESSION, ...(token === undefined ? {} : { token }) });
    assert.deepEqual(started, { endpoint: ENDPOINT, joinedAt: NOW });
  } finally {
    reactor.stop();
  }
  return sent;
}

test("the agent authorizes the page's code and the browser submits the form", async () => {
  const browser = new Browser();
  const sent = await joined(browser);
  assert.deepEqual(browser.loaded, [ENDPOINT]);
  assert.equal(browser.submitted, 1);
  assert.deepEqual(sent.map(({ method, url }) => [method, url]), [["POST", AUTHORIZE]]);
  assert.deepEqual(JSON.parse(sent[0].body), { code: CODE });
  const payload = decodeJwt(sent[0].headers["Poppy-Session"]);
  // Signed out: the Session header alone, with no `ath` (§6).
  assert.deepEqual([payload.htm, payload.htu, payload.sid], ["POST", AUTHORIZE, SESSION.sid]);
  assert.equal("ath" in payload, false);
  assert.equal("Authorization" in sent[0].headers, false);
});

test("signed in, the access token goes with the agent's own request", async () => {
  const token = accessTokenFromResponse(
    parseTokenResponse({ access_token: "access-secret", token_type: "Bearer", scope: "orders:read" }),
  );
  const browser = new Browser();
  const sent = await joined(browser, { token });
  assert.equal(sent[0].headers.Authorization, "Bearer access-secret");
  assert.equal(decodeJwt(sent[0].headers["Poppy-Session"]).ath, await tokenHash(token.accessToken));
  assert.equal(browser.submitted, 1);
});

test("a code the company refuses is never submitted", async () => {
  const browser = new Browser();
  await assert.rejects(
    joined(browser, {
      company: () =>
        new Response('{"error":"invalid_request"}', { status: 400, headers: { "content-type": "application/json" } }),
    }),
    (error) => error instanceof BrowserSessionError && error.code === "join_not_authorized" && error.statusCode === 400,
  );
  assert.equal(browser.submitted, 0);
});

test("a redirect at /authorize gets nothing, and nothing is submitted", async () => {
  const browser = new Browser();
  await assert.rejects(
    joined(browser, {
      company: () => new Response(null, { status: 307, headers: { Location: "https://elsewhere.example/" } }),
    }),
    (error) => error instanceof BrowserSessionError && error.code === "redirect_refused",
  );
  assert.equal(browser.submitted, 0);
});

test("a code too short to be one-time is never signed", async () => {
  const browser = new Browser("short");
  const sent = [];
  await assert.rejects(
    joined(browser, {
      company: (input) => {
        sent.push(String(input));
        return new Response(null, { status: 204 });
      },
    }),
    (error) => error instanceof BrowserSessionError && error.code === "invalid_join_code",
  );
  assert.deepEqual(sent, []);
  assert.equal(browser.submitted, 0);
});
