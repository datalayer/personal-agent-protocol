/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  DpopFetchClient,
  DpopProofProviders,
  SecretValue,
  TransportError,
  buildPapReactor,
} from "../../lib/index.js";

const token = {
  accessToken: new SecretValue("session-secret"),
  tokenType: "DPoP",
  expiresIn: 300,
  scopes: ["poppy:read"],
  sessionId: "ses_example",
  signedIn: true,
};

test("uses a fresh proof for nonce retry, and a redirect gets nothing", async () => {
  const requests = [];
  const calls = [];
  const plugin = {
    name: "@tests/pap-transport",
    contributes: [
      {
        point: DpopProofProviders,
        value: {
          async create(request) {
            requests.push(request);
            return new SecretValue(`proof-${requests.length}`);
          },
        },
        options: { id: "proofs" },
      },
    ],
  };
  const fetch = async (input, init) => {
    calls.push({ input: input.toString(), init });
    assert.equal(init.headers.Authorization, "DPoP session-secret");
    assert.equal(init.headers.DPoP, `proof-${calls.length}`);
    if (calls.length === 1)
      return new Response(null, {
        status: 401,
        headers: {
          "WWW-Authenticate": 'DPoP error="use_dpop_nonce"',
          "DPoP-Nonce": "company-nonce",
        },
      });
    if (calls.length === 2) return new Response('{"ok":true}', { status: 200 });
    // Even on the company's own origin, a redirect is never followed with the token, a
    // proof, or the body (§3): the caller sees `redirect_refused`.
    return new Response(null, {
      status: 307,
      headers: { Location: "/orders/current" },
    });
  };
  const reactor = buildPapReactor({ fetch }, [plugin]);
  const client = new DpopFetchClient({ reactor, fetch });
  const options = {
    token,
    tenantId: "tenant",
    pairwiseUserId: "usr_example",
    issuer: "https://auth.example",
  };
  const response = await client.request("GET", "https://api.example/orders", options);
  await assert.rejects(
    client.request("GET", "https://api.example/orders", options),
    (error) => error instanceof TransportError && error.code === "redirect_refused" && error.statusCode === 307,
  );
  reactor.stop();
  assert.equal(response.status, 200);
  assert.deepEqual(
    requests.map((request) => request.nonce),
    [undefined, "company-nonce", undefined],
  );
  assert.deepEqual(
    requests.map((request) => request.url),
    Array(3).fill("https://api.example/orders"),
  );
  assert.equal(calls.length, 3);
});

test("never forwards PAP credentials across origins", async () => {
  let calls = 0;
  const plugin = {
    name: "@tests/pap-transport-cross-origin",
    contributes: [
      {
        point: DpopProofProviders,
        value: { create: async () => new SecretValue("proof") },
        options: { id: "proofs" },
      },
    ],
  };
  const fetch = async () => {
    calls += 1;
    return new Response(null, {
      status: 307,
      headers: { Location: "https://attacker.example/collect" },
    });
  };
  const reactor = buildPapReactor({ fetch }, [plugin]);
  const client = new DpopFetchClient({ reactor, fetch });
  await assert.rejects(
    client.request("GET", "https://api.example/orders", {
      token,
      tenantId: "tenant",
      pairwiseUserId: "usr_example",
      issuer: "https://auth.example",
    }),
    (error) =>
      error instanceof TransportError && error.code === "redirect_refused",
  );
  reactor.stop();
  assert.equal(calls, 1);
});
