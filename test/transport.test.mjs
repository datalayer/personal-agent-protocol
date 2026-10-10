import assert from "node:assert/strict";
import test from "node:test";

import {
  DpopFetchClient,
  DpopProofProviders,
  SecretValue,
  TransportError,
  buildPapReactor,
} from "../lib/index.js";

const token = {
  accessToken: new SecretValue("session-secret"),
  tokenType: "DPoP",
  expiresIn: 300,
  scopes: ["poppy:read"],
  sessionId: "ses_example",
  signedIn: true,
};

test("uses a fresh proof for nonce retry and same-origin redirect", async () => {
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
    if (calls.length === 2)
      return new Response(null, {
        status: 307,
        headers: { Location: "/orders/current" },
      });
    return new Response('{"ok":true}', { status: 200 });
  };
  const reactor = buildPapReactor({ fetch }, [plugin]);
  const response = await new DpopFetchClient({ reactor, fetch }).request(
    "GET",
    "https://api.example/orders",
    {
      token,
      tenantId: "tenant",
      pairwiseUserId: "usr_example",
      issuer: "https://auth.example",
    },
  );
  reactor.stop();
  assert.equal(response.status, 200);
  assert.deepEqual(
    requests.map((request) => request.nonce),
    [undefined, "company-nonce", undefined],
  );
  assert.deepEqual(
    requests.map((request) => request.url),
    [
      "https://api.example/orders",
      "https://api.example/orders",
      "https://api.example/orders/current",
    ],
  );
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
      error instanceof TransportError && error.code === "cross_origin_redirect",
  );
  reactor.stop();
  assert.equal(calls, 1);
});
