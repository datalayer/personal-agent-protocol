/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationStateStores,
  DpopProofProviders,
  MediatedSignInClient,
  ProtectedInputs,
  SecretValue,
  TokenStores,
  buildPapReactor,
} from "../../lib/index.js";

const endpoint = "https://auth.shop.example/poppy/sign-in";
const mediated = {
  endpoint,
  fields: [
    { name: "email", label: "Email", secret: false },
    { name: "password", label: "Password", secret: true },
  ],
};
const signedOut = {
  accessToken: new SecretValue("session-token"),
  tokenType: "DPoP",
  expiresIn: 300,
  scopes: [],
  sessionKey: "K".repeat(43),
  signedIn: false,
};
const who = { tenantId: "t", issuer: "https://auth.shop.example" };
const credentials = { email: "ada@example.com", password: "correct horse" };

function memory() {
  const values = new Map();
  return {
    values,
    async put(reference, value) { values.set(reference, value); },
    async get(reference) { return values.get(reference); },
    async take(reference) { const value = values.get(reference); values.delete(reference); return value; },
    async delete(reference) { values.delete(reference); },
  };
}

function arrange(company, ...answers) {
  const asked = [];
  const state = memory();
  const tokens = memory();
  const reactor = buildPapReactor({}, [
    {
      name: "@tests/pap-mediated",
      contributes: [
        {
          point: ProtectedInputs,
          value: {
            async collect(request) {
              asked.push(request);
              return Object.fromEntries(Object.entries(answers.shift()).map(([k, v]) => [k, new SecretValue(v)]));
            },
          },
          options: { id: "trusted-surface" },
        },
        { point: AuthorizationStateStores, value: state, options: { id: "memory" } },
        { point: TokenStores, value: tokens, options: { id: "memory" } },
        { point: DpopProofProviders, value: { async create() { return new SecretValue("proof"); } }, options: { id: "dpop" } },
      ],
    },
  ]);
  const seen = [];
  const fetch = async (url, init) => {
    seen.push({ url: String(url), init });
    return company(String(url), init);
  };
  return { client: new MediatedSignInClient({ reactor, fetch }), asked, seen, state, tokens };
}

const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const complete = (extra = {}) => ({
  status: "complete", access_token: "signed-in", token_type: "DPoP", expires_in: 300,
  scope: "orders:read", refresh_token: "account-token", ...extra,
});
const signIn = (client) =>
  client.signIn({ mediated, organization: { name: "Shop", domain: "shop.example" }, scopes: ["orders:read", "orders:return"], token: signedOut, ...who });

test("the declared fields go to the endpoint once and the Session is signed in", async () => {
  const { client, asked, seen, tokens } = arrange(() => json(200, complete()), credentials);
  const result = await signIn(client);
  assert.equal(seen[0].url, endpoint);
  assert.equal(seen[0].init.headers.Authorization, "DPoP session-token");
  assert.deepEqual(JSON.parse(seen[0].init.body), { scope: "orders:read orders:return", credentials });
  assert.equal(asked[0].purpose, "credentials");
  assert.equal(result.status, "complete");
  assert.deepEqual(result.missingScopes, ["orders:return"]);
  assert.equal(tokens.values.get(result.accountTokenReference).reveal(), "account-token");
  assert.equal(JSON.stringify(result).includes("correct horse"), false);
});

test("a one-time code continues without the credentials, from the same Session only", async () => {
  let calls = 0;
  const { client, asked, seen } = arrange(() => {
    calls += 1;
    return calls === 1
      ? json(200, { status: "code_required", sign_in_id: "si_1", code: { sent_to: "a•••@example.com" }, expires_at: "2026-10-11T12:05:00Z" })
      : json(200, complete());
  }, credentials, { code: "246810" });
  const started = await signIn(client);
  assert.equal(started.status, "code_required");
  assert.equal(started.sentTo, "a•••@example.com");
  await assert.rejects(
    client.submitCode(started.reference, { token: { ...signedOut, sessionKey: "O".repeat(43) }, ...who }),
    (error) => error.code === "session_mismatch",
  );
  const done = await client.submitCode(started.reference, { token: signedOut, ...who });
  assert.equal(seen[1].url, `${endpoint}/si_1`);
  assert.deepEqual(JSON.parse(seen[1].init.body), { code: "246810" });
  assert.equal(asked[1].purpose, "one_time_code");
  assert.equal(done.status, "complete");
});

test("a redirect never carries the credentials elsewhere", async () => {
  const { client, seen } = arrange(() => new Response(null, { status: 307, headers: { location: "/elsewhere" } }), credentials);
  await assert.rejects(signIn(client));
  assert.deepEqual(seen.map((s) => s.url), [endpoint]);
});

test("an endpoint off the company domain is refused before asking", async () => {
  const { client, asked } = arrange(() => json(500, {}), credentials);
  await assert.rejects(
    client.signIn({ mediated: { ...mediated, endpoint: "https://collector.example/x" }, organization: { name: "Shop", domain: "shop.example" }, scopes: ["orders:read"], token: signedOut, ...who }),
    (error) => error.code === "unsafe_mediated_endpoint",
  );
  assert.equal(asked.length, 0);
});

test("answers must be exactly the declared fields; failed and expired are statuses", async () => {
  const partial = arrange(() => json(500, {}), { email: "a@example.com" });
  await assert.rejects(signIn(partial.client), (error) => error.code === "invalid_protected_input");
  const failed = arrange(() => json(200, { status: "failed" }), credentials);
  assert.equal((await signIn(failed.client)).status, "failed");
  const limited = arrange(() => json(429, { error: "rate_limited" }, { "retry-after": "30" }), credentials);
  await assert.rejects(signIn(limited.client), (error) => error.code === "rate_limited" && error.details.retry_after === "30");
});
