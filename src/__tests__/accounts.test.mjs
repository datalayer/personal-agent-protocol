/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  AccountTokenClient,
  DpopProofProviders,
  SecretValue,
  Signers,
  TokenStores,
  buildPapReactor,
} from "../../lib/index.js";

const context = {
  tokenEndpoint: "https://auth.shop.example/oauth/token",
  revocationEndpoint: "https://auth.shop.example/oauth/revoke",
  issuer: "https://auth.shop.example",
  clientId: "https://assistant.example/agent.json",
  tenantId: "tenant",
  pairwiseUserId: "usr_pairwise",
};

function arrange(company) {
  const tokens = new Map([["account_ref", new SecretValue("account-token-1")]]);
  const proofs = [];
  const reactor = buildPapReactor({}, [
    {
      name: "@tests/pap-accounts",
      contributes: [
        {
          point: TokenStores,
          value: {
            async put(reference, token) { tokens.set(reference, token); },
            async get(reference) { return tokens.get(reference); },
            async delete(reference) { tokens.delete(reference); },
          },
          options: { id: "memory" },
        },
        { point: Signers, value: { async sign() { return new SecretValue("assertion"); } }, options: { id: "signer" } },
        {
          point: DpopProofProviders,
          value: { async create(request) { proofs.push(request); return new SecretValue("proof"); } },
          options: { id: "dpop" },
        },
      ],
    },
  ]);
  const fetch = async (url, init) => company(String(url), Object.fromEntries(new URLSearchParams(init.body)), init);
  return { client: new AccountTokenClient({ reactor, fetch }), tokens, proofs };
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

const signedIn = (extra = {}) => ({
  access_token: "session-token",
  token_type: "DPoP",
  expires_in: 300,
  scope: "orders:read",
  session_id: "ses_1",
  signed_in: true,
  ...extra,
});

test("refresh signs the Session in and rotates the stored token", async () => {
  const seen = [];
  const { client, tokens, proofs } = arrange((_, form) => {
    seen.push(form);
    return json(200, signedIn({ refresh_token: "account-token-2" }));
  });
  const result = await client.refresh("account_ref", { context, sessionId: "ses_1" });
  assert.equal(result.status, "signed_in");
  assert.equal(result.rotated, true);
  assert.equal(result.token.accountToken, undefined);
  assert.equal(tokens.get("account_ref").reveal(), "account-token-2");
  assert.equal(seen[0].grant_type, "refresh_token");
  assert.equal(seen[0].session_id, "ses_1");
  assert.equal(proofs.length, 1);
});

test("a narrower refresh reports what was left out; a wider one is re-consent", async () => {
  const { client } = arrange((_, form) =>
    form.scope.includes("orders:admin")
      ? json(400, { error: "invalid_scope" })
      : json(200, signedIn()),
  );
  const narrowed = await client.refresh("account_ref", {
    context, sessionId: "ses_1", scopes: ["orders:read", "orders:return"],
  });
  assert.deepEqual(narrowed.missingScopes, ["orders:return"]);
  const wider = await client.refresh("account_ref", { context, sessionId: "ses_1", scopes: ["orders:admin"] });
  assert.equal(wider.status, "re_consent_required");
});

test("invalid_grant deletes the token and leaves the Session signed out", async () => {
  const { client, tokens } = arrange(() => json(400, { error: "invalid_grant" }));
  const result = await client.refresh("account_ref", { context, sessionId: "ses_1" });
  assert.equal(result.status, "signed_out");
  assert.equal(tokens.has("account_ref"), false);
});

test("concurrent refreshes rotate one after the other", async () => {
  const used = [];
  const { client, tokens } = arrange(async (_, form) => {
    used.push(form.refresh_token);
    await new Promise((resolve) => setTimeout(resolve, 1));
    const next = Number(form.refresh_token.split("-").pop()) + 1;
    return json(200, signedIn({ refresh_token: `account-token-${next}` }));
  });
  await Promise.all([
    client.refresh("account_ref", { context, sessionId: "ses_1" }),
    client.refresh("account_ref", { context, sessionId: "ses_1" }),
  ]);
  assert.deepEqual(used, ["account-token-1", "account-token-2"]);
  assert.equal(tokens.get("account_ref").reveal(), "account-token-3");
});

test("one DPoP nonce retry with a fresh proof", async () => {
  let calls = 0;
  const { client, proofs } = arrange(() => {
    calls += 1;
    return calls === 1 ? json(400, { error: "use_dpop_nonce" }, { "dpop-nonce": "n-1" }) : json(200, signedIn());
  });
  await client.refresh("account_ref", { context, sessionId: "ses_1" });
  assert.deepEqual(proofs.map((p) => p.nonce), [undefined, "n-1"]);
});

test("revocation forgets the token once the company answers, keeps it if refused", async () => {
  const ok = arrange((_, form, init) => {
    assert.equal(form.token_type_hint, "refresh_token");
    assert.equal(init.headers.DPoP, undefined);
    return new Response(null, { status: 200 });
  });
  assert.deepEqual(await ok.client.revoke("account_ref", { context }), { revoked: true, deletedLocally: true });
  assert.equal(ok.tokens.has("account_ref"), false);

  const refused = arrange(() => json(503, { error: "temporarily_unavailable" }));
  await assert.rejects(refused.client.revoke("account_ref", { context }));
  assert.equal(refused.tokens.has("account_ref"), true);
});
