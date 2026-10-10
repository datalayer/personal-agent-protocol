import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationStateStores,
  Clocks,
  DeviceSignInClient,
  DpopProofProviders,
  SecretValue,
  Signers,
  TokenStores,
  buildPapReactor,
} from "../../lib/index.js";

function devicePlugin() {
  const state = new Map();
  const tokens = new Map();
  let now = new Date("2026-10-10T00:00:00Z");
  const plugin = {
    name: "@tests/pap-device-sign-in",
    contributes: [
      {
        point: Clocks,
        value: { now: () => now },
        options: { id: "mutable" },
      },
      {
        point: AuthorizationStateStores,
        value: {
          async put(reference, value) {
            state.set(reference, value);
          },
          async take(reference) {
            const value = state.get(reference);
            state.delete(reference);
            return value;
          },
        },
        options: { id: "memory" },
      },
      {
        point: TokenStores,
        value: {
          async put(reference, token) {
            tokens.set(reference, token);
          },
          async get(reference) {
            return tokens.get(reference);
          },
          async delete(reference) {
            tokens.delete(reference);
          },
        },
        options: { id: "memory" },
      },
      {
        point: Signers,
        value: { async sign() { return new SecretValue("client-assertion"); } },
        options: { id: "signer" },
      },
      {
        point: DpopProofProviders,
        value: { async create() { return new SecretValue("proof"); } },
        options: { id: "dpop" },
      },
    ],
  };
  return {
    plugin,
    tokens,
    advance(seconds) {
      now = new Date(now.getTime() + seconds * 1000);
    },
  };
}

const options = {
  deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  issuer: "https://auth.example.com",
  clientId: "https://agent.example/agent.json",
  scopes: ["poppy:read", "poppy:write"],
  tenantId: "application-one",
  pairwiseUserId: "usr_AAECAwQFBgcICQoLDA0ODw",
  sessionId: "ses_existing",
};

test("Device Sign-In paces polling and stores the Account Token", async () => {
  const extension = devicePlugin();
  const forms = [];
  let calls = 0;
  const fetch = async (_input, init) => {
    calls += 1;
    forms.push(new URLSearchParams(init.body));
    if (calls === 1) {
      assert.equal(init.headers.DPoP, undefined);
      return Response.json({
        device_code: "private-device-code",
        user_code: "WDJB-MJHT",
        verification_uri: "https://company.example/device",
        verification_uri_complete: "https://company.example/device?user_code=WDJB-MJHT",
        expires_in: 600,
        interval: 5,
      });
    }
    assert.equal(init.headers.DPoP, "proof");
    if (calls === 2) {
      return Response.json({ error: "authorization_pending" }, { status: 400 });
    }
    if (calls === 3) return Response.json({ error: "slow_down" }, { status: 400 });
    return Response.json({
      access_token: "signed-in-session-token",
      token_type: "DPoP",
      expires_in: 300,
      scope: "poppy:read",
      session_id: "ses_existing",
      signed_in: true,
      refresh_token: "private-account-token",
    });
  };
  const reactor = buildPapReactor({ fetch }, [extension.plugin]);
  const client = new DeviceSignInClient({ reactor, fetch });
  const started = await client.begin(options);
  assert.equal(started.userCode, "WDJB-MJHT");
  assert.ok(!JSON.stringify(started).includes("private-device-code"));

  const early = await client.poll(started.reference);
  assert.equal(early.status, "pending");
  assert.equal(calls, 1);
  extension.advance(5);
  await client.poll(started.reference);
  extension.advance(5);
  const slowed = await client.poll(started.reference);
  assert.equal(slowed.retryAt.toISOString(), "2026-10-10T00:00:20.000Z");
  extension.advance(10);
  const complete = await client.poll(started.reference);
  reactor.stop();

  assert.equal(complete.status, "complete");
  assert.deepEqual(complete.grantedScopes, ["poppy:read"]);
  assert.deepEqual(complete.missingScopes, ["poppy:write"]);
  assert.equal(complete.token.accountToken, undefined);
  assert.equal(extension.tokens.get(complete.accountTokenReference).reveal(), "private-account-token");
  assert.equal(forms[1].get("device_code"), "private-device-code");
});
