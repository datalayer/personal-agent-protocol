import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationCodeGrant,
  AuthorizationError,
  buildDirectSignInRequest,
  validateDirectSignInCallback,
} from "../lib/index.js";

const fixedRandom = (length) => Uint8Array.from({ length }, (_, index) => index);

async function request() {
  return buildDirectSignInRequest({
    authorizationEndpoint: "https://auth.example.com/oauth/authorize",
    issuer: "https://auth.example.com",
    clientId: "https://agent.example/agent.json",
    redirectUri: "https://agent.example/oauth/callback",
    scopes: ["poppy:read", "poppy:write"],
    randomBytes: fixedRandom,
  });
}

test("builds Direct Sign-In state and S256 PKCE", async () => {
  const signIn = await request();
  const url = new URL(signIn.authorizationUrl.reveal());

  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("scope"), "poppy:read poppy:write");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  assert.equal(signIn.codeVerifier.reveal().length, 43);
  assert.equal(JSON.stringify(signIn).includes(signIn.state.reveal()), false);
});

test("validates the callback and redacts the exchange grant", async () => {
  const signIn = await request();
  const callback = new URL(signIn.redirectUri);
  callback.searchParams.set("code", "one-time-code");
  callback.searchParams.set("state", signIn.state.reveal());
  callback.searchParams.set("iss", signIn.issuer);
  const result = validateDirectSignInCallback(signIn, callback.toString());
  const grant = new AuthorizationCodeGrant({
    code: result.code.reveal(),
    redirectUri: signIn.redirectUri,
    codeVerifier: signIn.codeVerifier.reveal(),
    sessionId: "ses_2Lm0",
    clientId: signIn.clientId,
    clientAssertion: "signed-client-assertion",
  });

  assert.equal(grant.toForm().get("code"), "one-time-code");
  assert.equal(JSON.stringify(grant).includes("one-time-code"), false);
  assert.equal(JSON.stringify(grant).includes("signed-client-assertion"), false);
});

for (const [name, values, code] of [
  ["state mismatch", { state: "attacker-state" }, "state_mismatch"],
  ["issuer mix-up", { iss: "https://attacker.example" }, "issuer_mismatch"],
  ["missing code", { code: "" }, "invalid_callback"],
  ["user denial", { error: "access_denied", code: "" }, "authorization_denied"],
]) {
  test(`rejects ${name}`, async () => {
    const signIn = await request();
    const callback = new URL(signIn.redirectUri);
    const parameters = {
      code: "one-time-code",
      state: signIn.state.reveal(),
      iss: signIn.issuer,
      ...values,
    };
    for (const [key, value] of Object.entries(parameters)) callback.searchParams.set(key, value);

    assert.throws(
      () => validateDirectSignInCallback(signIn, callback.toString()),
      (error) => error instanceof AuthorizationError && error.code === code,
    );
  });
}

test("rejects weak authorization entropy", async () => {
  await assert.rejects(
    buildDirectSignInRequest({
      authorizationEndpoint: "https://auth.example.com/oauth/authorize",
      issuer: "https://auth.example.com",
      clientId: "https://agent.example/agent.json",
      redirectUri: "https://agent.example/oauth/callback",
      scopes: ["poppy:read"],
      randomBytes: () => new Uint8Array(4),
    }),
    (error) => error instanceof AuthorizationError && error.code === "weak_entropy",
  );
});

test("rejects duplicate callback security parameters", async () => {
  const signIn = await request();
  const callback = new URL(signIn.redirectUri);
  callback.searchParams.append("code", "one-time-code");
  callback.searchParams.append("state", signIn.state.reveal());
  callback.searchParams.append("state", "second-state");
  callback.searchParams.append("iss", signIn.issuer);

  assert.throws(
    () => validateDirectSignInCallback(signIn, callback.toString()),
    (error) => error instanceof AuthorizationError && error.code === "invalid_callback",
  );
});

test("rejects callbacks at another redirect location", async () => {
  const signIn = await request();
  const callback = new URL("https://agent.example/other/callback");
  callback.searchParams.set("code", "one-time-code");
  callback.searchParams.set("state", signIn.state.reveal());
  callback.searchParams.set("iss", signIn.issuer);

  assert.throws(
    () => validateDirectSignInCallback(signIn, callback.toString()),
    (error) => error instanceof AuthorizationError && error.code === "redirect_mismatch",
  );
});
