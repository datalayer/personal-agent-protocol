/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationStateStores,
  AuthorizationCodeGrant,
  AuthorizationError,
  BrowserHandoffs,
  DirectSignInClient,
  DpopProofProviders,
  Signers,
  TokenStores,
  buildPapReactor,
  buildDirectSignInRequest,
  validateDirectSignInCallback,
} from "../../lib/index.js";

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

function orchestrationPlugin() {
  const values = new Map();
  const tokens = new Map();
  const browserUrls = [];
  const proofRequests = [];
  const purposes = [];
  let signature = 0;
  return {
    plugin: {
      name: "@tests/pap-direct-sign-in",
      contributes: [
        {
          point: AuthorizationStateStores,
          value: {
            async put(reference, value) {
              values.set(reference, value);
            },
            async take(reference) {
              const value = values.get(reference);
              values.delete(reference);
              return value;
            },
          },
          options: { id: "memory" },
        },
        {
          point: BrowserHandoffs,
          value: {
            async open(url) {
              browserUrls.push(url.reveal());
            },
          },
          options: { id: "browser" },
        },
        {
          point: Signers,
          value: {
            async sign(_claims, options) {
              purposes.push(options.purpose);
              signature += 1;
              const value = `client-assertion-${signature}`;
              return {
                reveal: () => value,
                toString: () => "[REDACTED]",
                toJSON: () => "[REDACTED]",
              };
            },
          },
          options: { id: "signer" },
        },
        {
          point: DpopProofProviders,
          value: {
            async create(proofRequest) {
              proofRequests.push(proofRequest);
              const value = `dpop-${proofRequests.length}`;
              return {
                reveal: () => value,
                toString: () => "[REDACTED]",
                toJSON: () => "[REDACTED]",
              };
            },
          },
          options: { id: "dpop" },
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
      ],
    },
    tokens,
    browserUrls,
    proofRequests,
    purposes,
  };
}

const orchestrationOptions = {
  authorizationEndpoint: "https://auth.example.com/oauth/authorize",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  issuer: "https://auth.example.com",
  clientId: "https://agent.example/agent.json",
  redirectUri: "https://agent.example/oauth/callback",
  scopes: ["poppy:read", "poppy:write"],
  tenantId: "application-one",
  pairwiseUserId: "usr_AAECAwQFBgcICQoLDA0ODw",
  sessionId: "ses_existing",
};

function browserCallback(browserUrl, overrides = {}) {
  const authorization = new URL(browserUrl);
  const callback = new URL(orchestrationOptions.redirectUri);
  const parameters = {
    code: "one-time-code",
    state: authorization.searchParams.get("state"),
    iss: orchestrationOptions.issuer,
    ...overrides,
  };
  for (const [key, value] of Object.entries(parameters)) callback.searchParams.set(key, value);
  return callback.toString();
}

test("orchestrates one-use Direct Sign-In with nonce and partial scopes", async () => {
  const orchestration = orchestrationPlugin();
  const forms = [];
  const signals = [];
  let calls = 0;
  const fetch = async (_input, init) => {
    calls += 1;
    forms.push(new URLSearchParams(init.body));
    signals.push(init.signal);
    assert.equal(init.headers.DPoP, `dpop-${calls}`);
    assert.equal(init.redirect, "error");
    if (calls === 1) {
      return new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
        status: 400,
        headers: {
          "content-type": "application/json",
          "DPoP-Nonce": "company-nonce",
        },
      });
    }
    return new Response(
      JSON.stringify({
        access_token: "signed-in-session-token",
        token_type: "DPoP",
        expires_in: 300,
        scope: "poppy:read",
        session_id: "ses_existing",
        signed_in: true,
        refresh_token: "account-token",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  const reactor = buildPapReactor({ fetch }, [orchestration.plugin]);
  const client = new DirectSignInClient({ reactor, fetch });
  const controller = new AbortController();
  const started = await client.begin(orchestrationOptions);
  const callbackUrl = browserCallback(orchestration.browserUrls[0]);
  const result = await client.complete({ callbackUrl, signal: controller.signal });
  await assert.rejects(
    client.complete({ callbackUrl }),
    (error) =>
      error instanceof AuthorizationError && error.code === "invalid_or_expired_state",
  );
  reactor.stop();

  assert.ok(started.expiresAt > new Date());
  assert.deepEqual(started.requestedScopes, ["poppy:read", "poppy:write"]);
  assert.deepEqual(result.grantedScopes, ["poppy:read"]);
  assert.deepEqual(result.missingScopes, ["poppy:write"]);
  assert.equal(result.token.accessToken.reveal(), "signed-in-session-token");
  // The Account Token never stays in the result (§4.8): only its opaque reference.
  assert.equal(result.token.accountToken, undefined);
  assert.match(result.accountTokenReference, /^account_/);
  assert.equal(orchestration.tokens.get(result.accountTokenReference).reveal(), "account-token");
  assert.ok(!JSON.stringify(result).includes("account-token"));
  assert.deepEqual(
    orchestration.proofRequests.map((proof) => proof.nonce),
    [undefined, "company-nonce"],
  );
  assert.deepEqual(orchestration.purposes, ["client_assertion", "client_assertion"]);
  assert.equal(forms[0].get("session_id"), "ses_existing");
  assert.equal(forms[0].get("code_verifier"), forms[1].get("code_verifier"));
  assert.notEqual(forms[0].get("client_assertion"), forms[1].get("client_assertion"));
  assert.deepEqual(signals, [controller.signal, controller.signal]);
});

test("Direct Sign-In denial consumes state without exposing remote text", async () => {
  const orchestration = orchestrationPlugin();
  const fetch = async () => {
    throw new Error("token endpoint must not be called for a denial");
  };
  const reactor = buildPapReactor({ fetch }, [orchestration.plugin]);
  const client = new DirectSignInClient({ reactor, fetch });
  await client.begin(orchestrationOptions);
  const callbackUrl = browserCallback(orchestration.browserUrls[0], {
    error: "access_denied",
    error_description: "private company detail",
    code: "",
  });

  await assert.rejects(
    client.complete({ callbackUrl }),
    (error) =>
      error instanceof AuthorizationError &&
      error.code === "authorization_denied" &&
      !String(error).includes("private company detail"),
  );
  await assert.rejects(
    client.complete({ callbackUrl }),
    (error) =>
      error instanceof AuthorizationError && error.code === "invalid_or_expired_state",
  );
  reactor.stop();
});
