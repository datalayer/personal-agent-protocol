/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationStateStores,
  AuthorizationError,
  BrowserHandoffs,
  DirectSignInClient,
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
    scopes: ["orders:read", "orders:write"],
    randomBytes: fixedRandom,
  });
}

test("builds Direct Sign-In state and S256 PKCE", async () => {
  const signIn = await request();
  const url = new URL(signIn.authorizationUrl.reveal());

  assert.equal(url.searchParams.get("response_type"), "code");
  assert.equal(url.searchParams.get("scope"), "orders:read orders:write");
  assert.equal(url.searchParams.get("code_challenge_method"), "S256");
  // Plain OAuth: the sign-in names no Session (§4.2, §5.4).
  assert.equal(url.searchParams.has("dpop_jkt"), false);
  assert.equal(url.searchParams.has("session_key"), false);
  assert.equal(signIn.codeVerifier.reveal().length, 43);
  assert.equal(JSON.stringify(signIn).includes(signIn.state.reveal()), false);
});

test("validates the callback and keeps the code secret", async () => {
  const signIn = await request();
  const callback = new URL(signIn.redirectUri);
  callback.searchParams.set("code", "one-time-code");
  callback.searchParams.set("state", signIn.state.reveal());
  callback.searchParams.set("iss", signIn.issuer);
  const result = validateDirectSignInCallback(signIn, callback.toString());
  assert.equal(result.code.reveal(), "one-time-code");
  assert.equal(JSON.stringify(result).includes("one-time-code"), false);
});

test("a loopback redirect matches with any port", async () => {
  const signIn = await buildDirectSignInRequest({
    authorizationEndpoint: "https://auth.example.com/oauth/authorize",
    issuer: "https://auth.example.com",
    clientId: "https://agent.example/agent.json",
    redirectUri: "http://127.0.0.1/callback",
    scopes: ["orders:read"],
    randomBytes: fixedRandom,
  });
  const values = new URLSearchParams({ code: "c", state: signIn.state.reveal(), iss: signIn.issuer });
  // An app on the user's computer listens on a port it picks (RFC 8252 §7.3, §4.5).
  const callback = validateDirectSignInCallback(signIn, `http://127.0.0.1:53111/callback?${values}`);
  assert.equal(callback.code.reveal(), "c");
  assert.throws(
    () => validateDirectSignInCallback(signIn, `http://127.0.0.1:53111/other?${values}`),
    (error) => error instanceof AuthorizationError,
  );
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
      scopes: ["orders:read"],
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
  const purposes = [];
  const claims = [];
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
            async sign(signed, options) {
              purposes.push(options.purpose);
              claims.push(signed);
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
    purposes,
    claims,
  };
}

const orchestrationOptions = {
  authorizationEndpoint: "https://auth.example.com/oauth/authorize",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  issuer: "https://auth.example.com",
  clientId: "https://agent.example/agent.json",
  redirectUri: "https://agent.example/oauth/callback",
  scopes: ["orders:read", "orders:write"],
  tenantId: "application-one",
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

test("orchestrates one-use Direct Sign-In with partial scopes", async () => {
  const orchestration = orchestrationPlugin();
  const forms = [];
  const signals = [];
  const fetch = async (_input, init) => {
    forms.push(new URLSearchParams(init.body));
    signals.push(init.signal);
    const headers = Object.keys(init.headers).map((name) => name.toLowerCase());
    assert.ok(!headers.includes("dpop") && !headers.includes("poppy-session"));
    // A redirect is answered, never followed: nothing goes to a new URL (§3).
    assert.equal(init.redirect, "manual");
    return new Response(
      JSON.stringify({
        access_token: "signed-in-access-token",
        token_type: "Bearer",
        expires_in: 300,
        scope: "orders:read",
        refresh_token: "private-refresh-token",
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
  assert.deepEqual(started.requestedScopes, ["orders:read", "orders:write"]);
  assert.deepEqual(result.grantedScopes, ["orders:read"]);
  assert.deepEqual(result.missingScopes, ["orders:write"]);
  assert.equal(result.token.accessToken.reveal(), "signed-in-access-token");
  assert.equal(result.token.tokenType, "Bearer");
  // The refresh token never stays in the result (§4.4): only its opaque reference.
  assert.match(result.refreshTokenReference, /^refresh_/);
  assert.equal(orchestration.tokens.get(result.refreshTokenReference).reveal(), "private-refresh-token");
  assert.ok(!JSON.stringify(result).includes("private-refresh-token"));
  assert.deepEqual(orchestration.purposes, ["client_assertion"]);
  // The client assertion names the issuer, never the token endpoint (§4.1).
  assert.deepEqual(orchestration.claims.map((claims) => claims.aud), ["https://auth.example.com"]);
  assert.equal(forms.length, 1);
  assert.equal(forms[0].get("grant_type"), "authorization_code");
  assert.equal(forms[0].get("code"), "one-time-code");
  assert.ok(forms[0].get("code_verifier"));
  assert.equal(forms[0].get("client_assertion"), "client-assertion-1");
  // No Session is named (§5.4).
  assert.ok(!forms[0].has("session_id") && !forms[0].has("session_key"));
  assert.deepEqual(signals, [controller.signal]);
});

test("a DPoP token type at the end of Direct Sign-In is refused", async () => {
  const orchestration = orchestrationPlugin();
  const fetch = async () =>
    new Response(JSON.stringify({ access_token: "t", token_type: "DPoP", scope: "orders:read", refresh_token: "r" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  const reactor = buildPapReactor({ fetch }, [orchestration.plugin]);
  const client = new DirectSignInClient({ reactor, fetch });
  await client.begin(orchestrationOptions);
  await assert.rejects(
    client.complete({ callbackUrl: browserCallback(orchestration.browserUrls[0]) }),
    (error) => error instanceof AuthorizationError && error.code === "unsupported_token_type",
  );
  reactor.stop();
  assert.equal(orchestration.tokens.size, 0);
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

test("a Direct Sign-In token endpoint answering with a redirect gets nothing", async () => {
  const orchestration = orchestrationPlugin();
  const sent = [];
  const fetch = async (input) => {
    sent.push(String(input));
    return new Response(null, { status: 307, headers: { Location: "https://elsewhere.example/token" } });
  };
  const reactor = buildPapReactor({ fetch }, [orchestration.plugin]);
  const client = new DirectSignInClient({ reactor, fetch });
  await client.begin(orchestrationOptions);
  await assert.rejects(
    client.complete({ callbackUrl: browserCallback(orchestration.browserUrls[0]) }),
    (error) => error instanceof AuthorizationError && error.code === "redirect_refused" && error.statusCode === 307,
  );
  reactor.stop();
  assert.deepEqual(sent, ["https://auth.example.com/oauth/token"]);
});
