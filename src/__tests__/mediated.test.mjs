/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Mediated Sign-In extension v1: credentials to one token endpoint, once, never to a model.
import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationError,
  AuthorizationStateStores,
  JWT_CLIENT_ASSERTION,
  MEDIATED_EXTENSION,
  MEDIATED_GRANT,
  MEDIATED_VERSION,
  MediatedSignInClient,
  ProtectedInputs,
  SecretValue,
  Signers,
  TokenStores,
  buildPapReactor,
  extensionRequired,
  mediatedSignIn,
  negotiateExtensions,
  parseDiscoveryDocument,
  parseOAuthServerMetadata,
} from "../../lib/index.js";

const TOKEN_ENDPOINT = "https://auth.shop.example/oauth/token";
const CLIENT_ID = "https://agent.example/agent.json";
const AGENT = { protocols: [{ type: "poppy", endpoint: "https://shop.example/poppy/conversations" }] };
const EXTENSION = {
  version: "1",
  fields: [
    { name: "email", label: "Email", secret: false },
    { name: "password", label: "Password", secret: true },
  ],
  scopes: ["orders:read", "orders:return"],
};
const CREDENTIALS = { email: "ada@example.com", password: "correct horse" };

function company(extension = EXTENSION, grants = [MEDIATED_GRANT], more = {}) {
  return {
    discoveryUrl: "https://shop.example/.well-known/poppy.json",
    document: parseDiscoveryDocument({
      protocol_version: "0.3",
      organization: { name: "Shop", domain: "shop.example" },
      agent: AGENT,
      ...(extension === null ? {} : { extensions: { [MEDIATED_EXTENSION]: extension } }),
      ...more,
    }),
    oauthMetadata: parseOAuthServerMetadata({
      issuer: "https://auth.shop.example",
      token_endpoint: TOKEN_ENDPOINT,
      revocation_endpoint: "https://auth.shop.example/oauth/revoke",
      grant_types_supported: ["refresh_token", ...grants],
      protected_resources: ["https://shop.example"],
    }),
  };
}

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

function arrange(shop, ...answers) {
  const asked = [];
  const state = memory();
  const tokens = memory();
  const seen = [];
  const fetch = async (url, init) => {
    seen.push({ url: String(url), init, form: Object.fromEntries(new URLSearchParams(init.body)) });
    return shop(seen.length);
  };
  const reactor = buildPapReactor({ fetch }, [
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
        {
          point: Signers,
          value: {
            async sign(_claims, { purpose }) {
              assert.equal(purpose, "client_assertion");
              return new SecretValue("client-assertion");
            },
          },
          options: { id: "agent-key" },
        },
      ],
    },
  ]);
  return { client: new MediatedSignInClient({ reactor, fetch }), asked, seen, state, tokens };
}

const json = (status, body, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const complete = (extra = {}) => ({
  access_token: "signed-in-token",
  token_type: "Bearer",
  expires_in: 300,
  scope: "orders:read",
  refresh_token: "private-refresh-token",
  ...extra,
});
const codeRequired = (extra = {}) =>
  json(400, {
    error: "code_required",
    sign_in_id: "sgn_3Hq8",
    sent_to: "Text to the phone number ending in 71",
    expires_in: 600,
    ...extra,
  });
const signIn = (client, offered = company()) =>
  client.signIn({ company: offered, clientId: CLIENT_ID, scopes: ["orders:read", "orders:return"] });

test("the declared fields go to the token endpoint as the grant", async () => {
  const { client, asked, seen, tokens } = arrange(() => json(200, complete()), CREDENTIALS);
  const result = await signIn(client);
  assert.equal(seen[0].url, TOKEN_ENDPOINT);
  // No Session header at an OAuth endpoint (spec 5.2), and no JSON body.
  const headers = Object.keys(seen[0].init.headers).map((name) => name.toLowerCase());
  assert.ok(!headers.includes("poppy-session") && !headers.includes("authorization"));
  assert.deepEqual(seen[0].form, {
    grant_type: MEDIATED_GRANT,
    scope: "orders:read orders:return",
    email: "ada@example.com",
    password: "correct horse",
    client_id: CLIENT_ID,
    client_assertion_type: JWT_CLIENT_ASSERTION,
    client_assertion: "client-assertion",
  });
  assert.equal(asked[0].purpose, "credentials");
  assert.equal(asked[0].issuer, "https://auth.shop.example");
  assert.deepEqual(asked[0].fields.map((field) => field.name), ["email", "password"]);
  assert.equal(result.status, "complete");
  assert.deepEqual(result.missingScopes, ["orders:return"]);
  assert.ok(result.token);
  assert.equal(tokens.values.get(result.refreshTokenReference).reveal(), "private-refresh-token");
  const text = JSON.stringify(result);
  assert.ok(!text.includes("private-refresh-token") && !text.includes("correct horse"));
});

test("a one-time code continues without the credentials or scope", async () => {
  const { client, asked, seen } = arrange(
    (call) => (call === 1 ? codeRequired() : json(200, complete())),
    CREDENTIALS,
    { code: "246810" },
  );
  const started = await signIn(client);
  assert.equal(started.status, "code_required");
  assert.equal(started.sentTo, "Text to the phone number ending in 71");
  assert.ok(started.expiresAt instanceof Date);
  assert.ok(started.reference);

  const finished = await client.submitCode(started.reference);
  assert.equal(seen[1].url, TOKEN_ENDPOINT);
  assert.deepEqual(seen[1].form, {
    grant_type: MEDIATED_GRANT,
    sign_in_id: "sgn_3Hq8",
    one_time_code: "246810",
    client_id: CLIENT_ID,
    client_assertion_type: JWT_CLIENT_ASSERTION,
    client_assertion: "client-assertion",
  });
  assert.equal(asked[1].purpose, "one_time_code");
  assert.equal(asked[1].sentTo, "Text to the phone number ending in 71");
  assert.equal(asked[1].companyDomain, "shop.example");
  // The sign-in keeps the scopes of the first request.
  assert.equal(finished.status, "complete");
  assert.deepEqual(finished.missingScopes, ["orders:return"]);
});

test("a wrong code asks again and invalid_grant ends it", async () => {
  const answers = [codeRequired(), codeRequired(), json(400, { error: "invalid_grant" })];
  const { client, state } = arrange(() => answers.shift(), CREDENTIALS, { code: "1" }, { code: "2" });
  const started = await signIn(client);
  const again = await client.submitCode(started.reference);
  assert.equal(again.status, "code_required");
  assert.equal(again.reference, started.reference);
  await assert.rejects(
    client.submitCode(started.reference),
    (error) => error instanceof AuthorizationError && error.code === "invalid_grant",
  );
  assert.equal(state.values.size, 0);
});

test("a continuation under another sign_in_id is refused", async () => {
  const answers = [codeRequired(), codeRequired({ sign_in_id: "sgn_other" })];
  const { client } = arrange(() => answers.shift(), CREDENTIALS, { code: "1" });
  const started = await signIn(client);
  await assert.rejects(client.submitCode(started.reference), (error) => error.code === "invalid_mediated_response");
});

test("a used reference is refused", async () => {
  const answers = [codeRequired(), json(200, complete())];
  const { client } = arrange(() => answers.shift(), CREDENTIALS, { code: "1" });
  const started = await signIn(client);
  await client.submitCode(started.reference);
  await assert.rejects(client.submitCode(started.reference), (error) => error.code === "invalid_or_expired_sign_in");
});

for (const error of ["invalid_grant", "expired_token", "access_denied", "invalid_scope"]) {
  test(`${error} ends the sign-in`, async () => {
    const { client } = arrange(() => json(400, { error }), CREDENTIALS);
    await assert.rejects(signIn(client), (raised) => {
      assert.ok(raised instanceof AuthorizationError);
      assert.deepEqual([raised.code, raised.statusCode], [error, 400]);
      assert.ok(!JSON.stringify({ ...raised }).includes("correct horse"));
      return true;
    });
  });
}

test("a code_required without its sign_in_id is refused", async () => {
  const { client, state } = arrange(() => json(400, { error: "code_required" }), CREDENTIALS);
  await assert.rejects(signIn(client), (error) => error.code === "invalid_mediated_response");
  assert.equal(state.values.size, 0);
});

test("a redirect never carries the credentials elsewhere", async () => {
  const { client, seen } = arrange(() => new Response(null, { status: 307, headers: { Location: "/elsewhere" } }), CREDENTIALS);
  await assert.rejects(signIn(client), (error) => error.code === "redirect_refused");
  assert.deepEqual(seen.map(({ url }) => url), [TOKEN_ENDPOINT]);
});

test("a company without the grant offers no Mediated Sign-In", async () => {
  assert.deepEqual(mediatedSignIn(company()).scopes, EXTENSION.scopes);
  assert.equal(mediatedSignIn(company(EXTENSION, [])), undefined);
  assert.equal(mediatedSignIn(company(null)), undefined);
  // Another major version doesn't count as support.
  assert.equal(mediatedSignIn(company({ version: "2", fields: [] })), undefined);
  const { client, asked } = arrange(() => new Response(null, { status: 500 }), CREDENTIALS);
  await assert.rejects(signIn(client, company(EXTENSION, [])), (error) => error.code === "no_mediated");
  assert.deepEqual(asked, []);
});

test("the old auth.mediated offers nothing", () => {
  const offered = company(null, [MEDIATED_GRANT], {
    auth: {
      mediated: {
        endpoint: "https://auth.shop.example/poppy/sign-in",
        fields: EXTENSION.fields,
        scopes: ["orders:read"],
      },
    },
  });
  assert.equal(mediatedSignIn(offered), undefined);
});

for (const name of [
  "grant_type",
  "scope",
  "resource",
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
  "sign_in_id",
  "one_time_code",
]) {
  test(`a field named ${name} is refused`, async () => {
    const extension = { version: "1", fields: [{ name, label: "Anything", secret: false }], scopes: ["orders:read"] };
    assert.equal(mediatedSignIn(company(extension)), undefined);
    const { client, asked } = arrange(() => new Response(null, { status: 500 }), { [name]: "x" });
    await assert.rejects(signIn(client, company(extension)), (error) => error.code === "invalid_mediated_extension");
    assert.deepEqual(asked, []);
  });
}

test("answers must be exactly the declared fields", async () => {
  for (const answer of [{ email: "a@example.com" }, { ...CREDENTIALS, extra: "x" }]) {
    const { client, seen } = arrange(() => new Response(null, { status: 500 }), answer);
    await assert.rejects(signIn(client), (error) => error.code === "invalid_protected_input");
    assert.deepEqual(seen, []);
  }
});

test("rate_limited is reported with Retry-After and no credential", async () => {
  // A 429 has `Retry-After` and no body (§5.6).
  const { client } = arrange(() => new Response(null, { status: 429, headers: { "Retry-After": "30" } }), CREDENTIALS);
  await assert.rejects(signIn(client), (error) => {
    assert.equal(error.code, "rate_limited");
    assert.deepEqual(error.details, { retry_after: "30" });
    assert.ok(!JSON.stringify({ ...error }).includes("correct horse"));
    return true;
  });
});

test("a rate-limited code keeps the sign-in", async () => {
  const answers = [codeRequired(), new Response(null, { status: 429, headers: { "Retry-After": "30" } })];
  const { client, state } = arrange(() => answers.shift(), CREDENTIALS, { code: "1" });
  const started = await signIn(client);
  await assert.rejects(client.submitCode(started.reference), (error) => error.code === "rate_limited");
  assert.equal(state.values.has(started.reference), true);
});

test("a DPoP answer to a Mediated Sign-In is refused", async () => {
  const { client } = arrange(() => json(200, complete({ token_type: "DPoP" })), CREDENTIALS);
  await assert.rejects(signIn(client), (error) => error.code === "unsupported_token_type");
});

test("no refresh token, no sign-in", async () => {
  const { refresh_token: _refresh, ...answer } = complete();
  const { client } = arrange(() => json(200, answer), CREDENTIALS);
  await assert.rejects(signIn(client), (error) => error.code === "missing_refresh_token");
});

test("an extension used by the request is negotiated without an agent entry", () => {
  assert.equal(MEDIATED_VERSION, "1");
  assert.deepEqual(negotiateExtensions({ [MEDIATED_EXTENSION]: { version: "1" } }, {}), { [MEDIATED_EXTENSION]: "1" });
  // Another major version is not this extension.
  assert.deepEqual(negotiateExtensions({ [MEDIATED_EXTENSION]: { version: "2" } }, {}), {});
});

test("a refusal of an extension the request uses is not extension_required", () => {
  // A Company can't refuse it: such a 403 isn't what the extension's error means (§3.3).
  const body = { error: "extension_required", extension: MEDIATED_EXTENSION };
  assert.equal(extensionRequired(403, body), undefined);
  assert.equal(extensionRequired(403, { ...body, extension: "operations" }), "operations");
});
