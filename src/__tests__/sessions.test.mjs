/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Sessions, client assertions, and plain OAuth token responses (§4, §5).
import assert from "node:assert/strict";
import test from "node:test";

import {
  ASSERTION_MAX_LIFETIME_SECONDS,
  JWT_CLIENT_ASSERTION,
  PapSession,
  ProtocolValidationError,
  REFRESH_TOKEN_GRANT,
  SecretValue,
  SessionClient,
  SessionError,
  SessionFetchClient,
  SessionSigners,
  Signers,
  accessTokenFromResponse,
  buildClientAssertionClaims,
  buildPapReactor,
  generatePairwiseUserId,
  newSessionId,
  parseTokenResponse,
} from "../../lib/index.js";

const CLIENT_ID = "https://agent.example/agent.json";
const ISSUER = "https://auth.example.com";
const TOKEN_ENDPOINT = "https://auth.example.com/oauth/token";
const PAIRWISE = "usr_AAECAwQFBgcICQoLDA0ODw";
const WHO = { clientId: CLIENT_ID, pairwiseUserId: PAIRWISE, issuer: ISSUER, tenantId: "tenant-one" };

const fixedRandom = (length) => Uint8Array.from({ length }, (_, index) => index);
const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const tokenResponse = { access_token: "opaque-access-token", token_type: "Bearer", expires_in: 3600 };

function securityPlugin() {
  const purposes = [];
  const claims = [];
  const sessionRequests = [];
  const signer = {
    async sign(signed, options) {
      purposes.push(options.purpose);
      claims.push(signed);
      return new SecretValue(`signed-${options.purpose}-${purposes.length}`);
    },
  };
  const sessionSigner = {
    async sign(request) {
      sessionRequests.push(request);
      return new SecretValue(`session-jwt-${sessionRequests.length}`);
    },
  };
  return {
    plugin: {
      name: "@tests/pap-session-security",
      contributes: [
        { point: Signers, value: signer, options: { id: "test-signer" } },
        { point: SessionSigners, value: sessionSigner, options: { id: "test-session-signer" } },
      ],
    },
    purposes,
    claims,
    sessionRequests,
  };
}

/** One grant at the token endpoint, as a sign-in or a refresh sends it. */
const refresh = (client) =>
  client.tokenRequest({
    clientId: CLIENT_ID,
    issuer: ISSUER,
    tokenEndpoint: TOKEN_ENDPOINT,
    form: () => ({ grant_type: REFRESH_TOKEN_GRANT, refresh_token: "refresh-secret" }),
    error: SessionError,
  });

function setup(fetch) {
  const security = securityPlugin();
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  return { security, reactor, client: new SessionClient({ reactor, fetch }) };
}

test("generates a random pairwise identifier without personal data", () => {
  assert.equal(generatePairwiseUserId(fixedRandom), "usr_AAECAwQFBgcICQoLDA0ODw");
});

test("a client assertion names the issuer and lives at most five minutes", () => {
  const now = new Date("2026-10-10T00:00:00Z");
  const claims = buildClientAssertionClaims({
    clientId: CLIENT_ID,
    issuer: "https://auth.provider.example/shop-a",
    now,
    randomBytes: fixedRandom,
  });
  assert.deepEqual([claims.iss, claims.sub], [CLIENT_ID, CLIENT_ID]);
  assert.equal(claims.aud, "https://auth.provider.example/shop-a");
  assert.equal(claims.exp - claims.iat, 60);
  assert.equal(claims.jti, "AAECAwQFBgcICQoLDA0ODw");
  const longest = buildClientAssertionClaims({
    clientId: CLIENT_ID,
    issuer: ISSUER,
    now,
    lifetimeSeconds: ASSERTION_MAX_LIFETIME_SECONDS,
  });
  assert.equal(longest.exp - longest.iat, 300);
  assert.throws(
    () => buildClientAssertionClaims({ clientId: CLIENT_ID, issuer: ISSUER, now, lifetimeSeconds: 301 }),
    (error) => error.code === "invalid_assertion_lifetime" && /300/.test(error.message),
  );
});

test("parses an access token as an opaque secret", () => {
  const token = accessTokenFromResponse(
    parseTokenResponse({
      access_token: "opaque-access-token",
      token_type: "bearer",
      expires_in: 3600,
      scope: "orders:read orders:write",
    }),
  );
  // `token_type` is compared ignoring case (RFC 6749 §5.1).
  assert.equal(token.tokenType, "Bearer");
  assert.equal(token.accessToken.reveal(), "opaque-access-token");
  assert.deepEqual(token.scopes, ["orders:read", "orders:write"]);
  assert.equal(token.resource, undefined);
  assert.ok(!String(token.accessToken).includes("opaque-access-token"));
  assert.ok(!JSON.stringify(token).includes("opaque-access-token"));
});

test("a signed-in response without scope granted exactly what was asked", () => {
  const response = parseTokenResponse({ access_token: "t", token_type: "Bearer", expires_in: 60, refresh_token: "r" });
  assert.deepEqual(accessTokenFromResponse(response, { requestedScopes: ["orders:read"] }).scopes, ["orders:read"]);
  // A sign-in grants at least one scope (§4.7).
  assert.throws(() => accessTokenFromResponse(response), (error) => error.code === "invalid_token_response");
});

test("an access token remembers the service it was issued for", () => {
  const response = parseTokenResponse({ access_token: "t", token_type: "Bearer", scope: "orders:read" });
  const mcp = "https://mcp.example.com/mcp";
  assert.equal(accessTokenFromResponse(response, { resource: mcp }).resource, mcp);
});

for (const tokenType of ["DPoP", "dpop", "mac"]) {
  test(`a token response is Bearer, never ${tokenType}`, () => {
    assert.throws(
      () => parseTokenResponse({ access_token: "t", token_type: tokenType }),
      (error) => error instanceof ProtocolValidationError,
    );
  });
}

test("a Session starts with no request and a new random sid", async () => {
  const sent = [];
  const fetch = async (input) => {
    sent.push(String(input));
    return new Response(null, { status: 500 });
  };
  const { security, reactor, client } = setup(fetch);
  const first = await client.start(WHO);
  const second = await client.start(WHO);
  reactor.stop();

  // Local: nothing is asked of the company, and nothing is signed yet (§5.2).
  assert.deepEqual(sent, []);
  assert.deepEqual(security.purposes, []);
  assert.deepEqual(security.sessionRequests, []);
  assert.notEqual(first.sid, second.sid);
  assert.ok(first.sid.length >= 22);
  assert.deepEqual([first.sub, first.issuer, first.clientId], [PAIRWISE, ISSUER, CLIENT_ID]);
  assert.equal(first.tenantId, "tenant-one");
  assert.equal(first.agentId, undefined);
  assert.equal(first.handle, `ses_${first.sid}`);
  assert.deepEqual(PapSession.fromJson(first.toJson()).toJson(), first.toJson());
});

test("a Session ID is at least 128 random bits", () => {
  assert.equal(newSessionId(fixedRandom), "AAECAwQFBgcICQoLDA0ODw");
  assert.throws(() => newSessionId(() => new Uint8Array(5)), /128 random bits/);
  assert.throws(
    () => new PapSession({ sid: "short", sub: PAIRWISE, issuer: ISSUER, clientId: CLIENT_ID, tenantId: "tenant-one" }),
    (error) => error.code === "invalid_session_id",
  );
});

test("a new Session replaces an ended one for the same User", async () => {
  const { reactor, client } = setup(async () => new Response(null, { status: 500 }));
  const session = await client.start({ ...WHO, agentId: "agt_shopping" });
  reactor.stop();
  const ended = session.sid;
  session.restart(fixedRandom);
  // The Session has ended: its `sid` is never used again (§5.5).
  assert.equal(session.sid, "AAECAwQFBgcICQoLDA0ODw");
  assert.notEqual(session.sid, ended);
  assert.deepEqual([session.sub, session.agentId], [PAIRWISE, "agt_shopping"]);
});

test("the token endpoint gets a client assertion and no Session", async () => {
  const sent = [];
  const fetch = async (_input, init) => {
    sent.push(init);
    return json(tokenResponse);
  };
  const { security, reactor, client } = setup(fetch);
  const response = await refresh(client);
  await refresh(client);
  reactor.stop();

  assert.equal(response.accessToken.reveal(), "opaque-access-token");
  const forms = sent.map((init) => new URLSearchParams(init.body));
  assert.equal(forms[0].get("grant_type"), "refresh_token");
  assert.equal(forms[0].get("client_id"), CLIENT_ID);
  assert.equal(forms[0].get("client_assertion_type"), JWT_CLIENT_ASSERTION);
  // A fresh assertion for each request; no Session header at an OAuth endpoint (§5.2).
  assert.deepEqual(forms.map((form) => form.get("client_assertion")), [
    "signed-client_assertion-1",
    "signed-client_assertion-2",
  ]);
  assert.deepEqual(security.sessionRequests, []);
  for (const { headers } of sent) {
    const names = Object.keys(headers).map((name) => name.toLowerCase());
    assert.ok(!names.includes("poppy-session"));
    assert.ok(!names.includes("dpop"));
  }
});

test("a DPoP token type is refused at the token endpoint", async () => {
  const answer = { access_token: "key-bound-secret", token_type: "DPoP", expires_in: 60 };
  const { reactor, client } = setup(async () => json(answer));
  await assert.rejects(refresh(client), (error) => {
    assert.ok(error instanceof SessionError);
    assert.deepEqual([error.code, error.statusCode], ["unsupported_token_type", 200]);
    assert.ok(!String(error).includes("key-bound-secret"));
    return true;
  });
  reactor.stop();
});

test("a malformed token response is not a token type refusal", async () => {
  const { reactor, client } = setup(async () => json({ access_token: "t", token_type: "mac" }));
  await assert.rejects(refresh(client), (error) => error instanceof SessionError && error.code === "invalid_token_response");
  reactor.stop();
});

test("does not expose a remote OAuth error description", async () => {
  const { reactor, client } = setup(async () =>
    json({ error: "invalid_client", error_description: "secret-token" }, 401),
  );
  await assert.rejects(
    refresh(client),
    (error) =>
      error instanceof SessionError &&
      error.code === "invalid_client" &&
      error.statusCode === 401 &&
      !String(error).includes("secret-token"),
  );
  reactor.stop();
});

test("rejects duplicate members in a token response", async () => {
  const { reactor, client } = setup(
    async () =>
      new Response('{"access_token":"one","access_token":"two","token_type":"Bearer","expires_in":3600}', {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  );
  await assert.rejects(refresh(client), (error) => error instanceof SessionError && error.code === "invalid_json");
  reactor.stop();
});

test("a client assertion names the issuer and lives one minute", async () => {
  const { security, reactor, client } = setup(async () => json(tokenResponse));
  await refresh(client);
  reactor.stop();
  // aud is the company's issuer, one string, never its token endpoint (§4.1).
  assert.deepEqual(security.claims.map((claims) => claims.aud), [ISSUER]);
  assert.ok(security.claims.every((claims) => claims.exp - claims.iat === 60));
});

test("a redirect at the token endpoint gets nothing", async () => {
  const sent = [];
  const fetch = async (input, init) => {
    sent.push(String(input));
    assert.equal(init.redirect, "manual");
    return new Response(null, { status: 307, headers: { Location: "https://elsewhere.example/token" } });
  };
  const { reactor, client } = setup(fetch);
  // Nothing is sent to the new URL: no assertion, no refresh token (§3).
  await assert.rejects(
    refresh(client),
    (error) => error instanceof SessionError && error.code === "redirect_refused" && error.statusCode === 307,
  );
  reactor.stop();
  assert.deepEqual(sent, [TOKEN_ENDPOINT]);
});

test("extension_required and rate_limited at the token endpoint are read", async () => {
  const answers = [
    () => json({ error: "extension_required", extension: "operations" }, 403),
    // A 429 has `Retry-After` and no body (§5.6).
    () => new Response(null, { status: 429, headers: { "Retry-After": "7" } }),
  ];
  const { reactor, client } = setup(async () => answers.shift()());
  await assert.rejects(refresh(client), (error) => {
    assert.deepEqual([error.code, error.statusCode, error.details], ["extension_required", 403, { extension: "operations" }]);
    return true;
  });
  await assert.rejects(refresh(client), (error) => {
    assert.deepEqual([error.code, error.details], ["rate_limited", { retry_after: "7" }]);
    return true;
  });
  reactor.stop();
});

test("an Agent ID rides in the Session", async () => {
  const seen = [];
  const fetch = async (_input, init) => {
    seen.push(init.headers);
    return json({});
  };
  const { security, reactor, client } = setup(fetch);
  const transport = new SessionFetchClient({ reactor, fetch });
  for (const agentId of ["agt_shopping", undefined]) {
    const session = await client.start({ ...WHO, ...(agentId === undefined ? {} : { agentId }) });
    await transport.request("GET", "https://shop.example/api/orders", { session });
  }
  reactor.stop();
  // A User with one agent leaves it out (§5.2).
  assert.deepEqual(security.sessionRequests.map((request) => request.agentId), ["agt_shopping", undefined]);
  assert.deepEqual(security.sessionRequests.map((request) => request.sub), [PAIRWISE, PAIRWISE]);
  assert.deepEqual(seen.map((headers) => headers["Poppy-Session"]), ["session-jwt-1", "session-jwt-2"]);
  assert.throws(
    () => new PapSession({ sid: "S".repeat(22), sub: PAIRWISE, issuer: ISSUER, clientId: CLIENT_ID, tenantId: "t", agentId: "not valid!" }),
    (error) => error.code === "invalid_agent_id",
  );
});
