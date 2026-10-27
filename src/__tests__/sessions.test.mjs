/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  ASSERTION_MAX_LIFETIME_SECONDS,
  DpopProofProviders,
  JWT_BEARER_GRANT,
  SessionClient,
  SessionError,
  Signers,
  buildClientAssertionClaims,
  buildPapReactor,
  buildSessionAssertionClaims,
  parseTokenResponse,
  sessionTokenFromResponse,
} from "../../lib/index.js";

/** A Session Key's thumbprint: 43 base64url characters (RFC 7638, SHA-256). */
const KEY = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

const tokenResponse = {
  access_token: "opaque-session-token",
  token_type: "DPoP",
  expires_in: 3600,
};

function securityPlugin() {
  const purposes = [];
  const claims = [];
  const proofRequests = [];
  const made = [];
  const discarded = [];
  const signer = {
    async sign(signed, options) {
      purposes.push(options.purpose);
      claims.push(signed);
      return {
        reveal: () => `signed-${options.purpose}-${purposes.length}`,
        toString: () => "[REDACTED]",
        toJSON: () => "[REDACTED]",
      };
    },
  };
  const dpop = {
    async newSessionKey() {
      made.push(`${"k".repeat(42)}${made.length}`);
      return made.at(-1);
    },
    async discardSessionKey({ sessionKey }) {
      discarded.push(sessionKey);
    },
    async create(request) {
      proofRequests.push(request);
      return {
        reveal: () => `proof-${proofRequests.length}`,
        toString: () => "[REDACTED]",
        toJSON: () => "[REDACTED]",
      };
    },
  };
  return {
    plugin: {
      name: "@tests/pap-session-security",
      contributes: [
        { point: Signers, value: signer, options: { id: "test-signer" } },
        { point: DpopProofProviders, value: dpop, options: { id: "test-dpop" } },
      ],
    },
    purposes,
    claims,
    proofRequests,
    made,
    discarded,
  };
}

const requestOptions = {
  clientId: "https://agent.example/agent.json",
  pairwiseUserId: "usr_AAECAwQFBgcICQoLDA0ODw",
  issuer: "https://auth.example.com",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  tenantId: "tenant-one",
};

test("starts and renews a signed-out session over HTTP", async () => {
  const security = securityPlugin();
  const controller = new AbortController();
  const forms = [];
  const signals = [];
  const fetch = async (_input, init) => {
    assert.equal(init.method, "POST");
    assert.match(init.headers.DPoP, /^proof-/);
    forms.push(new URLSearchParams(init.body));
    signals.push(init.signal);
    return new Response(JSON.stringify(tokenResponse), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const client = new SessionClient({ reactor, fetch });

  const started = await client.start({ ...requestOptions, signal: controller.signal });
  const renewed = await client.renew({
    ...requestOptions,
    sessionKey: started.sessionKey,
    signal: controller.signal,
  });
  reactor.stop();

  // A new key starts the Session; the renewal is signed with the same key, which names the
  // Session: nothing else does (§4.3).
  assert.equal(started.sessionKey, security.made[0]);
  assert.equal(renewed.sessionKey, security.made[0]);
  assert.deepEqual(security.proofRequests.map((request) => request.sessionKey), [security.made[0], security.made[0]]);
  assert.ok(forms.every((form) => !form.has("session_id") && !form.has("session_key")));
  assert.equal(started.signedIn, false);
  assert.deepEqual(started.scopes, []);
  assert.equal(forms[0].get("grant_type"), JWT_BEARER_GRANT);
  assert.deepEqual(signals, [controller.signal, controller.signal]);
  assert.deepEqual(security.purposes, [
    "session_assertion",
    "client_assertion",
    "session_assertion",
    "client_assertion",
  ]);
  assert.ok(security.proofRequests.every((request) => request.tenantId === "tenant-one"));
});

test("retries one DPoP nonce challenge with fresh assertions and proof", async () => {
  const security = securityPlugin();
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    if (calls === 1) {
      return new Response(JSON.stringify({ error: "use_dpop_nonce" }), {
        status: 400,
        headers: {
          "content-type": "application/json",
          "DPoP-Nonce": "company-nonce",
        },
      });
    }
    return new Response(JSON.stringify(tokenResponse), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const token = await new SessionClient({ reactor, fetch }).start(requestOptions);
  reactor.stop();

  assert.equal(token.sessionKey, security.made[0]);
  assert.deepEqual(
    security.proofRequests.map((request) => request.nonce),
    [undefined, "company-nonce"],
  );
  assert.equal(security.purposes.length, 4);
});

test("does not expose a remote OAuth error description", async () => {
  const security = securityPlugin();
  const fetch = async () =>
    new Response(
      JSON.stringify({ error: "invalid_client", error_description: "secret-token" }),
      { status: 401, headers: { "content-type": "application/json" } },
    );
  const reactor = buildPapReactor({ fetch }, [security.plugin]);

  await assert.rejects(
    new SessionClient({ reactor, fetch }).start(requestOptions),
    (error) =>
      error instanceof SessionError &&
      error.code === "invalid_client" &&
      error.statusCode === 401 &&
      !String(error).includes("secret-token"),
  );
  reactor.stop();
});

test("rejects duplicate members in a token response", async () => {
  const security = securityPlugin();
  const fetch = async () =>
    new Response(
      '{"access_token":"one","access_token":"two","token_type":"DPoP",' +
        '"expires_in":3600}',
      { status: 200, headers: { "content-type": "application/json" } },
    );
  const reactor = buildPapReactor({ fetch }, [security.plugin]);

  await assert.rejects(
    new SessionClient({ reactor, fetch }).start(requestOptions),
    (error) => error instanceof SessionError && error.code === "invalid_json",
  );
  reactor.stop();
});

const fixedRandom = (length) => Uint8Array.from({ length }, (_, index) => index);
const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

test("a client assertion names the issuer and lives at most five minutes", () => {
  const now = new Date("2026-10-10T00:00:00Z");
  const claims = buildClientAssertionClaims({
    clientId: "https://agent.example/agent.json",
    issuer: "https://auth.provider.example/shop-a",
    now,
    randomBytes: fixedRandom,
  });
  assert.deepEqual([claims.iss, claims.sub], ["https://agent.example/agent.json", "https://agent.example/agent.json"]);
  assert.equal(claims.aud, "https://auth.provider.example/shop-a");
  assert.equal(claims.exp - claims.iat, 60);
  assert.equal(claims.jti, "jti_AAECAwQFBgcICQoLDA0ODw");
  const longest = buildClientAssertionClaims({
    clientId: "https://agent.example/agent.json",
    issuer: "https://auth.example.com",
    now,
    lifetimeSeconds: ASSERTION_MAX_LIFETIME_SECONDS,
  });
  assert.equal(longest.exp - longest.iat, 300);
  for (const build of [buildClientAssertionClaims, buildSessionAssertionClaims]) {
    assert.throws(
      () =>
        build({
          clientId: "https://agent.example/agent.json",
          pairwiseUserId: "usr_x",
          issuer: "https://auth.example.com",
          now,
          lifetimeSeconds: 301,
        }),
      (error) => error.code === "invalid_assertion_lifetime" && /300/.test(error.message),
    );
  }
  // The company's auth.issuer, one string, never its token endpoint (§4.2, §9.4).
  const session = buildSessionAssertionClaims({
    clientId: "https://agent.example/agent.json",
    pairwiseUserId: "usr_AAECAwQFBgcICQoLDA0ODw",
    issuer: "https://auth.example.com",
    now,
    randomBytes: fixedRandom,
  });
  assert.equal(session.aud, "https://auth.example.com");
});

test("both assertions name the issuer and live one minute", async () => {
  const security = securityPlugin();
  const fetch = async () => json(tokenResponse);
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  await new SessionClient({ reactor, fetch }).start(requestOptions);
  reactor.stop();
  // aud is the company's auth.issuer, one string, never its token endpoint (§4.1, §4.2).
  assert.deepEqual(security.claims.map((claims) => claims.aud), ["https://auth.example.com", "https://auth.example.com"]);
  assert.ok(security.claims.every((claims) => claims.exp - claims.iat === 60));
});

test("a redirect at the token endpoint gets nothing", async () => {
  const security = securityPlugin();
  const sent = [];
  const fetch = async (input, init) => {
    sent.push(String(input));
    assert.equal(init.redirect, "manual");
    return new Response(null, { status: 307, headers: { Location: "https://elsewhere.example/token" } });
  };
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  // Nothing is sent to the new URL: no assertion, no proof (§3).
  await assert.rejects(
    new SessionClient({ reactor, fetch }).start(requestOptions),
    (error) => error instanceof SessionError && error.code === "redirect_refused" && error.statusCode === 307,
  );
  reactor.stop();
  assert.deepEqual(sent, ["https://auth.example.com/oauth/token"]);
});

test("extension_required and rate_limited at the token endpoint are read", async () => {
  const security = securityPlugin();
  const answers = [
    () => json({ error: "extension_required", extension: "operations" }, 403),
    () => json({ error: "rate_limited" }, 429, { "Retry-After": "7" }),
  ];
  const fetch = async () => answers.shift()();
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const client = new SessionClient({ reactor, fetch });
  await assert.rejects(client.start(requestOptions), (error) => {
    assert.deepEqual([error.code, error.statusCode, error.details], ["extension_required", 403, { extension: "operations" }]);
    return true;
  });
  await assert.rejects(client.start(requestOptions), (error) => {
    assert.deepEqual([error.code, error.details], ["rate_limited", { retry_after: "7" }]);
    return true;
  });
  reactor.stop();
});

test("the shared Session Token fixture is a signed-out token", () => {
  const token = sessionTokenFromResponse(parseTokenResponse(tokenResponse), { sessionKey: KEY, signedIn: false });
  // Signed out: no `scope` in the response, and none granted (§4.2).
  assert.deepEqual(token.scopes, []);
  assert.equal(token.signedIn, false);
});

test("a signed-in response without scope granted exactly what was asked", () => {
  const response = parseTokenResponse({ access_token: "t", token_type: "DPoP", expires_in: 60, refresh_token: "r" });
  const token = sessionTokenFromResponse(response, { sessionKey: KEY, signedIn: true, requestedScopes: ["orders:read"] });
  assert.deepEqual(token.scopes, ["orders:read"]);
  // A sign-in grants at least one scope (§4.4).
  assert.throws(() => sessionTokenFromResponse(response, { sessionKey: KEY, signedIn: true }), (error) => error.code === "invalid_token_response");
});

test("invalid_grant on a renewal discards the key for good", async () => {
  const security = securityPlugin();
  const answers = [() => json(tokenResponse), () => json({ error: "invalid_grant" }, 400)];
  const fetch = async () => answers.shift()();
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const client = new SessionClient({ reactor, fetch });
  const started = await client.start(requestOptions);
  await assert.rejects(
    client.renew({ ...requestOptions, sessionKey: started.sessionKey }),
    (error) => error instanceof SessionError && error.code === "invalid_grant",
  );
  reactor.stop();
  // The Session has ended: its key is never used again (§4.2).
  assert.deepEqual(security.discarded, [started.sessionKey]);
});

test("an Agent ID rides in the Session assertion", async () => {
  const security = securityPlugin();
  const fetch = async () => json(tokenResponse);
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const client = new SessionClient({ reactor, fetch });
  await client.start({ ...requestOptions, agentId: "agt_shopping" });
  await client.start(requestOptions);
  reactor.stop();
  const sessions = security.claims.filter((_, index) => security.purposes[index] === "session_assertion");
  assert.equal(sessions[0].agent_id, "agt_shopping");
  assert.equal("agent_id" in sessions[1], false); // a user with one agent leaves it out (§4.2)
  assert.throws(() => buildSessionAssertionClaims({ ...requestOptions, agentId: "not valid!" }), (error) => error.code === "invalid_agent_id");
});

test("a Bearer token for an MCP server comes from Token Exchange", async () => {
  const security = securityPlugin();
  const forms = [];
  const proofs = [];
  const answers = [
    tokenResponse,
    { access_token: "bearer", token_type: "Bearer", issued_token_type: "urn:ietf:params:oauth:token-type:access_token", expires_in: 60 },
    { access_token: "dpop", token_type: "DPoP", expires_in: 60 },
  ];
  const fetch = async (_input, init) => {
    forms.push(new URLSearchParams(init.body));
    proofs.push("DPoP" in init.headers);
    return json(answers.shift());
  };
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const client = new SessionClient({ reactor, fetch });
  const mcp = "https://mcp.example.com/mcp";
  const session = await client.start(requestOptions);
  const { pairwiseUserId: _user, ...exchange } = requestOptions;
  const bearer = await client.tokenForMcp({ ...exchange, sessionKey: session.sessionKey, subjectToken: session.accessToken, resource: mcp });
  // Token Exchange answers with a Bearer token, or it is refused (§4.3).
  await assert.rejects(
    client.tokenForMcp({ ...exchange, sessionKey: session.sessionKey, subjectToken: session.accessToken, resource: mcp }),
    (error) => error instanceof SessionError && error.code === "unexpected_token_type",
  );
  reactor.stop();
  assert.equal(bearer.tokenType, "Bearer");
  assert.equal(bearer.sessionKey, session.sessionKey);
  // Every token request carries a proof, Token Exchange included (§4.3).
  assert.deepEqual(proofs, [true, true, true]);
  assert.equal(forms[1].get("grant_type"), "urn:ietf:params:oauth:grant-type:token-exchange");
  assert.equal(forms[1].get("subject_token"), "opaque-session-token");
  assert.equal(forms[1].get("subject_token_type"), "urn:ietf:params:oauth:token-type:access_token");
  assert.equal(forms[1].get("resource"), mcp);
});
