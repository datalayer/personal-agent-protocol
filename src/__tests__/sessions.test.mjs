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
} from "../../lib/index.js";

const tokenResponse = {
  access_token: "opaque-session-token",
  token_type: "DPoP",
  expires_in: 3600,
  scope: "",
  session_id: "ses_2Lm0",
  signed_in: false,
};

function securityPlugin() {
  const purposes = [];
  const claims = [];
  const proofRequests = [];
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
    sessionId: started.sessionId,
    signal: controller.signal,
  });
  reactor.stop();

  assert.equal(started.sessionId, "ses_2Lm0");
  assert.equal(renewed.sessionId, "ses_2Lm0");
  assert.equal(forms[0].has("session_id"), false);
  assert.equal(forms[1].get("session_id"), "ses_2Lm0");
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

  assert.equal(token.sessionId, "ses_2Lm0");
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
        '"expires_in":3600,"session_id":"ses_2Lm0","signed_in":false}',
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

test("a token for an MCP server uses the scheme its token_type names", async () => {
  const security = securityPlugin();
  const forms = [];
  const proofs = [];
  const answers = ["DPoP", "Bearer", "Bearer", "DPoP"];
  const fetch = async (_input, init) => {
    forms.push(new URLSearchParams(init.body));
    proofs.push("DPoP" in init.headers);
    return json({ ...tokenResponse, token_type: answers.shift() });
  };
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const client = new SessionClient({ reactor, fetch });
  const mcp = "https://mcp.example.com/mcp";
  const dpop = await client.tokenForMcp({ ...requestOptions, resource: mcp, dpop: true });
  // A proof was sent, and the server takes no DPoP: the Bearer token is used (§4.3).
  const bearerWithProof = await client.tokenForMcp({ ...requestOptions, resource: mcp, dpop: true });
  const bearer = await client.tokenForMcp({ ...requestOptions, resource: mcp, dpop: false });
  // No proof was sent: a DPoP token can't be one.
  await assert.rejects(
    client.tokenForMcp({ ...requestOptions, resource: mcp, dpop: false }),
    (error) => error instanceof SessionError && error.code === "unexpected_token_type",
  );
  reactor.stop();
  assert.deepEqual([dpop.tokenType, bearerWithProof.tokenType, bearer.tokenType], ["DPoP", "Bearer", "Bearer"]);
  assert.deepEqual(proofs, [true, true, false, false]);
  assert.ok(forms.every((form) => form.get("resource") === mcp));
  assert.ok(forms.every((form) => !form.has("session_id"))); // starting a Session for it
});
