import assert from "node:assert/strict";
import test from "node:test";

import {
  DpopProofProviders,
  JWT_BEARER_GRANT,
  SessionClient,
  SessionError,
  Signers,
  buildPapReactor,
} from "../lib/index.js";

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
  const proofRequests = [];
  const signer = {
    async sign(_claims, options) {
      purposes.push(options.purpose);
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
  const forms = [];
  const fetch = async (_input, init) => {
    assert.equal(init.method, "POST");
    assert.match(init.headers.DPoP, /^proof-/);
    forms.push(new URLSearchParams(init.body));
    return new Response(JSON.stringify(tokenResponse), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const reactor = buildPapReactor({ fetch }, [security.plugin]);
  const client = new SessionClient({ reactor, fetch });

  const started = await client.start(requestOptions);
  const renewed = await client.renew({ ...requestOptions, sessionId: started.sessionId });
  reactor.stop();

  assert.equal(started.sessionId, "ses_2Lm0");
  assert.equal(renewed.sessionId, "ses_2Lm0");
  assert.equal(forms[0].has("session_id"), false);
  assert.equal(forms[1].get("session_id"), "ses_2Lm0");
  assert.equal(forms[0].get("grant_type"), JWT_BEARER_GRANT);
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
