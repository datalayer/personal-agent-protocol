/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The Session header on every request (§5.2, §5.6).
import assert from "node:assert/strict";
import test from "node:test";

import {
  PapSession,
  RateLimitBudgets,
  RetryPolicies,
  RetryPolicy,
  SESSION_HEADER,
  SecretValue,
  SessionFetchClient,
  SessionSigners,
  TransportError,
  accessTokenFromResponse,
  buildPapReactor,
  invalidSession,
  parseTokenResponse,
} from "../../lib/index.js";

const ORDERS = "https://api.example/orders";
const INVALID_SESSION = JSON.stringify({ error: "invalid_session" });
const json = { "content-type": "application/json" };

const session = () =>
  new PapSession({
    sid: "S".repeat(22),
    sub: "usr_pairwise",
    issuer: "https://auth.example",
    clientId: "https://agent.example/agent.json",
    tenantId: "tenant",
  });
const token = () =>
  accessTokenFromResponse(
    parseTokenResponse({ access_token: "access-secret", token_type: "Bearer", expires_in: 300, scope: "orders:read" }),
  );

/** A Session signer that counts, and a client over `fetch`. */
function setup(fetch, plugins = []) {
  const requests = [];
  const reactor = buildPapReactor({ fetch }, [
    {
      name: "@tests/pap-transport",
      contributes: [
        {
          point: SessionSigners,
          value: {
            async sign(request) {
              requests.push(request);
              return new SecretValue(`jwt-${requests.length}`);
            },
          },
          options: { id: "session-signer" },
        },
      ],
    },
    ...plugins,
  ]);
  return { requests, reactor, client: new SessionFetchClient({ reactor, fetch }) };
}

test("the header is the spec's", () => {
  assert.equal(SESSION_HEADER, "Poppy-Session");
});

test("invalid_session restarts once with a fresh JWT, and a redirect gets nothing", async () => {
  let calls = 0;
  const fetch = async (_input, init) => {
    calls += 1;
    assert.equal(init.headers.Authorization, "Bearer access-secret");
    assert.equal(init.headers["Poppy-Session"], `jwt-${calls}`);
    assert.ok(!("DPoP" in init.headers));
    if (calls === 1) return new Response(INVALID_SESSION, { status: 400, headers: json });
    if (calls === 2) return new Response('{"ok":true}', { status: 200, headers: json });
    // Even on the company's own origin, a redirect is never followed with the token, a
    // Session JWT, or the body (§3): the caller sees `redirect_refused`.
    return new Response(null, { status: 307, headers: { Location: "/orders/current" } });
  };
  const { requests, reactor, client } = setup(fetch);
  const papSession = session();
  const response = await client.request("GET", ORDERS, { session: papSession, token: token() });
  await assert.rejects(
    client.request("GET", ORDERS, { session: papSession, token: token() }),
    (error) => error instanceof TransportError && error.code === "redirect_refused" && error.statusCode === 307,
  );
  reactor.stop();

  assert.equal(response.status, 200);
  assert.equal(calls, 3);
  // A new `sid` for the same User, from the moment the first was refused (§5.5, §7).
  const sids = requests.map((request) => request.sid);
  assert.equal(sids[0], "S".repeat(22));
  assert.equal(sids[1], papSession.sid);
  assert.equal(sids[2], papSession.sid);
  assert.notEqual(sids[1], sids[0]);
  assert.deepEqual([...new Set(requests.map((request) => request.sub))], ["usr_pairwise"]);
  assert.deepEqual(requests.map((request) => request.url), Array(3).fill(ORDERS));
  assert.ok(requests.every((request) => request.accessToken.reveal() === "access-secret"));
});

test("a second invalid_session goes back to the caller", async () => {
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return new Response(INVALID_SESSION, { status: 400, headers: json });
  };
  const { reactor, client } = setup(fetch);
  const response = await client.request("POST", ORDERS, { session: session(), body: "{}" });
  reactor.stop();
  // The Personal Agent stops sending the request (§7).
  assert.equal(response.status, 400);
  assert.equal(calls, 2);
  assert.equal(await invalidSession(response), true);
});

test("another 400 is not invalid_session", async () => {
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return new Response('{"error":"invalid_request"}', { status: 400, headers: json });
  };
  const { reactor, client } = setup(fetch);
  const papSession = session();
  const response = await client.request("GET", ORDERS, { session: papSession });
  reactor.stop();
  assert.equal(response.status, 400);
  assert.equal(calls, 1);
  assert.equal(papSession.sid, "S".repeat(22));
  assert.equal(await invalidSession(response), false);
});

test("signed-out requests carry the Session header alone", async () => {
  const sent = [];
  const fetch = async (_input, init) => {
    sent.push(init.headers);
    return new Response("{}", { status: 200, headers: json });
  };
  const { requests, reactor, client } = setup(fetch);
  await client.request("GET", ORDERS, { session: session() });
  reactor.stop();
  assert.equal(sent[0]["Poppy-Session"], "jwt-1");
  assert.ok(!("Authorization" in sent[0]));
  assert.equal(requests[0].accessToken, undefined);
});

test("refuses a cross-origin redirect and the headers the host owns", async () => {
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return new Response(null, { status: 307, headers: { Location: "https://attacker.example/collect" } });
  };
  const { reactor, client } = setup(fetch);
  await assert.rejects(
    client.request("GET", ORDERS, { session: session(), token: token() }),
    (error) => error instanceof TransportError && error.code === "redirect_refused",
  );
  for (const name of ["Authorization", "authorization", "Poppy-Session", "DPoP"]) {
    await assert.rejects(
      client.request("GET", ORDERS, { session: session(), token: token(), headers: { [name]: "attacker-controlled" } }),
      (error) => error instanceof TransportError && error.code === "protected_header" && /host-owned/.test(error.message),
    );
  }
  reactor.stop();
  assert.equal(calls, 1);
});

/** A budget that remembers each pause and never sleeps. */
function recordingBudget() {
  const budget = {
    deferred: [],
    acquired: 0,
    async acquire() {
      budget.acquired += 1;
    },
    async defer(key, seconds) {
      budget.deferred.push([key, seconds]);
    },
  };
  const plugin = {
    name: "@tests/pap-transport-limits",
    contributes: [
      { point: RateLimitBudgets, value: budget, options: { id: "budget", order: 1 } },
      {
        point: RetryPolicies,
        value: new RetryPolicy({ maxAttempts: 2, maxRetryAfter: 10 }),
        options: { id: "policy", order: 1 },
      },
    ],
  };
  return { budget, plugin };
}

for (const status of [429, 503]) {
  test(`a ${status} on a safe method is retried after Retry-After, with a fresh JWT`, async () => {
    const answers = [
      () => new Response(null, { status, headers: { "Retry-After": "2" } }),
      () => new Response("{}", { status: 200, headers: json }),
    ];
    const { budget, plugin } = recordingBudget();
    const { requests, reactor, client } = setup(async () => answers.shift()(), [plugin]);
    const response = await client.request("GET", ORDERS, { session: session() });
    reactor.stop();
    assert.equal(response.status, 200);
    assert.equal(requests.length, 2);
    assert.equal(budget.acquired, 2);
    assert.equal(budget.deferred.length, 1);
    assert.ok(budget.deferred[0][1] >= 2);
  });

  test(`a ${status} on a write goes back to the caller, its pause shared`, async () => {
    let calls = 0;
    const fetch = async () => {
      calls += 1;
      return new Response(null, { status, headers: { "Retry-After": "7" } });
    };
    const { budget, plugin } = recordingBudget();
    const { reactor, client } = setup(fetch, [plugin]);
    const response = await client.request("POST", ORDERS, { session: session(), body: "{}" });
    reactor.stop();
    assert.equal(response.status, status);
    assert.equal(calls, 1);
    assert.deepEqual(budget.deferred.map(([, seconds]) => seconds), [7]);
  });
}

test("a Retry-After longer than the policy allows returns the refusal", async () => {
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return new Response(null, { status: 429, headers: { "Retry-After": "600" } });
  };
  const { budget, plugin } = recordingBudget();
  const { reactor, client } = setup(fetch, [plugin]);
  const response = await client.request("GET", ORDERS, { session: session() });
  reactor.stop();
  assert.equal(response.status, 429);
  assert.equal(calls, 1);
  assert.deepEqual(budget.deferred.map(([, seconds]) => seconds), [600]);
});
