/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// DPoP (§4.5, RFC 9449): the personal agent's proofs, token requests and resources, as
// Python's test_dpop.py holds the Python SDK.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { compactVerify, decodeJwt, decodeProtectedHeader, importJWK } from "jose";

import {
  Clocks,
  DpopProvers,
  InMemoryDpopKeys,
  JoseDpopProver,
  McpSessionAuth,
  PapSession,
  ProofError,
  SecretValue,
  SessionClient,
  SessionError,
  SessionFetchClient,
  SessionSigners,
  Signers,
  TransportError,
  buildPapReactor,
  challengeParameters,
  firstContribution,
  jwkThumbprint,
  tokenHash,
} from "../../lib/index.js";

const ISSUER = "https://shop.example";
const NOW = new Date("2026-10-30T12:00:00Z");
const ORDERS = "https://shop.example/api/orders";
const TOKEN_ENDPOINT = `${ISSUER}/oauth/token`;
const ISSUED = { access_token: "at", token_type: "DPoP", expires_in: 60 };
const BOUND = { accessToken: new SecretValue("bound-token"), tokenType: "DPoP", scopes: ["orders:read"] };
const PLAIN = { accessToken: new SecretValue("plain-token"), tokenType: "Bearer", scopes: ["orders:read"] };

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

const proofRequest = (changes = {}) => ({
  method: "post",
  url: "https://shop.example/api/orders?page=2#top",
  tenantId: "tenant",
  issuer: ISSUER,
  ...changes,
});

/** A proof's header and claims, its signature checked with the key it carries. */
async function read(proof) {
  const compact = proof instanceof SecretValue ? proof.reveal() : proof;
  const header = decodeProtectedHeader(compact);
  await compactVerify(compact, await importJWK(header.jwk, "ES256"));
  return [header, decodeJwt(compact)];
}

test("a proof has the header and claims of RFC 9449", async () => {
  const prover = new JoseDpopProver(new InMemoryDpopKeys(), { now: () => NOW });
  const [header, claims] = await read(await prover.prove(proofRequest()));
  assert.equal(header.typ, "dpop+jwt");
  assert.equal(header.alg, "ES256");
  assert.deepEqual(Object.keys(header.jwk).sort(), ["crv", "kty", "x", "y"]);
  assert.deepEqual(Object.keys(claims).sort(), ["htm", "htu", "iat", "jti"]);
  assert.equal(claims.htm, "POST");
  assert.equal(claims.htu, ORDERS);
  assert.equal(claims.iat, NOW.getTime() / 1000);
  assert.ok(claims.jti.length >= 22);
});

test("ath goes with an access token, and a nonce when given", async () => {
  const prover = new JoseDpopProver(new InMemoryDpopKeys(), { now: () => NOW });
  const proof = await prover.prove(proofRequest({ accessToken: new SecretValue("access-secret"), nonce: "n-1" }));
  const [, claims] = await read(proof);
  assert.equal(claims.ath, createHash("sha256").update("access-secret").digest("base64url"));
  assert.equal(claims.nonce, "n-1");
});

test("one key per Company for a tenant, and a new jti for each proof", async () => {
  const keys = new InMemoryDpopKeys();
  const prover = new JoseDpopProver(keys, { now: () => NOW });
  const keyOf = async (changes) => {
    const [header, claims] = await read(await prover.prove(proofRequest(changes)));
    return [await jwkThumbprint(header.jwk), claims.jti];
  };
  const [first, jti] = await keyOf();
  const [same, otherJti] = await keyOf();
  assert.equal(first, same);
  assert.notEqual(jti, otherJti);
  assert.notEqual(first, (await keyOf({ tenantId: "other" }))[0]);
  assert.notEqual(first, (await keyOf({ issuer: "https://other.example" }))[0]);
  assert.equal(keys.size, 3);
  await keys.forget({ tenantId: "tenant", issuer: ISSUER });
  assert.notEqual(first, (await keyOf())[0]);
});

test("two callers never get two keys", async () => {
  const keys = new InMemoryDpopKeys();
  const who = { tenantId: "tenant", issuer: ISSUER };
  const found = await Promise.all(Array.from({ length: 8 }, () => keys.keyFor(who)));
  assert.equal(new Set(found.map((key) => key.thumbprint)).size, 1);
  assert.equal(keys.size, 1);
});

test("a proof needs 128 random bits", async () => {
  const weak = new JoseDpopProver(new InMemoryDpopKeys(), { now: () => NOW, randomBytes: () => new Uint8Array(5) });
  await assert.rejects(weak.prove(proofRequest()), (error) => error instanceof ProofError && error.code === "weak_randomness");
});

test("the default prover reads the host's clock and random source when it signs", async () => {
  const reactor = buildPapReactor({}, [
    { name: "host", contributes: [{ point: Clocks, value: { now: () => NOW }, options: { id: "host", order: 10 } }] },
  ]);
  const prover = firstContribution(reactor, DpopProvers, "DPoP prover");
  assert.ok(prover instanceof JoseDpopProver);
  const [, claims] = await read(await prover.prove(proofRequest()));
  reactor.stop();
  assert.equal(claims.iat, NOW.getTime() / 1000);
});

// Token requests ---------------------------------------------------------------------

const signer = { sign: async (claims) => new SecretValue(`assertion-${claims.jti}`) };

async function tokenRequest(answers, dpopSigningAlgs) {
  const sent = [];
  const fetch = async (url, init) => {
    const request = { url: String(url), headers: new Headers(init.headers), body: String(init.body) };
    sent.push(request);
    return answers(request);
  };
  const reactor = buildPapReactor({ fetch }, [
    { name: "host", contributes: [{ point: Signers, value: signer, options: { id: "agent" } }] },
  ]);
  try {
    const response = await new SessionClient({ reactor, fetch }).tokenRequest({
      clientId: "https://agent.example/agent.json",
      issuer: ISSUER,
      tokenEndpoint: TOKEN_ENDPOINT,
      form: () => ({ grant_type: "refresh_token", refresh_token: "rt" }),
      error: SessionError,
      tenantId: "tenant",
      dpopSigningAlgs,
    });
    return { response, sent };
  } catch (error) {
    error.sent = sent;
    throw error;
  } finally {
    reactor.stop();
  }
}

for (const algs of [["ES256"], ["RS256", "ES256"]]) {
  test(`a token request proves when the issuer lists ${algs.join(" and ")}`, async () => {
    const { response, sent } = await tokenRequest(() => json(ISSUED), algs);
    assert.equal(response.tokenType, "DPoP");
    const [, claims] = await read(sent[0].headers.get("dpop"));
    assert.equal(claims.htm, "POST");
    assert.equal(claims.htu, TOKEN_ENDPOINT);
    assert.ok(!("ath" in claims) && !("nonce" in claims));
  });
}

for (const algs of [undefined, [], ["RS256"], ["es256"]]) {
  test(`a token request sends no proof when the issuer lists ${JSON.stringify(algs)}`, async () => {
    const { sent } = await tokenRequest(() => json({ ...ISSUED, token_type: "Bearer" }), algs);
    assert.equal(sent[0].headers.has("dpop"), false);
  });
}

test("Bearer after a proof is the Company's choice", async () => {
  const { response, sent } = await tokenRequest(() => json({ ...ISSUED, token_type: "Bearer" }), ["ES256"]);
  assert.equal(response.tokenType, "Bearer");
  assert.ok(sent[0].headers.has("dpop"));
});

test("DPoP with no proof sent is refused", async () => {
  await assert.rejects(tokenRequest(() => json(ISSUED), ["RS256"]), (error) => {
    assert.equal(error.code, "unsupported_token_type");
    assert.ok(!error.message.split(" ").includes("at"));
    return true;
  });
});

test("use_dpop_nonce is retried once with a fresh proof and assertion", async () => {
  const answers = async (request) => {
    const [, claims] = await read(request.headers.get("dpop"));
    return claims.nonce === undefined ? json({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": "n-1" }) : json(ISSUED);
  };
  const { response, sent } = await tokenRequest(answers, ["ES256"]);
  assert.equal(response.tokenType, "DPoP");
  assert.equal(sent.length, 2);
  const [[, first], [, second]] = await Promise.all(sent.map((item) => read(item.headers.get("dpop"))));
  assert.notEqual(first.jti, second.jti);
  assert.equal(second.nonce, "n-1");
  const assertions = sent.map((item) => new URLSearchParams(item.body).get("client_assertion"));
  assert.notEqual(assertions[0], assertions[1]);
});

test("a second use_dpop_nonce is refused and not retried again", async () => {
  await assert.rejects(
    tokenRequest(() => json({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": "n-again" }), ["ES256"]),
    (error) => error.code === "use_dpop_nonce" && error.sent.length === 2,
  );
});

test("use_dpop_nonce with no proof sent is not retried", async () => {
  await assert.rejects(
    tokenRequest(() => json({ error: "use_dpop_nonce" }, 400, { "DPoP-Nonce": "n-1" }), undefined),
    (error) => error.code === "use_dpop_nonce" && error.sent.length === 1,
  );
});

// Resources --------------------------------------------------------------------------

const session = () =>
  new PapSession({
    sid: "S".repeat(22),
    sub: "usr_pairwise",
    issuer: ISSUER,
    clientId: "https://agent.example/agent.json",
    tenantId: "tenant",
  });

function world(answers) {
  const sent = [];
  const jwts = [];
  const fetch = async (url, init) => {
    const request = { url: String(url), headers: new Headers(init.headers) };
    sent.push(request);
    return answers(request);
  };
  const sessionSigner = {
    async sign(request) {
      jwts.push(request);
      return new SecretValue(`jwt-${jwts.length}`);
    },
  };
  const reactor = buildPapReactor({ fetch }, [
    { name: "host", contributes: [{ point: SessionSigners, value: sessionSigner, options: { id: "session-signer" } }] },
  ]);
  return { client: new SessionFetchClient({ reactor, fetch }), fetch, sent, jwts, reactor };
}

const NONCE_CHALLENGE = { "WWW-Authenticate": 'DPoP error="use_dpop_nonce"', "DPoP-Nonce": "n-1" };

async function challengeNonce(request) {
  const [, claims] = await read(request.headers.get("dpop"));
  if (claims.nonce === "n-1") return json({}, 200, { "DPoP-Nonce": "n-2" });
  return json({ error: "use_dpop_nonce" }, 401, NONCE_CHALLENGE);
}

test("a DPoP token goes with a proof and the Session header", async () => {
  const { client, sent, jwts, reactor } = world(() => json({}));
  await client.request("GET", `${ORDERS}?page=2`, { session: session(), token: BOUND });
  reactor.stop();
  const { headers } = sent[0];
  assert.equal(headers.get("authorization"), "DPoP bound-token");
  assert.equal(headers.get("poppy-session"), "jwt-1");
  const [, claims] = await read(headers.get("dpop"));
  assert.equal(claims.htu, ORDERS);
  assert.equal(claims.htm, "GET");
  assert.equal(claims.ath, await tokenHash(BOUND.accessToken));
  assert.equal(jwts[0].accessToken, BOUND.accessToken);
});

test("a Bearer token and a signed-out request carry no proof", async () => {
  const { client, sent, reactor } = world(() => json({}));
  await client.request("GET", ORDERS, { session: session(), token: PLAIN });
  await client.request("GET", ORDERS, { session: session() });
  reactor.stop();
  assert.equal(sent[0].headers.get("authorization"), "Bearer plain-token");
  assert.ok(sent.every((request) => !request.headers.has("dpop")));
});

test("a resource nonce is retried once and the latest kept for the origin", async () => {
  const { client, sent, jwts, reactor } = world(challengeNonce);
  const answered = await client.request("GET", ORDERS, { session: session(), token: BOUND });
  assert.equal(answered.status, 200);
  assert.equal(sent.length, 2);
  const [[, first], [, second]] = await Promise.all(sent.map((item) => read(item.headers.get("dpop"))));
  assert.notEqual(first.jti, second.jti);
  assert.ok(!("nonce" in first));
  assert.equal(second.nonce, "n-1");
  // A fresh Session JWT too.
  assert.deepEqual(sent.map((item) => item.headers.get("poppy-session")), ["jwt-1", "jwt-2"]);
  assert.equal(jwts.length, 2);
  // The latest nonce, from the success, goes with the next request to the origin.
  assert.deepEqual([...client.dpopNonces], [["https://shop.example:443", "n-2"]]);
  client.dpopNonces.set("https://shop.example:443", "n-1");
  await client.request("GET", `${ORDERS}/1`, { session: session(), token: BOUND });
  assert.equal(sent.length, 3);
  assert.equal((await read(sent[2].headers.get("dpop")))[1].nonce, "n-1");
  reactor.stop();
});

test("a second nonce challenge is returned to the caller", async () => {
  const { client, sent, reactor } = world(() => json({ error: "use_dpop_nonce" }, 401, { ...NONCE_CHALLENGE, "DPoP-Nonce": "n-3" }));
  const answered = await client.request("GET", ORDERS, { session: session(), token: BOUND });
  reactor.stop();
  assert.equal(answered.status, 401);
  assert.equal(sent.length, 2);
});

test("a Bearer token ignores a nonce challenge", async () => {
  const { client, sent, reactor } = world(() => new Response(null, { status: 401, headers: NONCE_CHALLENGE }));
  const answered = await client.request("GET", ORDERS, { session: session(), token: PLAIN });
  reactor.stop();
  assert.equal(answered.status, 401);
  assert.equal(sent.length, 1);
  assert.equal(client.dpopNonces.size, 0);
});

test("a restarted Session sends a fresh proof, and a redirect is refused", async () => {
  const answers = [
    json({ error: "invalid_session" }, 400),
    new Response(null, { status: 302, headers: { Location: "https://elsewhere.example/" } }),
  ];
  const { client, sent, reactor } = world(() => answers.shift());
  await assert.rejects(
    client.request("GET", ORDERS, { session: session(), token: BOUND }),
    (error) => error instanceof TransportError && error.code === "redirect_refused",
  );
  reactor.stop();
  assert.equal(sent.length, 2);
  assert.notEqual(sent[0].headers.get("dpop"), sent[1].headers.get("dpop"));
});

test("the DPoP header stays the host's", async () => {
  const { client, sent, reactor } = world(() => json({}));
  await assert.rejects(
    client.request("GET", ORDERS, { session: session(), token: BOUND, headers: { DPoP: "forged" } }),
    (error) => error.code === "protected_header",
  );
  reactor.stop();
  assert.equal(sent.length, 0);
});

test("MCP sends a proof, retries a nonce once, and keeps it", async () => {
  const url = "https://shop.example/mcp";
  const { client, fetch, sent, reactor } = world(challengeNonce);
  const auth = new McpSessionAuth(url, { session: session(), token: { ...BOUND, resource: url }, reactor, fetch });
  const answered = await auth.fetch(url, { method: "POST", body: "{}" });
  assert.equal(answered.status, 200);
  assert.equal(sent.length, 2);
  assert.equal(sent[1].headers.get("authorization"), "DPoP bound-token");
  assert.equal((await read(sent[1].headers.get("dpop")))[1].nonce, "n-1");
  assert.equal(auth.dpopNonce, "n-2");
  reactor.stop();
  assert.equal(client.dpopNonces.size, 0);
});

test("a challenge names its parameters whichever scheme comes first", () => {
  assert.equal(challengeParameters(NONCE_CHALLENGE["WWW-Authenticate"]).error, "use_dpop_nonce");
});
