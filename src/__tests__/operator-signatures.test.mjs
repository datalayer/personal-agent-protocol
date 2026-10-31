/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Operator signatures (§5.3, RFC 9421, Web Bot Auth): what each side does with one, as Python's
// test_operator_signatures.py holds the Python SDK.
import assert from "node:assert/strict";
import test from "node:test";

import {
  AgentIdentityClient,
  DiscoveryError,
  IdentityError,
  OperatorSigners,
  OPERATOR_DIRECTORY_MEDIA_TYPE,
  OPERATOR_DIRECTORY_PATH,
  PapSession,
  ProtocolValidationError,
  SIGNATURE_AGENT_HEADER,
  SIGNATURE_HEADER,
  SIGNATURE_INPUT_HEADER,
  SecretValue,
  SessionFetchClient,
  SessionSigners,
  TransportError,
  WebBotAuthSigner,
  buildPapReactor,
  newOperatorKey,
  operatorDirectory,
  sessionHeaders,
  signOperatorRequest,
  verifyOperatorSignature,
} from "../../lib/index.js";
import { CompanyConfig } from "../../lib/server.js";

const NOW = new Date("2026-10-31T12:00:00Z");
const STAMP = NOW.getTime() / 1000;
const URL_ = "https://shop.example/api/orders?limit=2";
const AGENT = "https://agent.example/operator-keys.json";
const SESSION_JWT = "session.jwt.value";
const TOKEN = "Bearer a-token";

const request = (authorization = TOKEN) => ({
  method: "GET",
  url: URL_,
  tenantId: "tenant",
  sessionJwt: new SecretValue(SESSION_JWT),
  ...(authorization === null ? {} : { authorization: new SecretValue(authorization) }),
});

async function headersOf(key, { authorization = TOKEN, created = STAMP, expires = STAMP + 60, signatureAgent = AGENT, tag } = {}) {
  const signed = await signOperatorRequest(request(authorization), key, {
    signatureAgent,
    created,
    expires,
    nonce: "nonce",
    ...(tag === undefined ? {} : { tag }),
  });
  return {
    "poppy-session": SESSION_JWT,
    "signature-agent": signed.signatureAgent,
    "signature-input": signed.signatureInput,
    signature: signed.signature,
    ...(authorization === null ? {} : { authorization }),
  };
}

const keysOf = (...known) => async (url) => {
  assert.equal(url, AGENT);
  return operatorDirectory(known).keys;
};

const verdictOf = (headers, keys) => verifyOperatorSignature({ method: "GET", url: URL_, headers, keys, now: NOW });

test("a signature verifies and names its key source", async () => {
  const key = await newOperatorKey();
  assert.deepEqual(await verdictOf(await headersOf(key), keysOf(key)), { outcome: "verified", operator: AGENT });
});

test("what a signed request is refused for", async () => {
  const key = await newOperatorKey();
  const good = await headersOf(key);
  for (const changed of [
    { "poppy-session": "another.jwt.value" },
    { authorization: "Bearer another-token" },
    { "signature-input": good["signature-input"].replace('"@method"', '"@method') },
    { "signature-input": `${good["signature-input"]},` },
    { "signature-input": Array.from({ length: 9 }, (_, n) => `s${n}=()`).join(", ") },
    { signature: "sig1=:!!!!:" },
    { signature: "sig2=:AAAA:" },
    { "signature-agent": "sig1=http" },
    { "signature-agent": 'sig1="http://agent.example/keys"' },
    { "signature-agent": `sig1="${AGENT}";type=jwks_uri` },
  ]) {
    assert.equal((await verdictOf({ ...good, ...changed }, keysOf(key))).outcome, "invalid", JSON.stringify(changed));
  }
});

test("a request with a token needs it covered, and one without does not", async () => {
  const key = await newOperatorKey();
  const plain = await headersOf(key, { authorization: null });
  assert.equal((await verdictOf(plain, keysOf(key))).outcome, "verified");
  assert.equal((await verdictOf({ ...plain, authorization: TOKEN }, keysOf(key))).outcome, "invalid");
});

test("no signature, or another profile's, is absent", async () => {
  const key = await newOperatorKey();
  assert.equal((await verdictOf({ "poppy-session": SESSION_JWT }, keysOf(key))).outcome, "absent");
  assert.equal((await verdictOf(await headersOf(key, { tag: "another-profile" }), keysOf(key))).outcome, "absent");
});

test("no key to decide with is unverified", async () => {
  const key = await newOperatorKey();
  const good = await headersOf(key);
  assert.equal((await verdictOf(good, keysOf())).outcome, "unverified");
  const outage = async () => {
    throw new DiscoveryError("metadata_timeout", "no answer");
  };
  assert.equal((await verdictOf(good, outage)).outcome, "unverified");
  const other = good["signature-input"].replace('alg="ed25519"', 'alg="rsa-pss-sha512"');
  assert.equal((await verdictOf({ ...good, "signature-input": other }, keysOf(key))).outcome, "unverified");
});

test("a Signature-Agent that is no URL decides nothing", async () => {
  const client = new AgentIdentityClient();
  const key = await newOperatorKey();
  const headers = { ...(await headersOf(key)), "signature-agent": 'sig1="https://[nonsense"' };
  const verdict = await verdictOf(headers, (url, keyid) => client.fetchOperatorKeys(url, { keyid }));
  assert.equal(verdict.outcome, "unverified");
});

test("freshness is the verifier's clock and window", async () => {
  const key = await newOperatorKey();
  for (const [created, expires, outcome] of [
    [STAMP - 120, STAMP - 60, "invalid"],
    [STAMP - 60, STAMP, "invalid"],
    [STAMP + 61, STAMP + 120, "invalid"],
    [STAMP + 60, STAMP + 120, "verified"],
    [STAMP, STAMP, "invalid"],
  ]) {
    const headers = await headersOf(key, { created, expires });
    assert.equal((await verdictOf(headers, keysOf(key))).outcome, outcome, `${created} ${expires}`);
  }
});

test("one verified signature of several is enough", async () => {
  const key = await newOperatorKey();
  const good = await headersOf(key);
  const extra = 'proxy=("@authority");created=1;tag="another-profile"';
  const headers = { ...good, "signature-input": `${extra}, ${good["signature-input"]}` };
  assert.equal((await verdictOf(headers, keysOf(key))).outcome, "verified");
});

test("a directory publishes the public key by its thumbprint", async () => {
  const key = await newOperatorKey();
  const [published] = operatorDirectory([key]).keys;
  assert.equal(published.kid, key.keyid);
  assert.equal(published.d, undefined);
  assert.equal(OPERATOR_DIRECTORY_PATH, "/.well-known/http-message-signatures-directory");
});

test("a signer refuses a Signature-Agent it cannot write", async () => {
  const key = await newOperatorKey();
  for (const signatureAgent of ["http://agent.example/keys", 'https://agent.example/"']) {
    await assert.rejects(headersOf(key, { signatureAgent }), /HTTPS/);
  }
});

test("a company takes off, optional or required", () => {
  assert.throws(
    () => new CompanyConfig({ domain: "shop.example", name: "Shop", scopes: ["orders:read"], operatorSignatures: "sometimes" }),
    /operatorSignatures/,
  );
});

// The transport ---------------------------------------------------------------------------

const session = () =>
  new PapSession({
    sid: "S".repeat(22),
    sub: "usr_pairwise",
    issuer: "https://shop.example",
    clientId: "https://agent.example/agent.json",
    tenantId: "tenant",
  });

const reactorWith = (operator, fetch) =>
  buildPapReactor({ fetch }, [
    {
      name: "host",
      contributes: [
        { point: SessionSigners, value: { sign: async ({ sid }) => new SecretValue(`jwt.${sid}.value`) }, options: { id: "sessions" } },
        ...(operator === undefined ? [] : [{ point: OperatorSigners, value: operator, options: { id: "operator" } }]),
      ],
    },
  ]);

test("with no signer contributed, requests go unsigned", async () => {
  const headers = await sessionHeaders(reactorWith(undefined, fetch), "GET", URL_, { session: session() });
  assert.deepEqual(Object.keys(headers), ["Poppy-Session"]);
});

test("every attempt is signed anew, and covers the Session JWT it carries", async () => {
  const sent = [];
  const answers = async (_url, init) => {
    sent.push(Object.fromEntries(Object.entries(init.headers).map(([name, value]) => [name.toLowerCase(), value])));
    return sent.length === 1
      ? new Response('{"error":"invalid_session"}', { status: 400, headers: { "content-type": "application/json" } })
      : new Response("{}", { status: 200 });
  };
  const key = await newOperatorKey();
  const signer = new WebBotAuthSigner(key, { signatureAgent: AGENT, now: () => NOW });
  const client = new SessionFetchClient({ reactor: reactorWith(signer, answers), fetch: answers });
  const answer = await client.request("POST", URL_, { session: session(), body: "{}" });
  assert.equal(answer.status, 200);
  assert.equal(sent.length, 2);
  assert.notEqual(sent[0]["signature-input"], sent[1]["signature-input"]);
  for (const headers of sent) {
    const verdict = await verifyOperatorSignature({ method: "POST", url: URL_, headers, keys: keysOf(key), now: NOW });
    assert.equal(verdict.outcome, "verified");
  }
});

test("a caller never sets the signature headers", async () => {
  const client = new SessionFetchClient({ reactor: reactorWith(undefined, fetch), fetch });
  for (const name of [SIGNATURE_HEADER, SIGNATURE_INPUT_HEADER, SIGNATURE_AGENT_HEADER.toUpperCase()]) {
    await assert.rejects(
      client.request("GET", URL_, { session: session(), headers: { [name]: "x" } }),
      (error) => error instanceof TransportError && /host-owned/.test(error.message),
    );
  }
});

test("a signer needs real randomness and a positive lifetime", async () => {
  const key = await newOperatorKey();
  const weak = new WebBotAuthSigner(key, { signatureAgent: AGENT, randomBytes: () => new Uint8Array() });
  await assert.rejects(weak.sign(request()), /256 bits/);
  assert.throws(() => new WebBotAuthSigner(key, { signatureAgent: AGENT, lifetimeSeconds: 0 }), /lifetime/);
});

// The directory ---------------------------------------------------------------------------

/** A directory whose answer changes, counting its fetches. */
function directoryOf(document, { status = 200 } = {}) {
  const state = { document, status, fetches: 0 };
  state.fetch = async () => {
    state.fetches += 1;
    return new Response(JSON.stringify(state.document), {
      status: state.status,
      headers: {
        "cache-control": "max-age=3600",
        "content-type": OPERATOR_DIRECTORY_MEDIA_TYPE,
        location: "https://elsewhere.example/",
      },
    });
  };
  return state;
}

const clientOf = (directory) => new AgentIdentityClient({ reactor: buildPapReactor({ fetch: directory.fetch }) });

test("a directory is cached, read again for a new key, and kept through an outage", async () => {
  const first = await newOperatorKey();
  const second = await newOperatorKey();
  const directory = directoryOf(operatorDirectory([first]));
  const client = clientOf(directory);
  assert.equal((await client.fetchOperatorKeys(AGENT, { keyid: first.keyid })).length, 1);
  assert.equal((await client.fetchOperatorKeys(AGENT, { keyid: first.keyid })).length, 1);
  assert.equal(directory.fetches, 1);

  directory.status = 503;
  await assert.rejects(client.fetchOperatorKeys(AGENT, { keyid: second.keyid }), IdentityError);
  assert.equal(directory.fetches, 2);
  // The outage kept the cached set, and a stream of unknown keys fetches no more.
  assert.equal((await client.fetchOperatorKeys(AGENT, { keyid: second.keyid })).length, 1);
  assert.equal((await client.fetchOperatorKeys(AGENT, { keyid: first.keyid })).length, 1);
  assert.equal(directory.fetches, 2);
});

test("a directory that can't be read isn't fetched for every request", async () => {
  const key = await newOperatorKey();
  const directory = directoryOf({}, { status: 404 });
  const client = clientOf(directory);
  for (let attempt = 0; attempt < 3; attempt += 1) {
    await assert.rejects(client.fetchOperatorKeys(AGENT, { keyid: key.keyid }), IdentityError);
  }
  assert.equal(directory.fetches, 1);
});

test("a directory never redirects, and is bounded and public", async () => {
  const key = await newOperatorKey();
  await assert.rejects(clientOf(directoryOf({}, { status: 302 })).fetchOperatorKeys(AGENT, { keyid: key.keyid }), IdentityError);
  const [jwk] = operatorDirectory([key]).keys;
  const tooMany = { keys: Array.from({ length: 33 }, () => jwk) };
  await assert.rejects(clientOf(directoryOf(tooMany)).fetchOperatorKeys(AGENT, { keyid: key.keyid }), ProtocolValidationError);
  const other = { kty: "EC", crv: "P-256", x: "x", y: "y" };
  const mixed = { keys: [other, { ...jwk, d: "secret" }] };
  assert.deepEqual(await clientOf(directoryOf(mixed)).fetchOperatorKeys(AGENT, { keyid: key.keyid }), []);
});
