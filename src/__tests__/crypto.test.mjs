/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// `JoseSigner`, thumbprints, delegated keys, and blind signing (§4.1, §5.2, §10.7, RFC 9474).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify } from "jose";

import {
  BlindJoseSigner,
  DELEGATION_MAX_LIFETIME_SECONDS,
  DelegatedSessionSigner,
  InMemoryDelegatedKeys,
  JOSE_ALGORITHMS,
  ProofError,
  RsaBlindSigningKey,
  SecretValue,
  buildClientAssertionClaims,
  delegationClaims,
  jwkThumbprint,
  normalizedHtu,
  publicJwk,
  sessionJwtClaims,
  tokenHash,
} from "../../lib/index.js";
import { JoseSigner } from "../../lib/server.js";

import { MutableClock, agentIdentity } from "./support/world.mjs";

/** The worked example of RFC 7638 §3.1. */
const RFC7638_JWK = {
  kty: "RSA",
  n:
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_B" +
    "JECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F" +
    "DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4" +
    "vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
  e: "AQAB",
  alg: "RS256",
  kid: "2011-04-29",
};
const RFC7638_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";

const ISSUER = "https://shop.example";
const URL_ORDERS = "https://shop.example/api/orders";
const SID = "Yx2b7Qd_Kp8mR3vT1nWc4A";

const ps384Keys = () => generateKeyPair("PS384", { extractable: true, modulusLength: 2048 });

for (const algorithm of ["ES256", "PS384"]) {
  const keys = () => (algorithm === "ES256" ? generateKeyPair("ES256", { extractable: true }) : ps384Keys());

  test(`signs and verifies ${algorithm} client assertions`, async () => {
    const { privateKey, publicKey } = await keys();
    const signer = new JoseSigner({ privateKey, algorithm, keyId: "agent-key" });
    const compact = (await signer.sign({ sub: "user" }, { purpose: "client_assertion" })).reveal();
    assert.deepEqual(decodeProtectedHeader(compact), { alg: algorithm, typ: "JWT", kid: "agent-key" });
    assert.deepEqual((await jwtVerify(compact, publicKey, { algorithms: [algorithm] })).payload, { sub: "user" });
  });

  test(`each purpose signs with its own type, ${algorithm}`, async () => {
    const { privateKey, publicKey } = await keys();
    const signer = new JoseSigner({ privateKey, algorithm });
    const delegation = (await signer.sign({ iss: "agent" }, { purpose: "delegation" })).reveal();
    assert.equal(decodeProtectedHeader(delegation).typ, "pap-delegation+jwt");
    await jwtVerify(delegation, publicKey, { algorithms: [algorithm], typ: "pap-delegation+jwt" });
    await assert.rejects(
      signer.sign({ sub: "user" }, { purpose: "session_assertion" }),
      (error) => error instanceof ProofError && error.code === "unknown_purpose",
    );
  });
}

test("the algorithms are ES256 and PS384, nothing symmetric, no none, no RS256", async () => {
  assert.deepEqual([...JOSE_ALGORITHMS], ["ES256", "PS384"]);
  const { privateKey } = await generateKeyPair("ES256");
  for (const algorithm of ["HS256", "none", "RS256"]) {
    assert.throws(() => new JoseSigner({ privateKey, algorithm }), /ES256 and PS384/);
  }
});

test("a thumbprint is RFC 7638", async () => {
  assert.equal(await jwkThumbprint(RFC7638_JWK), RFC7638_THUMBPRINT);
  // Only the required members count, whatever else the JWK carries and in any order.
  assert.equal(await jwkThumbprint({ e: RFC7638_JWK.e, kty: "RSA", n: RFC7638_JWK.n }), RFC7638_THUMBPRINT);
});

test("an EC thumbprint names one public key", async () => {
  const first = await exportJWK((await generateKeyPair("ES256", { extractable: true })).publicKey);
  const second = await exportJWK((await generateKeyPair("ES256", { extractable: true })).publicKey);
  assert.equal((await jwkThumbprint(first)).length, 43);
  assert.equal(await jwkThumbprint(first), await jwkThumbprint({ ...first, kid: "ignored" }));
  assert.notEqual(await jwkThumbprint(first), await jwkThumbprint(second));
});

test("refuses private material in a public JWK", async () => {
  const { privateKey } = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  assert.throws(() => publicJwk(privateJwk), /private key material/);
});

/** The agent, a delegated key custody, and a signer on a clock a test moves. */
const identity = await agentIdentity({ domain: "agent.example", name: "Agent" });
const CLIENT_ID = identity.clientId;

function fixture() {
  const clock = new MutableClock();
  const keys = new InMemoryDelegatedKeys();
  const signer = new DelegatedSessionSigner({ custody: keys, signer: identity.signer, now: () => clock.now() });
  return { clock, keys, signer };
}

const request = (sub = "usr_1", issuer = ISSUER, changes = {}) => ({
  method: "GET",
  url: URL_ORDERS,
  tenantId: "t",
  issuer,
  clientId: CLIENT_ID,
  sid: SID,
  sub,
  ...changes,
});

/** Verify a Session JWT as a company does: the delegation first, then its `cnf.jwk`. */
async function verified(compact) {
  const header = decodeProtectedHeader(compact);
  const agentKey = await importJWK(identity.jwks.keys[0], "ES256");
  const delegation = await jwtVerify(header.pap_dlg, agentKey, {
    typ: "pap-delegation+jwt",
    currentDate: new Date(decodeJwt(compact).iat * 1000),
  });
  const key = await importJWK(delegation.payload.cnf.jwk, "ES256");
  const { payload } = await jwtVerify(compact, key, {
    typ: "poppy-session+jwt",
    algorithms: ["ES256"],
    currentDate: new Date(decodeJwt(compact).iat * 1000),
  });
  assert.equal(header.kid, await jwkThumbprint(delegation.payload.cnf.jwk));
  return { header, claims: payload, delegation: delegation.payload };
}

test("a Session JWT has the spec's header and claims", async () => {
  const { signer } = fixture();
  const compact = (await signer.sign(request("usr_1", ISSUER, { agentId: "agt_1" }))).reveal();
  const { header, claims } = await verified(compact);
  assert.deepEqual(Object.keys(header).sort(), ["alg", "kid", "pap_dlg", "typ"]);
  assert.deepEqual([header.typ, header.alg], ["poppy-session+jwt", "ES256"]);
  assert.deepEqual(
    Object.keys(claims).sort(),
    ["agent_id", "aud", "htm", "htu", "iat", "iss", "jti", "sid", "sub"],
  );
  assert.deepEqual(
    [claims.iss, claims.aud, claims.sid, claims.sub, claims.agent_id, claims.htm, claims.htu],
    [CLIENT_ID, ISSUER, SID, "usr_1", "agt_1", "GET", URL_ORDERS],
  );
});

test("htu has no query or fragment, htm is upper case", async () => {
  const { signer } = fixture();
  const compact = (await signer.sign(request("usr_1", ISSUER, { url: `${URL_ORDERS}?page=2#top`, method: "post" }))).reveal();
  assert.equal(decodeJwt(compact).htu, URL_ORDERS);
  assert.equal(decodeJwt(compact).htm, "POST");
  assert.equal(normalizedHtu(`${URL_ORDERS}?page=2#top`), URL_ORDERS);
  assert.throws(() => normalizedHtu("http://shop.example/api"), (error) => error.code === "invalid_htu");
});

test("ath is the access token's SHA-256, only with a token", async () => {
  const issuedAt = new Date("2026-10-10T12:00:00Z");
  const accessToken = new SecretValue("opaque-token");
  const expected = createHash("sha256").update("opaque-token").digest("base64url");
  assert.equal(await tokenHash(accessToken), expected);
  const signedIn = await sessionJwtClaims(request("usr_1", ISSUER, { accessToken }), { issuedAt });
  assert.equal(signedIn.ath, expected);
  const signedOut = await sessionJwtClaims(request(), { issuedAt });
  assert.ok(!("ath" in signedOut));
  assert.ok(!("agent_id" in signedOut));
});

test("a Session JWT's claims refuse a bad sid, no User, and a weak jti", async () => {
  const issuedAt = new Date("2026-10-10T12:00:00Z");
  await assert.rejects(sessionJwtClaims(request("usr_1", ISSUER, { sid: "short" }), { issuedAt }), (error) => error.code === "invalid_session_id");
  await assert.rejects(sessionJwtClaims(request(""), { issuedAt }), (error) => error.code === "invalid_user_id");
  await assert.rejects(
    sessionJwtClaims(request(), { issuedAt, randomBytes: () => new Uint8Array(8) }),
    (error) => error.code === "weak_randomness",
  );
});

test("a delegation names no User and no Company", async () => {
  const { signer, keys } = fixture();
  await signer.sign(request("usr_1", ISSUER, { agentId: "agt_1" }));
  const key = await keys.current({ tenantId: "t", issuer: ISSUER, sub: "usr_1" });
  const compact = key.delegation.reveal();
  const header = decodeProtectedHeader(compact);
  assert.equal(header.typ, "pap-delegation+jwt");
  assert.equal(header.kid, "key-1");
  const claims = decodeJwt(compact);
  assert.deepEqual(Object.keys(claims).sort(), ["cnf", "exp", "iat", "iss", "jti"]);
  assert.equal(claims.iss, CLIENT_ID);
  assert.deepEqual(Object.keys(claims.cnf), ["jwk"]);
  assert.ok(!("d" in claims.cnf.jwk));
  assert.ok(claims.exp - claims.iat <= 24 * 3600);
  const text = JSON.stringify(claims);
  assert.ok(!text.includes("usr_1") && !text.includes("agt_1") && !text.includes("shop.example"));
});

test("a delegation is limited to 24 hours", async () => {
  const issuedAt = new Date("2026-10-10T12:00:00Z");
  const { publicKey } = await generateKeyPair("ES256", { extractable: true });
  const jwk = await exportJWK(publicKey);
  assert.equal(DELEGATION_MAX_LIFETIME_SECONDS, 86400);
  const longest = delegationClaims({ clientId: CLIENT_ID, publicKey: jwk, issuedAt, lifetimeSeconds: 86400 });
  assert.equal(longest.exp - longest.iat, 86400);
  for (const lifetimeSeconds of [86401, 0, -1]) {
    assert.throws(() => delegationClaims({ clientId: CLIENT_ID, publicKey: jwk, issuedAt, lifetimeSeconds }), RangeError);
    assert.throws(
      () => new DelegatedSessionSigner({ custody: new InMemoryDelegatedKeys(), signer: identity.signer, delegationLifetimeSeconds: lifetimeSeconds }),
      RangeError,
    );
  }
  assert.throws(
    () => delegationClaims({ clientId: CLIENT_ID, publicKey: { ...jwk, d: "secret" }, issuedAt, lifetimeSeconds: 60 }),
    /private key material/,
  );
  assert.throws(
    () => new DelegatedSessionSigner({ custody: new InMemoryDelegatedKeys(), signer: identity.signer, delegationLifetimeSeconds: 60, rotateBeforeSeconds: 60 }),
    RangeError,
  );
});

test("each User ID has its own key and delegation", async () => {
  // Two User IDs never share a thumbprint or a `jti`, at one company or two (§5.2).
  const { signer, keys } = fixture();
  const seen = [];
  for (const [sub, issuer] of [["usr_1", ISSUER], ["usr_2", ISSUER], ["usr_1", "https://other.example"]]) {
    const header = decodeProtectedHeader((await signer.sign(request(sub, issuer))).reveal());
    seen.push([header.kid, decodeJwt(header.pap_dlg).jti]);
  }
  assert.equal(new Set(seen.map(([kid]) => kid)).size, 3);
  assert.equal(new Set(seen.map(([, jti]) => jti)).size, 3);
  assert.equal(keys.size, 3);
  // And one User ID keeps its key from one request to the next.
  const again = decodeProtectedHeader((await signer.sign(request())).reveal());
  assert.equal(again.kid, seen[0][0]);
});

test("a delegation is rotated before it expires and never signed past", async () => {
  const { signer, clock } = fixture();
  const first = decodeProtectedHeader((await signer.sign(request())).reveal());
  clock.advance(3600 - 301);
  const kept = decodeProtectedHeader((await signer.sign(request())).reveal());
  assert.equal(kept.kid, first.kid);
  clock.advance(2);
  const compact = (await signer.sign(request())).reveal();
  const rotated = decodeProtectedHeader(compact);
  assert.notEqual(rotated.kid, first.kid);
  const delegation = decodeJwt(rotated.pap_dlg);
  assert.ok(decodeJwt(compact).iat < delegation.exp);
  // Long past the expiry: a new key again, never the old delegation.
  clock.advance(7200);
  const late = (await signer.sign(request())).reveal();
  const lateHeader = decodeProtectedHeader(late);
  assert.notEqual(lateHeader.kid, rotated.kid);
  assert.ok(decodeJwt(late).iat < decodeJwt(lateHeader.pap_dlg).exp);
  await verified(late);
});

test("a key for another agent's client ID is not reused", async () => {
  const { signer, keys } = fixture();
  const first = decodeProtectedHeader((await signer.sign(request())).reveal());
  const other = decodeProtectedHeader((await signer.sign(request("usr_1", ISSUER, { clientId: "https://other.example/agent.json" }))).reveal());
  assert.notEqual(other.kid, first.kid);
  assert.equal(keys.size, 1);
});

test("custody forgets a key", async () => {
  const { signer, keys } = fixture();
  const first = decodeProtectedHeader((await signer.sign(request())).reveal());
  await keys.forget({ tenantId: "t", issuer: ISSUER, sub: "usr_1" });
  assert.equal(keys.size, 0);
  assert.notEqual(decodeProtectedHeader((await signer.sign(request())).reveal()).kid, first.kid);
});

/** One RSA key for the blind signing tests: it takes a moment to make. */
const blind = await ps384Keys();
const blindPrivateJwk = await exportJWK(blind.privateKey);
const blindPublicJwk = await exportJWK(blind.publicKey);

/** The key holder, keeping everything it was ever sent. */
class WatchingKey extends RsaBlindSigningKey {
  seen = [];
  constructor() {
    super(blindPrivateJwk);
  }
  async blindSign(blinded) {
    this.seen.push(blinded);
    return super.blindSign(blinded);
  }
}

const blindSigner = (key) => new BlindJoseSigner({ key, publicKey: blindPublicJwk, keyId: "blind-1" });
const assertionClaims = () => buildClientAssertionClaims({ clientId: CLIENT_ID, issuer: ISSUER });
const contains = (haystack, needle) => Buffer.from(haystack).includes(Buffer.from(needle));

test("a blind signature verifies as ordinary PS384", async () => {
  const claims = assertionClaims();
  const compact = (await blindSigner(new WatchingKey()).sign(claims, { purpose: "client_assertion" })).reveal();
  assert.deepEqual(decodeProtectedHeader(compact), { alg: "PS384", typ: "JWT", kid: "blind-1" });
  const { payload } = await jwtVerify(compact, blind.publicKey, {
    algorithms: ["PS384"],
    audience: ISSUER,
    currentDate: new Date(claims.iat * 1000),
  });
  assert.deepEqual(payload, { ...claims });
});

test("a delegation is signed blindly too, with its own type", async () => {
  // One signer, both purposes (§10.7).
  const key = new WatchingKey();
  const custody = new InMemoryDelegatedKeys();
  const signer = blindSigner(key);
  const delegated = new DelegatedSessionSigner({ custody, signer });
  await delegated.sign(request());
  assert.equal(key.seen.length, 1);
  const stored = await custody.current({ tenantId: "t", issuer: ISSUER, sub: "usr_1" });
  const compact = stored.delegation.reveal();
  assert.deepEqual(decodeProtectedHeader(compact), { alg: "PS384", typ: "pap-delegation+jwt", kid: "blind-1" });
  await jwtVerify(compact, blind.publicKey, { algorithms: ["PS384"], typ: "pap-delegation+jwt" });
  const assertion = (await signer.sign(assertionClaims(), { purpose: "client_assertion" })).reveal();
  assert.equal(decodeProtectedHeader(assertion).typ, "JWT");
  assert.equal(key.seen.length, 2);
});

test("the key holder's input never contains the claims", async () => {
  // The same JWT signed twice blinds differently; nothing of it reaches the key.
  const key = new WatchingKey();
  const claims = assertionClaims();
  const first = (await blindSigner(key).sign(claims, { purpose: "client_assertion" })).reveal();
  await blindSigner(key).sign(claims, { purpose: "client_assertion" });
  assert.equal(key.seen.length, 2);
  assert.ok(!Buffer.from(key.seen[0]).equals(Buffer.from(key.seen[1])));
  const signingInput = first.slice(0, first.lastIndexOf("."));
  const payload = Buffer.from(first.split(".")[1], "base64url");
  for (const blinded of key.seen) {
    for (const part of [signingInput, payload, "shop.example", "agent.example", claims.jti]) {
      assert.equal(contains(blinded, part), false);
    }
    assert.equal(blinded.byteLength, 2048 / 8);
  }
});

test("no jti from the device, no signature", async () => {
  // The variant is safe only with a value the signer can't guess (§10.7, RFC 9474 §7.3).
  const key = new WatchingKey();
  for (const claims of [{ iss: "x" }, { iss: "x", jti: "short" }, { iss: "x", jti: 42 }]) {
    await assert.rejects(
      blindSigner(key).sign(claims, { purpose: "client_assertion" }),
      (error) => error instanceof ProofError && error.code === "weak_randomness",
    );
  }
  assert.deepEqual(key.seen, []);
  await assert.rejects(
    blindSigner(key).sign(assertionClaims(), { purpose: "session_assertion" }),
    (error) => error.code === "unknown_purpose",
  );
});

test("a wrong answer never leaves the device", async () => {
  class Lying extends WatchingKey {
    async blindSign(blinded) {
      return (await super.blindSign(blinded)).reverse();
    }
  }
  await assert.rejects(
    blindSigner(new Lying()).sign(assertionClaims(), { purpose: "client_assertion" }),
    (error) => error instanceof ProofError && error.code === "signing_failed",
  );
});

test("a short key is refused, and a key that isn't RSA", async () => {
  const n = Buffer.alloc(128, 0xff).toString("base64url");
  assert.throws(() => new RsaBlindSigningKey({ kty: "RSA", n, e: "AQAB", d: "AQAB" }), /2048/);
  assert.throws(() => new RsaBlindSigningKey({ kty: "EC" }), /RSA key/);
  assert.throws(
    () =>
      new BlindJoseSigner({
        key: new WatchingKey(),
        publicKey: { kty: "RSA", n, e: "AQAB" },
        keyId: "short",
      }),
    /2048/,
  );
});
