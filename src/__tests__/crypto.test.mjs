import assert from "node:assert/strict";
import test from "node:test";

import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from "jose";

import {
  JoseDpopProofProvider,
  ProofError,
  SecretValue,
} from "../../lib/index.js";
import { JoseSigner, verifyDpopProof } from "../../lib/server.js";

const now = new Date("2026-10-10T12:00:00Z");

class ReplayCache {
  keys = new Set();

  async markOnce(key, options) {
    assert.ok(options.expiresAt > now);
    if (this.keys.has(key)) return false;
    this.keys.add(key);
    return true;
  }
}

for (const algorithm of ["ES256", "RS256"]) {
  test(`signs and verifies ${algorithm} PAP assertions`, async () => {
    const keys = await generateKeyPair(algorithm, { extractable: true });
    const signer = new JoseSigner({
      privateKey: keys.privateKey,
      algorithm,
      keyId: "agent-key",
    });

    const compact = (await signer.sign({ sub: "user" }, { purpose: "test" })).reveal();

    assert.deepEqual(decodeProtectedHeader(compact), {
      alg: algorithm,
      typ: "JWT",
      kid: "agent-key",
    });
    assert.equal((await jwtVerify(compact, keys.publicKey)).payload.sub, "user");
  });
}

test("rejects symmetric and none algorithms", async () => {
  const { privateKey } = await generateKeyPair("ES256");
  assert.throws(
    () => new JoseSigner({ privateKey, algorithm: "HS256" }),
    /ES256 or RS256/,
  );
  assert.throws(
    () => new JoseSigner({ privateKey, algorithm: "none" }),
    /ES256 or RS256/,
  );
});

test("creates and verifies a bound DPoP proof only once", async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(keys.publicKey);
  const provider = new JoseDpopProofProvider({
    resolveKey: async () => ({ privateKey: keys.privateKey, publicJwk }),
    now: () => now,
    randomBytes: length => Uint8Array.from({ length }, (_, index) => index),
  });
  const accessToken = new SecretValue("opaque-token");
  const proof = await provider.create({
    method: "post",
    url: "https://api.example/orders?tracking=secret#fragment",
    tenantId: "tenant-one",
    subject: "usr_one",
    issuer: "https://auth.example",
    accessToken,
    nonce: "company-nonce",
  });
  assert.equal(decodeJwt(proof.reveal()).jti, "AAECAwQFBgcICQoLDA0ODw");
  const cache = new ReplayCache();

  const verified = await verifyDpopProof(proof, {
    method: "POST",
    url: "https://api.example/orders?different=query",
    accessToken,
    nonce: "company-nonce",
    replayCache: cache,
    now,
  });

  assert.deepEqual(verified.publicJwk, publicJwk);
  assert.ok(verified.keyThumbprint);
  await assert.rejects(
    verifyDpopProof(proof, {
      method: "POST",
      url: "https://api.example/orders",
      accessToken,
      nonce: "company-nonce",
      replayCache: cache,
      now,
    }),
    error => error instanceof ProofError && /already been used/.test(error.message),
  );
});

test("rejects DPoP request and token mismatch", async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(keys.publicKey);
  const provider = new JoseDpopProofProvider({
    resolveKey: () => ({ privateKey: keys.privateKey, publicJwk }),
    now: () => now,
  });
  const proof = await provider.create({
    method: "GET",
    url: "https://api.example/orders",
    tenantId: "tenant-one",
    subject: "usr_one",
    issuer: "https://auth.example",
    accessToken: new SecretValue("right-token"),
  });

  await assert.rejects(
    verifyDpopProof(proof, {
      method: "DELETE",
      url: "https://api.example/orders",
      accessToken: new SecretValue("right-token"),
      replayCache: new ReplayCache(),
      now,
    }),
    error => error instanceof ProofError && /does not match/.test(error.message),
  );
  await assert.rejects(
    verifyDpopProof(proof, {
      method: "GET",
      url: "https://api.example/orders",
      accessToken: new SecretValue("wrong-token"),
      replayCache: new ReplayCache(),
      now,
    }),
    error => error instanceof ProofError && /hash is invalid/.test(error.message),
  );
});

test("rejects a private JWK in the DPoP protected header", async () => {
  const keys = await generateKeyPair("ES256", { extractable: true });
  const privateJwk = await exportJWK(keys.privateKey);
  const provider = new JoseDpopProofProvider({
    resolveKey: () => ({ privateKey: keys.privateKey, publicJwk: privateJwk }),
  });

  await assert.rejects(
    provider.create({
      method: "POST",
      url: "https://auth.example/token",
      tenantId: "tenant-one",
      subject: "usr_one",
      issuer: "https://auth.example",
    }),
    /private key material/,
  );
});
