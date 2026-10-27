/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import { decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from "jose";

import {
  InMemorySessionKeys,
  JoseDpopProofProvider,
  ProofError,
  SecretValue,
  jwkThumbprint,
} from "../../lib/index.js";
import { JoseSigner, verifyDpopProof } from "../../lib/server.js";

const now = new Date("2026-10-10T12:00:00Z");

/** One Session Key, already made: a custody holding exactly it. */
class FixedKey {
  constructor(material, thumbprint) {
    this.material = material;
    this.thumbprint = thumbprint;
  }

  static async of(material) {
    return new FixedKey(material, await jwkThumbprint(material.publicJwk).catch(() => "K".repeat(43)));
  }

  async generate() {
    return this.material;
  }

  async get({ thumbprint }) {
    return thumbprint === this.thumbprint ? this.material : undefined;
  }

  async discard() {}
}

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
  const fixed = await FixedKey.of({ privateKey: keys.privateKey, publicJwk });
  const provider = new JoseDpopProofProvider({
    keys: fixed,
    now: () => now,
    randomBytes: length => Uint8Array.from({ length }, (_, index) => index),
  });
  const accessToken = new SecretValue("opaque-token");
  const proof = await provider.create({
    method: "post",
    url: "https://api.example/orders?tracking=secret#fragment",
    tenantId: "tenant-one",
    sessionKey: fixed.thumbprint,
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
  const fixed = await FixedKey.of({ privateKey: keys.privateKey, publicJwk });
  const provider = new JoseDpopProofProvider({
    keys: fixed,
    now: () => now,
  });
  const proof = await provider.create({
    method: "GET",
    url: "https://api.example/orders",
    tenantId: "tenant-one",
    sessionKey: fixed.thumbprint,
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
  const fixed = await FixedKey.of({ privateKey: keys.privateKey, publicJwk: privateJwk });
  const provider = new JoseDpopProofProvider({
    keys: fixed,
  });

  await assert.rejects(
    provider.create({
      method: "POST",
      url: "https://auth.example/token",
      tenantId: "tenant-one",
      sessionKey: fixed.thumbprint,
      issuer: "https://auth.example",
    }),
    /private key material/,
  );
});

test("each Session has a key of its own until it is discarded", async () => {
  // A new key pair for each Session, named by its thumbprint (§4.3); a discarded key is
  // never used again (§4.2).
  const keys = new InMemorySessionKeys();
  const provider = new JoseDpopProofProvider({ keys, now: () => now });
  const shop = "https://auth.provider.example/shop-a";
  const first = await provider.newSessionKey({ tenantId: "tenant", issuer: shop });
  const second = await provider.newSessionKey({ tenantId: "tenant", issuer: shop });
  assert.notEqual(first, second);
  assert.equal(first.length, 43);
  const material = await keys.get({ tenantId: "tenant", issuer: shop, thumbprint: first });
  assert.equal(await jwkThumbprint(material.publicJwk), first);
  const request = { method: "POST", url: "https://auth.provider.example/oauth/token", tenantId: "tenant", issuer: shop, sessionKey: first };
  const header = decodeProtectedHeader((await provider.create(request)).reveal());
  assert.equal(await jwkThumbprint(header.jwk), first);
  // Another issuer, or another tenant, is another key's name space.
  assert.equal(await keys.get({ tenantId: "tenant", issuer: "https://other.example", thumbprint: first }), undefined);
  assert.equal(await keys.get({ tenantId: "other", issuer: shop, thumbprint: first }), undefined);
  await provider.discardSessionKey({ tenantId: "tenant", issuer: shop, sessionKey: first });
  await assert.rejects(provider.create(request), (error) => error instanceof ProofError && error.code === "unknown_session_key");
});
