/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// A Company with no OAuth issuer: its identifier is its HTTPS domain (§3.2, §5.1, §5.2), as
// Python's test_issuerless.py holds the Python SDK.
import assert from "node:assert/strict";
import test from "node:test";

import { AuthorizationError, DiscoveryError, ProtocolValidationError, companyIdentifier, discoverCompany, requireOauth } from "../../lib/index.js";
import { CompanyConfig } from "../../lib/server.js";

const RESOURCE_METADATA = "/.well-known/oauth-protected-resource";
const SIGNED_OUT = {
  protocol_version: "0.3",
  organization: { name: "Example", domain: "Example.COM" },
  apis: [{ type: "openapi", url: "https://example.com/o.json", description: "Catalog" }],
  agent: { protocols: [{ type: "poppy", endpoint: "https://example.com/poppy" }] },
  feedback: { endpoint: "https://example.com/feedback" },
  web: { browser_session_endpoint: "https://example.com/join" },
};
const ISSUER_METADATA = {
  issuer: "https://auth.example.com",
  token_endpoint: "https://auth.example.com/token",
  revocation_endpoint: "https://auth.example.com/revoke",
  grant_types_supported: ["refresh_token"],
  protected_resources: ["https://example.com"],
};
const NAMES_ISSUER = { resource: "https://example.com", authorization_servers: ["https://auth.example.com"] };

const json = (body, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function site({ resource, document = SIGNED_OUT, issuer = () => new Response(null, { status: 404 }) }) {
  return async (input) => {
    const { pathname } = new URL(input);
    if (pathname === "/.well-known/poppy.json") return json(document);
    if (pathname === RESOURCE_METADATA) return resource();
    return issuer();
  };
}

const discover = (options, extra = {}) => discoverCompany("example.com", { fetch: site(options), ...extra });
const notFound = () => new Response(null, { status: 404 });
const code = (wanted) => (error) => error.code === wanted;

for (const [name, resource] of [
  ["404", notFound],
  ["absent", () => json({ resource: "https://example.com" })],
  ["empty", () => json({ resource: "https://example.com", authorization_servers: [] })],
]) {
  test(`no issuer is found, and the identifier is the domain (${name})`, async () => {
    const company = await discover({ resource });
    assert.equal(company.oauthMetadata, undefined);
    assert.equal(companyIdentifier(company), "https://example.com");
  });
}

test("with an issuer the identifier is the issuer", async () => {
  const company = await discover({ resource: () => json(NAMES_ISSUER), issuer: () => json(ISSUER_METADATA) });
  assert.equal(companyIdentifier(company), "https://auth.example.com");
});

for (const [name, offers] of [
  ["auth.issuer", { auth: { issuer: "https://auth.example.com" } }],
  ["access", { agent: { protocols: [{ type: "poppy", endpoint: "https://example.com/p", access: "signed_in" }] } }],
  ["mediated", { extensions: { "mediated-sign-in": { version: "2" } } }],
]) {
  test(`no issuer is refused for a company that offers sign-in (${name})`, async () => {
    await assert.rejects(discover({ resource: notFound, document: { ...SIGNED_OUT, ...offers } }), code("issuer_not_found"));
  });
}

test("an ordinary extension needs no issuer", async () => {
  const document = { ...SIGNED_OUT, extensions: { "example.com/gift-wrap": { version: "1" } } };
  assert.equal(companyIdentifier(await discover({ resource: notFound, document })), "https://example.com");
});

for (const status of [401, 403, 500, 503]) {
  test(`a ${status} is never the domain fallback`, async () => {
    await assert.rejects(
      discover({ resource: () => new Response(null, { status }) }),
      (error) => error instanceof DiscoveryError && error.code === "http_error",
    );
  });
}

test("a timeout and a failed request are never the domain fallback", async () => {
  await assert.rejects(discover({ resource: () => new Promise(() => {}) }, { timeoutMs: 20 }), code("metadata_timeout"));
  await assert.rejects(
    discover({
      resource: () => {
        throw new TypeError("fetch failed");
      },
    }),
    code("request_failed"),
  );
});

for (const [name, resource, wanted] of [
  ["no resource", () => json({ authorization_servers: [] }), "invalid_resource_metadata"],
  ["null servers", () => json({ resource: "https://example.com", authorization_servers: null }), "invalid_resource_metadata"],
  ["another resource", () => json({ resource: "https://other.example" }), "resource_mismatch"],
  ["not JSON", () => new Response("no", { headers: { "content-type": "text/plain" } }), "invalid_content_type"],
]) {
  test(`invalid metadata is never the domain fallback (${name})`, async () => {
    await assert.rejects(
      discover({ resource }),
      (error) => (error instanceof DiscoveryError || error instanceof ProtocolValidationError) && error.code === wanted,
    );
  });
}

for (const [name, issuer, wanted] of [
  ["unpublished", notFound, "http_error"],
  ["another issuer", () => json({ ...ISSUER_METADATA, issuer: "https://x.example" }), "issuer_mismatch"],
  ["domain not listed", () => json({ ...ISSUER_METADATA, protected_resources: ["https://x.example"] }), "domain_not_authorized"],
]) {
  test(`an issuer that fails to verify is never the domain fallback (${name})`, async () => {
    await assert.rejects(discover({ resource: () => json(NAMES_ISSUER), issuer }), code(wanted));
  });
}

test("sign-in is refused locally", async () => {
  const company = await discover({ resource: notFound });
  assert.throws(
    () => requireOauth(company),
    (error) => error instanceof AuthorizationError && error.code === "no_issuer" && error.message.includes("no sign-in"),
  );
});

const config = (changes = {}) =>
  new CompanyConfig({
    name: "Shop",
    domain: "Shop.Example",
    scopes: ["orders:read"],
    scopeDescriptions: { "orders:read": "See your orders" },
    oauth: false,
    operations: false,
    ...changes,
  });

for (const [name, offers] of [
  ["mediated", { mediatedFields: [["email", "Email", false]] }],
  ["operations", { operations: true, writeScopes: ["orders:read"] }],
  ["aliases", { aliases: ["other.example"] }],
  ["dpop", { dpopBinding: "optional" }],
]) {
  test(`a company with no issuer refuses what needs one (${name})`, () => {
    assert.throws(() => config(offers), /no issuer/);
  });
}

test("the company's identifier is its lowercase domain", () => {
  assert.equal(config().identifier, "https://shop.example");
  assert.equal(config({ oauth: true, operations: true, writeScopes: ["orders:read"] }).identifier, "https://Shop.Example");
});
