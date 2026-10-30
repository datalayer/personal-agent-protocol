/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Refresh tokens: refresh, rotation, narrowing, invalid_grant, revocation (§4.4, §4.6, §5.5).
import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationError,
  RefreshTokenClient,
  SecretValue,
  ServiceTokens,
  Signers,
  TokenStores,
  buildPapReactor,
  staleResourceMetadata,
} from "../../lib/index.js";

const context = {
  tokenEndpoint: "https://auth.shop.example/oauth/token",
  revocationEndpoint: "https://auth.shop.example/oauth/revoke",
  issuer: "https://auth.shop.example",
  clientId: "https://assistant.example/agent.json",
  tenantId: "tenant",
};

function arrange(company) {
  const tokens = new Map([["refresh_ref", new SecretValue("refresh-token-1")]]);
  const purposes = [];
  const fetch = async (url, init) => company(String(url), Object.fromEntries(new URLSearchParams(init.body)), init);
  const reactor = buildPapReactor({ fetch }, [
    {
      name: "@tests/pap-accounts",
      contributes: [
        {
          point: TokenStores,
          value: {
            async put(reference, token) { tokens.set(reference, token); },
            async get(reference) { return tokens.get(reference); },
            async delete(reference) { tokens.delete(reference); },
          },
          options: { id: "memory" },
        },
        {
          point: Signers,
          value: {
            async sign(_claims, options) {
              purposes.push(options.purpose);
              return new SecretValue(options.purpose);
            },
          },
          options: { id: "signer" },
        },
      ],
    },
  ]);
  return { client: new RefreshTokenClient({ reactor, fetch }), reactor, tokens, purposes };
}

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

const signedIn = (extra = {}) => ({
  access_token: "access-token",
  token_type: "Bearer",
  expires_in: 300,
  scope: "orders:read",
  ...extra,
});

test("refresh gets an access token and rotates the stored token", async () => {
  const seen = [];
  const { client, tokens, purposes } = arrange((_url, form, init) => {
    seen.push({ form, init });
    return json(200, signedIn({ refresh_token: "refresh-token-2" }));
  });
  const result = await client.refresh("refresh_ref", { context });
  assert.equal(result.status, "signed_in");
  assert.equal(result.rotated, true);
  assert.equal(result.token.accessToken.reveal(), "access-token");
  assert.ok(!JSON.stringify(result).includes("refresh-token-2"));
  assert.equal(tokens.get("refresh_ref").reveal(), "refresh-token-2");
  const { form, init } = seen[0];
  assert.equal(form.grant_type, "refresh_token");
  assert.equal(form.refresh_token, "refresh-token-1");
  assert.equal(form.client_assertion, "client_assertion");
  assert.deepEqual(purposes, ["client_assertion"]);
  // No Session is named: any of the User's Sessions uses the token (§4.4, §5.4).
  assert.equal("session_key" in form || "session_id" in form, false);
  assert.equal("scope" in form, false);
  const headers = Object.keys(init.headers).map((name) => name.toLowerCase());
  assert.ok(!headers.includes("poppy-session") && !headers.includes("dpop"));
});

test("a narrower refresh reports what was left out", async () => {
  const { client, tokens } = arrange((_url, form) => {
    assert.equal(form.scope, "orders:read orders:return");
    assert.equal(form.resource, "https://api.shop.example/");
    return json(200, signedIn());
  });
  const result = await client.refresh("refresh_ref", {
    context,
    scopes: ["orders:read", "orders:return"],
    resource: "https://api.shop.example/",
  });
  assert.deepEqual(result.missingScopes, ["orders:return"]);
  assert.equal(result.token.resource, "https://api.shop.example/");
  assert.equal(result.rotated, false);
  assert.equal(tokens.get("refresh_ref").reveal(), "refresh-token-1");
});

test("a response without scope granted exactly the narrower scopes asked for", async () => {
  const { access_token, token_type } = signedIn();
  const { client } = arrange(() => json(200, { access_token, token_type }));
  const result = await client.refresh("refresh_ref", { context, scopes: ["orders:read"] });
  assert.deepEqual(result.grantedScopes, ["orders:read"]);
  assert.deepEqual(result.missingScopes, []);
});

test("a wider scope is re-consent, not a retry", async () => {
  const { client, tokens } = arrange(() => json(400, { error: "invalid_scope" }));
  const result = await client.refresh("refresh_ref", { context, scopes: ["orders:write"] });
  assert.equal(result.status, "re_consent_required");
  assert.equal(tokens.has("refresh_ref"), true);
});

test("invalid_grant forgets the token and the Sessions go on signed out", async () => {
  const { client, tokens } = arrange(() => json(400, { error: "invalid_grant" }));
  const result = await client.refresh("refresh_ref", { context });
  // The stored copy is useless and goes; the Sessions continue signed out (§5.5).
  assert.equal(result.status, "signed_out");
  assert.equal(result.token, undefined);
  assert.equal(tokens.has("refresh_ref"), false);
});

test("a reference with no token is signed out without asking", async () => {
  let calls = 0;
  const { client } = arrange(() => {
    calls += 1;
    return new Response(null, { status: 500 });
  });
  assert.equal((await client.refresh("gone", { context })).status, "signed_out");
  assert.equal(calls, 0);
});

test("a scope the company was not asked for is refused", async () => {
  const { client } = arrange(() => json(200, signedIn({ scope: "orders:read orders:write" })));
  await assert.rejects(
    client.refresh("refresh_ref", { context, scopes: ["orders:read"] }),
    (error) => error instanceof AuthorizationError && error.code === "scope_escalation",
  );
});

test("a DPoP answer to a refresh is refused", async () => {
  const { client } = arrange(() => json(200, signedIn({ token_type: "DPoP" })));
  await assert.rejects(
    client.refresh("refresh_ref", { context }),
    (error) => error instanceof AuthorizationError && error.code === "unsupported_token_type",
  );
});

test("a token for an MCP server names it as the resource", async () => {
  const seen = [];
  const { client } = arrange((_url, form) => {
    seen.push(form);
    return json(200, signedIn());
  });
  const mcp = "https://mcp.shop.example/mcp";
  const result = await client.tokenForMcp("refresh_ref", { context, url: mcp });
  assert.equal(result.status, "signed_in");
  assert.equal(result.token.resource, mcp);
  // An OAuth refresh with `resource` (RFC 8707, §4.5): no Token Exchange.
  assert.equal(seen[0].grant_type, "refresh_token");
  assert.equal(seen[0].resource, mcp);
  assert.equal("subject_token" in seen[0], false);
});

test("a token refused with resource_metadata means the view is stale", () => {
  const details = { resource_metadata: "https://mcp.shop.example/prm" };
  assert.equal(staleResourceMetadata(new AuthorizationError("invalid_token", "refused", { details })), true);
  assert.equal(staleResourceMetadata(new AuthorizationError("invalid_token", "refused")), false);
  assert.equal(staleResourceMetadata(new AuthorizationError("insufficient_scope", "refused", { details })), false);
});

test("concurrent refreshes rotate one after the other", async () => {
  const used = [];
  const { client, tokens } = arrange(async (_url, form) => {
    used.push(form.refresh_token);
    await new Promise((resolve) => setTimeout(resolve, 1));
    const next = Number(form.refresh_token.split("-").pop()) + 1;
    return json(200, signedIn({ refresh_token: `refresh-token-${next}` }));
  });
  await Promise.all([client.refresh("refresh_ref", { context }), client.refresh("refresh_ref", { context })]);
  // Each refresh presented the token the previous one rotated in: never the same twice.
  assert.deepEqual(used, ["refresh-token-1", "refresh-token-2"]);
  assert.equal(tokens.get("refresh_ref").reveal(), "refresh-token-3");
});

test("revocation forgets the token once the company answers", async () => {
  const { client, tokens } = arrange((url, form, init) => {
    assert.equal(url, context.revocationEndpoint);
    assert.equal(form.token_type_hint, "refresh_token");
    assert.equal(form.client_assertion, "client_assertion");
    const headers = Object.keys(init.headers).map((name) => name.toLowerCase());
    assert.ok(!headers.includes("poppy-session") && !headers.includes("dpop"));
    return new Response(null, { status: 200 });
  });
  assert.deepEqual(await client.revoke("refresh_ref", { context }), { revoked: true, deletedLocally: true });
  assert.equal(tokens.has("refresh_ref"), false);
});

test("a refused revocation keeps the token for a retry", async () => {
  const { client, tokens } = arrange(() => json(503, { error: "temporarily_unavailable" }));
  await assert.rejects(client.revoke("refresh_ref", { context }), AuthorizationError);
  assert.equal(tokens.has("refresh_ref"), true);
});

test("sign-out revokes every refresh token held for the account", async () => {
  const revoked = [];
  const { client, tokens } = arrange((_url, form) => {
    revoked.push(form.token);
    return new Response(null, { status: 200 });
  });
  tokens.set("other_ref", new SecretValue("refresh-token-other"));
  const result = await client.signOut(["refresh_ref", "other_ref", "refresh_ref"], { context });
  assert.deepEqual(result, { revoked: 2, signedOut: true });
  assert.deepEqual(revoked, ["refresh-token-1", "refresh-token-other"]);
  assert.equal(tokens.size, 0);
});

test("sign-out stops at a refusal, and says the account isn't signed out", async () => {
  const answers = [() => new Response(null, { status: 200 }), () => json(503, { error: "temporarily_unavailable" })];
  const { client, tokens } = arrange(() => answers.shift()());
  tokens.set("other_ref", new SecretValue("refresh-token-other"));
  await assert.rejects(client.signOut(["refresh_ref", "other_ref"], { context }), AuthorizationError);
  // The one the company refused stays, so a retry can finish the job.
  assert.deepEqual([...tokens.keys()], ["other_ref"]);
});

test("no error carries the refresh token", async () => {
  const { client } = arrange(() => json(400, { error: "server_error", echo: "refresh-token-1" }));
  await assert.rejects(client.refresh("refresh_ref", { context }), (error) => {
    assert.ok(!String(error).includes("refresh-token-1"));
    assert.ok(!JSON.stringify({ ...error, details: error.details }).includes("refresh-token-1"));
    return true;
  });
});

const COMPANY = {
  discoveryUrl: "https://shop.example/.well-known/poppy.json",
  document: { organization: { name: "Shop", domain: "shop.example" } },
  resourceMetadata: { resource: "https://shop.example", authorization_servers: [context.issuer] },
  oauthMetadata: { issuer: context.issuer },
};
const MCP = "https://mcp.shop.example/mcp";
const MCP_METADATA = "https://mcp.shop.example/.well-known/oauth-protected-resource/mcp";

/** A refresh endpoint and the services' metadata, by URL; `metadata` a test can change. */
function arrangeServices(metadata) {
  const reads = [];
  const forms = [];
  const arranged = arrange((url, form) => {
    if (url === context.tokenEndpoint) {
      forms.push(form);
      return json(200, signedIn({ access_token: `access-${forms.length}` }));
    }
    reads.push(url);
    const body = metadata[url];
    return body === undefined
      ? json(404, { error: "not_found" })
      : json(200, body, { "cache-control": "max-age=3600" });
  });
  const tokens = new ServiceTokens({
    refresh: arranged.client,
    company: COMPANY,
    reference: "refresh_ref",
    context,
    discovery: { reactor: arranged.reactor },
  });
  return { ...arranged, reads, forms, service: tokens };
}

test("ServiceTokens: a service with its own resource gets a token only for it", async () => {
  const { service, forms } = arrangeServices({
    [MCP_METADATA]: { resource: MCP, authorization_servers: [context.issuer] },
  });
  const token = await service.tokenFor(MCP);
  assert.equal(token.resource, MCP);
  assert.equal(forms[0].resource, MCP);
  // The token is kept for that service, and another service gets the default one.
  assert.equal(await service.tokenFor(MCP), token);
  const fallback = await service.tokenFor("https://shop.example/api/orders");
  assert.equal(fallback.resource, undefined);
  assert.equal("resource" in forms[1], false);
  assert.equal(forms.length, 2);
  // One default token: a second service without metadata shares it.
  assert.equal(await service.tokenFor("https://shop.example/api/returns"), fallback);
  assert.equal(forms.length, 2);
});

test("ServiceTokens: the domain's own metadata doesn't make a service need its own token", async () => {
  const { service, forms } = arrangeServices({
    "https://shop.example/.well-known/oauth-protected-resource/api": COMPANY.resourceMetadata,
  });
  assert.equal((await service.tokenFor("https://shop.example/api")).resource, undefined);
  assert.equal("resource" in forms[0], false);
});

test("ServiceTokens: a service naming another authorization server is refused", async () => {
  const { service, forms } = arrangeServices({
    [MCP_METADATA]: { resource: MCP, authorization_servers: ["https://attacker.example"] },
  });
  await assert.rejects(service.tokenFor(MCP), (error) => error.code === "invalid_resource_metadata");
  assert.equal(forms.length, 0);
});

test("ServiceTokens: fresh reads the metadata again and asks for a new token", async () => {
  const metadata = { [MCP_METADATA]: { resource: MCP, authorization_servers: [context.issuer] } };
  const { service, reads, forms } = arrangeServices(metadata);
  const first = await service.tokenFor(MCP);
  await service.tokenFor(MCP);
  assert.equal(reads.length, 1);
  // The service moved to another resource, and said so with `invalid_token`.
  const moved = "https://mcp.shop.example/v2";
  metadata[MCP_METADATA] = { resource: moved, authorization_servers: [context.issuer] };
  assert.equal(await service.resourceFor(MCP), MCP); // cached until told otherwise
  const second = await service.tokenFor(MCP, { fresh: true });
  assert.equal(reads.length, 2);
  assert.equal(second.resource, moved);
  assert.notEqual(second, first);
  assert.equal(forms.at(-1).resource, moved);
});

test("ServiceTokens: signed out, every token held goes", async () => {
  const { service, tokens, forms } = arrangeServices({});
  assert.ok(await service.tokenFor("https://shop.example/api"));
  service.forget();
  tokens.delete("refresh_ref");
  assert.equal(await service.tokenFor("https://shop.example/api"), undefined);
  assert.equal(forms.length, 1);
});
