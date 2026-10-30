/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  AuthorizationStateStores,
  Clocks,
  AuthorizationError,
  DeviceSignInClient,
  SecretValue,
  Signers,
  TokenStores,
  buildPapReactor,
  verificationHostAllowed,
} from "../../lib/index.js";

function devicePlugin() {
  const state = new Map();
  const tokens = new Map();
  let now = new Date("2026-10-10T00:00:00Z");
  const plugin = {
    name: "@tests/pap-device-sign-in",
    contributes: [
      {
        point: Clocks,
        value: { now: () => now },
        options: { id: "mutable" },
      },
      {
        point: AuthorizationStateStores,
        value: {
          async put(reference, value) {
            state.set(reference, value);
          },
          async take(reference) {
            const value = state.get(reference);
            state.delete(reference);
            return value;
          },
        },
        options: { id: "memory" },
      },
      {
        point: TokenStores,
        value: {
          async put(reference, token) {
            tokens.set(reference, token);
          },
          async get(reference) {
            return tokens.get(reference);
          },
          async delete(reference) {
            tokens.delete(reference);
          },
        },
        options: { id: "memory" },
      },
      {
        point: Signers,
        value: {
          async sign(_claims, { purpose }) {
            assert.equal(purpose, "client_assertion");
            return new SecretValue("client-assertion");
          },
        },
        options: { id: "signer" },
      },
    ],
  };
  return {
    plugin,
    tokens,
    state,
    advance(seconds) {
      now = new Date(now.getTime() + seconds * 1000);
    },
  };
}

const options = {
  deviceAuthorizationEndpoint: "https://auth.example.com/oauth/device",
  tokenEndpoint: "https://auth.example.com/oauth/token",
  issuer: "https://auth.example.com",
  clientId: "https://agent.example/agent.json",
  scopes: ["orders:read", "orders:write"],
  tenantId: "application-one",
  organization: { name: "Company", domain: "company.example" },
  protectedResources: ["https://company.example"],
};

test("Device Sign-In paces polling and keeps the refresh token behind a reference", async () => {
  const extension = devicePlugin();
  const forms = [];
  let calls = 0;
  const fetch = async (_input, init) => {
    calls += 1;
    const form = new URLSearchParams(init.body);
    forms.push(form);
    // OAuth endpoints get no Session header and no proof (§5.2).
    const headers = Object.keys(init.headers).map((name) => name.toLowerCase());
    assert.ok(!headers.includes("poppy-session") && !headers.includes("dpop"));
    assert.equal(form.get("client_assertion"), "client-assertion");
    if (calls === 1) {
      return Response.json({
        device_code: "private-device-code",
        user_code: "WDJB-MJHT",
        verification_uri: "https://company.example/device",
        verification_uri_complete: "https://company.example/device?user_code=WDJB-MJHT",
        expires_in: 600,
        interval: 5,
      });
    }
    if (calls === 2) {
      return Response.json({ error: "authorization_pending" }, { status: 400 });
    }
    if (calls === 3) return Response.json({ error: "slow_down" }, { status: 400 });
    return Response.json({
      access_token: "signed-in-access-token",
      token_type: "Bearer",
      expires_in: 300,
      scope: "orders:read",
      refresh_token: "private-refresh-token",
    });
  };
  const reactor = buildPapReactor({ fetch }, [extension.plugin]);
  const client = new DeviceSignInClient({ reactor, fetch });
  const started = await client.begin(options);
  assert.equal(started.userCode, "WDJB-MJHT");
  assert.deepEqual([started.organizationName, started.organizationDomain], ["Company", "company.example"]);
  assert.ok(!JSON.stringify(started).includes("private-device-code"));
  assert.equal(calls, 1);

  const early = await client.poll(started.reference);
  assert.equal(early.status, "pending");
  assert.equal(calls, 1);
  extension.advance(5);
  const pending = await client.poll(started.reference);
  assert.equal(pending.retryAt.toISOString(), "2026-10-10T00:00:10.000Z");
  extension.advance(5);
  const slowed = await client.poll(started.reference);
  assert.equal(slowed.retryAt.toISOString(), "2026-10-10T00:00:20.000Z");
  extension.advance(10);
  const complete = await client.poll(started.reference);
  reactor.stop();

  assert.equal(complete.status, "complete");
  assert.deepEqual(complete.grantedScopes, ["orders:read"]);
  assert.deepEqual(complete.missingScopes, ["orders:write"]);
  assert.equal(complete.token.accessToken.reveal(), "signed-in-access-token");
  assert.ok(!JSON.stringify(complete).includes("private-refresh-token"));
  assert.equal(extension.tokens.get(complete.refreshTokenReference).reveal(), "private-refresh-token");
  assert.equal(forms[0].get("scope"), "orders:read orders:write");
  assert.equal(forms.length, 4);
  assert.ok(forms.slice(1).every((form) => form.get("device_code") === "private-device-code"));
});

test("a denied Device Sign-In is terminal", async () => {
  const extension = devicePlugin();
  const fetch = async (input) =>
    String(input).endsWith("/device")
      ? Response.json({
          device_code: "private-device-code",
          user_code: "ABCD-EFGH",
          verification_uri: "https://company.example/device",
          expires_in: 60,
          interval: 1,
        })
      : Response.json({ error: "access_denied", error_description: "private detail" }, { status: 400 });
  const reactor = buildPapReactor({ fetch }, [extension.plugin]);
  const client = new DeviceSignInClient({ reactor, fetch });
  const started = await client.begin(options);
  extension.advance(1);
  await assert.rejects(client.poll(started.reference), (error) => {
    assert.ok(error instanceof AuthorizationError);
    assert.equal(error.code, "access_denied");
    assert.ok(!String(error).includes("private detail"));
    return true;
  });
  await assert.rejects(
    client.poll(started.reference),
    (error) => error instanceof AuthorizationError && error.code === "invalid_or_expired_device_session",
  );
  reactor.stop();
});

const LINKS = [
  ["https://company.example/device", true],
  ["https://login.company.example/device", true],
  ["https://auth.example.com/device", true],
  ["https://www.auth.example.com/device", true],
  ["https://COMPANY.example/device", true],
  ["https://other-company.example/device", false],
  ["https://company.example.evil.example/device", false],
  ["https://evilcompany.example/device", false],
];

for (const [link, allowed] of LINKS) {
  test(`a device link is shown only on the issuer or its domains: ${link} ${allowed ? "shown" : "refused"}`, async () => {
    // Its host is the issuer's, the host of a URL in protected_resources, or a subdomain of
    // either (§4.6).
    assert.equal(verificationHostAllowed(link, { issuer: options.issuer, protectedResources: options.protectedResources }), allowed);
    const extension = devicePlugin();
    const fetch = async () =>
      Response.json({
        device_code: "private-device-code",
        user_code: "WDJB-MJHT",
        verification_uri: link,
        expires_in: 600,
        interval: 5,
      });
    const reactor = buildPapReactor({ fetch }, [extension.plugin]);
    const begin = new DeviceSignInClient({ reactor, fetch }).begin(options);
    if (allowed) {
      const started = await begin;
      assert.deepEqual([started.organizationName, started.organizationDomain], ["Company", "company.example"]);
    } else {
      await assert.rejects(begin, (error) => error instanceof AuthorizationError && error.code === "unsafe_verification_uri");
      assert.equal(extension.state.size, 0); // nothing kept for a link never shown
    }
    reactor.stop();
  });
}

test("a device authorization answering with a redirect gets nothing", async () => {
  const extension = devicePlugin();
  const sent = [];
  const fetch = async (input) => {
    sent.push(String(input));
    return new Response(null, { status: 302, headers: { Location: "https://elsewhere.example/device" } });
  };
  const reactor = buildPapReactor({ fetch }, [extension.plugin]);
  await assert.rejects(
    new DeviceSignInClient({ reactor, fetch }).begin(options),
    (error) => error instanceof AuthorizationError && error.code === "redirect_refused" && error.statusCode === 302,
  );
  reactor.stop();
  assert.deepEqual(sent, ["https://auth.example.com/oauth/device"]);
});
