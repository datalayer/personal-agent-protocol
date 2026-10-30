/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DiscoveryTransports,
  DiscoveryError,
  ProtocolValidationError,
  UrlSafetyPolicies,
  accessTokenFromResponse,
  buildClientAssertionClaims,
  buildPapReactor,
  companyIssuer,
  companyResource,
  discoverCompany,
  generatePairwiseUserId,
  parseClientMetadata,
  parseConversationEventPage,
  parseDiscoveryDocument,
  parseJsonStrict,
  parseMessage,
  parseOperation,
  parseTokenResponse,
  resourceMetadata,
  serviceResource,
} from "../../lib/index.js";

const RESOURCE_METADATA = "/.well-known/oauth-protected-resource";

/** The company's documents by path: its poppy.json, its domain's resource metadata, its issuer's. */
const PRM = {
  resource: "https://example.com",
  authorization_servers: ["https://auth.example.com"],
};
const documentAt = (input, discovery, metadata) => {
  const url = new URL(input);
  if (url.pathname === RESOURCE_METADATA) return PRM;
  return url.hostname === "example.com" ? discovery : metadata;
};

const fixture = async (name) =>
  JSON.parse(
    await readFile(new URL(`../../protocol/fixtures/${name}`, import.meta.url), "utf8"),
  );

test("parses the shared discovery fixture and preserves extension fields", async () => {
  const document = parseDiscoveryDocument(await fixture("discovery-valid.json"));
  assert.equal(document.protocol_version, "0.3");
  assert.equal(document.apis[1].type, "mcp");
  assert.equal(document.auth.scopes.addresses, "See and change your saved shipping addresses");
  assert.deepEqual(document.auth.scope_hints["orders:write"], { changes: "irreversible", personal_data: true });
  assert.equal(document.excluded_tasks.url, "https://example.com/poppy/excluded-tasks.json");
  assert.equal(document.extensions.operations.version, "2");
});

const jsonResponse = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

/** example.com's poppy.json and resource metadata, auth.example.com's metadata; any changed. */
async function companySite({ prm, document } = {}) {
  const discovery = document ?? (await fixture("discovery-valid.json"));
  const metadata = await fixture("oauth-metadata-valid.json");
  const domain = prm ?? (await fixture("protected-resource-metadata-valid.json"));
  return async (input) => {
    const url = new URL(input);
    if (url.hostname === "example.com" && url.pathname === RESOURCE_METADATA) return jsonResponse(domain);
    if (url.hostname === "example.com") return jsonResponse(discovery);
    if (url.hostname === "auth.example.com") return jsonResponse(metadata);
    return jsonResponse({ error: "not_found" }, 404);
  };
}

test("discovers and authenticates a company", async () => {
  const company = await discoverCompany("example.com", { fetch: await companySite() });
  assert.equal(company.document.organization.name, "Example Company");
  assert.equal(company.oauthMetadata.token_endpoint, "https://auth.example.com/oauth/token");
  // The issuer is the one the domain's protected resource metadata names (§3.2).
  assert.equal(companyIssuer(company), "https://auth.example.com");
  assert.equal(company.resourceMetadata.resource, "https://example.com");
  assert.equal(companyResource(company), "https://example.com");
});

test("the issuer comes from the domain's protected resource metadata", async () => {
  // One authorization server is the issuer: poppy.json may leave `auth` out (§3.1, §3.2).
  const { auth: _auth, ...document } = await fixture("discovery-valid.json");
  const company = await discoverCompany("example.com", { fetch: await companySite({ document }) });
  assert.equal(company.document.auth, undefined);
  assert.equal(companyIssuer(company), "https://auth.example.com");
});

test("refuses protected resource metadata for another resource", async () => {
  // `resource` is exactly `https://{organization.domain}` (§3.2).
  for (const other of ["https://example.com/", "https://www.example.com", "https://example.com/api"]) {
    const prm = { resource: other, authorization_servers: ["https://auth.example.com"] };
    await assert.rejects(
      discoverCompany("example.com", { fetch: await companySite({ prm }) }),
      (error) => error instanceof DiscoveryError && error.code === "resource_mismatch",
    );
  }
});

test("several authorization servers need auth.issuer among them", async () => {
  const prm = {
    resource: "https://example.com",
    authorization_servers: ["https://staff.example.com", "https://auth.example.com"],
  };
  const named = await fixture("discovery-valid.json");
  const { auth: _auth, ...without } = named;
  await assert.rejects(
    discoverCompany("example.com", { fetch: await companySite({ prm, document: without }) }),
    (error) => error instanceof DiscoveryError && error.code === "issuer_not_named",
  );
  const company = await discoverCompany("example.com", { fetch: await companySite({ prm }) });
  assert.equal(companyIssuer(company), "https://auth.example.com");
  const unlisted = { ...named, auth: { ...named.auth, issuer: "https://login.example.com" } };
  await assert.rejects(
    discoverCompany("example.com", { fetch: await companySite({ prm, document: unlisted }) }),
    (error) => error instanceof DiscoveryError && error.code === "issuer_mismatch",
  );
});

test("one authorization server and another auth.issuer is refused", async () => {
  const named = await fixture("discovery-valid.json");
  const document = { ...named, auth: { ...named.auth, issuer: "https://login.example.com" } };
  await assert.rejects(
    discoverCompany("example.com", { fetch: await companySite({ document }) }),
    (error) => error instanceof DiscoveryError && error.code === "issuer_mismatch",
  );
});

test("a company that needs an issuer and publishes none is refused", async () => {
  // `auth.issuer` says it has one: a 404 can't make it a Company without (§3.2).
  const discovery = await fixture("discovery-valid.json");
  assert.ok(discovery.auth.issuer);
  const fetch = async (input) =>
    new URL(input).pathname === "/.well-known/poppy.json"
      ? jsonResponse(discovery)
      : jsonResponse({ error: "not_found" }, 404);
  await assert.rejects(
    discoverCompany("example.com", { fetch }),
    (error) => error instanceof DiscoveryError && error.code === "issuer_not_found",
  );
});

test("refuses a private discovery address", async () => {
  let calls = 0;
  const fetch = async () => {
    calls += 1;
    return new Response(null, { status: 500 });
  };
  for (const domain of ["127.0.0.1", "localhost", "shop.internal"]) {
    await assert.rejects(
      discoverCompany(domain, { fetch }),
      (error) => error instanceof DiscoveryError && error.code === "unsafe_address",
    );
  }
  assert.equal(calls, 0);
});

test("metadata fetches carry no cookie or credential", async () => {
  const site = await companySite();
  const seen = [];
  const fetch = (input, init) => {
    seen.push(init);
    return site(input, init);
  };
  await discoverCompany("example.com", { fetch });
  assert.equal(seen.length, 3);
  for (const init of seen) {
    assert.equal(init.credentials, "omit");
    assert.deepEqual(Object.keys(init.headers), ["Accept"]);
  }
});

/** A company for `serviceResource`, and a network that counts reads of the service's metadata. */
async function services(metadata) {
  const reads = [];
  const site = await companySite();
  const fetch = async (input, init) => {
    const url = String(input);
    if (url.startsWith("https://mcp.example.com/")) {
      reads.push(url);
      const body = metadata.current;
      return body === undefined
        ? jsonResponse({ error: "not_found" }, 404)
        : jsonResponse(body, 200, { "cache-control": "max-age=3600" });
    }
    return site(input, init);
  };
  const reactor = buildPapReactor({ fetch });
  return { company: await discoverCompany("example.com", { reactor }), reactor, reads };
}

const SERVICE = "https://mcp.example.com/mcp";
const SERVICE_METADATA = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp";

test("a service's resource is read from the RFC 9728 URL of its own URL", async () => {
  const metadata = { current: { resource: SERVICE, authorization_servers: ["https://auth.example.com"] } };
  const { company, reactor, reads } = await services(metadata);
  assert.equal(await serviceResource(company, SERVICE, { reactor }), SERVICE);
  assert.deepEqual(reads, [SERVICE_METADATA]);
  assert.equal((await resourceMetadata(SERVICE, { reactor })).resource, SERVICE);
  reactor.stop();
});

test("no metadata, or the domain's own: the default token works there", async () => {
  const metadata = { current: undefined };
  const { company, reactor } = await services(metadata);
  assert.equal(await serviceResource(company, SERVICE, { reactor }), undefined);
  assert.equal(await resourceMetadata(SERVICE, { reactor }), undefined);
  metadata.current = { resource: "https://example.com", authorization_servers: ["https://auth.example.com"] };
  assert.equal(await serviceResource(company, SERVICE, { reactor, fresh: true }), undefined);
  reactor.stop();
});

test("a service must name the Company's issuer", async () => {
  const metadata = { current: { resource: SERVICE, authorization_servers: ["https://attacker.example"] } };
  const { company, reactor } = await services(metadata);
  await assert.rejects(
    serviceResource(company, SERVICE, { reactor }),
    (error) => error instanceof DiscoveryError && error.code === "invalid_resource_metadata",
  );
  reactor.stop();
});

test("metadata stays cached until a service says it is stale, then is read fresh", async () => {
  const metadata = { current: { resource: SERVICE, authorization_servers: ["https://auth.example.com"] } };
  const { company, reactor, reads } = await services(metadata);
  await serviceResource(company, SERVICE, { reactor });
  const moved = "https://mcp.example.com/v2";
  metadata.current = { resource: moved, authorization_servers: ["https://auth.example.com"] };
  assert.equal(await serviceResource(company, SERVICE, { reactor }), SERVICE);
  assert.equal(reads.length, 1);
  assert.equal(await serviceResource(company, SERVICE, { reactor, fresh: true }), moved);
  assert.equal(reads.length, 2);
  // The fresh answer is what stays cached.
  assert.equal(await serviceResource(company, SERVICE, { reactor }), moved);
  assert.equal(reads.length, 2);
  reactor.stop();
});

test("malformed service metadata is refused", async () => {
  const { company, reactor } = await services({ current: { resource: 42 } });
  await assert.rejects(
    serviceResource(company, SERVICE, { reactor }),
    (error) => error instanceof ProtocolValidationError && error.code === "invalid_resource_metadata",
  );
  reactor.stop();
});

test("passes AbortSignal to discovery requests", async () => {
  const discovery = await fixture("discovery-valid.json");
  const metadata = await fixture("oauth-metadata-valid.json");
  const controller = new AbortController();
  const receivedSignals = [];
  const fetch = async (input, init) => {
    receivedSignals.push(init.signal);
    const body = documentAt(input, discovery, metadata);
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await discoverCompany("example.com", { fetch, signal: controller.signal });

  // Each request is given a signal of its own that follows the caller's
  // (combined with the SDK's deadline), not the caller's object itself.
  assert.equal(receivedSignals.length, 3);
  for (const signal of receivedSignals) {
    assert.ok(signal instanceof AbortSignal);
    assert.equal(signal.aborted, false);
  }

  // The caller aborting while a request is under way aborts that request.
  const stopping = new AbortController();
  let followed;
  const aborting = async (_input, init) => {
    stopping.abort(new Error("stop"));
    followed = init.signal.aborted;
    throw init.signal.reason ?? new Error("aborted");
  };
  await assert.rejects(discoverCompany("example.com", { fetch: aborting, signal: stopping.signal }));
  assert.equal(followed, true);
});

test("rejects an OAuth issuer that does not authorize the company domain", async () => {
  const discovery = await fixture("discovery-valid.json");
  const metadata = {
    ...(await fixture("oauth-metadata-valid.json")),
    protected_resources: ["https://attacker.example"],
  };
  const fetch = async (input) => {
    const body = documentAt(input, discovery, metadata);
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };

  await assert.rejects(
    discoverCompany("example.com", { fetch }),
    (error) => error instanceof DiscoveryError && error.code === "domain_not_authorized",
  );
});

test("a company lists whichever DPoP algorithms it accepts", async () => {
  // DPoP is the Company's choice (§4.5): nothing here says which, and a list isn't refused.
  const discovery = await fixture("discovery-valid.json");
  const metadata = { ...(await fixture("oauth-metadata-valid.json")), dpop_signing_alg_values_supported: ["PS256"] };
  const fetch = async (input) => jsonResponse(documentAt(input, discovery, metadata));
  const company = await discoverCompany("example.com", { fetch });
  assert.deepEqual(company.oauthMetadata.dpop_signing_alg_values_supported, ["PS256"]);
});

test("discovers through Reactor contributions", async () => {
  const discovery = await fixture("discovery-valid.json");
  const metadata = await fixture("oauth-metadata-valid.json");
  const plugin = {
    name: "pap-test",
    contributes: [
      {
        point: DiscoveryTransports,
        value: {
          fetch: async (input) => {
            const body = documentAt(input, discovery, metadata);
            return new Response(JSON.stringify(body), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          },
        },
      },
      {
        point: UrlSafetyPolicies,
        value: { assertSafe: () => undefined },
      },
    ],
  };
  const reactor = buildPapReactor({}, [plugin]);

  const company = await discoverCompany("example.com", { reactor });

  assert.equal(company.oauthMetadata.issuer, "https://auth.example.com");
});

test("rejects duplicate JSON members at every trust-boundary depth", async () => {
  assert.throws(
    () => parseJsonStrict('{"organization":{"name":"first","name":"second"}}'),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "duplicate_json_member",
  );
  assert.throws(
    () => parseJsonStrict('{"name":1,"n\\u0061me":2}'),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "duplicate_json_member",
  );

  const fetch = async () =>
    new Response(
      '{"protocol_version":"0.1","protocol_version":"0.3",' +
        '"organization":{"name":"Example","domain":"example.com"},' +
        '"auth":{"issuer":"https://auth.example.com"},' +
        '"apis":[{"type":"openapi","url":"https://example.com/openapi.json",' +
        '"description":"Example"}]}',
      { status: 200, headers: { "content-type": "application/json" } },
    );

  await assert.rejects(
    discoverCompany("example.com", { fetch }),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "duplicate_json_member",
  );
});

test("builds redacted PAP session primitives", async () => {
  const randomBytes = (length) => Uint8Array.from({ length }, (_, index) => index);
  const userId = generatePairwiseUserId(randomBytes);
  const claims = buildClientAssertionClaims({
    clientId: "https://agent.example/agent.json",
    issuer: "https://auth.example.com",
    now: new Date("2026-10-10T00:00:00Z"),
    randomBytes,
  });
  const token = accessTokenFromResponse(parseTokenResponse(await fixture("token-response-valid.json")));

  assert.equal(userId, "usr_AAECAwQFBgcICQoLDA0ODw");
  assert.equal(claims.exp - claims.iat, 60);
  assert.equal(claims.jti, "AAECAwQFBgcICQoLDA0ODw");
  const secret = (await fixture("token-response-valid.json")).access_token;
  assert.equal(token.accessToken.reveal(), secret);
  assert.equal(JSON.stringify(token).includes(secret), false);
});

test("parses shared client, conversation, and operation fixtures", async () => {
  const client = parseClientMetadata(await fixture("client-metadata-valid.json"));
  const operation = parseOperation(await fixture("operation-valid.json"));
  const page = parseConversationEventPage(
    await fixture("conversation-events-valid.json"),
  );

  assert.equal(client.extensions["example.org/preferences"].mode, "compact");
  assert.equal(operation.revision, "1791487200-k3Jd9Qx2mW8v");
  assert.equal("user_approval_required" in operation, false);
  assert.deepEqual(page.events[0].message.operation, operation);
  assert.equal(page.events[2].type, "example.org/future-event");
  assert.equal(page.events[2].future, true);
});

test("validates known conversation shapes while preserving future events", () => {
  assert.throws(
    () => parseMessage({ id: "msg_empty", author: { type: "agent" } }),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "invalid_message",
  );
  assert.throws(
    () =>
      parseConversationEventPage({
        conversation_id: "cnv_one",
        events: [
          {
            id: "evt_one",
            type: "state",
            created_at: "2026-10-10T17:03:00Z",
            status: "idle",
          },
        ],
        cursor: "evt_one",
        has_more: false,
        status: "idle",
        responder: "agent",
      }),
    (error) => error instanceof ProtocolValidationError && error.code === "invalid_event",
  );
});

test("requires client security URLs to stay on the client ID domain", () => {
  assert.throws(
    () =>
      parseClientMetadata({
        client_id: "https://agent.example/agent.json",
        client_name: "Example Agent",
        jwks_uri: "https://attacker.example/jwks.json",
        redirect_uris: [],
      }),
    (error) =>
      error instanceof ProtocolValidationError && error.code === "client_domain_mismatch",
  );
});
