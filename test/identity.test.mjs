import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  AgentIdentityClient,
  IdentityError,
  ProtocolValidationError,
} from "../lib/index.js";

const clientId = "https://agent.example/agent.json";
const fixture = async (name) =>
  JSON.parse(
    await readFile(new URL(`../protocol/fixtures/${name}`, import.meta.url), "utf8"),
  );

test("fetches and binds client metadata and public JWKS", async () => {
  const metadata = await fixture("client-metadata-valid.json");
  const jwks = await fixture("jwks-valid.json");
  const fetch = async (input) =>
    new Response(JSON.stringify(new URL(input).pathname === "/agent.json" ? metadata : jwks), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  const client = new AgentIdentityClient({ fetch });

  const resolved = await client.fetchMetadata(clientId);
  const keys = await client.fetchJwks(clientId);

  assert.equal(resolved.client_name, "Example Agent");
  assert.equal(keys.keys[0].kid, "agent-signing-2026-10");
  assert.equal(keys.keys[0].alg, "ES256");
});

test("does not follow client metadata redirects", async () => {
  const client = new AgentIdentityClient({
    fetch: async () =>
      new Response(null, { status: 302, headers: { location: "/moved.json" } }),
  });

  await assert.rejects(
    client.fetchMetadata(clientId),
    (error) => error instanceof IdentityError && error.code === "metadata_redirect",
  );
});

test("rejects a substituted client_id", async () => {
  const metadata = {
    ...(await fixture("client-metadata-valid.json")),
    client_id: "https://agent.example/another-agent.json",
  };
  const client = new AgentIdentityClient({
    fetch: async () =>
      new Response(JSON.stringify(metadata), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
  });

  await assert.rejects(
    client.fetchMetadata(clientId),
    (error) => error instanceof IdentityError && error.code === "client_id_mismatch",
  );
});

test("rejects private key material in JWKS", async () => {
  const metadata = await fixture("client-metadata-valid.json");
  const jwks = await fixture("jwks-valid.json");
  jwks.keys[0].d = "private-material";
  const client = new AgentIdentityClient({
    fetch: async (input) =>
      new Response(
        JSON.stringify(new URL(input).pathname === "/agent.json" ? metadata : jwks),
        { status: 200, headers: { "content-type": "application/json" } },
      ),
  });

  await assert.rejects(
    client.fetchJwks(clientId),
    (error) => error instanceof ProtocolValidationError && error.code === "invalid_jwks",
  );
});

test("rejects a cross-domain JWKS redirect", async () => {
  const metadata = await fixture("client-metadata-valid.json");
  const client = new AgentIdentityClient({
    fetch: async (input) => {
      if (new URL(input).pathname === "/agent.json") {
        return new Response(JSON.stringify(metadata), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(null, {
        status: 302,
        headers: { location: "https://keys.example/jwks.json" },
      });
    },
  });

  await assert.rejects(
    client.fetchJwks(clientId),
    (error) => error instanceof IdentityError && error.code === "jwks_domain_mismatch",
  );
});

test("passes AbortSignal to every identity request", async () => {
  const metadata = await fixture("client-metadata-valid.json");
  const controller = new AbortController();
  let receivedSignal;
  const client = new AgentIdentityClient({
    fetch: async (_input, init) => {
      receivedSignal = init.signal;
      return new Response(JSON.stringify(metadata), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  await client.fetchMetadata(clientId, { signal: controller.signal });

  assert.equal(receivedSignal, controller.signal);
});
