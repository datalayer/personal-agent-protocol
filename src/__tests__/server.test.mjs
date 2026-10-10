import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { DiscoveryError } from "../../lib/index.js";
import { NodeUrlSafetyPolicy, isPublicIpAddress } from "../../lib/server.js";

test("classifies public and non-public IP address ranges", () => {
  assert.equal(isPublicIpAddress("93.184.216.34"), true);
  assert.equal(isPublicIpAddress("2606:2800:220:1:248:1893:25c8:1946"), true);
  for (const address of [
    "127.0.0.1",
    "10.0.0.1",
    "169.254.169.254",
    "192.168.1.1",
    "198.51.100.1",
    "::1",
    "fc00::1",
    "fe80::1",
    "2001:db8::1",
  ]) {
    assert.equal(isPublicIpAddress(address), false, address);
  }
});

test("accepts a hostname only when every resolved address is public", async () => {
  const safe = new NodeUrlSafetyPolicy({
    resolver: async () => ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
  });
  await safe.assertSafe(new URL("https://agent.example/agent.json"));

  const rebinding = new NodeUrlSafetyPolicy({
    resolver: async () => ["93.184.216.34", "127.0.0.1"],
  });
  await assert.rejects(
    rebinding.assertSafe(new URL("https://agent.example/agent.json")),
    (error) => error instanceof DiscoveryError && error.code === "unsafe_address",
  );
});

test("rejects private literals before DNS and permits explicit private deployments", async () => {
  let resolutions = 0;
  const policy = new NodeUrlSafetyPolicy({
    resolver: async () => {
      resolutions += 1;
      return ["93.184.216.34"];
    },
  });
  await assert.rejects(
    policy.assertSafe(new URL("https://127.0.0.1/agent.json")),
    (error) => error instanceof DiscoveryError && error.code === "unsafe_address",
  );
  assert.equal(resolutions, 0);

  const privatePolicy = new NodeUrlSafetyPolicy({ allowPrivateNetworks: true });
  await privatePolicy.assertSafe(new URL("https://127.0.0.1/agent.json"));
});

test("keeps server security APIs out of the portable entry bundle", async () => {
  const bundle = await readFile(new URL("../../lib/index.js", import.meta.url), "utf8");
  assert.equal(bundle.includes("node:dns"), false);
  assert.equal(bundle.includes("NodeUrlSafetyPolicy"), false);
  assert.equal(bundle.includes("JoseSigner"), false);
  assert.equal(bundle.includes("verifyDpopProof"), false);
  assert.equal(bundle.includes("verifyBrowserAssertion"), false);
});
