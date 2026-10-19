/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The conformance cases as the TypeScript personal agent against the TypeScript company,
// over real TCP and TLS (TypeScript agent ↔ TypeScript company). The other pairings run
// from personal_agent_protocol/__tests__/test_cross_language.py.
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

import { exportJWK, generateKeyPair } from "jose";

import { Context, companyCases, identityFrom, runConformance } from "./support/conformance.mjs";
import { serveCompany } from "./support/tls-company.mjs";
import { MutableClock, certificates, tlsFetch } from "./support/world.mjs";

const scenario = JSON.parse(
  readFileSync(new URL("../../protocol/scenarios/manzanita-conformance.json", import.meta.url), "utf8"),
);

async function agent(domain, name, extensions) {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return identityFrom({ domain, name, extensions, privateJwk: await exportJWK(pair.privateKey) });
}

/** The cases this pairing does not pass yet, with why (kept exact: a fix shows here). */
const GAPS = {};

/** Run `cases` (every company case by default) against Manzanita, changed by `config`. */
async function runPairing({ config, cases } = {}) {
  const atlas = await agent("atlas.example", "Atlas", ["operations"]);
  const plain = await agent("plain.example", "Plain", []);
  const clock = new MutableClock();
  const tls = certificates(["manzanita.example", atlas.domain, plain.domain]);
  const documents = (identity) => ({ "/agent.json": identity.metadata, "/jwks.json": identity.jwks });
  const company = await serveCompany({
    ...tls,
    clock,
    ...(config === undefined ? {} : { config }),
    agents: { [atlas.domain]: documents(atlas), [plain.domain]: documents(plain) },
  });
  const executors = [company.plugin.executor, company.plugin.giftWrap, company.plugin.returns, company.plugin.repairs];
  try {
    const context = new Context({
      baseUrl: "https://manzanita.example",
      identity: atlas,
      otherIdentity: plain,
      fetch: tlsFetch({ port: company.port, ca: tls.ca, domains: company.domains }),
      // The agent's own browser: its own connections and cookie jar.
      browserFetch: tlsFetch({ port: company.port, ca: tls.ca, domains: company.domains }),
      scenario,
      clock,
      driver: {
        capabilities: new Set(["revise", "forget_events", "disconnect", "performed", "clock", "second_identity"]),
        accounts: ["acct_ada", "acct_ada_business"],
        async approveDevice(userCode, { account, scopes }) {
          await company.service.approveDevice(userCode, { accountId: account, ...(scopes ? { scopes } : {}) });
        },
        async wait(seconds) {
          clock.advance(seconds);
        },
        async revise(operationId) {
          const current = (await company.service.operationRecord(operationId)).operation;
          await company.service.revise(operationId, {
            summary: `${current.summary} Ships in 5 days instead of 2.`,
            terms: { ...(current.terms ?? {}), ships_in_days: 5 },
          });
        },
        async forgetEvents(conversationId) {
          await company.service.forgetEvents(conversationId, { keep: 1 });
        },
        async disconnect(clientId, account) {
          await company.service.disconnect(clientId, account);
        },
        async performed(operationId) {
          return executors.flatMap((executor) => executor.performed).filter((id) => id === operationId).length;
        },
      },
    });
    return await runConformance(context, cases === undefined ? {} : { cases });
  } finally {
    await company.close();
  }
}

test("the conformance cases: TypeScript agent ↔ TypeScript company over TLS", async () => {
  const report = await runPairing();
  // Kept for the compatibility report (scripts/conformance_report.py), when asked.
  const reports = process.env.PAP_CONFORMANCE_REPORTS;
  if (reports) {
    mkdirSync(reports, { recursive: true });
    writeFileSync(join(reports, "typescript-agent-typescript-company.json"), `${JSON.stringify(report, null, 2)}\n`);
  }
  const failed = Object.fromEntries(report.cases.filter((item) => item.outcome === "failed").map((item) => [item.id, item.message]));
  assert.deepEqual(Object.keys(failed), Object.keys(GAPS), JSON.stringify(failed));
  assert.deepEqual(report.summary, { passed: report.cases.length, failed: 0, skipped: 0 });
});

test("the MCP cases pass against an MCP server without DPoP: Bearer tokens (§4.3)", async () => {
  const mcp = companyCases().filter((item) => item.id.includes(".mcp-") || item.id === "operations.cross-channel-mcp");
  assert.ok(mcp.length >= 6);
  const report = await runPairing({ config: { mcpDpop: false }, cases: mcp });
  const failed = Object.fromEntries(report.cases.filter((item) => item.outcome === "failed").map((item) => [item.id, item.message]));
  assert.deepEqual(failed, {});
  assert.deepEqual(report.summary, { passed: mcp.length, failed: 0, skipped: 0 });
});
