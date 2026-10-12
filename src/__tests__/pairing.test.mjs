/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// TypeScript agent ↔ TypeScript company over real TCP and TLS (PAP §5 pairings).
// The Python pairings (Python agent ↔ TypeScript company, TypeScript agent ↔ Python
// company) live in personal_agent_protocol/__tests__/test_pairings.py and run the same
// scenario, protocol/scenarios/user-with-a-company.json.
import assert from "node:assert/strict";
import test from "node:test";

import { runJourney, scenario } from "./support/journey.mjs";
import { serveCompany } from "./support/tls-company.mjs";
import { agentHost, agentIdentity, certificates, systemClock, tlsFetch } from "./support/world.mjs";

test("the shared journey: TypeScript agent ↔ TypeScript company over TLS", async () => {
  const identity = await agentIdentity({ domain: scenario.agent.domain, name: scenario.agent.name });
  const tls = certificates([scenario.company.domain, identity.domain]);
  const company = await serveCompany({ ...tls, agents: { [identity.domain]: identity.documents } });
  try {
    const fetch = tlsFetch({ port: company.port, ca: tls.ca, domains: company.domains });
    const host = await agentHost({ identity, fetch, clock: systemClock });
    const result = await runJourney({
      reactor: host.reactor,
      fetch,
      browser: host.browser,
      identity,
      company: {
        approveAuthorization: async (requestId, accountId) => company.service.approveAuthorization(requestId, { accountId }),
        performed: async () => [...company.plugin.executor.performed],
      },
    });
    assert.deepEqual(result.steps, scenario.steps.map((step) => step.step));
    assert.equal(result.operation.performed, 1);
    // A certificate from another CA is refused: the TLS is real.
    const other = certificates([scenario.company.domain]);
    const stranger = tlsFetch({ port: company.port, ca: other.ca });
    await assert.rejects(stranger("https://manzanita.example/.well-known/poppy.json"));
  } finally {
    await company.close();
  }
});
