/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Run the shared journey as the TypeScript personal agent against a company served by
// Python over TLS.
//
//   node run-agent.mjs config.json
//
// config.json: {"port": N, "ca": path, "agent_key": path to the agent's private JWK}.
// The user's actions at the company are asked of the Python side, one JSON line each:
// {"ask": "approve_authorization", "request_id", "account_id"} → {"callback"} and
// {"ask": "performed", "action"} → {"performed"}. Ends with {"done": result} (exit 0)
// or {"failed": message} (exit 1).
import { readFileSync } from "node:fs";

import { runJourney, scenario } from "./journey.mjs";
import { channel } from "./lines.mjs";
import { agentHost, agentIdentity, systemClock, tlsFetch } from "./world.mjs";

const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
const lines = channel();
try {
  const identity = await agentIdentity({
    domain: scenario.agent.domain,
    name: scenario.agent.name,
    privateJwk: JSON.parse(readFileSync(config.agent_key, "utf8")),
  });
  const fetch = tlsFetch({ port: config.port, ca: readFileSync(config.ca) });
  const host = await agentHost({ identity, fetch, clock: systemClock });
  const result = await runJourney({
    reactor: host.reactor,
    fetch,
    browser: host.browser,
    identity,
    company: {
      async approveAuthorization(requestId, accountId) {
        const answer = await lines.ask({ ask: "approve_authorization", request_id: requestId, account_id: accountId });
        return answer.callback;
      },
      async performed(action) {
        return (await lines.ask({ ask: "performed", action })).performed;
      },
    },
  });
  lines.send({ done: result });
  lines.close();
  process.exit(0);
} catch (error) {
  lines.send({ failed: String(error?.stack ?? error) });
  lines.close();
  process.exit(1);
}
