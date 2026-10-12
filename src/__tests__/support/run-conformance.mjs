// Run the conformance cases as the TypeScript personal agent against a company served by
// Python over TLS (TypeScript agent ↔ Python company).
//
//   node run-conformance.mjs config.json
//
// config.json: {"port", "ca", "base_url", "scenario", "accounts", "capabilities",
// "clock" (ISO), "agent": {"domain", "name", "key", "extensions"}, "other": {...}}.
// The user's and the demo operator's actions are asked of the Python side, one JSON line
// each ({"ask": "approve_device" | "wait" | "revise" | "forget_events" | "disconnect" |
// "performed", ...}). Ends with {"report": ...} (exit 0) or {"failed": message} (exit 1).
import { readFileSync } from "node:fs";

import { Context, identityFrom, runConformance } from "./conformance.mjs";
import { channel } from "./lines.mjs";
import { MutableClock, tlsFetch } from "./world.mjs";

const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
const lines = channel();

async function ask(message) {
  const answer = await lines.ask(message);
  if (answer.error) throw new Error(`the company side refused ${message.ask}: ${answer.error}`);
  return answer;
}

try {
  const identity = async (agent) =>
    identityFrom({
      domain: agent.domain,
      name: agent.name,
      extensions: agent.extensions,
      privateJwk: JSON.parse(readFileSync(agent.key, "utf8")),
    });
  const clock = new MutableClock(new Date(config.clock));
  const driver = {
    capabilities: new Set(config.capabilities),
    accounts: config.accounts,
    async approveDevice(userCode, { account, scopes }) {
      await ask({ ask: "approve_device", user_code: userCode, account, scopes: scopes ?? null });
    },
    async wait(seconds) {
      clock.advance(seconds);
      await ask({ ask: "wait", seconds });
    },
    async revise(operationId) {
      await ask({ ask: "revise", operation_id: operationId });
    },
    async forgetEvents(conversationId) {
      await ask({ ask: "forget_events", conversation_id: conversationId });
    },
    async disconnect(clientId, account) {
      await ask({ ask: "disconnect", client_id: clientId, account });
    },
    async performed(operationId) {
      return (await ask({ ask: "performed", operation_id: operationId })).count;
    },
  };
  const context = new Context({
    baseUrl: config.base_url,
    identity: await identity(config.agent),
    otherIdentity: await identity(config.other),
    fetch: tlsFetch({ port: config.port, ca: readFileSync(config.ca) }),
    // The agent's own browser: its own connections and cookie jar.
    browserFetch: tlsFetch({ port: config.port, ca: readFileSync(config.ca) }),
    driver,
    scenario: config.scenario,
    clock,
  });
  const report = await runConformance(context);
  lines.send({ report });
  lines.close();
  process.exit(0);
} catch (error) {
  lines.send({ failed: String(error?.stack ?? error) });
  lines.close();
  process.exit(1);
}
