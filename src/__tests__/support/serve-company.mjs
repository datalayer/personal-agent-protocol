// Serve the TypeScript Manzanita over TLS for a Python personal agent.
//
//   node serve-company.mjs config.json
//
// config.json: {"cert": path, "key": path, "ca": path, "agents": {domain: {path: document}}}.
// Prints {"ready": {"port": N}}, then answers the user's actions at the company, one JSON
// line each: {"op": "approve_authorization", "request_id", "account_id"} → {"callback"},
// {"op": "approve_device", "user_code", "account_id"} → {"granted"},
// {"op": "performed", "action"} → {"performed"}, {"op": "close"} → exit.
import { readFileSync } from "node:fs";

import { channel } from "./lines.mjs";
import { serveCompany } from "./tls-company.mjs";

const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
const company = await serveCompany({
  cert: readFileSync(config.cert),
  key: readFileSync(config.key),
  ca: readFileSync(config.ca),
  agents: config.agents ?? {},
});
const lines = channel();
lines.send({ ready: { port: company.port } });
const executors = {
  "orders.exchange": company.plugin.executor,
  "orders.gift_wrap": company.plugin.giftWrap,
  "orders.return": company.plugin.returns,
  "orders.repair": company.plugin.repairs,
};
while (true) {
  const command = await lines.receive();
  try {
    if (command.op === "approve_authorization") {
      lines.send({ callback: company.service.approveAuthorization(command.request_id, { accountId: command.account_id }) });
    } else if (command.op === "approve_device") {
      lines.send({ granted: company.service.approveDevice(command.user_code, { accountId: command.account_id }) });
    } else if (command.op === "performed") {
      lines.send({ performed: [...(executors[command.action]?.performed ?? [])] });
    } else if (command.op === "close") {
      await company.close();
      lines.close();
      process.exit(0);
    } else {
      lines.send({ error: `unknown op ${command.op}` });
    }
  } catch (error) {
    lines.send({ error: String(error?.message ?? error) });
  }
}
