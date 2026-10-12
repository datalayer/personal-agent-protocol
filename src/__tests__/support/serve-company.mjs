/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Serve the TypeScript Manzanita over TLS for a Python personal agent.
//
//   node serve-company.mjs config.json
//
// config.json: {"cert": path, "key": path, "ca": path, "agents": {domain: {path: document}}}.
// Prints {"ready": {"port": N}}, then answers the user's actions at the company, one JSON
// line each: {"op": "approve_authorization", "request_id", "account_id"} → {"callback"},
// {"op": "approve_device", "user_code", "account_id"} → {"granted"},
// {"op": "performed", "action"} → {"performed"}, {"op": "close"} → exit.
// For the conformance runner (the driver of a demo company): config "clock" (an ISO
// instant) gives the company a clock the test moves with {"op": "advance", "seconds"};
// {"op": "approve_device", ..., "scopes"}, {"op": "revise", "operation_id"},
// {"op": "forget_events", "conversation_id"}, {"op": "disconnect", "client_id",
// "account_id"} → {"ok": ...}, and {"op": "performed", "operation_id"} → {"count"}.
import { readFileSync } from "node:fs";

import { channel } from "./lines.mjs";
import { serveCompany } from "./tls-company.mjs";

const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
let now = config.clock === undefined ? undefined : Date.parse(config.clock);
const clock = now === undefined ? undefined : { now: () => new Date(now) };
const company = await serveCompany({
  cert: readFileSync(config.cert),
  key: readFileSync(config.key),
  ca: readFileSync(config.ca),
  agents: config.agents ?? {},
  ...(clock === undefined ? {} : { clock }),
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
      lines.send({ callback: await company.service.approveAuthorization(command.request_id, { accountId: command.account_id }) });
    } else if (command.op === "approve_device") {
      const scopes = command.scopes ?? undefined;
      lines.send({
        granted: await company.service.approveDevice(command.user_code, {
          accountId: command.account_id,
          ...(scopes ? { scopes } : {}),
        }),
      });
    } else if (command.op === "performed" && command.operation_id !== undefined) {
      const count = Object.values(executors)
        .map((executor) => executor.performed.filter((id) => id === command.operation_id).length)
        .reduce((a, b) => a + b, 0);
      lines.send({ count });
    } else if (command.op === "performed") {
      lines.send({ performed: [...(executors[command.action]?.performed ?? [])] });
    } else if (command.op === "advance") {
      if (now === undefined) throw new Error("the company runs on the system clock");
      now += command.seconds * 1000;
      lines.send({ ok: new Date(now).toISOString() });
    } else if (command.op === "revise") {
      const current = (await company.service.operationRecord(command.operation_id)).operation;
      await company.service.revise(command.operation_id, {
        summary: `${current.summary} Ships in 5 days instead of 2.`,
        terms: { ...(current.terms ?? {}), ships_in_days: 5 },
      });
      lines.send({ ok: true });
    } else if (command.op === "forget_events") {
      await company.service.forgetEvents(command.conversation_id, { keep: 1 });
      lines.send({ ok: true });
    } else if (command.op === "disconnect") {
      lines.send({ ok: await company.service.disconnect(command.client_id, command.account_id) });
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
