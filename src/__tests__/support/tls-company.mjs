/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The TypeScript Manzanita on node:https, answering for itself and for the personal
// agents' identity documents by Host, with a throwaway CA.
import { createServer } from "node:https";

import { byHost, companyRequestListener, jsonSite } from "../../../lib/server.js";
import { manzanita } from "../../../lib/demo/manzanita.js";
import { systemClock, tlsFetch } from "./world.mjs";

/**
 * Serve Manzanita at `manzanita.example`, and each agent's documents at its domain.
 * The company fetches agents' metadata and keys over the same TLS server. `config`
 * changes Manzanita's configuration (e.g. `{ web: false }`).
 */
export async function serveCompany({ cert, key, ca, agents = {}, clock = systemClock, config }) {
  const domains = ["manzanita.example", ...Object.keys(agents)];
  let port = 0;
  const fetch = (input, init) => tlsFetch({ port, ca, domains })(input, init);
  const { service, plugin } = manzanita({ fetch, clock, ...(config === undefined ? {} : { config }) });
  const sites = { "manzanita.example": companyRequestListener(service) };
  for (const [domain, documents] of Object.entries(agents)) sites[domain] = jsonSite(documents);
  const server = createServer({ cert, key }, byHost(sites));
  // Longer than any Retry-After a client waits out: a connection dropped as it is
  // reused loses a POST the client can't resend.
  server.keepAliveTimeout = 60_000;
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  port = server.address().port;
  return {
    port,
    service,
    plugin,
    domains,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
