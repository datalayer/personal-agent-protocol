/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Atlas, a personal agent, and Manzanita Outfitters, the reference company, in one process:
// the world the tests of version 0.4 as published and of Operations version 3 share.
import assert from "node:assert/strict";

import {
  ApiClient,
  ConversationClient,
  DeviceSignInClient,
  RefreshTokenClient,
  SessionClient,
  SessionFetchClient,
  discoverCompany,
  negotiateExtensions,
} from "../../../lib/index.js";
import { manzanita } from "../../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./world.mjs";

export const TENANT = "atlas-demo";
export const PAIRWISE = "usr_ada_at_manzanita_000000";
export const SHOP = "https://manzanita.example";

/** Atlas and Manzanita; `config` changes Manzanita's configuration, `plugins` adds to it. */
export async function shopWorld({ config, plugins, extensions } = {}) {
  const clock = new MutableClock();
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas", ...(extensions ? { extensions } : {}) });
  sites["atlas.example"] = identity.documents;
  const { service: shop, plugin } = manzanita({ fetch, clock, ...(config ? { config } : {}), ...(plugins ? { plugins } : {}) });
  sites["manzanita.example"] = shop;
  const host = await agentHost({ identity, fetch, clock });
  const reactor = host.reactor;
  const transport = new SessionFetchClient({ reactor, fetch });
  const company = await discoverCompany("manzanita.example", { reactor });
  const metadata = company.oauthMetadata;
  const sessions = new SessionClient({ reactor, fetch });
  const conversations = new ConversationClient({ reactor, transport });
  const start = (pairwiseUserId = PAIRWISE) =>
    sessions.start({
      clientId: identity.clientId,
      pairwiseUserId,
      issuer: metadata.issuer,
      tenantId: TENANT,
      extensions: negotiateExtensions(company.document.extensions, identity.supportedExtensions),
    });
  return {
    clock,
    sites,
    fetch,
    identity,
    shop,
    plugin,
    host,
    reactor,
    transport,
    company,
    metadata,
    start,
    conversations,
    endpoint: company.document.agent.protocols[0].endpoint,
    message: (text, type = "human") => ({ id: conversations.generateRequestId(), author: { type }, text }),
    api: new ApiClient({ transport }),
    accounts: new RefreshTokenClient({ reactor, fetch }),
    context: {
      tokenEndpoint: metadata.token_endpoint,
      revocationEndpoint: metadata.revocation_endpoint,
      issuer: metadata.issuer,
      clientId: identity.clientId,
      tenantId: TENANT,
    },
  };
}

/** A Session signed in by Device Sign-In with Ada approving: the Session, its token, its reference. */
export async function signedIn(w, scopes = ["orders:read", "orders:write"]) {
  const session = await w.start();
  const device = new DeviceSignInClient({ reactor: w.reactor, fetch: w.fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: w.metadata.device_authorization_endpoint,
    tokenEndpoint: w.metadata.token_endpoint,
    issuer: w.metadata.issuer,
    clientId: w.identity.clientId,
    scopes,
    tenantId: TENANT,
    organization: w.company.document.organization,
  });
  await w.shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  w.clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  return { session, token: done.token, reference: done.refreshTokenReference };
}

/** A transport whose requests `handler(url, init)` answers, with the world's own Reactor. */
export const mockTransport = (w, handler) =>
  new SessionFetchClient({ reactor: w.reactor, fetch: async (input, init = {}) => handler(new URL(String(input)), init) });

/** Counts the requests a transport sends: method, URL, and whether a token went with it. */
export function counting(transport) {
  const sent = [];
  const inner = transport.request.bind(transport);
  transport.request = async (method, url, options) => {
    sent.push([method, url, options.token !== undefined]);
    return inner(method, url, options);
  };
  return sent;
}

/** The error a promise rejects with. */
export async function rejection(promise) {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  return assert.fail("expected a rejection");
}
