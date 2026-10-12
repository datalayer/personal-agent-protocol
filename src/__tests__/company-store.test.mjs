// The company store contract: the conformance kit, and a company restarted over its store
// (the same cases as the Python `test_company_store.py`).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  AccountTokenClient,
  ConversationClient,
  DeviceSignInClient,
  DpopFetchClient,
  OperationsClient,
  SessionClient,
  TokenStores,
  approve,
  discoverCompany,
  firstContribution,
  operationsEndpoint,
  parseClientMetadata,
} from "../../lib/index.js";
import { MemoryCompanyStore, StoreConformanceError, checkStore } from "../../lib/server.js";
import { manzanita } from "../../lib/demo/manzanita.js";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const TENANT = "atlas-demo";
const PAIRWISE = "usr_ada_at_manzanita_000000";

test("the memory store keeps the contract", async () => {
  await checkStore(() => new MemoryCompanyStore());
});

/** A store whose `take` reads without deleting: two callers would both get it. */
class TakeTwice extends MemoryCompanyStore {
  async take(kind, key) {
    return (await this.get(kind, key))?.value;
  }
}

/** A store whose compare-and-set ignores the version. */
class BlindReplace extends MemoryCompanyStore {
  async replace(kind, key, _version, value, options) {
    if ((await this.get(kind, key)) === undefined) return false;
    await this.put(kind, key, value, options);
    return true;
  }
}

/** A store that hands back the very object it was given. */
class Shared extends MemoryCompanyStore {
  async put(kind, key, value, options) {
    await super.put(kind, key, value, options);
    this.last = value;
  }
  async get(kind, key) {
    const entry = await super.get(kind, key);
    return entry !== undefined && this.last !== undefined ? { ...entry, value: this.last } : entry;
  }
}

for (const [Store, broken] of [
  [TakeTwice, /take returned the record/],
  [BlindReplace, /replace/],
  [Shared, /copy/],
]) {
  test(`the kit names what a broken store breaks: ${Store.name}`, async () => {
    await assert.rejects(() => checkStore(() => new Store()), (error) => {
      assert.ok(error instanceof StoreConformanceError);
      assert.match(error.message, broken);
      return true;
    });
  });
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

test("a company restarted over its store continues every flow", async () => {
  const clock = new MutableClock();
  const store = new MemoryCompanyStore({ clock });
  const sites = {};
  const fetch = inProcessFetch(sites);
  const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
  sites["atlas.example"] = identity.documents;
  let shop;
  let plugin;
  const restart = () => {
    // Manzanita stops and starts again (or another replica answers) over its store.
    ({ service: shop, plugin } = manzanita({ fetch, clock, store }));
    sites["manzanita.example"] = shop;
  };
  restart();
  const host = await agentHost({ identity, fetch, clock });
  const transport = new DpopFetchClient({ reactor: host.reactor, fetch });
  const conversations = new ConversationClient({ reactor: host.reactor, transport });
  const company = await discoverCompany("manzanita.example", { reactor: host.reactor });
  const metadata = company.oauthMetadata;
  const who = { tenantId: TENANT, pairwiseUserId: PAIRWISE, issuer: metadata.issuer };
  const endpoint = company.document.agent.protocols[0].endpoint;
  const message = (text) => ({ id: conversations.generateMessageId(), sender: "human", text });
  const session = await new SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: identity.clientId, pairwiseUserId: PAIRWISE, issuer: metadata.issuer, tokenEndpoint: metadata.token_endpoint, tenantId: TENANT,
  });

  // Before: a conversation with events, and a Device Sign-In the user has not approved.
  let page = await conversations.start(endpoint, message("Where is my jacket order?"), { ...who, token: session, wait: 0 });
  const device = new DeviceSignInClient({ reactor: host.reactor, fetch });
  const started = await device.begin({
    deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
    tokenEndpoint: metadata.token_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    scopes: ["orders:read", "orders:write"],
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
    sessionId: session.sessionId,
  });
  clock.advance(started.pollInterval);
  assert.equal((await device.poll(started.reference)).status, "pending");

  restart();

  // The pending sign-in survived: approved and completed on the restarted company.
  await shop.approveDevice(started.userCode, { accountId: "acct_ada" });
  clock.advance(started.pollInterval);
  const done = await device.poll(started.reference);
  assert.equal(done.status, "complete");
  assert.equal(done.token.sessionId, session.sessionId);
  const reference = done.accountTokenReference;

  // The Account Token rotates before the next restart.
  const accounts = new AccountTokenClient({ reactor: host.reactor, fetch });
  const context = {
    tokenEndpoint: metadata.token_endpoint,
    revocationEndpoint: metadata.revocation_endpoint,
    issuer: metadata.issuer,
    clientId: identity.clientId,
    tenantId: TENANT,
    pairwiseUserId: PAIRWISE,
  };
  const tokens = firstContribution(host.reactor, TokenStores, "token store");
  const before = await tokens.get(reference);
  const refreshed = await accounts.refresh(reference, { context, sessionId: session.sessionId });
  assert.equal(refreshed.status, "signed_in");
  assert.equal(refreshed.rotated, true);
  const rotated = await tokens.get(reference);
  assert.notEqual(rotated.reveal(), before.reveal());

  // The conversation continues from its cursor; the company proposes an operation.
  page = await conversations.send(endpoint, page.conversation_id, message("Exchange it for something warmer"), {
    ...who, token: refreshed.token, cursor: page.cursor, wait: 0,
  });
  const proposal = page.events.filter((e) => e.type !== "state").at(-1).message.operation;
  assert.equal(proposal.state, "proposed");
  const cursor = page.cursor;

  restart();

  // The rotated-away token stays refused after the restart; the new one works.
  const old = await store.get("account_token", sha256(before.reveal()));
  assert.equal(old.value.revoked, true);
  await tokens.put(reference, before);
  assert.equal((await accounts.refresh(reference, { context, sessionId: session.sessionId })).status, "signed_out");
  await tokens.put(reference, rotated);
  const again = await accounts.refresh(reference, { context, sessionId: session.sessionId });
  assert.equal(again.status, "signed_in");

  // The operation proposed before the restart is confirmed once after it.
  const operations = new OperationsClient({ reactor: host.reactor, transport });
  const target = operationsEndpoint(company.document, parseClientMetadata(identity.metadata));
  const outcome = await operations.confirm(target, proposal, { ...who, token: again.token, approval: await approve(proposal) });
  assert.equal(outcome.status, "confirmed");
  assert.equal(outcome.operation.state, "succeeded");
  const retried = await operations.confirm(target, proposal, { ...who, token: again.token, approval: await approve(proposal) });
  assert.equal(retried.operation.state, "succeeded");
  assert.deepEqual(plugin.executor.performed, [proposal.operation_id]);

  // The event cursor taken before the restart resumes after it: nothing is lost or repeated.
  const resumed = await conversations.readEvents(endpoint, page.conversation_id, { ...who, token: again.token, cursor });
  assert.ok(resumed.events.every((event) => event.id !== cursor));
  assert.equal(resumed.cursor, resumed.events.at(-1)?.id ?? cursor);
});
