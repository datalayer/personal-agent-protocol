/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The user-with-a-company journey, run by the TypeScript agent against any company:
// the steps and expectations come from protocol/scenarios/user-with-a-company.json,
// which the Python agent's journey reads too.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  ConversationClient,
  DirectSignInClient,
  DpopFetchClient,
  OperationsClient,
  SessionClient,
  approve,
  discoverCompany,
  operationsEndpoint,
  parseClientMetadata,
} from "../../../lib/index.js";

export const scenario = JSON.parse(
  readFileSync(new URL("../../../protocol/scenarios/user-with-a-company.json", import.meta.url), "utf8"),
);

/**
 * Run every step. `company` plays the user's side at the company, whatever process it
 * lives in: `approveAuthorization(requestId, accountId)` answers the callback URL, and
 * `performed(action)` the operation IDs its executor performed.
 */
export async function runJourney({ reactor, fetch, browser, identity, company, log = () => {} }) {
  const { agent } = scenario;
  const domain = scenario.company.domain;
  const transport = new DpopFetchClient({ reactor, fetch });
  const conversations = new ConversationClient({ reactor, transport });
  const seen = {};
  let discovered;
  let who;
  let session;
  let signedIn;
  let page;
  let proposal;
  const endpoint = () => discovered.document.agent.protocols[0].endpoint;
  const message = (text) => ({ id: conversations.generateMessageId(), author: { type: "human" }, text });

  for (const step of scenario.steps) {
    log(step.step);
    const expect = step.expect;
    if (step.step === "discover") {
      discovered = await discoverCompany(domain, { reactor });
      assert.equal(discovered.document.organization.name, expect.organization);
      assert.equal(Boolean(discovered.document.extensions?.operations), expect.operations);
      who = { tenantId: agent.tenant_id, issuer: discovered.oauthMetadata.issuer };
    } else if (step.step === "session") {
      session = await new SessionClient({ reactor, fetch }).start({
        clientId: identity.clientId,
        pairwiseUserId: agent.pairwise_user_id,
        issuer: who.issuer,
        tokenEndpoint: discovered.oauthMetadata.token_endpoint,
        tenantId: agent.tenant_id,
      });
      assert.equal(session.signedIn, expect.signed_in);
    } else if (step.step === "ask") {
      page = await conversations.start(endpoint(), message(step.text), { ...who, token: session, wait: 0 });
      assert.deepEqual(page.events.map((event) => event.type), expect.events);
      assert.equal(page.events.filter((e) => e.type !== "state").at(-1).error, expect.error);
      seen.authorization = page.events.filter((e) => e.type !== "state").at(-1).error;
    } else if (step.step === "sign_in") {
      assert.equal(step.method, "direct");
      const metadata = discovered.oauthMetadata;
      const client = new DirectSignInClient({ reactor, fetch });
      await client.begin({
        authorizationEndpoint: metadata.authorization_endpoint,
        tokenEndpoint: metadata.token_endpoint,
        issuer: metadata.issuer,
        clientId: identity.clientId,
        redirectUri: `https://${agent.domain}${agent.redirect_path}`,
        scopes: step.scopes,
        tenantId: agent.tenant_id,
        sessionKey: session.sessionKey,
      });
      const consent = browser.pages.at(-1);
      for (const text of expect.consent_page) assert.ok(consent.includes(text), `consent page names ${text}`);
      const callbackUrl = await company.approveAuthorization(browser.requestId, scenario.company.account_id);
      const result = await client.complete({ callbackUrl });
      signedIn = result.token;
      assert.equal(signedIn.signedIn, expect.signed_in);
      assert.equal(signedIn.sessionKey, session.sessionKey);
      assert.deepEqual([...result.grantedScopes], expect.granted);
    } else if (step.step === "api_read") {
      const response = await transport.request(step.method, `https://${domain}${step.path}`, {
        ...who,
        token: signedIn,
        headers: { Accept: "application/json" },
      });
      assert.equal(response.status, expect.status);
      assert.deepEqual(await response.json(), expect.body);
      seen.read = true;
    } else if (step.step === "continue") {
      page = await conversations.send(endpoint(), page.conversation_id, message(step.text), {
        ...who,
        token: signedIn,
        cursor: page.cursor,
        wait: 0,
      });
      proposal = page.events.filter((e) => e.type !== "state").at(-1).message.operation;
      assert.equal(proposal.state, expect.operation_state);
      assert.equal(proposal.user_approval_required, expect.user_approval_required);
    } else if (step.step === "confirm") {
      const operations = new OperationsClient({ reactor, transport });
      const target = operationsEndpoint(discovered.document, parseClientMetadata(identity.metadata));
      assert.ok(target, "both sides list Operations v1");
      let outcome;
      for (let time = 0; time < step.times; time += 1) {
        outcome = await operations.confirm(target, proposal, { ...who, token: signedIn, approval: await approve(proposal) });
        assert.equal(outcome.status, "confirmed");
        assert.equal(outcome.operation.state, expect.state);
        assert.equal(outcome.operation.confirmation.approved_by, step.approved_by);
      }
      assert.ok(outcome.operation.result.summary.startsWith(expect.summary_starts_with));
      const performed = await company.performed("orders.exchange");
      assert.equal(performed.length, expect.performed);
      assert.deepEqual(performed, [proposal.operation_id]);
      seen.operation = { operation_id: proposal.operation_id, state: outcome.operation.state, performed: performed.length };
    } else {
      throw new Error(`unknown step ${step.step}`);
    }
  }
  return { steps: scenario.steps.map((step) => step.step), ...seen };
}
