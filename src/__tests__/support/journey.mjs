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
  ApiClient,
  ConversationClient,
  DirectSignInClient,
  OperationsClient,
  SessionClient,
  SessionFetchClient,
  discoverCompany,
  operationsNegotiated,
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
  const transport = new SessionFetchClient({ reactor, fetch });
  const conversations = new ConversationClient({ reactor, transport });
  const seen = {};
  let discovered;
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
    } else if (step.step === "session") {
      session = await new SessionClient({ reactor, fetch }).start({
        clientId: identity.clientId,
        pairwiseUserId: agent.pairwise_user_id,
        issuer: discovered.oauthMetadata.issuer,
        tenantId: agent.tenant_id,
      });
      assert.equal(signedIn !== undefined, expect.signed_in);
    } else if (step.step === "ask") {
      page = await conversations.start(endpoint(), message(step.text), { session, wait: 0 });
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
      });
      const consent = browser.pages.at(-1);
      for (const text of expect.consent_page) assert.ok(consent.includes(text), `consent page names ${text}`);
      const callbackUrl = await company.approveAuthorization(browser.requestId, scenario.company.account_id);
      const result = await client.complete({ callbackUrl });
      signedIn = result.token;
      assert.equal(signedIn !== undefined, expect.signed_in);
      assert.deepEqual([...result.grantedScopes], expect.granted);
    } else if (step.step === "api_read") {
      const answer = await new ApiClient({ transport }).call(step.method, `https://${domain}${step.path}`, { session, token: signedIn });
      assert.equal(answer.status, expect.status);
      assert.deepEqual(answer.body, expect.body);
      seen.read = true;
    } else if (step.step === "continue") {
      page = await conversations.send(endpoint(), page.conversation_id, message(step.text), {
        session,
        token: signedIn,
        cursor: page.cursor,
        wait: 0,
      });
      proposal = page.events.filter((e) => e.type !== "state").at(-1).message.operation;
      assert.equal(proposal !== undefined, expect.operation);
    } else if (step.step === "approve") {
      assert.ok(operationsNegotiated(discovered.document, parseClientMetadata(identity.metadata)), "both sides list Operations v2");
      const approval = await new OperationsClient({ reactor }).askUser(proposal, {
        organization: discovered.document.organization,
        tenantId: agent.tenant_id,
      });
      let told;
      for (let time = 0; time < step.times; time += 1) {
        const answer = await conversations.send(
          endpoint(),
          page.conversation_id,
          { id: conversations.generateMessageId(), author: { type: "agent" }, approval },
          { session, token: signedIn, wait: 0 },
        );
        const said = answer.events.filter((event) => event.message?.role === "company").map((event) => event.message);
        told ??= said.at(-1);
      }
      assert.ok(told.text.startsWith(expect.summary_starts_with));
      const performed = await company.performed("orders.exchange");
      assert.equal(performed.length, expect.performed);
      assert.deepEqual(performed, [proposal.operation_id]);
      seen.operation = { operation_id: proposal.operation_id, performed: performed.length };
    } else {
      throw new Error(`unknown step ${step.step}`);
    }
  }
  return { steps: scenario.steps.map((step) => step.step), ...seen };
}
