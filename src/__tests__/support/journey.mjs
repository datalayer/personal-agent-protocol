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
  agentInstruction,
  SessionClient,
  SessionFetchClient,
  discoverCompany,
  operationsNegotiated,
  parseClientMetadata,
  messageOperation,
  operationsContent,
} from "../../../lib/index.js";

export const scenario = JSON.parse(
  readFileSync(new URL("../../../protocol/scenarios/user-with-a-company.json", import.meta.url), "utf8"),
);

/**
 * The journey's one instruction, as the user gave it to the agent, with the host's own check of
 * a revision's terms against it: the amount at `amount_path`, in `currency`, is at most
 * `limit`. Anything it can't read is `null`: the user is asked.
 */
export function scriptedInstruction(spec) {
  const at = (terms, path) => {
    let value = terms;
    for (const key of path.split(".")) {
      if (typeof value !== "object" || value === null || Array.isArray(value) || !Object.hasOwn(value, key)) return undefined;
      value = value[key];
    }
    return value;
  };
  const decimal = (text) => (/^\d+(\.\d+)?$/.test(text) ? Number(text) : undefined);
  return agentInstruction(spec.text, (operation) => {
    const amount = at(operation.terms, spec.amount_path);
    const currency = at(operation.terms, spec.currency_path);
    if (typeof amount !== "string" || typeof currency !== "string") return null;
    const [value, limit] = [decimal(amount), decimal(spec.limit)];
    if (value === undefined || limit === undefined) return null;
    return currency === spec.currency && value <= limit;
  });
}

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
  const message = (text) => ({ id: conversations.generateRequestId(), author: { type: "human" }, text });

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
        company: discovered,
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
      proposal = messageOperation(page.events.filter((e) => e.type !== "state").at(-1).message);
      assert.equal(proposal !== undefined, expect.operation);
    } else if (step.step === "approve") {
      assert.ok(operationsNegotiated(discovered.document, session), "the company lists Operations version 3 and the Session declares it");
      const approval = await new OperationsClient({ reactor }).askUser(proposal, {
        organization: discovered.document.organization,
        tenantId: agent.tenant_id,
      });
      let told;
      for (let time = 0; time < step.times; time += 1) {
        const answer = await conversations.send(
          endpoint(),
          page.conversation_id,
          { id: conversations.generateRequestId(), author: { type: "agent" }, extensions: operationsContent({ approval }) },
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
    } else if (step.step === "agent_approve") {
      // The agent approves an operation itself, on the one instruction the user gave it: nobody
      // is asked, and the approval says `approver: agent` (Operations 5, 6).
      const api = new ApiClient({ transport });
      const url = `https://${domain}${step.path}`;
      const asked = await api.call(step.method, url, { session, token: signedIn, body: {} });
      const operation = asked.operation;
      assert.ok(operation !== undefined);
      assert.deepEqual(operation.terms, expect.terms);
      const surface = { asked: [], approve: async (request) => (surface.asked.push(request), true) };
      const client = new OperationsClient({ reactor });
      const approval = await client.approveAsAgent(operation, {
        instruction: scriptedInstruction(step.instruction),
        reference: client.newReference(),
      });
      assert.equal(approval.approver, expect.approver);
      assert.equal(approval.input_type, undefined);
      assert.equal(surface.asked.length > 0, expect.asked_user);
      const sent = await client.send(
        (given) => api.call(step.method, url, { session, token: signedIn, body: {}, approval: given }),
        approval,
      );
      assert.equal(sent.status, "answered");
      assert.equal(sent.answer.status, expect.status);
      seen.agent_approval = { approver: approval.approver };
    } else {
      throw new Error(`unknown step ${step.step}`);
    }
  }
  return { steps: scenario.steps.map((step) => step.step), ...seen };
}
