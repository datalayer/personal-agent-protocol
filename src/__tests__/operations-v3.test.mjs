/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Operations version 3: who approved, agent approvals on the user's instruction, required
// terms, declined approvals, and no version 2 on either side.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  APPROVAL_DECLINED,
  APPROVAL_HEADER,
  APPROVERS,
  ApiClient,
  ApiError,
  ApprovalSurfaces,
  Clocks,
  McpClient,
  OPERATIONS_VERSION,
  OperationError,
  OperationsClient,
  PapSession,
  ProtocolValidationError,
  SUPPORTED_EXTENSIONS,
  SessionFetchClient,
  agentInstruction,
  approvalFromMeta,
  approvalHeader,
  buildPapReactor,
  declinedFrom,
  messageApproval,
  messageDeclined,
  messageOperation,
  newApprovalReference,
  operationShown,
  operationsContent,
  parseApproval,
  parseApprovalDeclined,
  parseApprovalHeader,
  parseMessage,
  parseOperation,
  parseOperationsContent,
  parseProtectedResourceMetadata,
  sessionHeaders,
  termsLeaves,
} from "../../lib/index.js";
import { CONFIG_OPTIONS, declineAgentReturns } from "../../lib/demo/manzanita.js";
import { CompanyApis, OperationExecutors } from "../../lib/server.js";
import { rejection, shopWorld, signedIn } from "./support/shop.mjs";

const fixtures = new URL("../../protocol/fixtures/", import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, fixtures), "utf8"));
const NOW = new Date("2026-10-10T12:00:00Z");
const SHOP = { name: "Shop", domain: "shop.example" };
const ORDERS = "https://manzanita.example/api/orders/ord_7Hk2";
const EXCHANGE = `${ORDERS}/exchanges`;
const GIFT_WRAP = `${ORDERS}/gift-wrap`;
const RETURNS = `${ORDERS}/returns`;
const MCP = "https://manzanita.example/mcp";

const wire = (changes = {}) => ({ ...fixture("operation-valid.json"), ...changes });
const returned = (changes = {}) => parseOperation(wire(changes));

/** The host's surface, answering each question in turn. */
class Surface {
  constructor(...answers) {
    this.answers = answers;
    this.asked = [];
  }
  async approve(request) {
    this.asked.push(request);
    return this.answers.shift();
  }
}

function clientFor(surface, options = {}) {
  const reactor = buildPapReactor({}, [
    {
      name: "@tests/pap-operations-v3",
      contributes: [
        { point: Clocks, value: { now: () => NOW }, options: { id: "fixed", order: 10 } },
        ...(surface === undefined ? [] : [{ point: ApprovalSurfaces, value: surface, options: { id: "the-user" } }]),
      ],
    },
  ]);
  return new OperationsClient({ reactor, ...options });
}

/** A request's answers, in order; an error is thrown. */
function script(...answers) {
  const request = async (approval) => {
    request.sent.push(approval);
    const next = answers.shift();
    if (next instanceof Error) throw next;
    return next;
  };
  request.sent = [];
  return request;
}

/**
 * "Go ahead with gift wrap up to USD 10": the user's instruction, and the host's own check of
 * a revision's terms against it. `null` when it can't tell.
 */
const UNDER_TEN = agentInstruction("Go ahead with gift wrap up to USD 10.", (operation) =>
  operation.terms.price === undefined
    ? null
    : operation.terms.price.currency === "USD" && Number(operation.terms.price.amount) <= 10,
);
const ANYTHING = agentInstruction("Do whatever this shop asks.", () => true);

test("the SDK implements version 3 and no other", () => {
  assert.equal(OPERATIONS_VERSION, "3");
  assert.equal(SUPPORTED_EXTENSIONS.operations, "3");
  assert.deepEqual([...APPROVERS], ["user", "agent"]);
});

// The approval: who approved ------------------------------------------------------------------

test("an approval names its approver and the header carries every member", () => {
  // `approver` is required; `Poppy-Approval` carries it with `approved_at`, `input_type` (a
  // user approval only) and `reference` (Operations 6).
  const byUser = parseApproval({
    operation_id: "exc_5Rt2",
    revision: "1791487200-k3Jd9Qx2mW8v",
    approver: "user",
    approved_at: 1791487260,
    input_type: "tap",
    reference: "apr_01JD8ZK3Q9",
  });
  assert.equal(
    approvalHeader(byUser),
    'operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v", approver="user", ' +
      'approved_at=1791487260, input_type="tap", reference="apr_01JD8ZK3Q9"',
  );
  assert.deepEqual(parseApprovalHeader(approvalHeader(byUser)), byUser);
  const byAgent = parseApproval({
    operation_id: "exc_5Rt2",
    revision: "1791487200-k3Jd9Qx2mW8v",
    approver: "agent",
    approved_at: 1791487255,
    reference: "apr_01JD8ZK3R4",
  });
  assert.equal(
    approvalHeader(byAgent),
    'operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v", approver="agent", ' +
      'approved_at=1791487255, reference="apr_01JD8ZK3R4"',
  );
  assert.deepEqual(parseApprovalHeader(approvalHeader(byAgent)), byAgent);
  assert.throws(() => parseApproval({ operation_id: "exc_5Rt2", revision: "r1" }), ProtocolValidationError);
  assert.throws(() => parseApproval({ operation_id: "exc_5Rt2", revision: "r1", approver: "rule" }), ProtocolValidationError);
});

test("an agent approval never carries an input type", () => {
  // Never sent with `agent`, and ignored by a company that receives one (Operations 6).
  const stated = parseApproval({ operation_id: "a", revision: "b", approver: "agent", input_type: "tap" });
  assert.equal(stated.input_type, undefined);
  // Nor from an approval a host built by hand.
  assert.ok(!approvalHeader({ operation_id: "a", revision: "b", approver: "agent", input_type: "tap" }).includes("input_type"));
  const received = parseApprovalHeader('operation_id="a", revision="b", approver="agent", input_type="tap"');
  assert.deepEqual(received, { operation_id: "a", revision: "b", approver: "agent" });
  const fromMeta = approvalFromMeta({
    "personalagentprotocol.org/approval": { operation_id: "a", revision: "b", approver: "agent", input_type: "voice" },
  });
  assert.deepEqual(fromMeta, { operation_id: "a", revision: "b", approver: "agent" });
});

for (const value of [
  // What version 2 sent: no approver. Not an approval in version 3.
  'operation_id="a", revision="b"',
  'operation_id="a", revision="b", approved_at=1791487260, input_type="tap"',
  'operation_id="a", revision="b", approver="rule"',
  'operation_id="a", revision="b", approver=user',
  'operation_id="a", revision="b", approver=1',
]) {
  test(`an approval without a valid approver is no approval: ${value}`, () => {
    assert.equal(parseApprovalHeader(value), undefined);
    assert.equal(approvalFromMeta({ "personalagentprotocol.org/approval": { operation_id: "a", revision: "b" } }), undefined);
  });
}

test("a malformed optional member is left out, never a reason to refuse", () => {
  const parsed = parseApprovalHeader(
    'operation_id="a", revision="b", approver="user", reference="not an id!", approved_at="soon", input_type=tap, later=1',
  );
  assert.deepEqual(parsed, { operation_id: "a", revision: "b", approver: "user" });
});

test("a reference is opaque, random and never the same twice", () => {
  // `reference` names the agent's own record: the IDs' characters, no personal data, and a new
  // one per approval, so two Companies never see the same (Operations 6).
  const references = new Set(Array.from({ length: 64 }, () => newApprovalReference()));
  assert.equal(references.size, 64);
  for (const reference of references) {
    assert.ok(reference.startsWith("apr_") && reference.length === 36);
    assert.equal(parseApproval({ operation_id: "a", revision: "b", approver: "user", reference }).reference, reference);
  }
  const fixed = newApprovalReference((length) => Uint8Array.from({ length }, (_, index) => index));
  assert.equal(fixed, "apr_000102030405060708090a0b0c0d0e0f");
  assert.match(clientFor().newReference(), /^apr_[0-9a-f]{32}$/);
});

test("extensions.operations carries an operation, an approval or a decline", () => {
  const declined = parseApprovalDeclined({ operation_id: "cls_2Wq8", revision: "r1", reason: "No." });
  const content = operationsContent({ declined });
  assert.deepEqual(content, { operations: { declined: { operation_id: "cls_2Wq8", revision: "r1", reason: "No." } } });
  const message = parseMessage({ author: { type: "agent" }, role: "company", text: "No.", extensions: content });
  assert.deepEqual(messageDeclined(message), declined);
  assert.equal(messageOperation(message), undefined);
  assert.equal(messageApproval(message), undefined);
  assert.throws(() => parseOperationsContent({ operation: wire(), declined }), ProtocolValidationError);
  assert.throws(() => parseOperationsContent({}), ProtocolValidationError);
  assert.throws(() => operationsContent({}), ProtocolValidationError);
});

test("a decline is read from each interface", () => {
  const members = {
    operation_id: "cls_2Wq8",
    revision: "1791487200-p9Lm3Rt6Vx1c",
    reason: "Only the account holder can close this account.",
    alternative: {
      instructions: "The account holder can close the account in the Example app.",
      references: [{ type: "web", url: "https://example.com/account/close" }],
    },
  };
  const api = declinedFrom({ error: APPROVAL_DECLINED, ...members });
  const tool = declinedFrom({ isError: true, structuredContent: { error: APPROVAL_DECLINED, ...members } });
  const message = declinedFrom({ extensions: { operations: { declined: members } } });
  assert.deepEqual(api, members);
  assert.deepEqual(tool, api);
  assert.deepEqual(message, api);
  assert.equal("error" in api, false);
  assert.equal(api.alternative.references[0].url, "https://example.com/account/close");
  assert.equal(declinedFrom({ error: "approval_required", ...members }), undefined);
  assert.equal(declinedFrom({ structuredContent: { operation: {} } }), undefined);
  assert.equal(declinedFrom(null), undefined);
  assert.throws(() => declinedFrom({ error: APPROVAL_DECLINED, reason: "names no operation" }), ProtocolValidationError);
  // The vendored schema says the same.
  const schema = JSON.parse(readFileSync(new URL("../../protocol/schemas/approval-declined.schema.json", import.meta.url), "utf8"));
  assert.deepEqual(schema.required, ["operation_id", "revision"]);
});

test("an operation has terms, and a summary only when the company wrote one", () => {
  const { summary: _summary, ...unsummarized } = wire();
  const operation = parseOperation(unsummarized);
  assert.equal("summary" in operation, false);
  assert.deepEqual([...termsLeaves(operation.terms)], [
    ["order_id", "ord_7Hk2"],
    ["price_difference.amount", "70.00"],
    ["price_difference.currency", "USD"],
  ]);
  assert.equal(operationShown(operation), "order_id: ord_7Hk2\nprice_difference.amount: 70.00\nprice_difference.currency: USD");
  assert.equal(operationShown(returned()), returned().summary);
  const { terms: _terms, ...withoutTerms } = wire();
  assert.throws(() => parseOperation(withoutTerms), ProtocolValidationError);
  assert.throws(() => parseOperation(wire({ terms: null })), ProtocolValidationError);
});

// Approving: the user, or the agent on the user's instruction ---------------------------------

test("a user approval says user, how, and under which reference", async () => {
  const approval = await clientFor(new Surface(true)).askUser(returned(), {
    organization: SHOP,
    tenantId: "t",
    inputType: "tap",
    reference: "apr_ledger_1",
  });
  assert.deepEqual(approval, {
    operation_id: "exc_5Rt2",
    revision: "1791487200-k3Jd9Qx2mW8v",
    approver: "user",
    approved_at: Math.floor(NOW.getTime() / 1000),
    input_type: "tap",
    reference: "apr_ledger_1",
  });
});

test("the user is shown the terms' values when there is no summary", async () => {
  const surface = new Surface(true);
  const { summary: _summary, ...unsummarized } = wire();
  await clientFor(surface).askUser(parseOperation(unsummarized), { organization: SHOP, tenantId: "t" });
  const [request] = surface.asked;
  assert.equal(request.summary, "order_id: ord_7Hk2\nprice_difference.amount: 70.00\nprice_difference.currency: USD");
  assert.deepEqual(request.terms, returned().terms);
  assert.deepEqual(request.differences, []);
});

const giftWrap = (changes = {}) =>
  returned({
    summary: "Gift-wrap order ord_7Hk2 before it ships again, USD 5.00.",
    terms: { order_id: "ord_7Hk2", price: { amount: "5.00", currency: "USD" } },
    ...changes,
  });

test("the agent approves only what the user's instruction covers", async () => {
  // An agent approval rests on an instruction the user gave, checked against the revision's
  // terms; nobody is asked, and anything short of a clear yes is the user's (Operations 5).
  const surface = new Surface(true);
  const client = clientFor(surface);
  const approval = await client.approveAsAgent(giftWrap(), { instruction: UNDER_TEN, reference: "apr_ledger_2" });
  assert.deepEqual(approval, {
    operation_id: "exc_5Rt2",
    revision: "1791487200-k3Jd9Qx2mW8v",
    approver: "agent",
    approved_at: Math.floor(NOW.getTime() / 1000),
    reference: "apr_ledger_2",
  });
  // The surface is the user's: an agent approval never uses it.
  assert.deepEqual(surface.asked, []);

  const refused = async (operation, instruction, more = {}) => {
    const error = await rejection(client.approveAsAgent(operation, { instruction, ...more }));
    assert.ok(error instanceof OperationError, String(error));
    return error.code;
  };
  // The instruction says no: USD 50.
  const dear = giftWrap({
    summary: "Gift-wrap order ord_7Hk2, USD 50.00.",
    terms: { order_id: "ord_7Hk2", price: { amount: "50.00", currency: "USD" } },
  });
  assert.equal(await refused(dear, UNDER_TEN), "ask_user");
  // It can't tell: the exchange has no `price`.
  assert.equal(await refused(returned(), UNDER_TEN), "ask_user");
  // Its check failed.
  const broken = agentInstruction("x", () => {
    throw new Error("the check broke");
  });
  assert.equal(await refused(giftWrap(), broken), "ask_user");
  // A truthy answer that is not `true` approves nothing.
  assert.equal(await refused(giftWrap(), agentInstruction("x", () => "yes")), "ask_user");
  assert.equal(await refused(giftWrap(), agentInstruction("x", () => 1)), "ask_user");
  // The terms differ from what the agent asked for, or from the summary: the user is told.
  assert.equal(await refused(giftWrap(), ANYTHING, { asked: { order_id: "ord_other" } }), "ask_user");
  assert.equal(await refused(giftWrap({ summary: "Gift-wrap the order, USD 1.00." }), ANYTHING), "ask_user");
  // Past its expiry there is nothing to approve.
  assert.equal(await refused(giftWrap({ expires_at: "2026-10-10T11:59:59Z" }), ANYTHING), "revision_expired");
  assert.deepEqual(surface.asked, []);
  // An agent approval rests on an instruction: none, or a blank one, is the caller's mistake.
  assert.throws(() => agentInstruction("  ", () => true), RangeError);
  await assert.rejects(client.approveAsAgent(giftWrap(), { instruction: { text: " ", covers: () => true } }), RangeError);
  await assert.rejects(client.approveAsAgent(giftWrap(), {}), RangeError);
});

test("new terms after an agent approval are the user's to approve", async () => {
  // A new revision in answer to an agent approval is never approved on the same instruction
  // (Operations 5); after a user approval it may be.
  const client = clientFor(new Surface(true));
  const first = giftWrap();
  const newer = giftWrap({ revision: "rev_2" });
  const approval = await client.approveAsAgent(first, { instruction: ANYTHING });
  const sent = await client.send(script({ status: 403, operation: newer }), approval);
  assert.deepEqual([sent.status, sent.askUser], ["new_revision", true]);
  assert.deepEqual([...client.userOnly], [first.operation_id]);
  assert.equal((await rejection(client.approveAsAgent(newer, { instruction: ANYTHING }))).code, "ask_user");
  // A host that outlives the client says so itself.
  assert.equal((await rejection(clientFor().approveAsAgent(newer, { instruction: ANYTHING, userOnly: true }))).code, "ask_user");
  // The user can approve it.
  const asked = await client.askUser(newer, { organization: SHOP, tenantId: "t", replaces: first });
  assert.equal(asked.approver, "user");
  const byUser = { operation_id: "exc_9", revision: "r1", approver: "user" };
  const afterUser = await client.send(script({ status: 403, operation: returned({ operation_id: "exc_9", revision: "r2" }) }), byUser);
  assert.deepEqual([afterUser.status, afterUser.askUser], ["new_revision", false]);
});

test("a declined approval is final and never sent again", async () => {
  // `approval_declined`: nothing was performed, the approval is not retried, and no new
  // revision of the action is approved without the user (Operations 6, 7).
  const client = clientFor();
  const operation = giftWrap();
  const approval = await client.approveAsAgent(operation, { instruction: ANYTHING });
  const declined = parseApprovalDeclined({ operation_id: operation.operation_id, revision: operation.revision, reason: "Not this way." });
  const request = script({ status: 403, declined }, { status: 200 });
  const sent = await client.send(request, approval);
  assert.deepEqual([sent.status, sent.declined, sent.askUser], ["declined", declined, true]);
  // A decline is not a failure: no retry.
  assert.equal(request.sent.length, 1);
  assert.equal((await rejection(client.approveAsAgent(giftWrap({ revision: "rev_2" }), { instruction: ANYTHING }))).code, "ask_user");
  // A decline after a failure is still a decline: it says the operation wasn't performed.
  const again = script(new ApiError("x", "x", { statusCode: 503 }), { status: 403, declined });
  assert.equal((await clientFor(undefined, { sleep: async () => {} }).send(again, approval)).status, "declined");
});

// The company ---------------------------------------------------------------------------------

async function world(options) {
  const w = await shopWorld(options);
  const { session, token, reference } = await signedIn(w);
  return { ...w, session, token, reference };
}

async function asked(w, url) {
  const answered = await w.api.call("POST", url, { session: w.session, token: w.token, body: {} });
  assert.equal(answered.status, 403);
  assert.ok(answered.operation !== undefined);
  return answered.operation;
}

const stated = (operation, approver = "agent", more = {}) => ({
  operation_id: operation.operation_id,
  revision: operation.revision,
  approver,
  ...more,
});

const post = (w, url, headers = {}, session = w.session) =>
  w.transport.request("POST", url, {
    session,
    token: w.token,
    headers: { "Content-Type": "application/json", ...headers },
    body: "{}",
  });

test("the company performs an agent approval and records who approved", async () => {
  const w = await world();
  const operation = await asked(w, GIFT_WRAP);
  const approval = stated(operation, "agent", { approved_at: 1791487255, reference: "apr_ledger_7" });
  const done = await w.api.call("POST", GIFT_WRAP, { session: w.session, token: w.token, body: {}, approval });
  assert.equal(done.status, 200);
  assert.equal(done.declined, undefined);
  const record = await w.shop.operationRecord(operation.operation_id);
  assert.deepEqual([record.status, record.approved], ["performed", operation.revision]);
  assert.deepEqual(record.approval, { approver: "agent", approved_at: 1791487255, reference: "apr_ledger_7" });
});

test("an approval with only its approver is acted on", async () => {
  // A Company MUST NOT reject or decline an approval because an optional member is missing or
  // its `input_type` is unknown (Operations 6).
  const w = await world();
  const operation = await asked(w, EXCHANGE);
  const bare = await w.api.call("POST", EXCHANGE, { session: w.session, token: w.token, body: {}, approval: stated(operation, "user") });
  assert.equal(bare.status, 200);
  assert.deepEqual((await w.shop.operationRecord(operation.operation_id)).approval, { approver: "user" });
  const odd = await asked(w, GIFT_WRAP);
  const done = await w.api.call("POST", GIFT_WRAP, {
    session: w.session,
    token: w.token,
    body: {},
    approval: stated(odd, "user", { input_type: "a gesture nobody defined" }),
  });
  assert.equal(done.status, 200);
});

test("a version 2 approval approves nothing", async () => {
  // Without `approver` the header is no approval: the request is one without an approval,
  // answered with the operation and performing nothing.
  const w = await world();
  const operation = await asked(w, EXCHANGE);
  const raw = await post(w, EXCHANGE, {
    [APPROVAL_HEADER]: `operation_id="${operation.operation_id}", revision="${operation.revision}", approved_at=1791487260, input_type="tap"`,
  });
  assert.equal(raw.status, 403);
  assert.equal((await raw.json()).error, "approval_required");
  assert.deepEqual(w.plugin.executor.performed, []);
});

test("a request that declares operations 2 gets no operation", async () => {
  // Version 2 is another major version (Operations 2): the company returns no operation to a
  // request that declares it, and says which extension the request needs, in a JSON body (§3.3).
  const w = await world();
  const { session } = w;
  const old = new PapSession({
    sid: session.sid,
    sub: session.sub,
    issuer: session.issuer,
    clientId: session.clientId,
    tenantId: session.tenantId,
    extensions: { operations: "2" },
  });
  const raw = await post(w, EXCHANGE, {}, old);
  assert.equal(raw.status, 403);
  assert.equal(raw.headers.has("www-authenticate"), false);
  assert.deepEqual(await raw.json(), { error: "extension_required", extension: "operations" });
  const refused = await rejection(w.api.call("POST", EXCHANGE, { session: old, token: w.token, body: {} }));
  assert.ok(refused instanceof ApiError);
  assert.equal(refused.code, "extension_required");
  assert.deepEqual(refused.details, { extension: "operations" });
  assert.deepEqual(w.plugin.executor.performed, []);
});

test("extension_required is read from the JSON body, never from a challenge", async () => {
  const w = await world();
  const challenged = async () =>
    new Response(null, { status: 403, headers: { "WWW-Authenticate": 'Bearer error="extension_required", extension="operations"' } });
  const api = new ApiClient({ transport: new SessionFetchClient({ reactor: w.reactor, fetch: challenged }) });
  const refused = await rejection(api.call("POST", EXCHANGE, { session: w.session, body: {} }));
  assert.equal(refused.code, "api_request_failed");
  assert.equal(refused.details?.extension, undefined);
});

test("Manzanita declines an agent approval of a return and takes the user's", async () => {
  // A decline at an API: HTTP 403, `approval_declined` with the members, a JSON body; nothing
  // performed, nothing recorded, no new operation (Operations 6).
  const w = await world();
  const operation = await asked(w, RETURNS);
  const byAgent = stated(operation, "agent", { reference: "apr_ledger_8" });
  const raw = await post(w, RETURNS, { [APPROVAL_HEADER]: approvalHeader(byAgent) });
  assert.equal(raw.status, 403);
  assert.equal(raw.headers.has("www-authenticate"), false);
  assert.deepEqual(await raw.json(), {
    error: "approval_declined",
    operation_id: operation.operation_id,
    revision: operation.revision,
    reason: "A return is refunded only when you approve it yourself.",
    alternative: {
      instructions: "Approve the return when your personal agent asks you.",
      references: [{ type: "web", url: "https://manzanita.example/returns" }],
    },
  });
  const call = (approval) => w.api.call("POST", RETURNS, { session: w.session, token: w.token, body: {}, approval });
  const answered = await call(byAgent);
  assert.ok(answered.declined !== undefined);
  assert.equal(answered.operation, undefined);
  assert.ok(answered.declined.alternative !== undefined);
  let record = await w.shop.operationRecord(operation.operation_id);
  assert.deepEqual([record.status, record.approved, record.approval], ["open", undefined, undefined]);
  // No new operation, no new revision.
  assert.equal(record.revisions.length, 1);
  assert.deepEqual(w.plugin.returns.performed, []);

  // The whole of it through the client: declined, then the user is asked, and theirs works.
  const client = clientFor(new Surface(true));
  const sent = await client.send(call, byAgent);
  assert.deepEqual([sent.status, sent.askUser], ["declined", true]);
  // Manzanita's return fails partway, which is its own story (Operations 7): what matters here
  // is that the company acted on the user's approval of the revision it had declined from the
  // agent.
  const failed = await rejection(call(stated(operation, "user", { input_type: "tap" })));
  assert.ok(failed instanceof ApiError);
  assert.equal(failed.code, "action_failed");
  record = await w.shop.operationRecord(operation.operation_id);
  assert.equal(record.status, "performed");
  assert.deepEqual(record.approval, { approver: "user", input_type: "tap" });
  // The demo's rule, by itself.
  assert.equal(declineAgentReturns({ action: "orders.exchange", operation, approval: byAgent }), undefined);
  assert.equal(declineAgentReturns({ action: "orders.return", operation, approval: stated(operation, "user") }), undefined);
  assert.equal(CONFIG_OPTIONS.decline, declineAgentReturns);
});

function noAgents(request) {
  assert.ok(request.action && request.operation.terms !== undefined);
  return request.approval.approver === "agent" ? { reason: "Ask the person." } : undefined;
}

test("a tool declines with an error result", async () => {
  const w = await world({ config: { decline: noAgents } });
  const forMcp = await w.accounts.tokenForMcp(w.reference, { context: w.context, server: parseProtectedResourceMetadata({ resource: MCP }) });
  assert.equal(forMcp.status, "signed_in");
  const client = new McpClient({ url: MCP, session: w.session, reactor: w.reactor, fetch: w.fetch, token: forMcp.token });
  const proposed = await client.callTool("exchange_jacket");
  assert.ok(proposed.operation !== undefined);
  // The tool's text says what is to approve, not that the user must: an agent may (Operations 5).
  assert.equal(proposed.text, `Not done yet. This needs approval: ${proposed.operation.summary}`);
  const declined = await client.callTool("exchange_jacket", {}, { approval: stated(proposed.operation) });
  assert.equal(declined.isError, true);
  assert.equal(declined.text, "Ask the person.");
  assert.deepEqual(declined.structuredContent, {
    error: "approval_declined",
    operation_id: proposed.operation.operation_id,
    revision: proposed.operation.revision,
    reason: "Ask the person.",
  });
  assert.deepEqual(declined.declined, {
    operation_id: proposed.operation.operation_id,
    revision: proposed.operation.revision,
    reason: "Ask the person.",
  });
  assert.equal(declined.operation, undefined);
  assert.deepEqual(w.plugin.executor.performed, []);
  const done = await client.callTool("exchange_jacket", {}, { approval: stated(proposed.operation, "user") });
  assert.equal(done.isError, false);
  assert.deepEqual(w.plugin.executor.performed, [proposed.operation.operation_id]);
});

test("a conversation declines in a later message, without error", async () => {
  const w = await world({ config: { decline: noAgents } });
  const { session, token } = w;
  const page = await w.conversations.start(w.endpoint, w.message("Exchange it for something warmer"), { session, token, wait: 0 });
  const said = (events) => events.events.filter((event) => event.message?.role === "company").map((event) => event.message);
  const operation = said(page).map(messageOperation).find((item) => item !== undefined);
  assert.ok(operation !== undefined);
  const approving = (approver) => ({
    id: w.conversations.generateRequestId(),
    author: { type: "agent" },
    extensions: operationsContent({ approval: stated(operation, approver) }),
  });
  const refusedPage = await w.conversations.send(w.endpoint, page.conversation_id, approving("agent"), { session, token, wait: 0 });
  const told = said(refusedPage).at(-1);
  assert.deepEqual(messageDeclined(told), {
    operation_id: operation.operation_id,
    revision: operation.revision,
    reason: "Ask the person.",
  });
  assert.equal(told.text, "Ask the person.");
  assert.equal(messageOperation(told), undefined);
  assert.equal("error" in told.extensions.operations.declined, false);
  assert.deepEqual(w.plugin.executor.performed, []);
  const donePage = await w.conversations.send(w.endpoint, page.conversation_id, approving("user"), { session, token, wait: 0 });
  assert.ok(said(donePage).at(-1).text.startsWith("Exchanged the Ridge Jacket"));
  assert.deepEqual(w.plugin.executor.performed, [operation.operation_id]);
});

/** An API of the company's whose one action proposes `operation`. */
const notesPlugin = (operation, performed = []) => ({
  name: "notes",
  version: "1",
  contributes: [
    { point: CompanyApis, value: { description: "Notes", openapi: () => ({}), handle: async () => ({ operation }) }, options: { id: "notes", order: -1 } },
    {
      point: OperationExecutors,
      value: {
        action: "orders.note",
        perform: async (approved) => {
          performed.push(approved.operation_id);
          return { summary: "Noted." };
        },
      },
      options: { id: "note" },
    },
  ],
});

test("a company sends terms always, and a summary when it has one", async () => {
  // `terms` are required of the company's actions; an operation without a summary goes out
  // without one (Operations 3, 4).
  const NOTES = "https://manzanita.example/api/notes";
  const terms = { order_id: "ord_7Hk2", note: "Leave it with the neighbour" };
  const performed = [];
  const w = await world({ plugins: [notesPlugin({ action: "orders.note", terms, subject: "ord_7Hk2" }, performed)] });
  const raw = await post(w, NOTES);
  assert.equal(raw.status, 403);
  const { operation } = await raw.json();
  assert.deepEqual(Object.keys(operation).sort(), ["expires_at", "operation_id", "revision", "terms"]);
  assert.deepEqual(operation.terms, terms);
  // The company can reword or drop the summary of a revision it changes: the terms are what count.
  const revised = await w.shop.revise(operation.operation_id, { terms: { ...terms, note: "Ring twice" } });
  assert.equal("summary" in revised, false);
  assert.notEqual(revised.revision, operation.revision);
  const worded = await w.shop.revise(operation.operation_id, { terms, summary: "Add a note to order ord_7Hk2." });
  assert.equal(worded.summary, "Add a note to order ord_7Hk2.");
  const done = await w.api.call("POST", NOTES, { session: w.session, token: w.token, body: {}, approval: stated(worded) });
  assert.equal(done.status, 200);
  assert.deepEqual(performed, [operation.operation_id]);

  // An action that proposes no terms is the company's own mistake, said at once.
  const bare = await world({ plugins: [notesPlugin({ action: "orders.note", summary: "Add a note." })] });
  const headers = { "Content-Type": "application/json", ...(await sessionHeaders(bare.reactor, "POST", NOTES, { session: bare.session, token: bare.token })) };
  await assert.rejects(
    bare.shop.handle({ method: "POST", url: NOTES, headers: Object.fromEntries(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), value])), body: "{}" }),
    TypeError,
  );
});
