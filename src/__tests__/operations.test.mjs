/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Operations v2 on the agent's side: the operation, the Poppy-Approval header, the terms check,
// the user's approval, and sending it at most once. The company's side is in company.test.mjs.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  APPROVAL_HEADER,
  APPROVAL_META_KEY,
  ApiError,
  ApprovalSurfaces,
  Clocks,
  OPERATIONS_EXTENSION,
  OPERATIONS_VERSION,
  OperationError,
  OperationsClient,
  ProtocolValidationError,
  SEND_ATTEMPTS,
  TransportError,
  approvalFromMeta,
  approvalHeader,
  buildPapReactor,
  operationFrom,
  operationsNegotiated,
  parseApprovalHeader,
  parseClientMetadata,
  parseDiscoveryDocument,
  parseMessage,
  parseOperation,
  termsDifferences,
} from "../../lib/index.js";

const fixtures = new URL("../../protocol/fixtures/", import.meta.url);
const fixture = (name) => JSON.parse(readFileSync(new URL(name, fixtures), "utf8"));
const NOW = new Date("2026-10-10T12:00:00Z");
const SHOP = { name: "Shop", domain: "shop.example" };

const wire = (changes = {}) => ({ ...fixture("operation-valid.json"), ...changes });
const returned = (changes = {}) => parseOperation(wire(changes));

function clientFor(surface, options = {}) {
  const reactor = buildPapReactor({}, [
    {
      name: "@tests/pap-operations",
      contributes: [
        { point: Clocks, value: { now: () => NOW }, options: { id: "fixed", order: 10 } },
        ...(surface === undefined ? [] : [{ point: ApprovalSurfaces, value: surface, options: { id: "the-user" } }]),
      ],
    },
  ]);
  return new OperationsClient({ reactor, ...options });
}

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

// The operation -------------------------------------------------------------------------------

test("the fixture is an operation and a revision is opaque", () => {
  const operation = returned();
  assert.equal(operation.revision, "1791487200-k3Jd9Qx2mW8v");
  assert.deepEqual(Object.keys(operation).sort(), ["expires_at", "operation_id", "revision", "summary", "terms"]);
  const { terms: _terms, ...without } = wire();
  assert.equal("terms" in parseOperation(without), false);
});

for (const changes of [
  { revision: 1 },
  { revision: "not an id" },
  { operation_id: "a/b" },
  { summary: "" },
  { expires_at: null },
  { expires_at: "2026-10-10T18:00:00" },
]) {
  test(`an operation with another shape is refused: ${JSON.stringify(changes)}`, () => {
    assert.throws(() => parseOperation(wire(changes)), ProtocolValidationError);
  });
}

test("fields of the old shape mean nothing: the user is asked all the same", async () => {
  const old = returned({
    state: "succeeded",
    url: "https://shop.example/op",
    confirmation: { approved_by: "standing_permission" },
    result: { summary: "Done." },
    user_approval_required: false,
  });
  const surface = new Surface(false);
  await assert.rejects(
    clientFor(surface).askUser(old, { organization: SHOP, tenantId: "t" }),
    (error) => error.code === "not_approved",
  );
  assert.equal(surface.asked.length, 1);
});

test("the operation from each interface", () => {
  const operation = returned();
  const message = parseMessage({ id: "msg_1", author: { type: "agent" }, role: "company", operation: wire() });
  for (const payload of [
    { error: "approval_required", operation: wire() },
    { isError: true, structuredContent: { operation: wire() } },
    message,
    wire(),
  ]) {
    assert.deepEqual(operationFrom(payload), operation);
  }
  assert.throws(() => operationFrom({}), (error) => error instanceof OperationError && error.code === "invalid_operation");
  assert.throws(() => operationFrom(null), (error) => error.code === "invalid_operation");
  assert.throws(() => operationFrom({ operation: { summary: "no id" } }), (error) => error.code === "invalid_operation");
});

test("a message with only an approval is a message, and text alone approves nothing", () => {
  const approval = { operation_id: "exc_5Rt2", revision: "r1" };
  assert.deepEqual(parseMessage({ id: "msg_1", author: { type: "agent" }, approval }).approval, approval);
  assert.throws(() => parseMessage({ id: "msg_2", author: { type: "agent" } }), ProtocolValidationError);
  assert.equal("approval" in parseMessage({ id: "msg_3", author: { type: "human" }, text: "I approve" }), false);
});

test("operations are used only when both sides list version 2", () => {
  assert.deepEqual([OPERATIONS_EXTENSION, OPERATIONS_VERSION], ["operations", "2"]);
  const document = (version) =>
    parseDiscoveryDocument({ ...fixture("discovery-valid.json"), extensions: { operations: { version } } });
  const agent = (extensions) => parseClientMetadata({ ...fixture("client-metadata-valid.json"), extensions });
  const both = agent({ operations: { version: "2" } });
  assert.equal(operationsNegotiated(document("2"), both), true);
  assert.equal(operationsNegotiated(document("2"), agent({})), false);
  assert.equal(operationsNegotiated(document("1"), both), false);
  assert.equal(operationsNegotiated(document("2"), agent({ operations: { version: "1" } })), false);
});

// The Poppy-Approval header -------------------------------------------------------------------

test("the header is a Dictionary with two Strings", () => {
  const approval = { operation_id: "exc_5Rt2", revision: "1791487200-k3Jd9Qx2mW8v" };
  const value = approvalHeader(approval);
  assert.equal(APPROVAL_HEADER, "Poppy-Approval");
  assert.equal(value, 'operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v"');
  assert.deepEqual(parseApprovalHeader(value), approval);
});

for (const value of [
  'operation_id="a", revision="b"',
  'revision="b",operation_id="a"',
  'operation_id="a",   revision="b"  ',
  'later=1, operation_id="a", revision="b"',
  'operation_id="a", revision="b", flag',
  'operation_id="a", revision="b", flag=?0, n=1.5, t=tok/en, d=:aGk=:, at=@1659578233',
  'operation_id="a";note="x", revision="b";a;b=2',
  'operation_id="a", revision="b", list=(1 "two" tok);p=1, empty=()',
  'operation_id="a", revision="b", display=%"caf%c3%a9"',
  'operation_id="old", operation_id="a", revision="b"', // the last one wins
]) {
  test(`the header parses as a Dictionary, ignoring unknown members: ${value}`, () => {
    assert.deepEqual(parseApprovalHeader(value), { operation_id: "a", revision: "b" });
  });
}

for (const value of [
  null,
  undefined,
  "",
  "operation_id=a, revision=b", // Tokens, not Strings
  'operation_id="a"',
  'revision="b"',
  'operation_id="a", revision=1',
  'operation_id="a", revision="not an id"',
  'operation_id="a", revision="b",', // a trailing comma
  'operation_id="a" revision="b"',
  'operation_id="a", revision="b', // unterminated
  'Operation_id="a", revision="b"', // keys are lower case
  'operation_id="a", revision="b", x=(1',
  'operation_id="a", revision="b\\n"',
]) {
  test(`a value that isn't such a Dictionary is no approval: ${value}`, () => {
    assert.equal(parseApprovalHeader(value), undefined);
  });
}

// The approval in `_meta` ---------------------------------------------------------------------

test("the MCP approval is read from _meta, ignoring unknown members", () => {
  const approval = { operation_id: "exc_5Rt2", revision: "r1" };
  assert.equal(APPROVAL_META_KEY, "personalagentprotocol.org/approval");
  assert.deepEqual(approvalFromMeta({ [APPROVAL_META_KEY]: approval }), approval);
  const read = approvalFromMeta({ [APPROVAL_META_KEY]: { ...approval, later: 1 }, "another.example/thing": true });
  assert.deepEqual([read.operation_id, read.revision], [approval.operation_id, approval.revision]);
});

for (const meta of [
  undefined,
  null,
  [],
  "approved",
  {},
  { "personalagentprotocol.org/approval": null },
  { "personalagentprotocol.org/approval": { operation_id: "exc_5Rt2" } },
  { "personalagentprotocol.org/approval": { operation_id: "exc_5Rt2", revision: 1 } },
  { "personalagentprotocol.org/approval": { operation_id: "a b", revision: "r1" } },
  { approval: { operation_id: "exc_5Rt2", revision: "r1" } },
]) {
  test(`_meta without a well-formed approval is none: ${JSON.stringify(meta)}`, () => {
    assert.equal(approvalFromMeta(meta), undefined);
  });
}

// The terms check -----------------------------------------------------------------------------

test("the terms check agrees with a summary that says the same", () => {
  assert.deepEqual(termsDifferences(returned()), []);
  // The spec's own example: identifiers aren't in a summary, written for people.
  const spec = returned({
    summary:
      "Exchange the Stormline Jacket (M) on order ord_7Hk2 for the Stormline Insulated " +
      "Jacket (M), for $70.00 more, charged to the card used for the order.",
    terms: {
      order_id: "ord_7Hk2",
      item_id: "itm_4Qa",
      replacement_sku: "stormline-insulated-m",
      price_difference: { amount: "70.00", currency: "USD" },
    },
  });
  assert.deepEqual(termsDifferences(spec), []);
  const { terms: _terms, ...without } = wire();
  assert.deepEqual(termsDifferences(parseOperation(without)), []);
});

test("the terms check points out a summary that says otherwise", () => {
  assert.deepEqual(termsDifferences(returned({ summary: "Exchange the jacket for USD 7.00 more." })), [
    "The terms say price_difference.amount 70.00; the summary doesn't.",
    "The summary says 7.00; the terms don't.",
  ]);
});

test("the terms check compares what was asked for", () => {
  const asked = { order_id: "ord_7Hk2", "price_difference.currency": "EUR", gift: "yes" };
  assert.deepEqual(termsDifferences(returned(), asked), [
    "You asked for price_difference.currency EUR; the terms say USD.",
    "You asked for gift yes; the terms don't say.",
  ]);
});

// Asking the user -----------------------------------------------------------------------------

test("the user is asked with the company, the summary and any difference", async () => {
  const surface = new Surface(true);
  const operation = returned({ summary: "Exchange the jacket for USD 7.00 more." });
  const older = returned({ summary: "Exchange the jacket.", terms: { order_id: "ord_7Hk2" } });
  const approval = await clientFor(surface).askUser(operation, { organization: SHOP, tenantId: "tenant", replaces: older });
  assert.deepEqual(approval, { operation_id: operation.operation_id, revision: operation.revision });
  const [asked] = surface.asked;
  assert.deepEqual([asked.companyName, asked.companyDomain], ["Shop", "shop.example"]);
  assert.equal(asked.summary, operation.summary);
  assert.equal(asked.expiresAt.getTime(), new Date(operation.expires_at).getTime());
  assert.deepEqual(asked.terms, operation.terms);
  assert.equal(asked.differences.length, 2);
  assert.deepEqual(asked.changed, ["summary", "price_difference.amount", "price_difference.currency"]);
});

for (const answer of [false, null, undefined, "yes", 1]) {
  test(`only true from the user's surface approves, not ${JSON.stringify(answer)}`, async () => {
    await assert.rejects(
      clientFor(new Surface(answer)).askUser(returned(), { organization: SHOP, tenantId: "t" }),
      (error) => error instanceof OperationError && error.code === "not_approved",
    );
  });
}

test("every operation is asked about, never approved on the user's behalf", async () => {
  // An approval says nothing of the next one, however like it (Operations 5).
  const surface = new Surface(true, false);
  const client = clientFor(surface);
  await client.askUser(returned(), { organization: SHOP, tenantId: "t" });
  await assert.rejects(
    client.askUser(returned({ revision: "r2" }), { organization: SHOP, tenantId: "t" }),
    (error) => error.code === "not_approved",
  );
  assert.equal(surface.asked.length, 2);
});

test("the same revision asked twice is asked twice", async () => {
  const surface = new Surface(true, true);
  const client = clientFor(surface);
  await client.askUser(returned(), { organization: SHOP, tenantId: "t" });
  await client.askUser(returned(), { organization: SHOP, tenantId: "t" });
  assert.equal(surface.asked.length, 2);
});

test("without a surface nothing is approved", async () => {
  await assert.rejects(
    clientFor().askUser(returned(), { organization: SHOP, tenantId: "t" }),
    (error) => error instanceof OperationError && error.code === "no_approval_surface",
  );
});

test("a failing surface approves nothing", async () => {
  const surface = { approve: async () => { throw new Error("the dialog crashed"); } };
  await assert.rejects(
    clientFor(surface).askUser(returned(), { organization: SHOP, tenantId: "t" }),
    (error) => error instanceof OperationError && error.code === "approval_failed",
  );
});

test("a host's own surface overrides the contribution", async () => {
  const contributed = new Surface(true);
  const own = new Surface(false);
  await assert.rejects(
    clientFor(contributed).askUser(returned(), { organization: SHOP, tenantId: "t", surface: own }),
    (error) => error.code === "not_approved",
  );
  assert.deepEqual(contributed.asked, []);
  assert.equal(own.asked.length, 1);
});

test("a revision past its expiry is not put to the user", async () => {
  const surface = new Surface(true);
  const past = returned({ expires_at: new Date(NOW.getTime() - 1000).toISOString() });
  await assert.rejects(
    clientFor(surface).askUser(past, { organization: SHOP, tenantId: "t" }),
    (error) => error.code === "revision_expired",
  );
  assert.deepEqual(surface.asked, []);
});

// Sending the approval ------------------------------------------------------------------------

const APPROVAL = { operation_id: "exc_5Rt2", revision: "1791487200-k3Jd9Qx2mW8v" };
const answer = (body, operation) => ({ status: operation === undefined ? 200 : 403, body, ...(operation === undefined ? {} : { operation }) });
const unavailable = (retryAfter) =>
  new ApiError("temporarily_unavailable", "x", {
    statusCode: 503,
    ...(retryAfter === undefined ? {} : { details: { retry_after: retryAfter } }),
  });

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

test("a failure or a timeout keeps the same approval", async () => {
  const waits = [];
  const request = script(
    new TransportError("request_failed", "the answer was lost"),
    unavailable("5"),
    answer({ summary: "Exchanged." }),
  );
  const sent = await clientFor(undefined, { sleep: async (seconds) => { waits.push(seconds); } }).send(request, APPROVAL);
  assert.equal(sent.status, "answered");
  assert.deepEqual(sent.answer.body, { summary: "Exchanged." });
  assert.deepEqual(request.sent, Array(3).fill(APPROVAL));
  assert.deepEqual(waits, [5]);
});

test("a new revision for a first send is for the user", async () => {
  const newer = returned({ revision: "r2" });
  const sent = await clientFor().send(script(answer(undefined, newer)), APPROVAL);
  assert.equal(sent.status, "new_revision");
  assert.deepEqual(sent.operation, newer);
});

test("a new operation in answer to a retry says nothing of the first", async () => {
  // Don't ask the user again until it's known whether the first was performed (Operations 7).
  const newer = returned({ revision: "r2" });
  const request = script(new TransportError("request_failed", "lost"), answer(undefined, newer));
  const sent = await clientFor().send(request, APPROVAL);
  assert.equal(sent.status, "unknown");
  assert.deepEqual(sent.operation, newer);
});

test("an answer with the revision named is refused", async () => {
  await assert.rejects(
    clientFor().send(script(answer(undefined, returned())), APPROVAL),
    (error) => error instanceof OperationError && error.code === "invalid_operation",
  );
});

test("still unknown after every attempt", async () => {
  assert.equal(SEND_ATTEMPTS, 3);
  const request = script(unavailable(), unavailable(), unavailable(), answer({}));
  const sent = await clientFor().send(request, APPROVAL);
  assert.equal(sent.status, "unknown");
  assert.equal(sent.operation, undefined);
  assert.equal(request.sent.length, 3);
});

test("attempts bounds the sends", async () => {
  const request = script(new TransportError("request_failed", "lost"), answer({}));
  assert.equal((await clientFor().send(request, APPROVAL, { attempts: 1 })).status, "unknown");
  assert.equal(request.sent.length, 1);
  await assert.rejects(clientFor().send(script(), APPROVAL, { attempts: 0 }), RangeError);
});

test("a wait longer than the client waits ends it", async () => {
  const request = script(unavailable("3600"), answer({}));
  const sent = await clientFor(undefined, { maxWait: 30 }).send(request, APPROVAL);
  assert.equal(sent.status, "unknown");
  assert.equal(sent.retryAfter, "3600");
  assert.equal(request.sent.length, 1);
});

test("another refusal is raised and not retried", async () => {
  const request = script(new ApiError("invalid_token", "x", { statusCode: 401 }));
  await assert.rejects(clientFor().send(request, APPROVAL), ApiError);
  assert.equal(request.sent.length, 1);
});
