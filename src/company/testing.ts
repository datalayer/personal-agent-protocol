/**
 * A conformance kit for `pap.company.store` backends (the port of the Python
 * `personal_agent_protocol.company.testing`).
 *
 * ```ts
 * test("my store conforms", () => checkStore(() => new MyDatabaseStore(url)));
 * ```
 *
 * `checkStore` rejects with `StoreConformanceError` naming the first property a
 * store breaks: absent and present records, expiry, `take` once under
 * concurrency, `create` only if absent, compare-and-set conflicts, kinds kept
 * apart, values copied rather than shared, and a JSON round trip of every
 * record kind the company keeps. `makeStore` returns a fresh, empty store (or
 * a promise of one); `now` is the clock the store judges expiry by.
 */

import type { Operation } from "../models.js";
import {
  RecordKinds,
  type AccountAgent,
  type AccountFamily,
  type AccountGrant,
  type CompanyStore,
  type IssuedCode,
  type IssuedSession,
  type JsonObject,
  type KnownClient,
  type MessageReceipt,
  type OperationProposal,
  type PendingAuthorization,
  type PendingDevice,
  type PendingMediated,
  type SessionPointer,
  type StoredConversation,
  type StoredOperation,
  type StoredSession,
  type UserCode,
} from "./store.js";

const CONCURRENCY = 16;

/** A company store does not behave as `pap.company.store` requires. */
export class StoreConformanceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StoreConformanceError";
  }
}

function check(condition: boolean, message: string): void {
  if (!condition) throw new StoreConformanceError(message);
}

/** Equal JSON values, whatever the member order. */
function same(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left).filter((key) => left[key] !== undefined);
  if (keys.length !== Object.keys(right).filter((key) => right[key] !== undefined).length) {
    return false;
  }
  return keys.every((key) => same(left[key], right[key]));
}

/** One record of every kind the company keeps, each field set, for round trips. */
export function recordSamples(now: Date): Readonly<Record<string, JsonObject>> {
  const later = new Date(now.getTime() + 5 * 60 * 1000).toISOString();
  const signedIn: IssuedSession = {
    sessionId: "ses_1",
    clientId: "https://atlas.example",
    pairwiseUserId: "usr_1",
    keyThumbprint: "thumb",
    expiresAt: later,
    accountId: "acct_1",
    scopes: ["orders:read", "orders:write"],
    accountToken: "digest_1",
    resource: "https://shop.example/mcp",
  };
  const operation = {
    operation_id: "op_1",
    revision: 2,
    state: "succeeded",
    summary: "Exchange the jacket.",
    terms: { order_id: "ord_1", price: { amount: "1.00", currency: "USD" } },
    expires_at: null,
    user_approval_required: true,
    url: "https://shop.example/operations/op_1",
    confirmation: { revision: 2, approved_by: "user", confirmed_at: now.toISOString() },
    result: { summary: "Exchanged.", data: null },
  } as unknown as Operation;
  const records: Record<string, object> = {
    [RecordKinds.session]: {
      sessionId: "ses_1",
      clientId: "https://atlas.example",
      pairwiseUserId: "usr_1",
      tokens: { tok_1: signedIn },
      latest: "tok_1",
    } satisfies StoredSession,
    [RecordKinds.sessionToken]: { sessionId: "ses_1" } satisfies SessionPointer,
    [RecordKinds.accountToken]: {
      family: "fam_1",
      accountId: "acct_1",
      clientId: "c",
      pairwiseUserId: "u",
      scopes: ["a", "b"],
      expiresAt: later,
      revoked: true,
    } satisfies AccountGrant,
    [RecordKinds.accountFamily]: {
      clientId: "c",
      accountId: "acct_1",
      tokens: ["t1", "t2"],
      sessions: ["ses_1"],
      revoked: true,
    } satisfies AccountFamily,
    [RecordKinds.accountAgent]: { families: ["fam_1", "fam_2"] } satisfies AccountAgent,
    [RecordKinds.client]: { extensions: ["operations"] } satisfies KnownClient,
    [RecordKinds.device]: {
      clientId: "c",
      scopes: ["a"],
      userCode: "ABCD-EFGH",
      expiresAt: later,
      interval: 10,
      lastPoll: now.toISOString(),
      accountId: "acct_1",
      granted: ["a"],
      denied: true,
    } satisfies PendingDevice,
    [RecordKinds.userCode]: { device: "dev_digest" } satisfies UserCode,
    [RecordKinds.authorization]: {
      clientId: "c",
      redirectUri: "https://atlas.example/cb",
      scopes: ["a"],
      state: "st",
      codeChallenge: "chal",
      expiresAt: later,
      clientName: "Atlas",
    } satisfies PendingAuthorization,
    [RecordKinds.code]: {
      clientId: "c",
      redirectUri: "https://atlas.example/cb",
      codeChallenge: "chal",
      accountId: "acct_1",
      scopes: ["a"],
      expiresAt: later,
    } satisfies IssuedCode,
    [RecordKinds.mediated]: {
      sessionId: "ses_1",
      accountId: "acct_1",
      scopes: ["a"],
      codeReference: "ref",
      expiresAt: later,
      attempts: 2,
    } satisfies PendingMediated,
    [RecordKinds.conversation]: {
      conversationId: "cnv_1",
      owner: ["c", "u"],
      status: "queued",
      responder: "human",
      parentId: "cnv_0",
      directChild: "cnv_2",
      accountId: "acct_1",
      events: [{ id: "evt_1", payload: { id: "evt_1", type: "state", nested: [1, null] } }],
      forgotten: ["evt_0"],
    } satisfies StoredConversation,
    [RecordKinds.messageId]: { conversationId: "cnv_1", digest: "digest" } satisfies MessageReceipt,
    [RecordKinds.operation]: {
      operation,
      action: "exchange",
      owner: ["c", "u"],
      accountId: "acct_1",
      performed: true,
    } satisfies StoredOperation,
    [RecordKinds.proposal]: { operationId: "op_1" } satisfies OperationProposal,
    [RecordKinds.browserCookie]: { sessionId: "ses_1" } satisfies SessionPointer,
  };
  return records as Readonly<Record<string, JsonObject>>;
}

/** Check that the stores `makeStore` returns keep the company store contract. */
export async function checkStore(
  makeStore: () => CompanyStore | Promise<CompanyStore>,
  options: { readonly now?: () => Date } = {},
): Promise<void> {
  const now = options.now ?? (() => new Date());
  await absent(await makeStore());
  await present(await makeStore());
  await expiry(await makeStore(), now());
  await takeOnce(await makeStore());
  await createOnce(await makeStore());
  await compareAndSet(await makeStore());
  await roundTrips(await makeStore(), now());
}

async function absent(store: CompanyStore): Promise<void> {
  check((await store.get("conversation", "missing")) === undefined, "get of a missing record");
  check((await store.take("conversation", "missing")) === undefined, "take of a missing record");
  check(
    !(await store.replace("conversation", "missing", "1", { a: 1 })),
    "replace of a missing record must fail",
  );
  await store.delete("conversation", "missing");
}

async function present(store: CompanyStore): Promise<void> {
  await store.put("conversation", "k", { a: 1 });
  const first = await store.get("conversation", "k");
  check(same(first?.value, { a: 1 }), "put then get returns the value");
  check((await store.get("operation", "k")) === undefined, "kinds are separate namespaces");
  await store.put("conversation", "k", { a: 2 });
  const second = await store.get("conversation", "k");
  check(same(second?.value, { a: 2 }), "put overwrites");
  check(
    first !== undefined && second !== undefined && first.version !== second.version,
    "every write gives a new version",
  );
  // Values are copies: changing what was written or read changes nothing stored.
  const written = { list: [1], nested: { b: true } };
  await store.put("conversation", "copy", written);
  written.list.push(2);
  const read = await store.get("conversation", "copy");
  check(same(read?.value.list, [1]), "the store keeps a copy of the value");
  const nested = read?.value.nested as { b: boolean } | undefined;
  if (nested !== undefined) nested.b = false;
  const again = await store.get("conversation", "copy");
  check(same(again?.value.nested, { b: true }), "reads return copies");
  await store.delete("conversation", "k");
  check((await store.get("conversation", "k")) === undefined, "delete removes the record");
}

async function expiry(store: CompanyStore, now: Date): Promise<void> {
  const past = new Date(now.getTime() - 1000);
  const future = new Date(now.getTime() + 60 * 60 * 1000);
  await store.put("code", "old", { a: 1 }, { expiresAt: past });
  check((await store.get("code", "old")) === undefined, "an expired record reads as absent");
  check((await store.take("code", "old")) === undefined, "an expired record cannot be taken");
  check(
    await store.create("code", "old", { a: 2 }, { expiresAt: future }),
    "create succeeds over an expired record",
  );
  const entry = await store.get("code", "old");
  check(same(entry?.value, { a: 2 }), "the created record replaced it");
  const expiresAt = entry === undefined ? undefined : entry.expiresAt;
  check(
    expiresAt !== undefined && Math.abs(expiresAt.getTime() - future.getTime()) < 1000,
    "get returns the record's expiry",
  );
  await store.put("code", "lasting", { a: 1 });
  const lasting = await store.get("code", "lasting");
  check(lasting !== undefined && lasting.expiresAt === undefined, "a record without expiry");
  if (entry !== undefined) {
    check(
      await store.replace("code", "old", entry.version, { a: 3 }, { expiresAt: past }),
      "replace may set an expiry",
    );
    check((await store.get("code", "old")) === undefined, "replace to a past expiry expires it");
  }
}

async function takeOnce(store: CompanyStore): Promise<void> {
  await store.put("authorization", "once", { a: 1 });
  const taken = await Promise.all(
    Array.from({ length: CONCURRENCY }, () => store.take("authorization", "once")),
  );
  const winners = taken.filter((value) => value !== undefined);
  check(winners.length === 1, `take returned the record ${winners.length} times, not once`);
  check(same(winners[0], { a: 1 }), "take returns the value");
  check((await store.get("authorization", "once")) === undefined, "a taken record is gone");
}

async function createOnce(store: CompanyStore): Promise<void> {
  const created = await Promise.all(
    Array.from({ length: CONCURRENCY }, (_, n) => store.create("message_id", "m", { n })),
  );
  const wins = created.filter(Boolean).length;
  check(wins === 1, `create succeeded ${wins} times, not once`);
  const entry = await store.get("message_id", "m");
  check(same(entry?.value, { n: created.indexOf(true) }), "the record is the one whose create succeeded");
  check(!(await store.create("message_id", "m", { n: -1 })), "create of a present record");
}

async function compareAndSet(store: CompanyStore): Promise<void> {
  await store.put("operation", "op", { state: "proposed" });
  const entry = await store.get("operation", "op");
  check(entry !== undefined, "the record is present");
  if (entry === undefined) return;
  const replaced = await Promise.all(
    Array.from({ length: CONCURRENCY }, (_, n) =>
      store.replace("operation", "op", entry.version, { state: "in_progress", n }),
    ),
  );
  const wins = replaced.filter(Boolean).length;
  check(wins === 1, `replace on one version succeeded ${wins} times`);
  check(
    !(await store.replace("operation", "op", entry.version, { state: "stale" })),
    "replace with a stale version fails",
  );
  const current = await store.get("operation", "op");
  check(
    same(current?.value, { state: "in_progress", n: replaced.indexOf(true) }),
    "the record is the winning replace's",
  );
  check(current !== undefined && current.version !== entry.version, "replace gives a new version");
}

async function roundTrips(store: CompanyStore, now: Date): Promise<void> {
  const samples = recordSamples(now);
  const kinds = Object.values(RecordKinds);
  check(
    kinds.length === Object.keys(samples).length && kinds.every((kind) => kind in samples),
    "a sample of every record kind",
  );
  for (const kind of kinds) {
    const record = samples[kind];
    if (record === undefined) continue;
    await store.put(kind, `${kind}_key`, record);
    const entry = await store.get(kind, `${kind}_key`);
    check(same(entry?.value, record), `${kind}: the record round-trips`);
  }
}
