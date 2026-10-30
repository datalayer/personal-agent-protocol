/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

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
 * apart, values copied rather than shared, every live record of a kind read at
 * once (`records`), and a JSON round trip of every record kind the company keeps. `makeStore` returns a fresh, empty store (or
 * a promise of one); `now` is the clock the store judges expiry by;
 * `concurrency` is how many callers race for one record.
 *
 * `checkReplayCache` does the same for `pap.company.replayCache`: of
 * `concurrency` callers marking one identifier at once, exactly one wins, and the
 * identifier stays refused; distinct identifiers are all accepted.
 */

import type { ReplayCache } from "./points.js";
import {
  RecordKinds,
  type AccountAgent,
  type AccountFamily,
  type AccountGrant,
  type CompanyStore,
  type IdempotencyRecord,
  type IssuedAccessToken,
  type IssuedCode,
  type JoinCode,
  type JsonObject,
  type KnownClient,
  type MessageReceipt,
  type OperationProposal,
  type PendingAuthorization,
  type PendingDevice,
  type PendingMediated,
  type ReplayMark,
  type SignInAttempts,
  type StoredConversation,
  type StoredFeedback,
  type StoredOperation,
  type StoredRecord,
  type StoredSession,
  type UserCode,
  type WebSession,
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
  const web: WebSession = {
    clientId: "https://atlas.example",
    sid: "sid_1",
    pairwiseUserId: "usr_1",
    expiresAt: later,
    agentId: "agt_1",
    accountId: "acct_1",
    scopes: ["orders:read"],
    family: "fam_1",
  };
  const records: Record<string, object> = {
    [RecordKinds.session]: {
      clientId: "https://atlas.example",
      sid: "sid_1",
      pairwiseUserId: "usr_1",
      endsAt: later,
      agentId: "agt_1",
      ended: true,
    } satisfies StoredSession,
    [RecordKinds.accessToken]: {
      clientId: "https://atlas.example",
      accountId: "acct_1",
      scopes: ["orders:read", "orders:write"],
      expiresAt: later,
      family: "fam_1",
      resource: "https://shop.example/mcp",
    } satisfies IssuedAccessToken,
    [RecordKinds.refreshToken]: {
      accountId: "acct_1",
      clientId: "c",
      scopes: ["a", "b"],
      expiresAt: later,
      revoked: true,
      family: "fam_1",
      signedInAt: now.toISOString(),
    } satisfies AccountGrant,
    [RecordKinds.accountFamily]: {
      clientId: "c",
      accountId: "acct_1",
      tokens: ["t1", "t2"],
      accessTokens: ["a1"],
      revoked: true,
    } satisfies AccountFamily,
    [RecordKinds.accountAgent]: { families: ["fam_1", "fam_2"] } satisfies AccountAgent,
    [RecordKinds.client]: { extensions: { operations: "2" } } satisfies KnownClient,
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
      browserBinding: "bind",
    } satisfies PendingAuthorization,
    [RecordKinds.code]: {
      clientId: "c",
      redirectUri: "https://atlas.example/cb",
      codeChallenge: "chal",
      requested: ["a"],
      accountId: "acct_1",
      scopes: ["a"],
      expiresAt: later,
    } satisfies IssuedCode,
    [RecordKinds.mediated]: {
      clientId: "c",
      accountId: "acct_1",
      scopes: ["a"],
      codeReference: "ref",
      expiresAt: later,
      sentTo: "a•••@example.com",
      attemptKeys: ["k1", "k2"],
      attempts: 2,
      status: "failed",
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
      operationId: "op_1",
      action: "exchange",
      owner: ["c", "u"],
      key: "key",
      revisions: [
        {
          revision: "rev_1",
          summary: "Exchange the jacket.",
          terms: { order_id: "ord_1", price: { amount: "1.00", currency: "USD" } },
          expiresAt: later,
          request: "request",
          asked: "asked",
          withdrawn: true,
        },
      ],
      accountId: "acct_1",
      scopes: ["orders:write"],
      status: "performed",
      approved: "rev_1",
      approvedAt: now.toISOString(),
      outcome: { summary: "Exchanged.", data: { order: "ord_1" }, succeeded: true },
    } satisfies StoredOperation,
    [RecordKinds.proposal]: { operationId: "op_1" } satisfies OperationProposal,
    [RecordKinds.browserCookie]: web,
    [RecordKinds.joinCode]: { browser: "browser_digest", authorized: web } satisfies JoinCode,
    [RecordKinds.replay]: {} satisfies ReplayMark,
    [RecordKinds.signInAttempts]: { failures: 3, lockedUntil: later } satisfies SignInAttempts,
    [RecordKinds.feedback]: {
      reportId: "fb_1",
      task: "Pay with a gift card",
      description: "No gift card field.",
      clientId: "c",
      pairwiseUserId: "u",
      receivedAt: now.toISOString(),
    } satisfies StoredFeedback,
    [RecordKinds.idempotency]: {
      digest: "digest",
      status: 200,
      body: { summary: "Exchanged." },
    } satisfies IdempotencyRecord,
  };
  return records as Readonly<Record<string, JsonObject>>;
}

/** Check that the stores `makeStore` returns keep the company store contract. */
export async function checkStore(
  makeStore: () => CompanyStore | Promise<CompanyStore>,
  options: { readonly now?: () => Date; readonly concurrency?: number } = {},
): Promise<void> {
  const now = options.now ?? (() => new Date());
  const concurrency = options.concurrency ?? CONCURRENCY;
  check(concurrency >= 2, "concurrency must be at least 2");
  await absent(await makeStore());
  await present(await makeStore());
  await expiry(await makeStore(), now());
  await takeOnce(await makeStore(), concurrency);
  await createOnce(await makeStore(), concurrency);
  await compareAndSet(await makeStore(), concurrency);
  await roundTrips(await makeStore(), now());
  await records(await makeStore(), now());
}

/** Check that the caches `makeCache` returns accept each identifier exactly once. */
export async function checkReplayCache(
  makeCache: () => ReplayCache | Promise<ReplayCache>,
  options: { readonly now?: () => Date; readonly concurrency?: number } = {},
): Promise<void> {
  const now = options.now ?? (() => new Date());
  const concurrency = options.concurrency ?? CONCURRENCY;
  check(concurrency >= 2, "concurrency must be at least 2");
  const cache = await makeCache();
  const expiresAt = new Date(now().getTime() + 5 * 60 * 1000);
  const marked = await Promise.all(
    Array.from({ length: concurrency }, () => cache.markOnce("proof:one", { expiresAt })),
  );
  const wins = marked.filter(Boolean).length;
  check(wins === 1, `one identifier was accepted ${wins} times, not once`);
  check(!(await cache.markOnce("proof:one", { expiresAt })), "an accepted identifier stays refused until it expires");
  const distinct = await Promise.all(
    Array.from({ length: concurrency }, (_, n) => cache.markOnce(`proof:${n}:distinct`, { expiresAt })),
  );
  check(distinct.every(Boolean), "distinct identifiers are each accepted");
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

async function takeOnce(store: CompanyStore, concurrency: number): Promise<void> {
  await store.put("authorization", "once", { a: 1 });
  const taken = await Promise.all(
    Array.from({ length: concurrency }, () => store.take("authorization", "once")),
  );
  const winners = taken.filter((value) => value !== undefined);
  check(winners.length === 1, `take returned the record ${winners.length} times, not once`);
  check(same(winners[0], { a: 1 }), "take returns the value");
  check((await store.get("authorization", "once")) === undefined, "a taken record is gone");
}

async function createOnce(store: CompanyStore, concurrency: number): Promise<void> {
  const created = await Promise.all(
    Array.from({ length: concurrency }, (_, n) => store.create("message_id", "m", { n })),
  );
  const wins = created.filter(Boolean).length;
  check(wins === 1, `create succeeded ${wins} times, not once`);
  const entry = await store.get("message_id", "m");
  check(same(entry?.value, { n: created.indexOf(true) }), "the record is the one whose create succeeded");
  check(!(await store.create("message_id", "m", { n: -1 })), "create of a present record");
}

async function compareAndSet(store: CompanyStore, concurrency: number): Promise<void> {
  await store.put("operation", "op", { state: "proposed" });
  const entry = await store.get("operation", "op");
  check(entry !== undefined, "the record is present");
  if (entry === undefined) return;
  const replaced = await Promise.all(
    Array.from({ length: concurrency }, (_, n) =>
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

async function records(store: CompanyStore, now: Date): Promise<void> {
  const later = new Date(now.getTime() + 60 * 60 * 1000);
  await store.put("operation", "a", { n: 1 });
  await store.put("operation", "b", { n: 2 }, { expiresAt: later });
  await store.put("operation", "gone", { n: 3 }, { expiresAt: new Date(now.getTime() - 1000) });
  await store.put("operation", "taken", { n: 4 });
  await store.take("operation", "taken");
  await store.put("operation", "deleted", { n: 5 });
  await store.delete("operation", "deleted");
  await store.put("conversation", "a", { n: 6 });
  const numbers = (found: readonly StoredRecord[]): number[] =>
    found.map((record) => record.value.n as number).sort((x, y) => x - y);
  const found = await store.records("operation");
  check(
    same(numbers(found), [1, 2]),
    "records reads every live record of its kind: nothing expired, taken, deleted or of another kind",
  );
  for (const record of found) {
    const entry = await store.get("operation", record.value.n === 1 ? "a" : "b");
    check(
      entry !== undefined &&
        entry.version === record.version &&
        entry.expiresAt?.getTime() === record.expiresAt?.getTime(),
      "records gives each record's version and expiry, as get does",
    );
    (record.value as { n: number }).n = 0;
  }
  check(same(numbers(await store.records("operation")), [1, 2]), "records returns copies");
  check((await store.records("device")).length === 0, "records of a kind with nothing live");
}
