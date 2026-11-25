/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Pairwise user identifiers derived with a keyed hash (§5.1; guides, *Choosing user IDs*), as
 * in Python's `personal_agent_protocol.pairwise`.
 *
 * A User ID is stable, but not permanent: a Personal Agent may replace one User's ID at a
 * Company when the User asks, and on its own once it went unused for 28 days with no refresh
 * token held (`replaceUserId`). Both ways of choosing IDs the guides describe can do it:
 *
 * - **A random ID, stored**: the host's `pap.pairwiseUserIdStore` stores a new random ID in its
 *   place (`replace`), and the old one is gone.
 * - **A keyed hash** (`derivePairwiseUserId`, `DerivedPairwiseUserIds`): HMAC-SHA256 of the
 *   internal user ID and the Company's identifier with a secret key. The key never changes,
 *   since that would replace every ID at once; one User's ID at one Company is replaced by a
 *   counter for that User and Company, included in what is hashed and increased
 *   (`PairwiseCounters`).
 */

import { base64Url } from "./crypto.js";

/** The shortest key `derivePairwiseUserId` takes: 256 bits. */
export const PAIRWISE_KEY_MIN_BYTES = 32;

/** One User at one Company: the tenant, the internal user ID, the Company's identifier. */
export interface PairwiseWho {
  readonly tenantId: string;
  readonly localUserId: string;
  readonly companyIssuer: string;
}

function keyPart(value: string, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || value.includes("\0")) {
    throw new RangeError(`${label} must contain between 1 and 256 safe characters`);
  }
  return value;
}

function issuer(value: string): string {
  let parsed: URL | undefined;
  try {
    parsed = new URL(value);
  } catch {
    parsed = undefined;
  }
  if (
    parsed === undefined ||
    parsed.protocol !== "https:" ||
    !parsed.hostname ||
    parsed.username ||
    parsed.password ||
    value.includes("?") ||
    value.includes("#")
  ) {
    throw new RangeError("company issuer must be an HTTPS issuer without query or fragment");
  }
  return value;
}

function keyParts(who: PairwiseWho): readonly [string, string, string] {
  return [keyPart(who.tenantId, "tenantId"), keyPart(who.localUserId, "localUserId"), issuer(who.companyIssuer)];
}

/**
 * The User ID a keyed hash gives one User at one Company (§5.1; guides, *Choosing user IDs*):
 * HMAC-SHA256, with a secret `key`, of the tenant, the internal user ID, the Company's
 * identifier (its issuer, or its HTTPS domain without one) and `counter`.
 *
 * The same inputs always give the same ID, here and in the Python SDK, so nothing is stored but
 * the key and the counters. Never change the key: that replaces every User's ID at once, which
 * §5.1 doesn't allow. To replace one User's ID at one Company, increase that User's `counter`
 * for that Company (`DerivedPairwiseUserIds.replace`).
 *
 * `localUserId` is an internal identifier, never personal information such as an email
 * address, phone number or name, nor a hash of it: a User ID MUST NOT be derived from personal
 * information, keyed or not (§5.1).
 */
export async function derivePairwiseUserId(
  key: Uint8Array,
  who: PairwiseWho & { readonly counter?: number },
): Promise<string> {
  if (!(key instanceof Uint8Array) || key.byteLength < PAIRWISE_KEY_MIN_BYTES) {
    throw new RangeError(`the key has at least ${PAIRWISE_KEY_MIN_BYTES} bytes`);
  }
  const counter = who.counter ?? 0;
  if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError("counter is zero or more");
  // Each part with its length, so no two inputs hash the same bytes.
  const encoder = new TextEncoder();
  const parts = ["pap-user-id", ...keyParts(who), String(counter)].map((part) => encoder.encode(part));
  const message = new Uint8Array(parts.reduce((total, part) => total + 4 + part.byteLength, 0));
  const view = new DataView(message.buffer);
  let at = 0;
  for (const part of parts) {
    view.setUint32(at, part.byteLength, false);
    message.set(part, at + 4);
    at += 4 + part.byteLength;
  }
  const imported = await crypto.subtle.importKey(
    "raw",
    key as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", imported, message as BufferSource));
  return `usr_${base64Url(digest)}`;
}

/**
 * One counter for each User and Company, zero until increased: what a keyed hash includes to
 * replace one User's ID (guides, *Choosing user IDs*). Durable, and shared by every process
 * that derives IDs: a counter that went back would bring an old ID back.
 */
export interface PairwiseCounters {
  get(who: PairwiseWho): Promise<number>;
  /**
   * The counter increased by one, when it is `expected`; a `RangeError` and no change when it
   * is another value, atomically.
   */
  increase(who: PairwiseWho, expected: number): Promise<number>;
}

/**
 * A `pap.pairwiseUserIdStore` that derives each ID with a keyed hash, and replaces one User's
 * ID at one Company by increasing its counter (§5.1; guides, *Choosing user IDs*). The key is
 * the host's secret, kept for as long as the IDs are.
 */
export class DerivedPairwiseUserIds {
  readonly #key: Uint8Array;
  readonly #counters: PairwiseCounters;

  constructor(key: Uint8Array, options: { readonly counters: PairwiseCounters }) {
    if (!(key instanceof Uint8Array) || key.byteLength < PAIRWISE_KEY_MIN_BYTES) {
      throw new RangeError(`the key has at least ${PAIRWISE_KEY_MIN_BYTES} bytes`);
    }
    // A copy the store owns: a Node.js Buffer's `slice` shares its memory.
    this.#key = new Uint8Array(key);
    this.#counters = options.counters;
  }

  async getOrCreate(who: PairwiseWho): Promise<string> {
    keyParts(who);
    return derivePairwiseUserId(this.#key, { ...who, counter: await this.#counters.get(who) });
  }

  /**
   * Increase the User's counter at the Company, and return the ID it now gives: only as the
   * last step of `replaceUserId`. `expected` is the ID being replaced: when the counter gives
   * another one, a `RangeError` and no change.
   */
  async replace(who: PairwiseWho & { readonly expected: string }): Promise<string> {
    keyParts(who);
    const { expected, ...whom } = who;
    const counter = await this.#counters.get(whom);
    if ((await derivePairwiseUserId(this.#key, { ...whom, counter })) !== expected) {
      throw new RangeError("the counter gives another User ID than the one to replace");
    }
    return derivePairwiseUserId(this.#key, { ...whom, counter: await this.#counters.increase(whom, counter) });
  }
}
