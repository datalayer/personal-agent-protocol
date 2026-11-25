/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Replacing a User ID at a Company (§5.1; guides, *Choosing user IDs*), as in Python's
 * `personal_agent_protocol.user_ids`.
 *
 * A User ID is stable, but not permanent. A Personal Agent MAY replace one User's ID at one
 * Company:
 *
 * - **when the User asks**, such as by clearing their data for the Company, as a browser lets
 *   them delete one site's cookies and site data;
 * - **on its own**, once 28 days have passed since it last used a Session with the ID
 *   (`USER_ID_UNUSED_AFTER_SECONDS`), and never while it holds a refresh token for the User
 *   there, however long the ID has gone unused.
 *
 * Apart from anonymous browsing and a change of the Company's identifier, it replaces User IDs
 * in no other case: a Company counts its Users and limits each one by them.
 *
 * `replaceUserId` does it in the order §5.1 asks:
 *
 * 1. **The current ID, between tasks.** It refuses an ID that is no longer the User's at the
 *    Company (`user_id_stale`), one replacement at a time, and while a Session uses the ID
 *    (`UserIdData.inUse`).
 * 2. **Sign out first.** With a refresh token for the User at the Company, the account would
 *    link the old ID and the new one: every refresh token is revoked, and the replacement stops
 *    if the Company doesn't acknowledge one.
 * 3. **Discard the old ID's identifiers and keys**: the DPoP key and the delegated key in their
 *    custodies, then what only the host holds (`UserIdData.discard`): the User's Agent IDs,
 *    `sid`s, the agent's browser's cookies and other site data for the Company, the IDs the
 *    Company gave it, such as `conversation_id`s and operation IDs, and responses it cached
 *    that the Company varied by Session or User.
 * 4. **A new ID**, last, from the `pap.pairwiseUserIdStore`. Nothing used or received under the
 *    old ID is sent under the new one, and the Company sees a new User: carts, conversations
 *    and other state don't carry over.
 *
 * The User may keep their own records of what they did at the Company, such as an order number
 * they need for a return, as long as the agent doesn't send them to the Company under the new
 * ID.
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import type { RefreshTokenClient, RefreshTokenContext } from "./accounts.js";
import type { DelegatedKeyCustody, DpopKeyCustody } from "./crypto.js";
import { PersonalAgentProtocolError } from "./errors.js";
import { Clocks, PairwiseUserIdStores, TokenStores, firstContribution, type PairwiseUserIdStore } from "./reactor.js";

/**
 * How long an ID goes unused before a Personal Agent may replace it on its own (§5.1): 28 days
 * since it last used a Session with it, and only with no refresh token held. In seconds.
 */
export const USER_ID_UNUSED_AFTER_SECONDS = 28 * 24 * 60 * 60;

/** Why an ID is replaced (§5.1): the User asked, or it went unused. */
export type ReplacementReason = "user_request" | "unused";

/**
 * A User ID was not replaced: `user_id_in_use`, `refresh_token_held`, `user_id_recently_used`,
 * `sign_out_failed`. Nothing of the old ID was discarded.
 */
export class UserIdError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; details?: Readonly<Record<string, unknown>>; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "UserIdError";
  }
}

/**
 * One User's ID at one Company: who (`tenantId`, `localUserId`), where (`company`, the
 * Company's identifier: its issuer, or `https://{organization.domain}` without one) and the
 * User ID itself, `pairwiseUserId`.
 */
export interface UserIdAtCompany {
  readonly tenantId: string;
  readonly localUserId: string;
  readonly company: string;
  readonly pairwiseUserId: string;
}

/**
 * What the host holds under a User ID that the SDK can't reach (§5.1).
 *
 * `inUse` says whether a task is using the ID now: a Session with it is open in a task the
 * agent is working on. An ID is replaced between tasks, never in the middle of one. The SDK
 * can't see the host's tasks, so the reservation is the host's: while `replaceUserId` is
 * awaited for a User at a Company, the host starts no task and no sign-in for them there, and
 * takes up again with the ID `replaceUserId` returns, or the old one when it threw.
 * `replaceUserId` itself runs one replacement at a time for a User at a Company, and refuses
 * an ID that is no longer theirs.
 *
 * `discard` removes everything the host kept under the ID, so none of it is ever sent to the
 * Company again: the User's Agent IDs, the Sessions and their `sid`s, access tokens, the
 * agent's browser's cookies and other site data for the Company, the IDs the Company gave
 * (conversation and operation IDs, carts), and responses cached that the Company varied by
 * Session or User (`TasksClient.forget`, `ServiceTokens.forget`). It throws when it couldn't:
 * the ID is then not replaced.
 */
export interface UserIdData {
  inUse(user: UserIdAtCompany): Promise<boolean>;
  discard(user: UserIdAtCompany): Promise<void>;
}

/**
 * A `pap.pairwiseUserIdStore` that can replace one User's ID at one Company (§5.1): a store of
 * random IDs with a new random one, `DerivedPairwiseUserIds` by its counter.
 */
export interface ReplaceablePairwiseUserIdStore extends PairwiseUserIdStore {
  /**
   * The new ID, when the store's ID is `expected`; a `RangeError` and no change when it is
   * another one, atomically.
   */
  replace(options: {
    readonly tenantId: string;
    readonly localUserId: string;
    readonly companyIssuer: string;
    readonly expected: string;
  }): Promise<string>;
}

/** A replacement that was made: the new User ID, and what signing out did first. */
export interface ReplacedUserId {
  readonly pairwiseUserId: string;
  /** Whether the agent held a refresh token for the User at the Company, and signed out. */
  readonly signedOut: boolean;
  /** How many refresh tokens it revoked. */
  readonly revoked: number;
}

/**
 * Whether a Personal Agent may replace an ID on its own (§5.1): 28 days have passed since it
 * last used a Session with it, and it holds no refresh token for the User at the Company. A
 * signed-in User keeps their ID until they clear the Company, however long it has gone unused;
 * after they sign out, the 28 days apply. Use one rule for every User, so the change singles no
 * one out.
 */
export function mayReplaceUnused(options: {
  readonly lastUsed: Date;
  readonly now: Date;
  readonly holdsRefreshToken: boolean;
}): boolean {
  return (
    !options.holdsRefreshToken &&
    options.now.getTime() - options.lastUsed.getTime() >= USER_ID_UNUSED_AFTER_SECONDS * 1000
  );
}

export interface ReplaceUserIdOptions {
  readonly user: UserIdAtCompany;
  /** The host's side: what it holds under the old ID. */
  readonly data: UserIdData;
  /** The custodies the host's `pap.dpopProver` and `pap.sessionSigner` keep the User's keys in. */
  readonly dpopKeys: DpopKeyCustody;
  readonly delegatedKeys: DelegatedKeyCustody;
  /**
   * `user_request` when the User asked, such as by clearing their data for the Company, and
   * `unused` when the agent ages the ID out on its own: then `lastUsed` says when it last used a
   * Session with the ID.
   */
  readonly reason: ReplacementReason;
  readonly lastUsed?: Date | undefined;
  /** All the refresh tokens the agent holds for the User at the Company, from every sign-in. */
  readonly refreshTokenReferences?: Iterable<string>;
  /** Needed to sign out first, when a refresh token is still stored. */
  readonly accounts?: RefreshTokenClient | undefined;
  readonly context?: RefreshTokenContext | undefined;
}

/**
 * Replace `user`'s ID at the Company, and return the new one (§5.1).
 *
 * With `reason: "unused"` the replacement is refused before 28 days (`user_id_recently_used`)
 * and while a refresh token is held (`refresh_token_held`). When a refresh token is still
 * stored, the agent signs out first (§5.5) with `accounts` and `context`, and stops
 * (`sign_out_failed`) unless the Company acknowledged every revocation. The old ID's DPoP and
 * delegated keys are forgotten, then what the host holds (`data`). The new ID comes last, from
 * a `pap.pairwiseUserIdStore` that can `replace`; until then the old ID is still the User's, so
 * a step that fails replaces nothing.
 */
export async function replaceUserId(
  reactor: ReactorPlatformView,
  options: ReplaceUserIdOptions,
): Promise<ReplacedUserId> {
  const { user, data } = options;
  const store = firstContribution(reactor, PairwiseUserIdStores, "pairwise user ID store") as Partial<
    ReplaceablePairwiseUserIdStore
  >;
  if (typeof store.replace !== "function" || typeof store.getOrCreate !== "function") {
    throw new TypeError("the pairwise user ID store can't replace an ID: it has no replace()");
  }
  const replaceable = store as ReplaceablePairwiseUserIdStore;
  const whom = { tenantId: user.tenantId, localUserId: user.localUserId, companyIssuer: user.company };
  // One replacement at a time for a User at a Company in this process; the store's own check
  // of the ID it replaces covers other processes.
  const key = JSON.stringify([user.tenantId, user.localUserId, user.company]);
  const before = replacing.get(key) ?? Promise.resolve();
  let release!: () => void;
  const mine = new Promise<void>((resolve) => (release = resolve));
  const queued = before.then(() => mine);
  replacing.set(key, queued);
  await before;
  try {
    return await replaceCurrent();
  } finally {
    release();
    if (replacing.get(key) === queued) replacing.delete(key);
  }

  async function replaceCurrent(): Promise<ReplacedUserId> {
  if ((await replaceable.getOrCreate(whom)) !== user.pairwiseUserId) {
    // Replaced already, or never the User's: nothing is checked or cleared for an ID that
    // isn't the current one.
    throw stale();
  }
  const references = [...new Set(options.refreshTokenReferences ?? [])];
  const held: string[] = [];
  if (references.length) {
    // Only then: a signed-out host needs no token store to replace an ID.
    const tokens = firstContribution(reactor, TokenStores, "token store");
    for (const reference of references) {
      if ((await tokens.get(reference)) !== undefined) held.push(reference);
    }
  }
  if (options.reason === "unused") {
    if (options.lastUsed === undefined) {
      throw new RangeError("an unused ID is replaced by when it was last used (lastUsed)");
    }
    if (held.length) {
      throw new UserIdError(
        "refresh_token_held",
        "A User ID isn't replaced on the agent's own while it holds a refresh token",
      );
    }
    const now = firstContribution(reactor, Clocks, "clock").now();
    if (!mayReplaceUnused({ lastUsed: options.lastUsed, now, holdsRefreshToken: false })) {
      throw new UserIdError(
        "user_id_recently_used",
        "A User ID is replaced on the agent's own only after 28 days unused",
      );
    }
  } else if (options.reason !== "user_request") {
    throw new RangeError("a User ID is replaced when the User asks, or once it went unused");
  }
  if (await data.inUse(user)) throw new UserIdError("user_id_in_use", "A User ID is replaced between tasks");
  let revoked = 0;
  if (held.length) {
    if (options.accounts === undefined || options.context === undefined) {
      throw new RangeError(
        "the agent holds a refresh token for the User: signing out first needs accounts and context",
      );
    }
    let result;
    try {
      result = await options.accounts.signOut(held, { context: options.context });
    } catch (cause) {
      if (!(cause instanceof PersonalAgentProtocolError)) throw cause;
      throw new UserIdError("sign_out_failed", "The agent could not sign out before replacing the User ID", {
        cause,
      });
    }
    if (!result.signedOut) {
      throw new UserIdError("sign_out_failed", "The agent could not sign out before replacing the User ID");
    }
    revoked = result.revoked;
  }
  const who = { tenantId: user.tenantId, issuer: user.company, sub: user.pairwiseUserId };
  await options.dpopKeys.forget(who);
  await options.delegatedKeys.forget(who);
  await data.discard(user);
  let replaced: string;
  try {
    replaced = await replaceable.replace({ ...whom, expected: user.pairwiseUserId });
  } catch (cause) {
    if (!(cause instanceof RangeError)) throw cause;
    throw stale(cause);
  }
  if (replaced === user.pairwiseUserId) {
    throw new Error("the pairwise user ID store returned the ID it was to replace");
  }
  return { pairwiseUserId: replaced, signedOut: held.length > 0, revoked };
  }
}

/** The replacements under way in this process, one at a time for a User at a Company. */
const replacing = new Map<string, Promise<void>>();

function stale(cause?: unknown): UserIdError {
  return new UserIdError(
    "user_id_stale",
    "The User ID to replace is no longer the User's ID at the Company",
    cause === undefined ? {} : { cause },
  );
}
