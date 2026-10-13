/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * PAP's displays for Reactor's ui channel (`@datalayer/reactor/ui`), as a
 * page receives them: the TypeScript side of `personal_agent_protocol.ui`.
 *
 * A display is declared once, in Python (`PapConfirm`, `PapOutcome`: pydantic
 * models with `@display_type`); this module types its wire form and checks it
 * with a guard, against the same committed examples the Python tests write
 * (`protocol/fixtures/pap-confirm-display.json`, `pap-outcome-display.json`). It needs no runtime from
 * Reactor: the guard takes any display-shaped value, so Reactor's `Display`
 * narrows to a `PapConfirmDisplay`.
 */

/** The display type of an operation waiting for the person to confirm it. */
export const PAP_CONFIRM_TYPE = "application/vnd.datalayer.pap.confirm+json";

/** The version of `PAP_CONFIRM_TYPE` this module reads. */
export const PAP_CONFIRM_VERSION = 1;

/** What confirming an operation does, as an application's Rules class it. */
export type PapActionClass = "read" | "write" | "send" | "buy" | "delete" | "publish";

/** Every `PapActionClass`, in the Rules' order. */
export const PAP_ACTION_CLASSES: readonly PapActionClass[] = [
  "read",
  "write",
  "send",
  "buy",
  "delete",
  "publish",
];

/**
 * The Session an operation is confirmed in: a one-way reference (12 hex
 * digits of the SHA-256 of its ID — never the ID, never the Session Token)
 * and whether the person is signed in there. The page sees the reference; a
 * model is told only `signed_in`.
 */
export type PapSessionShown = { ref: string; signed_in: boolean };

/** The revision a revised operation replaced, and its terms. */
export type PapTermsWas = { revision: number; terms: Record<string, unknown> };

/** An operation to confirm, as a display's `data` (`PapConfirm`'s fields). */
export type PapConfirmData = {
  /** The company, as the person knows it (its domain or its name). */
  company: string;
  /** The company's own words, shown verbatim, never rephrased. */
  summary: string;
  terms: Record<string, unknown>;
  /** The operation's reference at the company; with `revision`, what is confirmed. */
  operation_ref: string;
  revision: number;
  /** What confirming it does, as an application's Rules class it; null when not said. */
  does: PapActionClass | null;
  session: PapSessionShown | null;
  /** Until when the company holds these terms (ISO 8601). */
  expires_at: string | null;
  /** The revision it replaced, when the company changed its terms. */
  was: PapTermsWas | null;
  /** Only the person's own decision confirms it: no approval given in advance covers it. */
  only_the_person: boolean;
};

/** A display of an operation to confirm, as the page receives it. */
export type PapConfirmDisplay = {
  type: typeof PAP_CONFIRM_TYPE;
  version: typeof PAP_CONFIRM_VERSION;
  id: string;
  text: string;
  data: PapConfirmData;
  actions?: unknown[];
};

/** Anything shaped like a display: Reactor's `Display`, or a tool result's `_meta["reactor.ui/display"]`. */
export type DisplayLike = { type: string; version?: number; id?: string; text?: string; data?: unknown };

const DATA_KEYS = [
  "company",
  "summary",
  "terms",
  "operation_ref",
  "revision",
  "does",
  "session",
  "expires_at",
  "was",
  "only_the_person",
] as const;

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasExactly = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
};

const isRevision = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 1;

const isFilled = (value: unknown): value is string => typeof value === "string" && value.trim() !== "";

/** Whether a value is a `PapSessionShown`: a 12-hex-digit reference and `signed_in`, nothing else. */
export function isPapSessionShown(value: unknown): value is PapSessionShown {
  return (
    isObject(value) &&
    hasExactly(value, ["ref", "signed_in"]) &&
    typeof value.ref === "string" &&
    /^[0-9a-f]{12}$/.test(value.ref) &&
    typeof value.signed_in === "boolean"
  );
}

/**
 * Whether a value is an operation to confirm's `data`, as `PapConfirm` sends
 * it: every field, of its type, and no other (a member nobody declared is
 * refused, as the Python model refuses it).
 */
export function isPapConfirmData(value: unknown): value is PapConfirmData {
  if (!isObject(value) || !hasExactly(value, DATA_KEYS)) return false;
  const { company, summary, terms, operation_ref, revision, does, session, expires_at, was, only_the_person } =
    value;
  if (!isFilled(company) || !isFilled(summary) || !isFilled(operation_ref)) return false;
  if (!isObject(terms) || !isRevision(revision)) return false;
  if (does !== null && !PAP_ACTION_CLASSES.includes(does as PapActionClass)) return false;
  if (session !== null && !isPapSessionShown(session)) return false;
  if (expires_at !== null && (typeof expires_at !== "string" || Number.isNaN(Date.parse(expires_at)))) {
    return false;
  }
  if (was !== null) {
    if (!isObject(was) || !hasExactly(was, ["revision", "terms"])) return false;
    if (!isRevision(was.revision) || was.revision >= revision || !isObject(was.terms)) return false;
  }
  return typeof only_the_person === "boolean";
}

/** Whether a display is an operation to confirm, of the version this SDK reads. */
export function isPapConfirm<D extends DisplayLike>(display: D): display is D & PapConfirmDisplay {
  return (
    display.type === PAP_CONFIRM_TYPE &&
    display.version === PAP_CONFIRM_VERSION &&
    typeof display.id === "string" &&
    typeof display.text === "string" &&
    isPapConfirmData(display.data)
  );
}

/** What an operation to confirm reads as without a renderer: `PapConfirm.text()`, word for word. */
export function papConfirmText(data: PapConfirmData): string {
  const said = `${data.company} asks you to confirm: ${data.summary} (version ${data.revision})`;
  return data.was ? `${said} Changed since version ${data.was.revision}.` : said;
}

/** An operation to confirm as its display, `text` included; throws when `data` is not one. */
export function papConfirmDisplay(id: string, data: PapConfirmData): PapConfirmDisplay {
  if (!id || !isPapConfirmData(data)) {
    throw new TypeError("Not an operation to confirm: PapConfirm's fields, each of its type, and no other");
  }
  return { type: PAP_CONFIRM_TYPE, version: PAP_CONFIRM_VERSION, id, text: papConfirmText(data), data, actions: [] };
}

/** The display type of what a confirmed operation came to. */
export const PAP_OUTCOME_TYPE = "application/vnd.datalayer.pap.outcome+json";

/** The version of `PAP_OUTCOME_TYPE` this module reads. */
export const PAP_OUTCOME_VERSION = 1;

/** What a confirmed operation came to: every operation state but `proposed`. */
export type PapOutcomeState = "in_progress" | "succeeded" | "failed" | "cancelled" | "expired";

/** Every `PapOutcomeState`. */
export const PAP_OUTCOME_STATES: readonly PapOutcomeState[] = [
  "in_progress",
  "succeeded",
  "failed",
  "cancelled",
  "expired",
];

/** What a confirmed operation came to, as a display's `data` (`PapOutcome`'s fields). */
export type PapOutcomeData = {
  /** The company, as the person knows it (its domain or its name). */
  company: string;
  /** What was confirmed, in the company's words. */
  summary: string;
  operation_ref: string;
  revision: number;
  state: PapOutcomeState;
  /**
   * The company's final `result.summary`, verbatim — a failed operation's
   * partial effects included; null while in progress, never null once final.
   */
  result: string | null;
  /** Who confirmed it: the person, or a standing permission they gave; null when read back. */
  approved_by: "user" | "standing_permission" | null;
};

/** A display of what a confirmed operation came to, as the page receives it. */
export type PapOutcomeDisplay = {
  type: typeof PAP_OUTCOME_TYPE;
  version: typeof PAP_OUTCOME_VERSION;
  id: string;
  text: string;
  data: PapOutcomeData;
  actions?: unknown[];
};

const OUTCOME_KEYS = ["company", "summary", "operation_ref", "revision", "state", "result", "approved_by"] as const;

const OUTCOME_LEADS: Record<PapOutcomeState, string> = {
  succeeded: "Done at",
  failed: "Failed at",
  in_progress: "Still in progress at",
  cancelled: "Cancelled at",
  expired: "Expired at",
};

/**
 * Whether a value is an outcome's `data`, as `PapOutcome` sends it: every
 * field, of its type, and no other; a result once final and none before.
 */
export function isPapOutcomeData(value: unknown): value is PapOutcomeData {
  if (!isObject(value) || !hasExactly(value, OUTCOME_KEYS)) return false;
  const { company, summary, operation_ref, revision, state, result, approved_by } = value;
  if (!isFilled(company) || !isFilled(summary) || !isFilled(operation_ref) || !isRevision(revision)) return false;
  if (!PAP_OUTCOME_STATES.includes(state as PapOutcomeState)) return false;
  if (state === "in_progress" ? result !== null : !isFilled(result)) return false;
  return approved_by === null || approved_by === "user" || approved_by === "standing_permission";
}

/** Whether a display is what a confirmed operation came to, of the version this SDK reads. */
export function isPapOutcome<D extends DisplayLike>(display: D): display is D & PapOutcomeDisplay {
  return (
    display.type === PAP_OUTCOME_TYPE &&
    display.version === PAP_OUTCOME_VERSION &&
    typeof display.id === "string" &&
    typeof display.text === "string" &&
    isPapOutcomeData(display.data)
  );
}

/** What an outcome reads as without a renderer: `PapOutcome.text()`, word for word. */
export function papOutcomeText(data: PapOutcomeData): string {
  const lead = `${OUTCOME_LEADS[data.state]} ${data.company}`;
  return data.result === null
    ? `${lead}: ${data.summary} (version ${data.revision}) The outcome is not known yet.`
    : `${lead}: ${data.result} (version ${data.revision})`;
}

/** An outcome as its display, `text` included; throws when `data` is not one. */
export function papOutcomeDisplay(id: string, data: PapOutcomeData): PapOutcomeDisplay {
  if (!id || !isPapOutcomeData(data)) {
    throw new TypeError("Not an operation's outcome: PapOutcome's fields, each of its type, and no other");
  }
  return { type: PAP_OUTCOME_TYPE, version: PAP_OUTCOME_VERSION, id, text: papOutcomeText(data), data, actions: [] };
}

/** The display type of what a company answered in a conversation. */
export const PAP_REPLIES_TYPE = "application/vnd.datalayer.pap.replies+json";

/** The version of `PAP_REPLIES_TYPE` this module reads: 2 names the conversation. */
export const PAP_REPLIES_VERSION = 2;

/** Where a conversation stands (§7.8), apart from who answers in it. */
export type PapConversationStatus = "working" | "idle" | "queued" | "closed";

/** Every `PapConversationStatus`. */
export const PAP_CONVERSATION_STATUSES: readonly PapConversationStatus[] = ["working", "idle", "queued", "closed"];

/** One message a company wrote, and who wrote it there: its agent or one of its people. */
export type PapReply = { sender: "agent" | "human"; text: string };

/** What a company answered, as a display's `data` (`PapReplies`' fields). */
export type PapRepliesData = {
  /** The company, as the person knows it (its domain or its name). */
  company: string;
  /**
   * The conversation the replies are in, by the company's id for it: where the
   * person's own words open a Direct Conversation under it (§7.10), typed on
   * the page, never through the model.
   */
  conversation: string;
  /** Its replies, each in its words, verbatim, with who wrote it. */
  replies: PapReply[];
  status: PapConversationStatus | null;
  /** Who answers the conversation now. */
  responder: "agent" | "human" | null;
};

/** A display of what a company answered, as the page receives it. */
export type PapRepliesDisplay = {
  type: typeof PAP_REPLIES_TYPE;
  version: typeof PAP_REPLIES_VERSION;
  id: string;
  text: string;
  data: PapRepliesData;
  actions?: unknown[];
};

const REPLIES_KEYS = ["company", "conversation", "replies", "status", "responder"] as const;

const isConversationId = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_-]{1,256}$/.test(value);

const isSender = (value: unknown): value is "agent" | "human" => value === "agent" || value === "human";

const isReply = (value: unknown): value is PapReply =>
  isObject(value) && hasExactly(value, ["sender", "text"]) && isSender(value.sender) && isFilled(value.text);

/**
 * Whether a value is the `data` of what a company answered, as `PapReplies`
 * sends it: at least one reply, each with who wrote it, and nothing else.
 */
export function isPapRepliesData(value: unknown): value is PapRepliesData {
  if (!isObject(value) || !hasExactly(value, REPLIES_KEYS)) return false;
  const { company, conversation, replies, status, responder } = value;
  if (!isFilled(company) || !isConversationId(conversation)) return false;
  if (!Array.isArray(replies) || replies.length === 0 || !replies.every(isReply)) return false;
  if (status !== null && !PAP_CONVERSATION_STATUSES.includes(status as PapConversationStatus)) return false;
  return responder === null || isSender(responder);
}

/** Whether a display is what a company answered, of the version this SDK reads. */
export function isPapReplies<D extends DisplayLike>(display: D): display is D & PapRepliesDisplay {
  return (
    display.type === PAP_REPLIES_TYPE &&
    display.version === PAP_REPLIES_VERSION &&
    typeof display.id === "string" &&
    typeof display.text === "string" &&
    isPapRepliesData(display.data)
  );
}

const WROTE: Record<PapReply["sender"], string> = { agent: "its agent", human: "one of its people" };

/** What the replies read as without a renderer: `PapReplies.text()`, word for word. */
export function papRepliesText(data: PapRepliesData): string {
  return data.replies.map((reply) => `${data.company}, ${WROTE[reply.sender]}: ${reply.text}`).join("\n");
}

/** What a company answered as its display, `text` included; throws when `data` is not one. */
export function papRepliesDisplay(id: string, data: PapRepliesData): PapRepliesDisplay {
  if (!id || !isPapRepliesData(data)) {
    throw new TypeError("Not a company's replies: PapReplies' fields, each of its type, and no other");
  }
  return { type: PAP_REPLIES_TYPE, version: PAP_REPLIES_VERSION, id, text: papRepliesText(data), data, actions: [] };
}
