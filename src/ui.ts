/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * PAP's displays for Reactor's ui channel (`@datalayer/reactor/ui`), as a
 * page receives them: the TypeScript side of `personal_agent_protocol.ui`.
 *
 * A display is declared once, in Python (`PapConfirm`, `PapReplies`: pydantic
 * models with `@display_type`); this module types its wire form and checks it
 * with a guard, against the same committed examples the Python tests write
 * (`protocol/fixtures/pap-confirm-display.json`). It needs no runtime from
 * Reactor: the guard takes any display-shaped value, so Reactor's `Display`
 * narrows to a `PapConfirmDisplay`.
 */

import { knownResponder, knownStatus } from "./models.js";

/** The display type of an operation waiting for the person's approval. */
export const PAP_CONFIRM_TYPE = "application/vnd.datalayer.pap.confirm+json";

/** The version of `PAP_CONFIRM_TYPE` this module reads. */
export const PAP_CONFIRM_VERSION = 2;

/** What approving an operation does, as an application's Rules class it. */
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
 * The Session an operation is approved in: a one-way reference (12 hex
 * digits of the SHA-256 of its ID — never the ID, never an access token)
 * and whether the person is signed in there. The page sees the reference; a
 * model is told only `signed_in`.
 */
export type PapSessionShown = { ref: string; signed_in: boolean };

/** The revision a revised operation replaced, and its terms. */
export type PapTermsWas = { revision: string; terms: Record<string, unknown> };

/** An operation to approve, as a display's `data` (`PapConfirm`'s fields). */
export type PapConfirmData = {
  /** The Company's name (`organization.name`), or its domain. */
  company: string;
  /** The company's own words, shown verbatim as text, never rephrased. */
  summary: string;
  terms: Record<string, unknown>;
  /** The operation's ID at the company; with `revision`, what is approved. */
  operation_ref: string;
  /** Opaque (Operations 3). */
  revision: string;
  /** The last time an approval of this revision is accepted (ISO 8601). */
  expires_at: string;
  /** Where the terms disagree with the summary or with what was asked for. */
  differences: string[];
  /** What approving it does, as an application's Rules class it; null when not said. */
  does: PapActionClass | null;
  session: PapSessionShown | null;
  /** The revision it replaced, when the terms changed. */
  was: PapTermsWas | null;
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
  "expires_at",
  "differences",
  "does",
  "session",
  "was",
] as const;

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const hasExactly = (value: Record<string, unknown>, keys: readonly string[]): boolean => {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((key) => Object.hasOwn(value, key));
};

const isRevision = (value: unknown): value is string =>
  typeof value === "string" && /^[A-Za-z0-9_-]{1,256}$/.test(value);

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
 * Whether a value is an operation to approve's `data`, as `PapConfirm` sends
 * it: every field, of its type, and no other (a member nobody declared is
 * refused, as the Python model refuses it).
 */
export function isPapConfirmData(value: unknown): value is PapConfirmData {
  if (!isObject(value) || !hasExactly(value, DATA_KEYS)) return false;
  const { company, summary, terms, operation_ref, revision, expires_at, differences, does, session, was } = value;
  if (!isFilled(company) || !isFilled(summary) || !isFilled(operation_ref)) return false;
  if (!isObject(terms) || !isRevision(revision)) return false;
  if (typeof expires_at !== "string" || Number.isNaN(Date.parse(expires_at))) return false;
  if (!Array.isArray(differences) || differences.some((item) => typeof item !== "string")) return false;
  if (does !== null && !PAP_ACTION_CLASSES.includes(does as PapActionClass)) return false;
  if (session !== null && !isPapSessionShown(session)) return false;
  if (was !== null) {
    if (!isObject(was) || !hasExactly(was, ["revision", "terms"])) return false;
    if (!isRevision(was.revision) || was.revision === revision || !isObject(was.terms)) return false;
  }
  return true;
}

/** Whether a display is an operation to approve, of the version this SDK reads. */
export function isPapConfirm<D extends DisplayLike>(display: D): display is D & PapConfirmDisplay {
  return (
    display.type === PAP_CONFIRM_TYPE &&
    display.version === PAP_CONFIRM_VERSION &&
    typeof display.id === "string" &&
    typeof display.text === "string" &&
    isPapConfirmData(display.data)
  );
}

/** What makes a link, an image or HTML of a summary, in CommonMark and its autolinks. */
const ACTIVE = /[\\[\]<>@]|:\/\/|www\./g;

/**
 * A summary whose links, images and HTML show as text, wherever it is rendered.
 *
 * A summary can't send the User elsewhere or load content while they decide (Operations 3):
 * their markup is escaped, in the Markdown a chat renders. Emphasis, paragraphs and lists stay.
 * Text a host shows as text needs none of this: it shows the summary as it is.
 */
export function inertSummary(summary: string): string {
  return summary.replace(ACTIVE, (active) => {
    if (active === "://") return "\\://";
    if (active === "www.") return "www\\.";
    return `\\${active}`;
  });
}

/** What an operation to approve reads as without a renderer: `PapConfirm.text()`, word for word. */
export function papConfirmText(data: PapConfirmData): string {
  const expires = new Date(data.expires_at).toISOString().replace(/\.\d{3}Z$/, "+00:00");
  let said = `${data.company} asks you to approve: ${inertSummary(data.summary)} (revision ${data.revision}, until ${expires})`;
  if (data.was) said += " The terms changed since you saw them.";
  for (const difference of data.differences) said += ` Check: ${difference}`;
  return said;
}

/** An operation to approve as its display, `text` included; throws when `data` is not one. */
export function papConfirmDisplay(id: string, data: PapConfirmData): PapConfirmDisplay {
  if (!id || !isPapConfirmData(data)) {
    throw new TypeError("Not an operation to approve: PapConfirm's fields, each of its type, and no other");
  }
  return { type: PAP_CONFIRM_TYPE, version: PAP_CONFIRM_VERSION, id, text: papConfirmText(data), data, actions: [] };
}

/** The display type of what a company answered in a conversation. */
export const PAP_REPLIES_TYPE = "application/vnd.datalayer.pap.replies+json";

/**
 * The version of `PAP_REPLIES_TYPE` this module reads: 2 names the conversation, 3 gives
 * each reply its `author` and, when the company gives one, the writer's `name`.
 */
export const PAP_REPLIES_VERSION = 3;

/** Where a conversation stands (§7.8), apart from who answers in it. */
export type PapConversationStatus = "working" | "idle" | "queued" | "closed";

/** Every `PapConversationStatus`. */
export const PAP_CONVERSATION_STATUSES: readonly PapConversationStatus[] = ["working", "idle", "queued", "closed"];

/**
 * One message a company wrote, and who wrote it there: its agent or one of its people
 * (`author.type`, §7.4, §7.8), with the writer's display name when the company gives one
 * (`author.name`), else `null`.
 */
export type PapReply = { author: "agent" | "human"; name: string | null; text: string };

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
  isObject(value) &&
  hasExactly(value, ["author", "name", "text"]) &&
  isSender(value.author) &&
  (value.name === null || isFilled(value.name)) &&
  isFilled(value.text);

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

const WROTE: Record<PapReply["author"], string> = { agent: "its agent", human: "one of its people" };

/** What the replies read as without a renderer: `PapReplies.text()`, word for word. */
export function papRepliesText(data: PapRepliesData): string {
  return data.replies
    .map((reply) => `${data.company}, ${WROTE[reply.author]}${reply.name ? ` (${reply.name})` : ""}: ${reply.text}`)
    .join("\n");
}

/**
 * What a company answered as its display, `text` included; throws when `data` is not one.
 *
 * A `status` or `responder` of a later version reads as the most careful known one: `working`
 * and `human` (§8.7), so a display only ever carries the values above.
 */
export function papRepliesDisplay(id: string, data: PapRepliesData): PapRepliesDisplay {
  const read: unknown =
    typeof data === "object" && data !== null
      ? {
          ...data,
          status: typeof data.status === "string" ? knownStatus(data.status) : data.status,
          responder: typeof data.responder === "string" ? knownResponder(data.responder) : data.responder,
        }
      : data;
  if (!id || !isPapRepliesData(read)) {
    throw new TypeError("Not a company's replies: PapReplies' fields, each of its type, and no other");
  }
  return { type: PAP_REPLIES_TYPE, version: PAP_REPLIES_VERSION, id, text: papRepliesText(read), data: read, actions: [] };
}
