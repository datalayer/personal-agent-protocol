/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * PAP's displays for Reactor's ui channel (`@datalayer/reactor/ui`), as a
 * page receives them: the TypeScript side of `personal_agent_protocol.ui`.
 *
 * A display is declared once, in Python (`PapConfirm`, a pydantic model with
 * `@display_type`); this module types its wire form and checks it with a
 * guard, against the same committed example the Python tests write
 * (`protocol/fixtures/pap-confirm-display.json`). It needs no runtime from
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
export type DisplayLike = { type: string; version: number; id?: string; text?: string; data?: unknown };

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
