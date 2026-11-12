/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { PersonalAgentProtocolError, TransportError } from "./errors.js";
import {
  operationShown,
  parseApproval,
  parseApprovalDeclined,
  parseOperation,
  termsLeaves,
  type Approval,
  type ApprovalDeclined,
  type DiscoveryDocument,
  type Operation,
  type Organization,
  companyExtension,
} from "./models.js";
import type { PapSession } from "./sessions.js";
import {
  ApprovalSurfaces,
  Clocks,
  RandomSources,
  firstContribution,
  optionalContribution,
  type ApprovalRequest,
  type ApprovalSurface,
} from "./reactor.js";
import { operationResult, traced } from "./telemetry.js";

/**
 * PAP Operations extension, version 3: exact approval, at most once.
 *
 * A company that wants approval for an action refuses the request and returns the operation:
 * the terms as JSON, and usually in plain language too. The terms are approved, by the user or
 * by the personal agent on an instruction the user gave it, and the agent makes the same
 * request again with the approval, through the interface that returned the operation:
 *
 * - an API's `403` with `error: approval_required` and `operation`, answered by the same
 *   request with the `Poppy-Approval` header (`ApiClient.call(..., { approval })`);
 * - an MCP tool's error result with `structuredContent.operation`, answered by the same call
 *   with `_meta["personalagentprotocol.org/approval"]` (`McpClient.callTool(..., { approval })`);
 * - a company message's `operation`, answered by a message with `approval`.
 *
 * Operations a website returns to a joined browser (`Poppy-Operation`, the extension's
 * `endpoint`) are not implemented by this client: a host that joins a browser to a Session
 * declares no `operations` on that join until they are.
 *
 * What this client guarantees on the personal agent's side:
 *
 * - **Negotiation.** Operations are used only when the company's `poppy.json` lists
 *   `operations` version 3 and the Session declares it. Version 2 is another major version: it
 *   does not count, and nothing here speaks it.
 * - **Who approved.** Every approval says `approver`. `OperationsClient.askUser` asks the
 *   host's own approval surface (`pap.approvalSurface`), naming the company and the revision's
 *   terms: only the surface's `true` makes a `user` approval, and nothing here reads
 *   conversation text as approval. `OperationsClient.approveAsAgent` makes an `agent` approval
 *   only on an `AgentInstruction` the host holds from the user, and only when the instruction's
 *   own check says it covers the revision's terms; when it can't tell, when the terms differ
 *   from what was asked, or when the company answered an earlier agent approval of the action
 *   with new terms or declined one, it is `ask_user`.
 * - **Exact terms.** `termsDifferences` checks `terms` against what the agent asked for and
 *   against the `summary` when there is one. An approval covers one revision.
 * - **Declines.** A company may decline an approval that passes its checks
 *   (`approval_declined`): `send` reports `declined`, the approval is never sent again, and no
 *   new revision of that action is approved without the user.
 * - **At most once.** After a failure or a timeout, `OperationsClient.send` sends the same
 *   approval again, waiting for `Retry-After`. A new operation in answer to such a retry
 *   doesn't say whether the first was performed: it is `unknown`, and the host finds out
 *   another way before asking the user again.
 */

export const OPERATIONS_EXTENSION = "operations";
/**
 * The version this SDK implements, and the only one: version 2 is incompatible with it (another
 * major version, Operations 2), so a Company that lists only 2 gets no `operations`
 * declaration, and a request that declares 2 gets no operations here.
 */
export const OPERATIONS_VERSION = "3";
/** A Company's refusal to act on an approval that passed its checks (Operations 6). */
export const APPROVAL_DECLINED = "approval_declined";
/** An approved action that didn't finish: an API error saying every change made (Operations 7). */
export const ACTION_FAILED = "action_failed";
/** The header that carries an approval to an API (Operations 6). */
export const APPROVAL_HEADER = "Poppy-Approval";
/** The `_meta` key that carries an approval to an MCP tool (Operations 6). */
export const APPROVAL_META_KEY = "personalagentprotocol.org/approval";
/** How many times `send` sends an approval, unless told otherwise. */
export const SEND_ATTEMPTS = 3;

/** An operation could not be approved, or its approval could not be sent. */
export class OperationError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; details?: Readonly<Record<string, unknown>>; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "OperationError";
  }
}

/**
 * Whether the Company lists `operations` at this version and the Session declares it
 * (Operations 2): another major version doesn't count.
 */
export function operationsNegotiated(document: DiscoveryDocument, session: PapSession): boolean {
  return (
    companyExtension(document, OPERATIONS_EXTENSION, OPERATIONS_VERSION) !== undefined &&
    session.extensions[OPERATIONS_EXTENSION] === OPERATIONS_VERSION
  );
}

/**
 * The one operation object, from whichever interface carried it (Operations 4).
 *
 * Accepts an API's `403` body (`{operation: …}`), an MCP tool result
 * (`{structuredContent: {operation: …}}`), a conversation message (`{operation: …}`), or the
 * operation itself. A payload that carries none, or a malformed one, is `invalid_operation`.
 */
export function operationFrom(payload: unknown): Operation {
  let candidate: unknown = payload;
  if (typeof payload === "object" && payload !== null && !Array.isArray(payload)) {
    const source = payload as Record<string, unknown>;
    const structured = source.structuredContent;
    if (typeof structured === "object" && structured !== null && !Array.isArray(structured) && "operation" in structured) {
      candidate = (structured as Record<string, unknown>).operation;
    } else if ("operation" in source) {
      candidate = source.operation;
    } else if (typeof source.extensions === "object" && source.extensions !== null) {
      // A conversation message: `extensions.operations.operation` (Operations 4).
      const operations = (source.extensions as Record<string, unknown>).operations;
      candidate =
        typeof operations === "object" && operations !== null
          ? (operations as Record<string, unknown>).operation
          : undefined;
    }
  }
  if (candidate === undefined || candidate === null) {
    throw new OperationError("invalid_operation", "the payload carries no operation");
  }
  try {
    return parseOperation(candidate);
  } catch (cause) {
    throw new OperationError("invalid_operation", "the operation is malformed", { cause });
  }
}

/**
 * The decline a Company answered an approval with, or `undefined` (Operations 6).
 *
 * Accepts an API's `403` body (`error: approval_declined` with the members), an MCP tool result
 * (the same in `structuredContent`), a conversation message (`extensions.operations.declined`).
 * A decline that names no operation and revision throws a `ProtocolValidationError`.
 */
export function declinedFrom(payload: unknown): ApprovalDeclined | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  const source = payload as Record<string, unknown>;
  const object = (value: unknown): Record<string, unknown> | undefined =>
    typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
  const structured = object(source.structuredContent);
  const operations = object(object(source.extensions)?.operations);
  let candidate: Record<string, unknown> | undefined;
  if (structured?.error === APPROVAL_DECLINED) candidate = structured;
  else if (source.error === APPROVAL_DECLINED) candidate = source;
  else if (operations !== undefined) candidate = object(operations.declined);
  if (candidate === undefined) return undefined;
  // `error` marks the body at an API and a tool; it is not a member of the decline.
  const { error: _marker, ...members } = candidate;
  return parseApprovalDeclined(members);
}

// The `Poppy-Approval` header: an RFC 9651 Dictionary ---------------------------------------

function sfString(value: string): string {
  return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

/**
 * The value of `Poppy-Approval` (Operations 6): `operation_id`, `revision`, `approver` and any
 * `input_type` and `reference` as Strings, any `approved_at` as an Integer. An agent approval
 * never carries `input_type`.
 */
export function approvalHeader(approval: Approval): string {
  let value =
    `operation_id="${approval.operation_id}", revision="${approval.revision}", ` +
    `approver="${approval.approver}"`;
  if (approval.approved_at !== undefined) value += `, approved_at=${approval.approved_at}`;
  if (approval.input_type !== undefined && approval.approver === "user") {
    value += `, input_type=${sfString(approval.input_type)}`;
  }
  if (approval.reference !== undefined) value += `, reference="${approval.reference}"`;
  return value;
}

/**
 * A `reference` for one approval (Operations 6): `apr_` and 16 random bytes, so it is opaque,
 * identifies nobody, and is never the same at two Companies. The host keeps its own record of
 * the approval under it.
 */
export function newApprovalReference(
  randomBytes: (length: number) => Uint8Array = (length) => globalThis.crypto.getRandomValues(new Uint8Array(length)),
): string {
  return `apr_${[...randomBytes(16)].map((byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/** The value is not an RFC 9651 Dictionary: the whole field is ignored. */
class DictionaryError extends Error {}

const KEY = /[a-z*][a-z0-9_.*-]*/y;
const TOKEN = /[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*/y;
const NUMBER = /-?\d{1,15}(\.\d{1,3})?/y;
const BYTES = /:[A-Za-z0-9+/=]*:/y;
const DISPLAY = /%"[^"]*"/y;
/** Any bare item but a String: a Token `a` or an Integer `1` is never the String "a" or "1". */
const NOT_A_STRING = Symbol("not a String");

/** A strict parser of an RFC 9651 Dictionary, keeping the Strings a caller reads. */
class Dictionary {
  readonly #text: string;
  #at = 0;

  constructor(text: string) {
    this.#text = text.replace(/^ +| +$/g, "");
  }

  #peek(): string {
    return this.#text[this.#at] ?? "";
  }

  #match(pattern: RegExp): string {
    pattern.lastIndex = this.#at;
    const found = pattern.exec(this.#text);
    if (found === null) throw new DictionaryError();
    this.#at = pattern.lastIndex;
    return found[0];
  }

  #whitespace(): void {
    while (this.#peek() === " " || this.#peek() === "\t") this.#at += 1;
  }

  members(): Map<string, unknown> {
    const members = new Map<string, unknown>();
    while (this.#at < this.#text.length) {
      const key = this.#match(KEY);
      let value: unknown = true;
      if (this.#peek() === "=") {
        this.#at += 1;
        value = this.#peek() === "(" ? this.#innerList() : this.#bareItem();
      }
      this.#parameters();
      members.set(key, value); // the last one wins, in the first one's place
      this.#whitespace();
      if (this.#at === this.#text.length) break;
      if (this.#peek() !== ",") throw new DictionaryError();
      this.#at += 1;
      this.#whitespace();
      if (this.#at === this.#text.length) throw new DictionaryError(); // a trailing comma
    }
    return members;
  }

  #parameters(): void {
    while (this.#peek() === ";") {
      this.#at += 1;
      while (this.#peek() === " ") this.#at += 1;
      this.#match(KEY);
      if (this.#peek() === "=") {
        this.#at += 1;
        this.#bareItem();
      }
    }
  }

  #innerList(): unknown[] {
    this.#at += 1;
    const items: unknown[] = [];
    for (;;) {
      while (this.#peek() === " ") this.#at += 1;
      if (this.#peek() === ")") {
        this.#at += 1;
        return items;
      }
      items.push(this.#bareItem());
      this.#parameters();
      if (this.#peek() !== " " && this.#peek() !== ")") throw new DictionaryError();
    }
  }

  #bareItem(): string | number | typeof NOT_A_STRING {
    const first = this.#peek();
    if (first === '"') return this.#string();
    if (first === "?") {
      this.#at += 1;
      const value = this.#peek();
      if (value !== "0" && value !== "1") throw new DictionaryError();
      this.#at += 1;
    } else if (first === ":") {
      this.#match(BYTES);
    } else if (first === "@") {
      this.#at += 1;
      this.#match(NUMBER);
    } else if (first === "%") {
      this.#match(DISPLAY);
    } else if (first === "-" || /^[0-9]$/.test(first)) {
      // An Integer is a number (`approved_at`); a Decimal is opaque.
      const number = this.#match(NUMBER);
      if (!number.includes(".")) return Number(number);
    } else {
      this.#match(TOKEN);
    }
    return NOT_A_STRING;
  }

  #string(): string {
    this.#at += 1;
    let value = "";
    while (this.#at < this.#text.length) {
      const char = this.#text[this.#at] as string;
      this.#at += 1;
      if (char === "\\") {
        const escaped = this.#peek();
        if (escaped !== '"' && escaped !== "\\") throw new DictionaryError();
        this.#at += 1;
        value += escaped;
      } else if (char === '"') {
        return value;
      } else if (char < " " || char > "~") {
        throw new DictionaryError();
      } else {
        value += char;
      }
    }
    throw new DictionaryError();
  }
}

/**
 * The approval a `Poppy-Approval` value states, or `undefined`.
 *
 * A value that isn't a Dictionary is ignored whole (RFC 9651), and so is one without
 * `operation_id` and `revision` as Strings of the IDs' characters or without `approver` as
 * `user` or `agent`: a version 2 approval, which names no approver, is not an approval.
 * `approved_at` (an Integer), `input_type` and `reference` (Strings) are kept when they are
 * such, and left out otherwise; `input_type` is dropped with `agent`. Members this version
 * doesn't recognize are ignored, so later versions can add them (Operations 6).
 */
export function parseApprovalHeader(value: string | null | undefined): Approval | undefined {
  if (!value) return undefined;
  try {
    const members = new Dictionary(value).members();
    return parseApproval({
      operation_id: members.get("operation_id"),
      revision: members.get("revision"),
      approver: members.get("approver"),
      approved_at: members.get("approved_at"),
      input_type: members.get("input_type"),
      reference: members.get("reference"),
    });
  } catch {
    return undefined;
  }
}

/** The approval in an MCP tool call's `_meta`, or `undefined` (unknown members are ignored). */
export function approvalFromMeta(meta: unknown): Approval | undefined {
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) return undefined;
  try {
    return parseApproval((meta as Record<string, unknown>)[APPROVAL_META_KEY]);
  } catch {
    return undefined;
  }
}

// The terms check ---------------------------------------------------------------------------

/** A value a `summary` states with decimals, such as an amount. */
const DECIMAL = /(?<![\w.])\d[\d,]*\.\d+(?!\w)/g;
const NUMERIC = /^\d+(\.\d+)?$/;

const leaves = termsLeaves;

/**
 * Where `terms` disagree with what the agent asked for, or with the `summary`.
 *
 * `asked` gives the values the agent asked for, keyed by their dotted paths in `terms`: a
 * different or missing value is a difference. When the operation has a `summary`, the company
 * wrote both, so the summary alone could describe something other than the terms (Operations
 * 5): amounts are compared both ways, every decimal in the summary is in the terms and every
 * number in the terms is in the summary. Identifiers aren't, since a summary is written for
 * people. Without a `summary` only `asked` is compared.
 */
export function termsDifferences(
  operation: Operation,
  asked: Readonly<Record<string, unknown>> = {},
): readonly string[] {
  const found = leaves(operation.terms);
  const differences: string[] = [];
  for (const [path, wanted] of Object.entries(asked)) {
    if (!found.has(path)) {
      differences.push(`You asked for ${path} ${String(wanted)}; the terms don't say.`);
    } else if (String(found.get(path)) !== String(wanted)) {
      differences.push(`You asked for ${path} ${String(wanted)}; the terms say ${String(found.get(path))}.`);
    }
  }
  if (operation.summary === undefined) return differences;
  const stated = new Set([...operation.summary.matchAll(DECIMAL)].map(([match]) => match.replaceAll(",", "")));
  const numbers = new Map<string, string>();
  for (const [path, value] of found) {
    if ((typeof value === "string" || typeof value === "number") && NUMERIC.test(String(value))) {
      numbers.set(path, String(value));
    }
  }
  const summary = operation.summary.replaceAll(",", "");
  for (const [path, value] of numbers) {
    if (!summary.includes(value)) differences.push(`The terms say ${path} ${value}; the summary doesn't.`);
  }
  const inTerms = new Set(numbers.values());
  for (const value of [...stated].sort()) {
    if (!inTerms.has(value)) differences.push(`The summary says ${value}; the terms don't.`);
  }
  return differences;
}

/** What a new revision changed: `summary`, `expires_at`, and the terms' paths. */
function changedPaths(before: Operation, after: Operation): readonly string[] {
  const old = leaves(before.terms);
  const now = leaves(after.terms);
  const changed = [...new Set([...old.keys(), ...now.keys()])]
    .filter((path) => JSON.stringify(old.get(path)) !== JSON.stringify(now.get(path)))
    .sort();
  return [
    ...(before.summary === after.summary ? [] : ["summary"]),
    ...(before.expires_at === after.expires_at ? [] : ["expires_at"]),
    ...changed,
  ];
}

// Asking the user, and sending the approval ---------------------------------------------------

/**
 * What came of sending an approval.
 *
 * `answered`: the company answered as it would without operations; `answer` is that answer,
 * the same on every retry. `new_revision`: it returned an operation to approve, `operation`,
 * for a first send: show what changed and ask again. `declined`: the company will not act on
 * this approval (`declined` carries its `reason` and `alternative`, company content): nothing
 * was performed, the approval is never sent again, and the user is told. `askUser` is `true`
 * when a new revision of the action may only be approved by the user: after a decline, and when
 * the approval sent was the agent's (Operations 5). `unknown`: a send failed or timed out and
 * nothing since says whether the action was performed, with `operation` when the company
 * answered a retry with one, or the company is still performing it: find out another way, such
 * as from the order in the company's API, before asking the user about the same action again.
 */
export interface ApprovalSent<T> {
  readonly status: "answered" | "new_revision" | "declined" | "unknown";
  readonly answer?: T;
  readonly operation?: Operation;
  readonly declined?: ApprovalDeclined;
  readonly askUser: boolean;
  readonly retryAfter?: string;
}

/**
 * An instruction the User gave the Personal Agent, which an agent approval rests on
 * (Operations 5), such as "go ahead with any exchange under $20".
 *
 * The host holds it: `text` is the User's instruction as the host recorded it, taken through
 * the host's own interface, never content from a Company, a website or anything else the agent
 * read, even when that says it comes from the User. `covers` is the host's check of a
 * revision's terms against it: `true` only when the instruction covers them, `false` when it
 * does not, `null` when it can't tell. The extension doesn't say how to check; the SDK never
 * guesses, and only `true` approves.
 */
export interface AgentInstruction {
  readonly text: string;
  readonly covers: (operation: Operation) => boolean | null;
}

/** An `AgentInstruction`, checked: an agent approval rests on an instruction the User gave. */
export function agentInstruction(
  text: string,
  covers: (operation: Operation) => boolean | null,
): AgentInstruction {
  if (typeof text !== "string" || !text.trim()) {
    throw new RangeError("an agent approval rests on an instruction the User gave");
  }
  return Object.freeze({ text, covers });
}

export interface AskUserOptions {
  readonly organization: Pick<Organization, "name" | "domain">;
  readonly tenantId: string;
  /** Values the agent asked for, keyed by their dotted paths in `terms`. */
  readonly asked?: Readonly<Record<string, unknown>>;
  /** The revision this one replaces: the surface is told what changed. */
  readonly replaces?: Operation;
  /** Overrides the contribution, for a host whose interface is the caller's own. */
  readonly surface?: ApprovalSurface;
  /**
   * How the user answers on the host's surface: `tap`, `typed`, `voice`, or another short string,
   * never personal data. The approval says so, with `approved_at` (Operations 6).
   */
  readonly inputType?: string;
  /** Names the host's own record of the approval (`newApprovalReference`). */
  readonly reference?: string;
}

export interface ApproveAsAgentOptions {
  /** The User's instruction the approval rests on, and the host's check of terms against it. */
  readonly instruction: AgentInstruction;
  /** Values the agent asked for, keyed by their dotted paths in `terms`. */
  readonly asked?: Readonly<Record<string, unknown>>;
  /**
   * The host's own memory that a new revision of this action is the user's to approve: it was
   * declined before, or the company answered an earlier agent approval of it with new terms.
   */
  readonly userOnly?: boolean;
  /** Names the host's own record of the approval (`newApprovalReference`). */
  readonly reference?: string;
}

export interface OperationsClientOptions {
  readonly reactor: ReactorPlatformView;
  /** Waits for `Retry-After` between sends. */
  readonly sleep?: (seconds: number) => Promise<void>;
  /** The longest wait, in seconds, `send` will do. */
  readonly maxWait?: number;
}

const realSleep = (seconds: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, seconds * 1000));

/**
 * Approve an operation, as the user or on the user's instruction, and send the approval at
 * most once.
 *
 * `sleep` waits for `Retry-After` between sends; `maxWait` is the longest wait it will do. The
 * client remembers, for its own life, the operations whose next revision only the user may
 * approve (`userOnly`): a host that outlives it keeps that itself and passes `userOnly: true`
 * to `approveAsAgent`.
 */
export class OperationsClient {
  readonly #reactor: ReactorPlatformView;
  readonly #sleep: (seconds: number) => Promise<void>;
  readonly #maxWait: number;
  /**
   * The operations declined, or answered with new terms after an agent approval: no agent
   * approval of a new revision of the same action (Operations 5, 6).
   */
  readonly userOnly = new Set<string>();

  constructor(options: OperationsClientOptions) {
    this.#reactor = options.reactor;
    this.#sleep = options.sleep ?? realSleep;
    this.#maxWait = options.maxWait ?? 30;
  }

  /**
   * Ask the user about this revision, through the host's own surface: a `user` approval.
   *
   * Shows the company's name and the revision's terms, as the `summary` when the company wrote
   * one and else as the values in `terms`, with any difference the terms check finds, and with what changed from `replaces`, the revision this one replaces. Only `true`
   * from the surface approves; anything else is `not_approved`, a revision past its expiry is
   * `revision_expired` (make the request again for new terms), and a host with no surface is
   * `no_approval_surface`.
   */
  askUser(operation: Operation, options: AskUserOptions): Promise<Approval> {
    return traced(
      this.#reactor,
      "pap.operation.ask_user",
      {},
      () => this.#askUser(operation, options),
      operationResult,
    );
  }

  async #askUser(operation: Operation, options: AskUserOptions): Promise<Approval> {
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    if (clock.now().getTime() > new Date(operation.expires_at).getTime()) {
      throw new OperationError("revision_expired", "This revision has expired");
    }
    const request: ApprovalRequest = {
      actionId: "pap.operations.approve",
      actionName: "Approve an operation",
      summary: operationShown(operation),
      arguments: { operation_id: operation.operation_id, revision: operation.revision },
      tenantId: options.tenantId,
      companyName: options.organization.name,
      companyDomain: options.organization.domain,
      terms: operation.terms,
      expiresAt: new Date(operation.expires_at),
      differences: termsDifferences(operation, options.asked),
      changed: options.replaces === undefined ? [] : changedPaths(options.replaces, operation),
    };
    if ((await this.#approved(request, options.surface)) !== true) {
      throw new OperationError("not_approved", "The user did not approve");
    }
    // When and how the user approved: the Personal Agent's statements (Operations 6).
    return parseApproval({
      operation_id: operation.operation_id,
      revision: operation.revision,
      approver: "user",
      approved_at: Math.floor(clock.now().getTime() / 1000),
      ...(options.inputType === undefined ? {} : { input_type: options.inputType }),
      ...(options.reference === undefined ? {} : { reference: options.reference }),
    });
  }

  /**
   * Approve this revision on an instruction the user gave: an `agent` approval.
   *
   * Nobody is asked, so every doubt goes to the user instead: `ask_user` (an `OperationError`)
   * when the operation was declined before, or the company answered an earlier agent approval
   * of it with new terms (`userOnly`, or this client's own memory); when the terms differ from
   * what the agent asked for or from the summary; and when `instruction.covers` says anything
   * but `true`. The caller then asks with `askUser`. A revision past its expiry is
   * `revision_expired`. The approval says `approver: agent` and when, never an `input_type`.
   */
  approveAsAgent(operation: Operation, options: ApproveAsAgentOptions): Promise<Approval> {
    return traced(
      this.#reactor,
      "pap.operation.approve_as_agent",
      {},
      async () => this.#approveAsAgent(operation, options),
      operationResult,
    );
  }

  #approveAsAgent(operation: Operation, options: ApproveAsAgentOptions): Approval {
    const instruction = options.instruction;
    if (typeof instruction?.text !== "string" || !instruction.text.trim() || typeof instruction.covers !== "function") {
      throw new RangeError("an agent approval rests on an instruction the User gave");
    }
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    if (clock.now().getTime() > new Date(operation.expires_at).getTime()) {
      throw new OperationError("revision_expired", "This revision has expired");
    }
    if (options.userOnly === true || this.userOnly.has(operation.operation_id)) {
      throw new OperationError(
        "ask_user",
        "New terms after an agent approval, or after a decline, are the user's to approve",
      );
    }
    if (termsDifferences(operation, options.asked).length > 0) {
      throw new OperationError("ask_user", "The terms differ from what was asked: ask the user");
    }
    let covered: unknown;
    try {
      covered = instruction.covers(operation);
    } catch (cause) {
      throw new OperationError("ask_user", "The instruction's check failed: ask the user", { cause });
    }
    if (covered !== true) {
      throw new OperationError("ask_user", "The user's instruction does not clearly cover these terms");
    }
    return parseApproval({
      operation_id: operation.operation_id,
      revision: operation.revision,
      approver: "agent",
      approved_at: Math.floor(clock.now().getTime() / 1000),
      ...(options.reference === undefined ? {} : { reference: options.reference }),
    });
  }

  /** A `reference` for one approval, from the host's random source. */
  newReference(): string {
    const source = firstContribution(this.#reactor, RandomSources, "random");
    return newApprovalReference((length) => source.bytes(length));
  }

  async #approved(request: ApprovalRequest, surface: ApprovalSurface | undefined): Promise<unknown> {
    let chosen = surface;
    if (chosen === undefined) {
      try {
        chosen = optionalContribution(this.#reactor, ApprovalSurfaces, "approval surface");
      } catch (cause) {
        throw new OperationError("approval_surface_ambiguous", "Two approval surfaces at one order", { cause });
      }
      if (chosen === undefined) {
        throw new OperationError("no_approval_surface", "This host has no surface to ask the user through");
      }
    }
    try {
      return await chosen.approve(request);
    } catch (cause) {
      throw new OperationError("approval_failed", "The approval surface failed: nothing was approved", { cause });
    }
  }

  /**
   * Send one approval: the saved request, the same every time.
   *
   * `request(approval)` makes the request that returned the operation, with the approval:
   * `api.call(..., { approval })`, or the tool call, or the same message with the same ID. A
   * failure, a timeout, or a `503` sends it again with the same approval, waiting for
   * `Retry-After`. After `attempts`, or a longer wait than `maxWait`, the outcome is `unknown`.
   * A decline is final: `declined`, never sent again (Operations 6, 7).
   */
  send<T>(
    request: (approval: Approval) => Promise<T>,
    approval: Approval,
    options: { readonly attempts?: number } = {},
  ): Promise<ApprovalSent<T>> {
    return traced(
      this.#reactor,
      "pap.operation.send",
      {},
      () => this.#send(request, approval, options.attempts ?? SEND_ATTEMPTS),
      operationResult,
    );
  }

  async #send<T>(
    request: (approval: Approval) => Promise<T>,
    approval: Approval,
    attempts: number,
  ): Promise<ApprovalSent<T>> {
    if (!(attempts >= 1)) throw new RangeError("attempts must be positive");
    let uncertain = false;
    let retryAfter: string | undefined;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      let answer: T;
      try {
        answer = await request(approval);
      } catch (error) {
        if (error instanceof TransportError) {
          uncertain = true;
          retryAfter = undefined;
        } else if (error instanceof PersonalAgentProtocolError && error.statusCode === 503) {
          uncertain = true;
          const value = error.details?.retry_after;
          retryAfter = typeof value === "string" ? value : undefined;
        } else {
          throw error;
        }
        if (attempt + 1 < attempts && !(await this.#waited(retryAfter))) break;
        continue;
      }
      const sent = this.#sent(answer, approval, uncertain);
      if (sent.askUser) this.userOnly.add(approval.operation_id);
      return sent;
    }
    return { status: "unknown", askUser: false, ...(retryAfter === undefined ? {} : { retryAfter }) };
  }

  #sent<T>(answer: T, approval: Approval, uncertain: boolean): ApprovalSent<T> {
    const carried = answer as
      | { readonly operation?: Operation; readonly declined?: ApprovalDeclined }
      | null
      | undefined;
    const declined = carried?.declined;
    if (typeof declined === "object" && declined !== null) {
      return { status: "declined", declined, askUser: true };
    }
    const operation = carried?.operation;
    if (operation === undefined || operation === null) return { status: "answered", answer, askUser: false };
    if (operation.revision === approval.revision) {
      // Answering an approval with the revision it names would loop for ever.
      throw new OperationError("invalid_operation", "The company answered an approval with the same revision");
    }
    return {
      status: uncertain ? "unknown" : "new_revision",
      operation,
      askUser: approval.approver === "agent",
    };
  }

  /** Wait for `Retry-After`: `false` when it asks for longer than this client waits. */
  async #waited(retryAfter: string | undefined): Promise<boolean> {
    const seconds = retryAfter !== undefined && /^\d+$/.test(retryAfter) ? Number(retryAfter) : 0;
    if (seconds > this.#maxWait) return false;
    if (seconds > 0) await this.#sleep(seconds);
    return true;
  }
}
