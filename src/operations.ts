/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { PersonalAgentProtocolError, TransportError } from "./errors.js";
import {
  parseApproval,
  parseOperation,
  type Approval,
  type ClientMetadata,
  type DiscoveryDocument,
  type Operation,
  type Organization,
} from "./models.js";
import {
  ApprovalSurfaces,
  Clocks,
  firstContribution,
  optionalContribution,
  type ApprovalRequest,
  type ApprovalSurface,
} from "./reactor.js";
import { operationResult, traced } from "./telemetry.js";

/**
 * PAP Operations extension v2: exact approval, at most once, no endpoints of its own.
 *
 * A company that wants the user's approval for an action refuses the request and returns the
 * operation: the terms, in plain language and as JSON. The personal agent gets the user's
 * approval and makes the same request again with it, through the interface that returned the
 * operation:
 *
 * - an API's `403` with `error: approval_required` and `operation`, answered by the same
 *   request with the `Poppy-Approval` header (`ApiClient.call(..., { approval })`);
 * - an MCP tool's error result with `structuredContent.operation`, answered by the same call
 *   with `_meta["personalagentprotocol.org/approval"]` (`McpClient.callTool(..., { approval })`);
 * - a company message's `operation`, answered by a message with `approval`.
 *
 * What this client guarantees on the personal agent's side:
 *
 * - **Negotiation.** Operations are used only when the company's `poppy.json` and the agent's
 *   client metadata both list `operations` version 2.
 * - **The user decides.** `OperationsClient.askUser` asks the host's own approval surface
 *   (`pap.approvalSurface`) about every operation, naming the company and the revision's
 *   summary: only the surface's `true` makes an `Approval`. Nothing here reads conversation
 *   text as approval, approves in advance, or approves on the user's behalf; without a
 *   surface, nothing is approved.
 * - **Exact terms.** `termsDifferences` checks `terms` against the `summary` and against what
 *   the agent asked for, and the surface is told any difference. An approval covers one
 *   revision: a new one needs a new approval.
 * - **At most once.** After a failure or a timeout, `OperationsClient.send` sends the same
 *   approval again, waiting for `Retry-After`. A new operation in answer to such a retry
 *   doesn't say whether the first was performed: it is `unknown`, and the host finds out
 *   another way before asking the user again.
 */

export const OPERATIONS_EXTENSION = "operations";
export const OPERATIONS_VERSION = "2";
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

/** Whether both sides list `operations` with this version (another major doesn't count). */
export function operationsNegotiated(document: DiscoveryDocument, metadata: ClientMetadata): boolean {
  return (
    document.extensions[OPERATIONS_EXTENSION]?.version === OPERATIONS_VERSION &&
    metadata.extensions[OPERATIONS_EXTENSION]?.version === OPERATIONS_VERSION
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

// The `Poppy-Approval` header: an RFC 9651 Dictionary ---------------------------------------

/** The value of `Poppy-Approval`: the two members, as Strings. */
export function approvalHeader(approval: Approval): string {
  return `operation_id="${approval.operation_id}", revision="${approval.revision}"`;
}

/** The value is not an RFC 9651 Dictionary: the whole field is ignored. */
class DictionaryError extends Error {}

const KEY = /[a-z*][a-z0-9_.*-]*/y;
const TOKEN = /[A-Za-z*][A-Za-z0-9!#$%&'*+.^_`|~:/-]*/y;
const NUMBER = /-?\d{1,15}(\.\d{1,3})?/y;
const BYTES = /:[A-Za-z0-9+/=]*:/y;
const DISPLAY = /%"[^"]*"/y;

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

  #bareItem(): unknown {
    const first = this.#peek();
    if (first === '"') return this.#string();
    if (first === "?") {
      this.#at += 1;
      const value = this.#peek();
      if (value !== "0" && value !== "1") throw new DictionaryError();
      this.#at += 1;
      return value === "1";
    }
    if (first === ":") return this.#match(BYTES);
    if (first === "@") {
      this.#at += 1;
      return this.#match(NUMBER);
    }
    if (first === "%") return this.#match(DISPLAY);
    if (first === "-" || /^[0-9]$/.test(first)) return this.#match(NUMBER);
    return this.#match(TOKEN);
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
 * A value that isn't a Dictionary is ignored whole (RFC 9651), and so is one without both
 * members as Strings of the IDs' characters. Members this version doesn't recognize are
 * ignored, so later versions can add them (Operations 6).
 */
export function parseApprovalHeader(value: string | null | undefined): Approval | undefined {
  if (!value) return undefined;
  try {
    const members = new Dictionary(value).members();
    return parseApproval({ operation_id: members.get("operation_id"), revision: members.get("revision") });
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

function leaves(value: unknown, path = ""): Map<string, unknown> {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const found = new Map<string, unknown>();
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      for (const [inner, leaf] of leaves(item, path ? `${path}.${key}` : key)) found.set(inner, leaf);
    }
    return found;
  }
  return new Map([[path, value]]);
}

/**
 * Where `terms` disagree with the `summary`, or with what the agent asked for.
 *
 * The company writes both, so the summary alone could describe something other than the terms
 * (Operations 5). `asked` gives the values the agent asked for, keyed by their dotted paths in
 * `terms`: a different or missing value is a difference. Amounts are compared with the summary
 * both ways: every decimal in the summary is in the terms, and every number in the terms is in
 * the summary. Identifiers aren't, since a summary is written for people. Without `terms`
 * there is nothing to compare with.
 */
export function termsDifferences(
  operation: Operation,
  asked: Readonly<Record<string, unknown>> = {},
): readonly string[] {
  const found = leaves(operation.terms ?? {});
  const differences: string[] = [];
  for (const [path, wanted] of Object.entries(asked)) {
    if (!found.has(path)) {
      differences.push(`You asked for ${path} ${String(wanted)}; the terms don't say.`);
    } else if (String(found.get(path)) !== String(wanted)) {
      differences.push(`You asked for ${path} ${String(wanted)}; the terms say ${String(found.get(path))}.`);
    }
  }
  if (operation.terms === undefined) return differences;
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
  const old = leaves(before.terms ?? {});
  const now = leaves(after.terms ?? {});
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
 * for a first send: show what changed and ask again. `unknown`: a send failed or timed out and
 * nothing since says whether the action was performed, with `operation` when the company
 * answered a retry with one, or the company is still performing it: find out another way, such
 * as from the order in the company's API, before asking the user about the same action again.
 */
export interface ApprovalSent<T> {
  readonly status: "answered" | "new_revision" | "unknown";
  readonly answer?: T;
  readonly operation?: Operation;
  readonly retryAfter?: string;
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

/** Get the user's approval of an operation, and send it at most once. */
export class OperationsClient {
  readonly #reactor: ReactorPlatformView;
  readonly #sleep: (seconds: number) => Promise<void>;
  readonly #maxWait: number;

  constructor(options: OperationsClientOptions) {
    this.#reactor = options.reactor;
    this.#sleep = options.sleep ?? realSleep;
    this.#maxWait = options.maxWait ?? 30;
  }

  /**
   * Ask the user about this revision, through the host's own surface.
   *
   * Shows the company's name and the revision's `summary`, with any difference the terms check
   * finds, and with what changed from `replaces`, the revision this one replaces. Only `true`
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
      () => ({ "pap.operation.status": "approved" }),
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
      summary: operation.summary,
      arguments: { operation_id: operation.operation_id, revision: operation.revision },
      tenantId: options.tenantId,
      companyName: options.organization.name,
      companyDomain: options.organization.domain,
      ...(operation.terms === undefined ? {} : { terms: operation.terms }),
      expiresAt: new Date(operation.expires_at),
      differences: termsDifferences(operation, options.asked),
      changed: options.replaces === undefined ? [] : changedPaths(options.replaces, operation),
    };
    if ((await this.#approved(request, options.surface)) !== true) {
      throw new OperationError("not_approved", "The user did not approve");
    }
    return { operation_id: operation.operation_id, revision: operation.revision };
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
      try {
        return this.#sent(await request(approval), approval, uncertain);
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
      }
      if (attempt + 1 < attempts && !(await this.#waited(retryAfter))) break;
    }
    return { status: "unknown", ...(retryAfter === undefined ? {} : { retryAfter }) };
  }

  #sent<T>(answer: T, approval: Approval, uncertain: boolean): ApprovalSent<T> {
    const operation = (answer as { readonly operation?: Operation } | null | undefined)?.operation;
    if (operation === undefined) return { status: "answered", answer };
    if (operation.revision === approval.revision) {
      // Answering an approval with the revision it names would loop for ever.
      throw new OperationError("invalid_operation", "The company answered an approval with the same revision");
    }
    return { status: uncertain ? "unknown" : "new_revision", operation };
  }

  /** Wait for `Retry-After`: `false` when it asks for longer than this client waits. */
  async #waited(retryAfter: string | undefined): Promise<boolean> {
    const seconds = retryAfter !== undefined && /^\d+$/.test(retryAfter) ? Number(retryAfter) : 0;
    if (seconds > this.#maxWait) return false;
    if (seconds > 0) await this.#sleep(seconds);
    return true;
  }
}
