import { defineContributionPoint, type ReactorPlatformView } from "@datalayer/reactor";

import { PersonalAgentProtocolError, ProtocolValidationError, TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { parseOperation, type ClientMetadata, type DiscoveryDocument, type Operation } from "./models.js";
import { Clocks, firstContribution } from "./reactor.js";
import type { SessionToken } from "./sessions.js";
import type { DpopFetchClient } from "./transport.js";

/**
 * PAP Operations extension v1 on the personal agent's side, as in Python:
 * negotiation, exact user approval of one revision, standing permissions
 * checked term by term (Reactor `pap.standingPermissionStore`), recovery of a
 * lost confirmation by reading the same ID, and cancellation. A message never
 * confirms an operation.
 */

export const OPERATIONS_EXTENSION = "operations";
export const OPERATIONS_VERSION = "1";

const identifier = /^[A-Za-z0-9_-]{1,256}$/;

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

/** The company's operations endpoint when both sides list version 1. */
export function operationsEndpoint(document: DiscoveryDocument, metadata: ClientMetadata): string | undefined {
  const company = document.extensions[OPERATIONS_EXTENSION] as Record<string, unknown> | undefined;
  const agent = metadata.extensions[OPERATIONS_EXTENSION];
  if (!company || !agent || company.version !== OPERATIONS_VERSION || agent.version !== OPERATIONS_VERSION) {
    return undefined;
  }
  const endpoint = company.endpoint;
  return typeof endpoint === "string" && endpoint.startsWith("https://") ? endpoint : undefined;
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/** A digest of exactly what a revision says: its summary and its terms. */
export async function termsDigest(operation: Operation): Promise<string> {
  const bytes = new TextEncoder().encode(canonical({ summary: operation.summary, terms: operation.terms ?? {} }));
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export interface UserApproval {
  readonly operationId: string;
  readonly revision: number;
  readonly digest: string;
}

/** Record the user's approval of the revision the host just showed them. */
export async function approve(operation: Operation): Promise<UserApproval> {
  if (operation.state !== "proposed") {
    throw new OperationError("not_proposed", "Only a proposed operation can be approved");
  }
  return { operationId: operation.operation_id, revision: operation.revision, digest: await termsDigest(operation) };
}

export interface TermLimit {
  /** Dotted path in `terms`, e.g. `price_difference.amount`. */
  readonly path: string;
  /** Decimal maximum (amounts are strings on the wire). */
  readonly maximum?: string;
  readonly allowed?: readonly string[];
}

export interface StandingPermission {
  readonly reference: string;
  readonly company: string;
  readonly account: string;
  readonly action: string;
  readonly limits: readonly TermLimit[];
  readonly expiresAt: Date;
  readonly usesRemaining?: number;
}

export interface StandingPermissionRequest {
  readonly company: string;
  readonly account: string;
  readonly action: string;
  readonly operation: Operation;
}

/** Reserve, commit, and release uses of the user's standing permissions. */
export interface StandingPermissionStore {
  reserve(request: StandingPermissionRequest, options: { readonly now: Date }): Promise<string | undefined>;
  commit(reservation: string): Promise<void>;
  release(reservation: string): Promise<void>;
}

export const StandingPermissionStores = defineContributionPoint<StandingPermissionStore>(
  "pap.standingPermissionStore",
);

function term(terms: Readonly<Record<string, unknown>>, path: string): unknown {
  let value: unknown = terms;
  for (const part of path.split(".")) {
    if (typeof value !== "object" || value === null || !(part in value)) throw new RangeError(path);
    value = (value as Record<string, unknown>)[part];
  }
  return value;
}

function decimalAtMost(value: unknown, maximum: string): boolean {
  const pattern = /^-?\d+(\.\d+)?$/;
  const text = String(value);
  if (!pattern.test(text) || !pattern.test(maximum)) return false;
  const scale = Math.max((text.split(".")[1] ?? "").length, (maximum.split(".")[1] ?? "").length);
  const scaled = (input: string) => {
    const [whole, fraction = ""] = input.split(".");
    return BigInt(`${whole}${fraction.padEnd(scale, "0")}`);
  };
  return scaled(text) <= scaled(maximum);
}

/** Whether a standing permission covers this revision, term by term. */
export function covers(permission: StandingPermission, request: StandingPermissionRequest, now: Date): boolean {
  if (
    permission.company !== request.company ||
    permission.account !== request.account ||
    permission.action !== request.action ||
    now.getTime() >= permission.expiresAt.getTime() ||
    permission.usesRemaining === 0 ||
    request.operation.user_approval_required
  ) {
    return false;
  }
  const terms = request.operation.terms ?? {};
  for (const limit of permission.limits) {
    let value: unknown;
    try {
      value = term(terms, limit.path);
    } catch {
      return false;
    }
    if (limit.allowed !== undefined && !limit.allowed.includes(String(value))) return false;
    if (limit.maximum !== undefined && !decimalAtMost(value, limit.maximum)) return false;
  }
  return true;
}

/** A single-process store of standing permissions, for examples and tests. */
export class InMemoryStandingPermissionStore implements StandingPermissionStore {
  readonly permissions = new Map<string, StandingPermission>();
  readonly #reservations = new Map<string, string>();

  constructor(permissions: readonly StandingPermission[] = []) {
    for (const permission of permissions) this.permissions.set(permission.reference, permission);
  }

  async reserve(request: StandingPermissionRequest, options: { readonly now: Date }): Promise<string | undefined> {
    for (const [reference, permission] of this.permissions) {
      if (!covers(permission, request, options.now)) continue;
      if (permission.usesRemaining !== undefined) {
        this.permissions.set(reference, { ...permission, usesRemaining: permission.usesRemaining - 1 });
      }
      const reservation = `rsv_${this.#reservations.size + 1}_${request.operation.operation_id}`;
      this.#reservations.set(reservation, reference);
      return reservation;
    }
    return undefined;
  }

  async commit(reservation: string): Promise<void> {
    this.#reservations.delete(reservation);
  }

  async release(reservation: string): Promise<void> {
    const reference = this.#reservations.get(reservation);
    this.#reservations.delete(reservation);
    const permission = reference === undefined ? undefined : this.permissions.get(reference);
    if (permission?.usesRemaining !== undefined) {
      this.permissions.set(permission.reference, { ...permission, usesRemaining: permission.usesRemaining + 1 });
    }
  }
}

export interface ConfirmOutcome {
  /**
   * `confirmed`: accepted (final, or `in_progress` with `retryAfter`).
   * `terms_changed`: a newer revision to show the user. `approval_required`: the
   * company wants the user's own approval. `not_confirmed`: already cancelled or
   * expired, returned as it is; nothing was confirmed or performed.
   */
  readonly status: "confirmed" | "terms_changed" | "approval_required" | "not_confirmed";
  readonly operation?: Operation;
  readonly changed: readonly string[];
  readonly retryAfter?: number;
}

export interface OperationRequestOptions {
  readonly token: SessionToken;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly issuer: string;
  readonly signal?: AbortSignal;
}

export interface ConfirmOptions extends OperationRequestOptions {
  readonly approval?: UserApproval;
  /** `[company, account, action]` to look up a standing permission. */
  readonly standing?: readonly [string, string, string];
}

export interface OperationsClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly transport: DpopFetchClient;
  readonly maxResponseBytes?: number;
}

interface Held {
  readonly store: StandingPermissionStore;
  readonly reservation: string;
}

/** Read, confirm, and cancel operations at a negotiated endpoint. */
export class OperationsClient {
  readonly #reactor: ReactorPlatformView;
  readonly #transport: DpopFetchClient;
  readonly #maxResponseBytes: number;

  constructor(options: OperationsClientOptions) {
    const limit = options.maxResponseBytes ?? 256 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#reactor = options.reactor;
    this.#transport = options.transport;
    this.#maxResponseBytes = limit;
  }

  async read(endpoint: string, operationId: string, options: OperationRequestOptions): Promise<Operation> {
    const response = await this.#request("GET", endpoint, operationId, undefined, options);
    const payload = await this.#payload(response);
    if (response.status !== 200) throw operationError(response, payload);
    return expectOperation(payload, operationId);
  }

  async confirm(endpoint: string, operation: Operation, options: ConfirmOptions): Promise<ConfirmOutcome> {
    const { approvedBy, held } = await this.#authorize(operation, options);
    const body = JSON.stringify({ revision: operation.revision, approved_by: approvedBy });
    let response: Response;
    try {
      response = await this.#request("POST", endpoint, `${operation.operation_id}/confirm`, body, options);
    } catch (cause) {
      if (!(cause instanceof TransportError)) throw cause;
      // The answer was lost: the company may have performed it. Read it back.
      const current = await this.read(endpoint, operation.operation_id, options);
      await settle(held, current.state !== "proposed");
      if (current.state === "proposed") {
        throw new OperationError("confirm_not_received", "The confirmation did not reach the company; retry it");
      }
      return { status: "confirmed", operation: current, changed: [] };
    }
    const payload = await this.#payload(response);
    await settle(held, response.status === 200);
    if (response.status === 200) {
      const confirmed = expectOperation(payload, operation.operation_id);
      if (
        confirmed.confirmation === null &&
        (confirmed.state === "cancelled" || confirmed.state === "expired")
      ) {
        // A late confirm is safe: the record comes back unchanged (Operations §5.3).
        return { status: "not_confirmed", operation: confirmed, changed: [] };
      }
      if (confirmed.revision !== operation.revision || confirmed.confirmation === null) {
        throw new OperationError("invalid_operation", "The company confirmed a revision other than the one sent");
      }
      const retryAfter = Number(response.headers.get("retry-after"));
      return {
        status: "confirmed",
        operation: confirmed,
        changed: [],
        ...(Number.isInteger(retryAfter) && retryAfter > 0 ? { retryAfter } : {}),
      };
    }
    const error = errorCode(payload);
    if (error === "terms_changed") {
      const current = expectOperation((payload as Record<string, unknown>).operation, operation.operation_id);
      return { status: "terms_changed", operation: current, changed: changedPaths(operation, current) };
    }
    if (error === "user_approval_required") return { status: "approval_required", operation, changed: [] };
    throw operationError(response, payload);
  }

  async cancel(endpoint: string, operationId: string, options: OperationRequestOptions): Promise<Operation> {
    const response = await this.#request("POST", endpoint, `${operationId}/cancel`, "{}", options);
    const payload = await this.#payload(response);
    if (response.status !== 200) throw operationError(response, payload);
    return expectOperation(payload, operationId);
  }

  async #authorize(
    operation: Operation,
    options: ConfirmOptions,
  ): Promise<{ approvedBy: "user" | "standing_permission"; held?: Held }> {
    if ((options.approval === undefined) === (options.standing === undefined)) {
      throw new OperationError(
        "approval_required",
        "Confirm with exactly one of a user approval or a standing permission",
      );
    }
    if (operation.state !== "proposed") {
      throw new OperationError("not_proposed", "Only a proposed operation can be confirmed");
    }
    if (options.approval !== undefined) {
      const { approval } = options;
      if (
        approval.operationId !== operation.operation_id ||
        approval.revision !== operation.revision ||
        approval.digest !== (await termsDigest(operation))
      ) {
        throw new OperationError("approval_mismatch", "The user approved a different revision than this one");
      }
      return { approvedBy: "user" };
    }
    if (operation.user_approval_required) {
      throw new OperationError("user_approval_required", "This revision needs the user's own approval");
    }
    const store = firstContribution(this.#reactor, StandingPermissionStores, "standing permission store");
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const [company, account, action] = options.standing as readonly [string, string, string];
    const reservation = await store.reserve({ company, account, action, operation }, { now: clock.now() });
    if (reservation === undefined) {
      throw new OperationError("no_standing_permission", "No standing permission covers this revision: ask the user");
    }
    return { approvedBy: "standing_permission", held: { store, reservation } };
  }

  async #request(
    method: string,
    endpoint: string,
    path: string,
    body: string | undefined,
    options: OperationRequestOptions,
  ): Promise<Response> {
    if (!identifier.test(path.split("/", 1)[0] ?? "")) {
      throw new ProtocolValidationError("invalid_identifier", "operation ID is invalid");
    }
    return this.#transport.request(method, `${endpoint.replace(/\/$/, "")}/${path}`, {
      token: options.token,
      tenantId: options.tenantId,
      pairwiseUserId: options.pairwiseUserId,
      issuer: options.issuer,
      headers: { Accept: "application/json", ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
      ...(body === undefined ? {} : { body }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  }

  async #payload(response: Response): Promise<unknown> {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > this.#maxResponseBytes) {
      throw new OperationError("response_too_large", "operation response exceeded limit");
    }
    if (!text) return {};
    try {
      return parseJsonStrict(text);
    } catch (cause) {
      throw new OperationError("invalid_json", "operation response was not JSON", { cause });
    }
  }
}

async function settle(held: Held | undefined, spent: boolean): Promise<void> {
  if (held === undefined) return;
  if (spent) await held.store.commit(held.reservation);
  else await held.store.release(held.reservation);
}

function errorCode(payload: unknown): string | undefined {
  if (typeof payload !== "object" || payload === null || Array.isArray(payload)) return undefined;
  const error = (payload as Record<string, unknown>).error;
  return typeof error === "string" ? error : undefined;
}

function operationError(response: Response, payload: unknown): OperationError {
  const code = errorCode(payload);
  const extension =
    code === "extension_required" ? (payload as Record<string, unknown>).extension : undefined;
  const retryAfter = response.status === 429 ? response.headers.get("retry-after") : null;
  const details = {
    ...(typeof extension === "string" ? { extension } : {}),
    ...(retryAfter ? { retry_after: retryAfter } : {}),
  };
  return new OperationError(code ?? "operation_request_failed", "the operation request was refused", {
    statusCode: response.status,
    ...(Object.keys(details).length ? { details } : {}),
  });
}

function expectOperation(payload: unknown, operationId: string): Operation {
  const candidate =
    typeof payload === "object" && payload !== null && "operation" in payload
      ? (payload as Record<string, unknown>).operation
      : payload;
  let operation: Operation;
  try {
    operation = parseOperation(candidate);
  } catch (cause) {
    throw new OperationError("invalid_operation", "operation was malformed", { cause });
  }
  if (operation.operation_id !== operationId) {
    throw new OperationError("invalid_operation", "the company answered for another operation");
  }
  return operation;
}

function flatten(value: unknown, prefix = ""): Map<string, string> {
  const flat = new Map<string, string>();
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      for (const [path, leaf] of flatten(item, `${prefix}${key}.`)) flat.set(path, leaf);
    }
    return flat;
  }
  flat.set(prefix.replace(/\.$/, ""), JSON.stringify(value));
  return flat;
}

function changedPaths(before: Operation, after: Operation): readonly string[] {
  const old = flatten(before.terms ?? {});
  const now = flatten(after.terms ?? {});
  const changed = [...new Set([...old.keys(), ...now.keys()])].filter((path) => old.get(path) !== now.get(path)).sort();
  return before.summary !== after.summary ? ["summary", ...changed] : changed;
}
