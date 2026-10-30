/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Feedback: telling a company what its users couldn't do through the protocol (§8), as
 * in Python's `personal_agent_protocol.feedback`.
 *
 * A company that wants to know lists `feedback.endpoint` in its poppy.json. When a
 * user's task can't be done — not with the Company Agent, not with its APIs, not on its
 * website in a browser session — the personal agent MAY send one `FeedbackReport` for
 * that task with the Session's token and a DPoP proof:
 *
 * ```ts
 * const endpoint = feedbackEndpoint(company.document);
 * if (endpoint !== undefined) {
 *   await new FeedbackClient({ transport }).report(
 *     endpoint,
 *     { task: "Pay with a gift card", description: "..." },
 *     { token, ...who },
 *   );
 * }
 * ```
 *
 * The report describes the task, never the user: no names, contact details, order or
 * account numbers (SHOULD NOT), and never a secret (MUST NOT). The Session already
 * tells the company which personal agent and which user sent it. Errors are reported,
 * never retried here: send one report per task, not one per attempt.
 */
import { PersonalAgentProtocolError, ProtocolValidationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { readLimited } from "./limits.js";
import { parseAlternative, type Alternative, type DiscoveryDocument } from "./models.js";
import { challengeParameters, refusalDetails } from "./refusals.js";
import type { SessionToken } from "./sessions.js";
import type { DpopFetchClient } from "./transport.js";

/** The longest `task` a report carries (§8). */
export const FEEDBACK_TASK_MAX_LENGTH = 200;
/** The longest `description` a report carries (§8). */
export const FEEDBACK_DESCRIPTION_MAX_LENGTH = 2000;

/** The company refused a feedback report: `invalid_request`, `rate_limited`, a token error. */
export class FeedbackError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; details?: Readonly<Record<string, unknown>>; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "FeedbackError";
  }
}

/**
 * One report of a task the company offers no way to do through the protocol (§8).
 *
 * Exactly these two fields: nothing about the user, no identifiers, no secret.
 */
export interface FeedbackReport {
  readonly task: string;
  readonly description: string;
}

const REPORT_FIELDS = new Set(["task", "description"]);

/** A report to send, checked: `task` 1..200, `description` 1..2000. */
export function parseFeedbackReport(value: {
  readonly task: string;
  readonly description: string;
}): FeedbackReport {
  if (typeof value !== "object" || value === null || Object.keys(value).some((key) => !REPORT_FIELDS.has(key))) {
    throw new ProtocolValidationError("invalid_feedback", "a feedback report has task and description only");
  }
  const { task, description } = value;
  if (typeof task !== "string" || task.length < 1 || task.length > FEEDBACK_TASK_MAX_LENGTH) {
    throw new ProtocolValidationError("invalid_feedback", "task is 1 to 200 characters");
  }
  if (
    typeof description !== "string" ||
    description.length < 1 ||
    description.length > FEEDBACK_DESCRIPTION_MAX_LENGTH
  ) {
    throw new ProtocolValidationError("invalid_feedback", "description is 1 to 2000 characters");
  }
  return { task, description };
}

/** The company's feedback endpoint, when it asks for feedback. */
export function feedbackEndpoint(document: DiscoveryDocument): string | undefined {
  return document.feedback?.endpoint;
}

export interface FeedbackClientOptions {
  readonly transport: DpopFetchClient;
  readonly maxResponseBytes?: number;
}

export interface FeedbackReportOptions {
  readonly token: SessionToken;
  readonly tenantId: string;
  readonly issuer: string;
  readonly signal?: AbortSignal;
}

/** Send feedback reports with a Session Token, signed in or out, and a DPoP proof. */
export class FeedbackClient {
  readonly #transport: DpopFetchClient;
  readonly #maxResponseBytes: number;

  constructor(options: FeedbackClientOptions) {
    const limit = options.maxResponseBytes ?? 16 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#transport = options.transport;
    this.#maxResponseBytes = limit;
  }

  /**
   * `POST {feedback.endpoint}`: accepted, or answered with a way to do it (§8.3).
   *
   * `202` with no body returns `undefined`; `200` with an alternative (§8.2) returns it,
   * as content from the company, its references for the caller to filter with
   * `usableReferences`. Anything else is a `FeedbackError`. Don't report a task the
   * company lists as excluded (§8.1).
   *
   * A refusal is never retried here: a 429 carries its `Retry-After` in
   * `details.retry_after`, and the caller waits at least that long (§4.3).
   */
  async report(
    endpoint: string,
    report: { readonly task: string; readonly description: string },
    options: FeedbackReportOptions,
  ): Promise<Alternative | undefined> {
    const checked = parseFeedbackReport(report);
    const response = await this.#transport.request("POST", endpoint, {
      token: options.token,
      tenantId: options.tenantId,
      issuer: options.issuer,
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(checked),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (response.status === 202) {
      await response.body?.cancel().catch(() => undefined);
      return undefined;
    }
    const payload = await this.#payload(response);
    if (response.status === 200) {
      try {
        return parseAlternative(payload);
      } catch (cause) {
        throw new FeedbackError(
          "invalid_alternative",
          "the company answered with a malformed alternative",
          { statusCode: 200, cause },
        );
      }
    }
    let code =
      typeof payload === "object" && payload !== null && !Array.isArray(payload)
        ? (payload as Record<string, unknown>).error
        : undefined;
    if (typeof code !== "string") {
      // A token error may come only in WWW-Authenticate (§6).
      code = challengeParameters(response.headers.get("www-authenticate")).error;
    }
    const details = refusalDetails(response, payload);
    throw new FeedbackError(
      typeof code === "string" ? code : "feedback_request_failed",
      "the company refused the feedback report",
      { statusCode: response.status, ...(Object.keys(details).length > 0 ? { details } : {}) },
    );
  }

  async #payload(response: Response): Promise<unknown> {
    const bytes = await readLimited(response, this.#maxResponseBytes);
    if (bytes.byteLength === 0 || bytes.byteLength > this.#maxResponseBytes) return undefined;
    try {
      return parseJsonStrict(new TextDecoder().decode(bytes));
    } catch {
      return undefined;
    }
  }
}
