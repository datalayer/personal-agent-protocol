/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Feedback: telling a company what its users couldn't do through the protocol (§8), as
 * in Python's `personal_agent_protocol.feedback`.
 *
 * A company that wants to know lists `feedback.endpoint` in its tasks response, which the
 * agent gets per Session from `tasks.endpoint` (§9, `TasksClient`). When a
 * user's task can't be done — not with the Company Agent, not with its APIs, not on its
 * website in a browser session — the personal agent MAY send one `FeedbackReport` for
 * that task with the Session header and, signed in, the access token:
 *
 * ```ts
 * const tasks = await new TasksClient({ transport }).get(company.document, { session });
 * const endpoint = tasks.feedbackEndpoint;
 * if (endpoint !== undefined) {
 *   await new FeedbackClient({ transport }).report(
 *     endpoint,
 *     { task: "Pay with a gift card", description: "..." },
 *     { token, ...who },
 *   );
 * }
 * ```
 *
 * From 1.1 a company can list the tasks it already knows can't be done
 * (`SessionTasks.listedTasks`, each an `id` and a `task` phrase). When the user's task matches
 * one, the agent reports its ID instead of describing it (`listedReport(id, ...)`), and may
 * gather the IDs of a Session into one report, sent before the Session ends. A report has one
 * form or the other, never both.
 *
 * A free-text report describes the task, never the user: no names, contact details, order or
 * account numbers (SHOULD NOT), and never a secret (MUST NOT). The Session already
 * tells the company which personal agent and which user sent it. Errors are reported,
 * never retried here: send one report per task, not one per attempt.
 */
import { PersonalAgentProtocolError, ProtocolValidationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { readLimited } from "./limits.js";
import {
  LISTED_TASK_ID,
  LISTED_TASKS_SINCE,
  parseAlternative,
  versionDefines,
  type Alternative,
} from "./models.js";
import { refusalCode, refusalDetails } from "./refusals.js";
import type { AccessToken, PapSession } from "./sessions.js";
import type { SessionFetchClient } from "./transport.js";

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
 * One report of what the company offers no way to do through the protocol (§9.3).
 *
 * In one of two forms, never both: `task` and `description`, a task in free text (nothing
 * about the user, no identifiers, no secret), or, from 1.1, `task_ids`, the IDs of one or more
 * tasks the company lists in `feedback.tasks`, each once (`listedReport`). The object is the
 * request body: the one form the report has, and nothing else.
 */
export type FeedbackReport =
  | { readonly task: string; readonly description: string }
  | { readonly task_ids: readonly string[] };

const REPORT_FIELDS = new Set(["task", "description", "task_ids"]);

/** A report of listed tasks, by their IDs from `SessionTasks.listedTasks` (§9.3). */
export function listedReport(...taskIds: string[]): FeedbackReport {
  return parseFeedbackReport({ task_ids: taskIds });
}

/**
 * A report to send, checked: `task` 1..200 and `description` 1..2000, or `task_ids`, one or
 * more listed task IDs, each once; one form or the other, not both.
 */
export function parseFeedbackReport(value: {
  readonly task?: string;
  readonly description?: string;
  readonly task_ids?: readonly string[];
}): FeedbackReport {
  if (typeof value !== "object" || value === null || Object.keys(value).some((key) => !REPORT_FIELDS.has(key))) {
    throw new ProtocolValidationError(
      "invalid_feedback",
      "a feedback report has task_ids, or task and description, only",
    );
  }
  const { task, description } = value;
  const taskIds = value.task_ids;
  if (taskIds !== undefined) {
    if (task !== undefined || description !== undefined) {
      throw new ProtocolValidationError(
        "invalid_feedback",
        "a report has task_ids, or task and description, not both",
      );
    }
    if (!Array.isArray(taskIds) || taskIds.length === 0) {
      throw new ProtocolValidationError("invalid_feedback", "task_ids names at least one listed task");
    }
    if (new Set(taskIds).size !== taskIds.length) {
      throw new ProtocolValidationError("invalid_feedback", "task_ids names each listed task once");
    }
    if (taskIds.some((id) => typeof id !== "string" || !LISTED_TASK_ID.test(id))) {
      throw new ProtocolValidationError(
        "invalid_feedback",
        "a listed task's ID is lowercase letters, digits, - and _",
      );
    }
    return { task_ids: [...taskIds] };
  }
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

export interface FeedbackClientOptions {
  readonly transport: SessionFetchClient;
  readonly maxResponseBytes?: number;
}

export interface FeedbackReportOptions {
  readonly session: PapSession;
  /** Signed in with it, signed out without. */
  readonly token?: AccessToken | undefined;
  readonly signal?: AbortSignal;
}

/** Send feedback reports in a Session, signed in or out. */
export class FeedbackClient {
  readonly #transport: SessionFetchClient;
  readonly #maxResponseBytes: number;

  constructor(options: FeedbackClientOptions) {
    const limit = options.maxResponseBytes ?? 16 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#transport = options.transport;
    this.#maxResponseBytes = limit;
  }

  /**
   * `POST {feedback.endpoint}`: accepted, or answered with a way to do it (§9.3).
   *
   * `202` with no body returns `undefined`; `200` with an alternative (§9.2) returns it,
   * as content from the company, its references for the caller to filter with
   * `usableReferences`. Anything else is a `FeedbackError`. Don't report a task the
   * company lists as excluded (§9.1).
   *
   * A report of listed tasks (`task_ids`) is 1.1's: `RangeError` in a Session that names an
   * earlier version, which sends a Company nothing its version doesn't define (§3.4). The
   * company answers it with `202`, and ignores IDs it no longer lists.
   *
   * A refusal is never retried here: a 429 carries its `Retry-After` in
   * `details.retry_after`, and the caller waits at least that long (§5.6).
   */
  async report(
    endpoint: string,
    report: FeedbackReport,
    options: FeedbackReportOptions,
  ): Promise<Alternative | undefined> {
    const checked = parseFeedbackReport(report);
    if ("task_ids" in checked && !versionDefines(options.session.protocolVersion, LISTED_TASKS_SINCE)) {
      throw new RangeError(
        `listed tasks are reported by ID from ${LISTED_TASKS_SINCE}: this Session names ${options.session.protocolVersion}`,
      );
    }
    const response = await this.#transport.request("POST", endpoint, {
      session: options.session,
      token: options.token,
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
    const details = refusalDetails(response, payload);
    throw new FeedbackError(
      // In the JSON body, or a token error in WWW-Authenticate (§3.3, §7).
      refusalCode(response, payload, "feedback_request_failed"),
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
