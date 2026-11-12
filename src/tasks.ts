/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Task coverage per Session: excluded tasks, skills and the feedback endpoint (§9), as in
 * Python's `personal_agent_protocol.tasks`.
 *
 * A Company that lists excluded tasks, publishes skills or takes feedback names one
 * `tasks.endpoint` in its poppy.json. The Personal Agent sends `GET {tasks.endpoint}` with the
 * Session header and no access token, also in a signed-in Session, before it starts on a task
 * in that Session:
 *
 * ```ts
 * const tasks = await new TasksClient({ transport }).get(company.document, { session });
 * for (const excluded of tasks.excludedTasks) { ... } // the agent's judgment whether the task is one
 * for (const skill of tasks.skills) await fetchSkill(skill); // each `url` resolved against tasks.endpoint
 * if (tasks.feedbackEndpoint !== undefined) { ... } // a Session header destination (§5.2)
 * ```
 *
 * What this client guarantees:
 *
 * - **One Session.** A response is kept for the Session it was fetched in, for as long as its
 *   caching headers allow, and never used in another: the cache is keyed by the endpoint, the
 *   `client_id`, the `sid` and the User ID, and `SessionTasks.session` names the `sid` it
 *   belongs to.
 * - **No access token.** The response describes what the Company offers, not the User's
 *   account, so the request is always signed out.
 * - **No redirect.** The transport refuses one: nothing is sent to the new URL (§3).
 * - **Carrying on.** With no response (no endpoint, a network failure, a refusal, a body that
 *   is not a tasks response) the agent carries on as if the Company listed no excluded tasks,
 *   published no skills and took no feedback: `SessionTasks.available` is `false`.
 *   `invalid_session` and `version_unsupported` are thrown: they say the agent's own header is
 *   wrong, and are the same at every endpoint (§3.4, §5.3).
 */
import { PersonalAgentProtocolError, TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { DEFAULT_CACHE_BOUNDS, cacheLifetime, checkCacheBounds, readLimited, type CacheBounds } from "./limits.js";
import {
  parseTasksResponse,
  usableSkills,
  type DiscoveredCompany,
  type DiscoveryDocument,
  type ExcludedTask,
  type SkillEntry,
  type TasksResponse,
} from "./models.js";
import type { PapSession } from "./sessions.js";
import { sessionError, type SessionFetchClient } from "./transport.js";

/** The tasks endpoint refused the Session header: `invalid_session`, `version_unsupported`. */
export class TasksError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; details?: Readonly<Record<string, unknown>>; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "TasksError";
  }
}

/**
 * A Company's tasks response in one Session (§9): never used in another.
 *
 * `available` is `false` when the Company names no tasks endpoint or gave no response;
 * everything is then empty, and the agent carries on.
 */
export interface SessionTasks {
  /** The `sid` of the Session the response was fetched in. */
  readonly session: string;
  /** `tasks.endpoint`, the base a skill's `url` resolves against (§9.4); absent without one. */
  readonly endpoint?: string;
  readonly response: TasksResponse;
  readonly available: boolean;
  /** The tasks the Company chose not to offer through the protocol (§9.1). */
  readonly excludedTasks: readonly ExcludedTask[];
  /** The Company's skills this SDK can use (§9.4), each `url` resolved against `tasks.endpoint`. */
  readonly skills: readonly SkillEntry[];
  /** Where to report a task that can't be done (§9.3), when the Company takes feedback. */
  readonly feedbackEndpoint?: string;
}

const EMPTY: TasksResponse = Object.freeze({ excluded_tasks: Object.freeze([]) as readonly ExcludedTask[] });

function sessionTasks(session: string, endpoint?: string, response?: TasksResponse): SessionTasks {
  const kept = response ?? EMPTY;
  const feedback = kept.feedback?.endpoint;
  return Object.freeze({
    session,
    ...(endpoint === undefined ? {} : { endpoint }),
    response: kept,
    available: response !== undefined,
    excludedTasks: [...kept.excluded_tasks],
    skills: endpoint === undefined ? [] : usableSkills(kept, endpoint),
    ...(feedback === undefined ? {} : { feedbackEndpoint: feedback }),
  });
}

/** The Company's tasks endpoint, when its poppy.json names one (§3.1). */
export function tasksEndpoint(document: DiscoveryDocument): string | undefined {
  return document.tasks?.endpoint;
}

export interface TasksClientOptions {
  readonly transport: SessionFetchClient;
  /** Cache-Control bounds for a kept response (default: a minute to a day). */
  readonly bounds?: CacheBounds;
  readonly maxResponseBytes?: number;
}

export interface TasksGetOptions {
  readonly session: PapSession;
  /** Read it again, whatever was kept. */
  readonly fresh?: boolean;
  readonly signal?: AbortSignal;
}

/** Get a Company's tasks response in a Session, and keep it for that Session only. */
export class TasksClient {
  readonly #transport: SessionFetchClient;
  readonly #bounds: CacheBounds;
  readonly #maxResponseBytes: number;
  readonly #kept = new Map<string, { readonly expiresAt: number; readonly owner: string; readonly tasks: SessionTasks }>();

  constructor(options: TasksClientOptions) {
    const limit = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#transport = options.transport;
    this.#bounds = checkCacheBounds(options.bounds ?? DEFAULT_CACHE_BOUNDS);
    this.#maxResponseBytes = limit;
  }

  /**
   * `GET {tasks.endpoint}` in `session`, or the response kept for it (§9).
   *
   * Call it before starting on a task in the Session. `fresh` reads it again whatever was
   * kept. The request carries the Session header and never an access token.
   */
  async get(company: DiscoveredCompany | DiscoveryDocument, options: TasksGetOptions): Promise<SessionTasks> {
    const { session } = options;
    const document = "document" in company && "discoveryUrl" in company ? (company as DiscoveredCompany).document : (company as DiscoveryDocument);
    const endpoint = tasksEndpoint(document);
    if (endpoint === undefined) return sessionTasks(session.sid);
    const now = this.#transport.now().getTime();
    const kept = options.fresh === true ? undefined : this.#kept.get(TasksClient.#key(endpoint, session));
    if (kept !== undefined && kept.expiresAt > now) return kept.tasks;
    let response: Response;
    try {
      response = await this.#transport.request("GET", endpoint, {
        session,
        headers: { Accept: "application/json" },
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (error) {
      // No response (a redirect refused included): as if nothing were listed.
      if (error instanceof TransportError) return sessionTasks(session.sid, endpoint);
      throw error;
    }
    const refused = await sessionError(response);
    if (refused !== undefined) {
      // `session_ended` got its one new Session in the transport; what is left says this
      // agent's header is wrong, here as at any endpoint.
      await response.body?.cancel().catch(() => undefined);
      throw new TasksError(refused, "the tasks endpoint refused the Session header", { statusCode: 400 });
    }
    let tasks = sessionTasks(session.sid, endpoint);
    if (response.status === 200) {
      try {
        const bytes = await readLimited(response, this.#maxResponseBytes);
        if (bytes.byteLength <= this.#maxResponseBytes) {
          const payload = parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
          tasks = sessionTasks(session.sid, endpoint, parseTasksResponse(payload));
        }
      } catch {
        // A body that is not a tasks response: as if nothing were listed.
      }
    } else {
      await response.body?.cancel().catch(() => undefined);
    }
    const lifetime = tasks.available ? cacheLifetime(response.headers.get("cache-control"), this.#bounds) : undefined;
    const key = TasksClient.#key(endpoint, session);
    if (lifetime === undefined) this.#kept.delete(key);
    else this.#kept.set(key, { expiresAt: now + lifetime * 1000, owner: TasksClient.#key("", session), tasks });
    return tasks;
  }

  /** Drop what was kept for a Session, when it ends. */
  forget(session: PapSession): void {
    const owner = TasksClient.#key("", session);
    for (const [key, kept] of [...this.#kept]) {
      if (kept.owner === owner) this.#kept.delete(key);
    }
  }

  /** The endpoint, the `client_id`, the `sid` and the User ID, each length-prefixed. */
  static #key(endpoint: string, session: PapSession): string {
    return [endpoint, session.clientId, session.sid, session.sub].map((part) => `${part.length}:${part}`).join("");
  }
}
