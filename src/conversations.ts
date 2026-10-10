import type { ReactorPlatformView } from "@datalayer/reactor";

import { ConversationError, ProtocolValidationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  parseConversationEventPage,
  parseMessage,
  type ConversationEvent,
  type ConversationEventPage,
  type ConversationResponder,
  type ConversationStatus,
  type Message,
} from "./models.js";
import { RandomSources, firstContribution } from "./reactor.js";
import type { SessionToken } from "./sessions.js";
import { DpopFetchClient } from "./transport.js";

const identifier = /^[A-Za-z0-9_-]{1,256}$/;

export interface ConversationReceipt {
  readonly conversation_id: string;
  readonly status: ConversationStatus;
  readonly responder: ConversationResponder;
}

export type ConversationResponse = ConversationReceipt | ConversationEventPage;

export interface ConversationRequestOptions {
  readonly token: SessionToken;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly issuer: string;
  readonly cursor?: string;
  readonly wait?: number;
  readonly signal?: AbortSignal;
}

export interface StartConversationOptions extends ConversationRequestOptions {
  readonly parentConversationId?: string;
}

export interface ConversationEventOptions extends ConversationRequestOptions {
  /** Called before one recovery read from the beginning after cursor expiry. */
  readonly onCursorExpired?: () => void | Promise<void>;
  /** Bound retained event IDs used to suppress reconnect duplicates. */
  readonly maxSeenEventIds?: number;
}

export interface ConversationClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly transport: DpopFetchClient;
  readonly maxResponseBytes?: number;
}

function assertIdentifier(value: string, label: string): void {
  if (!identifier.test(value)) {
    throw new ProtocolValidationError(
      "invalid_identifier",
      `${label} is invalid`,
    );
  }
}

function base64Url(bytes: Uint8Array): string {
  const alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += alphabet[first >>> 2];
    output += alphabet[((first & 3) << 4) | ((second ?? 0) >>> 4)];
    if (second !== undefined)
      output += alphabet[((second & 15) << 2) | ((third ?? 0) >>> 6)];
    if (third !== undefined) output += alphabet[third & 63];
  }
  return output;
}

/** Generate a user-global message ID with at least 128 random bits. */
export function generateMessageId(reactor: ReactorPlatformView): string {
  const bytes = firstContribution(
    reactor,
    RandomSources,
    "random source",
  ).bytes(16);
  if (bytes.byteLength < 16) {
    throw new ConversationError(
      "insufficient_entropy",
      "message IDs require 128 random bits",
    );
  }
  return `msg_${base64Url(bytes)}`;
}

/** Start and continue PAP conversations through a proof-bound transport. */
export class ConversationClient {
  readonly #reactor: ReactorPlatformView;
  readonly #transport: DpopFetchClient;
  readonly #maxResponseBytes: number;

  constructor(options: ConversationClientOptions) {
    const maximum = options.maxResponseBytes ?? 1024 * 1024;
    if (!Number.isInteger(maximum) || maximum <= 0) {
      throw new RangeError("maxResponseBytes must be positive");
    }
    this.#reactor = options.reactor;
    this.#transport = options.transport;
    this.#maxResponseBytes = maximum;
  }

  generateMessageId(): string {
    return generateMessageId(this.#reactor);
  }

  async start(
    endpoint: string,
    message: Message,
    options: StartConversationOptions,
  ): Promise<ConversationResponse> {
    const body: Record<string, unknown> = { message: this.#outgoing(message) };
    if (options.parentConversationId !== undefined) {
      assertIdentifier(options.parentConversationId, "parent conversation ID");
      body.parent_conversation_id = options.parentConversationId;
    }
    return this.#send(endpoint, body, 201, options);
  }

  async send(
    endpoint: string,
    conversationId: string,
    message: Message,
    options: ConversationRequestOptions,
  ): Promise<ConversationResponse> {
    assertIdentifier(conversationId, "conversation ID");
    return this.#send(
      `${endpoint.replace(/\/$/, "")}/${conversationId}/messages`,
      { message: this.#outgoing(message) },
      202,
      options,
    );
  }

  /** Read one ordered page of events after an opaque cursor. */
  async readEvents(
    endpoint: string,
    conversationId: string,
    options: ConversationRequestOptions,
  ): Promise<ConversationEventPage> {
    assertIdentifier(conversationId, "conversation ID");
    const target = this.#eventTarget(
      endpoint,
      conversationId,
      options.cursor,
      options.wait,
    );
    const response = await this.#transport.request("GET", target, {
      token: options.token,
      tenantId: options.tenantId,
      pairwiseUserId: options.pairwiseUserId,
      issuer: options.issuer,
      headers: { Accept: "application/json" },
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const payload = await this.#responsePayload(response, 200);
    let page: ConversationEventPage;
    try {
      page = parseConversationEventPage(payload);
    } catch (cause) {
      throw new ConversationError(
        "invalid_response",
        "conversation response was malformed",
        { cause },
      );
    }
    if (page.conversation_id !== conversationId) {
      throw new ConversationError(
        "conversation_mismatch",
        "conversation event page belongs to a different conversation",
      );
    }
    return page;
  }

  /** Yield ordered, de-duplicated events until the conversation closes. */
  async *events(
    endpoint: string,
    conversationId: string,
    options: ConversationEventOptions,
  ): AsyncGenerator<ConversationEvent> {
    const {
      cursor: initialCursor,
      wait: pollWait,
      onCursorExpired,
      maxSeenEventIds,
      ...requestOptions
    } = options;
    const maximum = maxSeenEventIds ?? 10_000;
    if (!Number.isInteger(maximum) || maximum <= 0) {
      throw new RangeError("maxSeenEventIds must be positive");
    }
    let cursor = initialCursor;
    let recoveredCursor = false;
    let drainBacklog = false;
    const seen = new Set<string>();
    while (true) {
      let page: ConversationEventPage;
      try {
        page = await this.readEvents(endpoint, conversationId, {
          ...requestOptions,
          ...(cursor === undefined ? {} : { cursor }),
          ...(drainBacklog
            ? { wait: 0 }
            : pollWait === undefined
              ? {}
              : { wait: pollWait }),
        });
      } catch (cause) {
        if (
          !(cause instanceof ConversationError) ||
          cause.code !== "cursor_expired" ||
          cursor === undefined ||
          recoveredCursor
        ) {
          throw cause;
        }
        recoveredCursor = true;
        cursor = undefined;
        await onCursorExpired?.();
        continue;
      }
      for (const event of page.events) {
        if (seen.has(event.id)) continue;
        if (seen.size >= maximum) {
          throw new ConversationError(
            "event_history_too_large",
            "conversation event de-duplication limit was exceeded",
          );
        }
        seen.add(event.id);
        yield event;
      }
      cursor = page.cursor;
      if (page.status === "closed" && !page.has_more) return;
      drainBacklog = page.has_more;
    }
  }

  #outgoing(message: Message): Message {
    const parsed = parseMessage(message);
    if (parsed.role !== undefined) {
      throw new ProtocolValidationError(
        "invalid_message",
        "outgoing messages cannot set role",
      );
    }
    return parsed;
  }

  async #send(
    endpoint: string,
    body: Readonly<Record<string, unknown>>,
    expectedStatus: number,
    options: ConversationRequestOptions,
  ): Promise<ConversationResponse> {
    const target = new URL(endpoint);
    if (target.search || target.hash) {
      throw new ProtocolValidationError(
        "invalid_endpoint",
        "conversation endpoint cannot have query or fragment",
      );
    }
    if (options.cursor !== undefined) {
      assertIdentifier(options.cursor, "cursor");
      target.searchParams.set("cursor", options.cursor);
    }
    if (options.wait !== undefined) {
      if (!Number.isInteger(options.wait) || options.wait < 0) {
        throw new ProtocolValidationError(
          "invalid_wait",
          "wait must be a non-negative integer",
        );
      }
      target.searchParams.set("wait", String(options.wait));
    }
    const response = await this.#transport.request("POST", target.toString(), {
      token: options.token,
      tenantId: options.tenantId,
      pairwiseUserId: options.pairwiseUserId,
      issuer: options.issuer,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const payload = await this.#responsePayload(response, expectedStatus);
    return parseConversationResponse(payload);
  }

  #eventTarget(
    endpoint: string,
    conversationId: string,
    cursor?: string,
    wait?: number,
  ): string {
    const target = new URL(
      `${endpoint.replace(/\/$/, "")}/${conversationId}/events`,
    );
    if (target.search || target.hash) {
      throw new ProtocolValidationError(
        "invalid_endpoint",
        "conversation endpoint cannot have query or fragment",
      );
    }
    if (cursor !== undefined) {
      assertIdentifier(cursor, "cursor");
      target.searchParams.set("cursor", cursor);
    }
    if (wait !== undefined) {
      if (!Number.isInteger(wait) || wait < 0) {
        throw new ProtocolValidationError(
          "invalid_wait",
          "wait must be a non-negative integer",
        );
      }
      target.searchParams.set("wait", String(wait));
    }
    return target.toString();
  }

  async #responsePayload(
    response: Response,
    expectedStatus: number,
  ): Promise<unknown> {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > this.#maxResponseBytes) {
      throw new ConversationError(
        "response_too_large",
        "conversation response exceeded limit",
      );
    }
    let payload: unknown;
    try {
      payload = parseJsonStrict(
        new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      );
    } catch (cause) {
      throw new ConversationError(
        "invalid_response",
        "conversation returned invalid JSON",
        {
          cause,
        },
      );
    }
    if (response.status !== expectedStatus) {
      const error =
        typeof payload === "object" &&
        payload !== null &&
        !Array.isArray(payload)
          ? (payload as Record<string, unknown>).error
          : undefined;
      throw new ConversationError(
        typeof error === "string" ? error : "conversation_request_failed",
        "conversation request was rejected",
        { statusCode: response.status },
      );
    }
    return payload;
  }
}

function parseConversationResponse(value: unknown): ConversationResponse {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ConversationError(
      "invalid_response",
      "conversation response was malformed",
    );
  }
  const source = value as Record<string, unknown>;
  if (source.events !== undefined) return parseConversationEventPage(source);
  if (typeof source.conversation_id !== "string") {
    throw new ConversationError(
      "invalid_response",
      "conversation response was malformed",
    );
  }
  assertIdentifier(source.conversation_id, "conversation ID");
  if (
    !(["working", "idle", "queued", "closed"] as unknown[]).includes(
      source.status,
    )
  ) {
    throw new ConversationError(
      "invalid_response",
      "conversation response was malformed",
    );
  }
  if (!(["agent", "human"] as unknown[]).includes(source.responder)) {
    throw new ConversationError(
      "invalid_response",
      "conversation response was malformed",
    );
  }
  return {
    conversation_id: source.conversation_id,
    status: source.status as ConversationStatus,
    responder: source.responder as ConversationResponder,
  };
}
