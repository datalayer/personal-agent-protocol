/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { ConversationError, ProtocolValidationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  parseConversationEvent,
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
import { byEndpoint, conversationResult, traced } from "./telemetry.js";
import { DpopFetchClient } from "./transport.js";
import { readLimited } from "./limits.js";

const identifier = /^[A-Za-z0-9_-]{1,256}$/;

export interface ConversationReceipt {
  readonly conversation_id: string;
  readonly status: ConversationStatus;
  readonly responder: ConversationResponder;
}

export type ConversationResponse = ConversationReceipt | ConversationEventPage;

/**
 * A piece of a message still being written (SSE `text-delta`, §7.6): for
 * display only. The complete `message` event replaces the pieces, and a
 * personal agent MUST NOT act on a delta's text, so `actionable` is `false`.
 */
export interface TextDelta {
  readonly kind: "text-delta";
  readonly message_id: string;
  readonly text: string;
  readonly actionable: false;
}

/** The stream was reopened from `Last-Event-ID`; drop the partial messages named. */
export interface StreamReconnected {
  readonly kind: "reconnected";
  readonly lastEventId: string | undefined;
  readonly discardedMessageIds: readonly string[];
}

export type StreamItem = ConversationEvent | TextDelta | StreamReconnected;

export interface ConversationStreamOptions extends ConversationRequestOptions {
  readonly lastEventId?: string;
  readonly maxReconnects?: number;
  readonly maxSeenEventIds?: number;
}

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

  start(
    endpoint: string,
    message: Message,
    options: StartConversationOptions,
  ): Promise<ConversationResponse> {
    return traced(
      this.#reactor,
      "pap.conversation.start",
      byEndpoint(endpoint),
      () => this.#start(endpoint, message, options),
      conversationResult,
    );
  }

  async #start(
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

  send(
    endpoint: string,
    conversationId: string,
    message: Message,
    options: ConversationRequestOptions,
  ): Promise<ConversationResponse> {
    return traced(
      this.#reactor,
      "pap.conversation.send",
      byEndpoint(endpoint),
      () => this.#sendMessage(endpoint, conversationId, message, options),
      conversationResult,
    );
  }

  async #sendMessage(
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
  readEvents(
    endpoint: string,
    conversationId: string,
    options: ConversationRequestOptions,
  ): Promise<ConversationEventPage> {
    return traced(
      this.#reactor,
      "pap.conversation.read_events",
      byEndpoint(endpoint),
      () => this.#readEvents(endpoint, conversationId, options),
      conversationResult,
    );
  }

  async #readEvents(
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

  /** Open a Direct Conversation under an open parent (§7.10). */
  startDirect(
    endpoint: string,
    parentConversationId: string,
    message: Message,
    options: ConversationRequestOptions,
  ): Promise<ConversationResponse> {
    return traced(
      this.#reactor,
      "pap.conversation.start_direct",
      byEndpoint(endpoint),
      () => this.#startDirect(endpoint, parentConversationId, message, options),
      conversationResult,
    );
  }

  async #startDirect(
    endpoint: string,
    parentConversationId: string,
    message: Message,
    options: ConversationRequestOptions,
  ): Promise<ConversationResponse> {
    return this.start(endpoint, message, { ...options, parentConversationId });
  }

  /** Ask for a person at the company (§7.9): `queued` while one is found. */
  handoff(
    endpoint: string,
    conversationId: string,
    options: ConversationRequestOptions,
  ): Promise<ConversationReceipt> {
    return traced(
      this.#reactor,
      "pap.conversation.handoff",
      byEndpoint(endpoint),
      () => this.#handoff(endpoint, conversationId, options),
      conversationResult,
    );
  }

  async #handoff(
    endpoint: string,
    conversationId: string,
    options: ConversationRequestOptions,
  ): Promise<ConversationReceipt> {
    return this.#control(endpoint, conversationId, "handoff", 202, options);
  }

  /** Close the conversation (§7.12); what it started is not cancelled. */
  close(
    endpoint: string,
    conversationId: string,
    options: ConversationRequestOptions,
  ): Promise<ConversationReceipt> {
    return traced(
      this.#reactor,
      "pap.conversation.close",
      byEndpoint(endpoint),
      () => this.#close(endpoint, conversationId, options),
      conversationResult,
    );
  }

  async #close(
    endpoint: string,
    conversationId: string,
    options: ConversationRequestOptions,
  ): Promise<ConversationReceipt> {
    return this.#control(endpoint, conversationId, "close", 200, options);
  }

  /**
   * Yield events from the company's SSE stream until the conversation closes,
   * reopening from `Last-Event-ID` when the company ends the stream (§7.6).
   * A company that does not stream answers `sse_unsupported`.
   */
  async *stream(
    endpoint: string,
    conversationId: string,
    options: ConversationStreamOptions,
  ): AsyncGenerator<StreamItem> {
    assertIdentifier(conversationId, "conversation ID");
    const maxReconnects = options.maxReconnects ?? 5;
    const maximum = options.maxSeenEventIds ?? 10_000;
    let lastEventId = options.lastEventId;
    if (lastEventId !== undefined) assertIdentifier(lastEventId, "last event ID");
    const url = `${endpoint.replace(/\/$/, "")}/${conversationId}/events`;
    const seen = new Set<string>();
    let idle = 0;
    while (true) {
      let progressed = false;
      const partial: string[] = [];
      const response = await this.#transport.request("GET", url, {
        token: options.token,
        tenantId: options.tenantId,
        pairwiseUserId: options.pairwiseUserId,
        issuer: options.issuer,
        headers: {
          Accept: "text/event-stream",
          ...(lastEventId === undefined ? {} : { "Last-Event-ID": lastEventId }),
        },
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
      if (response.status !== 200) {
        await this.#responsePayload(response, 200);
      }
      const type = response.headers.get("content-type")?.split(";", 1)[0]?.trim();
      if (type !== "text/event-stream" || !response.body) {
        await response.body?.cancel();
        throw new ConversationError("sse_unsupported", "the company does not stream this conversation");
      }
      for await (const frame of sseFrames(response.body, this.#maxResponseBytes)) {
        if (frame.event === "text-delta") {
          const delta = parseDelta(frame.data);
          if (!partial.includes(delta.message_id)) partial.push(delta.message_id);
          yield delta;
          continue;
        }
        let event: ConversationEvent;
        try {
          event = parseConversationEvent(parseJsonStrict(frame.data));
        } catch (cause) {
          throw new ConversationError("invalid_response", "conversation event was malformed", { cause });
        }
        if (frame.id !== undefined && frame.id !== event.id) {
          throw new ConversationError("invalid_response", "SSE id and event id disagree");
        }
        lastEventId = event.id;
        if (seen.has(event.id)) continue;
        if (seen.size >= maximum) {
          throw new ConversationError(
            "event_history_too_large",
            "conversation event de-duplication limit was exceeded",
          );
        }
        seen.add(event.id);
        progressed = true;
        const messageId = event.message?.id;
        if (messageId !== undefined && partial.includes(messageId)) {
          partial.splice(partial.indexOf(messageId), 1);
        }
        yield event;
        if (event.type === "state" && event.status === "closed") return;
      }
      idle = progressed ? 0 : idle + 1;
      if (idle > maxReconnects) {
        throw new ConversationError(
          "stream_unavailable",
          "the conversation stream kept closing without events",
        );
      }
      yield { kind: "reconnected", lastEventId, discardedMessageIds: [...partial] };
    }
  }

  async #control(
    endpoint: string,
    conversationId: string,
    action: "handoff" | "close",
    expectedStatus: number,
    options: ConversationRequestOptions,
  ): Promise<ConversationReceipt> {
    assertIdentifier(conversationId, "conversation ID");
    const response = await this.#transport.request(
      "POST",
      `${endpoint.replace(/\/$/, "")}/${conversationId}/${action}`,
      {
        token: options.token,
        tenantId: options.tenantId,
        pairwiseUserId: options.pairwiseUserId,
        issuer: options.issuer,
        headers: { "Content-Type": "application/json" },
        body: "{}",
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      },
    );
    const parsed = parseConversationResponse(await this.#responsePayload(response, expectedStatus));
    if ("events" in parsed) {
      throw new ConversationError("invalid_response", "conversation response was malformed");
    }
    return parsed;
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
    const bytes = await readLimited(response, this.#maxResponseBytes);
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
      const openId =
        error === "direct_conversation_open" &&
        typeof (payload as Record<string, unknown>).conversation_id === "string" &&
        identifier.test((payload as Record<string, unknown>).conversation_id as string)
          ? ((payload as Record<string, unknown>).conversation_id as string)
          : undefined;
      // A 429's Retry-After goes to the caller, who waits at least this long (§4.3).
      const retryAfter = response.status === 429 ? response.headers.get("retry-after") : null;
      const details = {
        ...(openId === undefined ? {} : { conversation_id: openId }),
        ...(retryAfter ? { retry_after: retryAfter } : {}),
      };
      throw new ConversationError(
        typeof error === "string" ? error : "conversation_request_failed",
        "conversation request was rejected",
        {
          statusCode: response.status,
          ...(Object.keys(details).length ? { details } : {}),
        },
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

interface SseFrame {
  readonly event: string;
  readonly data: string;
  readonly id: string | undefined;
}

/** Parse SSE into frames; comments (keep-alives) are skipped. */
async function* sseFrames(
  body: ReadableStream<Uint8Array>,
  maxEventBytes: number,
): AsyncGenerator<SseFrame> {
  const decoder = new TextDecoder();
  let buffer = "";
  let event = "message";
  let data: string[] = [];
  let id: string | undefined;
  let size = 0;
  const dispatch = (): SseFrame | undefined => {
    const frame = data.length ? { event, data: data.join("\n"), id } : undefined;
    event = "message";
    data = [];
    id = undefined;
    size = 0;
    return frame;
  };
  const reader = body.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      buffer += done ? decoder.decode() : decoder.decode(value, { stream: true });
      let newline: number;
      while ((newline = buffer.search(/\r?\n/)) >= 0) {
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(buffer[newline] === "\r" ? newline + 2 : newline + 1);
        if (line === "") {
          const frame = dispatch();
          if (frame) yield frame;
          continue;
        }
        if (line.startsWith(":")) continue;
        const colon = line.indexOf(":");
        const field = colon < 0 ? line : line.slice(0, colon);
        let content = colon < 0 ? "" : line.slice(colon + 1);
        if (content.startsWith(" ")) content = content.slice(1);
        size += content.length;
        if (size > maxEventBytes) {
          throw new ConversationError("response_too_large", "conversation event exceeded limit");
        }
        if (field === "event") event = content;
        else if (field === "data") data.push(content);
        else if (field === "id") id = content || undefined;
      }
      if (done) break;
    }
    const last = dispatch();
    if (last) yield last;
  } finally {
    reader.releaseLock();
  }
}

function parseDelta(data: string): TextDelta {
  let source: unknown;
  try {
    source = parseJsonStrict(data);
  } catch (cause) {
    throw new ConversationError("invalid_response", "text-delta was malformed", { cause });
  }
  const value = source as Record<string, unknown>;
  if (
    typeof source !== "object" ||
    source === null ||
    typeof value.message_id !== "string" ||
    !identifier.test(value.message_id) ||
    typeof value.text !== "string"
  ) {
    throw new ConversationError("invalid_response", "text-delta was malformed");
  }
  return { kind: "text-delta", message_id: value.message_id, text: value.text, actionable: false };
}
