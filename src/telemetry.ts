/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Traces and analytics events of the SDK's protocol stages, redacted by construction: the
 * twin of `personal_agent_protocol/telemetry.py`.
 *
 * A host contributes a `TelemetrySink` to `pap.telemetry`; without one nothing is emitted.
 * Each discovery, Session, sign-in, conversation, and operation call then produces one
 * `TelemetryEvent` when it finishes: its name (`TELEMETRY_EVENTS`), its stage, `ok` or
 * `error`, its duration, and attributes from an allowlist (`TELEMETRY_ATTRIBUTES`). A name
 * outside it is a programming error; a value that fails its rule (a lowercase identifier,
 * a domain, an `https` issuer, a count, a flag) is dropped. No rule admits a token, an
 * assertion, a proof, a code, a cookie, a password, a mediated field, an identifier, or a
 * URL with a query.
 *
 * A company built on the SDK's company service reports through the same point (stage
 * `company`): an agent's identity verified for the first time or with new metadata, a
 * Session started or renewed, a Session moved to another interface (a Bearer token for the
 * MCP server, a browser joining it), and each request it refused, with the protocol's
 * code, the route, the status, and whether a proof or assertion was a replay. The device
 * flow's `authorization_pending` and `slow_down` are progress, not refusals.
 *
 * `openTelemetrySink(tracer)` makes each event a span of any OpenTelemetry API tracer
 * (`@opentelemetry/api` stays the host's optional dependency); `RecordingTelemetrySink`
 * keeps events in memory.
 */
import type { ReactorPlatformView } from "@datalayer/reactor";

import { PersonalAgentProtocolError } from "./errors.js";
import { TelemetrySinks, optionalContribution, type TelemetrySink } from "./reactor.js";

export type TelemetryStage =
  | "discovery"
  | "session"
  | "sign_in"
  | "conversation"
  | "operation"
  | "company";
export const TELEMETRY_STAGES: readonly TelemetryStage[] = [
  "discovery",
  "session",
  "sign_in",
  "conversation",
  "operation",
  "company",
];

/** Every event the SDK emits, and its stage. */
export const TELEMETRY_EVENTS: Readonly<Record<string, TelemetryStage>> = Object.freeze({
  "pap.discovery.discover": "discovery",
  "pap.session.start": "session",
  "pap.session.renew": "session",
  "pap.sign_in.direct.begin": "sign_in",
  "pap.sign_in.direct.complete": "sign_in",
  "pap.sign_in.device.begin": "sign_in",
  "pap.sign_in.device.poll": "sign_in",
  "pap.sign_in.mediated.sign_in": "sign_in",
  "pap.sign_in.mediated.submit_code": "sign_in",
  "pap.sign_in.account_token.refresh": "sign_in",
  "pap.sign_in.account_token.revoke": "sign_in",
  "pap.conversation.start": "conversation",
  "pap.conversation.send": "conversation",
  "pap.conversation.read_events": "conversation",
  "pap.conversation.start_direct": "conversation",
  "pap.conversation.handoff": "conversation",
  "pap.conversation.close": "conversation",
  "pap.operation.read": "operation",
  "pap.operation.confirm": "operation",
  "pap.operation.cancel": "operation",
  // What a company built on the SDK's company service did and refused.
  "pap.company.identity.check": "company",
  "pap.company.session.start": "company",
  "pap.company.session.renew": "company",
  "pap.company.interface.switch": "company",
  "pap.company.refused": "company",
});

/** The interfaces a company offers a personal agent (`pap.interface`). */
export const TELEMETRY_INTERFACES = ["agent", "openapi", "mcp", "web"] as const;
export type TelemetryInterface = (typeof TELEMETRY_INTERFACES)[number];

export type TelemetryValue = string | number | boolean;
export type TelemetryAttributes = Readonly<Record<string, TelemetryValue>>;

const IDENTIFIER = /^[a-z][a-z0-9_]{0,47}$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const PATH = /^(?:\/[A-Za-z0-9._~-]{1,64}){0,8}\/?$/;

const identifier = (value: unknown): boolean => typeof value === "string" && IDENTIFIER.test(value);
const domain = (value: unknown): boolean => typeof value === "string" && DOMAIN.test(value);
const count = (value: unknown): boolean =>
  typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 1_000_000;
const flag = (value: unknown): boolean => typeof value === "boolean";
const oneOf =
  (...allowed: string[]) =>
  (value: unknown): boolean =>
    typeof value === "string" && allowed.includes(value);

/** An `https` origin with at most a plain path: no user information, query, or fragment. */
function issuer(value: unknown): boolean {
  if (typeof value !== "string" || value.length > 256 || /[?#@]/.test(value)) return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  const path = parsed.pathname === "/" && !value.endsWith("/") ? "" : parsed.pathname;
  return (
    parsed.protocol === "https:" &&
    parsed.port === "" &&
    domain(parsed.hostname) &&
    PATH.test(path)
  );
}

/** The only attribute names an event may carry, each with the rule its value must pass. */
export const TELEMETRY_ATTRIBUTES: Readonly<Record<string, (value: unknown) => boolean>> =
  Object.freeze({
    "pap.stage": oneOf(...TELEMETRY_STAGES),
    "pap.outcome": oneOf("ok", "error"),
    "pap.error": identifier,
    "pap.company.domain": domain,
    "pap.company.issuer": issuer,
    "pap.sign_in.method": oneOf("direct", "device", "mediated", "account_token"),
    "pap.sign_in.status": identifier,
    "pap.session.signed_in": flag,
    "pap.scopes.granted": count,
    "pap.scopes.missing": count,
    "pap.conversation.status": identifier,
    "pap.conversation.events": count,
    "pap.operation.state": identifier,
    "pap.operation.status": identifier,
    "pap.operation.revision": count,
    "pap.client.id": issuer,
    "pap.interface": oneOf(...TELEMETRY_INTERFACES),
    "pap.company.route": identifier,
    "pap.http.status": count,
    "pap.replayed": flag,
  });

/** The allowlisted attributes of `values`; `undefined` and failing values are dropped. */
export function safeAttributes(values: Readonly<Record<string, unknown>>): TelemetryAttributes {
  const safe: Record<string, TelemetryValue> = {};
  for (const [name, value] of Object.entries(values)) {
    const rule = Object.hasOwn(TELEMETRY_ATTRIBUTES, name) ? TELEMETRY_ATTRIBUTES[name] : undefined;
    if (rule === undefined) throw new TypeError(`${name} is not a telemetry attribute`);
    if (value !== undefined && value !== null && rule(value)) safe[name] = value as TelemetryValue;
  }
  return Object.freeze(safe);
}

/** One finished protocol stage: a span for traces, an event for analytics. */
export class TelemetryEvent {
  readonly name: string;
  readonly outcome: "ok" | "error";
  readonly durationMs: number;
  readonly attributes: TelemetryAttributes;

  constructor(options: {
    readonly name: string;
    readonly outcome: "ok" | "error";
    readonly durationMs: number;
    readonly attributes?: Readonly<Record<string, unknown>>;
  }) {
    if (!Object.hasOwn(TELEMETRY_EVENTS, options.name)) {
      throw new TypeError(`${options.name} is not a telemetry event`);
    }
    if (options.outcome !== "ok" && options.outcome !== "error") {
      throw new TypeError("outcome is ok or error");
    }
    if (!(options.durationMs >= 0)) throw new RangeError("durationMs must not be negative");
    const given = options.attributes ?? {};
    const safe = safeAttributes(given);
    if (Object.keys(safe).length !== Object.keys(given).length) {
      throw new TypeError("a telemetry attribute failed its rule");
    }
    this.name = options.name;
    this.outcome = options.outcome;
    this.durationMs = options.durationMs;
    this.attributes = safe;
    Object.freeze(this);
  }

  get stage(): TelemetryStage {
    return TELEMETRY_EVENTS[this.name] as TelemetryStage;
  }

  /** Every attribute, the stage and outcome included (what a span carries). */
  asAttributes(): TelemetryAttributes {
    return { ...this.attributes, "pap.stage": this.stage, "pap.outcome": this.outcome };
  }

  /** The event as JSON-ready data, for an analytics pipeline. */
  toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      stage: this.stage,
      outcome: this.outcome,
      duration_ms: this.durationMs,
      attributes: { ...this.attributes },
    };
  }
}

/** `pap.telemetry` in memory: every event, in order. */
export class RecordingTelemetrySink implements TelemetrySink {
  readonly events: TelemetryEvent[] = [];

  record(event: TelemetryEvent): void {
    this.events.push(event);
  }
}

/** The part of an OpenTelemetry API `Tracer` the adapter uses. */
export interface OpenTelemetryTracer {
  startSpan(
    name: string,
    options?: { attributes?: Record<string, TelemetryValue>; startTime?: number },
  ): {
    setStatus(status: { code: number; message?: string }): unknown;
    end(endTime?: number): void;
  };
}

/** OpenTelemetry's `SpanStatusCode.ERROR`. */
const SPAN_STATUS_ERROR = 2;

/**
 * `pap.telemetry` as OpenTelemetry spans: one per event, from `tracer` (for example
 * `trace.getTracer("my-agent")` of `@opentelemetry/api`). A failed stage's span has an
 * error status whose only detail is the `pap.error` attribute.
 */
export function openTelemetrySink(tracer: OpenTelemetryTracer): TelemetrySink {
  return {
    record(event: TelemetryEvent): void {
      const end = Date.now();
      const span = tracer.startSpan(event.name, {
        attributes: { ...event.asAttributes() },
        startTime: end - event.durationMs,
      });
      if (event.outcome === "error") span.setStatus({ code: SPAN_STATUS_ERROR });
      span.end(end);
    },
  };
}

/** The host's sink, `undefined` when it contributes none; two at one order fail closed. */
export function telemetrySink(reactor: ReactorPlatformView | undefined): TelemetrySink | undefined {
  if (reactor === undefined) return undefined;
  return optionalContribution(reactor, TelemetrySinks, "telemetry sink");
}

const now = (): number => globalThis.performance?.now() ?? Date.now();

/** Record one event; a failing sink is logged by its type and never fails the call. */
export function emit(
  sink: TelemetrySink,
  name: string,
  outcome: "ok" | "error",
  durationMs: number,
  attributes: Readonly<Record<string, unknown>>,
): void {
  const event = new TelemetryEvent({
    name,
    outcome,
    durationMs: Math.max(0, durationMs),
    attributes: safeAttributes(attributes),
  });
  try {
    sink.record(event);
  } catch (error) {
    console.warn(`The telemetry sink failed: ${error instanceof Error ? error.name : "Error"}`);
  }
}

/**
 * Run `work`, then emit `name` through `reactor`'s sink: `ok` with `before` and what
 * `after` reads from the result, or `error` with the refusal's code (`unexpected` for
 * anything else), the error rethrown unchanged.
 */
export async function traced<T>(
  reactor: ReactorPlatformView | undefined,
  name: string,
  before: Readonly<Record<string, unknown>>,
  work: () => Promise<T>,
  after?: (result: T) => Readonly<Record<string, unknown>>,
): Promise<T> {
  if (!Object.hasOwn(TELEMETRY_EVENTS, name)) throw new TypeError(`${name} is not a telemetry event`);
  const sink = telemetrySink(reactor);
  if (sink === undefined) return work();
  const started = now();
  let result: T;
  try {
    result = await work();
  } catch (error) {
    const code = error instanceof PersonalAgentProtocolError ? error.code : "unexpected";
    emit(sink, name, "error", now() - started, { ...before, "pap.error": code });
    throw error;
  }
  emit(sink, name, "ok", now() - started, { ...before, ...(after?.(result) ?? {}) });
  return result;
}

// What the SDK's clients report: read from their arguments and results ---------------------

/** The host of a URL, for `pap.company.domain` (never its path or query). */
export function domainOf(url: string | undefined): string | undefined {
  if (url === undefined) return undefined;
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

export const byIssuer = (value: string | undefined, method?: string) => ({
  "pap.company.issuer": value,
  "pap.company.domain": domainOf(value),
  ...(method === undefined ? {} : { "pap.sign_in.method": method }),
});

export const byEndpoint = (endpoint: string) => ({ "pap.company.domain": domainOf(endpoint) });

interface SignInLike {
  readonly status?: string;
  readonly revoked?: boolean;
  readonly token?: { readonly signedIn?: boolean };
  readonly grantedScopes?: readonly string[];
  readonly missingScopes?: readonly string[];
}

export function signInResult(result: SignInLike): Record<string, unknown> {
  let status = result.status;
  if (status === undefined && result.revoked !== undefined) {
    status = result.revoked ? "revoked" : "not_revoked";
  }
  return {
    "pap.sign_in.status": status ?? "started",
    "pap.session.signed_in": result.token?.signedIn,
    "pap.scopes.granted": result.grantedScopes?.length,
    "pap.scopes.missing": result.missingScopes?.length,
  };
}

export const sessionResult = (result: { readonly signedIn: boolean }) => ({
  "pap.session.signed_in": result.signedIn,
});

export const conversationResult = (result: {
  readonly status?: string;
  readonly events?: readonly unknown[];
}) => ({
  "pap.conversation.status": result.status,
  "pap.conversation.events": result.events?.length,
});

interface OperationLike {
  readonly state?: string;
  readonly revision?: number;
}

export function operationResult(
  result: OperationLike | { readonly status: string; readonly operation?: OperationLike },
): Record<string, unknown> {
  const outcome = !("operation_id" in result);
  const operation = outcome
    ? (result as { operation?: OperationLike }).operation
    : (result as OperationLike);
  return {
    "pap.operation.status": outcome ? (result as { status?: string }).status : undefined,
    "pap.operation.state": operation?.state,
    "pap.operation.revision": operation?.revision,
  };
}
