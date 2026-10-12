/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import {
  AuthorizationStateStores,
  Clocks,
  DpopProofProviders,
  RandomSources,
  Signers,
  TokenStores,
  firstContribution,
} from "./reactor.js";
import { SecretValue } from "./secret.js";
import { JWT_CLIENT_ASSERTION, parseSessionToken, type SessionToken } from "./sessions.js";
import { byIssuer, signInResult, traced } from "./telemetry.js";
import { readLimitedText } from "./limits.js";

export const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

function httpsUrl(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`, { cause });
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return parsed.toString();
}

function scopes(values: readonly string[]): readonly string[] {
  const result = [...new Set(values)];
  const token = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
  if (result.length === 0 || result.some((scope) => !token.test(scope))) {
    throw new AuthorizationError("invalid_scope", "At least one valid OAuth scope is required");
  }
  return result;
}

function base64Url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += alphabet[first >>> 2];
    output += alphabet[((first & 3) << 4) | ((second ?? 0) >>> 4)];
    if (second !== undefined) {
      output += alphabet[((second & 15) << 2) | ((third ?? 0) >>> 6)];
    }
    if (third !== undefined) output += alphabet[third & 63];
  }
  return output;
}

function opaqueId(prefix: string, bytes: Uint8Array): string {
  if (bytes.byteLength < 16) {
    throw new AuthorizationError("weak_entropy", "Device Sign-In requires 128 random bits");
  }
  return `${prefix}_${base64Url(bytes)}`;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AuthorizationError("invalid_device_response", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) {
    throw new AuthorizationError("invalid_device_response", `${label} must be a non-empty string`);
  }
  return value;
}

interface DeviceAuthorizationResponse {
  readonly deviceCode: SecretValue;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly verificationUriComplete?: string;
  readonly expiresIn: number;
  readonly interval: number;
}

function parseDeviceAuthorization(value: unknown): DeviceAuthorizationResponse {
  const source = record(value, "device authorization response");
  const expiresIn = source.expires_in;
  const interval = source.interval ?? 5;
  if (!Number.isInteger(expiresIn) || (expiresIn as number) <= 0 || (expiresIn as number) > 3600) {
    throw new AuthorizationError("invalid_device_response", "expires_in must be 1..3600");
  }
  if (!Number.isInteger(interval) || (interval as number) <= 0 || (interval as number) > 300) {
    throw new AuthorizationError("invalid_device_response", "interval must be 1..300");
  }
  const complete = source.verification_uri_complete;
  if (complete !== undefined && typeof complete !== "string") {
    throw new AuthorizationError(
      "invalid_device_response",
      "verification_uri_complete must be a string",
    );
  }
  return {
    deviceCode: new SecretValue(string(source.device_code, "device_code")),
    userCode: string(source.user_code, "user_code"),
    verificationUri: httpsUrl(
      string(source.verification_uri, "verification_uri"),
      "verification_uri",
    ),
    ...(complete === undefined
      ? {}
      : { verificationUriComplete: httpsUrl(complete, "verification_uri_complete") }),
    expiresIn: expiresIn as number,
    interval: interval as number,
  };
}

interface PendingDeviceSignIn {
  readonly kind: "pap.device-sign-in.v1";
  readonly deviceCode: SecretValue;
  readonly tokenEndpoint: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly sessionId: string;
  readonly scopes: readonly string[];
  readonly expiresAt: Date;
  readonly nextPollAt: Date;
  readonly interval: number;
}

function isPending(value: unknown): value is PendingDeviceSignIn {
  if (typeof value !== "object" || value === null) return false;
  const pending = value as Partial<PendingDeviceSignIn>;
  return (
    pending.kind === "pap.device-sign-in.v1" &&
    pending.deviceCode instanceof SecretValue &&
    pending.expiresAt instanceof Date &&
    pending.nextPollAt instanceof Date &&
    typeof pending.tokenEndpoint === "string" &&
    typeof pending.interval === "number"
  );
}

export interface DeviceSignInStart {
  readonly reference: string;
  readonly userCode: string;
  readonly verificationUri: string;
  readonly verificationUriComplete?: string;
  readonly expiresAt: Date;
  readonly pollInterval: number;
  readonly requestedScopes: readonly string[];
}

export interface DeviceSignInPoll {
  readonly status: "pending" | "complete";
  readonly retryAt?: Date;
  readonly token?: SessionToken;
  readonly accountTokenReference?: string;
  readonly grantedScopes: readonly string[];
  readonly missingScopes: readonly string[];
}

export interface DeviceSignInBeginOptions {
  readonly deviceAuthorizationEndpoint: string;
  readonly tokenEndpoint: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly tenantId: string;
  readonly pairwiseUserId: string;
  readonly sessionId: string;
  readonly signal?: AbortSignal;
}

export interface DeviceSignInClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

/** PAP Device Sign-In with private device codes and Reactor-backed Account Tokens. */
export class DeviceSignInClient {
  readonly #reactor: ReactorPlatformView;
  readonly #fetch: typeof globalThis.fetch;
  readonly #maxResponseBytes: number;

  constructor(options: DeviceSignInClientOptions) {
    const fetcher = options.fetch ?? globalThis.fetch;
    if (!fetcher) throw new AuthorizationError("fetch_unavailable", "A fetch implementation is required");
    const limit = options.maxResponseBytes ?? 100 * 1024;
    if (!Number.isInteger(limit) || limit <= 0) throw new RangeError("maxResponseBytes must be positive");
    this.#reactor = options.reactor;
    this.#fetch = fetcher;
    this.#maxResponseBytes = limit;
  }

  begin(options: DeviceSignInBeginOptions): Promise<DeviceSignInStart> {
    return traced(
      this.#reactor,
      "pap.sign_in.device.begin",
      byIssuer(options.issuer, "device"),
      () => this.#begin(options),
      () => ({ "pap.sign_in.status": "started" }),
    );
  }

  async #begin(options: DeviceSignInBeginOptions): Promise<DeviceSignInStart> {
    this.#validateContext(options);
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const signer = firstContribution(this.#reactor, Signers, "signer");
    const endpoint = httpsUrl(options.deviceAuthorizationEndpoint, "deviceAuthorizationEndpoint");
    const tokenEndpoint = httpsUrl(options.tokenEndpoint, "tokenEndpoint");
    const issuer = httpsUrl(options.issuer, "issuer").replace(/\/$/, "");
    const clientId = httpsUrl(options.clientId, "clientId");
    const requestedScopes = scopes(options.scopes);
    const now = clock.now();
    const clientAssertion = await signer.sign(
      this.#claims(clientId, endpoint, now, random.bytes(16)),
      { purpose: "client_assertion" },
    );
    const response = await this.#request(
      endpoint,
      new URLSearchParams({
        scope: requestedScopes.join(" "),
        client_id: clientId,
        client_assertion_type: JWT_CLIENT_ASSERTION,
        client_assertion: clientAssertion.reveal(),
      }),
      undefined,
      options.signal,
    );
    const payload = await this.#decode(response, "Device authorization");
    if (!response.ok) throw this.#remoteError(response, payload, "Company refused Device Sign-In");
    const authorization = parseDeviceAuthorization(payload);
    const expiresAt = new Date(now.getTime() + authorization.expiresIn * 1000);
    const reference = opaqueId("device", random.bytes(16));
    const pending: PendingDeviceSignIn = {
      kind: "pap.device-sign-in.v1",
      deviceCode: authorization.deviceCode,
      tokenEndpoint,
      issuer,
      clientId,
      tenantId: options.tenantId,
      pairwiseUserId: options.pairwiseUserId,
      sessionId: options.sessionId,
      scopes: requestedScopes,
      expiresAt,
      nextPollAt: new Date(now.getTime() + authorization.interval * 1000),
      interval: authorization.interval,
    };
    const store = firstContribution(this.#reactor, AuthorizationStateStores, "authorization state store");
    await store.put(reference, pending, { expiresAt });
    return {
      reference,
      userCode: authorization.userCode,
      verificationUri: authorization.verificationUri,
      ...(authorization.verificationUriComplete === undefined
        ? {}
        : { verificationUriComplete: authorization.verificationUriComplete }),
      expiresAt,
      pollInterval: authorization.interval,
      requestedScopes,
    };
  }

  poll(reference: string, signal?: AbortSignal): Promise<DeviceSignInPoll> {
    return traced(
      this.#reactor,
      "pap.sign_in.device.poll",
      { "pap.sign_in.method": "device" },
      () => this.#poll(reference, signal),
      signInResult,
    );
  }

  async #poll(reference: string, signal?: AbortSignal): Promise<DeviceSignInPoll> {
    const store = firstContribution(this.#reactor, AuthorizationStateStores, "authorization state store");
    const pending = await store.take(reference);
    if (!isPending(pending)) {
      throw new AuthorizationError(
        "invalid_or_expired_device_session",
        "Device Sign-In is unknown, expired, complete, or already being polled",
      );
    }
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const now = clock.now();
    if (now.getTime() >= pending.expiresAt.getTime()) {
      throw new AuthorizationError("expired_token", "Device Sign-In has expired");
    }
    if (now.getTime() < pending.nextPollAt.getTime()) {
      await store.put(reference, pending, { expiresAt: pending.expiresAt });
      return { status: "pending", retryAt: pending.nextPollAt, grantedScopes: [], missingScopes: [] };
    }
    try {
      const result = await this.#pollToken(pending, now, signal);
      if (result.response.ok) return await this.#complete(result.response, result.payload, pending);
      const source = typeof result.payload === "object" && result.payload !== null ? result.payload : {};
      const remote = "error" in source ? (source as { error?: unknown }).error : undefined;
      if (remote === "authorization_pending" || remote === "slow_down") {
        const interval = pending.interval + (remote === "slow_down" ? 5 : 0);
        const resumed = { ...pending, interval, nextPollAt: new Date(now.getTime() + interval * 1000) };
        await store.put(reference, resumed, { expiresAt: pending.expiresAt });
        return { status: "pending", retryAt: resumed.nextPollAt, grantedScopes: [], missingScopes: [] };
      }
      if (remote === "access_denied" || remote === "expired_token") {
        throw new AuthorizationError(remote, "Device Sign-In ended without authorization");
      }
      await store.put(reference, pending, { expiresAt: pending.expiresAt });
      throw this.#remoteError(result.response, result.payload, "Company refused the device token request");
    } catch (cause) {
      if (cause instanceof AuthorizationError && ["access_denied", "expired_token"].includes(cause.code)) {
        throw cause;
      }
      const existing = await store.take(reference);
      if (existing === undefined) await store.put(reference, pending, { expiresAt: pending.expiresAt });
      throw cause;
    }
  }

  async #pollToken(pending: PendingDeviceSignIn, now: Date, signal?: AbortSignal) {
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const signer = firstContribution(this.#reactor, Signers, "signer");
    const dpop = firstContribution(this.#reactor, DpopProofProviders, "DPoP proof provider");
    const assertion = await signer.sign(
      this.#claims(pending.clientId, pending.tokenEndpoint, now, random.bytes(16)),
      { purpose: "client_assertion" },
    );
    const proof = await dpop.create({
      method: "POST",
      url: pending.tokenEndpoint,
      tenantId: pending.tenantId,
      subject: pending.pairwiseUserId,
      issuer: pending.issuer,
    });
    const response = await this.#request(
      pending.tokenEndpoint,
      new URLSearchParams({
        grant_type: DEVICE_CODE_GRANT,
        device_code: pending.deviceCode.reveal(),
        session_id: pending.sessionId,
        client_id: pending.clientId,
        client_assertion_type: JWT_CLIENT_ASSERTION,
        client_assertion: assertion.reveal(),
      }),
      proof.reveal(),
      signal,
    );
    return { response, payload: await this.#decode(response, "Device token") };
  }

  async #complete(response: Response, payload: unknown, pending: PendingDeviceSignIn): Promise<DeviceSignInPoll> {
    let token: SessionToken;
    try {
      token = parseSessionToken(payload);
    } catch (cause) {
      throw new AuthorizationError("invalid_token_response", "Device token response is malformed", {
        statusCode: response.status,
        cause,
      });
    }
    if (token.tokenType !== "DPoP" || !token.signedIn || token.sessionId !== pending.sessionId) {
      throw new AuthorizationError(
        "invalid_token_response",
        "Device Sign-In must return the signed-in proof-bound Session",
        { statusCode: response.status },
      );
    }
    if (token.scopes.some((scope) => !pending.scopes.includes(scope))) {
      throw new AuthorizationError("scope_escalation", "Company returned an unrequested scope");
    }
    if (!token.accountToken) {
      throw new AuthorizationError("missing_account_token", "Device Sign-In did not return an Account Token");
    }
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const accountTokenReference = opaqueId("account", random.bytes(16));
    const tokens = firstContribution(this.#reactor, TokenStores, "token store");
    await tokens.put(accountTokenReference, token.accountToken);
    const { accountToken: _accountToken, ...publicToken } = token;
    return {
      status: "complete",
      token: publicToken,
      accountTokenReference,
      grantedScopes: publicToken.scopes,
      missingScopes: pending.scopes.filter((scope) => !publicToken.scopes.includes(scope)),
    };
  }

  #claims(clientId: string, audience: string, now: Date, entropy: Uint8Array) {
    const iat = Math.floor(now.getTime() / 1000);
    return { iss: clientId, sub: clientId, aud: audience, iat, exp: iat + 60, jti: opaqueId("jti", entropy) };
  }

  #validateContext(options: DeviceSignInBeginOptions): void {
    if (!options.tenantId || options.tenantId.length > 256) throw new RangeError("Invalid tenantId");
    const identifiers: ReadonlyArray<readonly [string, string]> = [
      ["pairwiseUserId", options.pairwiseUserId],
      ["sessionId", options.sessionId],
    ];
    for (const [label, value] of identifiers) {
      if (!/^[A-Za-z0-9_-]{1,256}$/.test(value)) {
        throw new AuthorizationError("invalid_context", `Invalid ${label}`);
      }
    }
  }

  async #request(url: string, body: URLSearchParams, dpop?: string, signal?: AbortSignal): Promise<Response> {
    try {
      return await this.#fetch(url, {
        method: "POST",
        headers: { Accept: "application/json", ...(dpop === undefined ? {} : { DPoP: dpop }) },
        body,
        credentials: "omit",
        redirect: "error",
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (cause) {
      throw new AuthorizationError("request_failed", "Device Sign-In request failed", { cause });
    }
  }

  async #decode(response: Response, label: string): Promise<unknown> {
    if (response.headers.get("content-type")?.split(";", 1)[0]?.trim() !== "application/json") {
      throw new AuthorizationError("invalid_content_type", `${label} endpoint must return JSON`, {
        statusCode: response.status,
      });
    }
    const body = await readLimitedText(response, this.#maxResponseBytes);
    if (new TextEncoder().encode(body).byteLength > this.#maxResponseBytes) {
      throw new AuthorizationError("response_too_large", `${label} response exceeds size limit`, {
        statusCode: response.status,
      });
    }
    try {
      return parseJsonStrict(body);
    } catch (cause) {
      throw new AuthorizationError("invalid_json", `${label} endpoint returned invalid JSON`, {
        statusCode: response.status,
        cause,
      });
    }
  }

  #remoteError(response: Response, payload: unknown, message: string): AuthorizationError {
    const source = typeof payload === "object" && payload !== null ? payload : {};
    const remote = "error" in source ? (source as { error?: unknown }).error : undefined;
    return new AuthorizationError(typeof remote === "string" ? remote : "http_error", message, {
      statusCode: response.status,
    });
  }
}
