/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The UCP extension, version 1, as in Python's personal_agent_protocol.ucp: a Company that
// speaks the Universal Commerce Protocol. This protocol finds the Company, identifies the
// Personal Agent and a pseudonymous User, and signs the User in; UCP is how the Personal Agent
// shops once it is there (UCP extension 1). A Company lists `ucp` in `extensions` (2); its UCP
// profile is at `https://{organization.domain}/.well-known/ucp`, fetched without redirects (3);
// a UCP request carries the platform profile in `UCP-Agent`, the Session header, an operator
// signature when the host contributes one, and a Bearer access token when signed in (4).

import { PersonalAgentProtocolError, SessionError, TransportError } from "./errors.js";
import { parseJsonStrict } from "./json.js";
import { readLimited } from "./limits.js";
import { companyExtension, type DiscoveredCompany, type DiscoveryDocument } from "./models.js";
import { challengeParameters, refuseRedirect } from "./refusals.js";
import type { AccessToken, PapSession } from "./sessions.js";
import { sessionError, type SessionFetchClient } from "./transport.js";

/** The extension's name and version in `extensions` and `Poppy-Extensions` (UCP extension 2). */
export const UCP_EXTENSION = "ucp";
export const UCP_VERSION = "1";
/** Where a Company's UCP profile is, on `organization.domain` (UCP extension 3). */
export const UCP_PROFILE_PATH = "/.well-known/ucp";
/** The header a UCP REST request names the platform profile in (UCP extension 3, 4). */
export const UCP_AGENT_HEADER = "UCP-Agent";
/** UCP's service for shopping, and identity linking. */
export const UCP_SHOPPING = "dev.ucp.shopping";
export const UCP_IDENTITY_LINKING = "dev.ucp.common.identity_linking";
/** The UCP version the reference companies speak, in their profile (UCP's own versioning). */
export const UCP_PROFILE_VERSION = "2026-04-08";

/**
 * A UCP profile or request refused: its code, and `details` such as the scopes to get.
 *
 * `identity_required` (sign in, `details.scopes` from the profile's identity linking),
 * `insufficient_scope` (`details.scope`), `invalid_token`, `ucp_not_offered`,
 * `redirect_refused`, `ucp_profile_unavailable`, `invalid_ucp_profile`, or the code a UCP
 * error body names.
 */
export class UcpError extends PersonalAgentProtocolError {
  constructor(
    code: string,
    message: string,
    options: { statusCode?: number; details?: Readonly<Record<string, unknown>>; cause?: unknown } = {},
  ) {
    super(code, message, options);
    this.name = "UcpError";
  }
}

type Entries = Readonly<Record<string, readonly Readonly<Record<string, unknown>>[]>>;

/** A Company's UCP profile, as far as this extension reads it (UCP extension 3): data, never instructions. */
export interface UcpProfile {
  readonly version: string;
  readonly services: Entries;
  readonly capabilities: Entries;
}

function entries(value: unknown, label: string): Entries {
  if (value === undefined) return {};
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new UcpError("invalid_ucp_profile", `${label} must be an object`);
  }
  const out: Record<string, Readonly<Record<string, unknown>>[]> = {};
  for (const [name, list] of Object.entries(value as Record<string, unknown>)) {
    if (!Array.isArray(list) || list.some((item) => typeof item !== "object" || item === null || Array.isArray(item))) {
      throw new UcpError("invalid_ucp_profile", `${label}.${name} must be a list of objects`);
    }
    out[name] = list as Readonly<Record<string, unknown>>[];
  }
  return out;
}

/** The `ucp` member of a UCP profile document, checked. */
export function parseUcpProfile(value: unknown): UcpProfile {
  const body =
    typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>).ucp : undefined;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new UcpError("invalid_ucp_profile", "The UCP profile is malformed");
  }
  const source = body as Record<string, unknown>;
  if (typeof source.version !== "string" || !source.version) {
    throw new UcpError("invalid_ucp_profile", "The UCP profile names no version");
  }
  return {
    version: source.version,
    services: entries(source.services, "services"),
    capabilities: entries(source.capabilities, "capabilities"),
  };
}

/** The HTTPS endpoint of `service` for `transport`, or `undefined` when the profile offers none. */
export function ucpEndpoint(profile: UcpProfile, service = UCP_SHOPPING, transport = "rest"): string | undefined {
  for (const entry of profile.services[service] ?? []) {
    if (entry.transport === transport && typeof entry.endpoint === "string" && entry.endpoint.startsWith("https://")) {
      return entry.endpoint;
    }
  }
  return undefined;
}

/** Whether the profile lists `capability` (UCP's name, such as `dev.ucp.shopping.order`). */
export function ucpOffers(profile: UcpProfile, capability: string): boolean {
  return (profile.capabilities[capability] ?? []).length > 0;
}

/**
 * The scopes identity linking gates (`config.scopes`): what a sign-in asks for when a UCP request
 * answers `identity_required` (UCP extension 4).
 */
export function ucpIdentityLinkingScopes(profile: UcpProfile): readonly string[] {
  const scopes: string[] = [];
  for (const entry of profile.capabilities[UCP_IDENTITY_LINKING] ?? []) {
    const config = entry.config;
    const named =
      typeof config === "object" && config !== null ? (config as Record<string, unknown>).scopes : undefined;
    if (typeof named === "object" && named !== null && !Array.isArray(named)) {
      for (const name of Object.keys(named)) if (!scopes.includes(name)) scopes.push(name);
    }
  }
  return scopes;
}

/** The identity linking scopes not in `held`: UCP asks only for the missing ones (UCP extension 4). */
export function ucpScopes(profile: UcpProfile, held: readonly string[] = []): readonly string[] {
  return ucpIdentityLinkingScopes(profile).filter((scope) => !held.includes(scope));
}

/** Whether the Company lists the UCP extension at this version (UCP extension 2). */
export function speaksUcp(document: DiscoveryDocument): boolean {
  return companyExtension(document, UCP_EXTENSION, UCP_VERSION) !== undefined;
}

/** `https://{organization.domain}/.well-known/ucp`, on the validated domain (UCP extension 3). */
export function ucpProfileUrl(company: DiscoveredCompany): string {
  return `https://${company.document.organization.domain}${UCP_PROFILE_PATH}`;
}

/**
 * The `UCP-Agent` value naming the platform profile, an RFC 9651 Dictionary. The profile
 * describes the Personal Agent, never a User: one URL for every User (UCP extension 3, 10).
 */
export function ucpAgentHeader(platformProfile: string): string {
  if (!platformProfile.startsWith("https://") || /["\\\s]/.test(platformProfile)) {
    throw new RangeError("The platform profile is an HTTPS URL");
  }
  return `profile="${platformProfile}"`;
}

/**
 * The Company's UCP profile, from its validated domain, with no redirect followed: a redirect is
 * `redirect_refused`, as UCP requires (UCP extension 3).
 */
export async function fetchUcpProfile(
  company: DiscoveredCompany,
  options: { readonly fetch?: typeof globalThis.fetch; readonly maxResponseBytes?: number; readonly signal?: AbortSignal } = {},
): Promise<UcpProfile> {
  if (!speaksUcp(company.document)) throw new UcpError("ucp_not_offered", "The company doesn't list the UCP extension");
  const fetcher = options.fetch ?? globalThis.fetch;
  if (!fetcher) throw new TransportError("fetch_unavailable", "A fetch implementation is required");
  const limit = options.maxResponseBytes ?? 256 * 1024;
  let response: Response;
  try {
    response = await fetcher(ucpProfileUrl(company), {
      headers: { Accept: "application/json" },
      credentials: "omit",
      redirect: "manual",
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
  } catch (cause) {
    throw new UcpError("ucp_profile_unavailable", "The UCP profile request failed", { cause });
  }
  await refuseRedirect(response, UcpError);
  const bytes = await readLimited(response, limit);
  if (response.status !== 200) {
    throw new UcpError("ucp_profile_unavailable", "The UCP profile is unavailable", { statusCode: response.status });
  }
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(new TextDecoder().decode(bytes));
  } catch (cause) {
    throw new UcpError("invalid_ucp_profile", "The UCP profile is malformed", { cause });
  }
  return parseUcpProfile(parsed);
}

export interface UcpCallOptions {
  readonly session: PapSession;
  /** One from this protocol's sign-in, never one got independently of this extension. */
  readonly token?: AccessToken | undefined;
  readonly body?: Readonly<Record<string, unknown>>;
  readonly idempotencyKey?: string;
  readonly signal?: AbortSignal;
}

/**
 * Send UCP REST requests through this extension (UCP extension 4): the platform profile in
 * `UCP-Agent`, the Session header (and any operator signature) through `transport`, and the
 * access token when signed in. `session_ended` starts a new Session once, in the transport;
 * challenges are `UcpError`s, as the specification's API challenges (§7).
 */
export class UcpClient {
  readonly transport: SessionFetchClient;
  readonly agent: string;
  readonly profile: UcpProfile;

  constructor(options: { readonly transport: SessionFetchClient; readonly platformProfile: string; readonly profile: UcpProfile }) {
    this.transport = options.transport;
    this.agent = ucpAgentHeader(options.platformProfile);
    this.profile = options.profile;
  }

  /** One UCP request: its JSON answer, or a `UcpError` for a challenge or an error. */
  async call(method: string, url: string, options: UcpCallOptions): Promise<unknown> {
    const headers: Record<string, string> = { [UCP_AGENT_HEADER]: this.agent, Accept: "application/json" };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (options.idempotencyKey !== undefined) headers["Idempotency-Key"] = options.idempotencyKey;
    const response = await this.transport.request(method, url, {
      session: options.session,
      token: options.token,
      headers,
      ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    if (response.ok) {
      const text = await response.text();
      return text ? parseJsonStrict(text) : undefined;
    }
    const error = await sessionError(response);
    if (error !== undefined) throw new SessionError(error, "The company refused the Session", { statusCode: 400 });
    throw await this.#refusal(response);
  }

  async #refusal(response: Response): Promise<UcpError> {
    const challenge = challengeParameters(response.headers.get("www-authenticate"));
    let code: unknown;
    try {
      const payload = parseJsonStrict(await response.text());
      code = typeof payload === "object" && payload !== null ? (payload as Record<string, unknown>).code : undefined;
    } catch {
      code = undefined;
    }
    if (response.status === 401 && challenge.error === "invalid_token") {
      return new UcpError("invalid_token", "Refresh the access token", { statusCode: 401 });
    }
    if (response.status === 401) {
      // The scopes come from the profile, never from where the challenge points: the issuer stays
      // the one this protocol selected (UCP extension 4, 10).
      return new UcpError("identity_required", "Sign in for this UCP request", {
        statusCode: 401,
        details: { scopes: [...ucpIdentityLinkingScopes(this.profile)] },
      });
    }
    if (response.status === 403 && challenge.error === "insufficient_scope") {
      return new UcpError("insufficient_scope", "The access token lacks a scope this UCP request needs", {
        statusCode: 403,
        details: { scope: challenge.scope ?? "" },
      });
    }
    return new UcpError(typeof code === "string" && code ? code : "http_error", "The company refused the UCP request", {
      statusCode: response.status,
    });
  }
}
