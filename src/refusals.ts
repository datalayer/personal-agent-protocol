/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// How a company's refusals read, whichever endpoint answered (§3, §3.3, §4.3, §6), as in
// Python's personal_agent_protocol.refusals.
//
// Shared by every client: the parameters of a `WWW-Authenticate` challenge, the details
// a refusal carries besides its code (`extension`, `scope`, `retry_after`), and the one
// rule for redirects outside discovery.
import { PersonalAgentProtocolError, TransportError } from "./errors.js";

/** The statuses of an HTTP redirect. */
export const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

const CODE_REQUIRED = ["sign_in_id", "sent_to", "expires_in"];

const CHALLENGE_PARAMETER = /([A-Za-z_][A-Za-z0-9_-]*)="([^"]*)"/g;

/**
 * The quoted parameters of a `WWW-Authenticate` header: `error`, `scope`, `extension`...
 *
 * An MCP server sends one challenge per scheme it accepts (`Bearer` and `DPoP`, §6),
 * each with the same `error`; the first value of each name is kept.
 */
export function challengeParameters(header: string | null | undefined): Record<string, string> {
  const values: Record<string, string> = {};
  for (const [, name, value] of (header ?? "").matchAll(CHALLENGE_PARAMETER)) {
    if (name !== undefined && value !== undefined && !Object.hasOwn(values, name)) values[name] = value;
  }
  return values;
}

/**
 * What a refusal says besides its code: `extension`, `scope`, `retry_after`.
 *
 * `extension_required` names its extension in the JSON body at the token endpoint and
 * the endpoints the protocol or an extension defines, and in the `WWW-Authenticate`
 * challenge at APIs (§3.3); either shape is read. `retry_after` is kept as sent on a
 * 429 or 503 (§5.6), never acted on here.
 */
export function refusalDetails(response: Response, payload: unknown): Record<string, unknown> {
  const challenge = challengeParameters(response.headers.get("www-authenticate"));
  const body =
    typeof payload === "object" && payload !== null && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : {};
  const details: Record<string, unknown> = {};
  const extension = "extension" in body ? body.extension : challenge.extension;
  if (typeof extension === "string" && extension) details.extension = extension;
  const scope = "scope" in body ? body.scope : challenge.scope;
  if (typeof scope === "string" && scope) details.scope = scope;
  // A token not issued for this service: its metadata, to read again (§4.5).
  if (challenge.resource_metadata) details.resource_metadata = challenge.resource_metadata;
  const retryAfter = response.headers.get("retry-after");
  if ((response.status === 429 || response.status === 503) && retryAfter) {
    details.retry_after = retryAfter;
  }
  if (body.error === "code_required") {
    // What continues a Mediated Sign-In (Mediated Sign-In 4).
    for (const name of CODE_REQUIRED) if (name in body) details[name] = body[name];
  }
  return details;
}

/**
 * The error a refusal names: in its JSON body, else its `WWW-Authenticate` challenge.
 *
 * A 401 challenge with no error code and a `scope` is a signed-out request for something that
 * needs the account: read as `insufficient_scope` (§7). A 429 has no body: `rate_limited`
 * (§5.6).
 */
export function refusalCode(response: Response, payload: unknown, fallback: string): string {
  const body =
    typeof payload === "object" && payload !== null && !Array.isArray(payload)
      ? (payload as Record<string, unknown>)
      : {};
  if (typeof body.error === "string") return body.error;
  const challenge = challengeParameters(response.headers.get("www-authenticate"));
  if (challenge.error !== undefined) return challenge.error;
  if (response.status === 401 && challenge.scope) return "insufficient_scope";
  if (response.status === 429) return "rate_limited";
  return fallback;
}

/** A refusal with nothing to parse, such as a 429 (§5.6) or a challenge alone (§7). */
export function refusedWithoutBody(response: Response, text: string): boolean {
  return !response.ok && !text;
}

type ErrorClass = new (
  code: string,
  message: string,
  options?: { statusCode?: number },
) => PersonalAgentProtocolError;

/**
 * Outside discovery a redirect never carries the protocol's secrets (§3).
 *
 * A token, revocation, device authorization or Mediated Sign-In endpoint, an API, or a
 * conversation, feedback or extension endpoint answering with a redirect is refused:
 * nothing is sent to the new URL. Its body is released unread.
 */
export async function refuseRedirect(response: Response, error: ErrorClass = TransportError): Promise<void> {
  // A browser's fetch with `redirect: "manual"` answers an opaque redirect, status 0.
  if (!REDIRECT_STATUSES.has(response.status) && response.type !== "opaqueredirect") return;
  await response.body?.cancel().catch(() => undefined);
  throw new error("redirect_refused", "A protocol endpoint answered with a redirect: nothing is sent to the new URL", {
    statusCode: response.status,
  });
}
