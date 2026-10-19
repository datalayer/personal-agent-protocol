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
 * 429 (§4.3), never acted on here.
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
  const retryAfter = response.headers.get("retry-after");
  if (response.status === 429 && retryAfter) details.retry_after = retryAfter;
  return details;
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
