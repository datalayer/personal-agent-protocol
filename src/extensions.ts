/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Extension names, negotiation, and `extension_required` (§3.3), as in Python's
// personal_agent_protocol.extensions.
//
// Extensions defined with the protocol have plain names (`operations`); anyone else
// names theirs under a domain they control (`example.com/gift-wrap`). An invalid name is
// ignored like any extension the agent does not support. Negotiation keeps only what
// both sides list at the same major version, so either side works with the other under
// the specification alone. An extension the company recognizes from the request itself,
// such as one with its own grant type, needs no entry on the agent's side
// (`RECOGNIZED_FROM_THE_REQUEST`), and is never refused with `extension_required`.
import type { ExtensionDescriptor } from "./models.js";
import { challengeParameters } from "./refusals.js";

/** Extensions this SDK implements, by name and major version. */
export const SUPPORTED_EXTENSIONS: Readonly<Record<string, string>> = Object.freeze({
  operations: "2",
  "mediated-sign-in": "1",
});

/** Extensions a company recognizes from the request: the agent doesn't list them (§3.3). */
export const RECOGNIZED_FROM_THE_REQUEST: ReadonlySet<string> = new Set(["mediated-sign-in"]);

const PLAIN = /^[a-z][a-z0-9_-]{0,63}$/;
const LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
const THIRD_PARTY = new RegExp(`^((?:${LABEL}\\.)+${LABEL})/([a-z0-9][a-z0-9._-]{0,127})$`);

/** `plain` for a protocol-defined name, `third-party` for `domain/name`, else `invalid`. */
export function extensionNameKind(name: string): "plain" | "third-party" | "invalid" {
  if (PLAIN.test(name)) return "plain";
  if (THIRD_PARTY.test(name)) return "third-party";
  return "invalid";
}

/** The domain a third-party extension name is under, else `undefined`. */
export function extensionDomain(name: string): string | undefined {
  return THIRD_PARTY.exec(name)?.[1];
}

/** The extensions both sides list, at the same major version, that this host supports. */
export function negotiateExtensions(
  company: Readonly<Record<string, ExtensionDescriptor>>,
  agent: Readonly<Record<string, ExtensionDescriptor>>,
  supported: Readonly<Record<string, string>> = SUPPORTED_EXTENSIONS,
): Record<string, string> {
  const negotiated: Record<string, string> = {};
  for (const [name, descriptor] of Object.entries(company)) {
    if (extensionNameKind(name) === "invalid") continue;
    if (!Object.hasOwn(supported, name) || supported[name] !== descriptor.version) continue;
    const mine = Object.hasOwn(agent, name) ? agent[name] : undefined;
    if (mine === undefined) {
      if (RECOGNIZED_FROM_THE_REQUEST.has(name)) negotiated[name] = descriptor.version;
      continue;
    }
    if (mine.version === descriptor.version) negotiated[name] = descriptor.version;
  }
  return negotiated;
}

/**
 * The extension a `403 extension_required` names, else `undefined` (§3.3).
 *
 * In the JSON body at the token endpoint and the endpoints the protocol or an
 * extension defines; in the `WWW-Authenticate` challenge's `extension` attribute at an API.
 */
export function extensionRequired(status: number, payload: unknown, wwwAuthenticate?: string | null): string | undefined {
  if (status !== 403) return undefined;
  let values: Record<string, unknown> =
    typeof payload === "object" && payload !== null && !Array.isArray(payload) ? (payload as Record<string, unknown>) : {};
  if (values.error !== "extension_required" && wwwAuthenticate) values = challengeParameters(wwwAuthenticate);
  if (values.error !== "extension_required") return undefined;
  const name = values.extension;
  // A company can't refuse a request that uses the extension itself (§3.3).
  if (typeof name !== "string" || RECOGNIZED_FROM_THE_REQUEST.has(name)) return undefined;
  return extensionNameKind(name) !== "invalid" ? name : undefined;
}
