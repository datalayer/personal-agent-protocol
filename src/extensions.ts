/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Extension names, declaration, and `extension_required` (§3.3, §3.4), as in Python's
// personal_agent_protocol.extensions.
//
// Extensions defined with the protocol have plain names (`operations`); anyone else names
// theirs under a domain they control (`example.com/gift-wrap`). An invalid name is ignored
// like any extension the agent does not support. A Company lists each extension with an
// entry per version it supports; `negotiateExtensions` picks, for each, the version this
// SDK implements when the Company lists it: what the agent uses with that Company. It
// declares them, one version each, in the `Poppy-Extensions` header on every request with
// the Session header (`formatExtensionsHeader`, an RFC 9651 List of Strings with a `v`
// parameter), the same throughout a Session. An extension the company recognizes from the
// request itself, such as one with its own grant type, is never declared
// (`RECOGNIZED_FROM_THE_REQUEST`), and is never refused with `extension_required`. A Company
// reads the request's declaration (`parseExtensionsHeader`; a header that fails to parse
// declares none).
import type { ExtensionDescriptor } from "./models.js";

/** The header the Personal Agent declares the extensions it uses in (§3.4). */
export const EXTENSIONS_HEADER = "Poppy-Extensions";

/** Extensions this SDK implements, by name and major version. */
export const SUPPORTED_EXTENSIONS: Readonly<Record<string, string>> = Object.freeze({
  operations: "3",
  "mediated-sign-in": "1",
  links: "1",
  disclosures: "1",
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

/**
 * The extensions this agent uses with a Company, one version each (§3.3, §3.4): for each
 * extension the Company lists, with an entry per version it supports, the version this host
 * implements, when the Company lists it; everything else is ignored.
 */
export function negotiateExtensions(
  company: Readonly<Record<string, readonly ExtensionDescriptor[]>>,
  supported: Readonly<Record<string, string>> = SUPPORTED_EXTENSIONS,
): Record<string, string> {
  const negotiated: Record<string, string> = {};
  for (const [name, entries] of Object.entries(company)) {
    if (extensionNameKind(name) === "invalid") continue;
    const mine = Object.hasOwn(supported, name) ? supported[name] : undefined;
    if (mine !== undefined && entries.some((entry) => entry.version === mine)) negotiated[name] = mine;
  }
  return negotiated;
}

/**
 * `Poppy-Extensions` (§3.4): an RFC 9651 List of Strings, each an extension's name with its
 * version in the `v` parameter; `undefined` when nothing is declared. An extension the company
 * recognizes from the request itself is not declared.
 */
export function formatExtensionsHeader(extensions: Readonly<Record<string, string>>): string | undefined {
  const items = Object.entries(extensions)
    .filter(([name]) => !RECOGNIZED_FROM_THE_REQUEST.has(name) && extensionNameKind(name) !== "invalid")
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([name, version]) => `"${name}";v="${version}"`);
  return items.length ? items.join(", ") : undefined;
}

const SF_STRING = /"((?:[\x20\x21\x23-\x5B\x5D-\x7E]|\\["\\])*)"/y;
const SF_KEY = /[a-z*][a-z0-9_.*-]*/y;
const SF_COMMA = /[ \t]*,[ \t]*/y;

/**
 * The extensions a request declares (§3.4): the `Poppy-Extensions` List of Strings, each with
 * its `v` parameter. Without the header, or when it fails to parse (RFC 9651 §4.2), the request
 * declares no extensions; an item without a version, with an invalid name or an invalid
 * version, is ignored.
 */
export function parseExtensionsHeader(value: string | null | undefined): Record<string, string> {
  if (value === undefined || value === null || !value.trim()) return {};
  const text = value.trim();
  const declared: Record<string, string> = {};
  let position = 0;
  for (;;) {
    SF_STRING.lastIndex = position;
    const item = SF_STRING.exec(text);
    if (item === null) return {};
    const name = (item[1] ?? "").replace(/\\"/g, '"').replace(/\\\\/g, "\\");
    position = SF_STRING.lastIndex;
    let version: string | undefined;
    while (text[position] === ";") {
      position += 1;
      SF_KEY.lastIndex = position;
      const key = SF_KEY.exec(text);
      if (key === null) return {};
      position = SF_KEY.lastIndex;
      let parameter: string | undefined;
      if (text[position] === "=") {
        SF_STRING.lastIndex = position + 1;
        const quoted = SF_STRING.exec(text);
        if (quoted === null) return {};
        parameter = quoted[1] ?? "";
        position = SF_STRING.lastIndex;
      }
      if (key[0] === "v") version = parameter;
    }
    if (version !== undefined && /^(0|[1-9][0-9]*)$/.test(version) && extensionNameKind(name) !== "invalid") {
      declared[name] = version;
    }
    if (position >= text.length) return declared;
    SF_COMMA.lastIndex = position;
    const comma = SF_COMMA.exec(text);
    if (comma === null || SF_COMMA.lastIndex >= text.length) return {};
    position = SF_COMMA.lastIndex;
  }
}

/**
 * The extension a `403 extension_required` names, else `undefined` (§3.3).
 *
 * In the JSON body, at APIs as at the endpoints the protocol or an extension defines: it is not
 * an access token error, so a `WWW-Authenticate` challenge never carries it and none is read
 * for it (§7). The token endpoint returns none: extensions are declared per request, and one
 * with its own grant type is recognized from the request.
 */
export function extensionRequired(status: number, payload: unknown): string | undefined {
  if (status !== 403) return undefined;
  const values: Record<string, unknown> =
    typeof payload === "object" && payload !== null && !Array.isArray(payload) ? (payload as Record<string, unknown>) : {};
  if (values.error !== "extension_required") return undefined;
  const name = values.extension;
  // A company can't refuse a request that uses the extension itself (§3.3).
  if (typeof name !== "string" || RECOGNIZED_FROM_THE_REQUEST.has(name)) return undefined;
  return extensionNameKind(name) !== "invalid" ? name : undefined;
}
