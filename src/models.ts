/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { AuthorizationError, ProtocolValidationError } from "./errors.js";
import { DRAFT_PROTOCOL_VERSION, PROTOCOL_PROFILE } from "./profile.js";

export type UnknownFields = Readonly<Record<string, unknown>>;

/**
 * The protocol versions a Personal Agent implements unless it asks for others (§3.4): a
 * Company's document is used at a version compatible with one of them, the same major and,
 * before 1.0, the same minor. The published version only, never the draft.
 */
export const SUPPORTED_PROTOCOL_VERSIONS: ReadonlySet<string> = new Set([PROTOCOL_PROFILE]);
/**
 * Every protocol version this SDK implements: the published one and the 1.0 draft. A Personal
 * Agent (`discoverCompany(domain, { protocolVersions })`) or a Company
 * (`CompanyConfigOptions.protocolVersions`) uses the draft only when it names it.
 */
export const AVAILABLE_PROTOCOL_VERSIONS: ReadonlySet<string> = new Set([PROTOCOL_PROFILE, DRAFT_PROTOCOL_VERSION]);
const VERSION = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

/** `major.minor` as numbers, or `ProtocolValidationError`. */
export function parseVersion(value: string): readonly [major: number, minor: number] {
  const match = VERSION.exec(value);
  if (match === null) {
    throw new ProtocolValidationError("unsupported_protocol_version", "a protocol version is major.minor");
  }
  return [Number(match[1]), Number(match[2])];
}

/**
 * Whether two protocol versions are compatible (§3.4): the same major version and, before
 * 1.0, the same minor version.
 */
export function compatibleVersions(one: string, other: string): boolean {
  const [first, second] = [parseVersion(one), parseVersion(other)];
  if (first[0] !== second[0]) return false;
  return first[0] >= 1 || first[1] === second[1];
}

/**
 * The versions a Personal Agent implements: `versions` as given, each one this SDK implements
 * (`AVAILABLE_PROTOCOL_VERSIONS`), or `SUPPORTED_PROTOCOL_VERSIONS` when absent. Throws
 * `RangeError` for an empty list or a version the SDK doesn't implement.
 */
export function implementedProtocolVersions(versions?: Iterable<string>): ReadonlySet<string> {
  if (versions === undefined) return SUPPORTED_PROTOCOL_VERSIONS;
  const chosen = new Set(versions);
  if (chosen.size === 0) throw new RangeError("a Personal Agent implements at least one protocol version");
  const unknown = [...chosen].filter((version) => !AVAILABLE_PROTOCOL_VERSIONS.has(version)).sort();
  if (unknown.length) {
    throw new RangeError(
      `protocol versions this SDK doesn't implement: ${unknown.join(", ")} ` +
        `(it implements ${[...AVAILABLE_PROTOCOL_VERSIONS].sort().join(", ")})`,
    );
  }
  return chosen;
}

/**
 * The version a Personal Agent names in `Poppy-Version` when it uses a Company at `chosen`
 * (§3.4): the one it implements that is compatible with `chosen`, such as `1.0` for a Company
 * used at `1.2`. Throws `RangeError` when this SDK implements none.
 */
export function implementedVersionFor(chosen: string): string {
  for (const version of AVAILABLE_PROTOCOL_VERSIONS) {
    if (compatibleVersions(chosen, version)) return version;
  }
  throw new RangeError(`this SDK implements no protocol version compatible with ${chosen}`);
}

/**
 * The newest version, among `protocolVersion` and `supportedVersions`, that is compatible with
 * one this SDK implements (§3.4); `undefined` when none is, and the Personal Agent then uses
 * none of the documents.
 */
export function chooseProtocolVersion(
  protocolVersion: string,
  supportedVersions: Iterable<string> = [],
  implemented: Iterable<string> = SUPPORTED_PROTOCOL_VERSIONS,
): string | undefined {
  const mine = [...implemented];
  const usable = [protocolVersion, ...supportedVersions].filter(
    (version) => VERSION.test(version) && mine.some((v) => compatibleVersions(version, v)),
  );
  if (!usable.length) return undefined;
  return usable.reduce((newest, version) => {
    const [a, b] = [parseVersion(newest), parseVersion(version)];
    return b[0] > a[0] || (b[0] === a[0] && b[1] > a[1]) ? version : newest;
  });
}
/** OAuth scope syntax (RFC 6749 §3.3): one scope token. */
const SCOPE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
/** The grant a Company's token endpoint MUST accept (§3.2). */
export const REFRESH_TOKEN_GRANT = "refresh_token";
/** The grants that say the Company offers Direct and Device Sign-In (§3.2, §4.4). */
export const AUTHORIZATION_CODE_GRANT = "authorization_code";
export const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
/** The sign-in extension, listed in `extensions` (Mediated Sign-In 2). */
export const MEDIATED_EXTENSION = "mediated-sign-in";
/** The Mediated Sign-In extension's grant type (Mediated Sign-In 2). */
export const MEDIATED_GRANT = "https://personalagentprotocol.org/grant/mediated-sign-in";
/**
 * The sign-in types, in the order a Personal Agent prefers them (§4): Direct Sign-In is the
 * preferred type, Device Sign-In stays, and Mediated Sign-In is transitional.
 */
export const SIGN_IN_TYPES = ["direct", "device", "mediated"] as const;
export type SignInType = (typeof SIGN_IN_TYPES)[number];
/** `changes` values a scope hint may give (§4.4); any other is read as `irreversible`. */
export const SCOPE_CHANGES = ["none", "reversible", "irreversible"] as const;
export type ScopeChanges = (typeof SCOPE_CHANGES)[number];

function scopeToken(value: unknown, label: string): string {
  if (typeof value !== "string" || !SCOPE.test(value)) {
    throw new ProtocolValidationError("invalid_scope", `${label} must follow OAuth scope syntax`);
  }
  return value;
}

/**
 * A loopback redirect URI (RFC 8252 §7.3): `http` to a loopback IP literal, any port.
 *
 * An app on the User's computer receives Direct Sign-In's answer there (§4.1).
 */
export function isLoopbackRedirect(value: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol !== "http:" || !parsed.hostname || parsed.username || parsed.password) {
    return false;
  }
  if (parsed.hash || value.includes("#")) return false;
  const host = parsed.hostname;
  if (host.startsWith("[") && host.endsWith("]")) return host === "[::1]";
  const octets = host.split(".");
  // The WHATWG parser normalizes IPv4 literals; a name is not a loopback IP literal.
  return (
    octets.length === 4 &&
    octets.every((octet) => /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255) &&
    octets[0] === "127"
  );
}

/**
 * Whether `given` is the redirect URI `registered` names (§4.1, §4.5).
 *
 * Exactly, except that a loopback redirect URI matches with any port (RFC 8252 §7.3).
 */
export function redirectUriMatches(registered: string, given: string): boolean {
  if (registered === given) return true;
  if (!(isLoopbackRedirect(registered) && isLoopbackRedirect(given))) return false;
  const one = new URL(registered);
  const other = new URL(given);
  return (
    one.hostname === other.hostname && one.pathname === other.pathname && one.search === other.search
  );
}

/**
 * Who the Company says it is (§3.1). `domain` is its identity; `name` and `logo_uri` are what the
 * domain says about itself, and nothing confirms them (§10.3): show the domain with the name
 * (`organizationLabel`) wherever the User might rely on the name.
 */
export interface Organization extends UnknownFields {
  readonly name: string;
  readonly domain: string;
  /**
   * An HTTPS URL of the Company's logo (§3.1), named as in client metadata (§4.1). An agent
   * shows it next to the Company's name and domain, never in place of the domain, and serves
   * its own copy (guides, *Finding a company*).
   */
  readonly logo_uri?: string;
}

/**
 * The Agent Skills discovery draft revision `skill_index` pins (§9.4): the `$schema` an index
 * names. An index with another, or none, is ignored; the rest of the tasks response is used.
 */
export const SKILL_INDEX_SCHEMA = "https://schemas.agentskills.io/discovery/0.2.0/schema.json";
/**
 * The artifact types the SDK recognizes (§9.4): a single `SKILL.md`, or an archive with
 * supporting files. An entry of another type is skipped.
 */
export const SKILL_TYPES: ReadonlySet<string> = new Set(["skill-md", "archive"]);
const SKILL_DIGEST = /^sha256:[0-9a-f]{64}$/u;

/**
 * A skill a Company publishes for Personal Agents acting for the User there (§9.4).
 *
 * `url` is resolved against `tasks.endpoint` (RFC 3986 §5) and is HTTPS; `digest` is the
 * SHA-256 of the artifact's raw bytes, `sha256:` and 64 lowercase hex characters, which
 * `fetchSkill` verifies. A skill is Company content (§10.1): it grants no account access,
 * changes no scopes, and supplies no User approval.
 */
export interface SkillEntry extends UnknownFields {
  readonly name: string;
  readonly description: string;
  readonly type: string;
  readonly url: string;
  readonly digest: string;
}

export interface ScopeOption extends UnknownFields {
  readonly scopes: readonly string[];
}

export interface MediatedField extends UnknownFields {
  readonly name: string;
  readonly label: string;
  readonly secret: boolean;
}

/**
 * Field names a Mediated Sign-In can't use: they would overwrite the grant's own parameters
 * (Mediated Sign-In 2).
 */
export const MEDIATED_RESERVED_FIELDS: ReadonlySet<string> = new Set([
  "grant_type",
  "scope",
  "resource",
  "client_id",
  "client_secret",
  "client_assertion",
  "client_assertion_type",
  "sign_in_id",
  "one_time_code",
]);

/** `extensions["mediated-sign-in"]`, version 1: the credentials to collect, its scopes. */
export interface MediatedSignIn extends UnknownFields {
  readonly version: "1";
  readonly fields: readonly MediatedField[];
  readonly scopes: readonly string[];
}

/** What a scope allows, its most consequential operation (§4.4): a Company's claim. */
export interface ScopeHint extends UnknownFields {
  readonly changes: string;
  readonly personal_data: boolean;
}

/** A hint's `changes`, with a value this SDK doesn't know read as `irreversible` (§4.4). */
export function effectiveChanges(hint: ScopeHint): ScopeChanges {
  return hint.changes === "none" || hint.changes === "reversible" ? hint.changes : "irreversible";
}

/**
 * `auth` (§3.1): optional; the issuer it names, and the Company's scopes.
 *
 * `issuer` is needed only when the domain's protected resource metadata lists more than
 * one authorization server, and then names one of them; with one, it may be left out,
 * and if present names that one (§3.1, §3.2). Direct and Device Sign-In are not here:
 * the issuer's `grant_types_supported` says whether the Company offers them.
 */
export interface AuthCapabilities extends UnknownFields {
  readonly issuer?: string;
  /**
   * `true` when the Company offers Personal Agents no sign-in, though it has an issuer (§3.2):
   * its identifier stays the issuer, and no sign-in is started with it.
   */
  readonly disabled?: boolean;
  readonly scopes: Readonly<Record<string, string>>;
  readonly scope_hints: Readonly<Record<string, ScopeHint>>;
}

/** A conversation protocol the Company Agent speaks (§3.1, §8); read `access` with `accountAccess`. */
export interface AgentProtocol extends UnknownFields {
  readonly type: string;
  readonly endpoint: string;
  readonly access?: string;
}

/**
 * Whether a `poppy` entry needs account access before useful work can begin (§3.2).
 *
 * `signed_in` lets the agent arrange sign-in before its first request; a value this SDK doesn't
 * know is an absent hint. A hint only: it grants nothing, and challenges and authorization
 * events still decide.
 */
export function accountAccess(protocol: AgentProtocol): "session" | "signed_in" {
  return protocol.type === "poppy" && protocol.access === "signed_in" ? "signed_in" : "session";
}

export interface AgentDescriptor extends UnknownFields {
  readonly protocols: readonly AgentProtocol[];
}

export interface ApiDescriptor extends UnknownFields {
  readonly type: string;
  readonly url: string;
  readonly description: string;
}

/**
 * The Company's website (§3.1, §6): where the agent's browser joins a Session, whether the
 * Company asks Personal Agents not to browse (`disabled`), and whether `poppy:browser-sign-in`
 * gives the account's full access there (`unscoped`).
 */
export interface WebDescriptor extends UnknownFields {
  readonly browser_session_endpoint?: string;
  readonly disabled: boolean;
  readonly unscoped: boolean;
}

/**
 * The one scope the protocol defines (§4.7, §6): a signed-in browser join needs an access token
 * with it; the website applies the cookie's other scopes, or treats it as everything the account
 * can do there and says so with `web.unscoped`.
 */
export const BROWSER_SIGN_IN_SCOPE = "poppy:browser-sign-in";

/**
 * Whether the Company asks Personal Agents not to browse its website (`web.disabled`, §6): use
 * its Company Agent and APIs instead. Not enforceable, a preference.
 */
export function browsingDisabled(document: DiscoveryDocument): boolean {
  return document.web?.disabled === true;
}

/**
 * The scope a signed-in browser join needs (§6): `poppy:browser-sign-in`, requested only from a
 * Company that lists `browser_session_endpoint`; nothing otherwise.
 */
export function browserSignInScopes(document: DiscoveryDocument): readonly string[] {
  return document.web?.browser_session_endpoint === undefined ? [] : [BROWSER_SIGN_IN_SCOPE];
}

/**
 * What each scope allows, in the Company's words (§4.7).
 *
 * The scopes of the OAuth 2.0 security schemes in `openapi`, an OpenAPI description the Company
 * lists (section 7), then `auth.scopes`: when both describe a scope, the description in
 * `auth.scopes` is the one used.
 */
export function scopeDescriptions(document: DiscoveryDocument, openapi?: unknown): Record<string, string> {
  const described: Record<string, string> = {};
  const record = (value: unknown): Record<string, unknown> | undefined =>
    typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : undefined;
  const schemes = record(record(record(openapi)?.components)?.securitySchemes) ?? {};
  for (const scheme of Object.values(schemes).map(record)) {
    if (scheme?.type !== "oauth2") continue;
    for (const flow of Object.values(record(scheme.flows) ?? {}).map(record)) {
      for (const [name, text] of Object.entries(record(flow?.scopes) ?? {})) {
        if (typeof text === "string" && !(name in described)) described[name] = text;
      }
    }
  }
  return { ...described, ...(document.auth?.scopes ?? {}) };
}

/**
 * Whether `poppy:browser-sign-in` gives the account's full access on the website (`web.unscoped`,
 * §6): treat it like a scope that allows changes that can't be undone, and ask the User when you
 * would for one.
 */
export function browserSignInUnscoped(document: DiscoveryDocument): boolean {
  return document.web?.unscoped === true;
}

export interface ExtensionDescriptor extends UnknownFields {
  readonly version: string;
}

/**
 * Where personal agents report a task the protocol can't do at this company (§9.3): `feedback`
 * in the tasks response, a Session header destination (§5.2).
 */
export interface FeedbackDescriptor extends UnknownFields {
  readonly endpoint: string;
}

/**
 * Where a Personal Agent gets, for a Session, the tasks the Company chose not to offer, the
 * skills it publishes and where to send feedback (§3.1, §9): `tasks` in poppy.json.
 */
export interface TasksDescriptor extends UnknownFields {
  readonly endpoint: string;
}

export interface DiscoveryDocument extends UnknownFields {
  readonly protocol_version: string;
  /**
   * The other protocol versions the Company serves, each mapped to the HTTPS URL of that
   * version's document, on the host that served `poppy.json` (§3.4). A version's own document
   * lists none.
   */
  readonly supported_versions: Readonly<Record<string, string>>;
  readonly organization: Organization;
  readonly auth?: AuthCapabilities;
  readonly agent?: AgentDescriptor;
  readonly web?: WebDescriptor;
  readonly apis: readonly ApiDescriptor[];
  /**
   * Where the tasks response is served, per Session (§9): excluded tasks, skills and the
   * feedback endpoint are read from it, never from this document.
   */
  readonly tasks?: TasksDescriptor;
  /**
   * The extensions the Company supports, keyed by name, each a list with an entry per major
   * version it supports (§3.3); each extension defines the entry's other fields.
   */
  readonly extensions: Readonly<Record<string, readonly ExtensionDescriptor[]>>;
}

/** The issuer's RFC 8414 metadata, with the fields this protocol requires (§3.2). */
export interface OAuthServerMetadata extends UnknownFields {
  readonly issuer: string;
  readonly token_endpoint: string;
  readonly revocation_endpoint: string;
  readonly grant_types_supported: readonly string[];
  /**
   * RFC 9728 §4: `https://{domain}` for every domain whose `poppy.json` names the issuer,
   * exactly as written, compared as a string (§3.2).
   */
  readonly protected_resources: readonly string[];
  readonly authorization_endpoint?: string;
  readonly device_authorization_endpoint?: string;
  readonly pushed_authorization_request_endpoint?: string;
  readonly scopes_supported?: readonly string[];
  readonly dpop_signing_alg_values_supported?: readonly string[];
}

/** Whether the Company offers Direct Sign-In (§3.2, §4.4). */
export function offersDirect(metadata: OAuthServerMetadata): boolean {
  return metadata.grant_types_supported.includes(AUTHORIZATION_CODE_GRANT);
}

/** Whether the Company offers Device Sign-In (§3.2, §4.4). */
export function offersDevice(metadata: OAuthServerMetadata): boolean {
  return metadata.grant_types_supported.includes(DEVICE_CODE_GRANT);
}

/**
 * Whether `protected_resources` names `https://{domain}` (§3.2).
 *
 * Exactly, except that the host compares ignoring case: an entry with a path, a port or
 * a trailing slash does not match.
 */
export function listsResource(metadata: OAuthServerMetadata, domain: string): boolean {
  const wanted = domain.toLowerCase().replace(/\.$/, "");
  return metadata.protected_resources.some((entry) => {
    if (!entry.startsWith("https://")) return false;
    const host = entry.slice("https://".length);
    return Boolean(host) && !/[/?#:@]/.test(host) && host.toLowerCase() === wanted;
  });
}

export interface ClientMetadata extends UnknownFields {
  readonly client_id: string;
  readonly client_name: string;
  readonly logo_uri?: string;
  readonly jwks_uri: string;
  readonly redirect_uris: readonly string[];
  readonly token_endpoint_auth_method: "private_key_jwt";
}

export interface JsonWebKey extends UnknownFields {
  readonly kty: "EC" | "RSA";
  readonly kid?: string;
  readonly use?: "sig";
  readonly alg?: "ES256" | "PS384";
  readonly crv?: "P-256";
  readonly x?: string;
  readonly y?: string;
  readonly n?: string;
  readonly e?: string;
}

export interface JsonWebKeySet extends UnknownFields {
  readonly keys: readonly JsonWebKey[];
}

/**
 * One action the Company performs once it is approved (Operations 3).
 *
 * `terms` are required and hold everything that affects the action; `summary`, the same terms
 * in plain language, is optional (absent, never `null`). `revision` is opaque: it identifies
 * these terms, and the Company changes it whenever the `terms` or `expires_at` change.
 */
export interface Operation extends UnknownFields {
  readonly operation_id: string;
  readonly revision: string;
  readonly summary?: string;
  readonly terms: Readonly<Record<string, unknown>>;
  readonly expires_at: string;
}

/**
 * How a revision was approved (Operations 5, 6): by the User, asked by the Personal Agent, or
 * by the Personal Agent on an instruction the User gave it.
 */
export const APPROVERS = ["user", "agent"] as const;
export type Approver = (typeof APPROVERS)[number];

/** The values of an operation's `terms`, keyed by their dotted paths. */
export function termsLeaves(value: unknown, path = ""): Map<string, unknown> {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    const found = new Map<string, unknown>();
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      for (const [inner, leaf] of termsLeaves(item, path ? `${path}.${key}` : key)) found.set(inner, leaf);
    }
    return found;
  }
  return new Map([[path, value]]);
}

/**
 * A leaf of the terms as text, as Python's `str` writes it, so both SDKs show the same: a
 * string as it is, `True`, `False`, `None`, a number, a list of them.
 */
export function shownValue(value: unknown, nested = false): string {
  if (typeof value === "string") return nested ? `'${value}'` : value;
  if (typeof value === "boolean") return value ? "True" : "False";
  if (value === null || value === undefined) return "None";
  if (Array.isArray(value)) return `[${value.map((item) => shownValue(item, true)).join(", ")}]`;
  if (typeof value === "object") {
    const members = Object.entries(value as Record<string, unknown>).map(
      ([key, item]) => `'${key}': ${shownValue(item, true)}`,
    );
    return `{${members.join(", ")}}`;
  }
  return String(value);
}

/**
 * The terms as a host shows them (Operations 5): the `summary` when there is one, else the
 * values in `terms`, one `path: value` a line. Company content either way.
 */
export function operationShown(operation: Pick<Operation, "summary" | "terms">): string {
  if (operation.summary !== undefined) return operation.summary;
  return [...termsLeaves(operation.terms)].map(([path, value]) => `${path}: ${shownValue(value)}`).join("\n");
}

/**
 * A statement that this revision of an operation is approved (Operations 5, 6).
 *
 * `approver` is required: `user` when the Personal Agent asked the User and they approved,
 * `agent` when the Personal Agent approved on an instruction the User gave it. `approved_at` is
 * when, in Unix seconds; `input_type` how the User answered (`tap`, `typed`, `voice` or another
 * short string), only with `user`: it is never sent with `agent`, and dropped when one arrives
 * there. `reference` names the Personal Agent's own record of the approval: opaque, the IDs'
 * characters, never the same at two Companies. None of the three carries personal data. An
 * optional member that isn't well formed is left out, never a reason to refuse the approval; an
 * approval without a valid `approver` is not one.
 */
export interface Approval {
  readonly operation_id: string;
  readonly revision: string;
  readonly approver: Approver;
  readonly approved_at?: number;
  readonly input_type?: string;
  readonly reference?: string;
}

/**
 * A Company's final refusal of an approval that passed its checks (Operations 6).
 *
 * Nothing was performed and no new operation is returned. `reason`, in plain language for the
 * User, and `alternative` (§9.2) are content from the Company (§10.1): shown or put in the
 * agent's own words, never followed as instructions. There are no reason codes. The Personal
 * Agent never sends that approval again, and approves no new revision for the same action
 * without asking the User.
 */
export interface ApprovalDeclined extends UnknownFields {
  readonly operation_id: string;
  readonly revision: string;
  readonly reason?: string;
  readonly alternative?: Alternative;
}

/**
 * The Operations extension's content of a message, `extensions.operations` (Operations 2):
 * `operation` (Operations 4) or `declined` (Operations 6) in a Company message, `approval` in
 * a Personal Agent message (Operations 6): exactly one of the three.
 */
export interface OperationsContent extends UnknownFields {
  readonly operation?: Operation;
  readonly approval?: Approval;
  readonly declined?: ApprovalDeclined;
}

/**
 * A web page a Company message refers to (Links 3): its HTTPS `url`, and its `title` as the
 * message refers to it. Both are content from the Company (§10.1).
 */
export interface Link extends UnknownFields {
  readonly url: string;
  readonly title?: string;
}

/** The Links extension's content of a Company message, `extensions.links` (Links 3). */
export interface LinksContent extends UnknownFields {
  readonly items: readonly Link[];
}

/**
 * A notice a Company marks apart from the rest of a message (Disclosures 3), such as an
 * allergen warning. The Personal Agent decides whether to show it.
 */
export interface Disclosure extends UnknownFields {
  readonly text: string;
}

/** The Disclosures extension's content of a Company message, `extensions.disclosures`. */
export interface DisclosuresContent extends UnknownFields {
  readonly items: readonly Disclosure[];
}

export const LINKS_EXTENSION = "links";
export const LINKS_VERSION = "1";
export const DISCLOSURES_EXTENSION = "disclosures";
export const DISCLOSURES_VERSION = "1";

/**
 * Content extensions define in a message, keyed by extension name (§8.4). Each value is the
 * object its extension defines; the ones this SDK defines are checked by `parseMessage`,
 * and read with `messageOperation`, `messageApproval`, `messageLinks` and
 * `messageDisclosures`.
 */
export type MessageExtensions = Readonly<Record<string, Readonly<Record<string, unknown>>>>;

/**
 * Who wrote a message (§7.4): `agent` or `human`, and for a Company message, who.
 *
 * `id`, `name` and `image` name the Company's person or AI persona; each is optional, and
 * the Personal Agent never sends them.
 */
export interface Author extends UnknownFields {
  readonly type: "agent" | "human";
  readonly id?: string;
  readonly name?: string;
  readonly image?: string;
}

/**
 * A message sent by either side, or returned in a conversation event (§8.4).
 *
 * `id` is set by the Company when it records the message as an event: a Personal Agent
 * message's ID is its request's ID (§8.3), a Company message's one it chooses. On a message the
 * Personal Agent builds, `id` is the request ID the client sends at the top level of the `POST`;
 * the message itself goes without it.
 */
export interface Message extends UnknownFields {
  readonly id?: string;
  readonly author: Author;
  readonly role?: "user" | "company";
  /**
   * What the writer had seen (§8.4), hints neither side depends on: on a Company Agent message,
   * the ID of the latest request it took into account; on a message the Personal Agent wrote,
   * the last cursor it had read. A person's message carries neither.
   */
  readonly as_of_request?: string;
  readonly as_of_cursor?: string;
  readonly text?: string;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly context?: Readonly<Record<string, unknown>>;
  /**
   * Content extensions define, keyed by extension name (§8.4): `operations` carries an
   * operation, an approval or a decline, `links` and `disclosures` their items. A side sends an
   * extension's content only to a side that lists the same version; content of an extension
   * this SDK does not define is kept as the object it is.
   */
  readonly extensions?: MessageExtensions;
}

/** A Company message's operation, for the User's approval (Operations 4). */
export function messageOperation(message: Message): Operation | undefined {
  const content = message.extensions?.[OPERATIONS_CONTENT];
  return content === undefined ? undefined : parseOperationsContent(content).operation;
}

/** A Personal Agent message's approval: only this approves, never `text` (Operations 6). */
export function messageApproval(message: Message): Approval | undefined {
  const content = message.extensions?.[OPERATIONS_CONTENT];
  return content === undefined ? undefined : parseOperationsContent(content).approval;
}

/** A Company message's decline of an approval: nothing was performed (Operations 6). */
export function messageDeclined(message: Message): ApprovalDeclined | undefined {
  const content = message.extensions?.[OPERATIONS_CONTENT];
  return content === undefined ? undefined : parseOperationsContent(content).declined;
}

/** The web pages a Company message refers to (Links 3); none without the extension. */
export function messageLinks(message: Message): readonly Link[] {
  const content = message.extensions?.[LINKS_EXTENSION];
  return content === undefined ? [] : parseLinksContent(content).items;
}

/** The notices a Company message marks apart (Disclosures 3); none without the extension. */
export function messageDisclosures(message: Message): readonly Disclosure[] {
  const content = message.extensions?.[DISCLOSURES_EXTENSION];
  return content === undefined ? [] : parseDisclosuresContent(content).items;
}

/** A message's `extensions` carrying the Operations extension's content (Operations 2). */
export function operationsContent(content: {
  readonly operation?: Operation;
  readonly approval?: Approval;
  readonly declined?: ApprovalDeclined;
}): MessageExtensions {
  return { [OPERATIONS_CONTENT]: parseOperationsContent(content) as Record<string, unknown> };
}

const OPERATIONS_CONTENT = "operations";

/** Whether the Company is looking for a person (§8.7, §8.9). */
export type ConversationHandoff = "none" | "pending";
export type ConversationResponder = "agent" | "human";

/** A `handoff` this SDK doesn't recognize reads as `pending` (§8.7). */
export function knownHandoff(value: unknown, label = "handoff"): ConversationHandoff {
  if (typeof value !== "string") {
    throw new ProtocolValidationError("invalid_value", `${label} must be a string`);
  }
  return value === "none" ? "none" : "pending";
}

/**
 * Where a conversation stands, in four fields each independent of the others (§8.7).
 *
 * `working` is true while the Company has work in progress: a request it accepted but hasn't
 * acted on, a reply being written, or work it started on its own; a Personal Agent that wants
 * the whole reply reads until it is false. `handoff` is `pending` while the Company looks for
 * a person (§8.9). `responder` is who handles the Company side. `closed` means the conversation
 * takes no more messages (§8.12). A new conversation starts with `handoff` `none`, `responder`
 * `agent` and `closed` false.
 */
export interface ConversationState {
  readonly working: boolean;
  readonly handoff: ConversationHandoff;
  readonly responder: ConversationResponder;
  readonly closed: boolean;
}

/** The four state fields of a read or a receipt (§8.7). */
export function conversationState(value: ConversationState): ConversationState {
  const { working, handoff, responder, closed } = value;
  return { working, handoff, responder, closed };
}

function stateFields(source: Record<string, unknown>, label: string): ConversationState {
  return {
    working: boolean(source.working, `${label}.working`),
    handoff: knownHandoff(source.handoff, `${label}.handoff`),
    responder: knownResponder(source.responder, `${label}.responder`),
    closed: boolean(source.closed, `${label}.closed`),
  };
}

/** A `responder` this SDK doesn't recognize reads as `human` (§8.7). */
export function knownResponder(value: unknown, label = "responder"): ConversationResponder {
  if (typeof value !== "string") {
    throw new ProtocolValidationError("invalid_value", `${label} must be a string`);
  }
  return value === "agent" ? "agent" : "human";
}

export interface ConversationEvent extends UnknownFields {
  readonly id: string;
  readonly type: string;
  readonly created_at: string;
  readonly message?: Message;
  /** A `state` event's fields (§8.7): after any of them changes; `working` is never an event. */
  readonly handoff?: ConversationHandoff;
  readonly responder?: ConversationResponder;
  readonly closed?: boolean;
  readonly error?: "insufficient_scope";
  readonly scope?: string;
  readonly reason?: string;
  readonly conversation_id?: string;
}

/**
 * A cursor page returned by a read or a waited write, with the conversation's state when the
 * Company responded (§8.5, §8.7). While `has_more` is true the state fields can be newer than
 * the events returned: a reader applies the events in order and relies on the state once
 * `has_more` is false.
 */
export interface ConversationEventPage extends UnknownFields, ConversationState {
  readonly conversation_id: string;
  readonly events: readonly ConversationEvent[];
  readonly cursor: string;
  readonly has_more: boolean;
}

/**
 * A verified `poppy.json`, its domain's protected resource metadata, and its issuer's.
 *
 * A Company with no issuer has no `oauthMetadata`, and `resourceMetadata` only when the domain
 * publishes it with no authorization server; it offers no sign-in (§3.2).
 */
export interface DiscoveredCompany {
  readonly discoveryUrl: string;
  readonly document: DiscoveryDocument;
  readonly resourceMetadata?: ProtectedResourceMetadata;
  readonly oauthMetadata?: OAuthServerMetadata;
}

/**
 * The version a Personal Agent that implements `implemented` (this SDK's default versions
 * when absent) uses this Company at (§3.4): the newest, among `protocol_version` and
 * `supported_versions`, compatible with one it implements. When it is not `protocol_version`,
 * the version's own document is fetched and used.
 */
export function chosenVersion(
  document: DiscoveryDocument,
  implemented: Iterable<string> = SUPPORTED_PROTOCOL_VERSIONS,
): string | undefined {
  return chooseProtocolVersion(document.protocol_version, Object.keys(document.supported_versions), implemented);
}

/**
 * The protocol version the Company is used at (§3.4): `document` is that version's document,
 * and every Session with the Company names it in `Poppy-Version`.
 */
export function companyProtocolVersion(company: DiscoveredCompany): string {
  return company.document.protocol_version;
}

/**
 * What a Session with the Company names in `Poppy-Version` (§3.4): the version this SDK
 * implements that is compatible with the one the Company is used at.
 */
export function companySessionVersion(company: DiscoveredCompany): string {
  return implementedVersionFor(company.document.protocol_version);
}

/**
 * The Company's name with its domain beside it, `Manzanita (manzanita.example)`; only the
 * domain when the name is the domain. Nothing in `poppy.json` confirms that the domain belongs
 * to the company it names, and a lookalike domain can use another Company's name and logo
 * (§10.3): the domain is the Company, so show it wherever the User might rely on the name
 * (guides, *Finding a company*).
 */
export function organizationLabel(organization: Organization): string {
  const name = organization.name.trim();
  if (name.toLowerCase().replace(/\.$/, "") === organization.domain) return organization.domain;
  return `${name} (${organization.domain})`;
}

/** The Company's OAuth issuer, as found from its domain (§3.2). */
export function companyIssuer(company: DiscoveredCompany): string | undefined {
  return company.oauthMetadata?.issuer;
}

/** `https://{organization.domain}`: the resource the default access token is for. */
export function companyResource(company: DiscoveredCompany): string {
  return `https://${company.document.organization.domain}`;
}

/**
 * The sign-in types the Company offers a Personal Agent, in the order it prefers them (§4):
 * `direct`, then `device`, then `mediated`.
 *
 * Direct and Device Sign-In are the issuer's grants, Mediated Sign-In its grant with the
 * extension listed; none at all without an issuer or with sign-in turned off.
 */
export function signInTypes(company: DiscoveredCompany): readonly SignInType[] {
  const metadata = company.oauthMetadata;
  if (metadata === undefined || signInDisabled(company.document)) return [];
  const offered = [
    offersDirect(metadata),
    offersDevice(metadata),
    MEDIATED_EXTENSION in company.document.extensions &&
      metadata.grant_types_supported.includes(MEDIATED_GRANT),
  ];
  return SIGN_IN_TYPES.filter((_, index) => offered[index]);
}

/**
 * The sign-in type to use (§4): Direct Sign-In when the Company offers it, else Device Sign-In,
 * else Mediated Sign-In; `undefined` when it offers none.
 */
export function preferredSignIn(company: DiscoveredCompany): SignInType | undefined {
  return signInTypes(company)[0];
}

/**
 * The scopes the Company says a Personal Agent can request (§3.2, §4.7): the issuer's
 * `scopes_supported`, then the ones only the domain's protected resource metadata lists, each
 * once. A Company can list them in either or both, and the agent uses the scopes in either
 * list; both may leave out scopes it offers only to its other clients, and a scope its APIs or
 * a sign-in extension document may be requested though absent from both.
 */
export function scopesSupported(company: DiscoveredCompany): readonly string[] {
  return [
    ...new Set([
      ...(company.oauthMetadata?.scopes_supported ?? []),
      ...(company.resourceMetadata?.scopes_supported ?? []),
    ]),
  ];
}

/**
 * The skills of a tasks response's `skill_index` this SDK can use (§9.4), each `url` resolved.
 *
 * Nothing when there is no index or its `$schema` is not `SKILL_INDEX_SCHEMA`; an entry whose
 * `type` is unknown, which lacks a field, whose `digest` is malformed, or whose `url`, resolved
 * against `baseUrl` (`tasks.endpoint`), is not HTTPS is skipped. The guides suggest telling the
 * User when that mattered for the task.
 */
export function usableSkills(response: Pick<TasksResponse, "skill_index">, baseUrl: string): SkillEntry[] {
  const index = response.skill_index;
  if (index === undefined || index === null || typeof index !== "object") return [];
  if (index.$schema !== SKILL_INDEX_SCHEMA || !Array.isArray(index.skills)) return [];
  const usable: SkillEntry[] = [];
  for (const raw of index.skills as unknown[]) {
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) continue;
    const entry = raw as Record<string, unknown>;
    const { name, description, type, url, digest } = entry;
    if (typeof type !== "string" || !SKILL_TYPES.has(type)) continue;
    if (typeof name !== "string" || !name || typeof description !== "string" || !description) continue;
    if (typeof url !== "string" || !url || typeof digest !== "string" || !SKILL_DIGEST.test(digest)) continue;
    let resolved: string;
    try {
      resolved = httpsUrl(new URL(url, baseUrl).toString(), "skill url");
    } catch {
      continue;
    }
    usable.push({ ...entry, name, description, type, url: resolved, digest });
  }
  return usable;
}

/**
 * Who the Company is (§3.2): its issuer, else `https://{organization.domain}`.
 *
 * Session JWTs name it in `aud`, and User IDs and Agent IDs are scoped by it. Discovery reaches
 * the domain only when it established that there is no issuer: never after an error, a timeout,
 * or an issuer that failed to verify.
 */
export function companyIdentifier(company: DiscoveredCompany): string {
  return companyIssuer(company) ?? companyResource(company);
}

/** The issuer's metadata, or `AuthorizationError` (`no_issuer`), before any sign-in. */
/**
 * Whether the Company turned sign-in off (`auth.disabled`, §3.2): a Personal Agent starts no
 * Direct, Device or Mediated Sign-In with it, whatever its issuer's grants say; a Mediated
 * Sign-In entry or `signed_in` access it lists anyway is not used.
 */
export function signInDisabled(document: DiscoveryDocument): boolean {
  return document.auth?.disabled === true;
}

/**
 * The issuer's metadata, or `AuthorizationError`, before any sign-in: `no_issuer` for a
 * Company with no issuer, `sign_in_disabled` for one that turned sign-in off (§3.2).
 */
export function requireOauth(company: DiscoveredCompany): OAuthServerMetadata {
  if (company.oauthMetadata === undefined) {
    throw new AuthorizationError("no_issuer", "A Company with no issuer offers no sign-in");
  }
  if (signInDisabled(company.document)) {
    throw new AuthorizationError("sign_in_disabled", "The Company turned sign-in off for Personal Agents");
  }
  return company.oauthMetadata;
}

/**
 * Whether the Company offers sign-in, which needs an OAuth issuer (§3.2).
 *
 * `auth.issuer`, an `access: signed_in` conversation entry, or Mediated Sign-In. Anything else
 * works signed out: APIs, conversations, feedback and browser join.
 */
export function needsIssuer(document: DiscoveryDocument): boolean {
  return (
    document.auth?.issuer !== undefined ||
    (document.agent?.protocols.some((protocol) => accountAccess(protocol) === "signed_in") ?? false) ||
    MEDIATED_EXTENSION in document.extensions
  );
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ProtocolValidationError("invalid_type", `${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ProtocolValidationError("invalid_type", `${label} must be a non-empty string`);
  }
  return value;
}

function array(value: unknown, label: string): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new ProtocolValidationError("invalid_type", `${label} must be an array`);
  }
  return value;
}

function boolean(value: unknown, label: string): boolean {
  if (typeof value !== "boolean") {
    throw new ProtocolValidationError("invalid_type", `${label} must be a boolean`);
  }
  return value;
}

function integer(value: unknown, label: string, minimum = 1): number {
  if (!Number.isInteger(value) || (value as number) < minimum) {
    throw new ProtocolValidationError(
      "invalid_type",
      `${label} must be an integer greater than or equal to ${minimum}`,
    );
  }
  return value as number;
}

function identifier(value: unknown, label: string): string {
  const result = string(value, label);
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(result)) {
    throw new ProtocolValidationError(
      "invalid_identifier",
      `${label} must use the URL-safe base64 alphabet`,
    );
  }
  return result;
}

function timestamp(value: unknown, label: string): string {
  const result = string(value, label);
  if (!/(?:Z|[+-][0-9]{2}:[0-9]{2})$/u.test(result) || Number.isNaN(Date.parse(result))) {
    throw new ProtocolValidationError(
      "invalid_timestamp",
      `${label} must be an RFC 3339 timestamp with a timezone`,
    );
  }
  return result;
}

function oneOf<T extends string>(
  value: unknown,
  values: readonly T[],
  label: string,
): T {
  if (typeof value !== "string" || !values.includes(value as T)) {
    throw new ProtocolValidationError(
      "invalid_value",
      `${label} must be one of ${values.join(", ")}`,
    );
  }
  return value as T;
}

function optionalRecord(
  value: unknown,
  label: string,
): Readonly<Record<string, unknown>> | undefined {
  return value === undefined ? undefined : record(value, label);
}

/**
 * An object whose optional members may be JSON `null`, read as absent.
 *
 * Python's models declare these members `X | None` and serialize `None` as
 * `null`; both SDKs accept either spelling and treat them the same.
 */
function nullsAbsent(
  value: unknown,
  label: string,
  members: readonly string[],
): Record<string, unknown> {
  const source = record(value, label);
  if (!members.some((member) => source[member] === null)) return source;
  const copy: Record<string, unknown> = { ...source };
  for (const member of members) {
    if (copy[member] === null) delete copy[member];
  }
  return copy;
}

function extensions(
  value: unknown,
  label: string,
): Readonly<Record<string, readonly ExtensionDescriptor[]>> {
  const source = record(value ?? {}, label);
  return Object.fromEntries(
    Object.entries(source).map(([name, items]) => {
      const entries = array(items, `${label}.${name}`);
      if (!entries.length) {
        throw new ProtocolValidationError("invalid_extension", `${label}.${name} lists at least one version`);
      }
      return [
        name,
        entries.map((item, index) => {
          const extension = record(item, `${label}.${name}[${index}]`);
          const version = string(extension.version, `${label}.${name}[${index}].version`);
          if (!/^(0|[1-9][0-9]*)$/.test(version)) {
            throw new ProtocolValidationError(
              "invalid_extension_version",
              `${label}.${name}[${index}].version must be a major version`,
            );
          }
          return { ...extension, version } as ExtensionDescriptor;
        }),
      ];
    }),
  );
}

/** The Company's entry for `name` at `version` (§3.3), or `undefined`. */
export function companyExtension(
  document: DiscoveryDocument,
  name: string,
  version: string,
): ExtensionDescriptor | undefined {
  return (document.extensions[name] ?? []).find((entry) => entry.version === version);
}

function httpsUrl(value: unknown, label: string): string {
  const result = string(value, label);
  let parsed: URL;
  try {
    parsed = new URL(result);
  } catch (cause) {
    throw new ProtocolValidationError("invalid_url", `${label} must be an HTTPS URL`, {
      cause,
    });
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new ProtocolValidationError(
      "invalid_url",
      `${label} must be an HTTPS URL without user information`,
    );
  }
  return result;
}

function domain(value: unknown, label: string): string {
  const result = string(value, label).replace(/\.$/, "").toLowerCase();
  if (
    !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(
      result,
    )
  ) {
    throw new ProtocolValidationError("invalid_domain", `${label} must be a DNS domain`);
  }
  return result;
}

function scopes(value: unknown, label: string): ScopeOption {
  const source = record(value, label);
  return {
    ...source,
    scopes: array(source.scopes ?? [], `${label}.scopes`).map((item) =>
      scopeToken(item, `${label}.scopes entry`),
    ),
  } as ScopeOption;
}

function stringMap(value: unknown, label: string): Readonly<Record<string, string>> {
  const source = record(value, label);
  return Object.fromEntries(
    Object.entries(source).map(([key, item]) => [key, string(item, `${label}.${key}`)]),
  );
}

/**
 * A `poppy.json`, checked (§3.1). Its version, or one it links to, must be compatible with one
 * in `implemented`: by default any this SDK implements; which of them a Personal Agent uses is
 * its own choice, made at discovery (`DiscoveryOptions.protocolVersions`).
 */
export function parseDiscoveryDocument(
  value: unknown,
  implemented: Iterable<string> = AVAILABLE_PROTOCOL_VERSIONS,
): DiscoveryDocument {
  const source = record(value, "poppy.json");
  const version = string(source.protocol_version, "protocol_version");
  if (!VERSION.test(version)) {
    throw new ProtocolValidationError("unsupported_protocol_version", "protocol_version must use major.minor");
  }
  const supportedVersions = stringMap(source.supported_versions ?? {}, "supported_versions");
  for (const [other, url] of Object.entries(supportedVersions)) {
    if (!VERSION.test(other)) {
      throw new ProtocolValidationError("unsupported_protocol_version", "supported_versions are keyed by major.minor");
    }
    httpsUrl(url, `supported_versions[${other}]`);
  }
  if (chooseProtocolVersion(version, Object.keys(supportedVersions), implemented) === undefined) {
    // A document is used only at a version compatible with one this SDK implements, its
    // own or one it links to (§3.1, §3.4).
    throw new ProtocolValidationError(
      "unsupported_protocol_version",
      "protocol_version must be compatible with a version this SDK implements, or link to one",
    );
  }

  const organizationSource = record(source.organization, "organization");
  const organization: Organization = {
    ...organizationSource,
    name: string(organizationSource.name, "organization.name"),
    domain: domain(organizationSource.domain, "organization.domain"),
    ...(organizationSource.logo_uri === undefined || organizationSource.logo_uri === null
      ? {}
      : { logo_uri: httpsUrl(organizationSource.logo_uri, "organization.logo_uri") }),
  } as Organization;

  let auth: AuthCapabilities | undefined;
  if (source.auth !== undefined) {
    const authSource = record(source.auth, "auth");
    const scopeNames = stringMap(authSource.scopes ?? {}, "auth.scopes");
    for (const name of Object.keys(scopeNames)) {
      scopeToken(name, "auth.scopes name");
    }
    const hintsSource = record(authSource.scope_hints ?? {}, "auth.scope_hints");
    const scopeHints = Object.fromEntries(
      Object.entries(hintsSource).map(([name, item]) => {
        scopeToken(name, "auth.scope_hints name");
        const hint = record(item, `auth.scope_hints.${name}`);
        return [
          name,
          {
            ...hint,
            changes: string(hint.changes, `auth.scope_hints.${name}.changes`),
            personal_data: boolean(hint.personal_data, `auth.scope_hints.${name}.personal_data`),
          } as ScopeHint,
        ];
      }),
    );
    auth = {
      ...authSource,
      // Kept exactly as written: the issuer is compared character for character (§3.2).
      ...(authSource.issuer === undefined || authSource.issuer === null
        ? {}
        : { issuer: httpsUrl(authSource.issuer, "auth.issuer") }),
      ...(authSource.disabled === undefined || authSource.disabled === null
        ? {}
        : { disabled: boolean(authSource.disabled, "auth.disabled") }),
      scopes: scopeNames,
      scope_hints: scopeHints,
    } as AuthCapabilities;
  }

  const apis = array(source.apis ?? [], "apis").map((item, index) => {
    const api = record(item, `apis[${index}]`);
    return {
      ...api,
      type: string(api.type, `apis[${index}].type`),
      url: httpsUrl(api.url, `apis[${index}].url`),
      description: string(api.description, `apis[${index}].description`),
    } as ApiDescriptor;
  });

  let agent: AgentDescriptor | undefined;
  if (source.agent !== undefined) {
    const agentSource = record(source.agent, "agent");
    const protocols = array(agentSource.protocols, "agent.protocols").map((item, index) => {
      const protocol = record(item, `agent.protocols[${index}]`);
      if (protocol.access !== undefined && typeof protocol.access !== "string") {
        throw new ProtocolValidationError("invalid_type", `agent.protocols[${index}].access must be a string`);
      }
      return {
        ...protocol,
        type: string(protocol.type, `agent.protocols[${index}].type`),
        endpoint: httpsUrl(protocol.endpoint, `agent.protocols[${index}].endpoint`),
      } as AgentProtocol;
    });
    if (protocols.length === 0) {
      throw new ProtocolValidationError(
        "invalid_agent",
        "agent.protocols must not be empty",
      );
    }
    agent = { ...agentSource, protocols } as AgentDescriptor;
  }

  let web: WebDescriptor | undefined;
  if (source.web !== undefined) {
    const webSource = record(source.web, "web");
    const disabled = webSource.disabled === undefined ? false : boolean(webSource.disabled, "web.disabled");
    const unscoped = webSource.unscoped === undefined ? false : boolean(webSource.unscoped, "web.unscoped");
    web = {
      ...webSource,
      ...(webSource.browser_session_endpoint === undefined
        ? {}
        : {
            browser_session_endpoint: httpsUrl(
              webSource.browser_session_endpoint,
              "web.browser_session_endpoint",
            ),
          }),
      disabled,
      unscoped,
    };
    if (disabled && web.browser_session_endpoint !== undefined) {
      // A Company that asks agents not to browse lists no join endpoint (§6).
      throw new ProtocolValidationError("invalid_web", "web.disabled lists no browser_session_endpoint");
    }
    if (unscoped && web.browser_session_endpoint === undefined) {
      // The scope's meaning is said for a website agents can sign in to (§6).
      throw new ProtocolValidationError("invalid_web", "web.unscoped needs a browser_session_endpoint");
    }
  }

  let tasks: TasksDescriptor | undefined;
  if (source.tasks !== undefined && source.tasks !== null) {
    const tasksSource = record(source.tasks, "tasks");
    tasks = { ...tasksSource, endpoint: httpsUrl(tasksSource.endpoint, "tasks.endpoint") };
  }

  if (!agent && apis.length === 0 && !web) {
    // At least one of the three, not exactly one (§3.1).
    throw new ProtocolValidationError(
      "missing_interface",
      "at least one of agent, apis, or web is required",
    );
  }
  if (web?.disabled && agent === undefined && !apis.length) {
    // Asking agents not to browse means offering them the Company Agent or APIs (§6).
    throw new ProtocolValidationError("invalid_web", "web.disabled needs agent or apis");
  }
  const parsedExtensions = extensions(source.extensions, "extensions");

  return {
    ...source,
    protocol_version: version,
    supported_versions: supportedVersions,
    organization,
    ...(auth ? { auth } : {}),
    ...(agent ? { agent } : {}),
    ...(web ? { web } : {}),
    apis,
    ...(tasks ? { tasks } : {}),
    extensions: parsedExtensions,
  } as DiscoveryDocument;
}

/** A `dpop_signing_alg_values_supported` list: whichever a Company lists (§4.5). */
export function dpopAlgorithms(value: unknown, label: string): readonly string[] | undefined {
  if (value === undefined || value === null) return undefined;
  return array(value, label).map((item) => string(item, `${label} entry`));
}

/**
 * RFC 9728 protected resource metadata, with the fields this protocol uses (§3.2, §4.5).
 *
 * The Company's domain publishes it with `resource` exactly `https://{domain}` and its
 * issuer, if any, in `authorization_servers`; a service that accepts only tokens issued for it
 * publishes it with its own `resource`, as MCP servers do (§4.5, §7).
 */
export interface ProtectedResourceMetadata extends UnknownFields {
  readonly resource: string;
  /** Empty at the domain of a Company with no issuer (§3.2). */
  readonly authorization_servers: readonly string[];
  readonly scopes_supported: readonly string[];
  readonly bearer_methods_supported: readonly string[];
  /** At an MCP server it, not the issuer's list, says whether a token proves (§7). */
  readonly dpop_signing_alg_values_supported?: readonly string[];
}

export function parseProtectedResourceMetadata(value: unknown): ProtectedResourceMetadata {
  const source = record(value, "protected resource metadata");
  const servers = array(
    source.authorization_servers === undefined ? [] : source.authorization_servers,
    "authorization_servers",
  ).map((item) => httpsUrl(item, "authorization server"));
  const algorithms = dpopAlgorithms(source.dpop_signing_alg_values_supported, "dpop_signing_alg_values_supported");
  return {
    ...source,
    // Compared exactly as written: never normalized (§3.2, §4.5).
    resource: httpsUrl(source.resource, "resource"),
    authorization_servers: servers,
    scopes_supported: array(source.scopes_supported ?? [], "scopes_supported").map((item) =>
      string(item, "scopes_supported entry"),
    ),
    bearer_methods_supported: array(
      source.bearer_methods_supported ?? [],
      "bearer_methods_supported",
    ).map((item) => string(item, "bearer_methods_supported entry")),
    ...(algorithms === undefined ? {} : { dpop_signing_alg_values_supported: algorithms }),
  } as ProtectedResourceMetadata;
}

/**
 * Where a resource's RFC 9728 metadata is (RFC 9728 §3.1): the well-known path first.
 *
 * `https://example.com` has it at `https://example.com/.well-known/oauth-protected-resource`;
 * `https://example.com/mcp` at `https://example.com/.well-known/oauth-protected-resource/mcp`.
 */
export function protectedResourceMetadataUrl(url: string): string {
  const parsed = new URL(url);
  return `https://${parsed.host}/.well-known/oauth-protected-resource${parsed.pathname.replace(/\/+$/, "")}`;
}

export function parseOAuthServerMetadata(value: unknown): OAuthServerMetadata {
  const source = record(value, "OAuth metadata");
  const grants = array(source.grant_types_supported, "grant_types_supported").map((item) =>
    string(item, "grant_types_supported entry"),
  );
  if (!grants.includes(REFRESH_TOKEN_GRANT)) {
    throw new ProtocolValidationError(
      "invalid_oauth_metadata",
      "grant_types_supported must include refresh_token",
    );
  }
  const resources = array(source.protected_resources, "protected_resources").map((item) =>
    httpsUrl(item, "protected_resources entry"),
  );
  if (resources.length === 0) {
    throw new ProtocolValidationError(
      "invalid_oauth_metadata",
      "protected_resources must not be empty",
    );
  }
  const scopesSupported =
    source.scopes_supported === undefined || source.scopes_supported === null
      ? undefined
      : array(source.scopes_supported, "scopes_supported").map((item) =>
          scopeToken(item, "scopes_supported entry"),
        );
  const algorithms = dpopAlgorithms(source.dpop_signing_alg_values_supported, "dpop_signing_alg_values_supported");
  const endpoint = (name: string): Record<string, string> => {
    const item = source[name];
    return item === undefined || item === null ? {} : { [name]: httpsUrl(item, name) };
  };
  const metadata = {
    ...source,
    // Compared with `auth.issuer` character for character (§3.2): never normalized.
    issuer: httpsUrl(source.issuer, "issuer"),
    token_endpoint: httpsUrl(source.token_endpoint, "token_endpoint"),
    revocation_endpoint: httpsUrl(source.revocation_endpoint, "revocation_endpoint"),
    ...endpoint("authorization_endpoint"),
    ...endpoint("device_authorization_endpoint"),
    ...endpoint("pushed_authorization_request_endpoint"),
    grant_types_supported: grants,
    protected_resources: resources,
    ...(scopesSupported === undefined ? {} : { scopes_supported: scopesSupported }),
    ...(algorithms === undefined ? {} : { dpop_signing_alg_values_supported: algorithms }),
  } as OAuthServerMetadata;
  if (offersDirect(metadata) && metadata.authorization_endpoint === undefined) {
    throw new ProtocolValidationError(
      "invalid_oauth_metadata",
      "authorization_code needs authorization_endpoint",
    );
  }
  if (offersDevice(metadata) && metadata.device_authorization_endpoint === undefined) {
    throw new ProtocolValidationError(
      "invalid_oauth_metadata",
      "the device grant needs device_authorization_endpoint",
    );
  }
  return metadata;
}

export function parseClientMetadata(value: unknown): ClientMetadata {
  const source = record(value, "client metadata");
  const clientId = httpsUrl(source.client_id, "client_id");
  const clientDomain = new URL(clientId).hostname;
  const jwksUri = httpsUrl(source.jwks_uri, "jwks_uri");
  // An HTTPS URL, or a loopback redirect URI for an app on the User's computer (§4.1).
  const redirectUris = array(source.redirect_uris ?? [], "redirect_uris").map((item) =>
    typeof item === "string" && isLoopbackRedirect(item) ? item : httpsUrl(item, "redirect URI"),
  );
  if (
    new URL(jwksUri).hostname !== clientDomain ||
    redirectUris.some((uri) => !isLoopbackRedirect(uri) && new URL(uri).hostname !== clientDomain)
  ) {
    throw new ProtocolValidationError(
      "client_domain_mismatch",
      "jwks_uri and HTTPS redirect_uris must use the client_id domain",
    );
  }
  const authMethod = source.token_endpoint_auth_method ?? "private_key_jwt";
  if (authMethod !== "private_key_jwt") {
    throw new ProtocolValidationError(
      "invalid_client_auth_method",
      "token_endpoint_auth_method must be private_key_jwt",
    );
  }
  return {
    ...source,
    client_id: clientId,
    client_name: string(source.client_name, "client_name"),
    ...(source.logo_uri === undefined
      ? {}
      : { logo_uri: httpsUrl(source.logo_uri, "logo_uri") }),
    jwks_uri: jwksUri,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: authMethod,
  } as ClientMetadata;
}

const privateJwkMembers = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);

function parseJsonWebKey(value: unknown): JsonWebKey {
  const source = record(value, "JWKS key");
  if (Object.keys(source).some((key) => privateJwkMembers.has(key))) {
    throw new ProtocolValidationError(
      "private_jwk",
      "JWKS keys must not contain private or symmetric key material",
    );
  }
  const kty = oneOf(source.kty, ["EC", "RSA"] as const, "JWKS key kty");
  const kid = source.kid === undefined ? undefined : string(source.kid, "JWKS key kid");
  const use =
    source.use === undefined ? undefined : oneOf(source.use, ["sig"] as const, "use");
  const alg =
    source.alg === undefined
      ? undefined
      : oneOf(source.alg, ["ES256", "PS384"] as const, "alg");

  if (kty === "EC") {
    const crv = oneOf(source.crv, ["P-256"] as const, "EC key crv");
    const x = string(source.x, "EC key x");
    const y = string(source.y, "EC key y");
    if (alg !== undefined && alg !== "ES256") {
      throw new ProtocolValidationError(
        "invalid_jwk_algorithm",
        "P-256 signing keys may advertise only ES256",
      );
    }
    return {
      ...source,
      kty,
      ...(kid === undefined ? {} : { kid }),
      ...(use === undefined ? {} : { use }),
      ...(alg === undefined ? {} : { alg }),
      crv,
      x,
      y,
    } as JsonWebKey;
  }

  const n = string(source.n, "RSA key n");
  const e = string(source.e, "RSA key e");
  if (alg !== undefined && alg !== "PS384") {
    throw new ProtocolValidationError(
      "invalid_jwk_algorithm",
      "RSA signing keys may advertise only PS384",
    );
  }
  return {
    ...source,
    kty,
    ...(kid === undefined ? {} : { kid }),
    ...(use === undefined ? {} : { use }),
    ...(alg === undefined ? {} : { alg }),
    n,
    e,
  } as JsonWebKey;
}

export function parseJsonWebKeySet(value: unknown): JsonWebKeySet {
  const source = record(value, "JWKS");
  const keys = array(source.keys, "JWKS keys").map(parseJsonWebKey);
  if (keys.length === 0) {
    throw new ProtocolValidationError("invalid_jwks", "JWKS keys must not be empty");
  }
  return { ...source, keys } as JsonWebKeySet;
}

export function parseOperation(value: unknown): Operation {
  const source = nullsAbsent(value, "operation", ["summary"]);
  return {
    ...source,
    operation_id: identifier(source.operation_id, "operation.operation_id"),
    revision: identifier(source.revision, "operation.revision"),
    ...(source.summary === undefined ? {} : { summary: string(source.summary, "operation.summary") }),
    terms: record(source.terms, "operation.terms"),
    expires_at: timestamp(source.expires_at, "operation.expires_at"),
  } as Operation;
}

export function parseApprovalDeclined(value: unknown): ApprovalDeclined {
  const source = nullsAbsent(value, "declined", ["reason", "alternative"]);
  return {
    ...source,
    operation_id: identifier(source.operation_id, "declined.operation_id"),
    revision: identifier(source.revision, "declined.revision"),
    ...(source.reason === undefined ? {} : { reason: string(source.reason, "declined.reason") }),
    ...(source.alternative === undefined ? {} : { alternative: parseAlternative(source.alternative) }),
  } as ApprovalDeclined;
}

export function parseOperationsContent(value: unknown): OperationsContent {
  const source = nullsAbsent(value, "extensions.operations", ["operation", "approval", "declined"]);
  const operation = source.operation === undefined ? undefined : parseOperation(source.operation);
  const approval = source.approval === undefined ? undefined : parseApproval(source.approval);
  const declined = source.declined === undefined ? undefined : parseApprovalDeclined(source.declined);
  if ([operation, approval, declined].filter((item) => item !== undefined).length !== 1) {
    throw new ProtocolValidationError(
      "invalid_message",
      "extensions.operations carries an operation, an approval or a decline",
    );
  }
  return {
    ...source,
    ...(operation === undefined ? {} : { operation }),
    ...(approval === undefined ? {} : { approval }),
    ...(declined === undefined ? {} : { declined }),
  } as OperationsContent;
}

export function parseLinksContent(value: unknown): LinksContent {
  const source = record(value, "extensions.links");
  const items = array(source.items, "extensions.links.items").map((item, index) => {
    const link = nullsAbsent(item, `extensions.links.items[${index}]`, ["title"]);
    return {
      ...link,
      url: httpsUrl(link.url, `extensions.links.items[${index}].url`),
      ...(link.title === undefined
        ? {}
        : { title: string(link.title, `extensions.links.items[${index}].title`) }),
    } as Link;
  });
  return { ...source, items } as LinksContent;
}

export function parseDisclosuresContent(value: unknown): DisclosuresContent {
  const source = record(value, "extensions.disclosures");
  const items = array(source.items, "extensions.disclosures.items").map((item, index) => {
    const disclosure = record(item, `extensions.disclosures.items[${index}]`);
    return {
      ...disclosure,
      text: string(disclosure.text, `extensions.disclosures.items[${index}].text`),
    } as Disclosure;
  });
  return { ...source, items } as DisclosuresContent;
}

/** The extensions that define message content (§8.4), each with its parser. */
const MESSAGE_CONTENT_PARSERS: Readonly<Record<string, (value: unknown) => unknown>> = {
  [OPERATIONS_CONTENT]: parseOperationsContent,
  [LINKS_EXTENSION]: parseLinksContent,
  [DISCLOSURES_EXTENSION]: parseDisclosuresContent,
};

/** Each extension's content is an object; the ones this SDK defines, in their shape. */
function messageExtensions(value: unknown): MessageExtensions {
  const source = record(value, "message.extensions");
  for (const [name, content] of Object.entries(source)) {
    record(content, `message.extensions.${name}`);
    MESSAGE_CONTENT_PARSERS[name]?.(content);
  }
  return source as MessageExtensions;
}

export function parseApproval(value: unknown): Approval {
  const source = record(value, "approval");
  const approver = oneOf(source.approver, APPROVERS, "approval.approver");
  const approvedAt = source.approved_at;
  const inputType = source.input_type;
  const reference = source.reference;
  return {
    operation_id: identifier(source.operation_id, "approval.operation_id"),
    revision: identifier(source.revision, "approval.revision"),
    approver,
    ...(typeof approvedAt === "number" && Number.isSafeInteger(approvedAt) && approvedAt >= 0 ? { approved_at: approvedAt } : {}),
    // Never sent with `agent`, and ignored by a Company that receives it (Operations 6).
    ...(approver === "user" && typeof inputType === "string" && /^[\x20-\x7e]{1,64}$/.test(inputType)
      ? { input_type: inputType }
      : {}),
    ...(typeof reference === "string" && /^[A-Za-z0-9_-]{1,256}$/.test(reference) ? { reference } : {}),
  };
}

/** `extensions["mediated-sign-in"]`, version 1: its fields, none a reserved name, and scopes. */
export function parseMediatedSignIn(value: unknown): MediatedSignIn {
  const source = record(value, "mediated-sign-in");
  if (source.version !== "1") {
    throw new ProtocolValidationError("invalid_mediated_sign_in", "Mediated Sign-In is version 1");
  }
  const fields = array(source.fields, "mediated-sign-in.fields").map((item, index) => {
    const field = record(item, `mediated-sign-in.fields[${index}]`);
    return {
      ...field,
      name: string(field.name, `mediated-sign-in.fields[${index}].name`),
      label: string(field.label, `mediated-sign-in.fields[${index}].label`),
      secret: boolean(field.secret, `mediated-sign-in.fields[${index}].secret`),
    } as MediatedField;
  });
  if (fields.length === 0) {
    throw new ProtocolValidationError("invalid_mediated_sign_in", "fields must not be empty");
  }
  if (fields.some((field) => MEDIATED_RESERVED_FIELDS.has(field.name))) {
    throw new ProtocolValidationError(
      "invalid_mediated_sign_in",
      "a Mediated Sign-In field can't use a reserved parameter name",
    );
  }
  const scopeNames = array(source.scopes, "mediated-sign-in.scopes").map((item) =>
    scopeToken(item, "mediated-sign-in.scopes entry"),
  );
  if (scopeNames.length === 0) {
    throw new ProtocolValidationError("invalid_mediated_sign_in", "scopes must not be empty");
  }
  return { ...source, version: "1", fields, scopes: scopeNames } as MediatedSignIn;
}

const LOCALE = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{1,8})*$/;

function ianaZone(value: unknown): boolean {
  if (typeof value !== "string" || !value || value.length > 64 || value.includes("..")) return false;
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value });
    return true;
  } catch {
    return false;
  }
}

/** The facts §7.4 defines use its field names and formats; others pass through. */
function messageContext(
  context: Readonly<Record<string, unknown>> | undefined,
): Readonly<Record<string, unknown>> | undefined {
  if (context === undefined) return context;
  const { locale, time_zone: zone, user_available: available } = context;
  if (locale !== undefined && (typeof locale !== "string" || !LOCALE.test(locale))) {
    throw new ProtocolValidationError("invalid_message", "context.locale must be a language tag such as en-US");
  }
  if (zone !== undefined && !ianaZone(zone)) {
    throw new ProtocolValidationError("invalid_message", "context.time_zone must be an IANA time zone name");
  }
  if (available !== undefined && typeof available !== "boolean") {
    throw new ProtocolValidationError("invalid_message", "context.user_available must be true or false");
  }
  return context;
}

/** Who wrote a message (§7.4): `type`, and the Company's optional `id`, `name`, `image`. */
export function parseAuthor(value: unknown): Author {
  const source = nullsAbsent(value, "message.author", ["id", "name", "image"]);
  return {
    ...source,
    type: oneOf(source.type, ["agent", "human"] as const, "message.author.type"),
    ...(source.id === undefined ? {} : { id: identifier(source.id, "message.author.id") }),
    ...(source.name === undefined ? {} : { name: string(source.name, "message.author.name") }),
    ...(source.image === undefined
      ? {}
      : { image: httpsUrl(source.image, "message.author.image") }),
  } as Author;
}

export function parseMessage(value: unknown): Message {
  const source = nullsAbsent(value, "message", ["role", "as_of_request", "as_of_cursor", "text", "data", "context", "extensions"]);
  const text = source.text === undefined ? undefined : string(source.text, "message.text");
  const data = optionalRecord(source.data, "message.data");
  const context = messageContext(optionalRecord(source.context, "message.context"));
  const extensions =
    source.extensions === undefined ? undefined : messageExtensions(source.extensions);
  if (text === undefined && data === undefined && context === undefined && extensions === undefined) {
    throw new ProtocolValidationError(
      "invalid_message",
      "a message requires text, data, context, or extensions",
    );
  }
  const author = parseAuthor(source.author);
  const role = source.role === undefined ? undefined : oneOf(source.role, ["user", "company"] as const, "message.role");
  const asOfRequest = source.as_of_request === undefined ? undefined : identifier(source.as_of_request, "message.as_of_request");
  const asOfCursor = source.as_of_cursor === undefined ? undefined : identifier(source.as_of_cursor, "message.as_of_cursor");
  // Only messages written by an AI say what they took into account (§8.4): a person types
  // while messages arrive. `as_of_request` is the Company Agent's, `as_of_cursor` the
  // Personal Agent's.
  if (author.type === "human" && (asOfRequest !== undefined || asOfCursor !== undefined)) {
    throw new ProtocolValidationError("invalid_message", "a person's message carries neither as_of_request nor as_of_cursor");
  }
  if (role === "user" && asOfRequest !== undefined) {
    throw new ProtocolValidationError("invalid_message", "as_of_request is the Company Agent's");
  }
  if (role === "company" && asOfCursor !== undefined) {
    throw new ProtocolValidationError("invalid_message", "as_of_cursor is the Personal Agent's");
  }
  return {
    ...source,
    ...(source.id === undefined ? {} : { id: identifier(source.id, "message.id") }),
    author,
    ...(role === undefined ? {} : { role }),
    ...(asOfRequest === undefined ? {} : { as_of_request: asOfRequest }),
    ...(asOfCursor === undefined ? {} : { as_of_cursor: asOfCursor }),
    ...(text === undefined ? {} : { text }),
    ...(data === undefined ? {} : { data }),
    ...(context === undefined ? {} : { context }),
    ...(extensions === undefined ? {} : { extensions }),
  } as Message;
}

export function parseConversationEvent(value: unknown): ConversationEvent {
  const source = nullsAbsent(value, "conversation event", [
    "message",
    "status",
    "responder",
    "error",
    "scope",
    "reason",
    "conversation_id",
  ]);
  const type = string(source.type, "conversation event.type");
  const parsed: ConversationEvent = {
    ...source,
    id: identifier(source.id, "conversation event.id"),
    type,
    created_at: timestamp(source.created_at, "conversation event.created_at"),
    ...(source.message === undefined ? {} : { message: parseMessage(source.message) }),
    ...(source.handoff === undefined
      ? {}
      : {
          handoff: knownHandoff(source.handoff, "conversation event.handoff"),
        }),
    ...(source.responder === undefined
      ? {}
      : {
          responder: knownResponder(source.responder, "conversation event.responder"),
        }),
    ...(source.closed === undefined ? {} : { closed: boolean(source.closed, "conversation event.closed") }),
    ...(source.error === undefined
      ? {}
      : {
          error: oneOf(
            source.error,
            ["insufficient_scope"] as const,
            "conversation event.error",
          ),
        }),
    ...(source.scope === undefined ? {} : { scope: string(source.scope, "conversation event.scope") }),
    ...(source.reason === undefined
      ? {}
      : { reason: string(source.reason, "conversation event.reason") }),
    ...(source.conversation_id === undefined
      ? {}
      : {
          conversation_id: identifier(
            source.conversation_id,
            "conversation event.conversation_id",
          ),
        }),
  } as ConversationEvent;
  if (type === "message" && parsed.message === undefined) {
    throw new ProtocolValidationError("invalid_event", "a message event requires message");
  }
  if (
    type === "state" &&
    (parsed.handoff === undefined || parsed.responder === undefined || parsed.closed === undefined)
  ) {
    throw new ProtocolValidationError("invalid_event", "a state event requires handoff, responder and closed");
  }
  // Always both: the error, and the scopes the request needs (§7.11).
  if (type === "authorization" && (parsed.error === undefined || !parsed.scope)) {
    throw new ProtocolValidationError(
      "invalid_event",
      "an authorization event requires error and scope",
    );
  }
  if (type === "user_requested" && parsed.reason === undefined) {
    throw new ProtocolValidationError(
      "invalid_event",
      "a user_requested event requires reason",
    );
  }
  if (
    (type === "direct_opened" || type === "direct_closed") &&
    parsed.conversation_id === undefined
  ) {
    throw new ProtocolValidationError(
      "invalid_event",
      "a direct conversation event requires conversation_id",
    );
  }
  return parsed;
}

export function parseConversationEventPage(value: unknown): ConversationEventPage {
  const source = record(value, "conversation event page");
  return {
    ...source,
    conversation_id: identifier(source.conversation_id, "conversation_id"),
    events: array(source.events, "events").map(parseConversationEvent),
    cursor: identifier(source.cursor, "cursor"),
    has_more: boolean(source.has_more, "has_more"),
    ...stateFields(source, "conversation event page"),
  } as ConversationEventPage;
}

/** The four state fields of a response, read as §8.7 says (`parseConversationEventPage` uses it). */
export function parseConversationState(value: unknown, label = "conversation state"): ConversationState {
  return stateFields(record(value, label), label);
}

/** Where an alternative points (§8.2): an OpenAPI operation, an MCP tool, or a page. */
export interface AlternativeReference extends UnknownFields {
  readonly type: string;
  readonly url?: string;
  readonly operation_id?: string;
  readonly tool?: string;
}

/**
 * Another way to do a task (§8.2): `instructions`, `references`, or both.
 *
 * Content from the company (§9.1): a description of its interfaces, never instructions
 * the agent has to follow.
 */
export interface Alternative extends UnknownFields {
  readonly instructions?: string;
  readonly references: readonly AlternativeReference[];
}

/** A task the company chose not to offer through the protocol (§8.1). */
export interface ExcludedTask extends UnknownFields {
  readonly task: string;
  readonly alternative?: Alternative;
}

/**
 * The response to `GET {tasks.endpoint}` for one Session (§9).
 *
 * What the Company offers that Session, not the User's account: the tasks it chose not to
 * offer (none by default), the skills it publishes, and where to send feedback. It is used in
 * the Session it was fetched in and never in another.
 */
export interface TasksResponse extends UnknownFields {
  readonly excluded_tasks: readonly ExcludedTask[];
  /**
   * The Company's Agent Skills discovery index, as published (§9.4); read it through
   * `usableSkills`, which skips what this SDK does not recognize.
   */
  readonly skill_index?: Readonly<Record<string, unknown>>;
  readonly feedback?: FeedbackDescriptor;
}

const REFERENCE_FIELDS: Readonly<Record<string, readonly ("url" | "operation_id" | "tool")[]>> = {
  openapi: ["url", "operation_id"],
  mcp: ["url", "tool"],
  web: ["url"],
};

export function parseAlternativeReference(value: unknown): AlternativeReference {
  const source = nullsAbsent(value, "reference", ["url", "operation_id", "tool"]);
  const reference = {
    ...source,
    type: string(source.type, "reference.type"),
    ...(source.url === undefined ? {} : { url: httpsUrl(source.url, "reference.url") }),
    ...(source.operation_id === undefined
      ? {}
      : { operation_id: string(source.operation_id, "reference.operation_id") }),
    ...(source.tool === undefined ? {} : { tool: string(source.tool, "reference.tool") }),
  } as AlternativeReference;
  for (const name of REFERENCE_FIELDS[reference.type] ?? []) {
    if (reference[name] === undefined) {
      throw new ProtocolValidationError(
        "invalid_alternative",
        `a ${reference.type} reference lacks a required field`,
      );
    }
  }
  return reference;
}

export function parseAlternative(value: unknown): Alternative {
  const source = nullsAbsent(value, "alternative", ["instructions"]);
  let instructions: string | undefined;
  if (source.instructions !== undefined) {
    instructions = string(source.instructions, "alternative.instructions");
  }
  const references = array(source.references ?? [], "alternative.references").map(
    parseAlternativeReference,
  );
  if (instructions === undefined && references.length === 0) {
    throw new ProtocolValidationError(
      "invalid_alternative",
      "an alternative needs instructions or references",
    );
  }
  return {
    ...source,
    ...(instructions === undefined ? {} : { instructions }),
    references,
  } as Alternative;
}

/**
 * The references an agent may follow (§8.2).
 *
 * Types it knows only, and an `openapi` or `mcp` reference only when its `url` is an API
 * of that type the company's poppy.json lists: never another company's server.
 */
export function usableReferences(
  alternative: Alternative,
  document: DiscoveryDocument,
): readonly AlternativeReference[] {
  return alternative.references.filter(
    (reference) =>
      reference.type === "web" ||
      ((reference.type === "openapi" || reference.type === "mcp") &&
        document.apis.some((api) => api.type === reference.type && api.url === reference.url)),
  );
}

export function parseTasksResponse(value: unknown): TasksResponse {
  const source = nullsAbsent(value, "tasks response", ["excluded_tasks", "skill_index", "feedback"]);
  const tasks = array(source.excluded_tasks ?? [], "excluded_tasks").map((item, index) => {
    const task = nullsAbsent(item, `excluded_tasks[${index}]`, ["alternative"]);
    const name = string(task.task, `excluded_tasks[${index}].task`);
    if (name.length > 200) {
      throw new ProtocolValidationError(
        "invalid_excluded_task",
        `excluded_tasks[${index}].task must be at most 200 characters`,
      );
    }
    return {
      ...task,
      task: name,
      ...(task.alternative === undefined ? {} : { alternative: parseAlternative(task.alternative) }),
    } as ExcludedTask;
  });
  let feedback: FeedbackDescriptor | undefined;
  if (source.feedback !== undefined) {
    const feedbackSource = record(source.feedback, "feedback");
    feedback = { ...feedbackSource, endpoint: httpsUrl(feedbackSource.endpoint, "feedback.endpoint") };
  }
  return {
    ...source,
    excluded_tasks: tasks,
    ...(source.skill_index === undefined ? {} : { skill_index: record(source.skill_index, "skill_index") }),
    ...(feedback === undefined ? {} : { feedback }),
  } as TasksResponse;
}
