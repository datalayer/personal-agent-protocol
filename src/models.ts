/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { AuthorizationError, ProtocolValidationError } from "./errors.js";

export type UnknownFields = Readonly<Record<string, unknown>>;

/**
 * The `protocol_version` values this SDK uses a document of (§3.1): before 1.0 every
 * version can break the one before, so only its own `major.minor`.
 */
export const SUPPORTED_PROTOCOL_VERSIONS: ReadonlySet<string> = new Set(["0.3"]);
/** OAuth scope syntax (RFC 6749 §3.3): one scope token. */
const SCOPE = /^[\x21\x23-\x5B\x5D-\x7E]+$/;
/** The grant a Company's token endpoint MUST accept (§3.2). */
export const REFRESH_TOKEN_GRANT = "refresh_token";
/** The grants that say the Company offers Direct and Device Sign-In (§3.2, §4.4). */
export const AUTHORIZATION_CODE_GRANT = "authorization_code";
export const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
/** The sign-in extension, listed in `extensions` (Mediated Sign-In 2). */
export const MEDIATED_EXTENSION = "mediated-sign-in";
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

export interface Organization extends UnknownFields {
  readonly name: string;
  readonly domain: string;
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

export interface WebDescriptor extends UnknownFields {
  readonly browser_session_endpoint?: string;
}

export interface ExtensionDescriptor extends UnknownFields {
  readonly version: string;
}

/** Where personal agents report a task the protocol can't do at this company (§8). */
export interface FeedbackDescriptor extends UnknownFields {
  readonly endpoint: string;
}

/** Where the tasks the Company chose not to offer through the protocol are listed (§8.1). */
export interface ExcludedTasksDescriptor extends UnknownFields {
  readonly url: string;
}

export interface DiscoveryDocument extends UnknownFields {
  readonly protocol_version: string;
  readonly organization: Organization;
  readonly auth?: AuthCapabilities;
  readonly agent?: AgentDescriptor;
  readonly web?: WebDescriptor;
  readonly apis: readonly ApiDescriptor[];
  readonly feedback?: FeedbackDescriptor;
  readonly excluded_tasks?: ExcludedTasksDescriptor;
  readonly extensions: Readonly<Record<string, ExtensionDescriptor>>;
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
  readonly extensions: Readonly<Record<string, ExtensionDescriptor>>;
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
 * One action the Company performs once the User approves it (Operations 3).
 *
 * `revision` is opaque: it identifies these terms, and the Company changes it whenever the
 * `summary`, `terms`, or `expires_at` change.
 */
export interface Operation extends UnknownFields {
  readonly operation_id: string;
  readonly revision: string;
  readonly summary: string;
  readonly terms?: Readonly<Record<string, unknown>>;
  readonly expires_at: string;
}

/** A statement that the User approved this revision of an operation (Operations 5, 6). */
export interface Approval {
  readonly operation_id: string;
  readonly revision: string;
}

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

export interface Message extends UnknownFields {
  readonly id: string;
  readonly author: Author;
  readonly role?: "user" | "company";
  readonly text?: string;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly context?: Readonly<Record<string, unknown>>;
  /** A Company message's operation, for the User's approval (Operations 4). */
  readonly operation?: Operation;
  /** A Personal Agent message's approval: only this approves, never `text` (Operations 6). */
  readonly approval?: Approval;
}

export type ConversationStatus = "working" | "idle" | "queued" | "closed";
export type ConversationResponder = "agent" | "human";

const CONVERSATION_STATUSES = ["working", "idle", "queued", "closed"] as const;

/** A `status` this SDK doesn't recognize reads as `working` (§8.7). */
export function knownStatus(value: unknown, label = "status"): ConversationStatus {
  if (typeof value !== "string") {
    throw new ProtocolValidationError("invalid_value", `${label} must be a string`);
  }
  return (CONVERSATION_STATUSES as readonly string[]).includes(value)
    ? (value as ConversationStatus)
    : "working";
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
  readonly status?: ConversationStatus;
  readonly responder?: ConversationResponder;
  readonly error?: "insufficient_scope";
  readonly scope?: string;
  readonly reason?: string;
  readonly conversation_id?: string;
}

export interface ConversationEventPage extends UnknownFields {
  readonly conversation_id: string;
  readonly events: readonly ConversationEvent[];
  readonly cursor: string;
  readonly has_more: boolean;
  readonly status: ConversationStatus;
  readonly responder: ConversationResponder;
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

/** The Company's OAuth issuer, as found from its domain (§3.2). */
export function companyIssuer(company: DiscoveredCompany): string | undefined {
  return company.oauthMetadata?.issuer;
}

/** `https://{organization.domain}`: the resource the default access token is for. */
export function companyResource(company: DiscoveredCompany): string {
  return `https://${company.document.organization.domain}`;
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
export function requireOauth(company: DiscoveredCompany): OAuthServerMetadata {
  if (company.oauthMetadata === undefined) {
    throw new AuthorizationError("no_issuer", "A Company with no issuer offers no sign-in");
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
): Readonly<Record<string, ExtensionDescriptor>> {
  const source = record(value ?? {}, label);
  return Object.fromEntries(
    Object.entries(source).map(([name, item]) => {
      const extension = record(item, `${label}.${name}`);
      const version = string(extension.version, `${label}.${name}.version`);
      if (!/^(0|[1-9][0-9]*)$/.test(version)) {
        throw new ProtocolValidationError(
          "invalid_extension_version",
          `${label}.${name}.version must be a major version`,
        );
      }
      return [name, { ...extension, version } as ExtensionDescriptor];
    }),
  );
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

export function parseDiscoveryDocument(value: unknown): DiscoveryDocument {
  const source = record(value, "poppy.json");
  const version = string(source.protocol_version, "protocol_version");
  if (!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)) {
    throw new ProtocolValidationError("unsupported_protocol_version", "protocol_version must use major.minor");
  }
  if (!SUPPORTED_PROTOCOL_VERSIONS.has(version)) {
    // Before 1.0 a document is used only at a major.minor this SDK supports (§3.1).
    throw new ProtocolValidationError(
      "unsupported_protocol_version",
      "protocol_version must be a supported major.minor version",
    );
  }

  const organizationSource = record(source.organization, "organization");
  const organization: Organization = {
    ...organizationSource,
    name: string(organizationSource.name, "organization.name"),
    domain: domain(organizationSource.domain, "organization.domain"),
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
    };
  }

  let feedback: FeedbackDescriptor | undefined;
  if (source.feedback !== undefined) {
    const feedbackSource = record(source.feedback, "feedback");
    feedback = { ...feedbackSource, endpoint: httpsUrl(feedbackSource.endpoint, "feedback.endpoint") };
  }

  let excludedTasks: ExcludedTasksDescriptor | undefined;
  if (source.excluded_tasks !== undefined) {
    const excludedSource = record(source.excluded_tasks, "excluded_tasks");
    excludedTasks = {
      ...excludedSource,
      url: httpsUrl(excludedSource.url, "excluded_tasks.url"),
    };
  }

  if (!agent && apis.length === 0 && !web) {
    throw new ProtocolValidationError(
      "missing_interface",
      "one of agent, apis, or web is required",
    );
  }
  const parsedExtensions = extensions(source.extensions, "extensions");

  return {
    ...source,
    protocol_version: version,
    organization,
    ...(auth ? { auth } : {}),
    ...(agent ? { agent } : {}),
    ...(web ? { web } : {}),
    apis,
    ...(feedback ? { feedback } : {}),
    ...(excludedTasks ? { excluded_tasks: excludedTasks } : {}),
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
    extensions: extensions(source.extensions, "extensions"),
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
  const source = nullsAbsent(value, "operation", ["terms"]);
  return {
    ...source,
    operation_id: identifier(source.operation_id, "operation.operation_id"),
    revision: identifier(source.revision, "operation.revision"),
    summary: string(source.summary, "operation.summary"),
    ...(source.terms === undefined ? {} : { terms: record(source.terms, "operation.terms") }),
    expires_at: timestamp(source.expires_at, "operation.expires_at"),
  } as Operation;
}

export function parseApproval(value: unknown): Approval {
  const source = record(value, "approval");
  return {
    operation_id: identifier(source.operation_id, "approval.operation_id"),
    revision: identifier(source.revision, "approval.revision"),
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
  const source = nullsAbsent(value, "message", [
    "role",
    "text",
    "data",
    "context",
    "operation",
    "approval",
  ]);
  const text = source.text === undefined ? undefined : string(source.text, "message.text");
  const data = optionalRecord(source.data, "message.data");
  const context = messageContext(optionalRecord(source.context, "message.context"));
  const operation =
    source.operation === undefined ? undefined : parseOperation(source.operation);
  const approval = source.approval === undefined ? undefined : parseApproval(source.approval);
  if (
    text === undefined &&
    data === undefined &&
    context === undefined &&
    operation === undefined &&
    approval === undefined
  ) {
    throw new ProtocolValidationError(
      "invalid_message",
      "a message requires text, data, context, operation, or approval",
    );
  }
  return {
    ...source,
    id: identifier(source.id, "message.id"),
    author: parseAuthor(source.author),
    ...(source.role === undefined
      ? {}
      : { role: oneOf(source.role, ["user", "company"] as const, "message.role") }),
    ...(text === undefined ? {} : { text }),
    ...(data === undefined ? {} : { data }),
    ...(context === undefined ? {} : { context }),
    ...(operation === undefined ? {} : { operation }),
    ...(approval === undefined ? {} : { approval }),
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
    ...(source.status === undefined
      ? {}
      : {
          status: knownStatus(source.status, "conversation event.status"),
        }),
    ...(source.responder === undefined
      ? {}
      : {
          responder: knownResponder(source.responder, "conversation event.responder"),
        }),
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
  if (type === "state" && (parsed.status === undefined || parsed.responder === undefined)) {
    throw new ProtocolValidationError(
      "invalid_event",
      "a state event requires status and responder",
    );
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
    status: knownStatus(source.status),
    responder: knownResponder(source.responder),
  } as ConversationEventPage;
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

/** The document at `excluded_tasks.url` (§8.1): the same for every user. */
export interface ExcludedTasks extends UnknownFields {
  readonly tasks: readonly ExcludedTask[];
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

export function parseExcludedTasks(value: unknown): ExcludedTasks {
  const source = record(value, "excluded tasks");
  const tasks = array(source.tasks, "excluded tasks.tasks").map((item, index) => {
    const task = nullsAbsent(item, `tasks[${index}]`, ["alternative"]);
    const name = string(task.task, `tasks[${index}].task`);
    if (name.length > 200) {
      throw new ProtocolValidationError(
        "invalid_excluded_task",
        `tasks[${index}].task must be at most 200 characters`,
      );
    }
    return {
      ...task,
      task: name,
      ...(task.alternative === undefined ? {} : { alternative: parseAlternative(task.alternative) }),
    } as ExcludedTask;
  });
  return { ...source, tasks } as ExcludedTasks;
}
