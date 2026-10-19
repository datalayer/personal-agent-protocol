/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { ProtocolValidationError } from "./errors.js";

export type UnknownFields = Readonly<Record<string, unknown>>;

/**
 * The `protocol_version` values this SDK uses a document of (§3.1): before 1.0 every
 * version can break the one before, so only its own `major.minor`.
 */
export const SUPPORTED_PROTOCOL_VERSIONS: ReadonlySet<string> = new Set(["0.2"]);
/** The DPoP algorithm every company accepts (§3.2): a list a company publishes includes it. */
export const DPOP_REQUIRED_ALGORITHM = "ES256";

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

export interface MediatedSignIn extends ScopeOption {
  readonly endpoint: string;
  readonly fields: readonly MediatedField[];
}

export interface AuthCapabilities extends UnknownFields {
  readonly issuer: string;
  readonly direct?: ScopeOption;
  readonly device?: ScopeOption;
  readonly mediated?: MediatedSignIn;
  readonly custom_scopes?: Readonly<Record<string, string>>;
}

export interface AgentProtocol extends UnknownFields {
  readonly type: string;
  readonly endpoint: string;
  readonly resource?: string;
}

export interface AgentDescriptor extends UnknownFields {
  readonly protocols: readonly AgentProtocol[];
}

export interface ApiDescriptor extends UnknownFields {
  readonly type: string;
  readonly url: string;
  readonly description: string;
  readonly resource?: string;
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

export interface DiscoveryDocument extends UnknownFields {
  readonly protocol_version: string;
  readonly organization: Organization;
  readonly auth?: AuthCapabilities;
  readonly agent?: AgentDescriptor;
  readonly web?: WebDescriptor;
  readonly apis: readonly ApiDescriptor[];
  readonly feedback?: FeedbackDescriptor;
  readonly extensions: Readonly<Record<string, ExtensionDescriptor>>;
}

export interface OAuthServerMetadata extends UnknownFields {
  readonly issuer: string;
  readonly token_endpoint: string;
  readonly revocation_endpoint: string;
  readonly authorization_endpoint?: string;
  readonly device_authorization_endpoint?: string;
  readonly poppy_domains: readonly string[];
  readonly dpop_signing_alg_values_supported?: readonly string[];
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
  readonly alg?: "ES256" | "RS256";
  readonly crv?: "P-256";
  readonly x?: string;
  readonly y?: string;
  readonly n?: string;
  readonly e?: string;
}

export interface JsonWebKeySet extends UnknownFields {
  readonly keys: readonly JsonWebKey[];
}

export type OperationState =
  | "proposed"
  | "in_progress"
  | "succeeded"
  | "failed"
  | "cancelled"
  | "expired";

export interface OperationResult extends UnknownFields {
  readonly summary: string;
  readonly data?: Readonly<Record<string, unknown>>;
}

export interface OperationConfirmation extends UnknownFields {
  readonly revision: number;
  readonly approved_by: "user" | "standing_permission";
  readonly confirmed_at: string;
}

export interface Operation extends UnknownFields {
  readonly operation_id: string;
  readonly revision: number;
  readonly state: OperationState;
  readonly summary: string;
  readonly terms?: Readonly<Record<string, unknown>>;
  readonly expires_at?: string;
  readonly user_approval_required: boolean;
  readonly url?: string;
  readonly confirmation: OperationConfirmation | null;
  readonly result: OperationResult | null;
}

export interface Message extends UnknownFields {
  readonly id: string;
  readonly sender: "agent" | "human";
  readonly role?: "user" | "company";
  readonly text?: string;
  readonly data?: Readonly<Record<string, unknown>>;
  readonly context?: Readonly<Record<string, unknown>>;
  readonly operation?: Operation;
}

export type ConversationStatus = "working" | "idle" | "queued" | "closed";
export type ConversationResponder = "agent" | "human";

export interface ConversationEvent extends UnknownFields {
  readonly id: string;
  readonly type: string;
  readonly created_at: string;
  readonly message?: Message;
  readonly status?: ConversationStatus;
  readonly responder?: ConversationResponder;
  readonly error?: "sign_in_required" | "insufficient_scope";
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

export interface DiscoveredCompany {
  readonly discoveryUrl: string;
  readonly document: DiscoveryDocument;
  readonly oauthMetadata?: OAuthServerMetadata;
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
    scopes: array(source.scopes ?? [], `${label}.scopes`).map((item) => string(item, "scope")),
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
    let mediated: MediatedSignIn | undefined;
    if (authSource.mediated !== undefined) {
      const mediatedSource = record(authSource.mediated, "auth.mediated");
      const fields = array(mediatedSource.fields, "auth.mediated.fields").map(
        (item, index) => {
          const field = record(item, `auth.mediated.fields[${index}]`);
          return {
            ...field,
            name: string(field.name, `auth.mediated.fields[${index}].name`),
            label: string(field.label, `auth.mediated.fields[${index}].label`),
            secret: boolean(field.secret, `auth.mediated.fields[${index}].secret`),
          } as MediatedField;
        },
      );
      if (fields.length === 0) {
        throw new ProtocolValidationError(
          "invalid_mediated_sign_in",
          "auth.mediated.fields must not be empty",
        );
      }
      mediated = {
        ...mediatedSource,
        ...scopes(mediatedSource, "auth.mediated"),
        endpoint: httpsUrl(mediatedSource.endpoint, "auth.mediated.endpoint"),
        fields,
      } as MediatedSignIn;
    }
    auth = {
      ...authSource,
      // Kept exactly as written: the issuer is compared character for character (§3.2).
      issuer: httpsUrl(authSource.issuer, "auth.issuer"),
      ...(authSource.direct === undefined
        ? {}
        : { direct: scopes(authSource.direct, "auth.direct") }),
      ...(authSource.device === undefined
        ? {}
        : { device: scopes(authSource.device, "auth.device") }),
      ...(mediated === undefined ? {} : { mediated }),
      ...(authSource.custom_scopes === undefined
        ? {}
        : {
            custom_scopes: stringMap(authSource.custom_scopes, "auth.custom_scopes"),
          }),
    } as AuthCapabilities;
  }

  const apis = array(source.apis ?? [], "apis").map((item, index) => {
    const api = record(item, `apis[${index}]`);
    return {
      ...api,
      type: string(api.type, `apis[${index}].type`),
      url: httpsUrl(api.url, `apis[${index}].url`),
      description: string(api.description, `apis[${index}].description`),
      ...(api.resource === undefined
        ? {}
        : { resource: httpsUrl(api.resource, `apis[${index}].resource`) }),
    } as ApiDescriptor;
  });

  let agent: AgentDescriptor | undefined;
  if (source.agent !== undefined) {
    const agentSource = record(source.agent, "agent");
    const protocols = array(agentSource.protocols, "agent.protocols").map((item, index) => {
      const protocol = record(item, `agent.protocols[${index}]`);
      return {
        ...protocol,
        type: string(protocol.type, `agent.protocols[${index}].type`),
        endpoint: httpsUrl(protocol.endpoint, `agent.protocols[${index}].endpoint`),
        ...(protocol.resource === undefined
          ? {}
          : {
              resource: httpsUrl(
                protocol.resource,
                `agent.protocols[${index}].resource`,
              ),
            }),
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

  if (!agent && apis.length === 0 && !web) {
    throw new ProtocolValidationError(
      "missing_interface",
      "one of agent, apis, or web is required",
    );
  }
  if ((agent || apis.length > 0 || feedback || web?.browser_session_endpoint) && !auth) {
    throw new ProtocolValidationError(
      "missing_auth",
      "auth is required for sessions, APIs, conversations, or feedback",
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
    extensions: parsedExtensions,
  } as DiscoveryDocument;
}

/** A `dpop_signing_alg_values_supported` list: when listed, it includes ES256 (§3.2, §4.3). */
export function dpopAlgorithms(value: unknown, label: string): readonly string[] | undefined {
  if (value === undefined || value === null) return undefined;
  const algorithms = array(value, label).map((item) => string(item, `${label} entry`));
  if (!algorithms.includes(DPOP_REQUIRED_ALGORITHM)) {
    throw new ProtocolValidationError("invalid_oauth_metadata", `${label} must include ES256`);
  }
  return algorithms;
}

export function parseOAuthServerMetadata(value: unknown): OAuthServerMetadata {
  const source = record(value, "OAuth metadata");
  const poppyDomains = array(source.poppy_domains, "poppy_domains").map((item) =>
    domain(item, "poppy_domains entry"),
  );
  if (poppyDomains.length === 0) {
    throw new ProtocolValidationError(
      "invalid_oauth_metadata",
      "poppy_domains must not be empty",
    );
  }
  const algorithms = dpopAlgorithms(source.dpop_signing_alg_values_supported, "dpop_signing_alg_values_supported");
  return {
    ...source,
    // Compared with `auth.issuer` character for character (§3.2): never normalized.
    issuer: httpsUrl(source.issuer, "issuer"),
    token_endpoint: httpsUrl(source.token_endpoint, "token_endpoint"),
    revocation_endpoint: httpsUrl(source.revocation_endpoint, "revocation_endpoint"),
    ...(source.authorization_endpoint === undefined
      ? {}
      : {
          authorization_endpoint: httpsUrl(
            source.authorization_endpoint,
            "authorization_endpoint",
          ),
        }),
    ...(source.device_authorization_endpoint === undefined
      ? {}
      : {
          device_authorization_endpoint: httpsUrl(
            source.device_authorization_endpoint,
            "device_authorization_endpoint",
          ),
        }),
    poppy_domains: poppyDomains,
    ...(algorithms === undefined ? {} : { dpop_signing_alg_values_supported: algorithms }),
  } as OAuthServerMetadata;
}

export function parseClientMetadata(value: unknown): ClientMetadata {
  const source = record(value, "client metadata");
  const clientId = httpsUrl(source.client_id, "client_id");
  const clientDomain = new URL(clientId).hostname;
  const jwksUri = httpsUrl(source.jwks_uri, "jwks_uri");
  const redirectUris = array(source.redirect_uris ?? [], "redirect_uris").map((item) =>
    httpsUrl(item, "redirect URI"),
  );
  if (
    new URL(jwksUri).hostname !== clientDomain ||
    redirectUris.some((uri) => new URL(uri).hostname !== clientDomain)
  ) {
    throw new ProtocolValidationError(
      "client_domain_mismatch",
      "jwks_uri and redirect_uris must use the client_id domain",
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
      : oneOf(source.alg, ["ES256", "RS256"] as const, "alg");

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
  if (alg !== undefined && alg !== "RS256") {
    throw new ProtocolValidationError(
      "invalid_jwk_algorithm",
      "RSA signing keys may advertise only RS256",
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
  const source = nullsAbsent(value, "operation", ["terms", "expires_at", "url"]);
  const state = oneOf(
    source.state,
    ["proposed", "in_progress", "succeeded", "failed", "cancelled", "expired"] as const,
    "operation.state",
  );
  const revision = integer(source.revision, "operation.revision");
  let confirmation: OperationConfirmation | null = null;
  if (source.confirmation !== undefined && source.confirmation !== null) {
    const item = record(source.confirmation, "operation.confirmation");
    confirmation = {
      ...item,
      revision: integer(item.revision, "operation.confirmation.revision"),
      approved_by: oneOf(
        item.approved_by,
        ["user", "standing_permission"] as const,
        "operation.confirmation.approved_by",
      ),
      confirmed_at: timestamp(item.confirmed_at, "operation.confirmation.confirmed_at"),
    } as OperationConfirmation;
  }
  let result: OperationResult | null = null;
  if (source.result !== undefined && source.result !== null) {
    const item = nullsAbsent(source.result, "operation.result", ["data"]);
    result = {
      ...item,
      summary: string(item.summary, "operation.result.summary"),
      ...(item.data === undefined
        ? {}
        : { data: record(item.data, "operation.result.data") }),
    } as OperationResult;
  }
  const expiresAt =
    source.expires_at === undefined
      ? undefined
      : timestamp(source.expires_at, "operation.expires_at");
  if (state === "proposed" && expiresAt === undefined) {
    throw new ProtocolValidationError(
      "invalid_operation",
      "a proposed operation requires expires_at",
    );
  }
  if (state === "proposed" && confirmation !== null) {
    throw new ProtocolValidationError(
      "invalid_operation",
      "a proposed operation cannot be confirmed",
    );
  }
  if (confirmation !== null && confirmation.revision !== revision) {
    throw new ProtocolValidationError(
      "invalid_operation",
      "confirmation must name the current revision",
    );
  }
  if (["succeeded", "failed", "cancelled", "expired"].includes(state) && result === null) {
    throw new ProtocolValidationError(
      "invalid_operation",
      "a final operation requires a result",
    );
  }
  return {
    ...source,
    operation_id: identifier(source.operation_id, "operation.operation_id"),
    revision,
    state,
    summary: string(source.summary, "operation.summary"),
    ...(source.terms === undefined
      ? {}
      : { terms: record(source.terms, "operation.terms") }),
    ...(expiresAt === undefined ? {} : { expires_at: expiresAt }),
    user_approval_required:
      source.user_approval_required === undefined
        ? false
        : boolean(source.user_approval_required, "operation.user_approval_required"),
    ...(source.url === undefined ? {} : { url: httpsUrl(source.url, "operation.url") }),
    confirmation,
    result,
  } as Operation;
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

export function parseMessage(value: unknown): Message {
  const source = nullsAbsent(value, "message", [
    "role",
    "text",
    "data",
    "context",
    "operation",
  ]);
  const text = source.text === undefined ? undefined : string(source.text, "message.text");
  const data = optionalRecord(source.data, "message.data");
  const context = messageContext(optionalRecord(source.context, "message.context"));
  const operation =
    source.operation === undefined ? undefined : parseOperation(source.operation);
  if (text === undefined && data === undefined && context === undefined && operation === undefined) {
    throw new ProtocolValidationError(
      "invalid_message",
      "a message requires text, data, context, or operation",
    );
  }
  return {
    ...source,
    id: identifier(source.id, "message.id"),
    sender: oneOf(source.sender, ["agent", "human"] as const, "message.sender"),
    ...(source.role === undefined
      ? {}
      : { role: oneOf(source.role, ["user", "company"] as const, "message.role") }),
    ...(text === undefined ? {} : { text }),
    ...(data === undefined ? {} : { data }),
    ...(context === undefined ? {} : { context }),
    ...(operation === undefined ? {} : { operation }),
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
          status: oneOf(
            source.status,
            ["working", "idle", "queued", "closed"] as const,
            "conversation event.status",
          ),
        }),
    ...(source.responder === undefined
      ? {}
      : {
          responder: oneOf(
            source.responder,
            ["agent", "human"] as const,
            "conversation event.responder",
          ),
        }),
    ...(source.error === undefined
      ? {}
      : {
          error: oneOf(
            source.error,
            ["sign_in_required", "insufficient_scope"] as const,
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
  if (type === "authorization") {
    if (parsed.error === undefined) {
      throw new ProtocolValidationError(
        "invalid_event",
        "an authorization event requires error",
      );
    }
    if (parsed.error === "insufficient_scope" && parsed.scope === undefined) {
      throw new ProtocolValidationError(
        "invalid_event",
        "insufficient_scope requires scope",
      );
    }
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
    status: oneOf(
      source.status,
      ["working", "idle", "queued", "closed"] as const,
      "status",
    ),
    responder: oneOf(source.responder, ["agent", "human"] as const, "responder"),
  } as ConversationEventPage;
}
