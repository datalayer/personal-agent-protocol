/**
 * A framework-neutral PAP company: discovery, Sessions, sign-in, conversations, operations.
 *
 * `CompanyService.handle` takes a neutral request and returns a neutral
 * response, so any web framework can serve it (`node.ts` serves it over
 * `node:http` and `node:https`). Every part a company would replace is a
 * Reactor contribution (`points.ts`): its store, accounts, agent, operation
 * executors, client policy and resolver, and replay cache. It is the port of
 * the Python `personal_agent_protocol.company.service` and answers the same
 * requests with the same responses.
 *
 * What it implements of draft 0.1 and Operations v1:
 *
 * - Discovery (`/.well-known/poppy.json`) and OAuth metadata
 *   (`/.well-known/oauth-authorization-server`), one issuer on the company's
 *   own domain.
 * - Sessions (§4.2): the JWT-bearer grant with a verified client assertion and
 *   Session assertion, DPoP-bound tokens, renewal by `session_id`.
 * - Direct Sign-In (§4.5): the company's consent page, the user's decision as
 *   `approveAuthorization` / `denyAuthorization`, PKCE, one-use codes.
 * - Device Sign-In (§4.6) with `authorization_pending` and `slow_down`, and the
 *   company's own approval page as `approveDevice` (the user's action).
 * - Mediated Sign-In (§4.7) with a one-time code, attempt limits, and uniform
 *   failures; credentials are checked by the account directory and dropped.
 * - Account Tokens (§4.8, §4.9): rotation on every refresh, narrower scopes
 *   only, `invalid_grant` for an expired, revoked, or rotated-away token, and
 *   revocation that signs out every Session signed in with it.
 * - Conversations (§7): idempotent messages, ordered cursor events, waited
 *   replies, SSE, handoff, Direct Conversations, `authorization` events, and
 *   closing; a conversation that is not yours is `conversation_not_found`.
 * - The OpenAPI API point (`/api/…`), its consequential calls answering `202`
 *   with an operation (Operations §4.1).
 * - Operations v1: proposals from the company agent or the API, read, confirm
 *   (latest revision, approval rules, scope, extension negotiation), at most
 *   once, and cancel.
 */

import { createHash, timingSafeEqual } from "node:crypto";

import type { ReactorPlatformView } from "@datalayer/reactor";

import { verifyDpopProof } from "../crypto.js";
import { ProofError, SessionError } from "../errors.js";
import { parseJsonStrict } from "../json.js";
import {
  parseMessage,
  parseOperation,
  type ClientMetadata,
  type JsonWebKeySet,
  type Message,
  type Operation,
  type OperationResult,
} from "../models.js";
import { Clocks, RandomSources, firstContribution } from "../reactor.js";
import { SecretValue } from "../secret.js";
import { JWT_BEARER_GRANT, JWT_CLIENT_ASSERTION } from "../sessions.js";
import {
  ClientPolicies,
  ClientResolvers,
  CompanyAccounts,
  CompanyAgents,
  CompanyApis,
  CompanyStores,
  OperationExecutors,
  OperationFailed,
  OperationOutcomeUnknown,
  ReplayCaches,
  type CompanyApi,
  type CompanyStore,
  type IssuedSession,
  type Reply,
  type ReplayCache,
  type StoredConversation,
  type StoredEvent,
  type StoredOperation,
} from "./points.js";
import { verifyAssertion } from "./verify.js";

/** The `kid` a compact JWT's header names, if any (used only to look a key up). */
function keyId(compact: string): { readonly kid?: string } {
  try {
    const header: unknown = JSON.parse(
      Buffer.from(compact.split(".", 1)[0] ?? "", "base64url").toString("utf8"),
    );
    const kid = (header as { kid?: unknown } | null)?.kid;
    return typeof kid === "string" ? { kid } : {};
  } catch {
    return {};
  }
}

const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const REFRESH_TOKEN_GRANT = "refresh_token";
const PAGE = 50;

export type MediatedFieldSpec = readonly [name: string, label: string, secret: boolean];

export interface CompanyConfigOptions {
  readonly name: string;
  readonly domain: string;
  readonly scopes: readonly string[];
  readonly writeScopes?: readonly string[];
  readonly mediatedFields?: readonly MediatedFieldSpec[];
  readonly device?: boolean;
  readonly direct?: boolean;
  readonly operations?: boolean;
  readonly humansAvailable?: boolean;
  readonly sessionLifetimeSeconds?: number;
  readonly accountTokenLifetimeSeconds?: number;
  readonly operationLifetimeSeconds?: number;
  readonly deviceInterval?: number;
  readonly maxCodeAttempts?: number;
  readonly customScopes?: Readonly<Record<string, string>>;
}

/** What the company publishes and allows. */
export class CompanyConfig {
  readonly name: string;
  readonly domain: string;
  readonly scopes: readonly string[];
  readonly writeScopes: readonly string[];
  readonly mediatedFields: readonly MediatedFieldSpec[];
  readonly device: boolean;
  readonly direct: boolean;
  readonly operations: boolean;
  readonly humansAvailable: boolean;
  readonly sessionLifetimeSeconds: number;
  readonly accountTokenLifetimeSeconds: number;
  readonly operationLifetimeSeconds: number;
  readonly deviceInterval: number;
  readonly maxCodeAttempts: number;
  readonly customScopes: Readonly<Record<string, string>>;

  constructor(options: CompanyConfigOptions) {
    this.name = options.name;
    this.domain = options.domain;
    this.scopes = [...options.scopes];
    this.writeScopes = [...(options.writeScopes ?? [])];
    this.mediatedFields = [...(options.mediatedFields ?? [])];
    this.device = options.device ?? true;
    this.direct = options.direct ?? true;
    this.operations = options.operations ?? true;
    this.humansAvailable = options.humansAvailable ?? false;
    this.sessionLifetimeSeconds = options.sessionLifetimeSeconds ?? 60 * 60;
    this.accountTokenLifetimeSeconds = options.accountTokenLifetimeSeconds ?? 90 * 24 * 60 * 60;
    this.operationLifetimeSeconds = options.operationLifetimeSeconds ?? 15 * 60;
    this.deviceInterval = options.deviceInterval ?? 5;
    this.maxCodeAttempts = options.maxCodeAttempts ?? 3;
    this.customScopes = { ...(options.customScopes ?? {}) };
  }

  get base(): string {
    return `https://${this.domain}`;
  }
  get tokenEndpoint(): string {
    return `${this.base}/oauth/token`;
  }
  get deviceEndpoint(): string {
    return `${this.base}/oauth/device`;
  }
  get authorizationEndpoint(): string {
    return `${this.base}/oauth/authorize`;
  }
  get apiDescription(): string {
    return `${this.base}/api/openapi.json`;
  }
  get revocationEndpoint(): string {
    return `${this.base}/oauth/revoke`;
  }
  get mediatedEndpoint(): string {
    return `${this.base}/poppy/sign-in`;
  }
  get conversationsEndpoint(): string {
    return `${this.base}/poppy/conversations`;
  }
  get operationsEndpoint(): string {
    return `${this.base}/poppy/operations`;
  }
}

/** A request as any framework hands it over: full HTTPS URL, lower-case headers. */
export interface CompanyRequest {
  readonly method: string;
  readonly url: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: Uint8Array | string;
}

/**
 * A response: a JSON `body`, an HTML page (a string `body` with its own
 * `Content-Type`), or an SSE `stream`.
 */
export interface CompanyResponse {
  readonly status: number;
  readonly body?: unknown;
  readonly headers: Readonly<Record<string, string>>;
  readonly stream?: AsyncIterable<Uint8Array>;
}

class Refused extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly extra: Readonly<Record<string, unknown>> = {},
  ) {
    super(error);
  }
}

const NO_STORE = { "Cache-Control": "no-store" } as const;

const CHALLENGED = new Set([
  "invalid_token",
  "sign_in_required",
  "insufficient_scope",
  "invalid_dpop_proof",
]);

function jsonError(
  status: number,
  error: string,
  extra: Readonly<Record<string, unknown>> = {},
): CompanyResponse {
  const headers: Record<string, string> = { ...NO_STORE };
  if (CHALLENGED.has(error) && (status === 401 || status === 403)) {
    // Token errors are also in WWW-Authenticate (§6, RFC 9449).
    const scope = extra.scope;
    headers["WWW-Authenticate"] =
      `DPoP error="${error}"` + (typeof scope === "string" ? `, scope="${scope}"` : "");
  }
  return { status, body: { error, ...extra }, headers };
}

function digest(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

function base64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

/** Python's `parse_qsl` into a dict: blank values dropped, the last value wins. */
function pairs(query: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of new URLSearchParams(query)) {
    if (value) result[name] = value;
  }
  return result;
}

function text(body: Uint8Array | string | undefined): string {
  if (body === undefined) return "";
  return typeof body === "string" ? body : new TextDecoder().decode(body);
}

function words(value: unknown): string[] {
  return String(value ?? "")
    .split(" ")
    .filter(Boolean);
}

/** RFC 3339 in UTC with `Z`, without a fraction when there is none (Python's `isoformat`). */
function isoZ(date: Date): string {
  return date.toISOString().replace(".000Z", "Z");
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#x27;");
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sameOwner(a: readonly [string, string], b: readonly [string, string]): boolean {
  return a[0] === b[0] && a[1] === b[1];
}

/** The message as stored and digested: absent members dropped (Python's `exclude_none`). */
function plain(message: Message): Record<string, unknown> {
  return JSON.parse(JSON.stringify(message)) as Record<string, unknown>;
}

/** One company's PAP endpoints over Reactor contributions. */
export class CompanyService {
  readonly config: CompanyConfig;
  readonly reactor: ReactorPlatformView;
  /** The extensions each verified client declares, by `client_id`. */
  readonly extensions = new Map<string, ReadonlySet<string>>();

  constructor(options: { readonly config: CompanyConfig; readonly reactor: ReactorPlatformView }) {
    this.config = options.config;
    this.reactor = options.reactor;
  }

  // Contributions -------------------------------------------------------------------

  get store(): CompanyStore {
    return firstContribution(this.reactor, CompanyStores, "company store");
  }

  #now(): Date {
    return firstContribution(this.reactor, Clocks, "clock").now();
  }

  #id(prefix: string): string {
    const bytes = firstContribution(this.reactor, RandomSources, "random").bytes(16);
    if (bytes.byteLength < 16) {
      throw new Error("Opaque PAP identifiers require at least 128 random bits");
    }
    return `${prefix}_${base64Url(bytes)}`;
  }

  #replay(): ReplayCache {
    return firstContribution(this.reactor, ReplayCaches, "replay cache");
  }

  #later(seconds: number): Date {
    return new Date(this.#now().getTime() + seconds * 1000);
  }

  // Routing -------------------------------------------------------------------------

  async handle(request: CompanyRequest): Promise<CompanyResponse> {
    const path = new URL(request.url).pathname;
    const method = request.method.toUpperCase();
    try {
      if (method === "GET" && path === "/.well-known/poppy.json") {
        return { status: 200, body: this.discoveryDocument(), headers: {} };
      }
      if (method === "GET" && path === "/.well-known/oauth-authorization-server") {
        return { status: 200, body: this.oauthMetadata(), headers: {} };
      }
      if (method === "POST" && path === "/oauth/token") return await this.#token(request);
      if (method === "GET" && path === "/oauth/authorize" && this.config.direct) {
        return await this.#authorize(request);
      }
      const api = this.#api();
      if (method === "GET" && path === "/api/openapi.json" && api !== undefined) {
        return { status: 200, body: api.openapi(), headers: {} };
      }
      if (path.startsWith("/api/") && api !== undefined) {
        return await this.#apiCall(request, api, method, path);
      }
      if (method === "POST" && path === "/oauth/device" && this.config.device) {
        return await this.#device(request);
      }
      if (method === "POST" && path === "/oauth/revoke") return await this.#revoke(request);
      if (method === "POST" && path === "/poppy/sign-in" && this.config.mediatedFields.length) {
        return await this.#mediated(request);
      }
      if (method === "POST" && path.startsWith("/poppy/sign-in/")) {
        return await this.#mediatedCode(request, path.slice(path.lastIndexOf("/") + 1));
      }
      if (path === "/poppy/conversations" && method === "POST") {
        return await this.#startConversation(request);
      }
      if (path.startsWith("/poppy/conversations/")) {
        return await this.#conversationRoute(request, method, path);
      }
      if (path.startsWith("/poppy/operations/") && this.config.operations) {
        return await this.#operationRoute(request, method, path);
      }
    } catch (error) {
      if (error instanceof Refused) return jsonError(error.status, error.error, error.extra);
      if (error instanceof SessionError || error instanceof ProofError) {
        const status = error.statusCode ?? (error.code === "invalid_client" ? 401 : 400);
        return jsonError(status, error.code);
      }
      throw error;
    }
    return jsonError(404, "not_found");
  }

  // Discovery -----------------------------------------------------------------------

  discoveryDocument(): Record<string, unknown> {
    const config = this.config;
    const auth: Record<string, unknown> = { issuer: config.base };
    if (config.direct) auth.direct = { scopes: [...config.scopes] };
    if (config.device) auth.device = { scopes: [...config.scopes] };
    if (config.mediatedFields.length) {
      auth.mediated = {
        endpoint: config.mediatedEndpoint,
        fields: config.mediatedFields.map(([name, label, secret]) => ({ name, label, secret })),
        scopes: [...config.scopes],
      };
    }
    if (Object.keys(config.customScopes).length) auth.custom_scopes = { ...config.customScopes };
    const document: Record<string, unknown> = {
      protocol_version: "0.1",
      organization: { name: config.name, domain: config.domain },
      auth,
      agent: { protocols: [{ type: "poppy", endpoint: config.conversationsEndpoint }] },
    };
    const api = this.#api();
    if (api !== undefined) {
      document.apis = [
        { type: "openapi", url: config.apiDescription, description: api.description },
      ];
    }
    if (config.operations) {
      document.extensions = {
        operations: { version: "1", endpoint: config.operationsEndpoint },
      };
    }
    return document;
  }

  oauthMetadata(): Record<string, unknown> {
    const config = this.config;
    const metadata: Record<string, unknown> = {
      issuer: config.base,
      token_endpoint: config.tokenEndpoint,
      revocation_endpoint: config.revocationEndpoint,
      poppy_domains: [config.domain],
      dpop_signing_alg_values_supported: ["ES256", "RS256"],
    };
    if (config.device) metadata.device_authorization_endpoint = config.deviceEndpoint;
    if (config.direct) {
      metadata.authorization_endpoint = config.authorizationEndpoint;
      metadata.code_challenge_methods_supported = ["S256"];
    }
    return metadata;
  }

  // OAuth ---------------------------------------------------------------------------

  /** Verify the client assertion, the agent's keys, and the company's policy. */
  async #client(form: Readonly<Record<string, string>>, audience: string): Promise<string> {
    const clientId = form.client_id ?? "";
    if (form.client_assertion_type !== JWT_CLIENT_ASSERTION || !clientId) {
      throw new Refused(401, "invalid_client");
    }
    const policy = firstContribution(this.reactor, ClientPolicies, "policy");
    if (!(await policy.allows(clientId))) throw new Refused(401, "invalid_client");
    const resolver = firstContribution(this.reactor, ClientResolvers, "client resolver");
    let resolved: readonly [ClientMetadata, JsonWebKeySet];
    try {
      resolved = await resolver.resolve(clientId, keyId(form.client_assertion ?? ""));
    } catch {
      throw new Refused(401, "invalid_client");
    }
    const [metadata, keys] = resolved;
    await verifyAssertion(form.client_assertion ?? "", {
      keys,
      issuer: clientId,
      audience,
      subject: clientId,
      replayCache: this.#replay(),
      now: this.#now(),
    });
    this.extensions.set(clientId, new Set(Object.keys(metadata.extensions ?? {})));
    return clientId;
  }

  async #dpop(request: CompanyRequest, accessToken?: string): Promise<string> {
    const status = accessToken === undefined ? 400 : 401;
    const proof = request.headers.dpop;
    if (!proof) throw new Refused(status, "invalid_dpop_proof");
    try {
      const verified = await verifyDpopProof(proof, {
        method: request.method,
        url: request.url,
        replayCache: this.#replay(),
        ...(accessToken === undefined ? {} : { accessToken: new SecretValue(accessToken) }),
        now: this.#now(),
      });
      return verified.keyThumbprint;
    } catch (error) {
      if (error instanceof ProofError) throw new Refused(status, error.code);
      throw error;
    }
  }

  async #token(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const grant = form.grant_type;
    const clientId = await this.#client(form, this.config.tokenEndpoint);
    const thumbprint = await this.#dpop(request);
    if (grant === JWT_BEARER_GRANT) return this.#sessionGrant(form, clientId, thumbprint);
    if (grant === REFRESH_TOKEN_GRANT) return this.#refreshGrant(form, clientId, thumbprint);
    if (grant === "authorization_code" && this.config.direct) {
      return this.#codeGrant(form, clientId, thumbprint);
    }
    if (grant === DEVICE_CODE_GRANT && this.config.device) {
      return this.#deviceGrant(form, clientId, thumbprint);
    }
    throw new Refused(400, "unsupported_grant_type");
  }

  async #sessionGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const resolver = firstContribution(this.reactor, ClientResolvers, "client");
    const [, keys] = await resolver.resolve(clientId, keyId(form.assertion ?? ""));
    const claims = await verifyAssertion(form.assertion ?? "", {
      keys,
      issuer: clientId,
      audience: this.config.tokenEndpoint,
      replayCache: this.#replay(),
      now: this.#now(),
      error: "invalid_grant",
    });
    const pairwise = String(claims.sub);
    const sessionId = form.session_id;
    let session: IssuedSession;
    if (sessionId === undefined) {
      session = {
        sessionId: this.#id("ses"),
        clientId,
        pairwiseUserId: pairwise,
        keyThumbprint: thumbprint,
        expiresAt: this.#later(this.config.sessionLifetimeSeconds),
        scopes: [],
      };
    } else {
      const known = this.#sessionById(sessionId);
      if (known === undefined || known.clientId !== clientId || known.pairwiseUserId !== pairwise) {
        throw new Refused(400, "invalid_session");
      }
      this.#dropTokensOf(known.sessionId);
      session = {
        ...known,
        keyThumbprint: thumbprint,
        expiresAt: this.#later(this.config.sessionLifetimeSeconds),
      };
    }
    return this.#issue(session);
  }

  async #refreshGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const presented = form.refresh_token ?? "";
    const grant = this.store.accountTokens.get(digest(presented));
    const now = this.#now();
    if (
      grant === undefined ||
      grant.revoked ||
      now >= grant.expiresAt ||
      grant.clientId !== clientId
    ) {
      throw new Refused(400, "invalid_grant");
    }
    const session = this.#sessionById(form.session_id ?? "");
    if (
      session === undefined ||
      session.clientId !== clientId ||
      session.pairwiseUserId !== grant.pairwiseUserId
    ) {
      throw new Refused(400, "invalid_session");
    }
    if (session.accountId !== undefined && session.accountId !== grant.accountId) {
      // A Session signed in to one account never switches to another (§4.4).
      throw new Refused(400, "account_mismatch");
    }
    const requested = words(form.scope);
    if (requested.length && requested.some((scope) => !grant.scopes.includes(scope))) {
      throw new Refused(400, "invalid_scope");
    }
    // Rotation: the presented token stops working the moment its successor exists.
    grant.revoked = true;
    const rotated = this.#id("acct");
    this.store.accountTokens.set(digest(rotated), { ...grant, revoked: false });
    this.#dropTokensOf(session.sessionId);
    const resource = form.resource;
    const signedIn: IssuedSession = {
      ...session,
      keyThumbprint: thumbprint,
      accountId: grant.accountId,
      scopes: requested.length ? requested : grant.scopes,
      accountToken: digest(rotated),
      expiresAt: new Date(now.getTime() + this.config.sessionLifetimeSeconds * 1000),
    };
    // The resource is what this refresh asked for, never one an earlier refresh named.
    const { resource: _earlier, ...unbound } = signedIn;
    return this.#issue(resource === undefined ? unbound : { ...unbound, resource }, rotated);
  }

  async #device(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const clientId = await this.#client(form, this.config.deviceEndpoint);
    const scopes = words(form.scope);
    if (!scopes.length || scopes.some((scope) => !this.config.scopes.includes(scope))) {
      throw new Refused(400, "invalid_scope");
    }
    const deviceCode = this.#id("dev");
    let userCode = this.#id("u").slice(2, 10).toUpperCase().replaceAll("-", "X").replaceAll("_", "Y");
    userCode = `${userCode.slice(0, 4)}-${userCode.slice(4)}`;
    const lifetime = 600;
    this.store.devices.set(digest(deviceCode), {
      clientId,
      scopes,
      userCode,
      expiresAt: this.#later(lifetime),
      interval: this.config.deviceInterval,
      granted: [],
      denied: false,
    });
    return {
      status: 200,
      body: {
        device_code: deviceCode,
        user_code: userCode,
        verification_uri: `${this.config.base}/device`,
        verification_uri_complete: `${this.config.base}/device?user_code=${userCode}`,
        expires_in: lifetime,
        interval: this.config.deviceInterval,
      },
      headers: { ...NO_STORE },
    };
  }

  /**
   * The user signed in on the company's page and approved: what they granted.
   *
   * `scopes` may be fewer than requested (partial consent); omitted, all.
   */
  approveDevice(
    userCode: string,
    options: { readonly accountId: string; readonly scopes?: readonly string[] },
  ): readonly string[] {
    for (const pending of this.store.devices.values()) {
      if (pending.userCode === userCode && pending.accountId === undefined) {
        const granted = (options.scopes?.length ? options.scopes : pending.scopes).filter((s) =>
          pending.scopes.includes(s),
        );
        pending.accountId = options.accountId;
        pending.granted = granted;
        return granted;
      }
    }
    throw new Error("unknown or already approved user code");
  }

  denyDevice(userCode: string): void {
    for (const pending of this.store.devices.values()) {
      if (pending.userCode === userCode) {
        pending.denied = true;
        return;
      }
    }
    throw new Error("unknown user code");
  }

  async #deviceGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const key = digest(form.device_code ?? "");
    const pending = this.store.devices.get(key);
    const now = this.#now();
    if (pending === undefined || pending.clientId !== clientId) {
      throw new Refused(400, "invalid_grant");
    }
    if (now >= pending.expiresAt) {
      this.store.devices.delete(key);
      throw new Refused(400, "expired_token");
    }
    if (pending.denied) {
      this.store.devices.delete(key);
      throw new Refused(400, "access_denied");
    }
    if (
      pending.lastPoll !== undefined &&
      now.getTime() - pending.lastPoll.getTime() < pending.interval * 1000
    ) {
      pending.interval += 5;
      pending.lastPoll = now;
      throw new Refused(400, "slow_down");
    }
    pending.lastPoll = now;
    if (pending.accountId === undefined) throw new Refused(400, "authorization_pending");
    const session = this.#sessionById(form.session_id ?? "");
    if (session === undefined || session.clientId !== clientId) {
      throw new Refused(400, "invalid_session");
    }
    this.store.devices.delete(key);
    return this.#signIn(session, pending.accountId, pending.granted, thumbprint);
  }

  async #revoke(request: CompanyRequest): Promise<CompanyResponse> {
    const form = pairs(text(request.body));
    const clientId = await this.#client(form, this.config.revocationEndpoint);
    const key = digest(form.token ?? "");
    const grant = this.store.accountTokens.get(key);
    if (grant !== undefined && grant.clientId === clientId) {
      grant.revoked = true;
      // Every Session signed in with it continues signed out (§4.9).
      this.#signOutSessionsOf(key);
    }
    return { status: 200, body: {}, headers: { ...NO_STORE } };
  }

  /**
   * The user disconnects an agent in account settings: its tokens go, Sessions sign out.
   *
   * Returns how many Account Tokens were revoked (upstream guides, account settings).
   */
  disconnect(clientId: string, accountId: string): number {
    let revoked = 0;
    for (const [key, grant] of this.store.accountTokens) {
      if (grant.clientId === clientId && grant.accountId === accountId && !grant.revoked) {
        grant.revoked = true;
        revoked += 1;
        this.#signOutSessionsOf(key);
      }
    }
    return revoked;
  }

  #signOutSessionsOf(accountTokenKey: string): void {
    for (const [tokenKey, session] of [...this.store.sessions]) {
      if (session.accountToken === accountTokenKey) {
        const { accountId: _account, accountToken: _token, ...rest } = session;
        this.store.sessions.set(tokenKey, { ...rest, scopes: [] });
      }
    }
  }

  #signIn(
    session: IssuedSession,
    accountId: string,
    scopes: readonly string[],
    thumbprint?: string,
  ): CompanyResponse {
    if (session.accountId !== undefined && session.accountId !== accountId) {
      throw new Refused(400, "account_mismatch");
    }
    const accountToken = this.#id("acct");
    this.store.accountTokens.set(digest(accountToken), {
      accountId,
      clientId: session.clientId,
      pairwiseUserId: session.pairwiseUserId,
      scopes,
      expiresAt: this.#later(this.config.accountTokenLifetimeSeconds),
      revoked: false,
    });
    this.#dropTokensOf(session.sessionId);
    return this.#issue(
      {
        ...session,
        accountId,
        scopes,
        accountToken: digest(accountToken),
        keyThumbprint: thumbprint || session.keyThumbprint,
      },
      accountToken,
    );
  }

  #issue(session: IssuedSession, refreshToken?: string): CompanyResponse {
    const accessToken = this.#id("sat");
    this.store.sessions.set(digest(accessToken), session);
    const body: Record<string, unknown> = {
      access_token: accessToken,
      token_type: "DPoP",
      expires_in: Math.trunc((session.expiresAt.getTime() - this.#now().getTime()) / 1000),
      scope: session.scopes.join(" "),
      session_id: session.sessionId,
      signed_in: session.accountId !== undefined,
    };
    if (refreshToken !== undefined) body.refresh_token = refreshToken;
    return { status: 200, body, headers: { ...NO_STORE } };
  }

  #sessionById(sessionId: string): IssuedSession | undefined {
    for (const session of this.store.sessions.values()) {
      if (session.sessionId === sessionId) return session;
    }
    return undefined;
  }

  #dropTokensOf(sessionId: string): void {
    for (const [key, session] of [...this.store.sessions]) {
      if (session.sessionId === sessionId) this.store.sessions.delete(key);
    }
  }

  // Direct Sign-In (§4.5) -------------------------------------------------------------

  /** The company's own sign-in and consent page for a personal agent's request. */
  async #authorize(request: CompanyRequest): Promise<CompanyResponse> {
    const query = pairs(new URL(request.url).search);
    const clientId = query.client_id ?? "";
    const redirectUri = query.redirect_uri ?? "";
    const policy = firstContribution(this.reactor, ClientPolicies, "policy");
    const resolver = firstContribution(this.reactor, ClientResolvers, "client");
    let metadata: ClientMetadata;
    try {
      [metadata] = await resolver.resolve(clientId);
    } catch {
      return page(400, "This agent could not be verified.");
    }
    // An unknown client or redirect is never redirected to: that would be an open redirector.
    if (!(await policy.allows(clientId)) || !metadata.redirect_uris.includes(redirectUri)) {
      return page(400, "This sign-in request is not valid.");
    }
    const state = query.state ?? "";
    const scopes = words(query.scope);
    if (query.response_type !== "code") {
      return this.#redirect(redirectUri, { error: "unsupported_response_type", state });
    }
    if (query.code_challenge_method !== "S256" || !query.code_challenge) {
      return this.#redirect(redirectUri, { error: "invalid_request", state });
    }
    if (!scopes.length || scopes.some((scope) => !this.config.scopes.includes(scope))) {
      return this.#redirect(redirectUri, { error: "invalid_scope", state });
    }
    const requestId = this.#id("authz");
    this.store.authorizations.set(requestId, {
      clientId,
      redirectUri,
      scopes,
      state,
      codeChallenge: query.code_challenge,
      expiresAt: this.#later(10 * 60),
    });
    const agent = escapeHtml(metadata.client_name);
    const agentDomain = escapeHtml(new URL(clientId).hostname);
    const described = scopes
      .map((scope) => `<li>${escapeHtml(this.config.customScopes[scope] ?? scope)}</li>`)
      .join("");
    return page(
      200,
      `<h1>${escapeHtml(this.config.name)}</h1>` +
        `<p><strong>${agent}</strong> (${agentDomain}) asks to:</p><ul>${described}</ul>` +
        `<form method="post" data-request-id="${requestId}">` +
        `<input type="hidden" name="request_id" value="${requestId}">` +
        '<button name="decision" value="allow">Allow</button>' +
        '<button name="decision" value="deny">Deny</button></form>',
    );
  }

  /**
   * The user, signed in on the company's page, allowed: where their browser goes next.
   *
   * `scopes` may be fewer than requested (partial consent); omitted, all.
   */
  approveAuthorization(
    requestId: string,
    options: { readonly accountId: string; readonly scopes?: readonly string[] },
  ): string {
    const pending = this.#pendingAuthorization(requestId);
    const granted = (options.scopes?.length ? options.scopes : pending.scopes).filter((s) =>
      pending.scopes.includes(s),
    );
    const code = this.#id("code");
    this.store.codes.set(digest(code), {
      clientId: pending.clientId,
      redirectUri: pending.redirectUri,
      codeChallenge: pending.codeChallenge,
      accountId: options.accountId,
      scopes: granted,
      expiresAt: this.#later(60),
    });
    return this.#redirectUrl(pending.redirectUri, { code, state: pending.state });
  }

  /** The user refused: the agent learns only `access_denied`. */
  denyAuthorization(requestId: string): string {
    const pending = this.#pendingAuthorization(requestId);
    return this.#redirectUrl(pending.redirectUri, {
      error: "access_denied",
      state: pending.state,
    });
  }

  #pendingAuthorization(requestId: string) {
    const pending = this.store.authorizations.get(requestId);
    this.store.authorizations.delete(requestId);
    if (pending === undefined || this.#now() >= pending.expiresAt) {
      throw new Error("unknown, used, or expired sign-in request");
    }
    return pending;
  }

  async #codeGrant(
    form: Readonly<Record<string, string>>,
    clientId: string,
    thumbprint: string,
  ): Promise<CompanyResponse> {
    const key = digest(form.code ?? "");
    const issued = this.store.codes.get(key);
    this.store.codes.delete(key);
    if (
      issued === undefined ||
      this.#now() >= issued.expiresAt ||
      issued.clientId !== clientId ||
      issued.redirectUri !== form.redirect_uri
    ) {
      throw new Refused(400, "invalid_grant");
    }
    const challenge = createHash("sha256")
      .update(form.code_verifier ?? "")
      .digest("base64url");
    const expected = Buffer.from(issued.codeChallenge);
    const actual = Buffer.from(challenge);
    if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
      throw new Refused(400, "invalid_grant");
    }
    const session = this.#sessionById(form.session_id ?? "");
    if (session === undefined || session.clientId !== clientId) {
      throw new Refused(400, "invalid_session");
    }
    return this.#signIn(session, issued.accountId, issued.scopes, thumbprint);
  }

  #redirectUrl(redirectUri: string, values: Readonly<Record<string, string>>): string {
    const url = new URL(redirectUri);
    url.hash = "";
    for (const [name, value] of Object.entries(values)) {
      if (value) url.searchParams.append(name, value);
    }
    url.searchParams.append("iss", this.config.base);
    return url.toString();
  }

  #redirect(redirectUri: string, values: Readonly<Record<string, string>>): CompanyResponse {
    return {
      status: 303,
      headers: { Location: this.#redirectUrl(redirectUri, values), ...NO_STORE },
    };
  }

  // OpenAPI API (§6, Operations §4.1) -----------------------------------------------------

  #api(): CompanyApi | undefined {
    return this.reactor.getContributions(CompanyApis)[0]?.value;
  }

  async #apiCall(
    request: CompanyRequest,
    api: CompanyApi,
    method: string,
    path: string,
  ): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const source = text(request.body);
    const body = source ? parseJsonStrict(source) : undefined;
    const result = await api.handle({
      method,
      path: path.slice("/api".length),
      query: pairs(new URL(request.url).search),
      body,
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      scopes: session.scopes,
      clientId: session.clientId,
    });
    if (result.operation === undefined) {
      return { status: result.status ?? 200, body: result.body, headers: {} };
    }
    if (session.accountId === undefined) throw new Refused(403, "sign_in_required");
    if (!this.extensions.get(session.clientId)?.has("operations")) {
      throw new Refused(403, "extension_required", { extension: "operations" });
    }
    const operation = this.#propose(session, { operation: result.operation });
    return { status: 202, body: { operation }, headers: {} };
  }

  // Resource requests ---------------------------------------------------------------

  async #caller(request: CompanyRequest): Promise<[string, IssuedSession]> {
    const authorization = request.headers.authorization ?? "";
    const space = authorization.indexOf(" ");
    const scheme = space < 0 ? authorization : authorization.slice(0, space);
    const token = space < 0 ? "" : authorization.slice(space + 1);
    if (scheme !== "DPoP" || !token) throw new Refused(401, "invalid_token");
    const key = digest(token);
    const session = this.store.sessions.get(key);
    if (session === undefined || this.#now() >= session.expiresAt) {
      throw new Refused(401, "invalid_token");
    }
    const thumbprint = await this.#dpop(request, token);
    if (thumbprint !== session.keyThumbprint) throw new Refused(401, "invalid_dpop_proof");
    return [key, session];
  }

  async #mediated(request: CompanyRequest): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const source = text(request.body);
    const body = source ? parseJsonStrict(source) : {};
    const credentials = isObject(body) ? body.credentials : undefined;
    if (!isObject(credentials)) throw new Refused(400, "invalid_request");
    const requested = words(isObject(body) ? body.scope : "");
    const granted = requested.filter((scope) => this.config.scopes.includes(scope));
    const accounts = firstContribution(this.reactor, CompanyAccounts, "accounts");
    const secrets: Record<string, SecretValue> = {};
    for (const [name, value] of Object.entries(credentials)) {
      // An empty value is no credential: the directory sees it missing, and refuses.
      if (value !== undefined && value !== null && String(value)) {
        secrets[name] = new SecretValue(String(value));
      }
      delete credentials[name];
    }
    const authenticated = await accounts.authenticate(secrets);
    for (const name of Object.keys(secrets)) delete secrets[name];
    if (authenticated === undefined) {
      return { status: 200, body: { status: "failed" }, headers: { ...NO_STORE } };
    }
    if (authenticated.codeReference === undefined) {
      return this.#signedInBody(session, authenticated.accountId, granted);
    }
    const signInId = this.#id("si");
    const expiresAt = this.#later(5 * 60);
    this.store.mediated.set(signInId, {
      sessionId: session.sessionId,
      accountId: authenticated.accountId,
      scopes: granted,
      codeReference: authenticated.codeReference,
      expiresAt,
      attempts: 0,
    });
    return {
      status: 200,
      body: {
        status: "code_required",
        sign_in_id: signInId,
        code: { sent_to: authenticated.sentTo ?? "your device" },
        expires_at: isoZ(expiresAt),
      },
      headers: { ...NO_STORE },
    };
  }

  async #mediatedCode(request: CompanyRequest, signInId: string): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const pending = this.store.mediated.get(signInId);
    if (pending === undefined || pending.sessionId !== session.sessionId) {
      // Only the Session that started it can finish it; nothing else is said.
      throw new Refused(404, "not_found");
    }
    if (this.#now() >= pending.expiresAt) {
      this.store.mediated.delete(signInId);
      return { status: 200, body: { status: "expired" }, headers: { ...NO_STORE } };
    }
    const source = text(request.body);
    const body = source ? parseJsonStrict(source) : {};
    const code = isObject(body) ? body.code : undefined;
    const accounts = firstContribution(this.reactor, CompanyAccounts, "accounts");
    if (
      typeof code !== "string" ||
      !code ||
      !(await accounts.checkCode(pending.codeReference, new SecretValue(code)))
    ) {
      pending.attempts += 1;
      if (pending.attempts >= this.config.maxCodeAttempts) {
        this.store.mediated.delete(signInId);
        return { status: 200, body: { status: "failed" }, headers: { ...NO_STORE } };
      }
      return {
        status: 200,
        body: {
          status: "code_required",
          sign_in_id: signInId,
          code: {},
          expires_at: isoZ(pending.expiresAt),
        },
        headers: { ...NO_STORE },
      };
    }
    this.store.mediated.delete(signInId);
    return this.#signedInBody(session, pending.accountId, pending.scopes);
  }

  #signedInBody(
    session: IssuedSession,
    accountId: string,
    scopes: readonly string[],
  ): CompanyResponse {
    const response = this.#signIn(session, accountId, scopes);
    return {
      ...response,
      body: { status: "complete", ...(response.body as Record<string, unknown>) },
    };
  }

  // Conversations -------------------------------------------------------------------

  #owned(conversationId: string, session: IssuedSession): StoredConversation {
    const conversation = this.store.conversations.get(conversationId);
    if (
      conversation === undefined ||
      !sameOwner(conversation.owner, [session.clientId, session.pairwiseUserId])
    ) {
      throw new Refused(404, "conversation_not_found");
    }
    if (conversation.accountId !== undefined && session.accountId !== conversation.accountId) {
      // Once it used the account, it belongs to that account (§7.2, §7.11).
      if (session.accountId === undefined) throw new Refused(403, "sign_in_required");
      throw new Refused(404, "conversation_not_found");
    }
    return conversation;
  }

  #event(conversation: StoredConversation, payload: Readonly<Record<string, unknown>>): void {
    const id = this.#id("evt");
    conversation.events.push({ id, payload: { id, created_at: isoZ(this.#now()), ...payload } });
  }

  #state(conversation: StoredConversation): void {
    this.#event(conversation, {
      type: "state",
      status: conversation.status,
      responder: conversation.responder,
    });
  }

  async #startConversation(request: CompanyRequest): Promise<CompanyResponse> {
    const [, session] = await this.#caller(request);
    const body = parseJsonStrict(text(request.body));
    const message = parseMessage(isObject(body) ? body.message : undefined);
    const owner = [session.clientId, session.pairwiseUserId] as const;
    const replay = this.#replayed(owner, message);
    if (replay !== undefined) {
      return this.#answer(request, this.store.conversations.get(replay)!, 201);
    }
    const parentId = isObject(body) ? body.parent_conversation_id : undefined;
    let parent: StoredConversation | undefined;
    if (parentId !== undefined && parentId !== null) {
      parent = this.#owned(String(parentId), session);
      if (parent.status === "closed") throw new Refused(409, "conversation_closed");
      if (parent.parentId !== undefined) throw new Refused(404, "conversation_not_found");
      if (parent.directChild !== undefined) {
        throw new Refused(409, "direct_conversation_open", {
          conversation_id: parent.directChild,
        });
      }
    }
    const conversation: StoredConversation = {
      conversationId: this.#id("cnv"),
      owner,
      status: "idle",
      responder: "agent",
      ...(parent === undefined ? {} : { parentId: parent.conversationId }),
      events: [],
      forgotten: new Set(),
    };
    this.store.conversations.set(conversation.conversationId, conversation);
    if (parent !== undefined) {
      parent.directChild = conversation.conversationId;
      this.#event(parent, {
        type: "direct_opened",
        conversation_id: conversation.conversationId,
      });
    }
    await this.#receive(conversation, session, message);
    return this.#answer(request, conversation, 201);
  }

  async #conversationRoute(
    request: CompanyRequest,
    method: string,
    path: string,
  ): Promise<CompanyResponse> {
    const parts = path.split("/");
    const conversationId = parts[3] ?? "";
    const action = parts[4] ?? "";
    const [, session] = await this.#caller(request);
    const conversation = this.#owned(conversationId, session);
    if (method === "GET" && action === "events") {
      if ((request.headers.accept ?? "").includes("text/event-stream")) {
        return this.#stream(conversation, request.headers["last-event-id"]);
      }
      return this.#pageResponse(request, conversation, 200);
    }
    if (method !== "POST") throw new Refused(405, "method_not_allowed");
    if (action === "close") {
      this.#close(conversation);
      return this.#receipt(conversation, 200);
    }
    if (conversation.status === "closed") throw new Refused(409, "conversation_closed");
    if (conversation.directChild !== undefined) {
      throw new Refused(409, "direct_conversation_open", {
        conversation_id: conversation.directChild,
      });
    }
    if (action === "handoff") {
      conversation.status = "queued";
      this.#state(conversation);
      if (this.config.humansAvailable) {
        conversation.status = "idle";
        conversation.responder = "human";
      } else {
        conversation.status = "idle";
      }
      this.#state(conversation);
      return this.#receipt(conversation, 202);
    }
    if (action === "messages") {
      const body = parseJsonStrict(text(request.body));
      const message = parseMessage(isObject(body) ? body.message : undefined);
      const replay = this.#replayed([session.clientId, session.pairwiseUserId], message);
      if (replay === undefined) await this.#receive(conversation, session, message);
      return this.#answer(request, conversation, 202);
    }
    throw new Refused(404, "not_found");
  }

  #messageKey(owner: readonly [string, string], messageId: string): string {
    return JSON.stringify([owner[0], owner[1], messageId]);
  }

  /** A retried message returns its conversation; a reused ID with new content conflicts. */
  #replayed(owner: readonly [string, string], message: Message): string | undefined {
    const known = this.store.messageIds.get(this.#messageKey(owner, message.id));
    if (known === undefined) return undefined;
    const separator = known.indexOf(":");
    const conversationId = known.slice(0, separator);
    const knownDigest = known.slice(separator + 1);
    if (knownDigest !== digest(JSON.stringify(plain(message)))) {
      throw new Refused(409, "message_id_conflict");
    }
    return conversationId;
  }

  async #receive(
    conversation: StoredConversation,
    session: IssuedSession,
    message: Message,
  ): Promise<void> {
    const incoming = plain(message);
    this.store.messageIds.set(
      this.#messageKey(conversation.owner, message.id),
      `${conversation.conversationId}:${digest(JSON.stringify(incoming))}`,
    );
    if (session.accountId !== undefined) conversation.accountId = session.accountId;
    this.#event(conversation, { type: "message", message: { ...incoming, role: "user" } });
    if (conversation.responder === "human") return;
    const agent = firstContribution(this.reactor, CompanyAgents, "company agent");
    const replies = await agent.respond({
      conversationId: conversation.conversationId,
      ...(message.text === undefined ? {} : { text: message.text }),
      ...(message.data === undefined ? {} : { data: message.data }),
      sender: message.sender,
      ...(session.accountId === undefined ? {} : { accountId: session.accountId }),
      scopes: session.scopes,
      clientId: session.clientId,
      isDirect: conversation.parentId !== undefined,
    });
    for (const reply of replies) this.#reply(conversation, session, reply);
    conversation.status = "idle";
  }

  #reply(conversation: StoredConversation, session: IssuedSession, reply: Reply): void {
    if (reply.authorization !== undefined) {
      const [error, scope] = reply.authorization;
      this.#event(conversation, { type: "authorization", error, scope });
      return;
    }
    if (reply.userRequested !== undefined) {
      this.#event(conversation, { type: "user_requested", reason: reply.userRequested });
      return;
    }
    const message: Record<string, unknown> = {
      id: this.#id("msg"),
      sender: "agent",
      role: "company",
    };
    if (reply.text !== undefined) message.text = reply.text;
    if (reply.data !== undefined) message.data = reply.data;
    if (reply.operation !== undefined && session.accountId !== undefined) {
      if (this.extensions.get(session.clientId)?.has("operations")) {
        message.operation = this.#propose(session, reply);
      }
    }
    if (Object.keys(message).length > 3) this.#event(conversation, { type: "message", message });
  }

  #close(conversation: StoredConversation): void {
    if (conversation.status === "closed") return;
    if (conversation.directChild !== undefined) {
      this.#close(this.store.conversations.get(conversation.directChild)!);
    }
    conversation.status = "closed";
    this.#state(conversation);
    if (conversation.parentId !== undefined) {
      const parent = this.store.conversations.get(conversation.parentId)!;
      delete parent.directChild;
      this.#event(parent, {
        type: "direct_closed",
        conversation_id: conversation.conversationId,
      });
    }
  }

  #receipt(conversation: StoredConversation, status: number): CompanyResponse {
    return {
      status,
      body: {
        conversation_id: conversation.conversationId,
        status: conversation.status,
        responder: conversation.responder,
      },
      headers: {},
    };
  }

  #answer(
    request: CompanyRequest,
    conversation: StoredConversation,
    status: number,
  ): CompanyResponse {
    const query = pairs(new URL(request.url).search);
    if ("wait" in query || "cursor" in query) {
      return this.#pageResponse(request, conversation, status);
    }
    return this.#receipt(conversation, status);
  }

  #pageResponse(
    request: CompanyRequest,
    conversation: StoredConversation,
    status: number,
  ): CompanyResponse {
    const cursor = pairs(new URL(request.url).search).cursor;
    const events = this.#after(conversation, cursor);
    const pageEvents = events.slice(0, PAGE);
    const more = events.length > PAGE;
    const last = pageEvents.at(-1)?.id ?? cursor ?? startCursor(conversation);
    return {
      status,
      body: {
        conversation_id: conversation.conversationId,
        events: pageEvents.map((event) => event.payload),
        cursor: last,
        has_more: more,
        status: conversation.status,
        responder: conversation.responder,
      },
      headers: {},
    };
  }

  /** Retention: drop all but the last `keep` events; their cursors expire (§7.5). */
  forgetEvents(conversationId: string, options: { readonly keep?: number } = {}): void {
    const conversation = this.store.conversations.get(conversationId);
    if (conversation === undefined) throw new Error("unknown conversation");
    const cut = Math.max(conversation.events.length - (options.keep ?? 0), 0);
    for (const event of conversation.events.splice(0, cut)) conversation.forgotten.add(event.id);
  }

  #after(conversation: StoredConversation, cursor: string | undefined): StoredEvent[] {
    if (cursor === undefined || cursor === startCursor(conversation)) {
      return [...conversation.events];
    }
    if (conversation.forgotten.has(cursor)) throw new Refused(410, "cursor_expired");
    const index = conversation.events.findIndex((event) => event.id === cursor);
    if (index < 0) throw new Refused(400, "invalid_cursor");
    return conversation.events.slice(index + 1);
  }

  #stream(conversation: StoredConversation, lastEventId: string | undefined): CompanyResponse {
    const events = this.#after(conversation, lastEventId || undefined);
    const encoder = new TextEncoder();
    async function* frames(): AsyncGenerator<Uint8Array> {
      yield encoder.encode(": poppy\n\n");
      for (const event of events) {
        const message = event.payload.message;
        if (isObject(message) && message.role === "company" && message.text) {
          const full = String(message.text);
          const half = full.slice(0, Math.max(1, Math.floor(full.length / 2)));
          const delta = { message_id: message.id, text: half };
          yield encoder.encode(`event: text-delta\ndata: ${JSON.stringify(delta)}\n\n`);
        }
        yield encoder.encode(`id: ${event.id}\ndata: ${JSON.stringify(event.payload)}\n\n`);
      }
    }
    return {
      status: 200,
      headers: { "Content-Type": "text/event-stream", ...NO_STORE },
      stream: frames(),
    };
  }

  // Operations ----------------------------------------------------------------------

  /** A proposal as it goes on the wire: the same members, in the same order, as Python. */
  #propose(session: IssuedSession, reply: Reply): Operation {
    const proposal = reply.operation!;
    const owner = [session.clientId, session.pairwiseUserId] as const;
    for (const stored of this.store.operations.values()) {
      // The same action through another channel is the same operation (Operations §4).
      this.#expire(stored);
      if (
        sameOwner(stored.owner, owner) &&
        stored.accountId === session.accountId &&
        stored.action === proposal.action &&
        stored.operation.state === "proposed" &&
        stored.operation.summary === proposal.summary &&
        sameJson(stored.operation.terms, proposal.terms)
      ) {
        return stored.operation;
      }
    }
    const operationId = this.#id("op");
    const operation = {
      operation_id: operationId,
      revision: 1,
      state: "proposed",
      summary: proposal.summary,
      terms: { ...proposal.terms },
      expires_at: isoZ(this.#later(this.config.operationLifetimeSeconds)),
      user_approval_required: proposal.userApprovalRequired ?? false,
      url: `${this.config.base}/operations/${operationId}`,
      confirmation: null,
      result: null,
    } as unknown as Operation;
    this.store.operations.set(operation.operation_id, {
      operation,
      action: proposal.action,
      owner,
      accountId: session.accountId!,
      performed: false,
    });
    return operation;
  }

  /** The company changes a proposal's terms: a new revision, the old one unconfirmable. */
  revise(
    operationId: string,
    changes: { readonly summary: string; readonly terms: Readonly<Record<string, unknown>> },
  ): Operation {
    const stored = this.store.operations.get(operationId);
    if (stored === undefined) throw new Error("unknown operation");
    if (stored.operation.state !== "proposed") {
      throw new Error("only a proposed operation can be revised");
    }
    stored.operation = {
      ...stored.operation,
      revision: stored.operation.revision + 1,
      summary: changes.summary,
      terms: { ...changes.terms },
      expires_at: isoZ(this.#later(this.config.operationLifetimeSeconds)),
    };
    return stored.operation;
  }

  /** The company found out how an operation left `in_progress` ended. */
  settle(
    operationId: string,
    result: OperationResult,
    options: { readonly succeeded: boolean },
  ): Operation {
    const stored = this.store.operations.get(operationId);
    if (stored === undefined) throw new Error("unknown operation");
    if (stored.operation.state !== "in_progress") {
      throw new Error("only an operation in progress can be settled");
    }
    stored.performed = options.succeeded || stored.performed;
    stored.operation = {
      ...stored.operation,
      state: options.succeeded ? "succeeded" : "failed",
      result: resultJson(result),
    } as unknown as Operation;
    return stored.operation;
  }

  async #operationRoute(
    request: CompanyRequest,
    method: string,
    path: string,
  ): Promise<CompanyResponse> {
    const parts = path.split("/");
    const operationId = parts[3] ?? "";
    const action = parts[4] ?? "";
    const [, session] = await this.#caller(request);
    if (!this.extensions.get(session.clientId)?.has("operations")) {
      throw new Refused(403, "extension_required", { extension: "operations" });
    }
    const stored = this.store.operations.get(operationId);
    if (
      stored === undefined ||
      !sameOwner(stored.owner, [session.clientId, session.pairwiseUserId]) ||
      stored.accountId !== session.accountId
    ) {
      throw new Refused(404, "operation_not_found");
    }
    this.#expire(stored);
    if (method === "GET" && !action) return operationResponse(stored);
    if (method === "POST" && action === "cancel") {
      if (stored.operation.state === "proposed") {
        stored.operation = {
          ...stored.operation,
          state: "cancelled",
          result: { summary: "Nothing was changed.", data: null },
        } as unknown as Operation;
      }
      // In progress, it stays so until the company knows whether it stopped (§7).
      return operationResponse(stored);
    }
    if (method === "POST" && action === "confirm") {
      return this.#confirm(request, session, stored);
    }
    throw new Refused(404, "not_found");
  }

  #expire(stored: StoredOperation): void {
    const operation = stored.operation;
    if (
      operation.state === "proposed" &&
      operation.expires_at &&
      this.#now() >= new Date(operation.expires_at)
    ) {
      stored.operation = {
        ...operation,
        state: "expired",
        result: { summary: "Nothing was changed; the proposal expired.", data: null },
      } as unknown as Operation;
    }
  }

  async #confirm(
    request: CompanyRequest,
    session: IssuedSession,
    stored: StoredOperation,
  ): Promise<CompanyResponse> {
    const body = parseJsonStrict(text(request.body));
    const revision = isObject(body) ? body.revision : undefined;
    const approvedBy = isObject(body) ? body.approved_by : undefined;
    const operation = stored.operation;
    if (this.config.writeScopes.some((scope) => !session.scopes.includes(scope))) {
      throw new Refused(403, "insufficient_scope", { scope: this.config.writeScopes.join(" ") });
    }
    if (operation.state !== "proposed") {
      // At most once: a retried or late confirmation returns the record unchanged.
      return { status: 200, body: operation, headers: {} };
    }
    if (revision !== operation.revision) {
      throw new Refused(409, "terms_changed", { operation });
    }
    if (approvedBy !== "user" && approvedBy !== "standing_permission") {
      throw new Refused(400, "invalid_request");
    }
    if (approvedBy === "standing_permission" && operation.user_approval_required) {
      throw new Refused(403, "user_approval_required");
    }
    stored.operation = {
      ...operation,
      state: "in_progress",
      confirmation: {
        revision: operation.revision,
        approved_by: approvedBy,
        confirmed_at: isoZ(this.#now()),
      },
      expires_at: null,
    } as unknown as Operation;
    const executors = this.reactor
      .getContributions(OperationExecutors)
      .map((contribution) => contribution.value)
      .filter((executor) => executor.action === stored.action);
    const executor = executors[0];
    if (executors.length !== 1 || executor === undefined) {
      // Nobody can perform it: it stays in progress rather than claim a failure.
      return operationResponse(stored);
    }
    let result: OperationResult;
    try {
      result = await executor.perform(parseOperation(stored.operation), stored.accountId);
    } catch (error) {
      if (error instanceof OperationFailed) {
        // Failed partway: the result says every change that was made (Operations §6).
        stored.performed = true;
        stored.operation = {
          ...stored.operation,
          state: "failed",
          result: resultJson(error.result),
        } as unknown as Operation;
        return operationResponse(stored);
      }
      if (error instanceof OperationOutcomeUnknown) {
        // Never `failed` while it may have taken effect: it stays in progress.
        return operationResponse(stored);
      }
      throw error;
    }
    stored.performed = true;
    stored.operation = {
      ...stored.operation,
      state: "succeeded",
      result: resultJson(result),
    } as unknown as Operation;
    return operationResponse(stored);
  }
}

/** An operation's answer: `Retry-After` while it is in progress. */
function operationResponse(stored: StoredOperation): CompanyResponse {
  const headers: Record<string, string> =
    stored.operation.state === "in_progress" ? { "Retry-After": "5" } : {};
  return { status: 200, body: stored.operation, headers };
}

/** A result as Python serializes it: `data` is `null` when there is none. */
function resultJson(result: OperationResult): Record<string, unknown> {
  return { ...result, summary: result.summary, data: result.data ?? null };
}

/** Equal JSON values, whatever the member order (Python's `==` on dicts). */
function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  if (keys.length !== Object.keys(right).length) return false;
  return keys.every((key) => key in right && sameJson(left[key], right[key]));
}

function startCursor(conversation: StoredConversation): string {
  return `start_${conversation.conversationId}`;
}

/** A consent page: never framed, never cached (upstream guides, consent pages). */
function page(status: number, body: string): CompanyResponse {
  return {
    status,
    body: `<!doctype html><meta charset=utf-8><title>Sign in</title>${body}`,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Frame-Options": "DENY",
      "Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'",
      ...NO_STORE,
    },
  };
}
