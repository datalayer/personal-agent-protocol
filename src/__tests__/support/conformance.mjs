/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// The conformance cases as the TypeScript personal agent: the port of
// personal_agent_protocol/conformance.py, run against any company over real HTTPS.
//
// Each case is described by a shared fixture (protocol/fixtures/conformance/*.json) and
// uses the TypeScript SDK where the Python runner uses the Python one. What the agent
// cannot do itself, the driver does (the user approving Device Sign-In; a demo
// company's operator revising an operation, forgetting events, moving the clock).
// A case a side cannot run is skipped, never passed. The report has the Python runner's
// JSON shape (schema 1).
import { createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";

import { SignJWT, calculateJwkThumbprint, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK } from "jose";

import {
  APPROVAL_HEADER,
  ApiClient,
  ApiError,
  AuthorizationStateStores,
  BrowserHandoffs,
  BrowserJoins,
  BrowserSessionClient,
  Clocks,
  ConversationClient,
  DPOP_ALGORITHM,
  DPOP_HEADER,
  DPOP_NONCE_HEADER,
  DPOP_PROOF_TYPE,
  DelegatedSessionSigner,
  DeviceSignInClient,
  DirectSignInClient,
  DpopProvers,
  OperatorSigners,
  OPERATOR_SIGNATURE_REFUSED,
  SIGNATURE_AGENT_HEADER,
  SIGNATURE_HEADER,
  SIGNATURE_INPUT_HEADER,
  WEB_BOT_AUTH_TAG,
  WebBotAuthSigner,
  FeedbackClient,
  InMemoryDelegatedKeys,
  McpClient,
  McpError,
  OPERATIONS_VERSION,
  OperationsClient,
  PROTOCOL_PROFILE,
  PapSession,
  PersonalAgentProtocolError,
  RefreshTokenClient,
  SESSION_JWT_ALGORITHM,
  SESSION_JWT_TYPE,
  SESSION_HEADER,
  SecretValue,
  ServiceTokens,
  SessionClient,
  SessionFetchClient,
  SessionSigners,
  Signers,
  TokenStores,
  TransportError,
  approvalHeader,
  buildPapReactor,
  challengeParameters,
  companyIdentifier,
  conversationEndpoint,
  delegationClaims,
  discoverCompany,
  dpopProofClaims,
  feedbackEndpoint,
  fetchMcpServerMetadata,
  firstContribution,
  jwkThumbprint,
  mcpApi,
  newDpopKey,
  newOperatorKey,
  operatorDirectory,
  operatorKeyFrom,
  signOperatorRequest,
  offersDevice,
  offersDirect,
  openapiUrl,
  operationsNegotiated,
  parseClientMetadata,
  accessTokenFromResponse,
  requireOauth,
  serviceResource,
  sessionHeaders,
  sessionJwtClaims,
  staleResourceMetadata,
} from "../../../lib/index.js";
import { JoseSigner } from "../../../lib/server.js";
import { ControlledBrowser } from "./controlled-browser.mjs";

const SUITES = ["protocol", "security", "lifecycle", "conversations", "operations", "dpop", "operator", "no-issuer"];
const CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const DAY_SECONDS = 24 * 60 * 60;

const suiteDocument = (suite) =>
  JSON.parse(readFileSync(new URL(`../../../protocol/fixtures/conformance/${suite}.json`, import.meta.url), "utf8"));

/**
 * The fixture cases of one world the company is tested on (no `check`: those the SDK decides
 * alone). `world` names the company's configuration the cases need (`worldConfig`); `undefined`
 * is the default world.
 */
export function companyCases(world) {
  const cases = [];
  for (const suite of SUITES) {
    for (const raw of suiteDocument(suite).cases) {
      if (raw.check === undefined && raw.world === world) cases.push({ ...raw, suite, mutation: raw.mutation ?? {} });
    }
  }
  return cases;
}

/** The company configuration a world names, from its suite's `worlds`, in TypeScript's spelling. */
export function worldConfig(world) {
  for (const suite of SUITES) {
    const named = suiteDocument(suite).worlds?.[world];
    if (named !== undefined) {
      const camel = (name) => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
      return Object.fromEntries(Object.entries(named).map(([name, value]) => [camel(name), value]));
    }
  }
  throw new Error(`no conformance world ${world}`);
}

export class SkipCase extends Error {}
export class ConformanceFailure extends Error {}

export function check(condition, message) {
  if (!condition) throw new ConformanceFailure(message);
}

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const segment = (value) => b64(JSON.stringify(value));
const opaque = (prefix) => `${prefix}_${b64(randomBytes(16))}`;
const strongRandom = (length) => new Uint8Array(randomBytes(length));

/** Expect a refusal from `promise`; anything else fails the case. */
async function refused(promise, what) {
  try {
    await promise;
  } catch (error) {
    if (error instanceof PersonalAgentProtocolError) return error;
    throw error;
  }
  throw new ConformanceFailure(`expected the company to refuse (${what})`);
}

const textOf = (response) => response.clone().text();

async function errorOf(response) {
  try {
    const payload = JSON.parse(await textOf(response));
    return typeof payload?.error === "string" ? payload.error : undefined;
  } catch {
    return undefined;
  }
}

async function expectRefusal(response, status, error, what) {
  check(response.status === status, `${what}: expected HTTP ${status}, got ${response.status}`);
  if (error !== undefined && error !== null) {
    const actual = await errorOf(response);
    check(actual === error, `${what}: expected ${error}, got ${actual}`);
  }
}

/**
 * A personal agent's identity from its private JWK: `client_id`, published documents,
 * and the key the forged assertions are signed with.
 */
export async function identityFrom({ domain, name, privateJwk, operatorJwk, extensions = ["operations"], kid = "key-1" }) {
  const privateKey = await importJWK(privateJwk, "ES256");
  const { d: _d, ...publicJwk } = privateJwk;
  const clientId = `https://${domain}/agent.json`;
  const operatorKey = operatorJwk === undefined ? await newOperatorKey() : await operatorKeyFrom(operatorJwk);
  const jwks = { keys: [{ kty: "EC", crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y, kid, use: "sig", alg: "ES256" }] };
  const metadata = {
    client_id: clientId,
    client_name: name,
    jwks_uri: `https://${domain}/jwks.json`,
    redirect_uris: [`https://${domain}/oauth/callback`],
    token_endpoint_auth_method: "private_key_jwt",
    extensions: Object.fromEntries(extensions.map((extension) => [extension, { version: extension === "operations" ? OPERATIONS_VERSION : "1" }])),
  };
  return {
    domain,
    name,
    kid,
    extensions,
    clientId,
    privateKey,
    jwks,
    metadata,
    // The operator's key, no key of `jwks_uri`, and where it is published (§5.3).
    operatorKey,
    operatorUrl: `https://${domain}/operator-keys.json`,
    documents: {
      "/agent.json": metadata,
      "/jwks.json": jwks,
      "/operator-keys.json": operatorDirectory([operatorKey]),
    },
  };
}

/** A stranger's identity at the same domain and `kid`: its key isn't the published one. */
async function strangerOf(identity) {
  const pair = await generateKeyPair("ES256", { extractable: true });
  return identityFrom({ domain: identity.domain, name: "Stranger", kid: identity.kid, privateJwk: await exportJWK(pair.privateKey) });
}

/**
 * A personal agent: its identity, Reactor host, and SDK clients, and, when given a
 * `browserFetch`, its own controlled browser (`pap.browserJoin`, its own cookie jar).
 */
export class Agent {
  constructor(identity, { fetch, clock, browserFetch }) {
    this.identity = identity;
    this.fetch = fetch;
    this.browser = browserFetch === undefined ? undefined : new ControlledBrowser(browserFetch);
    this.tokens = new Map();
    this.state = new Map();
    this.browserFetch = browserFetch;
    this.delegatedKeys = new InMemoryDelegatedKeys();
    // The user's browser: the authorization URLs Direct Sign-In opened, for the driver.
    this.userBrowser = { urls: [], open: async (url) => void this.userBrowser.urls.push(url.reveal()) };
    this.reactor = buildPapReactor({ fetch }, [
      {
        name: `${identity.domain}-conformance`,
        contributes: [
          { point: Clocks, value: clock, options: { id: "clock" } },
          {
            point: Signers,
            value: new JoseSigner({ privateKey: identity.privateKey, algorithm: "ES256", keyId: identity.kid }),
            options: { id: "agent-key" },
          },
          {
            point: OperatorSigners,
            value: new WebBotAuthSigner(identity.operatorKey, {
              signatureAgent: identity.operatorUrl,
              now: () => clock.now(),
            }),
            options: { id: "operator-key" },
          },
          {
            point: SessionSigners,
            value: new DelegatedSessionSigner({
              custody: this.delegatedKeys,
              signer: new JoseSigner({ privateKey: identity.privateKey, algorithm: "ES256", keyId: identity.kid }),
              now: () => clock.now(),
            }),
            options: { id: "delegated-keys" },
          },
          {
            point: TokenStores,
            value: {
              put: async (reference, token) => void this.tokens.set(reference, token),
              get: async (reference) => this.tokens.get(reference),
              delete: async (reference) => void this.tokens.delete(reference),
            },
            options: { id: "vault" },
          },
          {
            point: AuthorizationStateStores,
            value: {
              put: async (reference, value) => void this.state.set(reference, value),
              take: async (reference) => {
                const value = this.state.get(reference);
                this.state.delete(reference);
                return value;
              },
            },
            options: { id: "state" },
          },
          { point: BrowserHandoffs, value: this.userBrowser, options: { id: "user-browser" } },
          ...(this.browser === undefined
            ? []
            : [{ point: BrowserJoins, value: this.browser, options: { id: "controlled-browser" } }]),
        ],
      },
    ]);
    this.transport = new SessionFetchClient({ reactor: this.reactor, fetch });
    this.sessions = new SessionClient({ reactor: this.reactor, fetch });
    this.device = new DeviceSignInClient({ reactor: this.reactor, fetch });
    this.accounts = new RefreshTokenClient({ reactor: this.reactor, fetch });
    this.api = new ApiClient({ transport: this.transport });
    this.conversations = new ConversationClient({ reactor: this.reactor, transport: this.transport });
    this.operations = new OperationsClient({ reactor: this.reactor, sleep: async () => {} });
  }
}

/** The target company and the personal agent the suite plays. */
export class Context {
  constructor({ baseUrl, identity, otherIdentity, fetch, browserFetch, driver, scenario, clock, tenantId = "pap-conformance" }) {
    const url = new URL(baseUrl);
    this.baseUrl = url.origin;
    this.domain = url.hostname;
    this.fetch = fetch;
    this.driver = driver;
    this.scenario = scenario;
    this.clock = clock;
    this.tenantId = tenantId;
    this.agent = new Agent(identity, { fetch, clock, browserFetch });
    this.otherIdentity = otherIdentity;
    this.other = undefined;
    this.discovered = undefined;
  }

  // The company ---------------------------------------------------------------------

  async company() {
    if (this.discovered === undefined) {
      this.discovered = await discoverCompany(this.domain, { reactor: this.agent.reactor });
      // API paths resolve at the company's OpenAPI API (its url's origin), not discovery's.
      const api = (this.discovered.document.apis ?? []).find((item) => item.type === "openapi");
      if (api !== undefined) this.apiBase = new URL(api.url).origin;
    }
    return this.discovered;
  }

  async metadata() {
    const company = await this.company();
    if (company.oauthMetadata === undefined) throw new SkipCase("the company offers no Sessions (no auth)");
    return company.oauthMetadata;
  }

  async conversationsEndpoint() {
    const endpoint = conversationEndpoint((await this.company()).document);
    if (endpoint === undefined) throw new SkipCase("the company lists no poppy conversation protocol");
    return endpoint;
  }

  async operationsNegotiated() {
    const metadata = parseClientMetadata(this.agent.identity.metadata);
    if (!operationsNegotiated((await this.company()).document, metadata)) {
      throw new SkipCase("operations v2 is not negotiated with this company");
    }
  }

  /** An API path at the company's API (its OpenAPI `url`'s origin), else its origin. */
  url(path) {
    return `${this.apiBase ?? this.baseUrl}${path}`;
  }

  // Capabilities --------------------------------------------------------------------

  require(...capabilities) {
    const missing = capabilities.filter((name) => !this.driver.capabilities.has(name));
    if (missing.length) throw new SkipCase(`the driver cannot ${missing.join(", ")}`);
  }

  proposal(kind) {
    const proposal = this.scenario.proposals?.[kind];
    if (proposal === undefined) throw new SkipCase(`the scenario has no ${kind} proposal`);
    return proposal;
  }

  otherAgent() {
    this.require("second_identity");
    this.other ??= new Agent(this.otherIdentity, { fetch: this.fetch, clock: this.clock });
    return this.other;
  }

  now() {
    return this.clock.now();
  }

  // Users and Sessions --------------------------------------------------------------

  /** A fresh pairwise User ID, so no case sees another's state. */
  newUser() {
    return opaque("usr_conf");
  }

  /** Another browser, with a cookie jar of its own, on the runner's browser network. */
  newBrowser() {
    if (this.agent.browserFetch === undefined) throw new SkipCase("the runner was given no browser of its own");
    return new ControlledBrowser(this.agent.browserFetch);
  }

  async session(user, agent = this.agent) {
    return agent.sessions.start({
      clientId: agent.identity.clientId,
      pairwiseUserId: user,
      issuer: companyIdentifier(await this.company()),
      tenantId: this.tenantId,
    });
  }

  /** Device Sign-In, the user approving on the company's page through the driver. */
  async signIn(user, session, { scopes, granted, account, agent = this.agent } = {}) {
    const metadata = await this.metadata();
    if (!offersDevice(metadata)) {
      if (this.driver.capabilities.has("direct_sign_in") && offersDirect(metadata)) {
        return this.#directSignIn(agent, session, { scopes, granted, account });
      }
      throw new SkipCase("the company offers no Device Sign-In");
    }
    const started = await agent.device.begin({
      deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: agent.identity.clientId,
      scopes: scopes ?? this.scenario.scopes,
      tenantId: this.tenantId,
      organization: (await this.company()).document.organization,
      protectedResources: metadata.protected_resources,
      dpopSigningAlgs: metadata.dpop_signing_alg_values_supported,
    });
    await this.driver.approveDevice(started.userCode, { account: account ?? this.driver.accounts[0], scopes: granted });
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await this.driver.wait(started.pollInterval);
      const polled = await agent.device.poll(started.reference);
      if (polled.status === "complete") {
        check(polled.token !== undefined && polled.refreshTokenReference !== undefined, "sign-in returns its token");
        return { session, token: polled.token, reference: polled.refreshTokenReference };
      }
    }
    throw new ConformanceFailure("Device Sign-In did not complete after approval");
  }

  /** Direct Sign-In, the driver playing the user on the company's consent page. */
  async #directSignIn(actor, session, { scopes, granted, account }) {
    const metadata = await this.metadata();
    const client = new DirectSignInClient({ reactor: actor.reactor, fetch: this.fetch });
    await client.begin({
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: actor.identity.clientId,
      redirectUri: actor.identity.metadata.redirect_uris[0],
      scopes: scopes ?? this.scenario.scopes,
      tenantId: this.tenantId,
      dpopSigningAlgs: metadata.dpop_signing_alg_values_supported,
    });
    const callbackUrl = await this.driver.approveAuthorization(actor.userBrowser.urls.at(-1), {
      account: account ?? this.driver.accounts[0],
      scopes: granted,
    });
    const done = await client.complete({ callbackUrl });
    check(done.refreshTokenReference !== undefined, "sign-in returns its refresh token");
    return { session, token: done.token, reference: done.refreshTokenReference };
  }

  async accountContext(_user, agent = this.agent) {
    const metadata = await this.metadata();
    return {
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: agent.identity.clientId,
      tenantId: this.tenantId,
      ...(metadata.revocation_endpoint ? { revocationEndpoint: metadata.revocation_endpoint } : {}),
      dpopSigningAlgs: metadata.dpop_signing_alg_values_supported,
    };
  }

  /** The refresh token behind `reference`. */
  refreshToken(reference) {
    const value = this.agent.tokens.get(reference);
    check(value instanceof SecretValue, "the refresh token is stored behind its reference");
    return value;
  }

  // Raw requests (for what the SDK would never send) -----------------------------------

  /** One request exactly as given: no cookies, no redirects followed. */
  send(method, url, { headers = {}, body } = {}) {
    return this.fetch(url, { method, headers, ...(body === undefined ? {} : { body }), redirect: "manual" });
  }

  /** The headers of one request in `session`: its Session JWT, token, and any proof. */
  auth(session, method, url, token, { agent = this.agent, dpopNonce } = {}) {
    return sessionHeaders(agent.reactor, method, url, { session, token, dpopNonce });
  }

  jwtRequest(session, method, url, token) {
    const accessToken = token instanceof SecretValue ? token : token?.accessToken;
    return {
      method,
      url,
      tenantId: session.tenantId,
      issuer: session.issuer,
      clientId: session.clientId,
      sid: session.sid,
      sub: session.sub,
      ...(session.agentId === undefined ? {} : { agentId: session.agentId }),
      ...(accessToken === undefined ? {} : { accessToken }),
    };
  }

  /** A Session JWT the SDK would never send: real keys, one thing wrong (§5.2). */
  async forgedSessionJwt(session, method, url, { token, mutation = {} } = {}) {
    const identity = this.agent.identity;
    const clockNow = this.now().getTime();
    const issuedAt = new Date(clockNow + (mutation.iat_offset ?? 0) * 1000);
    const claims = await sessionJwtClaims(this.jwtRequest(session, method, url, token), { issuedAt, randomBytes: strongRandom });
    if ("aud" in mutation) {
      claims.aud = mutation.aud === "token_endpoint" ? (await this.metadata()).token_endpoint : mutation.aud;
    }
    if ("htm" in mutation) claims.htm = mutation.htm;
    if ("htu" in mutation) claims.htu = mutation.htu;
    if ("ath" in mutation) claims.ath = mutation.ath;
    if (mutation.drop_ath) delete claims.ath;
    const delegated = await generateKeyPair("ES256", { extractable: true });
    const { kty, crv, x, y } = await exportJWK(delegated.publicKey);
    const publicKey = { kty, crv, x, y };
    const lifetime = mutation.delegation_lifetime ?? 3600;
    const body = delegationClaims({
      clientId: identity.clientId,
      publicKey,
      issuedAt: new Date(clockNow + (mutation.delegation_iat_offset ?? 0) * 1000),
      lifetimeSeconds: Math.min(lifetime, DAY_SECONDS),
      randomBytes: strongRandom,
    });
    if (lifetime > DAY_SECONDS) body.exp = body.iat + lifetime;
    if (mutation.delegation_extra) Object.assign(body, mutation.delegation_extra);
    const signedBy = async (privateKey) =>
      (await new JoseSigner({ privateKey, algorithm: "ES256", keyId: identity.kid }).sign(body, { purpose: "delegation" })).reveal();
    let delegation = await signedBy(identity.privateKey);
    if (mutation.delegation_signer === "stranger") {
      delegation = await signedBy((await generateKeyPair("ES256")).privateKey);
    }
    if (mutation.delegation_typ) {
      delegation = await new SignJWT(body)
        .setProtectedHeader({ alg: "ES256", typ: mutation.delegation_typ, kid: identity.kid })
        .sign(identity.privateKey);
    }
    const header = {
      typ: mutation.typ ?? SESSION_JWT_TYPE,
      kid: mutation.kid ?? (await calculateJwkThumbprint(publicKey, "sha256")),
      pap_dlg: delegation,
    };
    if (mutation.no_delegation) {
      // Signed directly with a key from `jwks_uri`, which never signs a Session JWT.
      const { pap_dlg: _gone, ...direct } = header;
      return new SignJWT(claims).setProtectedHeader({ ...direct, kid: identity.kid, alg: "ES256" }).sign(identity.privateKey);
    }
    if (mutation.alg === "none") return `${segment({ ...header, alg: "none" })}.${segment(claims)}.`;
    return new SignJWT(claims).setProtectedHeader({ ...header, alg: SESSION_JWT_ALGORITHM }).sign(delegated.privateKey);
  }

  claims({ subject, audience, lifetime = 60, shift = 0 }) {
    const issued = Math.floor(this.now().getTime() / 1000) + shift;
    return {
      iss: this.agent.identity.clientId,
      sub: subject,
      aud: audience,
      iat: issued,
      exp: issued + lifetime,
      jti: b64(randomBytes(16)),
    };
  }

  /** Sign assertion claims with the agent's key (or forge an unsigned or odd one). */
  async assertion(claims, { identity = this.agent.identity, algorithm = "ES256", headers = {} } = {}) {
    const header = { typ: "JWT", kid: identity.kid, ...headers };
    if (algorithm === "none") return `${segment({ ...header, alg: "none" })}.${segment(claims)}.`;
    if (algorithm === "HS256") {
      // The agent's public key used as an HMAC secret: algorithm confusion.
      const input = `${segment({ ...header, alg: "HS256" })}.${segment(claims)}`;
      const mac = createHmac("sha256", JSON.stringify(identity.jwks.keys[0])).update(input).digest();
      return `${input}.${b64(mac)}`;
    }
    const token = await new SignJWT(claims).setProtectedHeader({ ...header, alg: "ES256" }).sign(identity.privateKey);
    if (algorithm === "PS384") {
      const [, payload, signature] = token.split(".");
      return `${segment({ ...header, alg: "PS384" })}.${payload}.${signature}`;
    }
    return token;
  }

  /** A raw token request: no Session header goes to an OAuth endpoint (§5.2). */
  async tokenRequest(form, { dpop } = {}) {
    const endpoint = (await this.metadata()).token_endpoint;
    return this.send("POST", endpoint, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        ...(dpop === undefined ? {} : { [DPOP_HEADER]: dpop }),
      },
      body: new URLSearchParams(form).toString(),
    });
  }

  async clientForm(identity = this.agent.identity) {
    const metadata = await this.metadata();
    const claims = { ...this.claims({ subject: identity.clientId, audience: metadata.issuer }), iss: identity.clientId };
    return {
      client_id: identity.clientId,
      client_assertion_type: CLIENT_ASSERTION,
      client_assertion: await this.assertion(claims, { identity }),
    };
  }
}

export const CASES = {};

function caseFor(...ids) {
  return (run) => {
    for (const id of ids) {
      if (Object.hasOwn(CASES, id)) throw new Error(`conformance case ${id} is registered twice`);
      CASES[id] = run;
    }
  };
}

const refreshForm = async (ctx, reference, identity) => ({
  grant_type: "refresh_token",
  refresh_token: ctx.refreshToken(reference).reveal(),
  ...(await ctx.clientForm(identity)),
});

// Protocol ------------------------------------------------------------------------------

caseFor("protocol.extension-required-company")(async (ctx) => {
  const other = ctx.otherAgent();
  check(!("operations" in other.identity.metadata.extensions), "the second identity lists no operations");
  const proposal = ctx.proposal("user");
  const user = ctx.newUser();
  const session = await ctx.session(user, other);
  const signed = await ctx.signIn(user, session, { agent: other });
  const error = await refused(
    other.api.call(proposal.method, ctx.url(proposal.path), { session: signed.session, token: signed.token, body: proposal.body ?? {} }),
    "an operation without the extension",
  );
  check(error.code === "extension_required", `expected extension_required, got ${error.code}`);
  check(error.statusCode === 403, "extension_required is HTTP 403");
});

// Security: assertions ------------------------------------------------------------------

caseFor(
  "security.client-assertion-alg-none",
  "security.client-assertion-hs256-public-key",
  "security.client-assertion-ps384-header-on-ec-key",
  "security.client-assertion-embedded-key-ignored",
  "security.client-assertion-bad-audience",
  "security.client-assertion-audience-array",
  "security.client-assertion-token-endpoint-audience",
)(async (ctx, fixture) => {
  const metadata = await ctx.metadata();
  const { mutation } = fixture;
  const clientId = ctx.agent.identity.clientId;
  let audience = mutation.aud ?? metadata.issuer;
  // The token endpoint is not the issuer: refused, compared character for character.
  if (mutation.aud === "token_endpoint") audience = metadata.token_endpoint;
  if (mutation.aud_array) audience = [metadata.issuer, "https://other-company.example"];
  const claims = ctx.claims({ subject: clientId, audience });
  const headers = {};
  let identity;
  if (mutation.signer === "stranger") {
    identity = await strangerOf(ctx.agent.identity);
    if (mutation.embed_jwk) headers.jwk = identity.jwks.keys[0];
  }
  const clientAssertion = await ctx.assertion(claims, {
    ...(identity === undefined ? {} : { identity }),
    algorithm: mutation.alg ?? "ES256",
    headers,
  });
  const response = await ctx.tokenRequest({
    grant_type: "refresh_token",
    refresh_token: "rt_conformance_unknown",
    client_id: clientId,
    client_assertion_type: CLIENT_ASSERTION,
    client_assertion: clientAssertion,
  });
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
  check(!(await textOf(response)).includes(clientAssertion), "a refusal never echoes the assertion");
});

/** A signature that doesn't verify: another JWT's, one bit changed. */
function flip(compact) {
  const signature = compact.slice(compact.lastIndexOf(".") + 1);
  return `${signature[0] !== "A" ? "A" : "B"}${signature.slice(1)}`;
}

caseFor(
  "security.session-jwt-alg-none",
  "security.session-jwt-wrong-signature",
  "security.session-jwt-wrong-typ",
  "security.session-jwt-wrong-kid",
  "security.session-jwt-signed-with-jwks-key",
  "security.session-jwt-expired-delegation",
  "security.session-jwt-delegation-over-24-hours",
  "security.session-jwt-delegation-wrong-typ",
  "security.session-jwt-delegation-stranger-key",
  "security.session-jwt-other-audience",
  "security.session-jwt-token-endpoint-audience",
  "security.session-jwt-method-mismatch",
  "security.session-jwt-url-mismatch",
  "security.session-jwt-stale",
  "security.session-jwt-from-the-future",
  "security.session-jwt-ath-mismatch",
  "security.session-jwt-ath-missing",
  "security.session-jwt-ath-without-token",
)(async (ctx, fixture) => {
  // A Session JWT with one thing wrong: `invalid_session`, HTTP 400, whatever it was (§5.3).
  const { mutation } = fixture;
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const url = ctx.url(ctx.scenario.read_path);
  const headers = await ctx.auth(session, "GET", url, signed.token);
  const control = await ctx.send("GET", url, { headers });
  check(control.status === 200, "a valid Session JWT is accepted");
  const token = mutation.signed_out ? undefined : signed.token;
  let forged = await ctx.forgedSessionJwt(session, "GET", url, { token, mutation });
  if (mutation.tamper_signature) {
    const other = await ctx.auth(session, "GET", url, signed.token);
    forged = [...headers["Poppy-Session"].split(".").slice(0, 2), flip(other["Poppy-Session"])].join(".");
  }
  const sent = { "Poppy-Session": forged };
  if (token !== undefined) sent.Authorization = `Bearer ${token.accessToken.reveal()}`;
  const response = await ctx.send("GET", url, { headers: sent });
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
  check(!(await textOf(response)).includes(forged), "a refusal never echoes the Session JWT");
});

caseFor("security.session-header-missing")(async (ctx, fixture) => {
  // A request with no Session header is refused, and its access token useless (§5.3).
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const url = ctx.url(ctx.scenario.read_path);
  const token = signed.token.accessToken.reveal();
  for (const headers of [{}, { Authorization: `Bearer ${token}` }]) {
    const response = await ctx.send("GET", url, { headers });
    await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
    check(!(await textOf(response)).includes(token), "a refusal never echoes the access token");
  }
});

caseFor("security.session-jwt-replay")(async (ctx, fixture) => {
  // A company MAY refuse a reused `jti` (§5.3); the reference company does.
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const url = ctx.url(ctx.scenario.read_path);
  const headers = await ctx.auth(session, "GET", url, signed.token);
  const first = await ctx.send("GET", url, { headers });
  check(first.status === 200, "the first use is accepted");
  await expectRefusal(await ctx.send("GET", url, { headers }), fixture.expect.status, fixture.expect.error, fixture.id);
});

caseFor("security.session-header-twice")(async (ctx, fixture) => {
  // Exactly one `Poppy-Session` header holding one JWT: two are `invalid_session` (§5.2).
  const session = await ctx.session(ctx.newUser());
  const url = ctx.url(ctx.scenario.read_path);
  const first = await ctx.auth(session, "GET", url);
  const second = await ctx.auth(session, "GET", url);
  const response = await ctx.send("GET", url, { headers: { "Poppy-Session": `${first["Poppy-Session"]}, ${second["Poppy-Session"]}` } });
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
});

caseFor("security.session-sub-stays-the-same")(async (ctx, fixture) => {
  // A known `sid` keeps its `sub` (§5.2, §5.3): another User ID in it is refused.
  const session = await ctx.session(ctx.newUser());
  const url = ctx.url(ctx.scenario.read_path);
  await ctx.send("GET", url, { headers: await ctx.auth(session, "GET", url) });
  const other = new PapSession({
    sid: session.sid,
    sub: ctx.newUser(),
    issuer: session.issuer,
    clientId: session.clientId,
    tenantId: session.tenantId,
  });
  const response = await ctx.send("GET", url, { headers: await ctx.auth(other, "GET", url) });
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
});

caseFor("security.access-token-of-another-agent")(async (ctx, fixture) => {
  // The access token was issued to the same `client_id` as `iss` (§5.3).
  const other = ctx.otherAgent();
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const theirs = await ctx.session(user, other);
  const url = ctx.url(ctx.scenario.read_path);
  const response = await ctx.send("GET", url, { headers: await ctx.auth(theirs, "GET", url, signed.token, { agent: other }) });
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
});

caseFor("security.token-in-url-refused")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const token = signed.token.accessToken.reveal();
  const url = ctx.url(ctx.scenario.read_path);
  const headers = await ctx.auth(session, "GET", url);
  const response = await ctx.send("GET", `${url}?${new URLSearchParams({ access_token: token })}`, { headers });
  // Any refusal will do (§5.6 says only MUST NOT accept): 400 or 401 are both seen.
  check(response.status >= 400 && response.status < 500, `a token in the URL: expected a refusal, got ${response.status}`);
  check(!(await textOf(response)).includes(token), "a refusal never echoes the access token");
});

caseFor("security.authorization-header-without-cookies")(async (ctx) => {
  const session = await ctx.session(ctx.newUser());
  const endpoint = await ctx.conversationsEndpoint();
  const response = await ctx.send("POST", endpoint, {
    headers: { ...(await ctx.auth(session, "POST", endpoint)), "Content-Type": "application/json" },
    body: JSON.stringify({ message: { id: messageId(), author: { type: "agent" }, text: ctx.scenario.greeting } }),
  });
  check(response.status === 201, `served without cookies: got ${response.status}`);
});

caseFor("security.token-responses-not-cached")(async (ctx) => {
  const metadata = await ctx.metadata();
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const issued = await ctx.tokenRequest(await refreshForm(ctx, signed.reference));
  check(issued.status === 200, "the refresh is answered");
  check((issued.headers.get("cache-control") ?? "").includes("no-store"), "a token response is not cached");
  if (metadata.device_authorization_endpoint !== undefined) {
    const codes = await ctx.send("POST", metadata.device_authorization_endpoint, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ scope: ctx.scenario.read_scope, ...(await ctx.clientForm()) }).toString(),
    });
    check(codes.status === 200, "Device Sign-In starts");
    check((codes.headers.get("cache-control") ?? "").includes("no-store"), "a device-code response is not cached");
  }
});

caseFor("security.refusals-disclose-no-credential")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const refresh = ctx.refreshToken(signed.reference);
  const secret = refresh.reveal();
  // The refresh token sent where it does not belong, with a bad client assertion.
  const form = {
    grant_type: "refresh_token",
    refresh_token: secret,
    ...(await ctx.clientForm()),
    client_assertion: await ctx.assertion(ctx.claims({ subject: ctx.agent.identity.clientId, audience: "https://elsewhere.example/t" })),
  };
  const bad = await ctx.tokenRequest(form);
  check(bad.status === 400 || bad.status === 401, "a bad client assertion is refused");
  const text = await textOf(bad);
  for (const value of [secret, form.client_assertion]) check(!text.includes(value), "a token refusal never echoes a credential");
  const url = ctx.url(ctx.scenario.read_path);
  const used = await ctx.send("GET", url, {
    headers: {
      Authorization: `Bearer ${secret}`,
      "Poppy-Session": await ctx.forgedSessionJwt(session, "GET", url, { token: refresh }),
    },
  });
  await expectRefusal(used, 401, "invalid_token", "a refresh token at an API");
  check(!(await textOf(used)).includes(secret), "an API refusal never echoes a credential");
});

// Lifecycle ---------------------------------------------------------------------------

/**
 * What a read says of the request (§7): `served`, `signed_out`, or `invalid_token`.
 *
 * Signed out, a request for the account gets a 401 challenge with `scope` and no error
 * code; an access token that stopped working gets `invalid_token`.
 */
async function probe(ctx, session, token) {
  const url = ctx.url(ctx.scenario.read_path);
  const response = await ctx.send("GET", url, { headers: await ctx.auth(session, "GET", url, token) });
  if (response.status === 200) return "served";
  const challenge = challengeParameters(response.headers.get("www-authenticate") ?? "");
  if (response.status === 401 && !("error" in challenge) && "scope" in challenge) return "signed_out";
  if (response.status === 401 && challenge.error === "invalid_token") return "invalid_token";
  return `http_${response.status}`;
}

caseFor("lifecycle.signed-out-session")(async (ctx) => {
  const session = await ctx.session(ctx.newUser());
  check(session.sid.length >= 22, "a sid has at least 128 random bits");
  check((await probe(ctx, session)) === "signed_out", "a new Session is signed out");
});

caseFor("lifecycle.parallel-sessions")(async (ctx) => {
  const user = ctx.newUser();
  const [first, second] = await Promise.all([ctx.session(user), ctx.session(user)]);
  check(first.sid !== second.sid, "parallel Sessions are distinct");
  const endpoint = await ctx.conversationsEndpoint();
  for (const session of [first, second]) {
    const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), { session });
    check(receipt.conversation_id, "each Session is served");
  }
});

caseFor("lifecycle.signed-out-challenge")(async (ctx) => {
  // An account request with no access token: 401, `scope`, no error code (§7).
  const session = await ctx.session(ctx.newUser());
  const url = ctx.url(ctx.scenario.read_path);
  const response = await ctx.send("GET", url, { headers: await ctx.auth(session, "GET", url) });
  check(response.status === 401, `expected 401, got ${response.status}`);
  const challenge = challengeParameters(response.headers.get("www-authenticate") ?? "");
  check("scope" in challenge && !("error" in challenge), "the challenge names scopes only");
  const error = await refused(ctx.agent.api.call("GET", url, { session }), "a signed-out read");
  check(error.code === "insufficient_scope", "the SDK reads it as insufficient_scope");
});

caseFor("lifecycle.sign-in-scopes")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const granted = [ctx.scenario.read_scope];
  const signed = await ctx.signIn(user, session, { granted });
  check(JSON.stringify(signed.token.scopes) === JSON.stringify(granted), "only what the user approved is granted");
  check((await probe(ctx, session, signed.token)) === "served", "signed in with the token");
  check((await probe(ctx, session)) === "signed_out", "without it, the Session is signed out");
});

caseFor("lifecycle.unknown-scope-refused")(async (ctx) => {
  const metadata = await ctx.metadata();
  if (metadata.device_authorization_endpoint === undefined) throw new SkipCase("no Device Sign-In");
  const error = await refused(
    ctx.agent.device.begin({
      deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: ctx.agent.identity.clientId,
      scopes: ["conformance:not-a-scope"],
      tenantId: ctx.tenantId,
      organization: (await ctx.company()).document.organization,
      protectedResources: metadata.protected_resources,
    }),
    "an unknown scope",
  );
  check(error.code === "invalid_scope", `got ${error.code}`);
});

caseFor("lifecycle.refresh-token-serves-any-session")(async (ctx) => {
  // A refresh token isn't tied to a Session: any of the User's uses its tokens (§4.4, §5.4).
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const fresh = await ctx.session(user);
  const result = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user) });
  check(result.status === "signed_in" && result.token !== undefined, "an access token comes back");
  check((await probe(ctx, fresh, result.token)) === "served", "and works in another Session");
});

caseFor("lifecycle.rotated-token")(async (ctx) => {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const form = await refreshForm(ctx, signed.reference);
  const result = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user) });
  if (!result.rotated) throw new SkipCase("the company does not rotate refresh tokens");
  await expectRefusal(await ctx.tokenRequest(form), 400, "invalid_grant", "a rotated-away refresh token");
  const again = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user) });
  check(again.status === "signed_in", "the stored, rotated token keeps working");
});

caseFor("lifecycle.narrower-scopes")(async (ctx) => {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const result = await ctx.agent.accounts.refresh(signed.reference, {
    context: await ctx.accountContext(user),
    scopes: [ctx.scenario.read_scope],
  });
  check(result.status === "signed_in", "a narrower refresh is answered");
  check(JSON.stringify(result.grantedScopes) === JSON.stringify([ctx.scenario.read_scope]), "only the narrower scope");
});

caseFor("lifecycle.wider-scopes-refused")(async (ctx) => {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user), { granted: [ctx.scenario.read_scope] });
  const result = await ctx.agent.accounts.refresh(signed.reference, {
    context: await ctx.accountContext(user),
    scopes: ctx.scenario.scopes,
  });
  check(result.status === "re_consent_required", `got ${result.status}`);
});

caseFor("lifecycle.refresh-token-from-another-client")(async (ctx) => {
  const other = ctx.otherAgent();
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const response = await ctx.tokenRequest(await refreshForm(ctx, signed.reference, other.identity));
  await expectRefusal(response, 400, "invalid_grant", "another client's refresh token");
});

caseFor("lifecycle.refresh-token-at-api")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const secret = ctx.refreshToken(signed.reference);
  const url = ctx.url(ctx.scenario.read_path);
  const response = await ctx.send("GET", url, {
    headers: {
      Authorization: `Bearer ${secret.reveal()}`,
      "Poppy-Session": await ctx.forgedSessionJwt(session, "GET", url, { token: secret }),
    },
  });
  await expectRefusal(response, 401, "invalid_token", "a refresh token at an API");
});

caseFor("lifecycle.sign-out-takes-effect")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  check((await probe(ctx, session, signed.token)) === "served", "signed in, the read is served");
  const revoked = await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  check(revoked.revoked && revoked.deletedLocally, "the refresh token is revoked and gone");
  check((await probe(ctx, session, signed.token)) === "invalid_token", "the access token it gave stops working right away");
});

caseFor("lifecycle.sign-out-session-continues")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const form = await refreshForm(ctx, signed.reference);
  await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  check((await probe(ctx, session)) === "signed_out", "the Session continues signed out");
  await expectRefusal(await ctx.tokenRequest(form), 400, "invalid_grant", "a revoked token");
});

caseFor("lifecycle.sign-out-revokes-every-refresh-token")(async (ctx) => {
  // Sign-out revokes every refresh token held for the account (§4.6, §5.5).
  const user = ctx.newUser();
  const account = ctx.driver.accounts[0];
  const first = await ctx.signIn(user, await ctx.session(user), { account });
  const second = await ctx.signIn(user, await ctx.session(user), { account });
  const done = await ctx.agent.accounts.signOut([first.reference, second.reference], { context: await ctx.accountContext(user) });
  check(done.signedOut && done.revoked === 2, "every refresh token is revoked");
  for (const signed of [first, second]) {
    check((await probe(ctx, signed.session, signed.token)) === "invalid_token", "the access tokens they gave stop working");
    check((await probe(ctx, signed.session)) === "signed_out", "its Session goes on signed out");
  }
});

caseFor("lifecycle.disconnect-from-account-settings")(async (ctx) => {
  ctx.require("disconnect");
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  await ctx.driver.disconnect(ctx.agent.identity.clientId, ctx.driver.accounts[0]);
  check((await probe(ctx, session, signed.token)) === "invalid_token", "its access tokens stop working");
  const result = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user) });
  check(result.status === "signed_out", "the agent finds out from invalid_grant");
  check(!ctx.agent.tokens.has(signed.reference), "and forgets the token");
});

// Conversations -----------------------------------------------------------------------

const messageId = () => opaque("msg");
const message = (text, author = "agent") => ({ id: messageId(), author: { type: author }, text });

async function asUser(ctx) {
  const user = ctx.newUser();
  return { user, session: await ctx.session(user), endpoint: await ctx.conversationsEndpoint() };
}

async function conversationOf(ctx, session, token) {
  const endpoint = await ctx.conversationsEndpoint();
  const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), {
    session,
    ...(token === undefined ? {} : { token }),
  });
  return receipt.conversation_id;
}

caseFor("conversations.start-and-reply")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), { session });
  check(receipt.status && receipt.responder, "the answer has status and responder");
  const url = `${endpoint}/${receipt.conversation_id}/events`;
  const body = await (await ctx.send("GET", url, { headers: await ctx.auth(session, "GET", url) })).json();
  for (const key of ["cursor", "has_more", "status", "responder"]) check(key in body, `a read includes ${key}`);
  const company = body.events.filter((e) => e.type === "message" && e.message.role === "company").map((e) => e.message);
  check(company.length, "the company replies");
  check(company.every((m) => ["agent", "human"].includes(m.author?.type)), "replies carry author");
});

caseFor("conversations.retry-replays")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const first = message(ctx.scenario.greeting);
  const started = await ctx.agent.conversations.start(endpoint, first, { session });
  const page = await ctx.agent.conversations.readEvents(endpoint, started.conversation_id, { session });
  const again = await ctx.agent.conversations.start(endpoint, first, { session });
  check(again.conversation_id === started.conversation_id, "a retry returns the same one");
  const after = await ctx.agent.conversations.readEvents(endpoint, started.conversation_id, { session });
  check(after.events.length === page.events.length, "a retry adds nothing");
});

caseFor("conversations.message-id-conflict")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const first = message(ctx.scenario.greeting);
  await ctx.agent.conversations.start(endpoint, first, { session });
  const error = await refused(
    ctx.agent.conversations.start(endpoint, { ...first, text: "Something else entirely." }, { session }),
    "a reused message ID",
  );
  check(error.code === "message_id_conflict", `got ${error.code}`);
  check(error.statusCode === 409, "message_id_conflict is HTTP 409");
});

caseFor("conversations.invalid-cursor")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  const error = await refused(
    ctx.agent.conversations.readEvents(endpoint, conversation, { session, cursor: "evt_never_issued_by_the_company" }),
    "an invalid cursor",
  );
  check(error.code === "invalid_cursor", `got ${error.code}`);
  check(error.statusCode === 400, "invalid_cursor is HTTP 400");
});

caseFor("conversations.cursor-expired-recovery")(async (ctx) => {
  ctx.require("forget_events");
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, { session });
  const saved = page.events[0].id;
  await ctx.agent.conversations.send(endpoint, conversation, message("One more thing."), { session });
  await ctx.driver.forgetEvents(conversation);
  const error = await refused(ctx.agent.conversations.readEvents(endpoint, conversation, { session, cursor: saved }), "a forgotten cursor");
  check(error.code === "cursor_expired", `got ${error.code}`);
  check(error.statusCode === 410, "cursor_expired is HTTP 410");
  const told = [];
  const events = ctx.agent.conversations.events(endpoint, conversation, {
    session,
    cursor: saved,
    wait: 0,
    onCursorExpired: () => void told.push(true),
  });
  const first = (await events.next()).value;
  await events.return(undefined);
  check(told.length === 1, "the host is told part of the conversation is missing");
  check(first.id !== saved, "reading restarts from what the company still keeps");
});

caseFor("conversations.has-more-drained")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  let page = await ctx.agent.conversations.readEvents(endpoint, conversation, { session });
  let sent = 0;
  while (!page.has_more && sent < 80) {
    await ctx.agent.conversations.send(endpoint, conversation, message(`Note ${sent}.`), { session });
    sent += 1;
    if (sent % 10 === 0) page = await ctx.agent.conversations.readEvents(endpoint, conversation, { session });
  }
  if (!page.has_more) throw new SkipCase("the company returned every event in one page");
  const ids = [];
  let cursor;
  for (;;) {
    const current = await ctx.agent.conversations.readEvents(endpoint, conversation, { session, ...(cursor === undefined ? {} : { cursor }) });
    ids.push(...current.events.map((event) => event.id));
    cursor = current.cursor;
    if (!current.has_more) break;
  }
  check(ids.length === new Set(ids).size, "draining has_more pages repeats nothing");
  check(page.events.every((event, index) => event.id === ids[index]), "pages keep the order");
});

caseFor("conversations.empty-read")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, { session });
  const empty = await ctx.agent.conversations.readEvents(endpoint, conversation, { session, cursor: page.cursor });
  check(empty.events.length === 0, "nothing new: no events");
  check(empty.cursor === page.cursor, "the cursor is the request's own");
  check(empty.has_more === false, "has_more is false");
});

async function streamItems(ctx, session, conversation, { lastEventId, until }) {
  const endpoint = await ctx.conversationsEndpoint();
  const items = [];
  const stream = ctx.agent.conversations.stream(endpoint, conversation, {
    session,
    ...(lastEventId === undefined ? {} : { lastEventId }),
    maxReconnects: 1,
  });
  try {
    for await (const item of stream) {
      items.push(item);
      if (until(items)) break;
    }
  } catch (error) {
    if (error?.code === "sse_unsupported") throw new SkipCase("the company does not stream");
    throw error;
  }
  return items;
}

const isEvent = (item) => item.kind === undefined;

caseFor("conversations.sse-reconnect")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  await ctx.agent.conversations.send(endpoint, conversation, message("And another question."), { session });
  const every = await ctx.agent.conversations.readEvents(endpoint, conversation, { session });
  const ids = every.events.map((event) => event.id);
  check(ids.length >= 3, "the conversation has events to stream");
  const eventsOf = (items) => items.filter(isEvent);
  const first = await streamItems(ctx, session, conversation, { until: (items) => eventsOf(items).length >= 2 });
  const handled = eventsOf(first).at(-1).id;
  const resumed = await streamItems(ctx, session, conversation, { lastEventId: handled, until: (items) => eventsOf(items).length >= 1 });
  check(eventsOf(resumed)[0].id === ids[ids.indexOf(handled) + 1], "the stream resumes right after Last-Event-ID");
});

caseFor("conversations.text-delta-not-actionable")(async (ctx) => {
  const { session } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  const items = await streamItems(ctx, session, conversation, {
    until: (seen) => seen.some((item) => isEvent(item) && item.message?.role === "company"),
  });
  const deltas = items.filter((item) => item.kind === "text-delta");
  if (!deltas.length) throw new SkipCase("the company sends no text-delta pieces");
  check(deltas.every((delta) => delta.actionable === false), "a delta is never actionable");
  const complete = new Set(items.filter((item) => isEvent(item) && item.message).map((item) => item.message.id));
  for (const delta of deltas) check(complete.has(delta.message_id), "the complete message replaces the pieces");
});

caseFor("conversations.attribution")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const words = message("These are the user's own words.", "human");
  const receipt = await ctx.agent.conversations.start(endpoint, words, { session });
  const page = await ctx.agent.conversations.readEvents(endpoint, receipt.conversation_id, { session });
  const messages = page.events.filter((event) => event.message).map((event) => event.message);
  const mine = messages.filter((item) => item.id === words.id);
  check(mine[0]?.role === "user", "the user's message comes back with role user");
  check(mine[0]?.author.type === "human", "and keeps author human");
  const theirs = messages.filter((item) => item.role === "company");
  check(theirs.length && theirs.every((item) => ["agent", "human"].includes(item.author.type)), "replies have author");
});

caseFor("conversations.handoff")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  const receipt = await ctx.agent.conversations.handoff(endpoint, conversation, { session });
  check(["queued", "idle", "working"].includes(receipt.status), "handoff answers a status");
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, { session });
  const states = page.events.filter((event) => event.type === "state");
  check(states.length, "each status change is a state event");
  check(states.at(-1).status === page.status, "the last state event is the current status");
  check(states.at(-1).responder === page.responder, "and the current responder");
});

caseFor("conversations.direct-conversation")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const parent = await conversationOf(ctx, session);
  const direct = await ctx.agent.conversations.startDirect(endpoint, parent, message("I'd like to ask myself.", "human"), { session });
  let page = await ctx.agent.conversations.readEvents(endpoint, parent, { session });
  const opened = page.events.filter((event) => event.type === "direct_opened");
  check(opened.at(-1)?.conversation_id === direct.conversation_id, "direct_opened");
  const error = await refused(ctx.agent.conversations.send(endpoint, parent, message("Meanwhile."), { session }), "a message to a parent");
  check(error.code === "direct_conversation_open", `got ${error.code}`);
  check(error.details?.conversation_id === direct.conversation_id, "the refusal names the Direct Conversation");
  await ctx.agent.conversations.close(endpoint, direct.conversation_id, { session });
  page = await ctx.agent.conversations.readEvents(endpoint, parent, { session });
  check(page.events.some((event) => event.type === "direct_closed"), "direct_closed");
  await ctx.agent.conversations.send(endpoint, parent, message("Back to you."), { session });
});

caseFor("conversations.direct-of-direct-refused")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const parent = await conversationOf(ctx, session);
  const direct = await ctx.agent.conversations.startDirect(endpoint, parent, message("Hi.", "human"), { session });
  const error = await refused(
    ctx.agent.conversations.startDirect(endpoint, direct.conversation_id, message("Hi.", "human"), { session }),
    "a Direct Conversation under a Direct Conversation",
  );
  check(["conversation_not_found", "conversation_closed", "direct_conversation_open"].includes(error.code), `got ${error.code}`);
});

caseFor("conversations.authorization-then-same-conversation")(async (ctx) => {
  const prompt = ctx.scenario.account_prompt;
  if (prompt === undefined || prompt === null) throw new SkipCase("the scenario has no account prompt");
  const { user, session, endpoint } = await asUser(ctx);
  const receipt = await ctx.agent.conversations.start(endpoint, message(prompt), { session });
  const page = await ctx.agent.conversations.readEvents(endpoint, receipt.conversation_id, { session });
  check(page.events.some((event) => event.type === "authorization"), "the company asks for sign-in with an authorization event");
  check(page.events.some((event) => event.message?.role === "company"), "and says so in a message");
  const signed = await ctx.signIn(user, session);
  const again = await ctx.agent.conversations.send(endpoint, receipt.conversation_id, message(prompt), { session: signed.session, token: signed.token });
  check(again.conversation_id === receipt.conversation_id, "the same conversation continues");
});

caseFor("conversations.closed")(async (ctx) => {
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  const closed = await ctx.agent.conversations.close(endpoint, conversation, { session });
  check(closed.status === "closed", "closing answers status closed");
  const error = await refused(ctx.agent.conversations.send(endpoint, conversation, message("Still there?"), { session }), "a message to a closed conversation");
  check(error.code === "conversation_closed", `got ${error.code}`);
  check(error.statusCode === 409, "conversation_closed is HTTP 409");
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, { session });
  check(page.status === "closed" && page.events.length, "its events stay readable");
});

caseFor("conversations.not-found-indistinguishable")(async (ctx) => {
  const theirs = await conversationOf(ctx, await ctx.session(ctx.newUser()));
  const { session, endpoint } = await asUser(ctx);
  const bodies = [];
  for (const conversation of [theirs, "cnv_conformance_unknown_000000"]) {
    const url = `${endpoint}/${conversation}/events`;
    const response = await ctx.send("GET", url, { headers: await ctx.auth(session, "GET", url) });
    bodies.push([response.status, await response.json()]);
  }
  check(JSON.stringify(bodies[0]) === JSON.stringify(bodies[1]), "another user's and an unknown conversation look the same");
  check(bodies[0][0] === 404 && bodies[0][1].error === "conversation_not_found", "404");
});

caseFor("conversations.signed-out-on-account-conversation")(async (ctx) => {
  const { user, session, endpoint } = await asUser(ctx);
  const signed = await ctx.signIn(user, session);
  const conversation = await conversationOf(ctx, session, signed.token);
  await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  const error = await refused(ctx.agent.conversations.readEvents(endpoint, conversation, { session }), "a signed-out read");
  // The challenge with `scope` and no error code, read as `insufficient_scope` (§5.5, §7).
  check(error.code === "insufficient_scope", `got ${error.code}`);
  check(error.statusCode === 401, "a signed-out request gets the 401 challenge");
});

// Operations ----------------------------------------------------------------------------

async function signedInUser(ctx) {
  const user = ctx.newUser();
  return [user, await ctx.signIn(user, await ctx.session(user))];
}

function request(ctx, signed, kind, approval, { token, session } = {}) {
  const proposal = ctx.proposal(kind);
  return ctx.agent.api.call(proposal.method, ctx.url(proposal.path), {
    session: session ?? signed.session,
    token: token ?? signed.token,
    body: proposal.body ?? {},
    ...(approval === undefined ? {} : { approval }),
  });
}

/** The request for the action: refused, with the operation (Operations 4). */
async function propose(ctx, signed, kind) {
  const answer = await request(ctx, signed, kind);
  check(answer.status === 403 && answer.operation !== undefined, "approval_required, HTTP 403");
  return answer.operation;
}

async function performed(ctx, operation, times) {
  if (ctx.driver.capabilities.has("performed")) {
    const count = await ctx.driver.performed(operation.operation_id);
    check(count === times, `performed ${times} time(s), not ${count}`);
  }
}

/** A statement of the user's approval: the conformance runner plays the user here. */
const approved = (operation) => ({ operation_id: operation.operation_id, revision: operation.revision });

function checkNewRevision(answer, operation, named) {
  check(answer.operation !== undefined, "the company returns the operation, performing nothing");
  check(answer.operation.revision !== named, "never the revision the approval named");
  check(answer.operation.operation_id === operation.operation_id, "the same action, the same operation");
  return answer.operation;
}

caseFor("operations.approval-required")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  check(operation.summary.trim(), "it has a summary");
  check(operation.revision, "it has an opaque revision");
  check(new Date(operation.expires_at) > ctx.now(), "it can still be approved");
  await performed(ctx, operation, 0);
  const documented = ctx.proposal("user").documented_as;
  if (documented !== undefined && documented !== null) {
    const api = openapiUrl((await ctx.company()).document);
    const paths = api === undefined ? {} : ((await (await ctx.send("GET", api)).json()).paths ?? {});
    check(JSON.stringify(paths[documented] ?? {}).includes("approval_required"), "the API description says the endpoint can return approval_required");
  }
});

caseFor("operations.same-request-same-revision")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const first = await propose(ctx, signed, "user");
  const second = await propose(ctx, signed, "user");
  check(JSON.stringify(second) === JSON.stringify(first), "the same request, the same terms: the same revision");
});

caseFor("operations.approved-performed")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const done = await request(ctx, signed, "user", approved(operation));
  check(done.operation === undefined && done.status >= 200 && done.status < 300, `performed, got ${done.status}`);
  await performed(ctx, operation, 1);
});

caseFor("operations.retry-after-the-outcome")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const approval = approved(operation);
  const first = await request(ctx, signed, "user", approval);
  const second = await request(ctx, signed, "user", approval);
  check(JSON.stringify(second.body) === JSON.stringify(first.body), "a retry gets the original response");
  await performed(ctx, operation, 1);
});

caseFor("operations.retry-before-the-outcome")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "unknown");
  const approval = approved(operation);
  for (const attempt of ["the first request", "a retry"]) {
    const error = await refused(request(ctx, signed, "unknown", approval), attempt);
    check(error.statusCode === 503, `${attempt} waits, HTTP 503, never a failure`);
    check(error.details?.retry_after, `${attempt} says when: Retry-After`);
  }
  await performed(ctx, operation, 1);
});

caseFor("operations.new-revision-on-changed-terms")(async (ctx) => {
  ctx.require("revise");
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  await ctx.driver.revise(operation.operation_id);
  const answer = await request(ctx, signed, "user", approved(operation));
  const current = checkNewRevision(answer, operation, operation.revision);
  check(current.summary !== operation.summary, "the new revision has the new terms");
  await performed(ctx, operation, 0);
  const done = await request(ctx, signed, "user", approved(current));
  check(done.operation === undefined, "the new revision, approved, is performed");
  await performed(ctx, operation, 1);
});

caseFor("operations.approval-of-a-revision-never-returned")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const forged = { operation_id: operation.operation_id, revision: "never_returned_0000" };
  const answer = await request(ctx, signed, "user", forged);
  checkNewRevision(answer, operation, forged.revision);
  await performed(ctx, operation, 0);
});

caseFor("operations.approval-of-another-request")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const proposal = ctx.proposal("user");
  const answer = await ctx.agent.api.call(proposal.method, ctx.url(proposal.path), {
    session: signed.session,
    token: signed.token,
    body: { changed: "this request is not the one that returned the operation" },
    approval: approved(operation),
  });
  checkNewRevision(answer, operation, operation.revision);
  await performed(ctx, operation, 0);
});

const withHeader = async (ctx, signed, proposal, url, value) => ({
  ...(await ctx.auth(signed.session, proposal.method, url, signed.token)),
  "Content-Type": "application/json",
  [APPROVAL_HEADER]: value,
});

caseFor("operations.approval-unknown-members-ignored")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const proposal = ctx.proposal("user");
  const url = ctx.url(proposal.path);
  const response = await ctx.send(proposal.method, url, {
    headers: await withHeader(ctx, signed, proposal, url, `later=1, ${approvalHeader(approved(operation))}, flag;a=b`),
    body: JSON.stringify(proposal.body ?? {}),
  });
  check(response.status === 200, `unknown members are ignored, got ${response.status}`);
  await performed(ctx, operation, 1);
});

caseFor("operations.malformed-approval-header-ignored")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const proposal = ctx.proposal("user");
  const url = ctx.url(proposal.path);
  for (const value of [
    `operation_id=${operation.operation_id}`, // Tokens, not Strings
    `operation_id="${operation.operation_id}"`, // no revision
    `operation_id="${operation.operation_id}", revision="${operation.revision}`, // unclosed
  ]) {
    const response = await ctx.send(proposal.method, url, {
      headers: await withHeader(ctx, signed, proposal, url, value),
      body: JSON.stringify(proposal.body ?? {}),
    });
    await expectRefusal(response, 403, "approval_required", "a request without an approval");
  }
  await performed(ctx, operation, 0);
});

caseFor("operations.expired")(async (ctx) => {
  ctx.require("clock");
  await ctx.operationsNegotiated();
  const [user, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  await ctx.driver.wait((Date.parse(operation.expires_at) - ctx.now().getTime()) / 1000 + 1);
  // The access token may have expired meanwhile: a new one from the refresh token.
  const refreshed = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user) });
  const answer = await request(ctx, signed, "user", approved(operation), { token: refreshed.token });
  checkNewRevision(answer, operation, operation.revision);
  await performed(ctx, operation, 0);
});

caseFor("operations.any-session-of-the-account-approves")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [user, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const another = await ctx.session(user);
  const done = await request(ctx, signed, "user", approved(operation), { session: another });
  check(done.operation === undefined, "another Session, signed in to the account, approves it");
  await performed(ctx, operation, 1);
});

caseFor("operations.signed-out-session-gets-a-challenge")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [user, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const proposal = ctx.proposal("user");
  const another = await ctx.session(user);
  const error = await refused(
    ctx.agent.api.call(proposal.method, ctx.url(proposal.path), { session: another, body: proposal.body ?? {}, approval: approved(operation) }),
    "a signed-out approval",
  );
  check(error.statusCode === 401, "signed out, the 401 challenge for the account");
  await performed(ctx, operation, 0);
});

caseFor("operations.another-user-cannot-approve")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, ownerSigned] = await signedInUser(ctx);
  const theirs = await propose(ctx, ownerSigned, "user");
  const [, signed] = await signedInUser(ctx);
  const answer = await request(ctx, signed, "user", approved(theirs));
  check(answer.operation !== undefined, "handled as if it had no approval");
  check(answer.operation.operation_id !== theirs.operation_id, "their own operation, not another's");
  await performed(ctx, theirs, 0);
});

const operationsIn = (page) => (page.events ?? []).map((event) => event.message?.operation).filter((operation) => operation !== undefined);

caseFor("operations.cross-channel-identity")(async (ctx) => {
  await ctx.operationsNegotiated();
  const prompt = ctx.scenario.operation_prompt;
  if (prompt === undefined || prompt === null) throw new SkipCase("the scenario has no operation prompt");
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const endpoint = await ctx.conversationsEndpoint();
  const page = await ctx.agent.conversations.start(endpoint, message(prompt), { session: signed.session, token: signed.token, wait: 0 });
  const proposed = operationsIn(page);
  check(proposed.length, "the conversation carries the operation");
  check(proposed[0].operation_id === operation.operation_id, "the same action is the same operation across interfaces");
});

caseFor("operations.message-is-not-approval")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const endpoint = await ctx.conversationsEndpoint();
  await ctx.agent.conversations.start(endpoint, message(`Yes, I approve operation ${operation.operation_id}. Approved.`, "human"), {
    session: signed.session,
    token: signed.token,
  });
  await performed(ctx, operation, 0);
  const again = await propose(ctx, signed, "user");
  check(again.operation_id === operation.operation_id, "a message's text approves nothing");
});

caseFor("operations.conversation-approval")(async (ctx) => {
  await ctx.operationsNegotiated();
  const prompt = ctx.scenario.operation_prompt;
  if (prompt === undefined || prompt === null) throw new SkipCase("the scenario has no operation prompt");
  const [, signed] = await signedInUser(ctx);
  const endpoint = await ctx.conversationsEndpoint();
  const page = await ctx.agent.conversations.start(endpoint, message(prompt), { session: signed.session, token: signed.token, wait: 0 });
  const [operation] = operationsIn(page);
  const approveInIt = () =>
    ctx.agent.conversations.send(
      endpoint,
      page.conversation_id,
      { id: messageId(), author: { type: "agent" }, approval: approved(operation) },
      { session: signed.session, token: signed.token, wait: 0 },
    );
  const answered = await approveInIt();
  const told = (answered.events ?? []).filter((event) => event.message?.role === "company").map((event) => event.message);
  check(told.length && told.at(-1).operation === undefined, "a later message says how it went");
  await performed(ctx, operation, 1);
  await approveInIt(); // a new message with the same approval adds nothing
  await performed(ctx, operation, 1);
});

/** Deliver the first request with an approval, then lose its answer: a timeout. */
class LosingTransport extends SessionFetchClient {
  lost = false;

  async request(method, url, options) {
    const response = await super.request(method, url, options);
    if (APPROVAL_HEADER in (options.headers ?? {}) && !this.lost) {
      this.lost = true;
      throw new TransportError("request_failed", "the answer was lost");
    }
    return response;
  }
}

caseFor("operations.lost-answer-same-approval")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "user");
  const losing = new LosingTransport({ reactor: ctx.agent.reactor, fetch: ctx.fetch });
  const api = new ApiClient({ transport: losing });
  const proposal = ctx.proposal("user");
  const sent = await ctx.agent.operations.send(
    (approval) =>
      api.call(proposal.method, ctx.url(proposal.path), {
        session: signed.session,
        token: signed.token,
        body: proposal.body ?? {},
        approval,
      }),
    approved(operation),
  );
  check(losing.lost, "the answer was lost");
  check(sent.status === "answered", `the same approval, sent again, got ${sent.status}`);
  await performed(ctx, operation, 1);
});

caseFor("operations.failed-partial-result")(async (ctx) => {
  await ctx.operationsNegotiated();
  const [, signed] = await signedInUser(ctx);
  const operation = await propose(ctx, signed, "fails");
  const answers = [];
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const error = await refused(request(ctx, signed, "fails", approved(operation)), "an action that failed");
    answers.push([error.code, error.statusCode]);
  }
  check(JSON.stringify(answers[0]) === JSON.stringify(answers[1]), "a retry gets the same answer");
  await performed(ctx, operation, 1);
});

// MCP (§4.5, §7) ------------------------------------------------------------------------

async function mcpUrl(ctx) {
  const api = mcpApi((await ctx.company()).document);
  if (api === undefined) throw new SkipCase("the company lists no MCP server");
  return api.url;
}

function tool(name) {
  if (name === undefined || name === null) throw new SkipCase("the scenario names no MCP tool for this");
  return name;
}

const mcpClient = (ctx, session, token, url) =>
  new McpClient({ url, session, reactor: ctx.agent.reactor, fetch: ctx.fetch, ...(token === undefined ? {} : { token }) });

/** A signed-in user's access token for the MCP server: `resource` is its `url` (§7). */
async function signedInMcp(ctx) {
  const url = await mcpUrl(ctx);
  const [user, signed] = await signedInUser(ctx);
  const server = await fetchMcpServerMetadata(url, { issuer: (await ctx.metadata()).issuer, fetch: ctx.fetch });
  const result = await ctx.agent.accounts.tokenForMcp(signed.reference, { context: await ctx.accountContext(user), server });
  check(result.status === "signed_in" && result.token !== undefined, "a token for the server");
  return { user, signed, token: result.token, url };
}

caseFor("lifecycle.mcp-protected-resource-metadata")(async (ctx) => {
  const url = await mcpUrl(ctx);
  const metadata = await ctx.metadata();
  const served = await fetchMcpServerMetadata(url, { issuer: metadata.issuer, fetch: ctx.fetch });
  check(served.resource === url, "the metadata names the MCP server as its resource");
  check(metadata.protected_resources.includes(url), "the issuer lists the MCP server");
  const resource = await serviceResource(await ctx.company(), url, { reactor: ctx.agent.reactor });
  check(resource === url, "so a personal agent requests a token for its url (§4.5)");
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signedIn = await ctx.signIn(user, session);
  const bare = await ctx.send("POST", url, {
    headers: { ...(await ctx.auth(session, "POST", url, signedIn.token)), "Content-Type": "application/json" },
    body: '{"jsonrpc":"2.0","id":1,"method":"ping"}',
  });
  check(bare.status === 401, "a default access token is refused at the MCP server");
  const challenge = bare.headers.get("www-authenticate") ?? "";
  check(challenge.startsWith("Bearer") && challenge.includes("resource_metadata"), "Bearer challenge");
  check(challenge.includes('error="invalid_token"'), "invalid_token: not issued for this service");
});

caseFor("lifecycle.mcp-token-for-its-url")(async (ctx) => {
  const readTool = tool(ctx.scenario.mcp_read_tool);
  const { signed, token, url } = await signedInMcp(ctx);
  check(token.tokenType === "Bearer", "a Bearer token");
  check(token.resource === url, "issued for the server's url");
  const answer = await mcpClient(ctx, signed.session, token, url).callTool(readTool);
  check(!answer.isError, "the MCP server accepts it");
  // Signed out: the Session header alone, which this server takes; its scopes are enforced.
  const other = await ctx.session(ctx.newUser());
  const error = await refused(mcpClient(ctx, other, undefined, url).callTool(readTool), "a signed-out tool call");
  check(error.code === "insufficient_scope", `the MCP server enforces scopes, got ${error.code}`);
  check(error.statusCode === 401, "signed out, the 401 challenge");
});

caseFor("lifecycle.mcp-token-only-at-mcp")(async (ctx) => {
  const { signed, token } = await signedInMcp(ctx);
  const secret = token.accessToken.reveal();
  const targets = [["GET", ctx.url(ctx.scenario.read_path)]];
  const endpoint = (await ctx.company()).document.agent === undefined ? undefined : conversationEndpoint((await ctx.company()).document);
  if (endpoint !== undefined) targets.push(["POST", endpoint]);
  for (const [method, target] of targets) {
    const response = await ctx.send(method, target, {
      headers: { ...(await ctx.auth(signed.session, method, target, token)), "Content-Type": "application/json" },
      ...(method === "GET" ? {} : { body: "{}" }),
    });
    check(response.status === 401, `an MCP token is refused at ${method} ${target}`);
    const challenge = response.headers.get("www-authenticate") ?? "";
    check(challenge.includes('error="invalid_token"'), "invalid_token");
    check(challenge.includes("resource_metadata"), "with resource_metadata, for stale metadata (§4.5)");
    check(!(await textOf(response)).includes(secret), "and never echoed");
  }
});

caseFor("lifecycle.resource-not-served")(async (ctx) => {
  // A `resource` the company doesn't serve is `invalid_target` (RFC 8707, §4.5).
  const [, signed] = await signedInUser(ctx);
  const form = { ...(await refreshForm(ctx, signed.reference)), resource: "https://elsewhere.example/mcp" };
  await expectRefusal(await ctx.tokenRequest(form), 400, "invalid_target", "another resource");
});

caseFor("lifecycle.stale-resource-metadata")(async (ctx) => {
  // A service refusing a token not issued for it says where its metadata is (§4.5).
  const url = await mcpUrl(ctx);
  const readTool = tool(ctx.scenario.mcp_read_tool);
  const [user, signed] = await signedInUser(ctx);
  const tokens = new ServiceTokens({
    refresh: ctx.agent.accounts,
    discovery: { reactor: ctx.agent.reactor },
    company: await ctx.company(),
    reference: signed.reference,
    context: await ctx.accountContext(user),
  });
  // Stale: the default token, as if the server had no metadata of its own.
  const fallback = await tokens.tokenFor(ctx.url(ctx.scenario.read_path));
  check(fallback !== undefined && fallback.resource === undefined, "the default token");
  const stale = { ...fallback, resource: url };
  const error = await refused(mcpClient(ctx, signed.session, stale, url).callTool(readTool), "a token not issued for the server");
  check(error instanceof McpError && staleResourceMetadata(error), "invalid_token with resource_metadata");
  const fresh = await tokens.tokenFor(url, { fresh: true });
  check(fresh !== undefined && fresh.resource === url, "a token for the service, read again");
  const answer = await mcpClient(ctx, signed.session, fresh, url).callTool(readTool);
  check(!answer.isError, "and the service takes it");
});

caseFor("lifecycle.mcp-sign-out-takes-effect")(async (ctx) => {
  const readTool = tool(ctx.scenario.mcp_read_tool);
  const { user, signed, token, url } = await signedInMcp(ctx);
  const client = mcpClient(ctx, signed.session, token, url);
  check(!(await client.callTool(readTool)).isError, "signed in, the tool answers");
  await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  const error = await refused(client.callTool(readTool), "a revoked MCP token");
  check(error.code === "invalid_token", `got ${error.code}`);
});

caseFor("operations.cross-channel-mcp")(async (ctx) => {
  await ctx.operationsNegotiated();
  const proposeTool = tool(ctx.scenario.mcp_propose_tool);
  const { signed, token, url } = await signedInMcp(ctx);
  const throughApi = await propose(ctx, signed, "user");
  const answer = await mcpClient(ctx, signed.session, token, url).callTool(proposeTool);
  check(answer.isError, "an error result, nothing done");
  check(answer.operation !== undefined, "with structuredContent.operation");
  check(answer.operation.operation_id === throughApi.operation_id, "the same operation as through the API");
});

caseFor("operations.mcp-approval")(async (ctx) => {
  await ctx.operationsNegotiated();
  const proposeTool = tool(ctx.scenario.mcp_propose_tool);
  const { signed, token, url } = await signedInMcp(ctx);
  const client = mcpClient(ctx, signed.session, token, url);
  const { operation } = await client.callTool(proposeTool);
  const approval = approved(operation);
  const done = await client.callTool(proposeTool, {}, { approval });
  check(!done.isError && done.operation === undefined, "the same call, approved, is performed");
  const again = await client.callTool(proposeTool, {}, { approval });
  check(again.text === done.text, "a retry gets the original result");
  await performed(ctx, operation, 1);
});

// Company rules ---------------------------------------------------------------------------

caseFor("protocol.feedback-report")(async (ctx) => {
  // A report with the Session header, no scope: 202, or 200; malformed, 400 (§9.3).
  const endpoint = feedbackEndpoint((await ctx.company()).document);
  if (endpoint === undefined) throw new SkipCase("the company lists no feedback endpoint");
  const session = await ctx.session(ctx.newUser());
  const post = async (body) =>
    ctx.send("POST", endpoint, {
      headers: { ...(await ctx.auth(session, "POST", endpoint)), "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  const report = { task: "Conformance task", description: "Not offered." };
  const accepted = await post(report);
  // 202, or 200 with an alternative when the task can be done after all (§9.3).
  check(accepted.status === 200 || accepted.status === 202, `a report is accepted with 202 or 200, got ${accepted.status}`);
  const unknown = await post({ ...report, later: "a member it doesn't recognize" });
  check(unknown.status === 200 || unknown.status === 202, "a member it doesn't recognize is ignored");
  await expectRefusal(await post({ ...report, task: "x".repeat(201) }), 400, "invalid_request", "too long");
  const bare = await ctx.send("POST", endpoint, { headers: { "Content-Type": "application/json" }, body: "{}" });
  await expectRefusal(bare, 400, "invalid_session", "a report needs the Session header");
});

caseFor("conversations.read-fields")(async (ctx) => {
  // Every read has conversation_id, events, cursor, has_more, status, responder (§7.5).
  const { session, endpoint } = await asUser(ctx);
  const conversation = await conversationOf(ctx, session);
  const url = `${endpoint.replace(/\/+$/u, "")}/${conversation}/events`;
  const page = await (await ctx.send("GET", url, { headers: await ctx.auth(session, "GET", url) })).json();
  const later = `${url}?cursor=${page.cursor}`;
  const empty = await (await ctx.send("GET", later, { headers: await ctx.auth(session, "GET", later) })).json();
  const fields = ["conversation_id", "events", "cursor", "has_more", "status", "responder"];
  for (const read of [page, empty]) {
    const missing = fields.filter((field) => !(field in read));
    check(missing.length === 0, `a read has ${missing} missing`);
  }
  check(empty.events.length === 0, "events is an empty list when there are none");
});

// The website (§6) ------------------------------------------------------------------------

async function browserOf(ctx) {
  const endpoint = (await ctx.company()).document.web?.browser_session_endpoint;
  if (endpoint === undefined) throw new SkipCase("the company offers no browser sessions");
  if (ctx.agent.browser === undefined) throw new SkipCase("the runner was given no browser of its own");
  return [ctx.agent.browser, endpoint];
}

function setCookies(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  const value = headers.get("set-cookie");
  return value ? [value] : [];
}

/** Whether a response set a cookie, other than clearing one. */
const joined = (response) => setCookies(response.headers).some((value) => !value.toLowerCase().includes("max-age=0"));

/**
 * Join the runner's own browser to the Session (§6), then open `page` in it. Resolves to
 * the join's responses: the 303 that set the Session's cookie first.
 */
async function join(ctx, signed, page) {
  const [browser, endpoint] = await browserOf(ctx);
  await new BrowserSessionClient({ reactor: ctx.agent.reactor, transport: ctx.agent.transport }).join({
    browserSessionEndpoint: endpoint,
    session: signed.session,
    token: signed.token,
  });
  const landed = browser.page;
  check(landed.history[0]?.status === 303, "joined with 303 See Other");
  await browser.get(page);
  return landed.history;
}

caseFor("lifecycle.browser-joins-session")(async (ctx) => {
  const [, endpoint] = await browserOf(ctx);
  const loaded = await ctx.send("GET", endpoint);
  check(loaded.status === 200, "the join page loads with a GET");
  for (const [name, value] of [
    ["cache-control", "no-store"],
    ["content-security-policy", "frame-ancestors 'none'"],
    ["cross-origin-opener-policy", "same-origin"],
  ]) {
    check((loaded.headers.get(name) ?? "").includes(value), `the join page sends ${name}: ${value}`);
  }
  const joinCookie = (loaded.headers.get("set-cookie") ?? "").toLowerCase();
  for (const flag of ["__Host-", "Secure", "HttpOnly", "SameSite=Strict"]) {
    check(joinCookie.includes(flag.toLowerCase()), `the join cookie has ${flag}`);
  }
  const [, signed] = await signedInUser(ctx);
  const responses = await join(ctx, signed, ctx.url("/"));
  const cookies = responses.flatMap((response) => setCookies(response.headers)).filter((value) => !value.toLowerCase().includes("max-age=0"));
  const sessionCookie = (cookies.find((value) => value.toLowerCase().includes("secure")) ?? "").toLowerCase();
  for (const flag of ["Secure", "HttpOnly"]) check(sessionCookie.includes(flag.toLowerCase()), `the Session's cookie is ${flag}`);
  check(!sessionCookie.includes("max-age"), "the cookie has no lifetime of its own");
});

caseFor("lifecycle.browser-join-refused")(async (ctx) => {
  // Steps 2 and 3 of §6 and the attacks of §10.6: each wrong join sets no Session cookie.
  const [, endpoint] = await browserOf(ctx);
  const session = await ctx.session(ctx.newUser());
  const authorizeUrl = `${endpoint.replace(/\/+$/u, "")}/authorize`;
  const form = async () => {
    const browser = ctx.newBrowser();
    const page = await browser.get(endpoint);
    const found = /name="code" value="([^"]+)"/u.exec(page.text);
    check(found !== null, "the join page holds a code");
    return [browser, found[1]];
  };
  const authorize = async (code) =>
    ctx.send("POST", authorizeUrl, {
      headers: { ...(await ctx.auth(session, "POST", authorizeUrl)), "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
  const submit = (browser, code) => browser.postForm(endpoint, { code });

  let [browser, code] = await form();
  const done = await authorize(code);
  check(done.status === 204, `the agent authorizes a code: got ${done.status}`);
  await expectRefusal(await authorize(code), 400, "invalid_request", "a code authorized twice");
  await expectRefusal(await authorize(`bc_conformance_${"x".repeat(16)}`), 400, "invalid_request", "a code the company never issued");
  const stolen = await submit(ctx.newBrowser(), code);
  check(stolen.status === 400 && !joined(stolen), "a code from another browser joins none");
  const used = await submit(browser, code);
  check(used.status === 400 && !joined(used), "a code is used once, whatever the result");
  [browser, code] = await form();
  const unauthorized = await submit(browser, code);
  check(unauthorized.status === 400 && !joined(unauthorized), "a code the agent never authorized joins none");
  [browser, code] = await form();
  check((await authorize(code)).status === 204, "the agent authorizes a new code");
  const valid = await submit(browser, code);
  check(valid.status === 303 && joined(valid), "a valid join sets the Session's cookie");
});

// Operator signatures (§5.3, RFC 9421, Web Bot Auth) -----------------------------------

const operatorHeaders = [SIGNATURE_AGENT_HEADER, SIGNATURE_INPUT_HEADER, SIGNATURE_HEADER];

/** `headers` under a signature the SDK would never send: one thing wrong. */
async function forgedSignature(ctx, method, url, headers, { key, signatureAgent, mutation = {} } = {}) {
  const identity = ctx.agent.identity;
  const created = Math.floor(ctx.now().getTime() / 1000) + (mutation.created_offset ?? 0);
  const signed = await signOperatorRequest(
    {
      method,
      url,
      tenantId: "pap-conformance",
      sessionJwt: new SecretValue(headers[SESSION_HEADER]),
      ...(headers.Authorization === undefined ? {} : { authorization: new SecretValue(headers.Authorization) }),
    },
    key ?? identity.operatorKey,
    {
      signatureAgent: signatureAgent ?? identity.operatorUrl,
      created,
      expires: created + 60,
      nonce: "conformance",
      tag: mutation.tag ?? WEB_BOT_AUTH_TAG,
      ...(mutation.components === undefined ? {} : { components: mutation.components }),
    },
  );
  const out = {
    ...headers,
    [SIGNATURE_AGENT_HEADER]: signed.signatureAgent,
    [SIGNATURE_INPUT_HEADER]: signed.signatureInput,
    [SIGNATURE_HEADER]: signed.signature,
  };
  if (mutation.tamper) {
    const [label, value] = signed.signature.split("=:");
    out[SIGNATURE_HEADER] = `${label}=:${value[0] === "A" ? "B" : "A"}${value.slice(1)}`;
  }
  if (mutation.drop_agent) delete out[SIGNATURE_AGENT_HEADER];
  return out;
}

function unsigned(headers) {
  const out = { ...headers };
  for (const name of operatorHeaders) delete out[name];
  return out;
}

/** A signed-in user, the API URL they read, and the headers the SDK sends it. */
async function operatorRead(ctx) {
  const [, signed] = await signedInUser(ctx);
  const url = ctx.url(ctx.scenario.read_path);
  return [signed, url, await ctx.auth(signed.session, "GET", url, signed.token)];
}

async function operatorRefused(response, what) {
  const asked = response.headers.get("accept-signature") ?? "";
  await expectRefusal(response, 403, OPERATOR_SIGNATURE_REFUSED, what);
  check(asked.includes('"poppy-session"'), `${what}: Accept-Signature asks for poppy-session`);
  check(asked.includes('tag="web-bot-auth"'), `${what}: Accept-Signature names the tag`);
  return asked;
}

function served(response, what) {
  check(response.status === 200, `${what}: expected HTTP 200, got ${response.status}`);
}

caseFor("operator.signed-read")(async (ctx) => {
  const [signed, url, headers] = await operatorRead(ctx);
  const given = headers[SIGNATURE_INPUT_HEADER];
  check(given.includes('tag="web-bot-auth"'), "the signature is tagged web-bot-auth");
  check(given.includes(`keyid="${ctx.agent.identity.operatorKey.keyid}"`), "it names the operator key");
  for (const name of ['"poppy-session"', '"authorization"', '"signature-agent";key=']) {
    check(given.includes(name), `it covers ${name}`);
  }
  served(await ctx.send("GET", url, { headers }), "a verified request");
  served(await ctx.agent.transport.request("GET", url, { session: signed.session, token: signed.token }), "the transport's request");
});

caseFor("operator.signed-conversation-and-stream")(async (ctx) => {
  const session = await ctx.session(ctx.newUser());
  const endpoint = await ctx.conversationsEndpoint();
  const headers = await ctx.auth(session, "GET", ctx.url("/"));
  const given = headers[SIGNATURE_INPUT_HEADER];
  check(given.includes('"poppy-session"'), "a signed-out request covers poppy-session");
  check(!given.includes('"authorization"'), "and no authorization, as it has none");
  const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), { session });
  const items = [];
  for await (const item of ctx.agent.conversations.stream(endpoint, receipt.conversation_id, { session, maxReconnects: 0 })) {
    items.push(item);
    break;
  }
  check(items.length > 0, "the stream answers a signed request");
});

caseFor("operator.signed-mcp")(async (ctx) => {
  const readTool = tool(ctx.scenario.mcp_read_tool);
  const { signed, token, url } = await signedInMcp(ctx);
  const answer = await mcpClient(ctx, signed.session, token, url).callTool(readTool);
  check(!answer.isError, "the MCP server accepts signed requests");
});

caseFor("operator.signed-feedback")(async (ctx) => {
  const [, signed] = await signedInUser(ctx);
  const endpoint = feedbackEndpoint((await ctx.company()).document);
  if (endpoint === undefined) throw new SkipCase("the company lists no feedback endpoint");
  await new FeedbackClient({ transport: ctx.agent.transport }).report(
    endpoint,
    { task: "operator conformance", description: "A signed report." },
    { session: signed.session, token: signed.token },
  );
});

caseFor("operator.required-unsigned-refused")(async (ctx) => {
  const [, url, headers] = await operatorRead(ctx);
  const asked = await operatorRefused(await ctx.send("GET", url, { headers: unsigned(headers) }), "an unsigned request");
  check(asked.includes('"authorization"'), "it asks to cover the token");
});

caseFor("operator.required-mcp-refused")(async (ctx) => {
  const { signed, token, url } = await signedInMcp(ctx);
  const headers = { ...unsigned(await ctx.auth(signed.session, "POST", url, token)), "Content-Type": "application/json" };
  const answer = await ctx.send("POST", url, { headers, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
  check(!answer.headers.has("www-authenticate"), "no token challenge");
  await operatorRefused(answer, "an unsigned MCP request");
});

caseFor("operator.required-key-not-published")(async (ctx) => {
  const [, url, headers] = await operatorRead(ctx);
  const forged = await forgedSignature(ctx, "GET", url, headers, { key: await newOperatorKey() });
  await operatorRefused(await ctx.send("GET", url, { headers: forged }), "a key not published");
});

caseFor("operator.off-ignored", "operator.other-tag-ignored")(async (ctx, fixture) => {
  const [, url, headers] = await operatorRead(ctx);
  const forged = await forgedSignature(ctx, "GET", url, headers, { mutation: fixture.mutation });
  served(await ctx.send("GET", url, { headers: forged }), fixture.id);
});

caseFor("operator.unsigned-accepted")(async (ctx) => {
  const [, url, headers] = await operatorRead(ctx);
  served(await ctx.send("GET", url, { headers: unsigned(headers) }), "an unsigned request");
});

caseFor("operator.key-not-published")(async (ctx) => {
  const [, url, headers] = await operatorRead(ctx);
  const forged = await forgedSignature(ctx, "GET", url, headers, { key: await newOperatorKey() });
  served(await ctx.send("GET", url, { headers: forged }), "a key not published");
});

caseFor("operator.directory-unreadable")(async (ctx) => {
  const [, url, headers] = await operatorRead(ctx);
  const gone = `https://${ctx.agent.identity.domain}/no-such-directory.json`;
  const forged = await forgedSignature(ctx, "GET", url, headers, { signatureAgent: gone });
  served(await ctx.send("GET", url, { headers: forged }), "a directory that can't be read");
});

caseFor(
  "operator.required-other-tag",
  "operator.wrong-signature",
  "operator.session-header-not-covered",
  "operator.token-not-covered",
  "operator.authority-not-covered",
  "operator.agent-member-not-covered",
  "operator.no-signature-agent",
  "operator.expired",
  "operator.created-in-the-future",
)(async (ctx, fixture) => {
  const [, url, headers] = await operatorRead(ctx);
  const forged = await forgedSignature(ctx, "GET", url, headers, { mutation: fixture.mutation });
  await operatorRefused(await ctx.send("GET", url, { headers: forged }), fixture.id);
});

caseFor("operator.session-header-swapped")(async (ctx) => {
  const [signed, url, headers] = await operatorRead(ctx);
  const fresh = await ctx.auth(signed.session, "GET", url, signed.token);
  const swapped = { ...headers, [SESSION_HEADER]: fresh[SESSION_HEADER] };
  await operatorRefused(await ctx.send("GET", url, { headers: swapped }), "another Session JWT");
});

caseFor("operator.refusal-keeps-the-session")(async (ctx, fixture) => {
  const [signed, url, headers] = await operatorRead(ctx);
  const forged = await forgedSignature(ctx, "GET", url, headers, { mutation: fixture.mutation });
  await operatorRefused(await ctx.send("GET", url, { headers: forged }), "a wrong signature");
  const { sid } = signed.session;
  served(await ctx.agent.transport.request("GET", url, { session: signed.session, token: signed.token }), "the same Session, signed");
  check(signed.session.sid === sid, "the Session did not restart");
});

caseFor("operator.signature-never-vouches-for-the-session")(async (ctx) => {
  const [, url, headers] = await operatorRead(ctx);
  const jwt = headers[SESSION_HEADER];
  const signature = jwt.split(".")[2];
  const bad = { ...headers, [SESSION_HEADER]: [...jwt.split(".").slice(0, 2), `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`].join(".") };
  const forged = await forgedSignature(ctx, "GET", url, bad);
  await expectRefusal(await ctx.send("GET", url, { headers: forged }), 400, "invalid_session", "a signed request whose Session JWT fails");
});

// DPoP (§4.5, RFC 9449) ---------------------------------------------------------------

const prover = (ctx) => firstContribution(ctx.agent.reactor, DpopProvers, "DPoP prover");

async function dpopKey(ctx) {
  const metadata = await ctx.metadata();
  return prover(ctx).keys.keyFor({ tenantId: ctx.tenantId, issuer: metadata.issuer });
}

/** A proof the SDK would never send: real keys, one thing wrong (RFC 9449 §4.2). */
async function forgedProof(ctx, key, method, url, { token, nonce, mutation = {} } = {}) {
  const claims = await dpopProofClaims(
    {
      method,
      url,
      tenantId: ctx.tenantId,
      issuer: ctx.baseUrl,
      ...(token === undefined ? {} : { accessToken: token.accessToken }),
      ...(nonce === undefined || nonce === null ? {} : { nonce }),
    },
    { issuedAt: new Date(ctx.now().getTime() + (mutation.iat_offset ?? 0) * 1000), randomBytes: strongRandom },
  );
  for (const name of ["ath", "htm", "htu"]) if (name in mutation) claims[name] = mutation[name];
  return new SignJWT(claims)
    .setProtectedHeader({ alg: DPOP_ALGORITHM, typ: mutation.typ ?? DPOP_PROOF_TYPE, jwk: key.publicJwk })
    .sign(key.privateKey);
}

/** A signed-in user's DPoP token, and the API URL it reads. */
async function boundUser(ctx) {
  if (!(await ctx.metadata()).dpop_signing_alg_values_supported?.length) {
    throw new SkipCase("the company lists no DPoP algorithm");
  }
  const [, signed] = await signedInUser(ctx);
  check(signed.token.tokenType === "DPoP", "the token is bound");
  return [signed, ctx.url(ctx.scenario.read_path)];
}

/** The nonce `url` gives this request: `null` when the company asks for none. */
async function resourceNonce(ctx, signed, url) {
  const headers = await ctx.auth(signed.session, "GET", url, signed.token);
  return (await ctx.send("GET", url, { headers })).headers.get(DPOP_NONCE_HEADER);
}

/** `GET url` with the token, a fresh Session JWT, and `proof` in place of the SDK's. */
async function withProof(ctx, signed, url, proof) {
  const headers = await ctx.auth(signed.session, "GET", url, signed.token);
  delete headers[DPOP_HEADER];
  if (proof !== undefined) headers[DPOP_HEADER] = proof;
  return ctx.send("GET", url, { headers });
}

async function proofRefused(response, what) {
  await expectRefusal(response, 401, "invalid_dpop_proof", what);
  const challenge = response.headers.get("www-authenticate") ?? "";
  check(challenge.startsWith('DPoP error="invalid_dpop_proof"'), `${what}: the DPoP challenge, got ${challenge}`);
}

/** The nonce the token endpoint gives a proof. */
async function tokenNonce(ctx, signed) {
  const metadata = await ctx.metadata();
  const proof = await forgedProof(ctx, await dpopKey(ctx), "POST", metadata.token_endpoint);
  const answer = await ctx.tokenRequest(await refreshForm(ctx, signed.reference), { dpop: proof });
  await expectRefusal(answer, 400, "use_dpop_nonce", "a proof with no nonce");
  return answer.headers.get(DPOP_NONCE_HEADER);
}

caseFor("dpop.metadata-lists-es256")(async (ctx) => {
  check((await ctx.metadata()).dpop_signing_alg_values_supported?.includes(DPOP_ALGORITHM), "the metadata lists ES256");
});

caseFor("dpop.token-bound-and-used")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const answer = await ctx.agent.transport.request("GET", url, { session: signed.session, token: signed.token });
  check(answer.status === 200, `the bound token reads the API, got ${answer.status}`);
});

caseFor("dpop.session-and-proof-different-keys")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const headers = await ctx.auth(signed.session, "GET", url, signed.token);
  const delegated = decodeProtectedHeader(headers["Poppy-Session"]).kid;
  const proved = await jwkThumbprint(decodeProtectedHeader(headers[DPOP_HEADER]).jwk);
  check(proved === (await dpopKey(ctx)).thumbprint, "the proof is by the DPoP key");
  check(proved !== delegated, "the proof's key is not the delegated key");
  const agents = await Promise.all(ctx.agent.identity.jwks.keys.map((key) => jwkThumbprint(key)));
  check(!agents.includes(proved), "the proof's key is not one of the agent's jwks_uri");
});

caseFor("dpop.token-request-needs-a-proof")(async (ctx) => {
  const [signed] = await boundUser(ctx);
  const answer = await ctx.tokenRequest(await refreshForm(ctx, signed.reference));
  await expectRefusal(answer, 400, "invalid_dpop_proof", "a token request with no proof");
  const refreshed = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(signed.session.sub) });
  check(refreshed.status === "signed_in", "the refused request spent nothing");
});

caseFor(
  "dpop.token-proof-for-another-url",
  "dpop.token-proof-with-ath",
  "dpop.token-proof-outside-the-window",
  "dpop.token-proof-wrong-typ",
)(async (ctx, fixture) => {
  const [signed] = await boundUser(ctx);
  const metadata = await ctx.metadata();
  const nonce = await tokenNonce(ctx, signed);
  const proof = await forgedProof(ctx, await dpopKey(ctx), "POST", metadata.token_endpoint, { nonce, mutation: fixture.mutation });
  const answer = await ctx.tokenRequest(await refreshForm(ctx, signed.reference), { dpop: proof });
  await expectRefusal(answer, 400, "invalid_dpop_proof", fixture.id);
});

caseFor("dpop.nonce-at-the-token-endpoint")(async (ctx) => {
  const [signed] = await boundUser(ctx);
  const metadata = await ctx.metadata();
  const nonce = await tokenNonce(ctx, signed);
  check(nonce, "use_dpop_nonce gives a DPoP-Nonce");
  const proof = await forgedProof(ctx, await dpopKey(ctx), "POST", metadata.token_endpoint, { nonce });
  const answer = await ctx.tokenRequest(await refreshForm(ctx, signed.reference), { dpop: proof });
  check(answer.status === 200, `served with the nonce, got ${answer.status}`);
  check((await answer.json()).token_type === "DPoP", "the token is bound");
});

caseFor("dpop.nonce-at-a-resource")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const headers = await ctx.auth(signed.session, "GET", url, signed.token);
  const rejected = await ctx.send("GET", url, { headers });
  await expectRefusal(rejected, 401, "use_dpop_nonce", "a proof with no nonce");
  const challenge = rejected.headers.get("www-authenticate") ?? "";
  check(challenge.startsWith('DPoP error="use_dpop_nonce"'), "the DPoP challenge");
  check(rejected.headers.get(DPOP_NONCE_HEADER), "it gives a DPoP-Nonce");
  const transport = new SessionFetchClient({ reactor: ctx.agent.reactor, fetch: ctx.fetch });
  const answer = await transport.request("GET", url, { session: signed.session, token: signed.token });
  check(answer.status === 200, `the SDK retries once, got ${answer.status}`);
  check(transport.dpopNonces.size > 0, "and keeps the nonce for the origin");
});

caseFor("dpop.bound-token-without-a-proof")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  await proofRefused(await withProof(ctx, signed, url), "a bound token with no proof");
});

caseFor("dpop.bound-token-as-bearer")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const headers = await ctx.auth(signed.session, "GET", url, signed.token);
  delete headers[DPOP_HEADER];
  headers.Authorization = `Bearer ${signed.token.accessToken.reveal()}`;
  const answer = await ctx.send("GET", url, { headers });
  await expectRefusal(answer, 401, "invalid_token", "a bound token as Bearer");
  check((answer.headers.get("www-authenticate") ?? "").includes("DPoP"), "the challenge names DPoP");
});

caseFor("dpop.proof-of-another-key")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const nonce = await resourceNonce(ctx, signed, url);
  const proof = await forgedProof(ctx, await newDpopKey(), "GET", url, { token: signed.token, nonce });
  await proofRefused(await withProof(ctx, signed, url, proof), "another key's proof");
});

caseFor("dpop.proof-replayed")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const nonce = await resourceNonce(ctx, signed, url);
  const proof = await forgedProof(ctx, await dpopKey(ctx), "GET", url, { token: signed.token, nonce });
  const first = await withProof(ctx, signed, url, proof);
  check(first.status === 200, `the proof works once, got ${first.status}`);
  await proofRefused(await withProof(ctx, signed, url, proof), "a replayed proof");
});

caseFor(
  "dpop.proof-wrong-ath",
  "dpop.proof-wrong-htm",
  "dpop.proof-wrong-htu",
  "dpop.proof-outside-the-window",
)(async (ctx, fixture) => {
  const [signed, url] = await boundUser(ctx);
  const nonce = await resourceNonce(ctx, signed, url);
  const proof = await forgedProof(ctx, await dpopKey(ctx), "GET", url, { token: signed.token, nonce, mutation: fixture.mutation });
  await proofRefused(await withProof(ctx, signed, url, proof), fixture.id);
});

caseFor("dpop.session-header-still-checked")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const dpopNonce = await resourceNonce(ctx, signed, url);
  const headers = await ctx.auth(signed.session, "GET", url, signed.token, { dpopNonce: dpopNonce ?? undefined });
  delete headers["Poppy-Session"];
  await expectRefusal(await ctx.send("GET", url, { headers }), 400, "invalid_session", "a proof and no Session header");
});

caseFor("dpop.refresh-after-the-key-is-lost")(async (ctx) => {
  const [signed, url] = await boundUser(ctx);
  const metadata = await ctx.metadata();
  await prover(ctx).keys.forget({ tenantId: ctx.tenantId, issuer: metadata.issuer });
  const context = await ctx.accountContext(signed.session.sub);
  const refreshed = await ctx.agent.accounts.refresh(signed.reference, { context });
  check(refreshed.status === "signed_in", "a refresh, not a new sign-in");
  check(refreshed.token.tokenType === "DPoP", "a token for the new key");
  const { transport } = ctx.agent;
  const answer = await transport.request("GET", url, { session: signed.session, token: refreshed.token });
  check(answer.status === 200, `which works, got ${answer.status}`);
  const stale = await transport.request("GET", url, { session: signed.session, token: signed.token });
  await proofRefused(stale, "the token of the lost key");
});

caseFor("dpop.conversation-and-stream")(async (ctx) => {
  const [signed] = await boundUser(ctx);
  const endpoint = await ctx.conversationsEndpoint();
  const { session, token } = signed;
  const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), { session, token });
  const items = [];
  for await (const item of ctx.agent.conversations.stream(endpoint, receipt.conversation_id, { session, token, maxReconnects: 0 })) {
    items.push(item);
    break;
  }
  check(items.length > 0, "the stream answers with the bound token");
});

caseFor("dpop.feedback")(async (ctx) => {
  const [signed] = await boundUser(ctx);
  const endpoint = feedbackEndpoint((await ctx.company()).document);
  if (endpoint === undefined) throw new SkipCase("the company lists no feedback endpoint");
  await new FeedbackClient({ transport: ctx.agent.transport }).report(
    endpoint,
    { task: "dpop conformance", description: "A report with a bound token." },
    { session: signed.session, token: signed.token },
  );
});

caseFor("dpop.browser-join")(async (ctx) => {
  const [signed] = await boundUser(ctx);
  await join(ctx, signed, ctx.url("/"));
});

caseFor("dpop.mcp-token-bound")(async (ctx) => {
  const readTool = tool(ctx.scenario.mcp_read_tool);
  const { signed, token, url } = await signedInMcp(ctx);
  check(token.tokenType === "DPoP", "the MCP token is bound too");
  const answer = await mcpClient(ctx, signed.session, token, url).callTool(readTool);
  check(!answer.isError, "the MCP server accepts it with proofs");
});

caseFor("dpop.mcp-challenge-keeps-resource-metadata")(async (ctx) => {
  const { signed, token, url } = await signedInMcp(ctx);
  const headers = { ...(await ctx.auth(signed.session, "POST", url, token)), "Content-Type": "application/json" };
  delete headers[DPOP_HEADER];
  const answer = await ctx.send("POST", url, { headers, body: '{"jsonrpc":"2.0","id":1,"method":"ping"}' });
  await proofRefused(answer, "an MCP token with no proof");
  check((answer.headers.get("www-authenticate") ?? "").includes("resource_metadata"), "the challenge keeps resource_metadata (§7)");
});

caseFor("dpop.mcp-metadata-lists-es256")(async (ctx) => {
  const url = await mcpUrl(ctx);
  const served = await fetchMcpServerMetadata(url, { issuer: (await ctx.metadata()).issuer, fetch: ctx.fetch });
  const listed = served.dpop_signing_alg_values_supported ?? [];
  check(listed.length === 1 && listed[0] === DPOP_ALGORITHM, "the MCP server's own metadata lists ES256");
});

caseFor("dpop.mcp-challenges-bearer-then-dpop")(async (ctx) => {
  const url = await mcpUrl(ctx);
  const answer = await ctx.send("POST", url, {
    headers: { "Content-Type": "application/json" },
    body: '{"jsonrpc":"2.0","id":1,"method":"ping"}',
  });
  check(answer.status === 401, `a challenge, got ${answer.status}`);
  const challenges = answer.headers.get("www-authenticate") ?? "";
  const schemes = [...challenges.matchAll(/(?:^|,\s*)(Bearer|DPoP)\b/g)].map((match) => match[1]);
  check(schemes.join() === "Bearer,DPoP", `Bearer, then DPoP: ${challenges}`);
  check(challenges.split("resource_metadata=").length === 3, "each keeps resource_metadata");
});

caseFor("dpop.mcp-bearer-without-a-proof")(async (ctx, fixture) => {
  // An ordinary MCP client: Bearer for the server, at an issuer that requires a proof.
  const url = await mcpUrl(ctx);
  const [, signed] = await signedInUser(ctx);
  const refreshToken = ctx.refreshToken(signed.reference).reveal();
  const form = { grant_type: "refresh_token", refresh_token: refreshToken };
  const fallback = await ctx.tokenRequest({ ...form, ...(await ctx.clientForm()) });
  await expectRefusal(fallback, 400, fixture.expect.default, "no proof for the default token");
  const answer = await ctx.tokenRequest({ ...form, resource: url, ...(await ctx.clientForm()) });
  check(answer.status === 200, `no proof for the MCP server: got ${answer.status}`);
  const issued = await answer.json();
  check(issued.token_type.toLowerCase() === "bearer", "a Bearer token");
  const token = accessTokenFromResponse(
    { accessToken: new SecretValue(issued.access_token), tokenType: "Bearer", ...(issued.scope ? { scope: issued.scope } : {}) },
    { resource: url, requestedScopes: ctx.scenario.scopes },
  );
  const listed = await mcpClient(ctx, signed.session, token, url).callTool(tool(ctx.scenario.mcp_read_tool));
  check(!listed.isError, "the MCP server accepts it");
  const api = ctx.url(ctx.scenario.read_path);
  const elsewhere = await ctx.send("GET", api, { headers: await ctx.auth(signed.session, "GET", api, token) });
  check(elsewhere.status === 401, "and it works nowhere else");
});

caseFor("dpop.mcp-server-decides-the-proof")(async (ctx) => {
  // The issuer lists ES256; a server that doesn't gets Bearer, with no proof (§7).
  const url = await mcpUrl(ctx);
  const metadata = await ctx.metadata();
  check(metadata.dpop_signing_alg_values_supported?.length, "the issuer lists DPoP");
  const [, signed] = await signedInUser(ctx);
  const served = await fetchMcpServerMetadata(url, { issuer: metadata.issuer, fetch: ctx.fetch });
  const { dpop_signing_alg_values_supported: _listed, ...plain } = served;
  const result = await ctx.agent.accounts.tokenForMcp(signed.reference, {
    context: await ctx.accountContext(signed.session.sub),
    server: plain,
  });
  check(result.token.tokenType === "Bearer", "a server without the field gets Bearer");
  const listed = await mcpClient(ctx, signed.session, result.token, url).callTool(tool(ctx.scenario.mcp_read_tool));
  check(!listed.isError, "and takes it");
});

// A Company with no issuer (§3.2) ------------------------------------------------------

function noIssuerCompany(company) {
  check(company.oauthMetadata === undefined, "no OAuth metadata");
  check(companyIdentifier(company) === `https://${company.document.organization.domain}`, "its identifier is its HTTPS domain");
}

const jsonAnswer = (status, body) => () =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

/** The company's own network, but for one URL: an error is never no issuer (§3.2). */
const oneAnswer = (ctx, url, answer) => (input, init) =>
  String(input) === url ? Promise.resolve(answer()) : ctx.fetch(input, init);

/** Discovery of the company with its domain's protected resource metadata as `answer`. */
function discoverWith(ctx, answer, options = {}) {
  const fetch = oneAnswer(ctx, `${ctx.baseUrl}/.well-known/oauth-protected-resource`, answer);
  return discoverCompany(ctx.domain, { fetch, ...options });
}

async function discoveryStops(ctx, fixture, answer, options) {
  const error = await refused(discoverWith(ctx, answer, options), fixture.id);
  check(error.code === fixture.expect.error, `stopped by ${error.code}`);
}

caseFor("no-issuer.discovery")(async (ctx) => {
  const company = await ctx.company();
  noIssuerCompany(company);
  check(company.resourceMetadata === undefined, "the domain's metadata is a 404");
});

caseFor("no-issuer.metadata-without-servers")(async (ctx) => {
  for (const extra of [{}, { authorization_servers: [] }]) {
    noIssuerCompany(await discoverWith(ctx, jsonAnswer(200, { resource: ctx.baseUrl, ...extra })));
  }
});

caseFor("no-issuer.no-oauth-server")(async (ctx) => {
  const company = await ctx.company();
  check(company.document.auth === undefined, "poppy.json has no auth");
  for (const [method, path] of [
    ["GET", "/.well-known/oauth-authorization-server"],
    ["POST", "/oauth/token"],
    ["POST", "/oauth/device"],
    ["POST", "/oauth/revoke"],
    ["GET", "/oauth/authorize"],
  ]) {
    const answer = await ctx.send(method, `${ctx.baseUrl}${path}`);
    check(answer.status === 404, `${method} ${path}: got ${answer.status}`);
  }
});

caseFor("no-issuer.session-audience")(async (ctx, fixture) => {
  const session = await ctx.session(ctx.newUser());
  check(session.issuer === ctx.baseUrl, "the Session names the identifier");
  const url = await ctx.conversationsEndpoint();
  const body = JSON.stringify({ message: message(ctx.scenario.greeting) });
  const headers = { "Content-Type": "application/json" };
  const accepted = await ctx.send("POST", url, { headers: { ...(await ctx.auth(session, "POST", url)), ...headers }, body });
  check(accepted.ok, `aud is the identifier: got ${accepted.status}`);
  const forged = await ctx.forgedSessionJwt(session, "POST", url, { mutation: fixture.mutation });
  const answer = await ctx.send("POST", url, { headers: { "Poppy-Session": forged, ...headers }, body });
  await expectRefusal(answer, fixture.expect.status, fixture.expect.error, fixture.id);
});

caseFor("no-issuer.signed-out-interfaces")(async (ctx) => {
  const session = await ctx.session(ctx.newUser());
  const endpoint = await ctx.conversationsEndpoint();
  const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), { session });
  check(receipt.conversation_id, "a conversation starts signed out");
  const feedback = feedbackEndpoint((await ctx.company()).document);
  if (feedback === undefined) throw new SkipCase("the company lists no feedback endpoint");
  await new FeedbackClient({ transport: ctx.agent.transport }).report(
    feedback,
    { task: "no issuer", description: "A report from a signed-out Session." },
    { session },
  );
  check((await join(ctx, { session }, ctx.url("/"))).length > 0, "a browser joins signed out");
});

caseFor("no-issuer.sign-in-refused-locally")(async (ctx, fixture) => {
  const company = await ctx.company();
  let error;
  try {
    requireOauth(company);
  } catch (caught) {
    error = caught;
  }
  check(error?.code === fixture.expect.error, `refused by ${error?.code}`);
});

caseFor("no-issuer.no-fallback-server-error")((ctx, fixture) =>
  discoveryStops(ctx, fixture, jsonAnswer(500, { error: "server_error" })),
);

caseFor("no-issuer.no-fallback-timeout")((ctx, fixture) =>
  discoveryStops(ctx, fixture, () => new Promise(() => {}), { timeoutMs: 1000 }),
);

caseFor("no-issuer.no-fallback-invalid-metadata")((ctx, fixture) =>
  discoveryStops(ctx, fixture, jsonAnswer(200, { authorization_servers: [] })),
);

caseFor("no-issuer.no-fallback-unverified-issuer")((ctx, fixture) =>
  // The company has no issuer: the one named here publishes no metadata.
  discoveryStops(ctx, fixture, jsonAnswer(200, { resource: ctx.baseUrl, authorization_servers: [ctx.baseUrl] })),
);

caseFor("no-issuer.sign-in-offered-without-issuer")(async (ctx, fixture) => {
  const company = await ctx.company();
  const endpoint = await ctx.conversationsEndpoint();
  for (const offers of [
    { auth: { issuer: ctx.baseUrl } },
    { agent: { protocols: [{ type: "poppy", endpoint, access: "signed_in" }] } },
    { extensions: { "mediated-sign-in": { version: "1" } } },
  ]) {
    const answer = jsonAnswer(200, { ...company.document, ...offers });
    const fetch = oneAnswer(ctx, `${ctx.baseUrl}/.well-known/poppy.json`, answer);
    const error = await refused(discoverCompany(ctx.domain, { fetch }), fixture.id);
    check(error.code === fixture.expect.error, `stopped by ${error.code}`);
  }
});

/** Run each case; a failure never stops the others. The report is the runner's schema 1. */
export async function runConformance(ctx, { cases = companyCases(), timeoutMs = 30_000 } = {}) {
  const startedAt = new Date();
  const results = [];
  for (const fixture of cases) {
    const began = performance.now();
    let outcome = "passed";
    let message_ = null;
    const run = CASES[fixture.id];
    try {
      if (run === undefined) throw new SkipCase("not ported to TypeScript");
      let timer;
      await Promise.race([
        run(ctx, fixture),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new ConformanceFailure(`timed out after ${timeoutMs / 1000}s`)), timeoutMs);
        }),
      ]).finally(() => clearTimeout(timer));
    } catch (error) {
      if (error instanceof SkipCase) [outcome, message_] = ["skipped", error.message];
      else if (error instanceof ConformanceFailure) [outcome, message_] = ["failed", error.message];
      else if (error instanceof PersonalAgentProtocolError) [outcome, message_] = ["failed", `${error.name}: ${error.code}`];
      else [outcome, message_] = ["failed", `${error?.name ?? "Error"}: ${String(error?.message ?? error).slice(0, 200)}`];
    }
    results.push({
      id: fixture.id,
      suite: fixture.suite,
      kind: fixture.kind,
      requirements: fixture.requirements ?? [],
      outcome,
      duration_seconds: Math.round(performance.now() - began) / 1000,
      message: message_,
    });
  }
  const summary = { passed: 0, failed: 0, skipped: 0 };
  for (const result of results) summary[result.outcome] += 1;
  return {
    schema_version: 1,
    protocol: "personal-agent-protocol",
    profile: PROTOCOL_PROFILE,
    extensions: { operations: OPERATIONS_VERSION },
    role: "personal-agent",
    target: ctx.baseUrl,
    agent: ctx.agent.identity.clientId,
    started_at: startedAt.toISOString(),
    summary,
    cases: results,
  };
}
