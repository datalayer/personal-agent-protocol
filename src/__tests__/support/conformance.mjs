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

import { SignJWT, exportJWK, generateKeyPair, importJWK } from "jose";

import {
  AccountTokenClient,
  AuthorizationStateStores,
  BrowserFormPosts,
  BrowserSessionClient,
  Clocks,
  ConversationClient,
  DeviceSignInClient,
  DpopFetchClient,
  DpopProofProviders,
  InMemoryStandingPermissionStore,
  JoseDpopProofProvider,
  McpClient,
  OperationsClient,
  PROTOCOL_PROFILE,
  PersonalAgentProtocolError,
  SecretValue,
  SessionClient,
  Signers,
  StandingPermissionStores,
  TokenStores,
  approve,
  buildPapReactor,
  discoverCompany,
  mcpApi,
  operationPage,
  operationsEndpoint,
  parseClientMetadata,
  parseOperation,
} from "../../../lib/index.js";
import { JoseSigner } from "../../../lib/server.js";
import { ControlledBrowser } from "./controlled-browser.mjs";

const SUITES = ["protocol", "security", "lifecycle", "conversations", "operations"];
const JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const CLIENT_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** Every fixture case the company is tested on (no `check`: those the SDK decides alone). */
export function companyCases() {
  const cases = [];
  for (const suite of SUITES) {
    const document = JSON.parse(
      readFileSync(new URL(`../../../protocol/fixtures/conformance/${suite}.json`, import.meta.url), "utf8"),
    );
    for (const raw of document.cases) {
      if (raw.check === undefined) cases.push({ ...raw, suite, mutation: raw.mutation ?? {} });
    }
  }
  return cases;
}

export class SkipCase extends Error {}
export class ConformanceFailure extends Error {}

export function check(condition, message) {
  if (!condition) throw new ConformanceFailure(message);
}

const b64 = (bytes) => Buffer.from(bytes).toString("base64url");
const segment = (value) => b64(JSON.stringify(value));
const opaque = (prefix) => `${prefix}_${b64(randomBytes(16))}`;

async function refused(promise, what) {
  try {
    await promise;
  } catch (error) {
    if (error instanceof PersonalAgentProtocolError) return error;
    throw error;
  }
  throw new ConformanceFailure(`expected the company to refuse (${what})`);
}

async function errorOf(response) {
  try {
    const payload = JSON.parse(await response.clone().text());
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
export async function identityFrom({ domain, name, privateJwk, extensions = ["operations"], kid = "key-1" }) {
  const privateKey = await importJWK(privateJwk, "ES256");
  const { d: _d, ...publicJwk } = privateJwk;
  const clientId = `https://${domain}/agent.json`;
  return {
    domain,
    name,
    kid,
    extensions,
    clientId,
    privateKey,
    jwks: { keys: [{ kty: "EC", crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y, kid, use: "sig", alg: "ES256" }] },
    metadata: {
      client_id: clientId,
      client_name: name,
      jwks_uri: `https://${domain}/jwks.json`,
      redirect_uris: [`https://${domain}/oauth/callback`],
      token_endpoint_auth_method: "private_key_jwt",
      extensions: Object.fromEntries(extensions.map((extension) => [extension, { version: "1" }])),
    },
  };
}

/**
 * A personal agent: its identity, Reactor host, and SDK clients, and, when given a
 * `browserFetch`, its own controlled browser (`pap.browserFormPost`, its own cookie jar).
 */
export class Agent {
  constructor(identity, { fetch, clock, browserFetch }) {
    this.identity = identity;
    this.fetch = fetch;
    this.browser = browserFetch === undefined ? undefined : new ControlledBrowser(browserFetch);
    this.tokens = new Map();
    this.state = new Map();
    this.keys = new Map();
    this.standing = new InMemoryStandingPermissionStore();
    this.resolveKey = async (request) => {
      const key = `${request.tenantId}\u0000${request.subject}\u0000${request.issuer}`;
      // One key per (tenant, user, company), even for requests made at the same time.
      if (!this.keys.has(key)) {
        this.keys.set(
          key,
          generateKeyPair("ES256", { extractable: true }).then(async (pair) => ({
            privateKey: pair.privateKey,
            publicJwk: await exportJWK(pair.publicKey),
          })),
        );
      }
      return this.keys.get(key);
    };
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
            point: DpopProofProviders,
            value: new JoseDpopProofProvider({ now: () => clock.now(), resolveKey: this.resolveKey }),
            options: { id: "dpop-keys" },
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
          { point: StandingPermissionStores, value: this.standing, options: { id: "standing" } },
          ...(this.browser === undefined
            ? []
            : [{ point: BrowserFormPosts, value: this.browser, options: { id: "controlled-browser" } }]),
        ],
      },
    ]);
    this.transport = new DpopFetchClient({ reactor: this.reactor, fetch });
    this.sessions = new SessionClient({ reactor: this.reactor, fetch });
    this.device = new DeviceSignInClient({ reactor: this.reactor, fetch });
    this.accounts = new AccountTokenClient({ reactor: this.reactor, fetch });
    this.conversations = new ConversationClient({ reactor: this.reactor, transport: this.transport });
    this.operations = new OperationsClient({ reactor: this.reactor, transport: this.transport });
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
    const protocol = (await this.company()).document.agent?.protocols?.find((item) => item.type === "poppy");
    if (protocol === undefined) throw new SkipCase("the company lists no poppy conversation protocol");
    return protocol.endpoint;
  }

  async operationsEndpoint() {
    const endpoint = operationsEndpoint((await this.company()).document, parseClientMetadata(this.agent.identity.metadata));
    if (endpoint === undefined) throw new SkipCase("operations v1 is not negotiated with this company");
    return endpoint;
  }

  url(path) {
    return `${this.apiBase ?? this.baseUrl}${path}`;
  }

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

  newUser() {
    return opaque("usr_conf");
  }

  async who(user) {
    return { tenantId: this.tenantId, pairwiseUserId: user, issuer: (await this.metadata()).issuer };
  }

  async session(user, agent = this.agent) {
    const metadata = await this.metadata();
    return agent.sessions.start({
      clientId: agent.identity.clientId,
      pairwiseUserId: user,
      issuer: metadata.issuer,
      tokenEndpoint: metadata.token_endpoint,
      tenantId: this.tenantId,
    });
  }

  async renew(user, sessionId, agent = this.agent) {
    const metadata = await this.metadata();
    return agent.sessions.renew({
      clientId: agent.identity.clientId,
      pairwiseUserId: user,
      issuer: metadata.issuer,
      tokenEndpoint: metadata.token_endpoint,
      tenantId: this.tenantId,
      sessionId,
    });
  }

  /** Device Sign-In, the user approving on the company's page through the driver. */
  async signIn(user, session, { scopes, granted, account, agent = this.agent } = {}) {
    const metadata = await this.metadata();
    if (!metadata.device_authorization_endpoint) throw new SkipCase("the company offers no Device Sign-In");
    const started = await agent.device.begin({
      deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: agent.identity.clientId,
      scopes: scopes ?? this.scenario.scopes,
      tenantId: this.tenantId,
      pairwiseUserId: user,
      sessionId: session.sessionId,
    });
    await this.driver.approveDevice(started.userCode, { account: account ?? this.driver.accounts[0], scopes: granted });
    for (let attempt = 0; attempt < 10; attempt += 1) {
      await this.driver.wait(started.pollInterval);
      const polled = await agent.device.poll(started.reference);
      if (polled.status === "complete") {
        check(polled.token !== undefined && polled.accountTokenReference !== undefined, "sign-in returns its token");
        return { token: polled.token, reference: polled.accountTokenReference };
      }
    }
    throw new ConformanceFailure("Device Sign-In did not complete after approval");
  }

  async accountContext(user, agent = this.agent) {
    const metadata = await this.metadata();
    return {
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: agent.identity.clientId,
      tenantId: this.tenantId,
      pairwiseUserId: user,
      ...(metadata.revocation_endpoint ? { revocationEndpoint: metadata.revocation_endpoint } : {}),
    };
  }

  accountToken(reference) {
    const value = this.agent.tokens.get(reference);
    check(value instanceof SecretValue, "the Account Token is stored behind its reference");
    return value.reveal();
  }

  /** One request exactly as given: no cookies, no redirects followed. */
  send(method, url, { headers = {}, body } = {}) {
    return this.fetch(url, { method, headers, ...(body === undefined ? {} : { body }), redirect: "manual" });
  }

  /** A DPoP proof from the user's key, optionally made `shift` seconds off. */
  async proof(user, method, url, { token, agent = this.agent, shift = 0 } = {}) {
    const metadata = await this.metadata();
    const provider = shift
      ? new JoseDpopProofProvider({ now: () => new Date(this.now().getTime() + shift * 1000), resolveKey: agent.resolveKey })
      : agent.reactor.getContributions(DpopProofProviders)[0].value;
    const accessToken = token === undefined ? undefined : token.accessToken ?? new SecretValue(token);
    const proof = await provider.create({
      method,
      url,
      tenantId: this.tenantId,
      subject: user,
      issuer: metadata.issuer,
      ...(accessToken === undefined ? {} : { accessToken }),
    });
    return proof.reveal();
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
    if (algorithm === "RS256") {
      const [, payload, signature] = token.split(".");
      return `${segment({ ...header, alg: "RS256" })}.${payload}.${signature}`;
    }
    return token;
  }

  /** A raw token request; `dpop === true` makes a fresh valid proof, `null` sends none. */
  async tokenRequest(user, form, { dpop = true } = {}) {
    const endpoint = (await this.metadata()).token_endpoint;
    const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    if (dpop === true) headers.DPoP = await this.proof(user, "POST", endpoint);
    else if (dpop !== null) headers.DPoP = dpop;
    return this.send("POST", endpoint, { headers, body: new URLSearchParams(form).toString() });
  }

  async clientForm(identity = this.agent.identity) {
    const metadata = await this.metadata();
    const claims = { ...this.claims({ subject: identity.clientId, audience: metadata.token_endpoint }), iss: identity.clientId };
    return {
      client_id: identity.clientId,
      client_assertion_type: CLIENT_ASSERTION,
      client_assertion: await this.assertion(claims, { identity }),
    };
  }

  /** A raw read with a token and a fresh proof. */
  async read(user, url, token) {
    return this.send("GET", url, {
      headers: { Authorization: `DPoP ${token.accessToken.reveal()}`, DPoP: await this.proof(user, "GET", url, { token }) },
    });
  }
}

export const CASES = {};

function caseFor(...ids) {
  return (run) => {
    for (const id of ids) {
      if (CASES[id] !== undefined) throw new Error(`conformance case ${id} is registered twice`);
      CASES[id] = run;
    }
  };
}

const message = (text, sender = "agent") => ({ id: opaque("msg"), sender, text });

// Protocol ------------------------------------------------------------------------------

caseFor("protocol.extension-required-company")(async (ctx) => {
  const other = ctx.otherAgent();
  check(!other.identity.extensions.includes("operations"), "the second identity lists no operations");
  const proposal = ctx.proposal("user");
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user, other), { agent: other });
  const response = await other.transport.request(proposal.method, ctx.url(proposal.path), {
    ...(await ctx.who(user)),
    token: signed.token,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(proposal.body ?? {}),
  });
  await expectRefusal(response, 403, "extension_required", "an operation without the extension");
});

// Security: assertions --------------------------------------------------------------------

caseFor(
  "security.client-assertion-alg-none",
  "security.client-assertion-hs256-public-key",
  "security.client-assertion-rs256-header-on-ec-key",
  "security.client-assertion-embedded-key-ignored",
  "security.client-assertion-bad-audience",
  "security.client-assertion-audience-array",
)(async (ctx, fixture) => {
  const metadata = await ctx.metadata();
  const mutation = fixture.mutation;
  const user = ctx.newUser();
  const clientId = ctx.agent.identity.clientId;
  let audience = mutation.aud ?? metadata.token_endpoint;
  if (mutation.aud_array) audience = [metadata.token_endpoint, "https://other-company.example/oauth/token"];
  const headers = {};
  let identity;
  if (mutation.signer === "stranger") {
    const pair = await generateKeyPair("ES256", { extractable: true });
    const jwk = { ...(await exportJWK(pair.privateKey)) };
    identity = await identityFrom({ domain: ctx.agent.identity.domain, name: "Stranger", privateJwk: jwk });
    if (mutation.embed_jwk) headers.jwk = identity.jwks.keys[0];
  }
  const clientAssertion = await ctx.assertion(ctx.claims({ subject: clientId, audience }), {
    ...(identity === undefined ? {} : { identity }),
    algorithm: mutation.alg ?? "ES256",
    headers,
  });
  const form = {
    grant_type: JWT_BEARER,
    assertion: await ctx.assertion(ctx.claims({ subject: user, audience: metadata.token_endpoint })),
    client_id: clientId,
    client_assertion_type: CLIENT_ASSERTION,
    client_assertion: clientAssertion,
  };
  const response = await ctx.tokenRequest(user, form);
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
  check(!(await response.text()).includes(clientAssertion), "a refusal never echoes the assertion");
});

caseFor(
  "security.session-assertion-bad-audience",
  "security.session-assertion-wrong-issuer",
  "security.session-assertion-clock-skew-tolerated",
  "security.session-assertion-from-the-future",
  "security.session-assertion-expired",
  "security.session-assertion-long-lived",
  "security.session-assertion-replay",
  "security.browser-assertion-at-token-endpoint",
)(async (ctx, fixture) => {
  const metadata = await ctx.metadata();
  const mutation = fixture.mutation;
  const user = ctx.newUser();
  const claims = ctx.claims({
    subject: user,
    audience: mutation.aud ?? metadata.token_endpoint,
    lifetime: Number(mutation.lifetime ?? 60),
    shift: Number(mutation.iat_offset ?? 0),
  });
  if ("iss" in mutation) claims.iss = mutation.iss;
  const assertion = await ctx.assertion(claims, { headers: "typ" in mutation ? { typ: mutation.typ } : {} });
  const send = async () =>
    ctx.tokenRequest(user, { grant_type: JWT_BEARER, assertion, ...(await ctx.clientForm()) });
  let response = await send();
  if (mutation.replay) {
    check(response.status === 200, "the first use of the assertion is accepted");
    response = await send();
  }
  if (fixture.expect.status === 200) {
    check(response.status === 200, `${fixture.id}: expected 200, got ${response.status}`);
    check((await response.json()).signed_in === false, "a new Session starts signed out");
    return;
  }
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
});

caseFor("security.token-request-without-dpop", "security.token-dpop-with-ath")(async (ctx, fixture) => {
  const metadata = await ctx.metadata();
  const user = ctx.newUser();
  const form = {
    grant_type: JWT_BEARER,
    assertion: await ctx.assertion(ctx.claims({ subject: user, audience: metadata.token_endpoint })),
    ...(await ctx.clientForm()),
  };
  const response = fixture.mutation.omit
    ? await ctx.tokenRequest(user, form, { dpop: null })
    : await ctx.tokenRequest(user, form, {
        dpop: await ctx.proof(user, "POST", metadata.token_endpoint, { token: fixture.mutation.ath }),
      });
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
});

// Security: proofs at a resource -------------------------------------------------------------

caseFor(
  "security.dpop-alg-none",
  "security.dpop-wrong-signature",
  "security.dpop-other-key",
  "security.dpop-method-mismatch",
  "security.dpop-url-mismatch",
  "security.dpop-stale",
  "security.dpop-replay",
  "security.dpop-token-hash-mismatch",
  "security.dpop-missing",
  "security.dpop-token-as-bearer",
)(async (ctx, fixture) => {
  const mutation = fixture.mutation;
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const url = ctx.url(ctx.scenario.read_path);
  const token = session.accessToken.reveal();
  const valid = () => ctx.proof(user, "GET", url, { token: session });
  const control = await ctx.send("GET", url, { headers: { Authorization: `DPoP ${token}`, DPoP: await valid() } });
  check(![400, 401].includes(control.status), "a valid proof is accepted");
  const headers = { Authorization: `${mutation.scheme ?? "DPoP"} ${token}` };
  if (mutation.alg === "none") {
    const proof = await valid();
    const header = JSON.parse(Buffer.from(proof.split(".")[0], "base64url").toString());
    headers.DPoP = `${segment({ ...header, alg: "none" })}.${proof.split(".")[1]}.`;
  } else if (mutation.tamper_signature) {
    const [first, second] = [await valid(), await valid()];
    headers.DPoP = [...first.split(".").slice(0, 2), second.split(".")[2]].join(".");
  } else if (mutation.key === "other") {
    headers.DPoP = await ctx.proof(ctx.newUser(), "GET", url, { token: session });
  } else if ("htm" in mutation) {
    headers.DPoP = await ctx.proof(user, mutation.htm, url, { token: session });
  } else if ("htu" in mutation) {
    headers.DPoP = await ctx.proof(user, "GET", mutation.htu, { token: session });
  } else if ("iat_offset" in mutation) {
    headers.DPoP = await ctx.proof(user, "GET", url, { token: session, shift: mutation.iat_offset });
  } else if (mutation.replay) {
    const replayed = await valid();
    const used = await ctx.send("GET", url, { headers: { ...headers, DPoP: replayed } });
    check(![400, 401].includes(used.status), "the first use of the proof is accepted");
    headers.DPoP = replayed;
  } else if ("ath" in mutation) {
    headers.DPoP = await ctx.proof(user, "GET", url, { token: mutation.ath });
  } else if (!mutation.omit) {
    headers.DPoP = await valid();
  }
  const response = await ctx.send("GET", url, { headers });
  await expectRefusal(response, fixture.expect.status, fixture.expect.error, fixture.id);
  check(!(await response.text()).includes(token), "a refusal never echoes the Session Token");
  if (response.status === 401) check(response.headers.has("www-authenticate"), "a refusal carries WWW-Authenticate");
});

caseFor("security.token-in-url-refused")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const url = ctx.url(ctx.scenario.read_path);
  const proof = await ctx.proof(user, "GET", url, { token: session });
  const response = await ctx.send("GET", `${url}?${new URLSearchParams({ access_token: session.accessToken.reveal() })}`, {
    headers: { DPoP: proof },
  });
  // Any refusal will do (§4.3 says only MUST NOT accept): 400 or 401 are both seen.
  check(response.status >= 400 && response.status < 500, `a token in the URL: expected a refusal, got ${response.status}`);
  check(!(await response.text()).includes(session.accessToken.reveal()), "a refusal never echoes the Session Token");
});

caseFor("security.authorization-header-without-cookies")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const endpoint = await ctx.conversationsEndpoint();
  const response = await ctx.send("POST", endpoint, {
    headers: {
      Authorization: `DPoP ${session.accessToken.reveal()}`,
      DPoP: await ctx.proof(user, "POST", endpoint, { token: session }),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ message: message(ctx.scenario.greeting) }),
  });
  check(response.status === 201, `served without cookies: got ${response.status}`);
});

caseFor("security.token-responses-not-cached")(async (ctx) => {
  const metadata = await ctx.metadata();
  const user = ctx.newUser();
  const issued = await ctx.tokenRequest(user, {
    grant_type: JWT_BEARER,
    assertion: await ctx.assertion(ctx.claims({ subject: user, audience: metadata.token_endpoint })),
    ...(await ctx.clientForm()),
  });
  check(issued.status === 200, "the Session starts");
  check((issued.headers.get("cache-control") ?? "").includes("no-store"), "a token response is not cached");
  if (metadata.device_authorization_endpoint) {
    const form = {
      scope: ctx.scenario.read_scope,
      ...(await ctx.clientForm()),
      client_assertion: await ctx.assertion(
        ctx.claims({ subject: ctx.agent.identity.clientId, audience: metadata.device_authorization_endpoint }),
      ),
    };
    const codes = await ctx.send("POST", metadata.device_authorization_endpoint, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form).toString(),
    });
    check(codes.status === 200, "Device Sign-In starts");
    check((codes.headers.get("cache-control") ?? "").includes("no-store"), "a device-code response is not cached");
  }
});

caseFor("security.refusals-disclose-no-credential")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const accountToken = ctx.accountToken(signed.reference);
  const form = {
    grant_type: "refresh_token",
    refresh_token: accountToken,
    session_id: session.sessionId,
    ...(await ctx.clientForm()),
  };
  form.client_assertion = await ctx.assertion(
    ctx.claims({ subject: ctx.agent.identity.clientId, audience: "https://elsewhere.example/t" }),
  );
  const refusedToken = await ctx.tokenRequest(user, form);
  check([400, 401].includes(refusedToken.status), "a bad client assertion is refused");
  const text = await refusedToken.text();
  for (const secret of [accountToken, form.client_assertion]) check(!text.includes(secret), "a token refusal never echoes a credential");
  const url = ctx.url(ctx.scenario.read_path);
  const used = await ctx.send("GET", url, {
    headers: { Authorization: `DPoP ${accountToken}`, DPoP: await ctx.proof(user, "GET", url, { token: accountToken }) },
  });
  await expectRefusal(used, 401, "invalid_token", "an Account Token at an API");
  check(!(await used.text()).includes(accountToken), "an API refusal never echoes a credential");
});

// Lifecycle ---------------------------------------------------------------------------------

async function probe(ctx, user, token) {
  return (await ctx.read(user, ctx.url(ctx.scenario.read_path), token)).status;
}

caseFor("lifecycle.signed-out-session")(async (ctx) => {
  const session = await ctx.session(ctx.newUser());
  check(session.tokenType === "DPoP", "a proof-bound Session Token is DPoP");
  check(session.expiresIn > 0 && session.expiresIn <= 24 * 3600, "Session Tokens last hours, not days");
  check(!session.signedIn && session.scopes.length === 0, "a new Session is signed out");
});

caseFor("lifecycle.parallel-sessions")(async (ctx) => {
  const user = ctx.newUser();
  const [first, second] = await Promise.all([ctx.session(user), ctx.session(user)]);
  check(first.sessionId !== second.sessionId, "parallel Sessions are distinct");
  const endpoint = await ctx.conversationsEndpoint();
  for (const session of [first, second]) {
    const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), { ...(await ctx.who(user)), token: session });
    check(receipt.conversation_id, "each Session is served");
  }
});

caseFor("lifecycle.renew-signed-out")(async (ctx) => {
  const user = ctx.newUser();
  const old = await ctx.session(user);
  const renewed = await ctx.renew(user, old.sessionId);
  check(renewed.sessionId === old.sessionId, "renewal keeps the Session");
  check((await probe(ctx, user, renewed)) === 403, "the new token is served (signed out)");
  // Whether the replaced token stops at once is the company's choice (no MUST in §4.2).
});

caseFor("lifecycle.renew-for-another-user")(async (ctx) => {
  const owner = await ctx.session(ctx.newUser());
  const error = await refused(ctx.renew(ctx.newUser(), owner.sessionId), "renewal for another user");
  check(error.code === "invalid_session", `got ${error.code}`);
});

caseFor("lifecycle.sign-in-scopes")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const granted = [ctx.scenario.read_scope];
  const signed = await ctx.signIn(user, session, { granted });
  check(signed.token.signedIn, "the Session is signed in");
  check(signed.token.sessionId === session.sessionId, "the same Session is signed in");
  check(JSON.stringify(signed.token.scopes) === JSON.stringify(granted), "only what the user approved is granted");
});

caseFor("lifecycle.unknown-scope-refused")(async (ctx) => {
  const metadata = await ctx.metadata();
  if (!metadata.device_authorization_endpoint) throw new SkipCase("no Device Sign-In");
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const error = await refused(
    ctx.agent.device.begin({
      deviceAuthorizationEndpoint: metadata.device_authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: ctx.agent.identity.clientId,
      scopes: ["conformance:not-a-scope"],
      tenantId: ctx.tenantId,
      pairwiseUserId: user,
      sessionId: session.sessionId,
    }),
    "an unknown scope",
  );
  check(error.code === "invalid_scope", `got ${error.code}`);
});

caseFor("lifecycle.account-token-signs-in-new-session")(async (ctx) => {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const fresh = await ctx.session(user);
  const result = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user), sessionId: fresh.sessionId });
  check(result.status === "signed_in" && result.token !== undefined, "the Session signs in");
  check((await probe(ctx, user, result.token)) === 200, "it reads");
});

caseFor("lifecycle.rotated-token")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const before = ctx.accountToken(signed.reference);
  const context = await ctx.accountContext(user);
  const result = await ctx.agent.accounts.refresh(signed.reference, { context, sessionId: session.sessionId });
  if (!result.rotated) throw new SkipCase("the company does not rotate Account Tokens");
  const old = await ctx.tokenRequest(user, {
    grant_type: "refresh_token",
    refresh_token: before,
    session_id: session.sessionId,
    ...(await ctx.clientForm()),
  });
  await expectRefusal(old, 400, "invalid_grant", "a rotated-away Account Token");
  const again = await ctx.agent.accounts.refresh(signed.reference, { context, sessionId: session.sessionId });
  check(again.status === "signed_in", "the stored, rotated token keeps working");
});

caseFor("lifecycle.narrower-scopes")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const result = await ctx.agent.accounts.refresh(signed.reference, {
    context: await ctx.accountContext(user),
    sessionId: session.sessionId,
    scopes: [ctx.scenario.read_scope],
  });
  check(result.status === "signed_in", "a narrower refresh signs in");
  check(JSON.stringify(result.grantedScopes) === JSON.stringify([ctx.scenario.read_scope]), "only the narrower scope");
});

caseFor("lifecycle.wider-scopes-refused")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session, { granted: [ctx.scenario.read_scope] });
  const result = await ctx.agent.accounts.refresh(signed.reference, {
    context: await ctx.accountContext(user),
    sessionId: session.sessionId,
    scopes: ctx.scenario.scopes,
  });
  check(result.status === "re_consent_required", `got ${result.status}`);
});

caseFor("lifecycle.account-token-from-another-client")(async (ctx) => {
  const other = ctx.otherAgent();
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const otherSession = await ctx.session(user, other);
  const metadata = await ctx.metadata();
  const response = await ctx.tokenRequest(
    user,
    {
      grant_type: "refresh_token",
      refresh_token: ctx.accountToken(signed.reference),
      session_id: otherSession.sessionId,
      ...(await ctx.clientForm(other.identity)),
    },
    { dpop: await ctx.proof(user, "POST", metadata.token_endpoint, { agent: other }) },
  );
  await expectRefusal(response, 400, "invalid_grant", "another client's Account Token");
});

caseFor("lifecycle.account-token-at-api")(async (ctx) => {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const secret = ctx.accountToken(signed.reference);
  const url = ctx.url(ctx.scenario.read_path);
  const response = await ctx.send("GET", url, {
    headers: { Authorization: `DPoP ${secret}`, DPoP: await ctx.proof(user, "GET", url, { token: secret }) },
  });
  await expectRefusal(response, 401, "invalid_token", "an Account Token at an API");
});

caseFor("lifecycle.account-mismatch")(async (ctx) => {
  const user = ctx.newUser();
  const [first, second] = ctx.driver.accounts;
  const signed = await ctx.signIn(user, await ctx.session(user), { account: first });
  const otherSession = await ctx.session(user);
  await ctx.signIn(user, otherSession, { account: second });
  const error = await refused(
    ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user), sessionId: otherSession.sessionId }),
    "a refresh into another account's Session",
  );
  check(error.code === "account_mismatch", `got ${error.code}`);
});

caseFor("lifecycle.account-token-for-another-users-session")(async (ctx) => {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  const stranger = await ctx.session(ctx.newUser());
  const error = await refused(
    ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user), sessionId: stranger.sessionId }),
    "a refresh into another user's Session",
  );
  check(error.code === "invalid_session", `got ${error.code}`);
});

caseFor("lifecycle.sign-out-takes-effect")(async (ctx) => {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  check((await probe(ctx, user, signed.token)) === 200, "signed in, the read is served");
  const revoked = await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  check(revoked.revoked && revoked.deletedLocally, "the Account Token is revoked and gone");
  check((await probe(ctx, user, signed.token)) === 403, "the earlier signed-in token is handled as signed out right away");
});

caseFor("lifecycle.sign-out-session-continues")(async (ctx) => {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  const secret = ctx.accountToken(signed.reference);
  await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  const renewed = await ctx.renew(user, session.sessionId);
  check(!renewed.signedIn, "the Session continues signed out");
  const response = await ctx.tokenRequest(user, {
    grant_type: "refresh_token",
    refresh_token: secret,
    session_id: session.sessionId,
    ...(await ctx.clientForm()),
  });
  await expectRefusal(response, 400, "invalid_grant", "a revoked token");
});

caseFor("lifecycle.sign-out-every-session")(async (ctx) => {
  const user = ctx.newUser();
  const first = await ctx.session(user);
  const signed = await ctx.signIn(user, first);
  const second = await ctx.session(user);
  const context = await ctx.accountContext(user);
  const rotated = await ctx.agent.accounts.refresh(signed.reference, { context, sessionId: second.sessionId });
  check(rotated.status === "signed_in" && rotated.token !== undefined, "a second Session signs in");
  await ctx.agent.accounts.revoke(signed.reference, { context });
  for (const token of [signed.token, rotated.token]) {
    check((await probe(ctx, user, token)) === 403, "every Session from the sign-in is signed out");
  }
  check(!(await ctx.renew(user, first.sessionId)).signedIn, "renewing with the assertion gives a signed-out token");
});

caseFor("lifecycle.disconnect-from-account-settings")(async (ctx) => {
  ctx.require("disconnect");
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const signed = await ctx.signIn(user, session);
  await ctx.driver.disconnect(ctx.agent.identity.clientId, ctx.driver.accounts[0]);
  check((await probe(ctx, user, signed.token)) === 403, "its Sessions are signed out");
  const result = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user), sessionId: session.sessionId });
  check(result.status === "signed_out", "the agent finds out from invalid_grant");
  check(!ctx.agent.tokens.has(signed.reference), "and forgets the token");
});

// Conversations ------------------------------------------------------------------------------

async function conversationOf(ctx, user, session) {
  const endpoint = await ctx.conversationsEndpoint();
  const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), { ...(await ctx.who(user)), token: session });
  return receipt.conversation_id;
}

async function asUser(ctx) {
  const user = ctx.newUser();
  const session = await ctx.session(user);
  return { user, session, endpoint: await ctx.conversationsEndpoint(), who: { ...(await ctx.who(user)), token: session } };
}

caseFor("conversations.start-and-reply")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const receipt = await ctx.agent.conversations.start(endpoint, message(ctx.scenario.greeting), who);
  check(receipt.status && receipt.responder, "the answer has status and responder");
  const body = await (await ctx.read(user, `${endpoint}/${receipt.conversation_id}/events`, session)).json();
  for (const key of ["cursor", "has_more", "status", "responder"]) check(key in body, `a read includes ${key}`);
  const company = body.events.filter((event) => event.type === "message" && event.message.role === "company").map((event) => event.message);
  check(company.length, "the company replies");
  check(company.every((item) => ["agent", "human"].includes(item.sender)), "replies carry sender");
});

caseFor("conversations.retry-replays")(async (ctx) => {
  const { endpoint, who } = await asUser(ctx);
  const first = message(ctx.scenario.greeting);
  const receipt = await ctx.agent.conversations.start(endpoint, first, who);
  const page = await ctx.agent.conversations.readEvents(endpoint, receipt.conversation_id, who);
  const again = await ctx.agent.conversations.start(endpoint, first, who);
  check(again.conversation_id === receipt.conversation_id, "a retry returns the same one");
  const after = await ctx.agent.conversations.readEvents(endpoint, receipt.conversation_id, who);
  check(after.events.length === page.events.length, "a retry adds nothing");
});

caseFor("conversations.message-id-conflict")(async (ctx) => {
  const { endpoint, who } = await asUser(ctx);
  const first = message(ctx.scenario.greeting);
  await ctx.agent.conversations.start(endpoint, first, who);
  const error = await refused(ctx.agent.conversations.start(endpoint, { ...first, text: "Something else entirely." }, who), "a changed message");
  check(error.code === "message_id_conflict", `got ${error.code}`);
  check(error.statusCode === 409, "message_id_conflict is HTTP 409");
});

caseFor("conversations.invalid-cursor")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  const error = await refused(
    ctx.agent.conversations.readEvents(endpoint, conversation, { ...who, cursor: "evt_never_issued_by_the_company" }),
    "an unknown cursor",
  );
  check(error.code === "invalid_cursor", `got ${error.code}`);
  check(error.statusCode === 400, "invalid_cursor is HTTP 400");
});

caseFor("conversations.cursor-expired-recovery")(async (ctx) => {
  ctx.require("forget_events");
  const { user, session, endpoint, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, who);
  const saved = page.events[0].id;
  await ctx.agent.conversations.send(endpoint, conversation, message("One more thing."), who);
  await ctx.driver.forgetEvents(conversation);
  const error = await refused(ctx.agent.conversations.readEvents(endpoint, conversation, { ...who, cursor: saved }), "a forgotten cursor");
  check(error.code === "cursor_expired", `got ${error.code}`);
  check(error.statusCode === 410, "cursor_expired is HTTP 410");
  const told = [];
  const events = ctx.agent.conversations.events(endpoint, conversation, {
    ...who,
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
  const { user, session, endpoint, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  let page = await ctx.agent.conversations.readEvents(endpoint, conversation, who);
  let sent = 0;
  while (!page.has_more && sent < 80) {
    await ctx.agent.conversations.send(endpoint, conversation, message(`Note ${sent}.`), who);
    sent += 1;
    if (sent % 10 === 0) page = await ctx.agent.conversations.readEvents(endpoint, conversation, who);
  }
  if (!page.has_more) throw new SkipCase("the company returned every event in one page");
  const ids = [];
  let cursor;
  while (true) {
    const current = await ctx.agent.conversations.readEvents(endpoint, conversation, { ...who, ...(cursor ? { cursor } : {}) });
    ids.push(...current.events.map((event) => event.id));
    cursor = current.cursor;
    if (!current.has_more) break;
  }
  check(new Set(ids).size === ids.length, "draining has_more pages repeats nothing");
  check(JSON.stringify(ids.slice(0, page.events.length)) === JSON.stringify(page.events.map((event) => event.id)), "pages keep the order");
});

caseFor("conversations.empty-read")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, who);
  const empty = await ctx.agent.conversations.readEvents(endpoint, conversation, { ...who, cursor: page.cursor });
  check(empty.events.length === 0, "nothing new: no events");
  check(empty.cursor === page.cursor, "the cursor is the request's own");
  check(empty.has_more === false, "has_more is false");
});

const isEvent = (item) => item.kind === undefined;

async function streamItems(ctx, who, conversation, { lastEventId, until }) {
  const endpoint = await ctx.conversationsEndpoint();
  const items = [];
  const stream = ctx.agent.conversations.stream(endpoint, conversation, {
    ...who,
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

caseFor("conversations.sse-reconnect")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  await ctx.agent.conversations.send(endpoint, conversation, message("And another question."), who);
  const ids = (await ctx.agent.conversations.readEvents(endpoint, conversation, who)).events.map((event) => event.id);
  check(ids.length >= 3, "the conversation has events to stream");
  const eventsOf = (items) => items.filter(isEvent);
  const first = await streamItems(ctx, who, conversation, { until: (items) => eventsOf(items).length >= 2 });
  const handled = eventsOf(first).at(-1).id;
  const resumed = await streamItems(ctx, who, conversation, { lastEventId: handled, until: (items) => eventsOf(items).length >= 1 });
  check(eventsOf(resumed)[0].id === ids[ids.indexOf(handled) + 1], "the stream resumes right after Last-Event-ID");
});

caseFor("conversations.text-delta-not-actionable")(async (ctx) => {
  const { user, session, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  const items = await streamItems(ctx, who, conversation, {
    until: (seen) => seen.some((item) => isEvent(item) && item.message?.role === "company"),
  });
  const deltas = items.filter((item) => item.kind === "text-delta");
  if (!deltas.length) throw new SkipCase("the company sends no text-delta pieces");
  check(deltas.every((delta) => delta.actionable === false), "a delta is never actionable");
  const complete = new Set(items.filter((item) => isEvent(item) && item.message).map((item) => item.message.id));
  for (const delta of deltas) check(complete.has(delta.message_id), "the complete message replaces the pieces");
});

caseFor("conversations.attribution")(async (ctx) => {
  const { endpoint, who } = await asUser(ctx);
  const words = message("These are the user's own words.", "human");
  const receipt = await ctx.agent.conversations.start(endpoint, words, who);
  const page = await ctx.agent.conversations.readEvents(endpoint, receipt.conversation_id, who);
  const messages = page.events.filter((event) => event.message).map((event) => event.message);
  const mine = messages.filter((item) => item.id === words.id);
  check(mine.length && mine[0].role === "user", "the user's message comes back with role user");
  check(mine.length && mine[0].sender === "human", "and keeps sender human");
  const theirs = messages.filter((item) => item.role === "company");
  check(theirs.length && theirs.every((item) => ["agent", "human"].includes(item.sender)), "replies have sender");
});

caseFor("conversations.handoff")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  const receipt = await ctx.agent.conversations.handoff(endpoint, conversation, who);
  check(["queued", "idle", "working"].includes(receipt.status), "handoff answers a status");
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, who);
  const states = page.events.filter((event) => event.type === "state");
  check(states.length, "each status change is a state event");
  check(states.at(-1).status === page.status, "the last state event is the current status");
  check(states.at(-1).responder === page.responder, "and the current responder");
});

caseFor("conversations.direct-conversation")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const parent = await conversationOf(ctx, user, session);
  const direct = await ctx.agent.conversations.startDirect(endpoint, parent, message("I'd like to ask myself.", "human"), who);
  let page = await ctx.agent.conversations.readEvents(endpoint, parent, who);
  const opened = page.events.filter((event) => event.type === "direct_opened");
  check(opened.length && opened.at(-1).conversation_id === direct.conversation_id, "direct_opened");
  const error = await refused(ctx.agent.conversations.send(endpoint, parent, message("Meanwhile."), who), "a message while Direct");
  check(error.code === "direct_conversation_open", `got ${error.code}`);
  check(error.details?.conversation_id === direct.conversation_id, "the refusal names the Direct Conversation");
  await ctx.agent.conversations.close(endpoint, direct.conversation_id, who);
  page = await ctx.agent.conversations.readEvents(endpoint, parent, who);
  check(page.events.some((event) => event.type === "direct_closed"), "direct_closed");
  await ctx.agent.conversations.send(endpoint, parent, message("Back to you."), who);
});

caseFor("conversations.direct-of-direct-refused")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const parent = await conversationOf(ctx, user, session);
  const direct = await ctx.agent.conversations.startDirect(endpoint, parent, message("Hi.", "human"), who);
  const error = await refused(ctx.agent.conversations.startDirect(endpoint, direct.conversation_id, message("Hi.", "human"), who), "a Direct of a Direct");
  check(["conversation_not_found", "conversation_closed", "direct_conversation_open"].includes(error.code), `got ${error.code}`);
});

caseFor("conversations.authorization-then-same-conversation")(async (ctx) => {
  const prompt = ctx.scenario.account_prompt;
  if (!prompt) throw new SkipCase("the scenario has no account prompt");
  const { user, session, endpoint, who } = await asUser(ctx);
  const receipt = await ctx.agent.conversations.start(endpoint, message(prompt), who);
  const page = await ctx.agent.conversations.readEvents(endpoint, receipt.conversation_id, who);
  check(page.events.some((event) => event.type === "authorization"), "the company asks for sign-in with an authorization event");
  check(page.events.some((event) => event.message?.role === "company"), "and says so in a message");
  const signed = await ctx.signIn(user, session);
  const again = await ctx.agent.conversations.send(endpoint, receipt.conversation_id, message(prompt), { ...who, token: signed.token });
  check(again.conversation_id === receipt.conversation_id, "the same conversation continues");
});

caseFor("conversations.closed")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const conversation = await conversationOf(ctx, user, session);
  const closed = await ctx.agent.conversations.close(endpoint, conversation, who);
  check(closed.status === "closed", "closing answers status closed");
  const error = await refused(ctx.agent.conversations.send(endpoint, conversation, message("Still there?"), who), "a closed conversation");
  check(error.code === "conversation_closed", `got ${error.code}`);
  check(error.statusCode === 409, "conversation_closed is HTTP 409");
  const page = await ctx.agent.conversations.readEvents(endpoint, conversation, who);
  check(page.status === "closed" && page.events.length, "its events stay readable");
});

caseFor("conversations.not-found-indistinguishable")(async (ctx) => {
  const owner = ctx.newUser();
  const theirs = await conversationOf(ctx, owner, await ctx.session(owner));
  const { user, session, endpoint } = await asUser(ctx);
  const bodies = [];
  for (const conversation of [theirs, "cnv_conformance_unknown_000000"]) {
    const response = await ctx.read(user, `${endpoint}/${conversation}/events`, session);
    bodies.push(JSON.stringify([response.status, await response.json()]));
  }
  check(bodies[0] === bodies[1], "another user's and an unknown conversation look the same");
  const [status, body] = JSON.parse(bodies[0]);
  check(status === 404 && body.error === "conversation_not_found", "404 conversation_not_found");
});

caseFor("conversations.signed-out-token-on-account-conversation")(async (ctx) => {
  const { user, session, endpoint, who } = await asUser(ctx);
  const signed = await ctx.signIn(user, session);
  const conversation = await conversationOf(ctx, user, signed.token);
  await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  const signedOut = await ctx.renew(user, session.sessionId);
  const error = await refused(ctx.agent.conversations.readEvents(endpoint, conversation, { ...who, token: signedOut }), "a signed-out token");
  check(error.code === "sign_in_required", `got ${error.code}`);
});

// Operations --------------------------------------------------------------------------------

async function signedInUser(ctx) {
  const user = ctx.newUser();
  const signed = await ctx.signIn(user, await ctx.session(user));
  return { user, signed, who: { ...(await ctx.who(user)), token: signed.token } };
}

async function propose(ctx, user, signed, kind) {
  const proposal = ctx.proposal(kind);
  const response = await ctx.agent.transport.request(proposal.method, ctx.url(proposal.path), {
    ...(await ctx.who(user)),
    token: signed.token,
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(proposal.body ?? {}),
  });
  check(response.status === 202, `the API answers 202, got ${response.status}`);
  const body = await response.json();
  check(body.operation, "with an operation");
  return parseOperation(body.operation);
}

caseFor("operations.proposed-not-performed")(async (ctx) => {
  await ctx.operationsEndpoint();
  const { user, signed } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  check(operation.state === "proposed", "a proposal is proposed");
  check(operation.summary.trim(), "it has a summary");
  check(operation.confirmation === null && operation.result === null, "nothing happened yet");
  if (ctx.driver.capabilities.has("performed")) check((await ctx.driver.performed(operation.operation_id)) === 0, "nothing was performed");
  const description = (await ctx.company()).document.apis?.find((api) => api.type === "openapi");
  const documented = ctx.proposal("user").documented_as;
  if (description?.url && documented) {
    const paths = (await (await ctx.send("GET", description.url)).json()).paths ?? {};
    check(JSON.stringify(paths[documented] ?? {}).includes("operation"), "the API description says the endpoint returns an operation");
  }
});

caseFor("operations.readable-until-final")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  const read = await ctx.agent.operations.read(endpoint, operation.operation_id, who);
  check(JSON.stringify(read) === JSON.stringify(operation), "the same operation, unchanged");
});

caseFor("operations.confirm-succeeded")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  const outcome = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  const done = outcome.operation;
  check(outcome.status === "confirmed" && done.state === "succeeded", `got ${done?.state}`);
  check(done.confirmation !== null, "the confirmation is recorded");
  check(done.confirmation.revision === operation.revision, "for the approved revision");
  check(done.confirmation.approved_by === "user", "approved by the user");
  check(done.result?.summary, "the result says what happened");
  check(JSON.stringify(done.terms) === JSON.stringify(operation.terms), "it did what the revision described");
});

caseFor("operations.at-most-once")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  const approval = await approve(operation);
  const first = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval });
  const second = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval });
  check(JSON.stringify(first.operation) === JSON.stringify(second.operation), "a repeated confirm returns the same record");
  if (ctx.driver.capabilities.has("performed")) check((await ctx.driver.performed(operation.operation_id)) === 1, "performed once");
});

caseFor("operations.terms-changed")(async (ctx) => {
  ctx.require("revise");
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  await ctx.driver.revise(operation.operation_id);
  const outcome = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  check(outcome.status === "terms_changed", `got ${outcome.status}`);
  const current = outcome.operation;
  check(current.revision === operation.revision + 1, "the current revision comes back");
  check(outcome.changed.length, "with what changed");
  const done = await ctx.agent.operations.confirm(endpoint, current, { ...who, approval: await approve(current) });
  check(done.status === "confirmed", "the new revision, approved, confirms");
});

caseFor("operations.user-approval-required")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  if (!operation.user_approval_required) throw new SkipCase("the user proposal does not require the user's approval");
  const local = await refused(ctx.agent.operations.confirm(endpoint, operation, { ...who, standing: ["company", "account", "action"] }), "a standing permission");
  check(local.code === "user_approval_required", "the SDK refuses it locally");
  const url = `${endpoint}/${operation.operation_id}/confirm`;
  const response = await ctx.send("POST", url, {
    headers: {
      Authorization: `DPoP ${signed.token.accessToken.reveal()}`,
      DPoP: await ctx.proof(user, "POST", url, { token: signed.token }),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ revision: operation.revision, approved_by: "standing_permission" }),
  });
  await expectRefusal(response, 403, "user_approval_required", "a standing permission");
});

function permission(ctx, limits, usesRemaining) {
  const action = ctx.scenario.standing_action;
  if (!action) throw new SkipCase("the scenario has no standing-permission action");
  ctx.agent.standing.permissions.clear();
  const reference = opaque("perm");
  const company = ctx.domain;
  const account = ctx.driver.accounts[0];
  ctx.agent.standing.permissions.set(reference, {
    reference,
    company,
    account,
    action,
    limits,
    expiresAt: new Date(ctx.now().getTime() + 3600_000),
    ...(usesRemaining === undefined ? {} : { usesRemaining }),
  });
  return [company, account, action];
}

caseFor("operations.standing-permission-within-bounds")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const standing = permission(ctx, ctx.scenario.standing_limits, 2);
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "standing");
  const outcome = await ctx.agent.operations.confirm(endpoint, operation, { ...who, standing });
  check(outcome.status === "confirmed", `got ${outcome.status}`);
  check(outcome.operation.confirmation?.approved_by === "standing_permission", "under the standing permission");
});

caseFor("operations.standing-permission-out-of-bounds")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  if (!ctx.scenario.standing_too_low?.length) throw new SkipCase("the scenario has no out-of-bounds limits");
  const standing = permission(ctx, ctx.scenario.standing_too_low, undefined);
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "standing");
  const error = await refused(ctx.agent.operations.confirm(endpoint, operation, { ...who, standing }), "an out-of-bounds permission");
  check(error.code === "no_standing_permission", `got ${error.code}`);
  const read = await ctx.agent.operations.read(endpoint, operation.operation_id, who);
  check(read.state === "proposed", "nothing was sent: the user is asked instead");
});

caseFor("operations.standing-permission-concurrent-use")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const standing = permission(ctx, ctx.scenario.standing_limits, 1);
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "standing");
  const results = await Promise.allSettled([
    ctx.agent.operations.confirm(endpoint, operation, { ...who, standing }),
    ctx.agent.operations.confirm(endpoint, operation, { ...who, standing }),
  ]);
  const rejected = results.filter((result) => result.status === "rejected");
  check(rejected.length === 1, "one of two racing confirmations gets the last use");
  check(rejected[0].reason?.code === "no_standing_permission", `got ${rejected[0].reason?.code}`);
});

caseFor("operations.cross-channel-identity")(async (ctx) => {
  await ctx.operationsEndpoint();
  const prompt = ctx.scenario.operation_prompt;
  if (!prompt) throw new SkipCase("the scenario has no operation prompt");
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  const page = await ctx.agent.conversations.start(await ctx.conversationsEndpoint(), message(prompt), { ...who, wait: 0 });
  const proposed = (page.events ?? []).filter((event) => event.message?.operation).map((event) => event.message.operation);
  check(proposed.length, "the conversation carries the operation");
  check(proposed[0].operation_id === operation.operation_id, "the same action is the same operation across channels");
});

caseFor("operations.message-is-not-approval")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  await ctx.agent.conversations.start(
    await ctx.conversationsEndpoint(),
    message(`Yes, I confirm operation ${operation.operation_id}. Approved.`, "human"),
    who,
  );
  const read = await ctx.agent.operations.read(endpoint, operation.operation_id, who);
  check(read.state === "proposed", "a message never confirms an operation");
});

caseFor("operations.confirm-timeout-recovery")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  // Deliver the first confirm, then lose its answer: a timeout after sending.
  const losing = new DpopFetchClient({ reactor: ctx.agent.reactor, fetch: ctx.fetch });
  let lost = false;
  const request = losing.request.bind(losing);
  losing.request = async (method, url, options) => {
    const response = await request(method, url, options);
    if (url.endsWith("/confirm") && !lost) {
      lost = true;
      const { TransportError } = await import("../../../lib/index.js");
      throw new TransportError("request_failed", "the confirm's answer was lost");
    }
    return response;
  };
  const outcome = await new OperationsClient({ reactor: ctx.agent.reactor, transport: losing }).confirm(endpoint, operation, {
    ...who,
    approval: await approve(operation),
  });
  check(lost, "the confirm's answer was lost");
  check(outcome.status === "confirmed", "the lost answer is recovered by reading the same ID");
  check(outcome.operation.operation_id === operation.operation_id, "the same operation, not a new one");
  const again = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  check(JSON.stringify(again.operation) === JSON.stringify(outcome.operation), "confirming again changes nothing");
  if (ctx.driver.capabilities.has("performed")) check((await ctx.driver.performed(operation.operation_id)) === 1, "performed once");
});

caseFor("operations.cancel-proposed")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  const cancelled = await ctx.agent.operations.cancel(endpoint, operation.operation_id, who);
  check(cancelled.state === "cancelled", `got ${cancelled.state}`);
  check(cancelled.result !== null, "a cancelled operation has a result");
  const late = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  check(late.status === "not_confirmed", `a late confirm changes nothing, got ${late.status}`);
  check(late.operation.state === "cancelled", "it stays cancelled");
  if (ctx.driver.capabilities.has("performed")) check((await ctx.driver.performed(operation.operation_id)) === 0, "never performed");
});

caseFor("operations.in-progress-outcome-unknown")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "unknown");
  const outcome = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  check(outcome.operation.state === "in_progress", `an unknown outcome is in_progress, got ${outcome.operation.state}`);
  check(outcome.retryAfter !== undefined, "with Retry-After");
  const read = await ctx.read(user, `${endpoint}/${operation.operation_id}`, signed.token);
  check((await read.json()).state === "in_progress", "never failed while unknown");
  check(read.headers.has("retry-after"), "a read in progress carries Retry-After");
  const cancelled = await ctx.agent.operations.cancel(endpoint, operation.operation_id, who);
  check(cancelled.state === "in_progress", "cancelling leaves it in progress until known");
});

caseFor("operations.failed-partial-result")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "fails");
  const outcome = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  check(outcome.operation.state === "failed", `got ${outcome.operation.state}`);
  check(outcome.operation.result?.summary, "the result says what was changed");
});

caseFor("operations.expired")(async (ctx) => {
  ctx.require("clock");
  const endpoint = await ctx.operationsEndpoint();
  const { user, signed } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  check(operation.expires_at, "a proposal has expires_at");
  await ctx.driver.wait((Date.parse(operation.expires_at) - ctx.now().getTime()) / 1000 + 1);
  // The Session Token may have expired meanwhile: sign the Session in again.
  const refreshed = await ctx.agent.accounts.refresh(signed.reference, { context: await ctx.accountContext(user), sessionId: signed.token.sessionId });
  const who = { ...(await ctx.who(user)), token: refreshed.token };
  const read = await ctx.agent.operations.read(endpoint, operation.operation_id, who);
  check(read.state === "expired", `got ${read.state}`);
  const late = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  check(late.status === "not_confirmed", "an expired operation is returned as it is");
});

caseFor("operations.not-found-indistinguishable")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const owner = await signedInUser(ctx);
  const theirs = await propose(ctx, owner.user, owner.signed, "user");
  const { who } = await signedInUser(ctx);
  const answers = [];
  for (const operationId of [theirs.operation_id, "op_conformance_unknown_0000"]) {
    const error = await refused(ctx.agent.operations.read(endpoint, operationId, who), "an operation not the user's");
    answers.push(`${error.code} ${error.statusCode}`);
  }
  check(answers[0] === answers[1], "another user's and an unknown operation look the same");
  check(answers[0] === "operation_not_found 404", `got ${answers[0]}`);
});

// MCP (§4.3, §6) ----------------------------------------------------------------------------

async function mcpUrl(ctx) {
  const api = mcpApi((await ctx.company()).document);
  if (api === undefined) throw new SkipCase("the company lists no MCP server");
  return api.url;
}

function tool(name) {
  if (!name) throw new SkipCase("the scenario names no MCP tool for this");
  return name;
}

async function signedInBearer(ctx) {
  const url = await mcpUrl(ctx);
  const { user, signed } = await signedInUser(ctx);
  const result = await ctx.agent.accounts.bearerForMcp(signed.reference, {
    context: await ctx.accountContext(user),
    sessionId: signed.token.sessionId,
    resource: url,
  });
  check(result.status === "signed_in" && result.token !== undefined, "a signed-in Bearer");
  return { user, signed, bearer: result.token, url };
}

function mcpClient(ctx, token, url) {
  return new McpClient({ token, url, fetch: ctx.fetch });
}

caseFor("lifecycle.mcp-protected-resource-metadata")(async (ctx) => {
  const url = await mcpUrl(ctx);
  const metadata = await ctx.metadata();
  const parts = new URL(url);
  const location = `https://${parts.host}/.well-known/oauth-protected-resource${parts.pathname}`;
  const document = await (await ctx.send("GET", location)).json();
  check(document.resource === url, "the metadata names the MCP server as its resource");
  check((document.authorization_servers ?? []).includes(metadata.issuer), "authorization_servers includes auth.issuer");
  const bare = await ctx.send("POST", url, {
    headers: { "Content-Type": "application/json" },
    body: '{"jsonrpc":"2.0","id":1,"method":"ping"}',
  });
  check(bare.status === 401, "an unauthenticated MCP call is 401");
  const challenge = bare.headers.get("www-authenticate") ?? "";
  check(challenge.startsWith("Bearer") && challenge.includes("resource_metadata"), "Bearer challenge");
});

caseFor("lifecycle.mcp-bearer-for-its-url")(async (ctx) => {
  const readTool = tool(ctx.scenario.mcp_read_tool);
  const { signed, bearer, url } = await signedInBearer(ctx);
  check(bearer.tokenType === "Bearer", "a Bearer token");
  check(bearer.sessionId === signed.token.sessionId, "for the same Session");
  const answer = await mcpClient(ctx, bearer, url).callTool(readTool);
  check(!answer.isError, "the MCP server accepts it");
  const metadata = await ctx.metadata();
  const other = ctx.newUser();
  const session = await ctx.session(other);
  const signedOut = await ctx.agent.sessions.bearerForMcp({
    clientId: ctx.agent.identity.clientId,
    pairwiseUserId: other,
    issuer: metadata.issuer,
    tokenEndpoint: metadata.token_endpoint,
    tenantId: ctx.tenantId,
    sessionId: session.sessionId,
    resource: url,
  });
  check(!signedOut.signedIn, "a signed-out Session gets a signed-out Bearer");
  const error = await refused(mcpClient(ctx, signedOut, url).callTool(readTool), "a signed-out Bearer");
  check(
    error.code === "sign_in_required" || error.code === "insufficient_scope",
    `the MCP server enforces scopes, got ${error.code}`,
  );
});

caseFor("lifecycle.mcp-bearer-only-at-mcp")(async (ctx) => {
  const { user, signed, bearer, url } = await signedInBearer(ctx);
  const secret = bearer.accessToken.reveal();
  const targets = [["GET", ctx.url(ctx.scenario.read_path)]];
  try {
    targets.push(["POST", await ctx.conversationsEndpoint()]);
  } catch (error) {
    if (!(error instanceof SkipCase)) throw error;
  }
  try {
    targets.push(["GET", `${await ctx.operationsEndpoint()}/op_conformance_any`]);
  } catch (error) {
    if (!(error instanceof SkipCase)) throw error;
  }
  for (const [method, target] of targets) {
    for (const scheme of ["Bearer", "DPoP"]) {
      const headers = { Authorization: `${scheme} ${secret}`, "Content-Type": "application/json" };
      if (scheme === "DPoP") headers.DPoP = await ctx.proof(user, method, target, { token: bearer });
      const response = await ctx.send(method, target, { headers, ...(method === "GET" ? {} : { body: "{}" }) });
      check(response.status === 401, `a Bearer token is refused at ${method} ${target}`);
      check(!(await response.text()).includes(secret), "and never echoed");
    }
  }
  const dpopAtMcp = await ctx.send("POST", url, {
    headers: { Authorization: `Bearer ${signed.token.accessToken.reveal()}`, "Content-Type": "application/json" },
    body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
  });
  check(dpopAtMcp.status === 401, "the MCP server refuses a DPoP Session Token");
  const form = {
    grant_type: "refresh_token",
    refresh_token: ctx.accountToken(signed.reference),
    session_id: signed.token.sessionId,
    resource: ctx.url(ctx.scenario.read_path),
    ...(await ctx.clientForm()),
  };
  const elsewhere = await ctx.tokenRequest(user, form, { dpop: null });
  check(elsewhere.status === 400, "no Bearer token is issued for another resource");
});

caseFor("lifecycle.mcp-sign-out-takes-effect")(async (ctx) => {
  const readTool = tool(ctx.scenario.mcp_read_tool);
  const { user, signed, bearer, url } = await signedInBearer(ctx);
  const client = mcpClient(ctx, bearer, url);
  check(!(await client.callTool(readTool)).isError, "signed in, the tool answers");
  await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  const error = await refused(client.callTool(readTool), "a revoked sign-in");
  check(error.code === "sign_in_required", `got ${error.code}`);
});

caseFor("operations.cross-channel-mcp")(async (ctx) => {
  await ctx.operationsEndpoint();
  const proposeTool = tool(ctx.scenario.mcp_propose_tool);
  const { user, signed, bearer, url } = await signedInBearer(ctx);
  const throughApi = await propose(ctx, user, signed, "user");
  const answer = await mcpClient(ctx, bearer, url).callTool(proposeTool);
  check(answer.operation !== undefined, "the tool returns structuredContent.operation");
  check(JSON.stringify(answer.operation) === JSON.stringify(throughApi), "the same operation as through the API");
});

// The website (§5, Operations §4.4) --------------------------------------------------------

async function browserOf(ctx) {
  const web = (await ctx.company()).document.web;
  if (!web?.browser_session_endpoint) throw new SkipCase("the company offers no browser sessions");
  if (ctx.agent.browser === undefined) throw new SkipCase("the runner was given no browser of its own");
  return { browser: ctx.agent.browser, endpoint: web.browser_session_endpoint };
}

async function join(ctx, user, sessionId, returnTo) {
  const { endpoint } = await browserOf(ctx);
  await new BrowserSessionClient({ reactor: ctx.agent.reactor }).join({
    clientId: ctx.agent.identity.clientId,
    pairwiseUserId: user,
    browserSessionEndpoint: endpoint,
    sessionId,
    returnTo,
    companyDomain: (await ctx.company()).document.organization.domain,
  });
}

caseFor("lifecycle.browser-joins-session")(async (ctx) => {
  const { browser } = await browserOf(ctx);
  const { user, signed } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "standing");
  const page = operationPage(operation, (await ctx.company()).document.organization.domain);
  await join(ctx, user, signed.token.sessionId, page);
  const landed = browser.page;
  check(landed.history.length && landed.history[0].status === 303, "joined with 303 See Other");
  const cookie = landed.history[0].headers.get("set-cookie") ?? "";
  for (const flag of ["Secure", "HttpOnly"]) check(cookie.includes(flag), `the cookie is ${flag}`);
  check(!cookie.toLowerCase().includes("samesite=strict"), "the cookie is not SameSite=Strict");
  check(!cookie.toLowerCase().includes("max-age"), "the cookie has no lifetime of its own");
  check(landed.status === 200, "the operation's page shows in the Session");
  await ctx.agent.accounts.revoke(signed.reference, { context: await ctx.accountContext(user) });
  const after = await browser.get(page);
  check([401, 403, 404].includes(after.status), "signed out, the website shows it no more");
});

caseFor("lifecycle.browser-assertion-refused")(async (ctx) => {
  const { endpoint } = await browserOf(ctx);
  const domain = (await ctx.company()).document.organization.domain;
  const user = ctx.newUser();
  const session = await ctx.session(user);
  const claims = ({ lifetime = 60, ...changes } = {}) => ({
    ...ctx.claims({ subject: user, audience: endpoint, lifetime }),
    session_id: session.sessionId,
    return_to: `https://${domain}/`,
    ...changes,
  });
  const browserTyp = { headers: { typ: "poppy-browser+jwt" } };
  const cases = {
    "a foreign return_to": await ctx.assertion(claims({ return_to: "https://evil.example/" }), browserTyp),
    "a Session assertion": await ctx.assertion(claims()),
    "another user's Session": await ctx.assertion(claims({ sub: ctx.newUser() }), browserTyp),
    "a long-lived assertion": await ctx.assertion(claims({ lifetime: 600 }), browserTyp),
    "another audience": await ctx.assertion(claims({ aud: ctx.url("/elsewhere") }), browserTyp),
  };
  const replayed = await ctx.assertion(claims(), browserTyp);
  const post = (assertion) =>
    ctx.send("POST", endpoint, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ assertion }).toString(),
    });
  check((await post(replayed)).status === 303, "a valid browser assertion joins");
  cases["a replayed assertion"] = replayed;
  for (const [what, assertion] of Object.entries(cases)) {
    const response = await post(assertion);
    check(response.status === 400, `${what} is refused`);
    check(response.headers.get("set-cookie") === null, `${what} sets no cookie`);
  }
});

caseFor("operations.web-confirm-at-most-once")(async (ctx) => {
  const endpoint = await ctx.operationsEndpoint();
  const { browser } = await browserOf(ctx);
  const form = ctx.scenario.web_confirm_form;
  if (!form) throw new SkipCase("the scenario does not know the website's confirm form");
  const { user, signed, who } = await signedInUser(ctx);
  const operation = await propose(ctx, user, signed, "user");
  const page = operationPage(operation, (await ctx.company()).document.organization.domain);
  await join(ctx, user, signed.token.sessionId, page);
  const fields = Object.fromEntries(
    Object.entries(form).map(([name, value]) => [name, value.replaceAll("{revision}", String(operation.revision))]),
  );
  await browser.submit(page, fields);
  const read = await ctx.agent.operations.read(endpoint, operation.operation_id, who);
  check(read.state !== "proposed", "confirmed on the website");
  check(read.confirmation !== null, "with its confirmation");
  const again = await ctx.agent.operations.confirm(endpoint, operation, { ...who, approval: await approve(operation) });
  check(JSON.stringify(again.operation) === JSON.stringify(read), "confirming at the endpoint too changes nothing");
  if (ctx.driver.capabilities.has("performed")) check((await ctx.driver.performed(operation.operation_id)) === 1, "performed once");
});

/** Run each case; a failure never stops the others. The report is the runner's schema 1. */
export async function runConformance(ctx, { cases = companyCases(), timeoutMs = 30_000 } = {}) {
  const startedAt = new Date();
  const results = [];
  for (const fixture of cases) {
    const began = performance.now();
    let outcome = "passed";
    let message = null;
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
      if (error instanceof SkipCase) [outcome, message] = ["skipped", error.message];
      else if (error instanceof ConformanceFailure) [outcome, message] = ["failed", error.message];
      else if (error instanceof PersonalAgentProtocolError) [outcome, message] = ["failed", `${error.name}: ${error.code}`];
      else [outcome, message] = ["failed", `${error?.name ?? "Error"}: ${String(error?.message ?? error).slice(0, 200)}`];
    }
    results.push({
      id: fixture.id,
      suite: fixture.suite,
      kind: fixture.kind,
      requirements: fixture.requirements ?? [],
      outcome,
      duration_seconds: Math.round(performance.now() - began) / 1000,
      message,
    });
  }
  const summary = { passed: 0, failed: 0, skipped: 0 };
  for (const result of results) summary[result.outcome] += 1;
  return {
    schema_version: 1,
    protocol: "personal-agent-protocol",
    profile: PROTOCOL_PROFILE,
    extensions: { operations: "1" },
    role: "personal-agent",
    target: ctx.baseUrl,
    agent: ctx.agent.identity.clientId,
    started_at: startedAt.toISOString(),
    summary,
    cases: results,
  };
}
