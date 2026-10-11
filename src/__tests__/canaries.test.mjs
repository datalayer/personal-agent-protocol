// Credentials never reach logs, errors, model context, URLs, or the browser bundle: the
// TypeScript twin of personal_agent_protocol/__tests__/test_canaries.py.
//
// The TypeScript demo (Manzanita, the reference company) runs the shared journey (Direct
// Sign-In through the consent page, conversations, an operation), Mediated Sign-In with a
// one-time code, and the conformance runner's cases in one process, with canaries: every
// random value of 12 bytes or more the parties mint carries a counter and `CANARY`, and
// Ada's password is a canary. Every credential exchanged on the wire is harvested by kind,
// and none may appear in a console line, an error an SDK client or the company's methods
// throw (its message, `String`, and `util.inspect`), a requested URL, or what a model reads
// (every response body but the token and device endpoints', and each message's text).
// The TypeScript company has no MCP server, so no Bearer token is exchanged here.
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { inspect } from "node:util";

import * as pap from "../../lib/index.js";
import { CompanyService } from "../../lib/company/index.js";
import { ADA, ADA_CODE, manzanita } from "../../lib/demo/manzanita.js";
import { Context, identityFrom, runConformance } from "./support/conformance.mjs";
import { scenario as journeyScenario, runJourney } from "./support/journey.mjs";
import { MutableClock, agentHost, agentIdentity, inProcessFetch } from "./support/world.mjs";

const PASSWORD = "CANARY-password-7f3a9c";
const SHORTEST = 8;
/** The demo's one-time code is a six-digit constant: searched for all the same. */
const SHORT_KINDS = new Set(["one-time code"]);
const CREDENTIAL_ENDPOINTS = new Set(["/oauth/token", "/oauth/device"]);
const LIB = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "lib");

class Harvest {
  constructor() {
    this.secrets = new Map();
    this.urls = [];
    this.modelTexts = [];
    this.chatTexts = [];
    this.errors = [];
    this.logs = [];
  }
  secret(kind, value) {
    if (typeof value !== "string") return;
    if (value.length < (SHORT_KINDS.has(kind) ? 6 : SHORTEST)) return;
    if (!this.secrets.has(kind)) this.secrets.set(kind, new Set());
    this.secrets.get(kind).add(value);
  }
  all({ but = [] } = {}) {
    const values = new Map();
    for (const [kind, found] of this.secrets) if (!but.includes(kind)) for (const value of found) values.set(value, kind);
    return values;
  }
}

function cookies(header) {
  return (header ?? "")
    .split(/[;,]/)
    .map((part) => part.trim().split("="))
    .filter(([name, value]) => value !== undefined && name && !["path", "expires", "max-age", "samesite"].includes(name.toLowerCase()))
    .map(([name, ...value]) => [name, value.join("=")]);
}

/** `fetch` on the in-process network, recording every request and its answer. */
function recordingFetch(sites, harvest) {
  const fetch = inProcessFetch(sites);
  return async (input, init = {}) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    harvest.urls.push(url.toString());
    const headers = new Headers(init.headers);
    const [scheme, token] = (headers.get("authorization") ?? "").split(" ");
    if (token) harvest.secret(`${scheme} access token`, token);
    harvest.secret("DPoP proof", headers.get("dpop") ?? undefined);
    for (const [name, value] of cookies(headers.get("cookie"))) harvest.secret(`cookie ${name}`, value);
    const body = init.body === undefined || init.body === null ? "" : String(init.body);
    const type = headers.get("content-type") ?? (init.body instanceof URLSearchParams ? "application/x-www-form-urlencoded" : "");
    if (type.startsWith("application/x-www-form-urlencoded")) {
      const form = Object.fromEntries(new URLSearchParams(body));
      harvest.secret("client assertion", form.client_assertion);
      harvest.secret("Session or browser assertion", form.assertion);
      harvest.secret("authorization code", form.code);
      harvest.secret("PKCE verifier", form.code_verifier);
      harvest.secret("device code", form.device_code);
      harvest.secret("Account Token", form.refresh_token);
      harvest.secret("revoked token", form.token);
    } else if (type.startsWith("application/json") && url.pathname.startsWith("/poppy/sign-in")) {
      const sent = JSON.parse(body || "{}");
      harvest.secret("mediated password", sent.credentials?.password);
      harvest.secret("one-time code", sent.code);
    }
    const response = await fetch(input, init);
    const text = await response.clone().text();
    for (const [name, value] of cookies(response.headers.get("set-cookie"))) harvest.secret(`cookie ${name}`, value);
    const where = `${init.method ?? "GET"} ${url.pathname}`;
    if ((response.headers.get("content-type") ?? "").startsWith("application/json") && text) {
      const answer = JSON.parse(text);
      if (CREDENTIAL_ENDPOINTS.has(url.pathname)) {
        harvest.secret(`${answer.token_type ?? ""} access token`, answer.access_token);
        harvest.secret("Account Token", answer.refresh_token);
        harvest.secret("device code", answer.device_code);
        harvest.secret("user code", answer.user_code);
        return response;
      }
      for (const event of answer?.events ?? []) harvest.chatTexts.push([`a message in ${where}`, String(event.message?.text)]);
    }
    harvest.modelTexts.push([where, text]);
    return response;
  };
}

/** Canary randomness, harvested private keys, console lines, and thrown errors. */
async function withCanaries(harvest, run) {
  const crypto = globalThis.crypto;
  const getRandomValues = crypto.getRandomValues;
  let count = 0;
  crypto.getRandomValues = function canary(array) {
    if (!(array instanceof Uint8Array) || array.length < 12) return getRandomValues.call(crypto, array);
    count += 1;
    // The counter first: a device user code is made from the start of an ID.
    const width = Math.ceil(array.length / 3) * 4;
    const bytes = Buffer.from(`${String(count).padStart(8, "0")}CANARY`.padEnd(width, "A"), "base64url");
    array.set(bytes.subarray(0, array.length));
    return array;
  };
  const generateKey = crypto.subtle.generateKey;
  crypto.subtle.generateKey = async function recorded(...args) {
    const pair = await generateKey.apply(crypto.subtle, args);
    if (pair?.privateKey?.extractable) {
      harvest.secret("private key", (await crypto.subtle.exportKey("jwk", pair.privateKey)).d);
    }
    return pair;
  };
  const consoleMethods = ["log", "info", "warn", "error", "debug", "trace"];
  const saved = Object.fromEntries(consoleMethods.map((name) => [name, console[name]]));
  for (const name of consoleMethods) console[name] = (...args) => harvest.logs.push(args.map((arg) => inspect(arg)).join(" "));
  const emitWarning = process.emitWarning;
  process.emitWarning = (...args) => harvest.logs.push(args.map((arg) => inspect(arg)).join(" "));
  const restore = wrapThrowers(harvest);
  try {
    return await run();
  } finally {
    restore();
    process.emitWarning = emitWarning;
    for (const name of consoleMethods) console[name] = saved[name];
    crypto.subtle.generateKey = generateKey;
    crypto.getRandomValues = getRandomValues;
  }
}

/** Every method of every SDK client, and the company's, records what it throws. */
function wrapThrowers(harvest) {
  const classes = [CompanyService, ...Object.values(pap).filter((value) => typeof value === "function" && /Client$/.test(value.name))];
  const originals = [];
  const record = (error) => {
    harvest.errors.push([String(error), error?.message, inspect(error, { depth: 4 })].join(" "));
  };
  for (const kind of classes) {
    for (const name of Object.getOwnPropertyNames(kind.prototype)) {
      const descriptor = Object.getOwnPropertyDescriptor(kind.prototype, name);
      if (name === "constructor" || typeof descriptor?.value !== "function") continue;
      const method = descriptor.value;
      originals.push([kind.prototype, name, method]);
      kind.prototype[name] = function wrapped(...args) {
        try {
          const result = method.apply(this, args);
          return result instanceof Promise ? result.catch((error) => { record(error); throw error; }) : result;
        } catch (error) {
          record(error);
          throw error;
        }
      };
    }
  }
  return () => {
    for (const [prototype, name, method] of originals) prototype[name] = method;
  };
}

function leaks(harvest, sinks, options) {
  const found = [];
  for (const [value, kind] of harvest.all(options)) {
    for (const [where, text] of sinks) {
      const at = text.indexOf(value);
      if (at >= 0) found.push(`${kind} in ${where.slice(0, 120)}: …${text.slice(Math.max(0, at - 80), at + value.length + 40).replaceAll(value, `<${kind}>`)}…`);
    }
  }
  return found;
}

async function mediatedSignIn(fetch, clock, sites) {
  const identity = await agentIdentity({ domain: "mediated.example", name: "Atlas" });
  sites["mediated.example"] = identity.documents;
  const host = await agentHost({ identity, fetch, clock, answers: [{ ...ADA }, { code: "975313" }, { code: ADA_CODE }] });
  const company = await pap.discoverCompany("manzanita.example", { reactor: host.reactor });
  const issuer = company.oauthMetadata.issuer;
  const who = { tenantId: "atlas-demo", pairwiseUserId: "usr_ada_at_manzanita_000000", issuer };
  const session = await new pap.SessionClient({ reactor: host.reactor, fetch }).start({
    clientId: identity.clientId,
    pairwiseUserId: who.pairwiseUserId,
    issuer,
    tokenEndpoint: company.oauthMetadata.token_endpoint,
    tenantId: who.tenantId,
  });
  const mediated = new pap.MediatedSignInClient({ reactor: host.reactor, fetch });
  const started = await mediated.signIn({
    mediated: company.document.auth.mediated,
    organization: company.document.organization,
    issuer,
    scopes: ["orders:read"],
    token: session,
    tenantId: who.tenantId,
    pairwiseUserId: who.pairwiseUserId,
  });
  assert.equal(started.status, "code_required");
  assert.equal((await mediated.submitCode(started.reference, { token: session, ...who })).status, "code_required");
  assert.equal((await mediated.submitCode(started.reference, { token: session, ...who })).status, "complete");
}

test("no credential reaches a console line, an error, a URL, or model text", async () => {
  const harvest = new Harvest();
  const password = ADA.password;
  ADA.password = PASSWORD;
  try {
    await withCanaries(harvest, async () => {
      const clock = new MutableClock();
      const sites = {};
      const fetch = recordingFetch(sites, harvest);
      const { service, plugin } = manzanita({ fetch, clock });
      sites["manzanita.example"] = service;

      // The shared journey: Direct Sign-In on the consent page, a conversation, an operation.
      const identity = await agentIdentity({ domain: "atlas.example", name: "Atlas" });
      sites["atlas.example"] = identity.documents;
      const host = await agentHost({ identity, fetch, clock });
      await runJourney({
        reactor: host.reactor,
        fetch,
        browser: host.browser,
        identity,
        company: {
          approveAuthorization: async (requestId, accountId) => service.approveAuthorization(requestId, { accountId }),
          performed: async () => [...plugin.executor.performed],
        },
      });
      assert.equal(journeyScenario.company.domain, "manzanita.example");

      // Mediated Sign-In: the password and the one-time code.
      await mediatedSignIn(fetch, clock, sites);

      // The conformance cases, in process, but the probe that puts a Session Token in a
      // URL on purpose to see the company refuse it; a company of their own.
      const { service: conformant, plugin: conformantPlugin } = manzanita({ fetch, clock });
      sites["manzanita.example"] = conformant;
      const atlas = await identityFrom({ domain: "atlas.example", name: "Atlas", privateJwk: await privateJwk() });
      const plainIdentity = await identityFrom({ domain: "plain.example", name: "Plain", extensions: [], privateJwk: await privateJwk() });
      sites["atlas.example"] = { "/agent.json": atlas.metadata, "/jwks.json": atlas.jwks };
      sites["plain.example"] = { "/agent.json": plainIdentity.metadata, "/jwks.json": plainIdentity.jwks };
      const executors = ["executor", "giftWrap", "returns", "repairs"].map((name) => conformantPlugin[name]);
      const scenario = JSON.parse(readFileSync(new URL("../../protocol/scenarios/manzanita-conformance.json", import.meta.url), "utf8"));
      const context = new Context({
        baseUrl: "https://manzanita.example",
        identity: atlas,
        otherIdentity: plainIdentity,
        fetch,
        scenario,
        clock,
        driver: {
          capabilities: new Set(["revise", "forget_events", "disconnect", "performed", "clock", "second_identity"]),
          accounts: ["acct_ada", "acct_ada_business"],
          async approveDevice(userCode, { account, scopes }) {
            await conformant.approveDevice(userCode, { accountId: account, ...(scopes ? { scopes } : {}) });
          },
          async wait(seconds) {
            clock.advance(seconds);
          },
          async revise(operationId) {
            const current = (await conformant.operationRecord(operationId)).operation;
            await conformant.revise(operationId, { summary: `${current.summary} Ships in 5 days instead of 2.`, terms: { ...(current.terms ?? {}), ships_in_days: 5 } });
          },
          async forgetEvents(conversationId) {
            await conformant.forgetEvents(conversationId, { keep: 1 });
          },
          async disconnect(clientId, account) {
            await conformant.disconnect(clientId, account);
          },
          async performed(operationId) {
            return executors.flatMap((executor) => executor.performed).filter((id) => id === operationId).length;
          },
        },
      });
      const { companyCases } = await import("./support/conformance.mjs");
      const cases = companyCases().filter((item) => item.id !== "security.token-in-url-refused");
      const report = await runConformance(context, { cases });
      assert.deepEqual(report.cases.filter((item) => item.outcome === "failed").map((item) => `${item.id}: ${item.message}`), []);
      assert.ok(report.summary.passed >= 70, JSON.stringify(report.summary));
      harvest.modelTexts.push(["the conformance report", JSON.stringify(report)]);
    });
  } finally {
    ADA.password = password;
  }

  const kinds = new Set(harvest.secrets.keys());
  for (const kind of [
    "DPoP access token",
    "Account Token",
    "DPoP proof",
    "private key",
    "client assertion",
    "Session or browser assertion",
    "authorization code",
    "PKCE verifier",
    "device code",
    "user code",
    "mediated password",
    "one-time code",
  ]) {
    assert.ok(kinds.has(kind), `no ${kind} was exchanged: the canary run is incomplete`);
  }
  assert.ok([...harvest.all().keys()].some((value) => value.includes("CANARY")), "minted credentials carry the canary");
  assert.ok(harvest.errors.length > 0, "nothing was thrown: the error capture is not wired");

  assert.deepEqual(leaks(harvest, harvest.logs.map((line) => ["a console line", line])), []);
  assert.deepEqual(leaks(harvest, harvest.errors.map((error) => ["an error", error])), []);
  assert.deepEqual(leaks(harvest, harvest.urls.map((url) => [url, url])), []);
  assert.deepEqual(leaks(harvest, harvest.modelTexts, { but: ["user code"] }), []);
  assert.deepEqual(leaks(harvest, harvest.chatTexts), []);
  const counts = [...harvest.secrets].map(([kind, found]) => `${kind} ${found.size}`).sort().join(", ");
  process.stdout.write(
    `canaries: ${harvest.all().size} credentials (${counts}); searched ${harvest.logs.length} console lines, ` +
      `${harvest.errors.length} errors, ${harvest.urls.length} URLs, ${harvest.modelTexts.length} model-readable bodies, ` +
      `${harvest.chatTexts.length} messages\n`,
  );
});

async function privateJwk() {
  const pair = await globalThis.crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return globalThis.crypto.subtle.exportKey("jwk", pair.privateKey);
}

/** Every file a browser's `import "@datalayer/personal-agent-protocol"` reaches in lib/. */
function browserGraph(entry) {
  const seen = new Set();
  const pending = [entry];
  while (pending.length) {
    const file = pending.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/(?:from|import)\s*\(?\s*["'](\.{1,2}\/[^"']+)["']/g)) {
      pending.push(join(dirname(file), match[1]));
    }
  }
  return [...seen];
}

function walk(directory) {
  return readdirSync(directory).flatMap((name) => {
    const path = join(directory, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

const EMBEDDED_SECRETS = [
  // Key material after the header: jose's own source names the header to refuse it.
  ["a PEM private key", /-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)*[A-Za-z0-9+/=]{40,}/],
  ["a private JWK member", /["']d["']\s*:\s*["'][A-Za-z0-9_-]{32,}["']/],
  ["a compact JWT", /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/],
  ["a Bearer or DPoP token", /(?:Bearer|DPoP) [A-Za-z0-9_-]{20,}/],
  ["a canary", /CANARY/],
];

test("the npm package embeds no secret, and the browser entry no demo credential", (t) => {
  let files;
  try {
    files = walk(LIB).filter((file) => /\.(?:js|mjs|map|d\.ts)$/.test(file));
  } catch {
    t.skip("lib/ is not built");
    return;
  }
  assert.ok(files.length > 0);
  for (const file of files) {
    const text = readFileSync(file, "utf8");
    for (const [what, pattern] of EMBEDDED_SECRETS) {
      assert.doesNotMatch(text, pattern, `${what} in ${relative(LIB, file)}`);
    }
  }
  // The demo's fictional credentials ship only under lib/demo, which a browser entry never reaches.
  const reached = browserGraph(join(LIB, "index.js")).filter((file) => file.endsWith(".js"));
  assert.ok(reached.length > 1, "the browser entry imports its modules");
  for (const file of reached) {
    assert.ok(!relative(LIB, file).startsWith("demo"), `the browser entry reaches ${relative(LIB, file)}`);
    const text = readFileSync(file, "utf8");
    for (const credential of [ADA.password, ADA_CODE]) {
      assert.ok(!text.includes(credential), `a demo credential in ${relative(LIB, file)}`);
    }
  }
});
