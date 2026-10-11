// A personal agent's host, an in-process network, and real TLS, for the company specs and
// the language pairings. Nothing here is part of the SDK: it plays the parts a host owns.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { Agent, request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Readable } from "node:stream";

import { exportJWK, generateKeyPair, importJWK } from "jose";

import {
  AuthorizationStateStores,
  BrowserHandoffs,
  Clocks,
  DpopProofProviders,
  JoseDpopProofProvider,
  ProtectedInputs,
  SecretValue,
  Signers,
  TokenStores,
  buildPapReactor,
} from "../../../lib/index.js";
import { JoseSigner } from "../../../lib/server.js";

/** One clock for every party, so a spec can skip a polling interval. */
export class MutableClock {
  constructor(start = new Date("2026-10-11T09:00:00Z")) {
    this.value = start;
  }
  now() {
    return this.value;
  }
  advance(seconds) {
    this.value = new Date(this.value.getTime() + seconds * 1000);
  }
}

/** A personal agent's identity: its `client_id`, ES256 key, and published documents. */
export async function agentIdentity({ domain, name, extensions = ["operations"], privateJwk } = {}) {
  let privateKey;
  let publicJwk;
  if (privateJwk) {
    privateKey = await importJWK(privateJwk, "ES256");
    const { d: _d, ...rest } = privateJwk;
    publicJwk = rest;
  } else {
    const pair = await generateKeyPair("ES256", { extractable: true });
    privateKey = pair.privateKey;
    publicJwk = await exportJWK(pair.publicKey);
  }
  const clientId = `https://${domain}/agent.json`;
  const metadata = {
    client_id: clientId,
    client_name: name,
    jwks_uri: `https://${domain}/jwks.json`,
    redirect_uris: [`https://${domain}/oauth/callback`],
    token_endpoint_auth_method: "private_key_jwt",
    extensions: Object.fromEntries(extensions.map((extension) => [extension, { version: "1" }])),
  };
  const jwks = {
    keys: [{ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x, y: publicJwk.y, kid: "key-1", use: "sig", alg: "ES256" }],
  };
  return {
    domain,
    name,
    clientId,
    metadata,
    jwks,
    documents: { "/agent.json": metadata, "/jwks.json": jwks },
    signer: new JoseSigner({ privateKey, algorithm: "ES256", keyId: "key-1" }),
  };
}

function headerRecord(headers) {
  const result = {};
  if (!headers) return result;
  for (const [name, value] of new Headers(headers)) result[name.toLowerCase()] = value;
  return result;
}

function bodyOf(init) {
  const headers = headerRecord(init.headers);
  let body = init.body;
  if (body instanceof URLSearchParams) {
    body = body.toString();
    headers["content-type"] ??= "application/x-www-form-urlencoded;charset=UTF-8";
  }
  return { headers, body: body === undefined || body === null ? undefined : String(body) };
}

function toResponse(answer) {
  const headers = new Headers(answer.headers);
  if (answer.stream) return new Response(ReadableStream.from(answer.stream), { status: answer.status, headers });
  let payload = null;
  if (typeof answer.body === "string") payload = answer.body;
  else {
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
    if (answer.body !== undefined) payload = JSON.stringify(answer.body);
  }
  return new Response([204, 205, 304].includes(answer.status) ? null : payload, { status: answer.status, headers });
}

/**
 * Domains answered in this process: each a `CompanyService` or fixed JSON documents.
 * Requests are the same neutral requests the Node adapter hands the service.
 */
export function inProcessFetch(sites) {
  return async (input, init = {}) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const site = sites[url.hostname];
    if (url.protocol !== "https:" || site === undefined) {
      throw new TypeError(`${url.hostname} is not on the network`);
    }
    if (typeof site.handle !== "function") {
      const document = site[url.pathname];
      return toResponse(document === undefined
        ? { status: 404, body: { error: "not_found" }, headers: {} }
        : { status: 200, body: document, headers: {} });
    }
    const { headers, body } = bodyOf(init);
    return toResponse(await site.handle({ method: init.method ?? "GET", url: url.toString(), headers, body }));
  };
}

/** A throwaway CA, and one certificate for every domain it signs (openssl). */
export function certificates(domains) {
  const directory = mkdtempSync(join(tmpdir(), "pap-tls-"));
  const at = (name) => join(directory, name);
  const quiet = { stdio: ["ignore", "ignore", "pipe"] };
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
    "-keyout", at("ca.key"), "-out", at("ca.pem"), "-days", "1", "-subj", "/CN=PAP test CA",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
  ], quiet);
  execFileSync("openssl", [
    "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
    "-keyout", at("key.pem"), "-out", at("leaf.csr"), "-subj", `/CN=${domains[0]}`,
  ], quiet);
  writeFileSync(at("leaf.ext"), [
    `subjectAltName=${domains.map((domain) => `DNS:${domain}`).join(",")}`,
    "extendedKeyUsage=serverAuth",
    "basicConstraints=CA:FALSE",
  ].join("\n"));
  execFileSync("openssl", [
    "x509", "-req", "-in", at("leaf.csr"), "-CA", at("ca.pem"), "-CAkey", at("ca.key"),
    "-CAcreateserial", "-out", at("cert.pem"), "-days", "1", "-extfile", at("leaf.ext"),
  ], quiet);
  return {
    directory,
    ca: readFileSync(at("ca.pem")),
    cert: readFileSync(at("cert.pem")),
    key: readFileSync(at("key.pem")),
  };
}

/**
 * `fetch` over real TCP and TLS: every domain dials `127.0.0.1:port`, keeping its own
 * name for SNI and certificate verification against the throwaway CA.
 */
export function tlsFetch({ port, ca, domains }) {
  const agent = new Agent({ keepAlive: false, ca });
  return (input, init = {}) =>
    new Promise((resolve, reject) => {
      const url = new URL(String(input instanceof Request ? input.url : input));
      if (url.protocol !== "https:" || (domains && !domains.includes(url.hostname))) {
        reject(new TypeError(`${url.hostname} is not on the network`));
        return;
      }
      const { headers, body } = bodyOf(init);
      const request = httpsRequest(
        {
          agent,
          host: "127.0.0.1",
          port,
          servername: url.hostname,
          ca,
          method: init.method ?? "GET",
          path: `${url.pathname}${url.search}`,
          headers: { ...headers, host: url.host },
        },
        (response) => {
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (value === undefined) continue;
            for (const item of Array.isArray(value) ? value : [value]) responseHeaders.append(name, item);
          }
          const empty = [204, 205, 304].includes(response.statusCode ?? 0);
          if (empty) response.resume();
          resolve(new Response(empty ? null : Readable.toWeb(response), { status: response.statusCode, headers: responseHeaders }));
        },
      );
      request.on("error", reject);
      init.signal?.addEventListener("abort", () => request.destroy(init.signal.reason), { once: true });
      if (body !== undefined) request.write(body);
      request.end();
    });
}

/** The user's browser: opens the company's sign-in page and remembers what it showed. */
export class ScriptedBrowser {
  constructor(fetch) {
    this.fetch = fetch;
    this.pages = [];
    this.requestId = undefined;
  }
  async open(authorizationUrl) {
    const response = await this.fetch(authorizationUrl.reveal(), { method: "GET" });
    const page = await response.text();
    this.pages.push(page);
    const marker = 'name="request_id" value="';
    if (page.includes(marker)) this.requestId = page.split(marker, 2)[1].split('"', 1)[0];
  }
}

/** The host's trusted input surface, answered from a script. */
export class ScriptedInput {
  constructor(...answers) {
    this.answers = answers;
    this.asked = [];
  }
  async collect(request) {
    this.asked.push(request);
    const answer = this.answers.shift() ?? {};
    return Object.fromEntries(Object.entries(answer).map(([name, value]) => [name, new SecretValue(value)]));
  }
}

/** A personal agent's Reactor host: its signer, DPoP keys, clock, stores, browser, input. */
export async function agentHost({ identity, fetch, clock, answers = [] }) {
  const state = new Map();
  const tokens = new Map();
  const keys = new Map();
  const browser = new ScriptedBrowser(fetch);
  const input = new ScriptedInput(...answers);
  const now = () => clock.now();
  const reactor = buildPapReactor({ fetch }, [
    {
      name: `${identity.domain}-host`,
      contributes: [
        { point: Clocks, value: clock, options: { id: "clock" } },
        { point: Signers, value: identity.signer, options: { id: "agent-key" } },
        {
          point: DpopProofProviders,
          value: new JoseDpopProofProvider({
            now,
            async resolveKey(request) {
              const key = `${request.tenantId}\u0000${request.subject}\u0000${request.issuer}`;
              // One key per (tenant, user, company), even for requests made at the same time.
              if (!keys.has(key)) {
                keys.set(
                  key,
                  generateKeyPair("ES256", { extractable: true }).then(async (pair) => ({
                    privateKey: pair.privateKey,
                    publicJwk: await exportJWK(pair.publicKey),
                  })),
                );
              }
              return keys.get(key);
            },
          }),
          options: { id: "dpop-keys" },
        },
        {
          point: TokenStores,
          value: {
            async put(reference, token) { tokens.set(reference, token); },
            async get(reference) { return tokens.get(reference); },
            async delete(reference) { tokens.delete(reference); },
          },
          options: { id: "vault" },
        },
        {
          point: AuthorizationStateStores,
          value: {
            async put(reference, value) { state.set(reference, value); },
            async take(reference) { const value = state.get(reference); state.delete(reference); return value; },
          },
          options: { id: "vault" },
        },
        { point: BrowserHandoffs, value: browser, options: { id: "browser" } },
        { point: ProtectedInputs, value: input, options: { id: "trusted-input" } },
      ],
    },
  ]);
  return { reactor, browser, input, tokens };
}

/** The system clock, for parties in different processes. */
export const systemClock = { now: () => new Date() };
