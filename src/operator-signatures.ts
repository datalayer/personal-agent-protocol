/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * Operator signatures: an HTTP Message Signature beside the Session header (§5.3).
 *
 * A Personal Agent SHOULD sign requests that carry the Session header with RFC 9421 and Web Bot
 * Auth (`draft-ietf-webbotauth-httpsig-protocol-01`), so traffic-management infrastructure can
 * authenticate the operator before the Company's application sees the request. It is
 * compatibility support, not a credential: its absence does not make a Session JWT invalid, and
 * a verified one authenticates its key source, never a `client_id`.
 *
 * - `WebBotAuthSigner` is what a host contributes to `pap.operatorSigner`, which has no default:
 *   the key is the operator's, published in a directory the host serves. It covers the authority,
 *   the `Signature-Agent` member, the method, path and query, `poppy-session`, and `authorization`
 *   when present (§5.3). `Ed25519OperatorKey` keeps the key in this process; a key in a KMS is any
 *   `OperatorSigningKey`.
 * - `operatorDirectory` is the key set a host publishes at its `Signature-Agent` URL.
 * - `verifyOperatorSignature` is a Company's side, with the draft's outcomes kept apart: `absent`,
 *   `verified`, `invalid` and `unverified`. Each is the Company's to act on.
 *
 * Operator keys are never delegated keys, DPoP keys or keys from `jwks_uri`, and a device never
 * holds a shared operator key (Guides, operator signatures).
 */

import { exportJWK, generateKeyPair, importJWK, type JWK } from "jose";

import { base64Url, jwkThumbprint } from "./crypto.js";
import { PersonalAgentProtocolError, ProofError } from "./errors.js";
import type {
  OperatorSignature,
  OperatorSignatureRequest,
  OperatorSigner,
} from "./reactor.js";

/** The headers of a signed request (RFC 9421 §4; Web Bot Auth §5.2.5). */
export const SIGNATURE_HEADER = "Signature";
export const SIGNATURE_INPUT_HEADER = "Signature-Input";
export const SIGNATURE_AGENT_HEADER = "Signature-Agent";
/** The tag that marks a signature as Web Bot Auth's (§5.2). */
export const WEB_BOT_AUTH_TAG = "web-bot-auth";
/** The RFC 9421 algorithm these signatures use. */
export const OPERATOR_SIGNATURE_ALGORITHM = "ed25519";
/** The label a signature, and its `Signature-Agent` member, go by. */
export const OPERATOR_SIGNATURE_LABEL = "sig1";
/** A signature lives this long: each request and retry gets a fresh one. */
export const OPERATOR_SIGNATURE_LIFETIME_SECONDS = 60;
/** The well-known URL of an operator's directory, and its media type (Web Bot Auth §8). */
export const OPERATOR_DIRECTORY_PATH = "/.well-known/http-message-signatures-directory";
export const OPERATOR_DIRECTORY_MEDIA_TYPE = "application/http-message-signatures-directory+json";
/** The components a signature covers before `poppy-session` and `authorization`. */
export const OPERATOR_SIGNATURE_COMPONENTS = [
  "@authority",
  "signature-agent",
  "@method",
  "@path",
  "@query",
] as const;
/** A Company's refusal of a signature, at 403: this SDK's code, as the spec names none. */
export const OPERATOR_SIGNATURE_REFUSED = "operator_signature_refused";
/** No more signatures are read from one request. */
export const MAX_OFFERED_SIGNATURES = 8;

const DERIVED = new Set(["@method", "@authority", "@path", "@query", "@target-uri"]);
const KEY = /[a-z*][a-z0-9_\-.*]*/y;
const TOKEN = /[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:/]*/y;
const NUMBER = /-?[0-9]{1,15}(\.[0-9]{1,3})?/y;
const BYTES = /[A-Za-z0-9+/=]*/y;

/** An operator's key: `keyid` is its RFC 8037 thumbprint, and it signs with Ed25519. */
export interface OperatorSigningKey {
  readonly keyid: string;
  sign(data: Uint8Array): Promise<Uint8Array>;
}

/** An operator's Ed25519 key in this process's memory. */
export class Ed25519OperatorKey implements OperatorSigningKey {
  constructor(
    readonly privateKey: CryptoKey,
    readonly publicJwk: JWK,
    readonly keyid: string,
  ) {}

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const signature = await crypto.subtle.sign("Ed25519", this.privateKey, data as BufferSource);
    return new Uint8Array(signature);
  }
}

/** The `Ed25519OperatorKey` of a private JWK. */
export async function operatorKeyFrom(privateJwk: JWK): Promise<Ed25519OperatorKey> {
  const { kty, crv, x } = privateJwk;
  if (kty !== "OKP" || crv !== "Ed25519" || x === undefined || privateJwk.d === undefined) {
    throw new ProofError("invalid_operator_key", "An operator key is a private Ed25519 JWK");
  }
  const privateKey = (await importJWK(privateJwk, "Ed25519")) as CryptoKey;
  const publicJwk = { kty, crv, x };
  return new Ed25519OperatorKey(privateKey, publicJwk, await jwkThumbprint(publicJwk));
}

/** A new Ed25519 key, used for nothing but operator signatures (§5.3). */
export async function newOperatorKey(): Promise<Ed25519OperatorKey> {
  const { privateKey } = await generateKeyPair("Ed25519", { extractable: true });
  return operatorKeyFrom(await exportJWK(privateKey));
}

/** The JWK Set a host serves at its `Signature-Agent` URL (Web Bot Auth §5.5.1). */
export function operatorDirectory(keys: readonly Ed25519OperatorKey[]): { readonly keys: readonly JWK[] } {
  return { keys: keys.map((key) => ({ ...key.publicJwk, kid: key.keyid, use: "sig" })) };
}

// Signature bases (RFC 9421 §2) ----------------------------------------------------------

/** One covered component: its name, its `key` parameter, and its identifier as sent. */
interface Component {
  readonly name: string;
  readonly key: string | undefined;
  readonly identifier: string;
}

function covered(names: readonly string[], label: string): Component[] {
  return names.map((name) =>
    name === "signature-agent"
      ? { name, key: label, identifier: `"${name}";key="${label}"` }
      : { name, key: undefined, identifier: `"${name}"` },
  );
}

function derived(name: string, method: string, url: string): string {
  const target = new URL(url);
  if (name === "@method") return method.toUpperCase();
  if (name === "@authority") return target.host;
  if (name === "@path") return target.pathname || "/";
  if (name === "@query") return `?${target.search.slice(1)}`;
  return target.href;
}

function componentValue(
  component: Component,
  method: string,
  url: string,
  headers: Readonly<Record<string, string | undefined>>,
  agent: string | undefined,
): string {
  if (DERIVED.has(component.name)) return derived(component.name, method, url);
  if (component.key !== undefined) {
    if (agent === undefined) throw new RangeError("a component's member is absent");
    return agent;
  }
  const value = headers[component.name];
  if (value === undefined) throw new RangeError("a covered header is absent");
  return value.trim();
}

function signatureBase(
  components: readonly Component[],
  parameters: string,
  method: string,
  url: string,
  headers: Readonly<Record<string, string | undefined>>,
  agent: string | undefined,
): Uint8Array {
  const lines = components.map(
    (component) => `${component.identifier}: ${componentValue(component, method, url, headers, agent)}`,
  );
  return new TextEncoder().encode([...lines, `"@signature-params": ${parameters}`].join("\n"));
}

// Signing --------------------------------------------------------------------------------

function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

export interface SignOperatorRequestOptions {
  readonly signatureAgent: string;
  readonly created: number;
  readonly expires: number;
  readonly nonce: string;
  readonly tag?: string;
  readonly components?: readonly string[];
}

/**
 * The signature of one request, its `created`, `expires` and `nonce` given.
 *
 * `components` defaults to what §5.3 and Web Bot Auth ask: `authorization` joins `poppy-session`
 * when the request has one.
 */
export async function signOperatorRequest(
  request: OperatorSignatureRequest,
  key: OperatorSigningKey,
  options: SignOperatorRequestOptions,
): Promise<OperatorSignature> {
  const { signatureAgent, created, expires, nonce, tag = WEB_BOT_AUTH_TAG } = options;
  if (!signatureAgent.startsWith("https://") || /["\\\s]/.test(signatureAgent)) {
    throw new RangeError("a Signature-Agent is an HTTPS URL");
  }
  const label = OPERATOR_SIGNATURE_LABEL;
  const headers: Record<string, string> = { "poppy-session": request.sessionJwt.reveal() };
  if (request.authorization !== undefined) headers.authorization = request.authorization.reveal();
  const names = options.components ?? [...OPERATOR_SIGNATURE_COMPONENTS, ...Object.keys(headers)];
  const components = covered(names, label);
  const listed = components.map((component) => component.identifier).join(" ");
  const parameters =
    `(${listed});created=${created};keyid="${key.keyid}";alg="${OPERATOR_SIGNATURE_ALGORITHM}"` +
    `;expires=${expires};nonce="${nonce}";tag="${tag}"`;
  const agent = `"${signatureAgent}"`;
  const base = signatureBase(components, parameters, request.method, request.url, headers, agent);
  return {
    signatureAgent: `${label}=${agent}`,
    signatureInput: `${label}=${parameters}`,
    signature: `${label}=:${base64(await key.sign(base))}:`,
  };
}

export interface WebBotAuthSignerOptions {
  /** The HTTPS URL that serves the key in `operatorDirectory`. */
  readonly signatureAgent: string;
  readonly now?: () => Date;
  readonly randomBytes?: (length: number) => Uint8Array;
  readonly lifetimeSeconds?: number;
}

/**
 * `pap.operatorSigner`: a fresh Web Bot Auth signature for each request (§5.3).
 *
 * It signs for every tenant with its one key: a host with a key per tenant contributes a signer
 * of its own over `signOperatorRequest`.
 */
export class WebBotAuthSigner implements OperatorSigner {
  readonly key: OperatorSigningKey;
  readonly signatureAgent: string;
  readonly #now: () => Date;
  readonly #randomBytes: (length: number) => Uint8Array;
  readonly #lifetimeSeconds: number;

  constructor(key: OperatorSigningKey, options: WebBotAuthSignerOptions) {
    const lifetime = options.lifetimeSeconds ?? OPERATOR_SIGNATURE_LIFETIME_SECONDS;
    if (lifetime <= 0) throw new RangeError("an operator signature's lifetime must be positive");
    this.key = key;
    this.signatureAgent = options.signatureAgent;
    this.#now = options.now ?? (() => new Date());
    this.#randomBytes = options.randomBytes ?? ((length) => crypto.getRandomValues(new Uint8Array(length)));
    this.#lifetimeSeconds = lifetime;
  }

  async sign(request: OperatorSignatureRequest): Promise<OperatorSignature> {
    const random = this.#randomBytes(32);
    if (random.byteLength !== 32) {
      throw new ProofError("weak_randomness", "An operator signature's nonce needs 256 bits");
    }
    const created = Math.floor(this.#now().getTime() / 1000);
    return signOperatorRequest(request, this.key, {
      signatureAgent: this.signatureAgent,
      created,
      expires: created + this.#lifetimeSeconds,
      nonce: base64Url(random),
    });
  }
}

// Reading signatures (RFC 8941) -----------------------------------------------------------

type Bare = string | number | boolean | Uint8Array;

/** A dictionary member or inner-list item: its value, parameters and text as sent. */
interface Field {
  readonly value: Bare | readonly Field[];
  readonly parameters: Readonly<Record<string, Bare>>;
  readonly raw: string;
}

/** The parts of RFC 8941 these headers use; anything else throws a `RangeError`. */
class Parser {
  readonly text: string;
  at = 0;

  constructor(text: string) {
    this.text = text.replace(/^ +| +$/g, "");
  }

  #peek(): string {
    return this.text[this.at] ?? "";
  }

  #match(pattern: RegExp): string {
    pattern.lastIndex = this.at;
    const found = pattern.exec(this.text);
    if (found === null) throw new RangeError("a malformed structured field");
    this.at = pattern.lastIndex;
    return found[0];
  }

  #spaces(allowed = " "): void {
    while (this.#peek() !== "" && allowed.includes(this.#peek())) this.at += 1;
  }

  #string(): string {
    this.at += 1;
    let out = "";
    while (true) {
      let char = this.#peek();
      if (char === "" || char < " " || char > "~") throw new RangeError("an unterminated string");
      this.at += 1;
      if (char === '"') return out;
      if (char === "\\") {
        char = this.#peek();
        if (char !== '"' && char !== "\\") throw new RangeError("a bad escape");
        this.at += 1;
      }
      out += char;
    }
  }

  #bare(): Bare {
    const char = this.#peek();
    if (char === '"') return this.#string();
    if (char === ":") {
      this.at += 1;
      const encoded = this.#match(BYTES);
      if (this.#peek() !== ":" || encoded.length % 4 !== 0) {
        throw new RangeError("a malformed byte sequence");
      }
      this.at += 1;
      return Uint8Array.from(atob(encoded), (letter) => letter.charCodeAt(0));
    }
    if (char === "?") {
      this.at += 2;
      const value = this.text[this.at - 1];
      if (value !== "0" && value !== "1") throw new RangeError("a malformed boolean");
      return value === "1";
    }
    if (char === "-" || (char >= "0" && char <= "9" && char !== "")) return Number(this.#match(NUMBER));
    return this.#match(TOKEN);
  }

  #parameters(): Record<string, Bare> {
    const parameters: Record<string, Bare> = Object.create(null);
    while (this.#peek() === ";") {
      this.at += 1;
      this.#spaces();
      const name = this.#match(KEY);
      let value: Bare = true;
      if (this.#peek() === "=") {
        this.at += 1;
        value = this.#bare();
      }
      parameters[name] = value;
    }
    return parameters;
  }

  #item(): Field {
    const start = this.at;
    const value = this.#bare();
    const parameters = this.#parameters();
    return { value, parameters, raw: this.text.slice(start, this.at) };
  }

  #member(): Field {
    if (this.#peek() !== "(") return this.#item();
    const start = this.at;
    this.at += 1;
    const items: Field[] = [];
    while (true) {
      this.#spaces();
      if (this.#peek() === ")") {
        this.at += 1;
        break;
      }
      items.push(this.#item());
      if (this.#peek() !== " " && this.#peek() !== ")") throw new RangeError("a malformed inner list");
    }
    const parameters = this.#parameters();
    return { value: items, parameters, raw: this.text.slice(start, this.at) };
  }

  dictionary(): Map<string, Field> {
    const members = new Map<string, Field>();
    while (this.at < this.text.length) {
      const name = this.#match(KEY);
      if (this.#peek() === "=") {
        this.at += 1;
        members.set(name, this.#member());
      } else {
        members.set(name, { value: true, parameters: this.#parameters(), raw: "?1" });
      }
      this.#spaces(" \t");
      if (this.at === this.text.length) break;
      if (this.#peek() !== ",") throw new RangeError("a malformed dictionary");
      this.at += 1;
      this.#spaces(" \t");
      if (this.at === this.text.length) throw new RangeError("a trailing comma");
    }
    return members;
  }
}

// Verifying ------------------------------------------------------------------------------

/** Keys published at a `Signature-Agent` URL: the URL and the `keyid` asked of it. */
export type OperatorKeys = (url: string, keyid: string) => Promise<readonly JWK[]>;

/**
 * What one request's operator signature came to (Web Bot Auth, appendix C.1).
 *
 * `absent`: none offered, or none tagged `web-bot-auth`. `verified`: `operator` is the
 * `Signature-Agent` URL that provided the key. `invalid`: a signature, component or freshness
 * check failed. `unverified`: no key to decide with, as the directory could not be read, does
 * not list it, or it isn't Ed25519.
 */
export interface OperatorVerdict {
  readonly outcome: "absent" | "verified" | "invalid" | "unverified";
  readonly operator?: string;
}

/** One signature tagged `web-bot-auth`: what is needed to check it. */
interface Offered {
  readonly label: string;
  readonly components: readonly Component[];
  readonly parameters: Readonly<Record<string, Bare>>;
  readonly parametersText: string;
  readonly signature: Uint8Array;
  readonly agent: Field;
}

function component(item: Field): Component {
  const name = item.value;
  if (typeof name !== "string" || name === "") throw new RangeError("a component is a string");
  const key = item.parameters.key;
  const extra = Object.keys(item.parameters).some((parameter) => parameter !== "key");
  if (extra || (key !== undefined && (name !== "signature-agent" || typeof key !== "string"))) {
    throw new RangeError("a component's parameters aren't supported");
  }
  if (name.startsWith("@") && !DERIVED.has(name)) {
    throw new RangeError("a derived component isn't supported");
  }
  return { name, key, identifier: item.raw };
}

/** The signatures tagged `web-bot-auth`; a `RangeError` when the headers don't parse. */
function offeredSignatures(headers: Readonly<Record<string, string | undefined>>): Offered[] {
  const text = headers["signature-input"];
  if (text === undefined) return [];
  const inputs = new Parser(text).dictionary();
  if (inputs.size > MAX_OFFERED_SIGNATURES) throw new RangeError("too many signatures");
  const tagged = [...inputs].filter(
    ([, member]) => Array.isArray(member.value) && member.parameters.tag === WEB_BOT_AUTH_TAG,
  );
  if (tagged.length === 0) return [];
  const signatures = new Parser(headers.signature ?? "").dictionary();
  const agents = new Parser(headers["signature-agent"] ?? "").dictionary();
  return tagged.map(([label, member]) => {
    const signature = signatures.get(label);
    const agent = agents.get(label);
    if (signature === undefined || agent === undefined || !(signature.value instanceof Uint8Array)) {
      throw new RangeError("a signature, or its Signature-Agent member, is absent");
    }
    return {
      label,
      components: (member.value as readonly Field[]).map(component),
      parameters: member.parameters,
      parametersText: member.raw,
      signature: signature.value,
      agent,
    };
  });
}

/** The components §5.3 and Web Bot Auth §5.2 require, the parameters, and freshness. */
function sound(
  offered: Offered,
  headers: Readonly<Record<string, string | undefined>>,
  now: number,
  window: number,
): boolean {
  const names = new Set(offered.components.map((item) => item.name));
  const member = offered.components.some(
    (item) => item.name === "signature-agent" && item.key === offered.label,
  );
  const { created, expires, keyid } = offered.parameters;
  const url = offered.agent.value;
  return (
    member &&
    names.has("poppy-session") &&
    (headers.authorization === undefined || names.has("authorization")) &&
    (names.has("@authority") || names.has("@target-uri")) &&
    Number.isSafeInteger(created) &&
    Number.isSafeInteger(expires) &&
    typeof keyid === "string" &&
    Object.keys(offered.agent.parameters).length === 0 &&
    typeof url === "string" &&
    url.startsWith("https://") &&
    (created as number) <= now + window &&
    (created as number) < (expires as number) &&
    now < (expires as number)
  );
}

function usableJwk(jwk: JWK): boolean {
  return jwk.kty === "OKP" && jwk.crv === "Ed25519" && typeof jwk.x === "string";
}

async function checked(
  offered: Offered,
  method: string,
  url: string,
  headers: Readonly<Record<string, string | undefined>>,
  keys: OperatorKeys,
  now: number,
  window: number,
): Promise<OperatorVerdict> {
  if (!sound(offered, headers, now, window)) return { outcome: "invalid" };
  const agent = offered.agent.value as string;
  const keyid = offered.parameters.keyid as string;
  const algorithm = offered.parameters.alg ?? OPERATOR_SIGNATURE_ALGORITHM;
  if (algorithm !== OPERATOR_SIGNATURE_ALGORITHM) return { outcome: "unverified" };
  let published: readonly JWK[];
  try {
    published = await keys(agent, keyid);
  } catch (error) {
    if (error instanceof PersonalAgentProtocolError) return { outcome: "unverified" };
    throw error;
  }
  let jwk: JWK | undefined;
  for (const item of published) {
    if (usableJwk(item) && (await jwkThumbprint(item)) === keyid) jwk = item;
  }
  if (jwk === undefined) return { outcome: "unverified" };
  try {
    const base = signatureBase(offered.components, offered.parametersText, method, url, headers, offered.agent.raw);
    const { kty, crv, x } = jwk;
    const key = await crypto.subtle.importKey("jwk", { kty, crv, x } as JsonWebKey, "Ed25519", false, ["verify"]);
    const good = await crypto.subtle.verify("Ed25519", key, offered.signature as BufferSource, base as BufferSource);
    return good ? { outcome: "verified", operator: agent } : { outcome: "invalid" };
  } catch (error) {
    if (error instanceof RangeError || error instanceof DOMException) return { outcome: "invalid" };
    throw error;
  }
}

export interface VerifyOperatorSignatureOptions {
  readonly method: string;
  readonly url: string;
  /** Lower-case names. */
  readonly headers: Readonly<Record<string, string | undefined>>;
  readonly keys: OperatorKeys;
  readonly now: Date;
  /** The clock skew `created` is allowed, in seconds (default a minute). */
  readonly windowSeconds?: number;
}

/**
 * What the request's operator signature comes to.
 *
 * One verified signature is enough. The Session JWT is verified apart from this, whatever it
 * says (§5.3).
 */
export async function verifyOperatorSignature(
  options: VerifyOperatorSignatureOptions,
): Promise<OperatorVerdict> {
  const { method, url, headers, keys, windowSeconds = 60 } = options;
  let offered: Offered[];
  try {
    offered = offeredSignatures(headers);
  } catch (error) {
    if (error instanceof RangeError || error instanceof DOMException) return { outcome: "invalid" };
    throw error;
  }
  if (offered.length === 0) return { outcome: "absent" };
  const now = options.now.getTime() / 1000;
  const verdicts: OperatorVerdict[] = [];
  for (const one of offered) verdicts.push(await checked(one, method, url, headers, keys, now, windowSeconds));
  return (
    verdicts.find((verdict) => verdict.outcome === "verified") ??
    verdicts.find((verdict) => verdict.outcome === "invalid") ??
    (verdicts[0] as OperatorVerdict)
  );
}

/** The bytes the first `web-bot-auth` signature of `headers` signed (RFC 9421 §2.5). */
export function operatorSignatureBase(
  method: string,
  url: string,
  headers: Readonly<Record<string, string | undefined>>,
): Uint8Array {
  const offered = offeredSignatures(headers)[0];
  if (offered === undefined) throw new RangeError("no web-bot-auth signature");
  return signatureBase(offered.components, offered.parametersText, method, url, headers, offered.agent.raw);
}

/** The `Accept-Signature` of a refusal: what this request should have signed (RFC 9421 §5). */
export function acceptSignature(headers: Readonly<Record<string, string | undefined>>): string {
  const label = OPERATOR_SIGNATURE_LABEL;
  const names: string[] = [...OPERATOR_SIGNATURE_COMPONENTS, "poppy-session"];
  if (headers.authorization !== undefined) names.push("authorization");
  const listed = covered(names, label).map((item) => item.identifier).join(" ");
  return `${label}=(${listed});created;expires;tag="${WEB_BOT_AUTH_TAG}"`;
}
