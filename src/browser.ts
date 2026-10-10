import type { ReactorPlatformView } from "@datalayer/reactor";

import { BrowserSessionError } from "./errors.js";
import { BrowserFormPosts, Clocks, RandomSources, Signers, firstContribution } from "./reactor.js";
import { SecretValue } from "./secret.js";

export const BROWSER_ASSERTION_TYPE = "poppy-browser+jwt";

export interface BrowserAssertionClaims {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string;
  readonly session_id: string;
  readonly return_to: string;
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
}

export interface BrowserAssertionOptions {
  readonly clientId: string;
  readonly pairwiseUserId: string;
  readonly browserSessionEndpoint: string;
  readonly sessionId: string;
  readonly returnTo: string;
  readonly companyDomain: string;
  readonly now?: Date;
  readonly lifetimeSeconds?: number;
  readonly randomBytes?: (length: number) => Uint8Array;
}

function httpsUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new BrowserSessionError("invalid_url", `${label} must be an HTTPS URL`, { cause });
  }
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new BrowserSessionError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return url;
}

function companyReturnTo(value: string, companyDomain: string): string {
  const url = httpsUrl(value, "returnTo");
  const host = url.hostname.toLowerCase().replace(/\.$/u, "");
  const domain = companyDomain.toLowerCase().replace(/\.$/u, "");
  if (!domain || (host !== domain && !host.endsWith(`.${domain}`))) {
    throw new BrowserSessionError(
      "invalid_return_to",
      "returnTo must be on the company domain or a subdomain",
    );
  }
  return url.toString();
}

function defaultRandomBytes(length: number): Uint8Array {
  if (!globalThis.crypto) throw new BrowserSessionError("crypto_unavailable", "Web Crypto is required");
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function buildBrowserAssertionClaims(options: BrowserAssertionOptions): BrowserAssertionClaims {
  const lifetime = options.lifetimeSeconds ?? 60;
  if (!Number.isInteger(lifetime) || lifetime <= 0 || lifetime > 60) {
    throw new BrowserSessionError(
      "invalid_lifetime",
      "Browser assertion lifetime must be between 1 and 60 seconds",
    );
  }
  if (!/^[A-Za-z0-9_-]{1,256}$/u.test(options.pairwiseUserId)) {
    throw new BrowserSessionError("invalid_user_id", "Invalid pairwise user ID");
  }
  if (!/^[A-Za-z0-9_-]{1,256}$/u.test(options.sessionId)) {
    throw new BrowserSessionError("invalid_session_id", "Invalid PAP Session ID");
  }
  const entropy = (options.randomBytes ?? defaultRandomBytes)(16);
  if (entropy.byteLength < 16) {
    throw new BrowserSessionError("weak_randomness", "Browser assertion IDs require 128 random bits");
  }
  const iat = Math.floor((options.now ?? new Date()).getTime() / 1000);
  return {
    iss: httpsUrl(options.clientId, "clientId").toString(),
    sub: options.pairwiseUserId,
    aud: httpsUrl(options.browserSessionEndpoint, "browserSessionEndpoint").toString(),
    session_id: options.sessionId,
    return_to: companyReturnTo(options.returnTo, options.companyDomain),
    iat,
    exp: iat + lifetime,
    jti: `jti_${base64Url(entropy)}`,
  };
}

export interface BrowserSessionStart {
  readonly endpoint: string;
  readonly returnTo: string;
  readonly expiresAt: Date;
}

export class BrowserSessionClient {
  readonly #reactor: ReactorPlatformView;

  constructor(options: { readonly reactor: ReactorPlatformView }) {
    this.#reactor = options.reactor;
  }

  async join(options: Omit<BrowserAssertionOptions, "now" | "randomBytes">): Promise<BrowserSessionStart> {
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const signer = firstContribution(this.#reactor, Signers, "signer");
    const browser = firstContribution(this.#reactor, BrowserFormPosts, "browser form POST");
    const claims = buildBrowserAssertionClaims({
      ...options,
      now: clock.now(),
      randomBytes: length => random.bytes(length),
    });
    const assertion = await signer.sign({ ...claims }, { purpose: "browser_assertion" });
    await browser.post(new URL(claims.aud), { assertion });
    return {
      endpoint: claims.aud,
      returnTo: claims.return_to,
      expiresAt: new Date(claims.exp * 1000),
    };
  }
}

export function assertCompanyReturnTo(value: string, companyDomain: string): string {
  return companyReturnTo(value, companyDomain);
}

export function browserAssertionError(cause?: unknown): BrowserSessionError {
  return new BrowserSessionError(
    "invalid_browser_assertion",
    "Browser assertion signature or claims are invalid",
    cause === undefined ? {} : { cause },
  );
}

export function validateBrowserClaimIdentity(value: unknown, label: string): string {
  if (typeof value !== "string" || !value) throw browserAssertionError(new TypeError(`${label} is invalid`));
  return value;
}

export function redactBrowserAssertion(value: string): SecretValue {
  return new SecretValue(value);
}
