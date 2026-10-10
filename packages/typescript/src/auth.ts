import { AuthorizationError } from "./errors.js";
import { JWT_CLIENT_ASSERTION, SecretValue, type RandomBytes } from "./sessions.js";

function defaultRandomBytes(length: number): Uint8Array {
  if (!globalThis.crypto) {
    throw new AuthorizationError("crypto_unavailable", "Web Crypto is required");
  }
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

function entropy(length: number, randomBytes: RandomBytes): Uint8Array {
  const value = randomBytes(length);
  if (value.byteLength < length) {
    throw new AuthorizationError(
      "weak_entropy",
      `Authorization requires ${length * 8} random bits`,
    );
  }
  return value;
}

function base64Url(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let output = "";
  for (let index = 0; index < bytes.length; index += 3) {
    const first = bytes[index] ?? 0;
    const second = bytes[index + 1];
    const third = bytes[index + 2];
    output += alphabet[first >>> 2];
    output += alphabet[((first & 3) << 4) | ((second ?? 0) >>> 4)];
    if (second !== undefined) {
      output += alphabet[((second & 15) << 2) | ((third ?? 0) >>> 6)];
    }
    if (third !== undefined) {
      output += alphabet[third & 63];
    }
  }
  return output;
}

function httpsUrl(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (cause) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`, { cause });
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
    throw new AuthorizationError("invalid_url", `${label} must be an HTTPS URL`);
  }
  return parsed;
}

function validScopes(values: readonly string[]): readonly string[] {
  const scopes = [...new Set(values)];
  const token = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
  if (scopes.length === 0 || scopes.some((scope) => !token.test(scope))) {
    throw new AuthorizationError("invalid_scope", "At least one valid OAuth scope is required");
  }
  return scopes;
}

export interface DirectSignInOptions {
  readonly authorizationEndpoint: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly randomBytes?: RandomBytes;
}

export interface DirectSignInRequest {
  readonly authorizationUrl: SecretValue;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: readonly string[];
  readonly state: SecretValue;
  readonly codeVerifier: SecretValue;
}

export async function buildDirectSignInRequest(
  options: DirectSignInOptions,
): Promise<DirectSignInRequest> {
  const randomBytes = options.randomBytes ?? defaultRandomBytes;
  const state = base64Url(entropy(16, randomBytes));
  const verifier = base64Url(entropy(32, randomBytes));
  const challenge = base64Url(
    new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))),
  );
  const endpoint = httpsUrl(options.authorizationEndpoint, "authorizationEndpoint");
  const scopes = validScopes(options.scopes);
  const clientId = httpsUrl(options.clientId, "clientId").toString();
  const redirectUri = httpsUrl(options.redirectUri, "redirectUri").toString();
  const issuer = httpsUrl(options.issuer, "issuer").toString().replace(/\/$/, "");
  endpoint.searchParams.set("response_type", "code");
  endpoint.searchParams.set("client_id", clientId);
  endpoint.searchParams.set("redirect_uri", redirectUri);
  endpoint.searchParams.set("scope", scopes.join(" "));
  endpoint.searchParams.set("state", state);
  endpoint.searchParams.set("code_challenge", challenge);
  endpoint.searchParams.set("code_challenge_method", "S256");
  endpoint.hash = "";
  return {
    authorizationUrl: new SecretValue(endpoint.toString()),
    issuer,
    clientId,
    redirectUri,
    scopes,
    state: new SecretValue(state),
    codeVerifier: new SecretValue(verifier),
  };
}

export interface DirectSignInCallback {
  readonly code: SecretValue;
  readonly issuer: string;
}

function equalConstantTime(left: string, right: string): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

export function validateDirectSignInCallback(
  request: DirectSignInRequest,
  callbackUrl: string,
): DirectSignInCallback {
  const expected = httpsUrl(request.redirectUri, "redirectUri");
  const callback = httpsUrl(callbackUrl, "callbackUrl");
  if (callback.hash) {
    throw new AuthorizationError("invalid_callback", "Authorization callback has a fragment");
  }
  if (callback.origin !== expected.origin || callback.pathname !== expected.pathname) {
    throw new AuthorizationError("redirect_mismatch", "Callback does not match redirect URI");
  }
  for (const [key, value] of expected.searchParams) {
    if (callback.searchParams.get(key) !== value) {
      throw new AuthorizationError(
        "redirect_mismatch",
        "Callback changed redirect URI parameters",
      );
    }
  }
  for (const key of ["code", "state", "iss", "error"]) {
    if (callback.searchParams.getAll(key).length > 1) {
      throw new AuthorizationError(
        "invalid_callback",
        "Authorization callback repeats a security parameter",
      );
    }
  }
  if (callback.searchParams.has("error")) {
    throw new AuthorizationError("authorization_denied", "Company did not authorize the request");
  }
  if (!equalConstantTime(callback.searchParams.get("state") ?? "", request.state.reveal())) {
    throw new AuthorizationError("state_mismatch", "Authorization state does not match");
  }
  if (callback.searchParams.get("iss") !== request.issuer) {
    throw new AuthorizationError("issuer_mismatch", "Authorization issuer does not match");
  }
  const code = callback.searchParams.get("code");
  if (!code) {
    throw new AuthorizationError("invalid_callback", "Authorization callback has no code");
  }
  return { code: new SecretValue(code), issuer: request.issuer };
}

export interface AuthorizationCodeGrantOptions {
  readonly code: string;
  readonly redirectUri: string;
  readonly codeVerifier: string;
  readonly sessionId: string;
  readonly clientId: string;
  readonly clientAssertion: string;
}

export class AuthorizationCodeGrant {
  readonly code: SecretValue;
  readonly redirectUri: string;
  readonly codeVerifier: SecretValue;
  readonly sessionId: string;
  readonly clientId: string;
  readonly clientAssertion: SecretValue;

  constructor(options: AuthorizationCodeGrantOptions) {
    this.code = new SecretValue(options.code);
    this.redirectUri = httpsUrl(options.redirectUri, "redirectUri").toString();
    this.codeVerifier = new SecretValue(options.codeVerifier);
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(options.sessionId)) {
      throw new AuthorizationError("invalid_session_id", "Invalid PAP session ID");
    }
    this.sessionId = options.sessionId;
    this.clientId = httpsUrl(options.clientId, "clientId").toString();
    this.clientAssertion = new SecretValue(options.clientAssertion);
  }

  toForm(): URLSearchParams {
    return new URLSearchParams({
      grant_type: "authorization_code",
      code: this.code.reveal(),
      redirect_uri: this.redirectUri,
      code_verifier: this.codeVerifier.reveal(),
      session_id: this.sessionId,
      client_id: this.clientId,
      client_assertion_type: JWT_CLIENT_ASSERTION,
      client_assertion: this.clientAssertion.reveal(),
    });
  }

  toJSON(): Record<string, unknown> {
    return {
      grant_type: "authorization_code",
      code: this.code,
      redirect_uri: this.redirectUri,
      code_verifier: this.codeVerifier,
      session_id: this.sessionId,
      client_id: this.clientId,
      client_assertion_type: JWT_CLIENT_ASSERTION,
      client_assertion: this.clientAssertion,
    };
  }
}
