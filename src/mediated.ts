/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import type { ReactorPlatformView } from "@datalayer/reactor";

import { AuthorizationError, ProtocolValidationError } from "./errors.js";
import {
  parseMediatedSignIn,
  type DiscoveredCompany,
  type MediatedSignIn,
} from "./models.js";
import {
  AuthorizationStateStores,
  Clocks,
  ProtectedInputs,
  RandomSources,
  firstContribution,
  type ProtectedInputRequest,
} from "./reactor.js";
import type { SecretValue } from "./secret.js";
import {
  SessionClient,
  finishSignIn,
  opaqueId,
  type AccessToken,
  type TokenResponse,
} from "./sessions.js";
import { byIssuer, signInResult, traced } from "./telemetry.js";

/**
 * The Mediated Sign-In extension v1: the user's credentials, as an OAuth extension grant.
 *
 * A company that can't offer Direct or Device Sign-In yet lists
 * `extensions["mediated-sign-in"]` in its `poppy.json` and the grant type in its issuer's
 * `grant_types_supported`. It is the one sign-in where a password passes through the agent's
 * host, so this client narrows what the host can do with it:
 *
 * - The values are collected through the Reactor `pap.protectedInput` contribution, the host's
 *   own trusted surface, never from a model or a tool argument, and must be exactly the
 *   declared fields.
 * - They are sent to the `token_endpoint` of the company's issuer, with this grant, and
 *   nowhere else: no redirect is followed.
 * - They are sent once. A `code_required` answer continues with `sign_in_id` and the one-time
 *   code alone: no credentials, no scope.
 * - They are dropped as soon as the request is sent; no result, error, or log carries them,
 *   and the refresh token is kept behind an opaque reference.
 *
 * Errors are OAuth errors from the token endpoint, raised as `AuthorizationError`:
 * `invalid_grant`, `expired_token`, `access_denied`, `invalid_scope`, and a rate limit
 * (`rate_limited`, HTTP 429 with `Retry-After`). Mediated Sign-In is transitional: prefer
 * Direct or Device Sign-In when the company offers them.
 */

export const MEDIATED_EXTENSION = "mediated-sign-in";
export const MEDIATED_VERSION = "1";
export const MEDIATED_GRANT = "https://personalagentprotocol.org/grant/mediated-sign-in";

const SIGN_IN_ID = /^[A-Za-z0-9_-]{1,256}$/;

/** The extension's entry at this version, when the issuer lists the grant too. */
function declared(company: DiscoveredCompany): unknown {
  const descriptor = company.document.extensions[MEDIATED_EXTENSION];
  const metadata = company.oauthMetadata;
  if (
    descriptor === undefined ||
    descriptor.version !== MEDIATED_VERSION ||
    metadata === undefined ||
    !metadata.grant_types_supported.includes(MEDIATED_GRANT)
  ) {
    return undefined;
  }
  return descriptor;
}

/**
 * What the company's Mediated Sign-In asks for, or `undefined` when it offers none.
 *
 * An entry whose fields can't be used, such as one named `client_id`, is an extension this SDK
 * can't use either.
 */
export function mediatedSignIn(company: DiscoveredCompany): MediatedSignIn | undefined {
  const entry = declared(company);
  if (entry === undefined) return undefined;
  try {
    return parseMediatedSignIn(entry);
  } catch (error) {
    if (error instanceof ProtocolValidationError) return undefined;
    throw error;
  }
}

/**
 * Where a Mediated Sign-In stands, without any credential.
 *
 * `code_required` carries an opaque `reference` to continue with, where the company sent the
 * code (`sentTo`, as the company wrote it), and when it ends.
 */
export interface MediatedSignInResult {
  readonly status: "complete" | "code_required";
  readonly reference?: string;
  readonly sentTo?: string;
  readonly expiresAt?: Date;
  readonly token?: AccessToken;
  readonly refreshTokenReference?: string;
  readonly grantedScopes: readonly string[];
  readonly missingScopes: readonly string[];
}

export interface MediatedSignInOptions {
  readonly company: DiscoveredCompany;
  readonly clientId: string;
  readonly scopes: readonly string[];
  /** Whose DPoP key proves, when the issuer lists ES256 (§4.5). */
  readonly tenantId: string;
  readonly signal?: AbortSignal;
}

export interface MediatedSignInClientOptions {
  readonly reactor: ReactorPlatformView;
  readonly fetch?: typeof globalThis.fetch;
  readonly maxResponseBytes?: number;
}

interface PendingCode {
  readonly kind: "pap.mediated-sign-in.v1";
  readonly tokenEndpoint: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly scopes: readonly string[];
  readonly companyName: string;
  readonly companyDomain: string;
  readonly tenantId: string;
  readonly dpopSigningAlgs: readonly string[] | undefined;
  readonly signInId: string;
  readonly sentTo?: string;
  readonly expiresAt: Date;
}

const noResult = { grantedScopes: [], missingScopes: [] } as const;

function isPending(value: unknown): value is PendingCode {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Partial<PendingCode>).kind === "pap.mediated-sign-in.v1"
  );
}

/** Sign in with the user's credentials at the issuer's token endpoint, once. */
export class MediatedSignInClient {
  readonly #reactor: ReactorPlatformView;
  readonly #sessions: SessionClient;

  constructor(options: MediatedSignInClientOptions) {
    this.#reactor = options.reactor;
    this.#sessions = new SessionClient({
      reactor: options.reactor,
      ...(options.fetch === undefined ? {} : { fetch: options.fetch }),
      ...(options.maxResponseBytes === undefined ? {} : { maxResponseBytes: options.maxResponseBytes }),
    });
  }

  signIn(options: MediatedSignInOptions): Promise<MediatedSignInResult> {
    return traced(
      this.#reactor,
      "pap.sign_in.mediated.sign_in",
      byIssuer(options.company.oauthMetadata?.issuer, "mediated"),
      () => this.#signIn(options),
      signInResult,
    );
  }

  /**
   * Collect the declared fields from the user and send them with the grant.
   *
   * A DPoP proof goes with the grant when the issuer's metadata lists ES256 (§4.5).
   */
  async #signIn(options: MediatedSignInOptions): Promise<MediatedSignInResult> {
    const mediated = this.#offered(options.company);
    const metadata = options.company.oauthMetadata as NonNullable<DiscoveredCompany["oauthMetadata"]>;
    const organization = options.company.document.organization;
    const requested = [...new Set(options.scopes)];
    if (requested.length === 0) {
      throw new AuthorizationError("invalid_scope", "At least one valid OAuth scope is required");
    }
    const credentials = await this.#collect(
      {
        purpose: "credentials",
        companyName: organization.name,
        companyDomain: organization.domain,
        issuer: metadata.issuer,
        fields: mediated.fields.map(({ name, label, secret }) => ({ name, label, secret })),
      },
      new Set(mediated.fields.map((field) => field.name)),
    );
    let form: Record<string, string>;
    try {
      form = {
        grant_type: MEDIATED_GRANT,
        scope: requested.join(" "),
        ...Object.fromEntries(Object.entries(credentials).map(([name, value]) => [name, value.reveal()])),
      };
    } finally {
      for (const name of Object.keys(credentials)) delete credentials[name];
    }
    const pending: PendingCode = {
      kind: "pap.mediated-sign-in.v1",
      tokenEndpoint: metadata.token_endpoint,
      issuer: metadata.issuer,
      clientId: options.clientId,
      scopes: requested,
      companyName: organization.name,
      companyDomain: organization.domain,
      tenantId: options.tenantId,
      dpopSigningAlgs: metadata.dpop_signing_alg_values_supported,
      signInId: "",
      expiresAt: new Date(8.64e15),
    };
    return this.#grant(form, pending, undefined, options.signal);
  }

  /** Continue a `code_required` sign-in with the code the user received. */
  submitCode(reference: string, options: { readonly signal?: AbortSignal } = {}): Promise<MediatedSignInResult> {
    return traced(
      this.#reactor,
      "pap.sign_in.mediated.submit_code",
      { "pap.sign_in.method": "mediated" },
      () => this.#submitCode(reference, options.signal),
      signInResult,
    );
  }

  async #submitCode(reference: string, signal: AbortSignal | undefined): Promise<MediatedSignInResult> {
    const pending = await this.#state().take(reference);
    if (!isPending(pending)) {
      throw new AuthorizationError(
        "invalid_or_expired_sign_in",
        "Mediated Sign-In is unknown, expired, or already complete",
      );
    }
    const code = await this.#collect(
      {
        purpose: "one_time_code",
        companyName: pending.companyName,
        companyDomain: pending.companyDomain,
        issuer: pending.issuer,
        fields: [{ name: "code", label: "Code", secret: true }],
        ...(pending.sentTo === undefined ? {} : { sentTo: pending.sentTo }),
      },
      new Set(["code"]),
    );
    let form: Record<string, string>;
    try {
      form = {
        grant_type: MEDIATED_GRANT,
        sign_in_id: pending.signInId,
        one_time_code: (code.code as SecretValue).reveal(),
      };
    } finally {
      delete code.code;
    }
    return this.#grant(form, pending, reference, signal);
  }

  #offered(company: DiscoveredCompany): MediatedSignIn {
    const entry = declared(company);
    if (entry === undefined) {
      throw new AuthorizationError("no_mediated", "The company offers no Mediated Sign-In");
    }
    try {
      return parseMediatedSignIn(entry);
    } catch (cause) {
      // A field named like `client_id` would overwrite the grant's own parameters.
      throw new AuthorizationError(
        "invalid_mediated_extension",
        "The company's Mediated Sign-In can't be used",
        { cause },
      );
    }
  }

  async #grant(
    form: Record<string, string>,
    pending: PendingCode,
    reference: string | undefined,
    signal: AbortSignal | undefined,
  ): Promise<MediatedSignInResult> {
    let response: TokenResponse;
    try {
      response = await this.#sessions.tokenRequest({
        clientId: pending.clientId,
        issuer: pending.issuer,
        tokenEndpoint: pending.tokenEndpoint,
        form: () => form,
        error: AuthorizationError,
        tenantId: pending.tenantId,
        dpopSigningAlgs: pending.dpopSigningAlgs,
        ...(signal === undefined ? {} : { signal }),
      });
    } catch (error) {
      if (error instanceof AuthorizationError) {
        if (error.code === "code_required") return await this.#codeRequired(error, pending, reference);
        if (reference !== undefined && error.code === "rate_limited") {
          await this.#state().put(reference, pending, { expiresAt: pending.expiresAt });
        }
      }
      throw error;
    } finally {
      for (const name of Object.keys(form)) delete form[name];
    }
    return this.#complete(response, pending);
  }

  async #codeRequired(
    refusal: AuthorizationError,
    pending: PendingCode,
    reference: string | undefined,
  ): Promise<MediatedSignInResult> {
    const details = refusal.details ?? {};
    const { sign_in_id: signInId, sent_to: sentTo, expires_in: expiresIn } = details;
    const statusCode = refusal.statusCode;
    const context = statusCode === undefined ? {} : { statusCode };
    if (
      typeof signInId !== "string" ||
      !SIGN_IN_ID.test(signInId) ||
      (sentTo !== undefined && sentTo !== null && typeof sentTo !== "string") ||
      !Number.isInteger(expiresIn) ||
      (expiresIn as number) <= 0
    ) {
      throw new AuthorizationError("invalid_mediated_response", "Mediated Sign-In code challenge is malformed", context);
    }
    if (pending.signInId && signInId !== pending.signInId) {
      throw new AuthorizationError("invalid_mediated_response", "Mediated Sign-In changed its sign-in ID", context);
    }
    const clock = firstContribution(this.#reactor, Clocks, "clock");
    const expiresAt = new Date(clock.now().getTime() + (expiresIn as number) * 1000);
    const { sentTo: _sentBefore, ...earlier } = pending;
    const continued: PendingCode = {
      ...earlier,
      signInId,
      expiresAt,
      ...(typeof sentTo === "string" ? { sentTo } : {}),
    };
    const random = firstContribution(this.#reactor, RandomSources, "random source");
    const ref = reference ?? opaqueId("mediated", (length) => random.bytes(length));
    await this.#state().put(ref, continued, { expiresAt });
    return {
      status: "code_required",
      reference: ref,
      expiresAt,
      ...(continued.sentTo === undefined ? {} : { sentTo: continued.sentTo }),
      ...noResult,
    };
  }

  async #complete(response: TokenResponse, pending: PendingCode): Promise<MediatedSignInResult> {
    if (response.refreshToken === undefined) {
      throw new AuthorizationError("missing_refresh_token", "Mediated Sign-In did not return a refresh token");
    }
    // `scope` as at the token endpoint: left out only when exactly as requested.
    const result = await finishSignIn(this.#reactor, response, pending.scopes, { error: AuthorizationError });
    return { status: "complete", ...result };
  }

  async #collect(request: ProtectedInputRequest, expected: Set<string>): Promise<Record<string, SecretValue>> {
    const source = firstContribution(this.#reactor, ProtectedInputs, "protected input");
    const values = await source.collect(request);
    const names = Object.keys(values);
    if (
      names.length !== expected.size ||
      names.some((name) => !expected.has(name)) ||
      Object.values(values).some((value) => typeof value?.reveal !== "function" || !value.reveal())
    ) {
      for (const name of names) delete values[name];
      throw new AuthorizationError(
        "invalid_protected_input",
        "Protected input must answer exactly the declared fields, none empty",
      );
    }
    return values;
  }

  #state() {
    return firstContribution(this.#reactor, AuthorizationStateStores, "authorization state store");
  }
}
