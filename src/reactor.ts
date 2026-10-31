/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import {
  buildReactorFromPlugins,
  contribution,
  defineContributionPoint,
  definePlugin,
  type ReactorPlatform,
  type ReactorPlatformView,
  type ContributionPoint,
  type PlatformInput,
} from "@datalayer/reactor";

import { isGlobalAddress, literalAddress } from "./addresses.js";
// A cycle with crypto.ts, whose signers read this module's contracts: neither module uses the
// other while it loads.
import { InMemoryDpopKeys, JoseDpopProver } from "./crypto.js";
import { DiscoveryError } from "./errors.js";
import {
  InMemoryProtocolCache,
  RetryPolicy,
  SharedRateLimitBudget,
  type RateLimitBudget,
} from "./limits.js";
import type { SecretValue } from "./secret.js";
import type { TelemetryEvent } from "./telemetry.js";

export interface DiscoveryTransport {
  fetch(input: URL, init: RequestInit): Promise<Response>;
}

export interface UrlSafetyPolicy {
  assertSafe(url: URL): void | Promise<void>;
}

export interface Clock {
  now(): Date;
}

export interface RandomSource {
  bytes(length: number): Uint8Array;
}

export interface Signer {
  sign(
    claims: Readonly<Record<string, unknown>>,
    options: { readonly purpose: string },
  ): Promise<SecretValue>;
}


export interface TokenStore {
  put(reference: string, token: SecretValue): Promise<void>;
  get(reference: string): Promise<SecretValue | undefined>;
  delete(reference: string): Promise<void>;
}

export interface PairwiseUserIdStore {
  getOrCreate(options: {
    readonly tenantId: string;
    readonly localUserId: string;
    readonly companyIssuer: string;
  }): Promise<string>;
}

export interface AuthorizationStateStore {
  put(reference: string, value: unknown, options: { readonly expiresAt: Date }): Promise<void>;
  take(reference: string): Promise<unknown | undefined>;
}

export interface ProtocolCache {
  put(key: string, value: unknown, options: { readonly expiresAt: Date }): Promise<void>;
  get(key: string): Promise<unknown | undefined>;
  delete(key: string): Promise<void>;
}

export interface BrowserHandoff {
  open(authorizationUrl: SecretValue): Promise<void>;
}

/**
 * The personal agent's own browser, joining a Session through the company's form (§6).
 *
 * Only a browser the personal agent controls, never the User's own: otherwise the Company would
 * treat the User's own visits as the personal agent's. `loadJoinForm` opens the endpoint with a GET, as a top-level navigation, and returns the
 * form's one-time `code`, read from that page only; once the agent has authorized the code,
 * `submitJoinForm` submits the form, the code alone, from the same browser, whose cookie
 * ties the code to it.
 */
export interface BrowserJoin {
  loadJoinForm(endpoint: URL): Promise<SecretValue>;
  submitJoinForm(): Promise<void>;
}

/**
 * Inputs for one request's Session JWT (§5.2).
 *
 * `sid` names the Session, `sub` the User ID and `issuer` the Company; `accessToken`, when
 * the request carries one, is hashed into `ath`.
 */
export interface SessionJwtRequest {
  readonly method: string;
  readonly url: string;
  readonly tenantId: string;
  readonly issuer: string;
  readonly clientId: string;
  readonly sid: string;
  readonly sub: string;
  readonly agentId?: string;
  readonly accessToken?: SecretValue;
}

/**
 * Sign the Session JWT of one request with a delegated key whose private half it keeps
 * (§5.2). `DelegatedSessionSigner` is the default: one delegated key per User ID.
 */
export interface SessionSigner {
  sign(request: SessionJwtRequest): Promise<SecretValue>;
}

/**
 * What one DPoP proof is signed for (§4.5, RFC 9449 §4.2).
 *
 * `method` and `url` are the request's (`htm`, `htu`). `tenantId` and `issuer` say whose key
 * signs: one key per Company, for a tenant. `accessToken`, when the request carries one, is
 * hashed into `ath`, and `nonce` is the latest the server gave.
 */
export interface DpopProofRequest {
  readonly method: string;
  readonly url: string;
  readonly tenantId: string;
  readonly issuer: string;
  readonly accessToken?: SecretValue;
  readonly nonce?: string;
}

/**
 * Sign the DPoP proof of one request (§4.5).
 *
 * Never with a delegated key or a key from `jwks_uri`: a proof and a Session JWT are separate
 * signatures, by separate keys (§5.2).
 */
export interface DpopProver {
  prove(request: DpopProofRequest): Promise<SecretValue>;
}

/**
 * What one operator signature is signed for (§5.3, RFC 9421).
 *
 * `method` and `url` are the request's, `sessionJwt` the value of its `Poppy-Session` header and
 * `authorization` of its `Authorization` header, when it has one. A signature covers both.
 * `tenantId` says for whom, for a host with a key per tenant.
 */
export interface OperatorSignatureRequest {
  readonly method: string;
  readonly url: string;
  readonly tenantId: string;
  readonly sessionJwt: SecretValue;
  readonly authorization?: SecretValue;
}

/** The values of the three headers of a signed request (Web Bot Auth §5.2.5). */
export interface OperatorSignature {
  readonly signatureAgent: string;
  readonly signatureInput: string;
  readonly signature: string;
}

/**
 * Sign one request that carries the Session header, as its operator (§5.3).
 *
 * Never with a delegated key, a DPoP key or a key from `jwks_uri`: an operator signature is a
 * fourth signature, by a key the operator publishes in its directory.
 */
export interface OperatorSigner {
  sign(request: OperatorSignatureRequest): Promise<OperatorSignature>;
}

/** Serialize every use of one refresh token: rotation invalidates the one replaced (§4.4). */
export interface RefreshTokenLock {
  hold<T>(reference: string, work: () => Promise<T>): Promise<T>;
}

export interface ProtectedInputField {
  readonly name: string;
  readonly label: string;
  readonly secret: boolean;
}

/** What the host must ask the user for, outside any model (PAP §4.7). */
export interface ProtectedInputRequest {
  readonly purpose: "credentials" | "one_time_code";
  /** Shown whenever the host asks, with `companyDomain` (§4.7). */
  readonly companyName: string;
  readonly companyDomain: string;
  /**
   * The company's issuer: a credential store the user chose picks stored credentials by
   * it, never by the field labels, which the company writes and can name anything.
   */
  readonly issuer: string;
  readonly fields: readonly ProtectedInputField[];
  readonly sentTo?: string;
}

/** The host's trusted input surface: answers never pass through a model. */
export interface ProtectedInput {
  collect(request: ProtectedInputRequest): Promise<Record<string, SecretValue>>;
}

/**
 * What a user is asked to approve: nothing has been done yet.
 *
 * An operation (Operations 5): `summary` is the company's own, shown as it is and as text, its
 * links, images and HTML not rendered (`inertSummary`, wherever Markdown is); `companyName` and
 * `companyDomain` say who asks, and are shown with it; `terms` and `expiresAt` are the
 * revision's; `differences` what the terms check found, to point out; `changed` what a new
 * revision changed.
 */
export interface ApprovalRequest {
  readonly actionId: string;
  readonly actionName: string;
  readonly summary: string;
  readonly arguments: Readonly<Record<string, string>>;
  readonly tenantId: string;
  readonly companyName?: string;
  readonly companyDomain?: string;
  readonly terms?: Readonly<Record<string, unknown>>;
  readonly expiresAt?: Date;
  readonly differences: readonly string[];
  readonly changed: readonly string[];
}

/**
 * The host's own approval surface: the user, not a model, answers.
 *
 * Only `true` approves. The surface asks the user every time: it never answers from an earlier
 * decision, and never because of text from a company. Without a contribution, no operation is
 * approved.
 */
export interface ApprovalSurface {
  approve(request: ApprovalRequest): Promise<boolean>;
}

/**
 * Receive each finished protocol stage (`TelemetryEvent` of telemetry.ts), redacted already.
 * No contribution, no telemetry.
 */
export interface TelemetrySink {
  record(event: TelemetryEvent): void;
}

/** One in-process lock per reference: the default refresh token lock. */
export class InProcessRefreshTokenLock implements RefreshTokenLock {
  readonly #tails = new Map<string, Promise<unknown>>();

  async hold<T>(reference: string, work: () => Promise<T>): Promise<T> {
    const previous = this.#tails.get(reference) ?? Promise.resolve();
    const run = previous.then(work, work);
    const tail = run.catch(() => undefined);
    this.#tails.set(reference, tail);
    try {
      return await run;
    } finally {
      if (this.#tails.get(reference) === tail) this.#tails.delete(reference);
    }
  }
}

export const DiscoveryTransports = defineContributionPoint<DiscoveryTransport>(
  "pap.discoveryTransport",
);
export const UrlSafetyPolicies = defineContributionPoint<UrlSafetyPolicy>(
  "pap.urlSafetyPolicy",
);
export const Clocks = defineContributionPoint<Clock>("pap.clock");
export const RandomSources = defineContributionPoint<RandomSource>("pap.randomSource");
export const Signers = defineContributionPoint<Signer>("pap.signer");
export const TokenStores = defineContributionPoint<TokenStore>("pap.tokenStore");
export const PairwiseUserIdStores = defineContributionPoint<PairwiseUserIdStore>(
  "pap.pairwiseUserIdStore",
);
export const AuthorizationStateStores = defineContributionPoint<AuthorizationStateStore>(
  "pap.authorizationStateStore",
);
export const Caches = defineContributionPoint<ProtocolCache>("pap.cache");
export const BrowserHandoffs = defineContributionPoint<BrowserHandoff>(
  "pap.browserHandoff",
);
export const BrowserJoins = defineContributionPoint<BrowserJoin>("pap.browserJoin");
export const SessionSigners = defineContributionPoint<SessionSigner>("pap.sessionSigner");
/** `DpopProver`: the DPoP proof of a request, when the Company lists ES256 or bound a token. */
export const DpopProvers = defineContributionPoint<DpopProver>("pap.dpopProver");
/**
 * `OperatorSigner`: the operator signature of a request with the Session header; none, and
 * requests go unsigned.
 */
export const OperatorSigners = defineContributionPoint<OperatorSigner>("pap.operatorSigner");
export const RefreshTokenLocks = defineContributionPoint<RefreshTokenLock>(
  "pap.refreshTokenLock",
);
export const ProtectedInputs = defineContributionPoint<ProtectedInput>(
  "pap.protectedInput",
);

export const RetryPolicies = defineContributionPoint<RetryPolicy>("pap.retryPolicy");
export const RateLimitBudgets = defineContributionPoint<RateLimitBudget>(
  "pap.rateLimitBudget",
);
/** `ApprovalSurface`: the host's own surface, where the user answers (Operations 5). */
export const ApprovalSurfaces = defineContributionPoint<ApprovalSurface>("pap.approvalSurface");
/** `TelemetrySink`: where traces and analytics events go; none, and nothing is emitted. */
export const TelemetrySinks = defineContributionPoint<TelemetrySink>("pap.telemetry");

export interface PapCoreOptions {
  readonly fetch?: typeof globalThis.fetch;
  readonly assertSafeUrl?: (url: URL) => void | Promise<void>;
}

const systemClock: Clock = { now: () => new Date() };
const systemRandom: RandomSource = {
  bytes(length) {
    if (!Number.isInteger(length) || length <= 0) {
      throw new RangeError("Random byte length must be a positive integer");
    }
    if (!globalThis.crypto) {
      throw new Error("A cryptographically secure random source is required");
    }
    return globalThis.crypto.getRandomValues(new Uint8Array(length));
  },
};

/** Names that never leave the host or its network (RFC 6761, RFC 6762, RFC 8375, `.internal`). */
const LOCAL_NAMES = ["localhost", "local", "internal", "home.arpa", "localdomain"];

/**
 * The portable, textual URL check every runtime applies: HTTPS without user information,
 * and a host that is neither a local name nor an IP literal outside global unicast. It
 * cannot see where a name resolves: on Node, the company's default transport resolves
 * and pins (`createResolvingFetch`, `./server`); elsewhere, contribute a policy that can.
 */
function assertObviouslyPublic(url: URL): void {
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new DiscoveryError("unsafe_url", "Discovery and metadata URLs must use HTTPS");
  }
  // `localhost.` is `localhost`: a trailing dot names the same host.
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  const literal = literalAddress(host);
  const local = LOCAL_NAMES.some((name) => host === name || host.endsWith(`.${name}`));
  if (literal !== undefined ? !isGlobalAddress(literal) : !host || local) {
    throw new DiscoveryError("unsafe_address", "Discovery URL names a private address");
  }
}

export function createPapCorePlugin(options: PapCoreOptions = {}) {
  const fetcher = options.fetch ?? globalThis.fetch;
  if (!fetcher) {
    throw new DiscoveryError("fetch_unavailable", "A fetch implementation is required");
  }
  return definePlugin({
    name: "@datalayer/personal-agent-protocol-core",
    version: "0.30.0",
    contributionPoints: [
      DiscoveryTransports,
      UrlSafetyPolicies,
      Clocks,
      RandomSources,
      Signers,
      TokenStores,
      PairwiseUserIdStores,
      AuthorizationStateStores,
      Caches,
      BrowserHandoffs,
      BrowserJoins,
      SessionSigners,
      DpopProvers,
      OperatorSigners,
      RefreshTokenLocks,
      ProtectedInputs,
      RetryPolicies,
      RateLimitBudgets,
      ApprovalSurfaces,
      TelemetrySinks,
    ],
    contributes: [
      contribution(
        DiscoveryTransports,
        { fetch: (input, init) => fetcher(input, init) },
        { id: "fetch", order: 100 },
      ),
      contribution(
        UrlSafetyPolicies,
        {
          async assertSafe(url) {
            assertObviouslyPublic(url);
            await options.assertSafeUrl?.(url);
          },
        },
        { id: "public", order: 100 },
      ),
      contribution(Clocks, systemClock, { id: "system", order: 100 }),
      contribution(RandomSources, systemRandom, { id: "system", order: 100 }),
      contribution(RefreshTokenLocks, new InProcessRefreshTokenLock(), {
        id: "in-process",
        order: 100,
      }),
      contribution(Caches, new InMemoryProtocolCache(), { id: "memory", order: 100 }),
      contribution(RetryPolicies, new RetryPolicy(), { id: "default", order: 100 }),
      contribution(RateLimitBudgets, new SharedRateLimitBudget(), {
        id: "in-process",
        order: 100,
      }),
    ],
    register({ contribute, reactor }) {
      // Whichever clock and random source the host contributes, read when a proof is signed.
      contribute(
        DpopProvers,
        new JoseDpopProver(new InMemoryDpopKeys(), {
          now: () => firstContribution(reactor, Clocks, "clock").now(),
          randomBytes: (length) => firstContribution(reactor, RandomSources, "random source").bytes(length),
        }),
        { id: "in-memory", order: 100 },
      );
    },
  });
}

export function buildPapReactor(
  options: PapCoreOptions = {},
  plugins: PlatformInput[] = [],
): ReactorPlatform {
  const reactor = buildReactorFromPlugins([createPapCorePlugin(options), ...plugins]);
  reactor.start();
  return reactor;
}

export function firstContribution<T>(
  reactor: ReactorPlatformView,
  point: ContributionPoint<T>,
  label: string,
): T {
  const contributions = reactor.getContributions(point);
  const selected = contributions[0];
  if (!selected) {
    throw new Error(`PAP Reactor has no active ${label} contribution`);
  }
  if (contributions[1]?.order === selected.order) {
    throw new Error(`PAP Reactor has ambiguous ${label} contributions`);
  }
  return selected.value;
}

/**
 * The highest-priority provider for an optional PAP point, `undefined` when there is none.
 *
 * An optional point may have no provider (the feature is off), but never two at the same
 * winning priority: that fails closed exactly as `firstContribution` does.
 */
export function optionalContribution<T>(
  reactor: ReactorPlatformView,
  point: ContributionPoint<T>,
  label: string,
): T | undefined {
  if (!reactor.getContributions(point).length) return undefined;
  return firstContribution(reactor, point, label);
}
