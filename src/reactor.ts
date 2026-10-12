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
import { DiscoveryError } from "./errors.js";
import {
  InMemoryProtocolCache,
  RetryPolicy,
  SharedRateLimitBudget,
  type RateLimitBudget,
} from "./limits.js";
import type { StandingPermissionStore } from "./operations.js";
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

export interface BrowserFormPost {
  post(endpoint: URL, fields: Readonly<Record<string, SecretValue>>): Promise<void>;
}

export interface DpopProofRequest {
  readonly method: string;
  readonly url: string;
  readonly tenantId: string;
  readonly subject: string;
  readonly issuer: string;
  readonly accessToken?: SecretValue;
  readonly nonce?: string;
}

export interface DpopProofProvider {
  create(request: DpopProofRequest): Promise<SecretValue>;
}

/** Serialize every use of one Account Token: rotation invalidates the one replaced (PAP §4.8). */
export interface AccountTokenLock {
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
  readonly companyName: string;
  readonly companyDomain: string;
  readonly fields: readonly ProtectedInputField[];
  readonly sentTo?: string;
}

/** The host's trusted input surface: answers never pass through a model. */
export interface ProtectedInput {
  collect(request: ProtectedInputRequest): Promise<Record<string, SecretValue>>;
}

/**
 * Receive each finished protocol stage (`TelemetryEvent` of telemetry.ts), redacted already.
 * No contribution, no telemetry.
 */
export interface TelemetrySink {
  record(event: TelemetryEvent): void;
}

/** One in-process lock per reference: the default Account Token lock. */
export class InProcessAccountTokenLock implements AccountTokenLock {
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
export const BrowserFormPosts = defineContributionPoint<BrowserFormPost>(
  "pap.browserFormPost",
);
export const DpopProofProviders = defineContributionPoint<DpopProofProvider>(
  "pap.dpopProofProvider",
);
export const AccountTokenLocks = defineContributionPoint<AccountTokenLock>(
  "pap.accountTokenLock",
);
export const ProtectedInputs = defineContributionPoint<ProtectedInput>(
  "pap.protectedInput",
);

export const RetryPolicies = defineContributionPoint<RetryPolicy>("pap.retryPolicy");
export const RateLimitBudgets = defineContributionPoint<RateLimitBudget>(
  "pap.rateLimitBudget",
);
/** `StandingPermissionStore` (operations.ts): the user's standing permissions (Operations). */
export const StandingPermissionStores = defineContributionPoint<StandingPermissionStore>(
  "pap.standingPermissionStore",
);
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
    version: "0.11.0",
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
      BrowserFormPosts,
      DpopProofProviders,
      AccountTokenLocks,
      ProtectedInputs,
      RetryPolicies,
      RateLimitBudgets,
      StandingPermissionStores,
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
      contribution(AccountTokenLocks, new InProcessAccountTokenLock(), {
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
