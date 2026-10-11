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

import { DiscoveryError } from "./errors.js";
import {
  InMemoryProtocolCache,
  RetryPolicy,
  SharedRateLimitBudget,
  type RateLimitBudget,
} from "./limits.js";
import type { SecretValue } from "./secret.js";

export interface DiscoveryTransport {
  fetch(input: URL, init: RequestInit): Promise<Response>;
}

export interface UrlSafetyPolicy {
  assertSafe(url: URL): void | Promise<void>;
}

export interface ProtocolProfile {
  readonly version: string;
}

export interface ExtensionHandler {
  readonly name: string;
  readonly majorVersion: number;
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

export interface KeyReference {
  readonly id: string;
  readonly algorithm: string;
}

export interface KeyStore {
  getOrCreate(options: {
    readonly tenantId: string;
    readonly subject: string;
    readonly purpose: string;
  }): Promise<KeyReference>;
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
export const ProtocolProfiles = defineContributionPoint<ProtocolProfile>(
  "pap.protocolProfile",
);
export const ExtensionHandlers = defineContributionPoint<ExtensionHandler>(
  "pap.extensionHandler",
);
export const Clocks = defineContributionPoint<Clock>("pap.clock");
export const RandomSources = defineContributionPoint<RandomSource>("pap.randomSource");
export const Signers = defineContributionPoint<Signer>("pap.signer");
export const KeyStores = defineContributionPoint<KeyStore>("pap.keyStore");
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

function assertObviouslyPublic(url: URL): void {
  if (url.protocol !== "https:" || url.username || url.password) {
    throw new DiscoveryError("unsafe_url", "Discovery and metadata URLs must use HTTPS");
  }
  const host = url.hostname.toLowerCase().replace(/[\[\]]/g, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "::1" ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host)
  ) {
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
    version: "0.4.0",
    contributionPoints: [
      DiscoveryTransports,
      UrlSafetyPolicies,
      ProtocolProfiles,
      ExtensionHandlers,
      Clocks,
      RandomSources,
      Signers,
      KeyStores,
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
      contribution(ProtocolProfiles, { version: "0.1" }, { id: "0.1", order: 100 }),
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
