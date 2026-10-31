/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

/**
 * The company side of PAP, assembled from Reactor contributions.
 *
 * ```ts
 * const service = buildCompany(config, { plugins: [myCompanyPlugin] });
 * createServer(companyRequestListener(service)); // node:http or node:https
 * ```
 *
 * Server-only: exported from `@datalayer/personal-agent-protocol/server`.
 */

import {
  contribution,
  definePlugin,
  type PlatformInput,
  type ReactorPlatformView,
} from "@datalayer/reactor";

import type { JWK } from "jose";

import { AgentIdentityClient } from "../identity.js";
import { createResolvingFetch } from "../node-network.js";
import type { ClientMetadata, JsonWebKeySet } from "../models.js";
import {
  Clocks,
  buildPapReactor,
  firstContribution,
  type Clock,
  type PapCoreOptions,
} from "../reactor.js";
import {
  AllowEveryAgent,
  ClientPolicies,
  ClientResolvers,
  OperatorDirectories,
  CompanyAccounts,
  CompanyAgents,
  CompanyApis,
  CompanyMcps,
  CompanyRateLimits,
  CompanyStores,
  MemoryCompanyStore,
  OperationExecutors,
  ReplayCaches,
  StoreReplayCache,
  type ClientResolver,
  type OperatorDirectory,
  type CompanyStore,
} from "./points.js";
import { CompanyService, type CompanyConfig } from "./service.js";

/** Resolve a personal agent's metadata and keys over HTTPS (§4.1). */
export class IdentityClientResolver implements ClientResolver {
  #identity: AgentIdentityClient | undefined;

  constructor(identity?: AgentIdentityClient) {
    this.#identity = identity;
  }

  /** Give the resolver its client once the company's Reactor exists. */
  bind(identity: AgentIdentityClient): void {
    this.#identity = identity;
  }

  /** Cached metadata and keys, the keys fetched again for an unknown `kid`. */
  async resolve(
    clientId: string,
    options: { readonly kid?: string } = {},
  ): Promise<readonly [ClientMetadata, JsonWebKeySet]> {
    const identity = this.#identity;
    if (identity === undefined) throw new Error("IdentityClientResolver is not bound");
    return [
      await identity.fetchMetadata(clientId),
      await identity.fetchJwks(clientId, options.kid === undefined ? {} : { kid: options.kid }),
    ];
  }
}

/** Read an operator's published keys over HTTPS (§5.3, Web Bot Auth §5.5). */
export class IdentityOperatorDirectory implements OperatorDirectory {
  #identity: AgentIdentityClient | undefined;

  /** Give the directory its client once the company's Reactor exists. */
  bind(identity: AgentIdentityClient): void {
    this.#identity = identity;
  }

  /** Cached keys, fetched again for an unknown `keyid`. */
  async keys(url: string, keyid: string): Promise<readonly JWK[]> {
    if (this.#identity === undefined) throw new Error("IdentityOperatorDirectory is not bound");
    return this.#identity.fetchOperatorKeys(url, { keyid });
  }
}

/** The clock a reactor's `pap.clock` contribution keeps, read at each call once bound. */
export class ReactorClock implements Clock {
  #reactor: ReactorPlatformView | undefined;

  /** Read the company's clock once its Reactor exists (the system clock before). */
  bind(reactor: ReactorPlatformView): void {
    this.#reactor = reactor;
  }

  now(): Date {
    const reactor = this.#reactor;
    return reactor === undefined ? new Date() : firstContribution(reactor, Clocks, "clock").now();
  }
}

/**
 * The company side's defaults: memory store, a replay cache in the store, open policy,
 * HTTPS identity. `store` reads the company's contributed store at each call: the default
 * replay cache keeps its identifiers wherever the company keeps its records.
 */
export function createCompanyDefaultsPlugin(
  resolver: ClientResolver,
  clock: Clock | undefined,
  store: () => CompanyStore,
  directory?: OperatorDirectory,
) {
  return definePlugin({
    name: "personal-agent-protocol.company",
    version: "0.29.0",
    contributionPoints: [
      CompanyStores,
      CompanyAccounts,
      CompanyAgents,
      CompanyApis,
      CompanyMcps,
      CompanyRateLimits,
      OperationExecutors,
      ClientPolicies,
      ClientResolvers,
      OperatorDirectories,
      ReplayCaches,
    ],
    contributes: [
      contribution(
        CompanyStores,
        new MemoryCompanyStore(clock === undefined ? {} : { clock }),
        { id: "memory", order: 100 },
      ),
      // The replay cache is the contributed store's: a shared store, a shared cache.
      contribution(ReplayCaches, new StoreReplayCache(store), { id: "store", order: 100 }),
      contribution(ClientPolicies, new AllowEveryAgent(), { id: "allow", order: 100 }),
      contribution(ClientResolvers, resolver, { id: "https", order: 100 }),
      ...(directory === undefined ? [] : [contribution(OperatorDirectories, directory, { id: "https", order: 100 })]),
    ],
  });
}

export interface BuildCompanyOptions extends PapCoreOptions {
  /** The company's own plugins: accounts, agent, executors, API, and replacements. */
  readonly plugins?: readonly PlatformInput[];
}

/**
 * Assemble a company: PAP core, company defaults, then the company's own plugins.
 *
 * The company's plugins contribute at least `pap.company.accounts` and
 * `pap.company.agent`, and one `pap.company.operationExecutor` per action
 * that needs approval; a lower `order` replaces any default.
 */
export function buildCompany(
  config: CompanyConfig,
  options: BuildCompanyOptions = {},
): CompanyService {
  const resolver = new IdentityClientResolver();
  const clock = new ReactorClock();
  const { plugins = [], ...given } = options;
  // On Node the company fetches agents' metadata over its resolving transport: every
  // address vetted, the vetted one dialled (SSRF, DNS rebinding). A given `fetch` is the
  // caller's own (a test network, an egress proxy) and replaces it.
  const core: PapCoreOptions = given.fetch === undefined ? { ...given, fetch: createResolvingFetch() } : given;
  let built: ReactorPlatformView | undefined;
  const store = (): CompanyStore => {
    if (built === undefined) throw new Error("the company's Reactor is not built yet");
    return firstContribution(built, CompanyStores, "company store");
  };
  const directory = new IdentityOperatorDirectory();
  const reactor = buildPapReactor(core, [createCompanyDefaultsPlugin(resolver, clock, store, directory), ...plugins]);
  built = reactor;
  const identity = new AgentIdentityClient({ reactor });
  resolver.bind(identity);
  directory.bind(identity);
  clock.bind(reactor);
  return new CompanyService({ config, reactor });
}

export * from "./points.js";
export * from "./service.js";
export {
  DelegationCache,
  SESSION_JWT_WINDOW_SECONDS,
  unverifiedSessionIssuer,
  verifyAssertion,
  verifyDelegation,
  verifyDpopProof,
  verifySessionJwt,
  type ResolveClient,
  type VerifiedDelegation,
  type VerifiedDpopProof,
  type VerifiedSessionJwt,
  type VerifyAssertionOptions,
  type VerifyDpopProofOptions,
  type VerifySessionJwtOptions,
} from "./verify.js";
export { checkReplayCache, checkStore, recordSamples, StoreConformanceError } from "./testing.js";
export {
  byHost,
  companyRequestListener,
  jsonSite,
  type CompanyRequestListenerOptions,
  type RequestListener,
} from "./node.js";
