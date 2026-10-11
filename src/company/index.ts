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

import { contribution, definePlugin, type PlatformInput } from "@datalayer/reactor";

import { AgentIdentityClient } from "../identity.js";
import type { ClientMetadata, JsonWebKeySet } from "../models.js";
import { buildPapReactor, type PapCoreOptions } from "../reactor.js";
import {
  AllowEveryAgent,
  ClientPolicies,
  ClientResolvers,
  CompanyAccounts,
  CompanyAgents,
  CompanyApis,
  CompanyStores,
  MemoryCompanyStore,
  MemoryReplayCache,
  OperationExecutors,
  ReplayCaches,
  type ClientResolver,
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

  async resolve(clientId: string): Promise<readonly [ClientMetadata, JsonWebKeySet]> {
    const identity = this.#identity;
    if (identity === undefined) throw new Error("IdentityClientResolver is not bound");
    return [await identity.fetchMetadata(clientId), await identity.fetchJwks(clientId)];
  }
}

/** The company side's defaults: memory store and replay cache, open policy, HTTPS identity. */
export function createCompanyDefaultsPlugin(resolver: ClientResolver) {
  return definePlugin({
    name: "personal-agent-protocol.company",
    version: "0.3.3",
    contributionPoints: [
      CompanyStores,
      CompanyAccounts,
      CompanyAgents,
      CompanyApis,
      OperationExecutors,
      ClientPolicies,
      ClientResolvers,
      ReplayCaches,
    ],
    contributes: [
      contribution(CompanyStores, new MemoryCompanyStore(), { id: "memory", order: 100 }),
      contribution(ReplayCaches, new MemoryReplayCache(), { id: "memory", order: 100 }),
      contribution(ClientPolicies, new AllowEveryAgent(), { id: "allow", order: 100 }),
      contribution(ClientResolvers, resolver, { id: "https", order: 100 }),
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
 * its agent proposes; a lower `order` replaces any default.
 */
export function buildCompany(
  config: CompanyConfig,
  options: BuildCompanyOptions = {},
): CompanyService {
  const resolver = new IdentityClientResolver();
  const { plugins = [], ...core } = options;
  const reactor = buildPapReactor(core, [createCompanyDefaultsPlugin(resolver), ...plugins]);
  resolver.bind(new AgentIdentityClient({ reactor }));
  return new CompanyService({ config, reactor });
}

export * from "./points.js";
export * from "./service.js";
export { verifyAssertion, type VerifyAssertionOptions } from "./verify.js";
export {
  byHost,
  companyRequestListener,
  jsonSite,
  type CompanyRequestListenerOptions,
  type RequestListener,
} from "./node.js";
