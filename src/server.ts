/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

import { vetHost, type NodeAddressResolver } from "./node-network.js";
import type { UrlSafetyPolicy } from "./reactor.js";

export {
  JoseSigner,
  verifyDpopProof,
  type DpopReplayCache,
  type JoseSignerOptions,
  type VerifiedDpopProof,
  type VerifyDpopProofOptions,
} from "./crypto.js";
export {
  verifyBrowserAssertion,
  type BrowserAssertionReplayCache,
  type VerifiedBrowserAssertion,
  type VerifyBrowserAssertionOptions,
} from "./browser-server.js";
export * from "./company/index.js";

export { isGlobalAddress } from "./addresses.js";
export {
  createResolvingFetch,
  resolveAddresses,
  vetHost,
  type NodeAddressResolver,
  type ResolvingFetchOptions,
} from "./node-network.js";

export interface NodeUrlSafetyPolicyOptions {
  readonly resolver?: NodeAddressResolver;
  readonly allowPrivateNetworks?: boolean;
}

/**
 * DNS-aware server policy for untrusted PAP discovery and metadata URLs: every address
 * the host resolves to must be global unicast (`isGlobalAddress`). It checks; it does not
 * pin. Pair it with `createResolvingFetch`, which vets again and dials only the vetted
 * address (the Node company's default), so a name that rebinds between the check and
 * the connection still reaches no private address.
 */
export class NodeUrlSafetyPolicy implements UrlSafetyPolicy {
  readonly #resolver: NodeAddressResolver | undefined;
  readonly #allowPrivateNetworks: boolean;

  constructor(options: NodeUrlSafetyPolicyOptions = {}) {
    this.#resolver = options.resolver;
    this.#allowPrivateNetworks = options.allowPrivateNetworks ?? false;
  }

  async assertSafe(url: URL): Promise<void> {
    await vetHost(url, {
      ...(this.#resolver === undefined ? {} : { resolver: this.#resolver }),
      allowPrivateNetworks: this.#allowPrivateNetworks,
    });
  }
}
