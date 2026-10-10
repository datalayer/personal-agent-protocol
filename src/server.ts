import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import { DiscoveryError } from "./index.js";
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

export type NodeAddressResolver = (hostname: string) => Promise<readonly string[]>;

async function resolveAddresses(hostname: string): Promise<readonly string[]> {
  try {
    const records = await lookup(hostname, { all: true, verbatim: true });
    return [...new Set(records.map((record) => record.address))];
  } catch (cause) {
    throw new DiscoveryError("dns_failed", "Could not resolve metadata host", { cause });
  }
}

function isPublicIpv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false;
  }
  const [a = 0, b = 0] = parts;
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && parts[2] === 2) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && parts[2] === 100) ||
    (a === 203 && b === 0 && parts[2] === 113) ||
    a >= 224
  );
}

function isPublicIpv6(address: string): boolean {
  const normalized = address.toLowerCase();
  if (normalized.includes("%") || normalized.startsWith("2001:db8:")) return false;
  if (normalized.startsWith("2001:0:") || normalized.startsWith("2002:")) return false;
  const first = Number.parseInt(normalized.split(":", 1)[0] ?? "", 16);
  return first >= 0x2000 && first <= 0x3fff;
}

export function isPublicIpAddress(address: string): boolean {
  const version = isIP(address);
  if (version === 4) return isPublicIpv4(address);
  if (version === 6) return isPublicIpv6(address);
  return false;
}

export interface NodeUrlSafetyPolicyOptions {
  readonly resolver?: NodeAddressResolver;
  readonly allowPrivateNetworks?: boolean;
}

/** DNS-aware server policy for untrusted PAP discovery and metadata URLs. */
export class NodeUrlSafetyPolicy implements UrlSafetyPolicy {
  readonly #resolver: NodeAddressResolver;
  readonly #allowPrivateNetworks: boolean;

  constructor(options: NodeUrlSafetyPolicyOptions = {}) {
    this.#resolver = options.resolver ?? resolveAddresses;
    this.#allowPrivateNetworks = options.allowPrivateNetworks ?? false;
  }

  async assertSafe(url: URL): Promise<void> {
    if (url.protocol !== "https:" || url.username || url.password) {
      throw new DiscoveryError(
        "unsafe_url",
        "Discovery and metadata URLs must use HTTPS without user information",
      );
    }
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    const addresses = isIP(hostname) ? [hostname] : await this.#resolver(hostname);
    if (addresses.length === 0) {
      throw new DiscoveryError("dns_failed", "Metadata host has no addresses");
    }
    if (!this.#allowPrivateNetworks && addresses.some((address) => !isPublicIpAddress(address))) {
      throw new DiscoveryError(
        "unsafe_address",
        "Metadata host resolves to a non-public address",
      );
    }
  }
}
