/*
 * Copyright (c) 2025-2026 Datalayer, Inc.
 *
 * BSD 3-Clause License
 */

// Which IP addresses a PAP fetch may reach: only global unicast ones. Portable (no Node
// APIs): the textual URL check in every runtime, and the resolving transport on Node.

/** The four octets of a dotted-quad IPv4 address, or `undefined`. */
function ipv4Octets(text: string): number[] | undefined {
  const parts = text.split(".");
  if (parts.length !== 4) return undefined;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^(0|[1-9]\d{0,2})$/.test(part)) return undefined;
    const value = Number(part);
    if (value > 255) return undefined;
    octets.push(value);
  }
  return octets;
}

/** The eight 16-bit groups of an IPv6 address (`::` and a dotted IPv4 tail allowed). */
function ipv6Groups(text: string): number[] | undefined {
  if (text.includes("%")) return undefined; // a zone: link-local, never global
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const parse = (part: string, final: boolean): number[] | undefined => {
    if (part === "") return [];
    const items = part.split(":");
    const groups: number[] = [];
    for (const [index, item] of items.entries()) {
      if (final && index === items.length - 1 && item.includes(".")) {
        const octets = ipv4Octets(item);
        if (octets === undefined) return undefined;
        groups.push((octets[0]! << 8) | octets[1]!, (octets[2]! << 8) | octets[3]!);
        continue;
      }
      if (!/^[0-9a-fA-F]{1,4}$/.test(item)) return undefined;
      groups.push(Number.parseInt(item, 16));
    }
    return groups;
  };
  const left = parse(halves[0] ?? "", halves.length === 1);
  const right = halves.length === 2 ? parse(halves[1] ?? "", true) : [];
  if (left === undefined || right === undefined) return undefined;
  if (halves.length === 1) return left.length === 8 ? left : undefined;
  const missing = 8 - left.length - right.length;
  if (missing < 1) return undefined;
  return [...left, ...Array<number>(missing).fill(0), ...right];
}

function inV4(octets: readonly number[], network: readonly number[], bits: number): boolean {
  for (let bit = 0; bit < bits; bit += 1) {
    const index = bit >> 3;
    const mask = 0x80 >> (bit & 7);
    if (((octets[index] ?? 0) & mask) !== ((network[index] ?? 0) & mask)) return false;
  }
  return true;
}

/** IPv4 ranges that are not global unicast (IANA special-purpose registry, and more). */
const V4_NOT_GLOBAL: readonly (readonly [readonly number[], number])[] = [
  [[0, 0, 0, 0], 8], // "this network", 0.0.0.0
  [[10, 0, 0, 0], 8], // private
  [[100, 64, 0, 0], 10], // shared address space (CGNAT), 100.100.100.200 metadata
  [[127, 0, 0, 0], 8], // loopback
  [[169, 254, 0, 0], 16], // link-local, 169.254.169.254 metadata
  [[172, 16, 0, 0], 12], // private
  [[192, 0, 0, 0], 24], // IETF protocol assignments
  [[192, 0, 2, 0], 24], // documentation
  [[192, 31, 196, 0], 24], // AS112
  [[192, 52, 193, 0], 24], // AMT
  [[192, 88, 99, 0], 24], // deprecated 6to4 relay anycast
  [[192, 168, 0, 0], 16], // private
  [[192, 175, 48, 0], 24], // direct delegation AS112
  [[198, 18, 0, 0], 15], // benchmarking
  [[198, 51, 100, 0], 24], // documentation
  [[203, 0, 113, 0], 24], // documentation
  [[224, 0, 0, 0], 4], // multicast
  [[240, 0, 0, 0], 4], // reserved, and 255.255.255.255
];

function isGlobalV4(octets: readonly number[]): boolean {
  return !V4_NOT_GLOBAL.some(([network, bits]) => inV4(octets, network, bits));
}

function v4From(high: number, low: number): number[] {
  return [high >> 8, high & 0xff, low >> 8, low & 0xff];
}

function isGlobalV6(groups: readonly number[]): boolean {
  const [g0 = 0, g1 = 0, g2 = 0, g3 = 0, g4 = 0, g5 = 0, g6 = 0, g7 = 0] = groups;
  const zeroTo = (count: number) => groups.slice(0, count).every((group) => group === 0);
  // An IPv4 address carried in IPv6 is judged as that IPv4 address: IPv4-mapped
  // (::ffff:0:0/96), IPv4-compatible (::/96, `::` and `::1` included), NAT64 (64:ff9b::/96).
  if (zeroTo(5) && g5 === 0xffff) return isGlobalV4(v4From(g6, g7));
  if (zeroTo(6)) return isGlobalV4(v4From(g6, g7));
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
    return isGlobalV4(v4From(g6, g7));
  }
  // 6to4 (2002::/16) carries an IPv4 address in its next 32 bits.
  if (g0 === 0x2002) return isGlobalV4(v4From(g1, g2));
  // Local-use NAT64 (64:ff9b:1::/48): whatever its operator translates it to.
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 1) return false;
  // Only global unicast (2000::/3) can be global: this excludes ULA (fc00::/7, so
  // fd00:ec2::254), link-local (fe80::/10), site-local, multicast (ff00::/8), and ::/8.
  if (g0 < 0x2000 || g0 > 0x3fff) return false;
  if (g0 === 0x2001) {
    if (g1 < 0x0200) return false; // IETF protocol assignments: Teredo, ORCHID, benchmarking
    if (g1 === 0x0db8) return false; // documentation
  }
  if (g0 === 0x3fff && g1 < 0x1000) return false; // documentation (3fff::/20)
  return true;
}

/**
 * Whether a textual IP address is global unicast: never loopback, private, link-local,
 * shared (CGNAT), multicast, documentation, or reserved, and an IPv4 address carried in
 * IPv6 (mapped, compatible, NAT64, 6to4) judged as that IPv4 address. Anything that is
 * not an IP address is `false`.
 */
export function isGlobalAddress(address: string): boolean {
  const text = address.startsWith("[") && address.endsWith("]") ? address.slice(1, -1) : address;
  const octets = ipv4Octets(text);
  if (octets !== undefined) return isGlobalV4(octets);
  const groups = ipv6Groups(text);
  return groups !== undefined && isGlobalV6(groups);
}

/** The IP address a URL hostname names literally (`[…]` removed), or `undefined` for a name. */
export function literalAddress(hostname: string): string | undefined {
  const text = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  return ipv4Octets(text) !== undefined || ipv6Groups(text) !== undefined ? text : undefined;
}
