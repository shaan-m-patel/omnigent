// Allowlist for AGENT-driven browser navigation (the URL-bar path stays
// permissive — it's a user gesture). A model-issued load can point the
// embedded browser at file://, loopback, RFC1918, CGNAT, or cloud metadata
// and read the response back via screenshot. The string check rejects
// non-http(s) schemes and non-global literals; hostnames are resolved and
// pinned separately so a DNS rebinding answer cannot be what Chromium dials.
// Runs in the main process. No Electron imports, so `node --test` can drive it.

"use strict";

// Schemes the agent may navigate to. file:, chrome:, data:, javascript:, and
// the rest are privileged surfaces or code channels.
const ALLOWED_SCHEMES = new Set(["http:", "https:"]);

// Azure WireServer. Globally routable on paper, but Azure only routes it
// inside the tenant. Same /32 the egress proxy lists in _CLOUD_TRAP_NETWORKS.
const CLOUD_TRAP_IPV4 = ["168.63.129.16", 32];

// IPv4 ranges that are not globally routable (Python 3.12 ipaddress
// IPv4Address.is_global is false), plus multicast (is_global stays true)
// and the cloud-trap address above. 192.0.0.9/32 and 192.0.0.10/32 are
// carved back out — Python treats those two as global.
const IPV4_BLOCKED = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // CGNAT / RFC 6598, includes Alibaba IMDS 100.100.100.200
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4],
  CLOUD_TRAP_IPV4,
];

const IPV4_GLOBAL_EXCEPTIONS = [
  ["192.0.0.9", 32],
  ["192.0.0.10", 32],
];

/**
 * Parse a dotted-quad IPv4 host into four octets, or null. The WHATWG URL
 * parser already canonicalizes obfuscated forms (`0x7f000001`, `2130706433`)
 * to dotted-decimal before this runs.
 *
 * @param {string} host
 * @returns {[number, number, number, number] | null}
 */
function parseIpv4(host) {
  const parts = host.split(".");
  if (parts.length !== 4) return null;
  const octets = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    octets.push(n);
  }
  return /** @type {[number, number, number, number]} */ (octets);
}

/**
 * @param {[number, number, number, number]} octets
 * @returns {number}
 */
function ipv4ToInt(octets) {
  return ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
}

/**
 * @param {number} ip
 * @param {number} base
 * @param {number} prefixLen
 */
function ipv4InCidr(ip, base, prefixLen) {
  const mask = prefixLen === 0 ? 0 : (0xffffffff << (32 - prefixLen)) >>> 0;
  return (ip & mask) === (base & mask);
}

const IPV4_BLOCKED_INTS = IPV4_BLOCKED.map(([addr, len]) => [ipv4ToInt(parseIpv4(addr)), len]);
const IPV4_EXCEPTION_INTS = IPV4_GLOBAL_EXCEPTIONS.map(([addr, len]) => [
  ipv4ToInt(parseIpv4(addr)),
  len,
]);
const CLOUD_TRAP_INT = ipv4ToInt(parseIpv4(CLOUD_TRAP_IPV4[0]));

/**
 * True when the octets are not globally routable, multicast, or a cloud trap.
 *
 * @param {[number, number, number, number]} octets
 */
function isBlockedIpv4(octets) {
  const ip = ipv4ToInt(octets);
  for (const [base, len] of IPV4_EXCEPTION_INTS) {
    if (ipv4InCidr(ip, base, len)) return false;
  }
  for (const [base, len] of IPV4_BLOCKED_INTS) {
    if (ipv4InCidr(ip, base, len)) return true;
  }
  return false;
}

/**
 * @param {[number, number, number, number]} octets
 * @returns {"cloud-internal endpoint" | "multicast address" | "non-public address" | null}
 */
function ipv4BlockReason(octets) {
  if (!isBlockedIpv4(octets)) return null;
  if (ipv4ToInt(octets) === CLOUD_TRAP_INT) return "cloud-internal endpoint";
  const [a] = octets;
  if (a >= 224 && a <= 239) return "multicast address";
  return "non-public address";
}

/**
 * Parse an IPv6 literal to a 128-bit integer, or null. Accepts bracketed
 * hosts, a trailing zone id (`fe80::1%eth0`), and a dotted IPv4 tail.
 *
 * @param {string} input
 * @returns {bigint | null}
 */
function parseIpv6(input) {
  if (typeof input !== "string") return null;
  let host = input.trim().toLowerCase();
  if (host.startsWith("[")) {
    if (!host.endsWith("]")) return null;
    host = host.slice(1, -1);
  }
  const zone = host.indexOf("%");
  if (zone !== -1) host = host.slice(0, zone);
  if (host.length === 0) return null;

  // Fold a dotted IPv4 tail into two hex groups so the rest of the parser
  // only deals with hextets. URL parsing usually does this already; DNS
  // answers and hand-rolled literals still show up dotted.
  if (host.includes(".")) {
    const colon = host.lastIndexOf(":");
    if (colon === -1) return null;
    const octets = parseIpv4(host.slice(colon + 1));
    if (!octets) return null;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    // The colon we sliced off is the separator before the IPv4 tail, so put
    // it back between the head and the two hextets (`::ffff` + tail → `::ffff:7f00:1`).
    host = `${host.slice(0, colon)}:${hi}:${lo}`;
  }

  if (host.includes(":::")) return null;
  const compression = host.indexOf("::");
  if (compression !== -1 && host.indexOf("::", compression + 2) !== -1) return null;

  /** @type {string[]} */
  let groups;
  if (compression === -1) {
    groups = host.split(":");
    if (groups.length !== 8) return null;
  } else {
    const left = host.slice(0, compression);
    const right = host.slice(compression + 2);
    const leftGroups = left === "" ? [] : left.split(":");
    const rightGroups = right === "" ? [] : right.split(":");
    if (leftGroups.length + rightGroups.length > 7) return null;
    const fill = 8 - leftGroups.length - rightGroups.length;
    groups = [...leftGroups, ...Array(fill).fill("0"), ...rightGroups];
  }
  if (groups.length !== 8) return null;

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(group)) return null;
    value = (value << 16n) | BigInt(parseInt(group, 16));
  }
  return value;
}

/**
 * @param {bigint} addr
 * @param {bigint} network
 * @param {number} prefixLen
 */
function ipv6InPrefix(addr, network, prefixLen) {
  if (prefixLen <= 0) return true;
  const shift = BigInt(128 - prefixLen);
  return addr >> shift === network >> shift;
}

// Not-globally-routable IPv6 (Python 3.12 IPv6Address.is_private), plus
// multicast and deprecated site-local. IPv4-mapped and well-known NAT64
// addresses are judged by the embedded IPv4 instead of these prefixes.
const IPV6_BLOCKED_TEXT = [
  ["::", 96], // deprecated IPv4-compatible range, including :: and ::1
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["fec0::", 10], // deprecated site-local
  ["ff00::", 8], // multicast
];

// Python's is_global exceptions inside 2001::/23.
const IPV6_EXCEPTION_TEXT = [
  ["2001:1::1", 128],
  ["2001:1::2", 128],
  ["2001:3::", 32],
  ["2001:4:112::", 48],
  ["2001:20::", 28],
  ["2001:30::", 28],
];

const IPV6_BLOCKED = IPV6_BLOCKED_TEXT.map(([addr, len]) => [parseIpv6(addr), len]);
const IPV6_EXCEPTIONS = IPV6_EXCEPTION_TEXT.map(([addr, len]) => [parseIpv6(addr), len]);
const IPV4_MAPPED_PREFIX = parseIpv6("::ffff:0:0");
const NAT64_PREFIX = parseIpv6("64:ff9b::");

/**
 * @param {bigint} addr
 * @returns {"cloud-internal endpoint" | "multicast address" | "non-public address" | null}
 */
function ipv6BlockReason(addr) {
  // IPv4-mapped (::ffff:0:0/96) and well-known NAT64 (64:ff9b::/96) carry an
  // IPv4 in the low 32 bits. Python's IPv6 is_global reports CGNAT-mapped
  // addresses as global; judge the embedded IPv4 instead.
  if (ipv6InPrefix(addr, IPV4_MAPPED_PREFIX, 96) || ipv6InPrefix(addr, NAT64_PREFIX, 96)) {
    const v4 = Number(addr & 0xffffffffn);
    const octets = [(v4 >>> 24) & 255, (v4 >>> 16) & 255, (v4 >>> 8) & 255, v4 & 255];
    return ipv4BlockReason(octets);
  }
  for (const [network, len] of IPV6_EXCEPTIONS) {
    if (ipv6InPrefix(addr, network, len)) return null;
  }
  for (const [network, len] of IPV6_BLOCKED) {
    if (ipv6InPrefix(addr, network, len)) {
      if (ipv6InPrefix(addr, parseIpv6("ff00::"), 8)) return "multicast address";
      return "non-public address";
    }
  }
  return null;
}

/**
 * Strip URL brackets, a zone id, and a trailing DNS root dot.
 *
 * @param {string} hostname
 */
function bareHost(hostname) {
  let host = String(hostname || "")
    .trim()
    .toLowerCase();
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  const zone = host.indexOf("%");
  if (zone !== -1) host = host.slice(0, zone);
  while (host.endsWith(".")) host = host.slice(0, -1);
  return host;
}

/**
 * @param {string} bare
 */
function isLoopbackName(bare) {
  return bare === "" || bare === "localhost" || bare.endsWith(".localhost");
}

/**
 * True for a loopback name or a literal address the agent may not dial.
 * Non-literal hostnames return false — those are decided after DNS.
 *
 * @param {string} hostname
 */
function isBlockedHostname(hostname) {
  const bare = bareHost(hostname);
  if (isLoopbackName(bare)) return true;
  return assessIp(bare).ok === false && (parseIpv4(bare) !== null || parseIpv6(bare) !== null);
}

/**
 * Classify a literal IP. Unparseable input is rejected (fail closed) only
 * when the caller already believes it is an address; use `assessIp` for
 * that. A hostname that is not an IP returns `{ ok: true, literal: false }`.
 *
 * @param {string} ip
 * @returns {{ ok: true, literal: boolean } | { ok: false, error: string, literal: true }}
 */
function assessIp(ip) {
  const bare = bareHost(ip);
  const v4 = parseIpv4(bare);
  if (v4) {
    const reason = ipv4BlockReason(v4);
    if (reason) {
      return {
        ok: false,
        literal: true,
        error: `navigation blocked: host "${bare}" is a ${reason}`,
      };
    }
    return { ok: true, literal: true };
  }
  const v6 = parseIpv6(bare);
  if (v6 !== null) {
    const reason = ipv6BlockReason(v6);
    if (reason) {
      return {
        ok: false,
        literal: true,
        error: `navigation blocked: host "${bare}" is a ${reason}`,
      };
    }
    return { ok: true, literal: true };
  }
  return { ok: true, literal: false };
}

/**
 * Decide whether an AGENT-issued navigation to `url` is allowed from the
 * URL string alone: `{ ok: true }` for an http(s) URL whose host is not a
 * blocked literal or loopback name. Hostnames still need
 * `resolveAgentNavigation` before a connection is opened.
 *
 * @param {string} url
 * @returns {{ ok: true } | { ok: false, error: string }}
 */
function isAgentNavigationAllowed(url) {
  if (typeof url !== "string" || url.trim() === "") {
    return { ok: false, error: "navigation blocked: empty url" };
  }
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { ok: false, error: `navigation blocked: not a valid absolute URL: ${url}` };
  }
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    return {
      ok: false,
      error: `navigation blocked: scheme "${parsed.protocol}" is not allowed for agent navigation (only http/https)`,
    };
  }
  const bare = bareHost(parsed.hostname);
  if (isLoopbackName(bare)) {
    return {
      ok: false,
      error: `navigation blocked: host "${parsed.hostname}" is a loopback/internal host`,
    };
  }
  const address = assessIp(bare);
  if (address.literal && !address.ok) return { ok: false, error: address.error };
  return { ok: true };
}

/**
 * String-check `url`, resolve a hostname once, and return the address the
 * caller must connect to. Any non-global, multicast, or cloud-trap answer
 * fails the whole lookup (a mixed public/private list is not usable). DNS
 * errors fail closed. IP literals are not resolved again.
 *
 * @param {string} url
 * @param {(hostname: string) => Promise<Array<{ address: string } | string>>} lookup
 * @returns {Promise<{ ok: true, pinnedAddress: string } | { ok: false, error: string }>}
 */
async function resolveAgentNavigation(url, lookup) {
  const syncVerdict = isAgentNavigationAllowed(url);
  if (!syncVerdict.ok) return syncVerdict;
  const bare = bareHost(new URL(url).hostname);
  const literal = assessIp(bare);
  if (literal.literal) {
    if (!literal.ok) return { ok: false, error: literal.error };
    return { ok: true, pinnedAddress: bare };
  }
  if (typeof lookup !== "function") {
    return { ok: false, error: "navigation blocked: DNS resolver unavailable" };
  }
  /** @type {Array<{ address: string } | string>} */
  let records;
  try {
    records = await lookup(bare);
  } catch {
    return {
      ok: false,
      error: `navigation blocked: DNS resolution failed for host "${bare}"`,
    };
  }
  if (!Array.isArray(records) || records.length === 0) {
    return {
      ok: false,
      error: `navigation blocked: host "${bare}" resolved to no address`,
    };
  }
  let pinned = null;
  for (const record of records) {
    const address = bareHost(typeof record === "string" ? record : record && record.address);
    const verdict = assessIp(address);
    if (!verdict.literal || !verdict.ok) {
      return {
        ok: false,
        error: `navigation blocked: host "${bare}" resolves to blocked address ${address || "(empty)"}`,
      };
    }
    if (pinned === null) pinned = address;
  }
  return { ok: true, pinnedAddress: /** @type {string} */ (pinned) };
}

module.exports = {
  isAgentNavigationAllowed,
  resolveAgentNavigation,
  assessIp,
  parseIpv4,
  parseIpv6,
  isBlockedIpv4,
  isBlockedHostname,
  bareHost,
  ALLOWED_SCHEMES,
};
