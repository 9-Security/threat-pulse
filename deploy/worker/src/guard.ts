/**
 * Decides which submitted values the query service may look up at all.
 *
 * Two promises in `docs/data-handling.md` were specified and not kept, and the
 * reviewers listed both as blockers for an endpoint pilot:
 *
 * - Values past the batch limit were dropped with `.slice(0, MAX_BATCH)`. The
 *   response carried `requested` and `examined`, so a careful caller could notice,
 *   but nothing said *which* values were not looked up. Every one is now returned
 *   in `skipped` with its `input_index` and the reason `request_limit`.
 * - Private addresses and internal hostnames were queried like anything else. A
 *   caller that pasted a log line sent `10.0.0.5` or `dc01.corp` into a lookup
 *   against a corpus of published reporting, where it can never match and where
 *   sending it at all leaks internal structure. Those are now skipped before any
 *   query is built, so they never reach D1.
 *
 * The rules mirror the offline validator the reviewers already hold, so a value
 * skipped there is skipped here, under the same reason code. Kept free of imports
 * and Worker types so node can run its tests directly.
 */

export const MAX_BATCH = 100;
export const MAX_VALUE_LENGTH = 512;
/** DNS allows 127. This bounds how many parent candidates one value can expand to. */
export const MAX_LABELS = 16;

export type SkipReason =
  | "empty_value"
  | "invalid_value"
  | "non_public_ip"
  | "internal_hostname"
  | "sensitive_url"
  | "request_limit";

/** Names an organisation gives its own machines; identical to the offline validator. */
export const INTERNAL_SUFFIXES = [
  ".local",
  ".internal",
  ".corp",
  ".lan",
  ".home.arpa",
  ".localdomain",
  ".intranet",
];

/* ---------------------------------------------------------------- IPv4 --- */

/**
 * The IANA special-purpose ranges that are not globally reachable, plus the shared
 * address space. This is the definition Python's `ipaddress.is_global` uses from
 * 3.12.4 on, which is what the offline validator runs.
 */
const V4_NON_GLOBAL: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["240.0.0.0", 4],
];
/** Inside 192.0.0.0/24 but globally reachable (PCP and TURN anycast). */
const V4_GLOBAL_EXCEPTIONS = new Set(["192.0.0.9", "192.0.0.10"]);

const V4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** The address as an unsigned 32-bit number, or null if it is not a valid dotted quad. */
export function parseIPv4(text: string): number | null {
  const match = V4_RE.exec(text);
  if (!match) return null;
  let value = 0;
  for (let i = 1; i <= 4; i += 1) {
    const part = match[i];
    // A leading zero is ambiguous (octal in some parsers) and Python rejects it.
    if (part.length > 1 && part.startsWith("0")) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    value = value * 256 + octet;
  }
  return value;
}

function v4InRange(address: number, base: string, bits: number): boolean {
  const start = parseIPv4(base)!;
  const size = 2 ** (32 - bits);
  return address >= start && address < start + size;
}

export function isGlobalIPv4(address: number, text: string): boolean {
  if (V4_GLOBAL_EXCEPTIONS.has(text)) return true;
  return !V4_NON_GLOBAL.some(([base, bits]) => v4InRange(address, base, bits));
}

/* ---------------------------------------------------------------- IPv6 --- */

const V6_NON_GLOBAL: Array<[string, number]> = [
  ["::1", 128],
  ["::", 128],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
];
/** Inside 2001::/23 but globally reachable. */
const V6_GLOBAL_EXCEPTIONS: Array<[string, number]> = [
  ["2001:1::1", 128],
  ["2001:1::2", 128],
  ["2001:3::", 32],
  ["2001:4:112::", 48],
  ["2001:20::", 28],
  ["2001:30::", 28],
];

/** The address as a 128-bit bigint, or null if it is not a valid IPv6 literal. */
export function parseIPv6(input: string): bigint | null {
  let text = input;
  const zone = text.indexOf("%");
  if (zone !== -1) text = text.slice(0, zone);
  if (!text.includes(":")) return null;

  // An embedded dotted quad in the last 32 bits, as in ::ffff:10.0.0.1.
  let tail: number[] = [];
  const lastColon = text.lastIndexOf(":");
  const maybeV4 = text.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const v4 = parseIPv4(maybeV4);
    if (v4 === null) return null;
    tail = [Math.floor(v4 / 65536), v4 % 65536];
    text = text.slice(0, lastColon + 1) + "0:0";
  }

  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string): number[] | null => {
    if (part === "") return [];
    const groups = part.split(":");
    const out: number[] = [];
    for (const group of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
      out.push(parseInt(group, 16));
    }
    return out;
  };
  const head = parse(halves[0]);
  const rest = halves.length === 2 ? parse(halves[1]) : [];
  if (head === null || rest === null) return null;

  let groups: number[];
  if (halves.length === 2) {
    const missing = 8 - head.length - rest.length;
    if (missing < 1) return null;
    groups = [...head, ...new Array(missing).fill(0), ...rest];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  if (tail.length) {
    groups[6] = tail[0];
    groups[7] = tail[1];
  }
  return groups.reduce((acc, group) => (acc << 16n) | BigInt(group), 0n);
}

function v6InRange(address: bigint, base: string, bits: number): boolean {
  const start = parseIPv6(base)!;
  const shift = BigInt(128 - bits);
  return address >> shift === start >> shift;
}

export function isGlobalIPv6(address: bigint): boolean {
  // IPv4-mapped (::ffff:0:0/96): the embedded IPv4 address decides.
  if (address >> 32n === 0xffffn) {
    const v4 = Number(address & 0xffffffffn);
    const text = [v4 >>> 24, (v4 >>> 16) & 255, (v4 >>> 8) & 255, v4 & 255].join(".");
    return isGlobalIPv4(v4, text);
  }
  if (V6_GLOBAL_EXCEPTIONS.some(([base, bits]) => v6InRange(address, base, bits))) return true;
  return !V6_NON_GLOBAL.some(([base, bits]) => v6InRange(address, base, bits));
}

/* ------------------------------------------------------------ classify --- */

const HASH_RE = /^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$/i;
const CVE_RE = /^cve-\d{4}-\d{4,7}$/i;
const HOSTNAME_RE = /^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?$/i;

function classifyHost(host: string): SkipReason | null {
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  // Each label becomes a candidate, every 90 candidates a statement, and this
  // account may send 50 statements per request. Without a bound, one value of a
  // few hundred labels would exhaust the call for every other value in it.
  if (host.split(".").length > MAX_LABELS) return "invalid_value";

  const v4 = parseIPv4(host);
  if (v4 !== null) return isGlobalIPv4(v4, host) ? null : "non_public_ip";
  if (V4_RE.test(host)) return "invalid_value";

  if (host.includes(":")) {
    const v6 = parseIPv6(host);
    if (v6 !== null) return isGlobalIPv6(v6) ? null : "non_public_ip";
    // host:port -- classify the host part.
    const portMatch = /^([^:]+):(\d{1,5})$/.exec(host);
    if (portMatch) return classifyHost(portMatch[1]);
    return null;
  }

  if (!HOSTNAME_RE.test(host)) return null;
  const name = host.toLowerCase().replace(/\.$/, "");
  if (!name.includes(".")) return "internal_hostname";
  if (INTERNAL_SUFFIXES.some((suffix) => name.endsWith(suffix))) return "internal_hostname";
  return null;
}

/** Why a value must not be looked up, or null if it may be. */
export function classify(value: string): SkipReason | null {
  if (value === "") return "empty_value";
  if (value.length > MAX_VALUE_LENGTH) return "invalid_value";
  if (/[\s\x00-\x1f\x7f]/.test(value)) return "invalid_value";
  if (HASH_RE.test(value) || CVE_RE.test(value)) return null;
  // Counted over the whole value, not only a URL host: the lookup expands the
  // value as submitted, so a short host followed by a dotted path would otherwise
  // expand past the bound this exists to enforce.
  if (value.split(".").length > MAX_LABELS) return "invalid_value";

  if (value.includes("://")) {
    let url: URL;
    try {
      url = new URL(value);
    } catch {
      return "invalid_value";
    }
    // Credentials in a URL are a secret the caller pasted by accident; they are
    // not needed to match a host and must not be sent to a query.
    if (url.username || url.password) return "sensitive_url";
    return url.hostname ? classifyHost(url.hostname) : "invalid_value";
  }
  return classifyHost(value);
}

/**
 * The same guard for free-text search, applied only where the text is plainly an
 * address, a URL, or a dotted internal name. A single word such as "ransomware" is
 * a search term rather than a hostname, and is not refused.
 */
export function classifySearchText(text: string): SkipReason | null {
  const value = text.trim();
  if (value === "") return null;
  if (value.length > MAX_VALUE_LENGTH) return "invalid_value";
  if (value.includes("://")) return classify(value);
  const v4 = parseIPv4(value);
  if (v4 !== null) return isGlobalIPv4(v4, value) ? null : "non_public_ip";
  if (value.includes(":")) {
    const v6 = parseIPv6(value.replace(/^\[|\]$/g, ""));
    if (v6 !== null) return isGlobalIPv6(v6) ? null : "non_public_ip";
  }
  const name = value.toLowerCase().replace(/\.$/, "");
  if (name.includes(".") && HOSTNAME_RE.test(name) && INTERNAL_SUFFIXES.some((suffix) => name.endsWith(suffix))) {
    return "internal_hostname";
  }
  return null;
}

/* ----------------------------------------------------------- partition --- */

export interface Accepted {
  input_index: number;
  value: string;
}

export interface Skipped {
  input_index: number;
  value: string;
  reason: SkipReason;
}

export interface Partition {
  requested: number;
  accepted: Accepted[];
  skipped: Skipped[];
  /** True when any value was not looked up because the batch was over the limit. */
  truncated: boolean;
}

/**
 * Split a request into the values that may be looked up and the ones that may not,
 * keeping every position. Nothing is dropped: each submitted value appears exactly
 * once, in `accepted` or in `skipped`.
 */
export function partition(values: unknown, maxBatch: number = MAX_BATCH): Partition {
  const list: unknown[] = Array.isArray(values) ? values : [];
  const accepted: Accepted[] = [];
  const skipped: Skipped[] = [];
  list.forEach((raw, index) => {
    if (typeof raw !== "string") {
      skipped.push({ input_index: index, value: "", reason: "invalid_value" });
      return;
    }
    const value = raw.trim();
    if (index >= maxBatch) {
      skipped.push({ input_index: index, value, reason: "request_limit" });
      return;
    }
    const reason = classify(value);
    if (reason) skipped.push({ input_index: index, value, reason });
    else accepted.push({ input_index: index, value });
  });
  return { requested: list.length, accepted, skipped, truncated: list.length > maxBatch };
}
