/**
 * CIDR allowlist matching for AppRole IP restrictions.
 *
 * Supports IPv4 and IPv6 CIDRs. A plain IP literal is treated as /32 (IPv4)
 * or /128 (IPv6). Returns true if ip is within any CIDR in the list. An empty
 * or null list means "no restriction" (handled by callers).
 */

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const x = Number(p);
    if (!Number.isInteger(x) || x < 0 || x > 255) return null;
    n = (n * 256) + x;
  }
  return n >>> 0;
}

function ipv6ToBytes(ip: string): Uint8Array | null {
  // Expand :: shorthand
  let s = ip.toLowerCase();
  // Strip zone id
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);

  let head: string[];
  let tail: string[];
  if (s.includes("::")) {
    const [h, t] = s.split("::", 2);
    head = h ? h.split(":") : [];
    tail = t ? t.split(":") : [];
  } else {
    head = s.split(":");
    tail = [];
  }
  const totalFilled = head.length + tail.length;
  if (totalFilled > 8) return null;
  const zeros = new Array(8 - totalFilled).fill("0");
  const groups = [...head, ...zeros, ...tail];
  if (groups.length !== 8) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i];
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    bytes[i * 2] = (v >> 8) & 0xff;
    bytes[i * 2 + 1] = v & 0xff;
  }
  return bytes;
}

function cidrMatchV4(ip: number, cidr: string): boolean {
  const [net, lenStr] = cidr.split("/");
  const netInt = ipv4ToInt(net!);
  if (netInt === null) return false;
  const len = lenStr === undefined ? 32 : Number(lenStr);
  if (!Number.isInteger(len) || len < 0 || len > 32) return false;
  if (len === 0) return true;
  const mask = (~0 << (32 - len)) >>> 0;
  return (ip & mask) === (netInt & mask);
}

function cidrMatchV6(ip: Uint8Array, cidr: string): boolean {
  const [net, lenStr] = cidr.split("/");
  const netBytes = ipv6ToBytes(net!);
  if (!netBytes) return false;
  const len = lenStr === undefined ? 128 : Number(lenStr);
  if (!Number.isInteger(len) || len < 0 || len > 128) return false;
  const fullBytes = Math.floor(len / 8);
  const remBits = len % 8;
  for (let i = 0; i < fullBytes; i++) {
    if (ip[i] !== netBytes[i]) return false;
  }
  if (remBits) {
    const mask = (0xff << (8 - remBits)) & 0xff;
    if ((ip[fullBytes] & mask) !== (netBytes[fullBytes] & mask)) return false;
  }
  return true;
}

export function ipMatchesAllowlist(ip: string, allowlist: string[]): boolean {
  if (!allowlist || allowlist.length === 0) return true;
  // Strip IPv4-mapped IPv6 prefix
  let normalized = ip;
  if (normalized.startsWith("::ffff:")) normalized = normalized.slice(7);

  const v4 = ipv4ToInt(normalized);
  const v6 = v4 === null ? ipv6ToBytes(normalized) : null;

  for (const raw of allowlist) {
    const cidr = raw.trim();
    if (!cidr) continue;
    const isV4 = cidr.includes(".");
    if (isV4 && v4 !== null && cidrMatchV4(v4, cidr)) return true;
    if (!isV4 && v6 && cidrMatchV6(v6, cidr)) return true;
  }
  return false;
}

/**
 * Validate a list of CIDR strings for storage. Returns null on success, or an
 * error message describing the first invalid entry.
 */
export function validateCIDRs(list: string[]): string | null {
  for (const raw of list) {
    const cidr = raw.trim();
    if (!cidr) continue;
    const [net, lenStr] = cidr.split("/");
    const isV4 = net?.includes(".");
    if (isV4) {
      if (ipv4ToInt(net!) === null) return `invalid IPv4 address: ${cidr}`;
      if (lenStr !== undefined) {
        const len = Number(lenStr);
        if (!Number.isInteger(len) || len < 0 || len > 32) return `invalid prefix length: ${cidr}`;
      }
    } else {
      if (!ipv6ToBytes(net!)) return `invalid IPv6 address: ${cidr}`;
      if (lenStr !== undefined) {
        const len = Number(lenStr);
        if (!Number.isInteger(len) || len < 0 || len > 128) return `invalid prefix length: ${cidr}`;
      }
    }
  }
  return null;
}
