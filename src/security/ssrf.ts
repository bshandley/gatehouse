/**
 * SSRF defense helpers shared between the REST proxy and MCP proxy tool.
 *
 * isPrivateHost catches the usual private/reserved ranges AND the tricks
 * attackers use to smuggle them past naive regex checks:
 *   - decimal-encoded IPv4 (e.g. http://2130706433/ == 127.0.0.1)
 *   - octal-encoded IPv4 (e.g. http://0177.0.0.1/)
 *   - hex-encoded IPv4 (e.g. http://0x7f.0.0.1/)
 *   - IPv4-mapped IPv6 (::ffff:10.0.0.1)
 *   - IPv6 loopback / ULA / link-local with zone IDs
 *
 * scrubResponseBody redacts any occurrence of an injected secret from an
 * upstream response body so upstream servers that echo the credential back
 * can't leak it to the caller.
 */

// RFC1918, loopback, link-local, CGN, metadata, carrier-grade NAT
const PRIVATE_V4_REGEXES: RegExp[] = [
  /^0\./,                              // Current network
  /^10\./,                             // RFC 1918
  /^100\.(6[4-9]|[7-9]\d|1[0-2]\d)\./, // RFC 6598 shared address space
  /^127\./,                            // Loopback
  /^169\.254\./,                       // Link-local (incl. metadata 169.254.169.254)
  /^172\.(1[6-9]|2\d|3[01])\./,        // RFC 1918
  /^192\.0\.0\./,                      // IETF Protocol Assignments
  /^192\.0\.2\./,                      // TEST-NET-1
  /^192\.168\./,                       // RFC 1918
  /^198\.1[89]\./,                     // Benchmarking
  /^198\.51\.100\./,                   // TEST-NET-2
  /^203\.0\.113\./,                    // TEST-NET-3
  /^22[4-9]\./,                        // Multicast
  /^23\d\./,                           // Multicast
  /^24\d\./,                           // Reserved
  /^25[0-5]\./,                        // Reserved
];

function isPrivateIPv4(addr: string): boolean {
  return PRIVATE_V4_REGEXES.some((r) => r.test(addr));
}

/**
 * Normalize an IPv4 address written in decimal / octal / hex / mixed notation
 * to dotted decimal. Returns null if the input is not a parseable IPv4.
 *
 * URL.hostname may hand back forms like:
 *   "127.0.0.1"         -> 127.0.0.1
 *   "2130706433"        -> 127.0.0.1
 *   "0x7f000001"        -> 127.0.0.1
 *   "0177.0.0.1"        -> 127.0.0.1
 *   "127.1"             -> 127.0.0.1 (two-part form)
 */
function normalizeIPv4(hostname: string): string | null {
  // Strip enclosing brackets (URL.hostname doesn't, but belt and braces)
  const h = hostname.replace(/^\[|\]$/g, "");

  // Already dotted decimal?
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
    const parts = h.split(".").map(Number);
    if (parts.every((p) => p >= 0 && p <= 255)) return parts.join(".");
    return null;
  }

  // Single-part: decimal, octal (0...), or hex (0x...)
  if (/^(0x[0-9a-f]+|0[0-7]*|\d+)$/i.test(h)) {
    let n: number;
    if (/^0x/i.test(h)) n = parseInt(h, 16);
    else if (/^0[0-7]+$/.test(h)) n = parseInt(h, 8);
    else n = parseInt(h, 10);
    if (!Number.isFinite(n) || n < 0 || n > 0xffffffff) return null;
    return [
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ].join(".");
  }

  // Multi-part mixed forms (e.g. 127.1, 192.168.1)
  const parts = h.split(".");
  if (parts.length >= 2 && parts.length <= 4 && parts.every((p) => /^(0x[0-9a-f]+|0[0-7]*|\d+)$/i.test(p))) {
    const nums = parts.map((p) => {
      if (/^0x/i.test(p)) return parseInt(p, 16);
      if (/^0[0-7]+$/.test(p)) return parseInt(p, 8);
      return parseInt(p, 10);
    });
    // Last part can be larger than 255 in legacy "class" notation
    const last = nums.pop()!;
    if (nums.some((n) => n < 0 || n > 255) || last < 0) return null;
    // Pad with last absorbing the rest
    const pad = 4 - nums.length;
    const absorbed: number[] = [...nums];
    for (let i = pad - 1; i >= 0; i--) {
      absorbed.push((last >>> (i * 8)) & 0xff);
    }
    if (absorbed.length !== 4) return null;
    return absorbed.join(".");
  }

  return null;
}

function isPrivateIPv6(addr: string): boolean {
  // Strip brackets + zone id
  const a = addr.replace(/^\[|\]$/g, "").split("%")[0].toLowerCase();

  // Loopback
  if (a === "::1" || a === "0:0:0:0:0:0:0:1") return true;
  // Unspecified
  if (a === "::" || a === "0:0:0:0:0:0:0:0") return true;
  // Unique local (fc00::/7)
  if (/^f[cd][0-9a-f]{2}:/.test(a)) return true;
  // Link-local (fe80::/10)
  if (/^fe[89ab][0-9a-f]?:/.test(a)) return true;
  // IPv4-mapped (::ffff:a.b.c.d or ::ffff:hhhh:hhhh)
  const mappedDotted = a.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mappedDotted) {
    const v4 = normalizeIPv4(mappedDotted[1]);
    if (v4 && isPrivateIPv4(v4)) return true;
  }
  const mappedHex = a.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16);
    const lo = parseInt(mappedHex[2], 16);
    const v4 = [
      (hi >>> 8) & 0xff,
      hi & 0xff,
      (lo >>> 8) & 0xff,
      lo & 0xff,
    ].join(".");
    if (isPrivateIPv4(v4)) return true;
  }
  // IPv4-compatible ::a.b.c.d
  const compat = a.match(/^::(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (compat) {
    const v4 = normalizeIPv4(compat[1]);
    if (v4 && isPrivateIPv4(v4)) return true;
  }
  return false;
}

/**
 * Block requests to private/reserved addresses to prevent SSRF.
 * Accepts the raw hostname from URL.hostname (no scheme/port).
 * Handles decimal, octal, hex, and mixed IPv4 encodings plus IPv6.
 */
export function isPrivateHost(hostname: string): boolean {
  if (!hostname) return true;
  const h = hostname.toLowerCase();

  // Obvious DNS names
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".local")) return true;
  // AWS/GCE/Azure metadata DNS
  if (h === "metadata.google.internal") return true;
  if (h === "metadata" || h === "metadata.internal") return true;

  // IPv6 literals
  if (h.includes(":")) {
    return isPrivateIPv6(h);
  }

  // IPv4 - try to normalize alternative encodings to dotted decimal
  const v4 = normalizeIPv4(h);
  if (v4) return isPrivateIPv4(v4);

  // Couldn't parse as IP - assume it's a DNS name and allow (domain
  // allowlisting + DNS pinning is the next layer of defense).
  return false;
}

/**
 * Replace every occurrence of an injected secret value in a response body
 * with "[REDACTED]". This defeats naive upstream echo ("your token is X").
 *
 * We intentionally skip values shorter than 8 chars to avoid mangling
 * arbitrary substrings, and skip values that are all-whitespace or empty.
 */
export function scrubResponseBody(body: string, secretValues: Iterable<string>): string {
  let out = body;
  for (const v of secretValues) {
    if (!v || v.length < 8) continue;
    // Split+join is the fastest safe "replace all literal" in JS.
    if (out.includes(v)) {
      out = out.split(v).join("[REDACTED]");
    }
  }
  return out;
}

/** Maximum upstream response body size the proxy will buffer (bytes). */
export const MAX_UPSTREAM_BODY_BYTES = 10 * 1024 * 1024; // 10 MiB

/**
 * Read an upstream Response's body as text but cap at maxBytes. Throws
 * an Error tagged with `code = "BODY_TOO_LARGE"` if the limit is hit.
 */
export async function readCappedText(
  resp: Response,
  maxBytes: number = MAX_UPSTREAM_BODY_BYTES
): Promise<string> {
  // Fast-path: if Content-Length is present and over the cap, reject immediately.
  const cl = resp.headers.get("content-length");
  if (cl) {
    const n = parseInt(cl, 10);
    if (Number.isFinite(n) && n > maxBytes) {
      const e = new Error(`Upstream response exceeds ${maxBytes} bytes`);
      (e as any).code = "BODY_TOO_LARGE";
      throw e;
    }
  }

  if (!resp.body) return "";
  const reader = resp.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch { /* ignore */ }
        const e = new Error(`Upstream response exceeds ${maxBytes} bytes`);
        (e as any).code = "BODY_TOO_LARGE";
        throw e;
      }
      chunks.push(value);
    }
  }
  // Concatenate and decode as UTF-8
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(merged);
}
