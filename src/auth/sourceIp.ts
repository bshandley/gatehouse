/**
 * Trusted-proxy aware source-IP resolution.
 *
 * The source IP drives every network-origin security decision in Gatehouse:
 * AppRole IP allowlists, the rotate-token IP allowlist, and the lease/proxy
 * `auto_approve_from_ip` gate. None of those decisions may be steerable by a
 * client-supplied header. We therefore honor `X-Forwarded-For` / `X-Real-IP`
 * only when the request's immediate TCP peer is itself a trusted reverse
 * proxy. Otherwise the real socket address wins and a spoofed header is ignored.
 */
import { ipMatchesAllowlist } from "./cidr";

/**
 * Loopback is always trusted as a proxy hop. A reverse proxy colocated on the
 * same host (the common single-container topology) reaches Gatehouse over
 * 127.0.0.1 / ::1, and anyone who can already originate from loopback has local
 * access regardless. Operators add their own proxy CIDRs (e.g. the Docker
 * network gateway or a LAN reverse proxy) via GATEHOUSE_TRUSTED_PROXIES.
 */
export const DEFAULT_TRUSTED_PROXIES = ["127.0.0.0/8", "::1/128"];

/** Parse GATEHOUSE_TRUSTED_PROXIES, always seeding the loopback defaults. */
export function parseTrustedProxies(env: string | undefined | null): string[] {
  const extra = (env || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return [...DEFAULT_TRUSTED_PROXIES, ...extra];
}

function stripMapped(ip: string): string {
  const trimmed = ip.trim();
  return trimmed.startsWith("::ffff:") ? trimmed.slice(7) : trimmed;
}

export interface ResolveSourceIpInput {
  /** Immediate TCP peer address from the connection (getConnInfo). */
  socketIp: string | null | undefined;
  /** Raw X-Forwarded-For header value, if any. */
  forwardedFor?: string | null;
  /** Raw X-Real-IP header value, if any. */
  realIp?: string | null;
  /** Trusted-proxy CIDR list (already seeded with the loopback defaults). */
  trustedProxies: string[];
}

/**
 * Resolve the effective client IP. Forwarded headers are honored only when the
 * socket peer is a trusted proxy; otherwise the socket address is authoritative
 * and any forwarded header is ignored. Returns "unknown" when no address can be
 * determined.
 */
export function resolveSourceIp(input: ResolveSourceIpInput): string {
  const socket = input.socketIp ? stripMapped(input.socketIp) : "";
  const peerTrusted =
    socket !== "" && ipMatchesAllowlist(socket, input.trustedProxies);

  // Untrusted (or unknown) peer: never trust forwarded headers.
  if (!peerTrusted) {
    return socket || "unknown";
  }

  // Trusted proxy: walk the X-Forwarded-For chain right-to-left and return the
  // first hop that is not itself a trusted proxy. That hop is the real client,
  // because every proxy appends the address it received the request from.
  if (input.forwardedFor) {
    const chain = input.forwardedFor
      .split(",")
      .map(stripMapped)
      .filter(Boolean);
    for (let i = chain.length - 1; i >= 0; i--) {
      const hop = chain[i]!;
      if (!ipMatchesAllowlist(hop, input.trustedProxies)) return hop;
    }
    // Entire chain is trusted proxies: fall back to the left-most entry.
    if (chain.length > 0) return chain[0]!;
  }

  if (input.realIp) {
    const r = stripMapped(input.realIp);
    if (r) return r;
  }
  return socket || "unknown";
}
