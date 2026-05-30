import { describe, test, expect } from "bun:test";
import {
  resolveSourceIp,
  parseTrustedProxies,
  DEFAULT_TRUSTED_PROXIES,
} from "../src/auth/sourceIp";

describe("parseTrustedProxies", () => {
  test("seeds loopback by default when env is unset", () => {
    expect(parseTrustedProxies(undefined)).toEqual(DEFAULT_TRUSTED_PROXIES);
    expect(parseTrustedProxies("")).toEqual(DEFAULT_TRUSTED_PROXIES);
  });

  test("appends operator-supplied CIDRs to the loopback defaults", () => {
    expect(parseTrustedProxies("10.0.0.0/24, 172.18.0.1")).toEqual([
      "127.0.0.0/8",
      "::1/128",
      "10.0.0.0/24",
      "172.18.0.1",
    ]);
  });
});

describe("resolveSourceIp", () => {
  const trusted = parseTrustedProxies(undefined); // loopback only

  test("direct untrusted peer: ignores spoofed X-Forwarded-For", () => {
    // The core vuln. An off-network attacker sends a forged header.
    const ip = resolveSourceIp({
      socketIp: "203.0.113.9",
      forwardedFor: "10.0.0.5",
      realIp: "10.0.0.5",
      trustedProxies: trusted,
    });
    expect(ip).toBe("203.0.113.9");
  });

  test("direct untrusted peer with no headers: uses socket address", () => {
    expect(
      resolveSourceIp({ socketIp: "203.0.113.9", trustedProxies: trusted })
    ).toBe("203.0.113.9");
  });

  test("loopback proxy: honors X-Forwarded-For client", () => {
    const ip = resolveSourceIp({
      socketIp: "127.0.0.1",
      forwardedFor: "198.51.100.7",
      trustedProxies: trusted,
    });
    expect(ip).toBe("198.51.100.7");
  });

  test("operator-configured proxy CIDR: honors forwarded client", () => {
    const t = parseTrustedProxies("172.18.0.0/16");
    const ip = resolveSourceIp({
      socketIp: "172.18.0.1", // docker gateway
      forwardedFor: "198.51.100.7",
      trustedProxies: t,
    });
    expect(ip).toBe("198.51.100.7");
  });

  test("multi-hop chain: returns right-most untrusted hop (real client)", () => {
    // client -> edge proxy (untrusted-looking in chain) -> local proxy
    const t = parseTrustedProxies("10.10.0.0/16");
    const ip = resolveSourceIp({
      socketIp: "127.0.0.1",
      forwardedFor: "198.51.100.7, 10.10.0.2",
      trustedProxies: t,
    });
    expect(ip).toBe("198.51.100.7");
  });

  test("trusted peer, no XFF, falls back to X-Real-IP", () => {
    const ip = resolveSourceIp({
      socketIp: "127.0.0.1",
      realIp: "198.51.100.7",
      trustedProxies: trusted,
    });
    expect(ip).toBe("198.51.100.7");
  });

  test("strips IPv4-mapped IPv6 prefix from socket and forwarded values", () => {
    expect(
      resolveSourceIp({ socketIp: "::ffff:203.0.113.9", trustedProxies: trusted })
    ).toBe("203.0.113.9");
    expect(
      resolveSourceIp({
        socketIp: "127.0.0.1",
        forwardedFor: "::ffff:198.51.100.7",
        trustedProxies: trusted,
      })
    ).toBe("198.51.100.7");
  });

  test("unknown socket (no conn info) does not trust forwarded headers", () => {
    expect(
      resolveSourceIp({
        socketIp: null,
        forwardedFor: "10.0.0.5",
        trustedProxies: trusted,
      })
    ).toBe("unknown");
  });

  test("IPv6 loopback proxy is trusted", () => {
    const ip = resolveSourceIp({
      socketIp: "::1",
      forwardedFor: "198.51.100.7",
      trustedProxies: trusted,
    });
    expect(ip).toBe("198.51.100.7");
  });
});
