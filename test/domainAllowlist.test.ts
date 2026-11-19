import { describe, test, expect } from "bun:test";
import { hostAllowed } from "../src/security/domainAllowlist";

const allowed = (url: string, entries: string[]) => hostAllowed(url, entries).allowed;

describe("hostAllowed", () => {
  test("empty list allows everything", () => {
    expect(allowed("https://anything.example/x", [])).toBe(true);
  });

  test("bare domain matches itself and subdomains on any port", () => {
    expect(allowed("https://example.com/x", ["example.com"])).toBe(true);
    expect(allowed("https://api.example.com/x", ["example.com"])).toBe(true);
    expect(allowed("https://example.com:8443/x", ["example.com"])).toBe(true);
    expect(allowed("https://notexample.com/x", ["example.com"])).toBe(false);
    expect(allowed("https://example.com.evil.test/x", ["example.com"])).toBe(false);
  });

  test("matching is case-insensitive", () => {
    expect(allowed("https://API.Example.com/x", ["example.COM"])).toBe(true);
  });

  test("*.domain matches subdomains only", () => {
    expect(allowed("https://api.example.com/x", ["*.example.com"])).toBe(true);
    expect(allowed("https://a.b.example.com/x", ["*.example.com"])).toBe(true);
    expect(allowed("https://example.com/x", ["*.example.com"])).toBe(false);
  });

  test("host:port restricts the port", () => {
    expect(allowed("http://10.0.0.50:5230/api/v1/memos", ["10.0.0.50:5230"])).toBe(true);
    expect(allowed("http://10.0.0.50:9999/api", ["10.0.0.50:5230"])).toBe(false);
    expect(allowed("http://10.0.0.50/api", ["10.0.0.50:5230"])).toBe(false);
  });

  test("the URL port defaults from its scheme", () => {
    expect(allowed("https://example.com/x", ["example.com:443"])).toBe(true);
    expect(allowed("http://example.com/x", ["example.com:80"])).toBe(true);
    expect(allowed("http://example.com/x", ["example.com:443"])).toBe(false);
  });

  test("wildcard with a port", () => {
    expect(allowed("https://api.example.com:8443/x", ["*.example.com:8443"])).toBe(true);
    expect(allowed("https://api.example.com/x", ["*.example.com:8443"])).toBe(false);
  });

  test("IPv4 literal without a port matches any port", () => {
    expect(allowed("http://10.0.0.50:5230/x", ["10.0.0.50"])).toBe(true);
    expect(allowed("http://10.0.0.51:5230/x", ["10.0.0.50"])).toBe(false);
  });

  test("CIDR entry matches IP-literal hosts in range", () => {
    expect(allowed("http://10.0.0.50:5230/x", ["10.0.0.0/24"])).toBe(true);
    expect(allowed("http://10.0.1.50/x", ["10.0.0.0/24"])).toBe(false);
    expect(allowed("http://ten.example.com/x", ["10.0.0.0/24"])).toBe(false);
  });

  test("IPv6 literals, bracketed and bare, with and without a port", () => {
    expect(allowed("http://[fd00::1]:8080/x", ["[fd00::1]:8080"])).toBe(true);
    expect(allowed("http://[fd00::1]:8081/x", ["[fd00::1]:8080"])).toBe(false);
    expect(allowed("http://[fd00::1]/x", ["fd00::1"])).toBe(true);
    expect(allowed("http://[fd00::1]/x", ["[FD00::1]"])).toBe(true);
    expect(allowed("http://[fd00::2]/x", ["fd00::/8"])).toBe(true);
  });

  test("any entry may match", () => {
    expect(allowed("https://b.test/x", ["a.test", "b.test"])).toBe(true);
  });

  test("an unparseable entry matches nothing and does not throw", () => {
    expect(allowed("https://example.com/x", ["http://example.com", "exa mple"])).toBe(false);
  });

  test("an invalid URL is not allowed and reports hostname 'invalid'", () => {
    expect(hostAllowed("not a url", ["example.com"])).toEqual({ allowed: false, hostname: "invalid" });
  });

  test("reports the hostname it checked", () => {
    expect(hostAllowed("https://api.example.com/x", ["other.test"])).toEqual({ allowed: false, hostname: "api.example.com" });
  });
});
