import { describe, test, expect } from "bun:test";
import { splitList, splitModeFor, validateEntry, parseList, normalizeList } from "../src/ui/list-validate.js";

describe("splitList", () => {
  test("splits on commas, spaces, tabs and newlines", () => {
    expect(splitList("a,b c\td\ne")).toEqual(["a", "b", "c", "d", "e"]);
  });
  test("collapses repeated and mixed separators", () => {
    expect(splitList(" a ,, b  ,\n\n c ")).toEqual(["a", "b", "c"]);
  });
  test("drops duplicates, keeping first position", () => {
    expect(splitList("a, b, a, c, b")).toEqual(["a", "b", "c"]);
  });
  test("empty and non-string input give an empty list", () => {
    expect(splitList("")).toEqual([]);
    expect(splitList("  , ,")).toEqual([]);
    expect(splitList(undefined as any)).toEqual([]);
  });
});

describe("validateEntry: cidr", () => {
  const ok = ["10.0.0.5", "10.0.0.0/24", "0.0.0.0/0", "192.168.1.1/32", "::1", "fd00::/8", "2001:db8::1/128"];
  const bad = ["10.0.0", "10.0.0.256", "10.0.0.5/33", "10.0.0.5/", "example.com", "10.0.0.5:80", "fd00::/129", "1:2:3", "::1::2", "10.0.0.5/x"];
  for (const e of ok) test(`accepts ${e}`, () => expect(validateEntry("cidr", e)).toBeNull());
  for (const e of bad) test(`rejects ${e}`, () => expect(typeof validateEntry("cidr", e)).toBe("string"));
});

describe("validateEntry: host", () => {
  const ok = [
    "example.com", "api.example.com", "*.example.com", "localhost", "db.lab",
    "example.com:8443", "*.example.com:443", "10.0.0.50", "10.0.0.50:5230",
    "10.0.0.0/24", "[::1]", "[fd00::1]:8080", "::1", "xn--bcher-kva.example",
  ];
  const bad = [
    "http://example.com", "https://example.com/path", "example.com/path", "exa mple.com",
    "-bad.example.com", "example..com", "example.com:0", "example.com:70000", "example.com:abc",
    "10.0.0.999", "10.0.0.0/40", "*.", "*", "*example.com", "a.*.example.com", "[::1", "[zz::1]:80",
  ];
  for (const e of ok) test(`accepts ${e}`, () => expect(validateEntry("host", e)).toBeNull());
  for (const e of bad) test(`rejects ${e}`, () => expect(typeof validateEntry("host", e)).toBe("string"));
  test("a URL gets a reason that says to enter a host", () => {
    expect(validateEntry("host", "https://example.com")).toMatch(/host/i);
  });
});

describe("validateEntry: pathPrefix", () => {
  for (const e of ["/", "/v1", "/v1/", "/api/v2/things"]) test(`accepts ${e}`, () => expect(validateEntry("pathPrefix", e)).toBeNull());
  for (const e of ["v1", "v1/", "/v1?x=1", "/v1#frag", "https://x/v1"]) test(`rejects ${e}`, () => expect(typeof validateEntry("pathPrefix", e)).toBe("string"));
});

describe("validateEntry: policyPath", () => {
  for (const e of ["*", "api-keys/*", "db/postgres_prod", "a/b/c"]) test(`accepts ${e}`, () => expect(validateEntry("policyPath", e)).toBeNull());
  for (const e of ["api keys", "a.b", "a,b", "a/b?"]) test(`rejects ${e}`, () => expect(typeof validateEntry("policyPath", e)).toBe("string"));
});

describe("validateEntry: word", () => {
  test("accepts anything without whitespace or comma", () => {
    expect(validateEntry("word", "permit-pty")).toBeNull();
    expect(validateEntry("word", "SELECT")).toBeNull();
  });
  test("rejects empty", () => expect(typeof validateEntry("word", "")).toBe("string"));
});

describe("validateEntry: unknown kind", () => {
  test("throws", () => expect(() => validateEntry("nope" as any, "x")).toThrow());
});

describe("parseList and normalizeList", () => {
  test("parseList separates valid entries from errors", () => {
    const r = parseList("cidr", "10.0.0.5 nope, 10.0.0.0/24");
    expect(r.entries).toEqual(["10.0.0.5", "nope", "10.0.0.0/24"]);
    expect(r.errors).toHaveLength(1);
    expect(r.errors[0].entry).toBe("nope");
    expect(typeof r.errors[0].reason).toBe("string");
  });
  test("normalizeList joins valid entries with comma and space", () => {
    expect(normalizeList("cidr", "10.0.0.5\n10.0.0.6 ,10.0.0.5")).toEqual({ ok: true, value: "10.0.0.5, 10.0.0.6" });
  });
  test("normalizeList reports the first invalid entry", () => {
    const r = normalizeList("host", "example.com, http://bad");
    expect(r.ok).toBe(false);
    expect(r.entry).toBe("http://bad");
    expect(typeof r.reason).toBe("string");
  });
  test("normalizeList of an empty list is an empty string", () => {
    expect(normalizeList("host", "  ")).toEqual({ ok: true, value: "" });
  });
  test("normalizeList accepts a custom separator", () => {
    expect(normalizeList("word", "a b", ",")).toEqual({ ok: true, value: "a,b" });
  });
});

describe("comma mode and the phrase kind", () => {
  test("comma mode keeps spaces inside an entry and collapses runs", () => {
    expect(splitList("SELECT, ALL  PRIVILEGES ,\nLOCK TABLES", "comma")).toEqual(["SELECT", "ALL PRIVILEGES", "LOCK TABLES"]);
  });
  test("comma mode still dedupes", () => {
    expect(splitList("SELECT,SELECT , INSERT", "comma")).toEqual(["SELECT", "INSERT"]);
  });
  test("splitModeFor picks comma mode for phrase only", () => {
    expect(splitModeFor("phrase")).toBe("comma");
    expect(splitModeFor("word")).toBe("any");
  });
  test("phrase accepts multi-word values", () => {
    expect(validateEntry("phrase", "CREATE TEMPORARY TABLES")).toBeNull();
  });
  test("normalizeList with phrase uses comma splitting", () => {
    expect(normalizeList("phrase", "SELECT, LOCK TABLES", ",")).toEqual({ ok: true, value: "SELECT,LOCK TABLES" });
  });
});
