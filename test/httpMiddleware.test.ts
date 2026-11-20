import { describe, test, expect } from "bun:test";
import { Hono } from "hono";
import { bodySizeLimit, maxBodySizeFromEnv, requestLogger } from "../src/http/middleware";

describe("requestLogger", () => {
  function app(lines: string[]) {
    const a = new Hono();
    a.use("*", requestLogger((l) => lines.push(l)));
    a.all("*", (c) => c.text("ok"));
    return a;
  }

  test("a /p request is logged without its query string", async () => {
    const lines: string[] = [];
    await app(lines).request("/p/example/v1/items?apitoken=QUERY-MARKER-123&x=1");
    expect(lines).toHaveLength(2);
    for (const l of lines) {
      expect(l).not.toContain("QUERY-MARKER-123");
      expect(l).not.toContain("?");
      expect(l).toContain("GET /p/example/v1/items");
    }
    expect(lines[1]).toContain("200");
  });

  test("a bare /p/<alias> request is logged without its query string", async () => {
    const lines: string[] = [];
    await app(lines).request("/p/example?apitoken=QUERY-MARKER-123");
    for (const l of lines) expect(l).not.toContain("QUERY-MARKER-123");
    expect(lines[0]).toContain("GET /p/example");
  });

  test("a path containing $& cannot pull the query back into the line", async () => {
    const lines: string[] = [];
    await app(lines).request("/p/example/a$&b$`c?apitoken=QUERY-MARKER-123");
    for (const l of lines) expect(l).not.toContain("QUERY-MARKER-123");
  });

  test("other routes keep their query string, as before", async () => {
    const lines: string[] = [];
    await app(lines).request("/v1/audit?limit=5");
    expect(lines[0]).toContain("GET /v1/audit?limit=5");
    const more: string[] = [];
    await app(more).request("/pages?x=1");
    expect(more[0]).toContain("GET /pages?x=1");
  });
});

describe("bodySizeLimit and maxBodySizeFromEnv", () => {
  function app(max: number) {
    const a = new Hono();
    a.use("*", bodySizeLimit(max));
    a.post("*", (c) => c.text("ok"));
    return a;
  }

  test("a malformed GATEHOUSE_MAX_BODY_SIZE keeps the 1 MiB cap on /v1 and warns once", async () => {
    const warnings: string[] = [];
    const max = maxBodySizeFromEnv("lots", (l) => warnings.push(l));
    expect(max).toBe(1048576);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("GATEHOUSE_MAX_BODY_SIZE");
    expect(warnings[0]).toContain("1048576");
    const res = await app(max).request("/v1/secrets/x", {
      method: "POST",
      body: "x",
      headers: { "content-length": String(1048577) },
    });
    expect(res.status).toBe(413);
  });

  test("unset or blank is the default with no warning; a valid value is used silently", () => {
    const warnings: string[] = [];
    const warn = (l: string) => warnings.push(l);
    expect(maxBodySizeFromEnv(undefined, warn)).toBe(1048576);
    expect(maxBodySizeFromEnv("", warn)).toBe(1048576);
    expect(maxBodySizeFromEnv("  ", warn)).toBe(1048576);
    expect(maxBodySizeFromEnv("2048", warn)).toBe(2048);
    expect(warnings).toHaveLength(0);
    for (const bad of ["0", "-5", "1e9", "12abc", "1.5"]) expect(maxBodySizeFromEnv(bad, warn)).toBe(1048576);
    expect(warnings).toHaveLength(5);
  });

  test("the cap applies on /v1 and is skipped on /p", async () => {
    const a = app(10);
    const big = { method: "POST", body: "x".repeat(20), headers: { "content-length": "20" } };
    expect((await a.request("/v1/x", big)).status).toBe(413);
    expect((await a.request("/p/example/x", big)).status).toBe(200);
  });
});
