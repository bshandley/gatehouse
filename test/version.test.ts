import { describe, test, expect, beforeEach } from "bun:test";
import { Hono } from "hono";
import { compareVersions, versionRouter, _resetVersionCheckCache } from "../src/api/version";
import { VERSION } from "../src/version";

describe("compareVersions", () => {
  test("equal versions return 0", () => {
    expect(compareVersions("0.8.2", "0.8.2")).toBe(0);
    expect(compareVersions("v0.8.2", "0.8.2")).toBe(0);
    expect(compareVersions("0.8", "0.8.0")).toBe(0);
  });

  test("a < b returns negative", () => {
    expect(compareVersions("0.8.1", "0.8.2")).toBeLessThan(0);
    expect(compareVersions("0.7.99", "0.8.0")).toBeLessThan(0);
    expect(compareVersions("0.8.2", "1.0.0")).toBeLessThan(0);
  });

  test("a > b returns positive", () => {
    expect(compareVersions("0.8.10", "0.8.2")).toBeGreaterThan(0);
    expect(compareVersions("1.0.0", "0.99.99")).toBeGreaterThan(0);
  });

  test("v-prefix is tolerated on either side", () => {
    expect(compareVersions("v0.8.10", "v0.8.2")).toBeGreaterThan(0);
    expect(compareVersions("v0.8.2", "0.8.10")).toBeLessThan(0);
  });

  test("numeric not lexicographic on each component", () => {
    // The bug to avoid: "0.8.10" < "0.8.2" if compared lexicographically.
    expect(compareVersions("0.8.10", "0.8.2")).toBe(8);
  });
});

describe("GET /v1/version/check", () => {
  let app: Hono;

  beforeEach(() => {
    _resetVersionCheckCache();
    delete process.env.GATEHOUSE_UPDATE_CHECK;
  });

  test("returns has_update=false when latest equals current", async () => {
    const stub = async () => ({
      tag_name: `v${VERSION}`,
      html_url: "https://github.com/bshandley/gatehouse/releases/tag/v" + VERSION,
      published_at: "2026-04-25T00:00:00Z",
    });
    app = new Hono();
    app.route("/v1/version", versionRouter({ fetcher: stub }));
    const res = await app.request("/v1/version/check");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.current).toBe(VERSION);
    expect(body.latest).toBe(VERSION);
    expect(body.has_update).toBe(false);
  });

  test("returns has_update=true when GitHub has a newer release", async () => {
    // Bump the patch component of the running version so the comparison
    // is forward-going regardless of what VERSION is at any given moment.
    const newer =
      VERSION.split(".").map((n, i, a) => (i === a.length - 1 ? Number(n) + 1 : n)).join(".");
    const stub = async () => ({
      tag_name: `v${newer}`,
      html_url: `https://github.com/bshandley/gatehouse/releases/tag/v${newer}`,
      published_at: "2026-04-26T00:00:00Z",
    });
    app = new Hono();
    app.route("/v1/version", versionRouter({ fetcher: stub }));
    const res = await app.request("/v1/version/check");
    const body = await res.json();
    expect(body.has_update).toBe(true);
    expect(body.latest).toBe(newer);
    expect(body.release_url).toContain(newer);
  });

  test("handles 'no releases yet' (404 from GitHub) without breaking", async () => {
    const stub = async () => "not_found" as const;
    app = new Hono();
    app.route("/v1/version", versionRouter({ fetcher: stub }));
    const res = await app.request("/v1/version/check");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.no_releases).toBe(true);
    expect(body.has_update).toBe(false);
    expect(body.latest).toBeNull();
  });

  test("network failure returns check_failed without 5xx-ing the UI", async () => {
    const stub = async () => {
      throw new Error("ENOTFOUND api.github.com");
    };
    app = new Hono();
    app.route("/v1/version", versionRouter({ fetcher: stub }));
    const res = await app.request("/v1/version/check");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.check_failed).toBe(true);
    expect(body.current).toBe(VERSION);
  });

  test("GATEHOUSE_UPDATE_CHECK=false short-circuits without calling out", async () => {
    process.env.GATEHOUSE_UPDATE_CHECK = "false";
    let called = false;
    const stub = async () => {
      called = true;
      return "not_found" as const;
    };
    app = new Hono();
    app.route("/v1/version", versionRouter({ fetcher: stub }));
    const res = await app.request("/v1/version/check");
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.check_disabled).toBe(true);
    expect(body.current).toBe(VERSION);
    expect(called).toBe(false);
  });

  test("result is cached - second call within TTL does not re-fetch", async () => {
    let calls = 0;
    const stub = async () => {
      calls++;
      return {
        tag_name: `v${VERSION}`,
        html_url: "https://example.com",
        published_at: "2026-04-25T00:00:00Z",
      };
    };
    app = new Hono();
    app.route("/v1/version", versionRouter({ fetcher: stub }));
    await app.request("/v1/version/check");
    await app.request("/v1/version/check");
    await app.request("/v1/version/check");
    expect(calls).toBe(1);
  });
});
