import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import {
  DEFAULT_PROXY_LIMITS,
  getProxyLimits,
  setProxyLimits,
  _resetProxyLimitsCacheForTests,
} from "../src/settings/proxyLimits";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("proxy limits wiring", () => {
  let db: Database;
  let dir: string;
  let audit: AuditLog;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-pl-wire-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    _resetProxyLimitsCacheForTests();
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    _resetProxyLimitsCacheForTests();
  });

  test("setProxyLimits change is observable in getProxyLimits without restart", () => {
    expect(getProxyLimits(db)).toEqual(DEFAULT_PROXY_LIMITS);

    const r = setProxyLimits(db, audit, "user:admin", null, {
      max_timeout_ms: 60_000,
      max_body_bytes: 5_000_000,
    });
    expect(r.ok).toBe(true);

    expect(getProxyLimits(db)).toEqual({ max_timeout_ms: 60_000, max_body_bytes: 5_000_000 });
  });

  // Regression guard: both proxy paths must read limits from the same source.
  // This is a static-source check (read the file as text) so we don't have to
  // boot a real upstream server. The intent is to catch the bug where a future
  // edit changes one path but not the other.
  test("src/api/proxy.ts uses getProxyLimits (no hardcoded 120000 timeout cap)", () => {
    const src = readFileSync("src/api/proxy.ts", "utf8");
    expect(src).toContain("getProxyLimits");
    // Hardcoded 120_000 / 120000 cap should be gone from the timeout path.
    // Allow occurrences in comments only by checking the line content.
    const lines = src.split("\n");
    const offendingLines = lines.filter((line) => {
      const code = line.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "");
      return /Math\.min\([^,]+,\s*120_?000\s*\)/.test(code);
    });
    expect(offendingLines).toEqual([]);
  });

  test("src/api/proxy.ts uses dynamic max_body_bytes (no hardcoded MAX_UPSTREAM_BODY_BYTES in readCappedText)", () => {
    const src = readFileSync("src/api/proxy.ts", "utf8");
    expect(src).toContain("max_body_bytes");
    // readCappedText(...) should no longer be called with MAX_UPSTREAM_BODY_BYTES as the cap.
    expect(/readCappedText\([^)]*MAX_UPSTREAM_BODY_BYTES\)/.test(src)).toBe(false);
  });

  test("src/mcp/server.ts uses getProxyLimits (no hardcoded 120000 timeout cap)", () => {
    const src = readFileSync("src/mcp/server.ts", "utf8");
    expect(src).toContain("getProxyLimits");
    const lines = src.split("\n");
    const offendingLines = lines.filter((line) => {
      const code = line.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "");
      return /Math\.min\([^,]+,\s*120_?000\s*\)/.test(code);
    });
    expect(offendingLines).toEqual([]);
  });

  test("src/mcp/server.ts uses dynamic max_body_bytes (no hardcoded MAX_UPSTREAM_BODY_BYTES in readCappedText)", () => {
    const src = readFileSync("src/mcp/server.ts", "utf8");
    expect(src).toContain("max_body_bytes");
    expect(/readCappedText\([^)]*MAX_UPSTREAM_BODY_BYTES\)/.test(src)).toBe(false);
  });
});
