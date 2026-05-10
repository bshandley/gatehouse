import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import {
  DEFAULT_PROXY_LIMITS,
  PROXY_LIMITS_HARD_CEILING,
  validateProxyLimits,
  getProxyLimits,
  setProxyLimits,
  _resetProxyLimitsCacheForTests,
} from "../src/settings/proxyLimits";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("validateProxyLimits", () => {
  test("accepts the defaults", () => {
    expect(validateProxyLimits(DEFAULT_PROXY_LIMITS)).toEqual({
      ok: true,
      value: DEFAULT_PROXY_LIMITS,
    });
  });

  test("accepts the hard ceiling values", () => {
    const r = validateProxyLimits(PROXY_LIMITS_HARD_CEILING);
    expect(r.ok).toBe(true);
  });

  test("rejects zero timeout", () => {
    const r = validateProxyLimits({ max_timeout_ms: 0, max_body_bytes: 1024 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.some((e) => e.toLowerCase().includes("max_timeout_ms"))).toBe(true);
  });

  test("rejects negative timeout", () => {
    const r = validateProxyLimits({ max_timeout_ms: -1, max_body_bytes: 1024 });
    expect(r.ok).toBe(false);
  });

  test("rejects non-integer timeout", () => {
    const r = validateProxyLimits({ max_timeout_ms: 1500.5, max_body_bytes: 1024 });
    expect(r.ok).toBe(false);
  });

  test("rejects timeout below 1 second", () => {
    const r = validateProxyLimits({ max_timeout_ms: 999, max_body_bytes: 1024 });
    expect(r.ok).toBe(false);
  });

  test("rejects timeout above 30 minutes", () => {
    const r = validateProxyLimits({ max_timeout_ms: 1800001, max_body_bytes: 1024 });
    expect(r.ok).toBe(false);
  });

  test("rejects zero body bytes", () => {
    const r = validateProxyLimits({ max_timeout_ms: 1000, max_body_bytes: 0 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.errors.some((e) => e.toLowerCase().includes("max_body_bytes"))).toBe(true);
  });

  test("rejects body bytes below 1 KiB", () => {
    const r = validateProxyLimits({ max_timeout_ms: 1000, max_body_bytes: 1023 });
    expect(r.ok).toBe(false);
  });

  test("rejects body bytes above 100 MiB", () => {
    const r = validateProxyLimits({ max_timeout_ms: 1000, max_body_bytes: 104857601 });
    expect(r.ok).toBe(false);
  });

  test("rejects non-integer body bytes", () => {
    const r = validateProxyLimits({ max_timeout_ms: 1000, max_body_bytes: 2048.5 });
    expect(r.ok).toBe(false);
  });

  test("rejects missing fields", () => {
    expect(validateProxyLimits({} as any).ok).toBe(false);
    expect(validateProxyLimits({ max_timeout_ms: 60_000 } as any).ok).toBe(false);
    expect(validateProxyLimits({ max_body_bytes: 1024 } as any).ok).toBe(false);
  });

  test("rejects null", () => {
    expect(validateProxyLimits(null as any).ok).toBe(false);
  });
});

describe("getProxyLimits + setProxyLimits", () => {
  let db: Database;
  let dir: string;
  let audit: AuditLog;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-pl-"));
    db = initDB(dir);
    audit = new AuditLog(db);
    _resetProxyLimitsCacheForTests();
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
    _resetProxyLimitsCacheForTests();
  });

  test("getProxyLimits returns defaults when no row exists", () => {
    expect(getProxyLimits(db)).toEqual(DEFAULT_PROXY_LIMITS);
  });

  test("getProxyLimits returns defaults when row is malformed JSON", () => {
    db.query("INSERT INTO settings (key, value) VALUES ('proxy_limits', 'not-json')").run();
    expect(getProxyLimits(db)).toEqual(DEFAULT_PROXY_LIMITS);
  });

  test("getProxyLimits returns defaults when stored value fails validation", () => {
    db.query("INSERT INTO settings (key, value) VALUES ('proxy_limits', ?)").run(
      JSON.stringify({ max_timeout_ms: -1, max_body_bytes: 0 })
    );
    expect(getProxyLimits(db)).toEqual(DEFAULT_PROXY_LIMITS);
  });

  test("getProxyLimits returns persisted values", () => {
    const limits = { max_timeout_ms: 60_000, max_body_bytes: 5 * 1024 * 1024 };
    db.query("INSERT INTO settings (key, value) VALUES ('proxy_limits', ?)").run(JSON.stringify(limits));
    expect(getProxyLimits(db)).toEqual(limits);
  });

  test("getProxyLimits caches the row (no second SQLite call without invalidation)", () => {
    const limits = { max_timeout_ms: 60_000, max_body_bytes: 5 * 1024 * 1024 };
    db.query("INSERT INTO settings (key, value) VALUES ('proxy_limits', ?)").run(JSON.stringify(limits));
    expect(getProxyLimits(db)).toEqual(limits);

    // Mutate the row directly (bypassing the setter) to prove the cache is in effect.
    db.query("UPDATE settings SET value = ? WHERE key = 'proxy_limits'").run(
      JSON.stringify({ max_timeout_ms: 1000, max_body_bytes: 1024 })
    );
    expect(getProxyLimits(db)).toEqual(limits); // cached, not re-read
  });

  test("setProxyLimits persists, invalidates cache, audits", () => {
    // Prime the cache with defaults.
    expect(getProxyLimits(db)).toEqual(DEFAULT_PROXY_LIMITS);

    const newLimits = { max_timeout_ms: 60_000, max_body_bytes: 2 * 1024 * 1024 };
    const r = setProxyLimits(db, audit, "user:alice", "127.0.0.1", newLimits);
    expect(r.ok).toBe(true);

    // Cache invalidation: subsequent get returns the new value, not the cached defaults.
    expect(getProxyLimits(db)).toEqual(newLimits);

    // Audit row exists with old + new metadata.
    const auditRow = db
      .query(
        "SELECT identity, action, metadata FROM audit_log WHERE action = 'settings.proxy_limits.update' ORDER BY id DESC LIMIT 1"
      )
      .get() as any;
    expect(auditRow).toBeTruthy();
    expect(auditRow.identity).toBe("user:alice");
    const meta = JSON.parse(auditRow.metadata);
    expect(meta.old_max_timeout_ms).toBe(String(DEFAULT_PROXY_LIMITS.max_timeout_ms));
    expect(meta.new_max_timeout_ms).toBe("60000");
    expect(meta.old_max_body_bytes).toBe(String(DEFAULT_PROXY_LIMITS.max_body_bytes));
    expect(meta.new_max_body_bytes).toBe(String(2 * 1024 * 1024));
  });

  test("setProxyLimits rejects invalid input without writing", () => {
    const r = setProxyLimits(db, audit, "user:alice", "127.0.0.1", {
      max_timeout_ms: 0,
      max_body_bytes: 1024,
    });
    expect(r.ok).toBe(false);

    const row = db.query("SELECT value FROM settings WHERE key = 'proxy_limits'").get();
    expect(row).toBeNull();

    const auditRow = db
      .query("SELECT 1 FROM audit_log WHERE action = 'settings.proxy_limits.update'")
      .get();
    expect(auditRow).toBeNull();
  });

  test("setProxyLimits clamps non-integers / coerces? (NO: rejects)", () => {
    const r = setProxyLimits(db, audit, "user:alice", null, {
      max_timeout_ms: 60000.5,
      max_body_bytes: 1024,
    });
    expect(r.ok).toBe(false);
  });
});
