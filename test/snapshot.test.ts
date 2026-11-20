import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, mkdirSync, rmSync, existsSync, readFileSync, writeFileSync, chmodSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import {
  snapshotTo,
  tableRowCounts,
  startHeartbeat,
  isServerLive,
  LOCK_FILE_NAME,
} from "../src/backup/snapshot";

const KEY = Buffer.from("c".repeat(64), "hex");
let dir: string;
let out: string;
let db: Database | null = null;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "gh-snap-"));
  out = mkdtempSync(join(tmpdir(), "gh-snap-out-"));
});
afterEach(() => {
  try { db?.close(); } catch {}
  db = null;
  try { chmodSync(out, 0o700); } catch {}
  rmSync(dir, { recursive: true, force: true });
  rmSync(out, { recursive: true, force: true });
});

function seed() {
  db = initDB(dir);
  const eng = new SecretsEngine(db, KEY);
  eng.put("api-keys/example", "v1");
}

describe("snapshotTo", () => {
  test("snapshot of a WAL db with uncheckpointed writes contains them, and has no sidecars", () => {
    seed();
    snapshotTo(join(dir, "gatehouse.db"), join(out, "snap.db"));
    const snap = new Database(join(out, "snap.db"), { readonly: true });
    expect(snap.query("SELECT COUNT(*) AS n FROM secrets").get()).toEqual({ n: 1 });
    snap.close();
    expect(existsSync(join(out, "snap.db-wal"))).toBe(false);
    expect(existsSync(join(out, "snap.db-shm"))).toBe(false);
  });

  test("refuses to overwrite an existing output file", () => {
    seed();
    const target = join(out, "snap.db");
    writeFileSync(target, "precious");
    expect(() => snapshotTo(join(dir, "gatehouse.db"), target)).toThrow(/already exists/);
    expect(readFileSync(target, "utf8")).toBe("precious");
  });

  test("errors clearly when the output dir is not writable", () => {
    seed();
    chmodSync(out, 0o500);
    if (process.getuid && process.getuid() === 0) return; // root ignores modes
    expect(() => snapshotTo(join(dir, "gatehouse.db"), join(out, "snap.db"))).toThrow(/snapshot|writable|permission/i);
    expect(existsSync(join(out, "snap.db"))).toBe(false);
  });

  test("works on a WAL db whose sidecars are gone, and creates none", () => {
    // Linux SQLite deletes -wal and -shm on a clean close; a plain read-only
    // open of such a db fails because it would have to create the -shm.
    const sub = join(dir, "odd ?#% name");
    mkdirSync(sub);
    db = initDB(sub);
    new SecretsEngine(db, KEY).put("api-keys/example", "v1");
    db.run("PRAGMA wal_checkpoint(TRUNCATE)");
    db.close();
    db = null;
    const dbPath = join(sub, "gatehouse.db");
    rmSync(`${dbPath}-wal`, { force: true });
    rmSync(`${dbPath}-shm`, { force: true });
    snapshotTo(dbPath, join(out, "snap.db"));
    expect(tableRowCounts(dbPath).secrets).toBe(1);
    expect(existsSync(`${dbPath}-wal`)).toBe(false);
    expect(existsSync(`${dbPath}-shm`)).toBe(false);
    const snap = new Database(join(out, "snap.db"), { readonly: true });
    expect(snap.query("SELECT COUNT(*) AS n FROM secrets").get()).toEqual({ n: 1 });
    snap.close();
  });
});

describe("tableRowCounts", () => {
  test("reports every table", () => {
    seed();
    const counts = tableRowCounts(join(dir, "gatehouse.db"));
    expect(counts.secrets).toBe(1);
    expect("audit_log" in counts).toBe(true);
    expect(Object.keys(counts).some((t) => t.startsWith("sqlite_"))).toBe(false);
  });
});

describe("heartbeat lock", () => {
  test("creates the lock, isServerLive is true, stop removes it", () => {
    const stop = startHeartbeat(dir, 60_000);
    try {
      const lock = join(dir, LOCK_FILE_NAME);
      expect(existsSync(lock)).toBe(true);
      const body = JSON.parse(readFileSync(lock, "utf8"));
      expect(body.pid).toBe(process.pid);
      expect(typeof body.started_at).toBe("string");
      expect(isServerLive(dir)).toBe(true);
    } finally {
      stop();
    }
    expect(existsSync(join(dir, LOCK_FILE_NAME))).toBe(false);
    expect(isServerLive(dir)).toBe(false);
  });

  test("a lock older than staleMs is not live", () => {
    const stop = startHeartbeat(dir, 60_000);
    try {
      expect(isServerLive(dir, Date.now() + 31_000)).toBe(false);
    } finally {
      stop();
    }
  });

  test("the heartbeat refreshes the lock mtime", async () => {
    const stop = startHeartbeat(dir, 20);
    try {
      const lock = join(dir, LOCK_FILE_NAME);
      const { statSync, utimesSync } = await import("fs");
      const old = new Date(Date.now() - 60_000);
      utimesSync(lock, old, old);
      const deadline = Date.now() + 3000;
      while (Date.now() < deadline && statSync(lock).mtimeMs < Date.now() - 5000) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(isServerLive(dir)).toBe(true);
    } finally {
      stop();
    }
  });

  test("tick failures are logged once per streak, and recovery is logged", async () => {
    const hbDir = join(dir, "hb");
    mkdirSync(hbDir);
    const logs: string[] = [];
    const stop = startHeartbeat(hbDir, 10, (m) => logs.push(m));
    try {
      rmSync(hbDir, { recursive: true, force: true }); // ticks now fail
      const wait = async (cond: () => boolean) => {
        const deadline = Date.now() + 3000;
        while (Date.now() < deadline && !cond()) await new Promise((r) => setTimeout(r, 10));
      };
      await wait(() => logs.length >= 1);
      await new Promise((r) => setTimeout(r, 100)); // several more failing ticks
      expect(logs.length).toBe(1);
      expect(logs[0]).toMatch(/heartbeat failed: .+Import protection is degraded until this clears\./);
      mkdirSync(hbDir); // ticks recover
      await wait(() => logs.length >= 2);
      await new Promise((r) => setTimeout(r, 50));
      expect(logs.length).toBe(2);
      expect(logs[1]).toContain("recovered");
    } finally {
      stop();
    }
  });

  test("no lock file is not live", () => {
    expect(isServerLive(dir)).toBe(false);
  });
});
