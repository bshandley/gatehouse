import { Database, constants as sqlite } from "bun:sqlite";
import { existsSync, writeFileSync, utimesSync, unlinkSync, statSync, accessSync, constants } from "fs";
import { dirname, join, resolve } from "path";

export const LOCK_FILE_NAME = "gatehouse.lock";

/**
 * Open a db read-only without writing anything beside it.
 *
 * A WAL-mode db whose -wal is gone (SQLite removes it on a clean close) has
 * every committed page in the main file, so it is opened immutable, which
 * creates no sidecars. A plain read-only open is not safe for that case: what
 * it does depends on the platform. Linux SQLite quietly creates an empty -wal
 * and a -shm in a writable directory, and other builds refuse the first read.
 *
 * Immutable is only correct when nothing is writing, so it is not used while
 * the server's heartbeat lock is fresh. A running server always has a -wal,
 * so that guard only matters in the instant a server is starting.
 */
export function openReadonly(dbPath: string): Database {
  const immutable = () => {
    const uri = "file:" + encodeURI(resolve(dbPath)).replace(/\?/g, "%3F").replace(/#/g, "%23");
    // SQLITE_OPEN_URI must be passed explicitly. Bun's bundled SQLite on Linux
    // does not parse file: URIs without it ("unable to open database file");
    // macOS's system SQLite does, which hides the difference.
    return new Database(`${uri}?mode=ro&immutable=1`, sqlite.SQLITE_OPEN_READONLY | sqlite.SQLITE_OPEN_URI);
  };
  const walExists = existsSync(`${dbPath}-wal`);
  if (existsSync(dbPath) && !walExists && !isServerLive(dirname(dbPath), Date.now())) {
    return immutable();
  }
  let db: Database | null = null;
  try {
    db = new Database(dbPath, { readonly: true });
    // The open is lazy: the first read is what fails if SQLite cannot map the WAL.
    db.query("SELECT COUNT(*) FROM sqlite_master").get();
    return db;
  } catch (err) {
    try { db?.close(); } catch {}
    if (!existsSync(dbPath) || walExists) throw err;
    return immutable();
  }
}

/**
 * Write a consistent, single-file copy of the db using VACUUM INTO. Safe while
 * a server holds the db open in WAL mode: the result contains committed
 * writes and has no -wal or -shm sidecars.
 */
export function snapshotTo(dbPath: string, outPath: string): void {
  if (existsSync(outPath)) {
    throw new Error(`output file already exists: ${outPath}`);
  }
  try {
    accessSync(dirname(outPath), constants.W_OK);
  } catch {
    throw new Error(`output directory is not writable: ${dirname(outPath)}`);
  }
  const db = openReadonly(dbPath);
  try {
    db.query("VACUUM INTO ?").run(outPath);
  } finally {
    db.close();
  }
}

/** Row count for every user table (sqlite_ internals excluded). */
export function tableRowCounts(dbPath: string): Record<string, number> {
  const db = openReadonly(dbPath);
  try {
    const tables = db
      .query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
      .all() as { name: string }[];
    const counts: Record<string, number> = {};
    for (const { name } of tables) {
      const row = db.query(`SELECT COUNT(*) AS n FROM "${name.replace(/"/g, '""')}"`).get() as { n: number };
      counts[name] = row.n;
    }
    return counts;
  } finally {
    db.close();
  }
}

/**
 * Server liveness lock. A pid check is meaningless when import runs in a
 * second container on the same volume, so the server touches this file's
 * mtime on an interval and a crashed server's lock goes stale on its own.
 */
export function startHeartbeat(
  dataDir: string,
  intervalMs = 10_000,
  log: (msg: string) => void = (m) => console.error(m)
): () => void {
  const lock = join(dataDir, LOCK_FILE_NAME);
  const body = () => JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() });
  writeFileSync(lock, body());
  let failing = false;
  const timer = setInterval(() => {
    try {
      try {
        const now = new Date();
        utimesSync(lock, now, now);
      } catch {
        // lock removed underneath us: recreate it
        writeFileSync(lock, body());
      }
      if (failing) {
        failing = false;
        log("[gatehouse] heartbeat recovered. Import protection restored.");
      }
    } catch (err) {
      if (!failing) {
        failing = true;
        const msg = err instanceof Error ? err.message : String(err);
        log(`[gatehouse] heartbeat failed: ${msg}. Import protection is degraded until this clears.`);
      }
    }
  }, intervalMs);
  return () => {
    clearInterval(timer);
    try { unlinkSync(lock); } catch {}
  };
}

export function isServerLive(dataDir: string, now = Date.now(), staleMs = 30_000): boolean {
  try {
    return now - statSync(join(dataDir, LOCK_FILE_NAME)).mtimeMs <= staleMs;
  } catch {
    return false;
  }
}
