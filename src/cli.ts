#!/usr/bin/env bun
/**
 * gatehouse CLI: backup, export, import, verify.
 *
 * Exit codes: 0 ok, 1 general failure, 2 key mismatch, 3 live server.
 * Nothing printed here may contain a passphrase or a master key.
 */
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  chmodSync,
  unlinkSync,
  writeSync,
} from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";
import { keyFingerprint } from "./secrets/engine";
import { resolveMasterKey, MasterKeyError, KEY_FILE_NAME, persistKeyFile } from "./backup/keyfile";
import { snapshotTo, tableRowCounts, isServerLive, openReadonly } from "./backup/snapshot";
import { sealBundle, openBundle, BundleError } from "./backup/bundle";
import { verifyVault, type VerifyResult } from "./backup/verify";

export interface CliIo {
  env: Record<string, string | undefined>;
  out: (s: string) => void;
  err: (s: string) => void;
  isTTY: boolean;
  prompt?: (label: string) => Promise<string>;
  now?: () => Date;
}

const DB_FILE_NAME = "gatehouse.db";
const MIN_PASSPHRASE = 12;
const SQLITE_MAGIC = "SQLite format 3\0";

const USAGE = `Usage:
  gatehouse backup --out FILE
      Consistent snapshot of gatehouse.db (SQLite VACUUM INTO). Safe while the
      server runs. Does NOT include the master key: back that up separately.

  gatehouse export --out FILE [--passphrase-env VAR] [--no-key]
      Passphrase-encrypted bundle (scrypt + secretbox), written mode 0600.
      Includes the master key by default, so the file plus the passphrase
      recovers the whole vault and the passphrase strength is the whole game
      (minimum ${MIN_PASSPHRASE} characters). --no-key leaves the key out.

  gatehouse import --in FILE [--passphrase-env VAR] [--force]
      Full replace of the vault from a bundle, never a merge. Stop the server
      first. The previous db is kept as gatehouse.db.pre-import-<timestamp>.
      Refuses a bundle made with a different master key unless --force.

  gatehouse verify
      Print the master key fingerprint and check that it decrypts the data.

Passphrases come from the environment variable named by --passphrase-env, or
from a prompt on a TTY. They are never accepted as a flag value.
Data dir: GATEHOUSE_DATA_DIR (default /data).
Exit codes: 0 ok, 1 failure, 2 key mismatch, 3 server is running.`;

class CliExit extends Error {
  code: number;
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

const fail = (message: string, code = 1): never => {
  throw new CliExit(code, message);
};

function msgOf(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  return m.split("\n")[0];
}

// ── argument parsing ──────────────────────────────────

type Parsed = { values: Record<string, string>; flags: Set<string>; help: boolean };

function parseArgs(args: string[], valueOpts: string[], flagOpts: string[]): Parsed {
  const values: Record<string, string> = {};
  const flags = new Set<string>();
  let help = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--help" || a === "-h") {
      help = true;
      continue;
    }
    if (!a.startsWith("--")) {
      // Never echo it: it may be a passphrase typed in the wrong place.
      fail(`unexpected argument at position ${i + 1}. See gatehouse --help.`);
    }
    const eq = a.indexOf("=");
    const name = eq === -1 ? a : a.slice(0, eq);
    if (name === "--passphrase") {
      fail("passphrases are never accepted as a flag value. Use --passphrase-env VAR or run on a TTY to be prompted.");
    }
    if (valueOpts.includes(name)) {
      if (name in values) fail(`${name} given more than once`);
      let v: string | undefined;
      if (eq !== -1) v = a.slice(eq + 1);
      else {
        v = args[i + 1];
        if (v === undefined || v.startsWith("--")) fail(`${name} needs a value`);
        i++;
      }
      if (!v) fail(`${name} needs a value`);
      values[name] = v as string;
    } else if (flagOpts.includes(name) && eq === -1) {
      flags.add(name);
    } else {
      fail(`unknown option ${name}. See gatehouse --help.`);
    }
  }
  return { values, flags, help };
}

// ── helpers ───────────────────────────────────────────

function dataDirOf(io: CliIo): string {
  return io.env.GATEHOUSE_DATA_DIR || "/data";
}

function envKeyIsSet(io: CliIo): boolean {
  const k = io.env.GATEHOUSE_MASTER_KEY;
  return k !== undefined && k.trim() !== "";
}

function scryptLogN(io: CliIo): number {
  const raw = io.env.GATEHOUSE_BUNDLE_SCRYPT_LOGN;
  if (!raw || !/^\d+$/.test(raw.trim())) return 17;
  return Math.min(20, Math.max(10, parseInt(raw.trim(), 10)));
}

function loadKey(io: CliIo): Buffer {
  try {
    return resolveMasterKey({
      envKey: io.env.GATEHOUSE_MASTER_KEY,
      dataDir: dataDirOf(io),
      allowGenerate: false,
      log: io.err,
    }).key;
  } catch (e) {
    if (e instanceof MasterKeyError) {
      return fail(e.code === "missing" ? `no master key: ${e.message}` : `invalid master key: ${e.message}`);
    }
    throw e;
  }
}

async function readPassphrase(io: CliIo, envName: string | undefined, confirm: boolean): Promise<string> {
  if (envName !== undefined) {
    // Never echo the name back: a passphrase pasted here would leak.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName)) {
      fail("--passphrase-env takes the NAME of an environment variable that holds the passphrase, not the passphrase itself");
    }
    const v = io.env[envName];
    if (!v) fail("the environment variable named by --passphrase-env is unset or empty");
    return v as string;
  }
  if (!io.isTTY || !io.prompt) {
    fail("no passphrase source: pass --passphrase-env VAR, or run on a TTY to be prompted");
  }
  const ask = async (label: string): Promise<string> => {
    try {
      return await io.prompt!(label);
    } catch (e) {
      return fail(`passphrase prompt failed: ${msgOf(e)}`);
    }
  };
  const p = await ask("Passphrase: ");
  if (!p) fail("empty passphrase");
  if (confirm) {
    const again = await ask("Repeat passphrase: ");
    if (again !== p) fail("passphrases do not match");
  }
  return p;
}

function stampOf(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z").replace(/[-:]/g, "");
}

/** First free `${base}`, `${base}-2`, `${base}-3`, ... */
function freePath(base: string): string {
  if (!existsSync(base) && !existsSync(`${base}-wal`)) return base;
  for (let n = 2; ; n++) {
    const p = `${base}-${n}`;
    if (!existsSync(p) && !existsSync(`${p}-wal`)) return p;
  }
}

function safeVerify(dbPath: string, key: Buffer): { result: VerifyResult | null; error: string | null } {
  let db;
  try {
    db = openReadonly(dbPath);
    return { result: verifyVault(db, key), error: null };
  } catch (e) {
    return { result: null, error: msgOf(e) };
  } finally {
    try { db?.close(); } catch {}
  }
}

function describeVerify(r: VerifyResult): string {
  if (r.tested === "none") return "ok (no encrypted rows to test, key loaded)";
  const what = r.tested === "secret" ? "a secret" : "a dynamic secret config";
  return r.ok ? `ok (decrypted ${what})` : `FAILED: the key does not decrypt ${what}`;
}

function formatCounts(counts: Record<string, number>): string {
  return Object.entries(counts)
    .map(([t, n]) => `${t}=${n}`)
    .join(" ");
}

// ── commands ──────────────────────────────────────────

async function cmdBackup(args: string[], io: CliIo): Promise<number> {
  const p = parseArgs(args, ["--out"], []);
  if (p.help) return usage(io, 0);
  const out = p.values["--out"] ?? fail("backup needs --out FILE");
  const dbPath = join(dataDirOf(io), DB_FILE_NAME);
  if (!existsSync(dbPath)) fail(`no database at ${dbPath}`);
  const outPath = resolve(out);
  try {
    snapshotTo(dbPath, outPath);
    chmodSync(outPath, 0o600);
  } catch (e) {
    fail(`backup failed: ${msgOf(e)}`);
  }
  io.out(`wrote ${outPath}`);
  io.out(
    "remember to back up your master key separately (or use `gatehouse export` for a self-contained, passphrase-protected backup)."
  );
  return 0;
}

async function cmdExport(args: string[], io: CliIo): Promise<number> {
  const p = parseArgs(args, ["--out", "--passphrase-env"], ["--no-key"]);
  if (p.help) return usage(io, 0);
  const out = p.values["--out"] ?? fail("export needs --out FILE");
  const outPath = resolve(out);
  const includeKey = !p.flags.has("--no-key");
  if (existsSync(outPath)) fail(`output file already exists: ${outPath}`);
  const dbPath = join(dataDirOf(io), DB_FILE_NAME);
  if (!existsSync(dbPath)) fail(`no database at ${dbPath}`);
  const masterKey = loadKey(io);

  const passphrase = await readPassphrase(io, p.values["--passphrase-env"], true);
  if ([...passphrase.normalize("NFC")].length < MIN_PASSPHRASE) {
    fail(`passphrase is too short: use at least ${MIN_PASSPHRASE} characters`);
  }

  // The snapshot is a plaintext-structure copy of the vault: keep it out of
  // the data dir, in a private temp dir, and always delete it.
  const tmp = mkdtempSync(join(tmpdir(), "gatehouse-export-"));
  let bundle: Uint8Array;
  let counts: Record<string, number>;
  try {
    const snap = join(tmp, "snapshot.db");
    try {
      snapshotTo(dbPath, snap);
    } catch (e) {
      fail(`export failed: ${msgOf(e)}`);
    }
    counts = tableRowCounts(snap);
    if (masterKey.length !== 32) {
      fail(
        `export failed: the master key is ${masterKey.length} bytes, not 32 bytes (GATEHOUSE_MASTER_KEY is not 64-char hex). Re-key the vault before exporting.`
      );
    }
    // Never seal (or describe) a key that does not decrypt the data, e.g. a
    // stale master.key after a rotation. An empty vault (tested "none") passes.
    const v = safeVerify(snap, masterKey);
    if (!v.result) fail(`export failed: could not check the master key against the vault: ${v.error}`);
    if (!v.result!.ok) {
      fail(
        "export failed: the resolved master key does not decrypt this vault. Pass the right key (for Docker: -e GATEHOUSE_MASTER_KEY)."
      );
    }
    try {
      bundle = sealBundle({
        db: new Uint8Array(readFileSync(snap)),
        passphrase,
        masterKey,
        includeKey,
        createdAt: (io.now ?? (() => new Date()))().toISOString(),
        rowCounts: counts,
        scryptLogN: scryptLogN(io),
      });
    } catch (e) {
      fail(`export failed: ${msgOf(e)}`);
    }
    writeExclusive(outPath, bundle!);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  io.out(`wrote ${outPath}`);
  io.out(`key fingerprint: ${keyFingerprint(masterKey)}`);
  io.out(`rows: ${formatCounts(counts!)}`);
  if (includeKey) {
    io.out("this bundle includes the master key: the file plus its passphrase recovers the whole vault. Store them apart.");
  } else {
    io.out("this bundle does NOT include the master key: restoring it needs the same key, escrowed separately.");
  }
  return 0;
}

/** Create path exclusively with mode 0600; remove a partial file this call created. */
function writeExclusive(path: string, data: Uint8Array): void {
  let fd: number;
  try {
    fd = openSync(path, "wx", 0o600);
  } catch (e) {
    return fail(`cannot write ${path}: ${msgOf(e)}`);
  }
  try {
    let off = 0;
    while (off < data.length) off += writeSync(fd, data, off, data.length - off);
    fsyncSync(fd);
    closeSync(fd);
    chmodSync(path, 0o600);
  } catch (e) {
    try { closeSync(fd); } catch {}
    try { unlinkSync(path); } catch {}
    fail(`cannot write ${path}: ${msgOf(e)}`);
  }
}

const MISMATCH_UNSEALED =
  "this backup was made with a different master key. Set GATEHOUSE_MASTER_KEY to the matching key, " +
  "or restore from a sealed export, or pass --force to restore the data anyway (secrets will be undecryptable).";
const MISMATCH_SEALED =
  "GATEHOUSE_MASTER_KEY is set to a different key than this backup carries. Unset it, or set it to the backup's key.";

async function cmdImport(args: string[], io: CliIo): Promise<number> {
  const p = parseArgs(args, ["--in", "--passphrase-env"], ["--force"]);
  if (p.help) return usage(io, 0);
  const inFile = p.values["--in"] ?? fail("import needs --in FILE");
  const force = p.flags.has("--force");
  const dataDir = resolve(dataDirOf(io));
  const dbPath = join(dataDir, DB_FILE_NAME);

  // 1. Never touch a db a running server holds open.
  if (isServerLive(dataDir)) {
    fail("the Gatehouse server is running on this data dir. Stop it, then run import again", 3);
  }

  // 2. Open the bundle. Nothing is written until step 5.
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(readFileSync(resolve(inFile)));
  } catch (e) {
    return fail(`cannot read ${resolve(inFile)}: ${msgOf(e)}`);
  }
  const passphrase = await readPassphrase(io, p.values["--passphrase-env"], false);
  let opened: ReturnType<typeof openBundle>;
  try {
    opened = openBundle(bytes, passphrase);
  } catch (e) {
    if (e instanceof BundleError) return fail(`import failed: ${e.message}`);
    return fail(`import failed: ${msgOf(e)}`);
  }
  const { header, db, masterKey: bundledKey } = opened;
  if (db.length < SQLITE_MAGIC.length || new TextDecoder().decode(db.subarray(0, SQLITE_MAGIC.length)) !== SQLITE_MAGIC) {
    fail("import failed: the bundle does not contain a SQLite database");
  }

  // 3. Pick the key the restored vault will be read with.
  let targetKey: Buffer | null;
  let envOverrides = false; // --force past a conflicting env key on a sealed bundle
  const envSet = envKeyIsSet(io);
  if (bundledKey) {
    targetKey = bundledKey;
    if (envSet) {
      const envKey = loadKey(io);
      if (keyFingerprint(envKey) !== header.key_fingerprint) {
        if (!force) fail(MISMATCH_SEALED, 2);
        envOverrides = true;
        io.err(
          "WARNING: --force: GATEHOUSE_MASTER_KEY differs from the backup's key and wins at boot, so the restored secrets will not decrypt. The backup's key is not written to master.key."
        );
      }
    }
  } else {
    let resolved: Buffer | null = null;
    try {
      resolved = resolveMasterKey({ envKey: io.env.GATEHOUSE_MASTER_KEY, dataDir, allowGenerate: false, log: io.err }).key;
    } catch (e) {
      if (!(e instanceof MasterKeyError)) throw e;
      if (e.code !== "missing") fail(`invalid master key: ${e.message}`);
    }
    if (!resolved || keyFingerprint(resolved) !== header.key_fingerprint) {
      if (!force) fail(MISMATCH_UNSEALED, 2);
      io.err("WARNING: --force: restoring with a master key that does not match this backup. Secrets will not decrypt.");
    }
    targetKey = resolved;
  }

  // 4 to 6. Swap the db in, rolling back on any failure.
  const willWriteKey = bundledKey !== null && !envSet;
  const { preImport } = _swapIntoPlace({
    dataDir,
    db,
    stamp: stampOf((io.now ?? (() => new Date()))()),
    keyHex: willWriteKey ? bundledKey!.toString("hex") : null,
    keyFingerprint: header.key_fingerprint,
    log: io.err,
    isLive: () => isServerLive(dataDir),
  });

  // 7. Verify the restored vault and report.
  io.out(`restored ${dbPath} from ${resolve(inFile)} (made ${header.created_at}, gatehouse ${header.gatehouse_version})`);
  try {
    const counts = tableRowCounts(dbPath);
    io.out(`rows: ${formatCounts(counts)}`);
    if (formatCounts(counts) !== formatCounts(header.row_counts)) {
      io.err("WARNING: row counts differ from the bundle's manifest");
    }
  } catch (e) {
    io.err(`WARNING: could not count rows in the restored database: ${msgOf(e)}`);
  }
  if (preImport) io.out(`previous database kept as ${preImport}`);
  if (willWriteKey) io.out(`master key written to ${join(dataDir, KEY_FILE_NAME)}`);

  if (!targetKey) {
    io.out("key fingerprint: none (no master key available)");
    io.err("verification skipped: no master key. Secrets will not decrypt until the matching key is supplied.");
    return 0; // only reachable with --force
  }
  io.out(`key fingerprint: ${keyFingerprint(targetKey)}`);
  if (envOverrides) {
    // The server will boot with the env key, not the one this data was verified against.
    io.out("verify: SKIPPED. GATEHOUSE_MASTER_KEY overrides the restored key and does not match this data.");
    return 0; // only reachable with --force
  }
  const v = safeVerify(dbPath, targetKey);
  if (v.result && v.result.ok) {
    io.out(`verify: ${describeVerify(v.result)}`);
    return 0;
  }
  const why = v.result ? describeVerify(v.result) : `FAILED: ${v.error}`;
  if (force) {
    io.err(`verify: ${why} (ignored: --force)`);
    return 0;
  }
  io.err(`verify: ${why}. The restored database is in place${preImport ? `; the previous one is ${preImport}` : ""}.`);
  return 1;
}

type SwapOps = {
  renameSync: (from: string, to: string) => void;
  persistKeyFile: typeof persistKeyFile;
  /** Create path and write data to it, fsynced. Test seam. */
  writeFile?: (path: string, data: Uint8Array) => void;
};
const realSwapOps: SwapOps = { renameSync, persistKeyFile };

function writeFsynced(path: string, data: Uint8Array): void {
  const fd = openSync(path, "w", 0o600);
  try {
    let off = 0;
    while (off < data.length) off += writeSync(fd, data, off, data.length - off);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Import steps 4 to 6: write the restored db to a temp file first, then move
 * the previous db aside and the temp file into place back to back, then write
 * master.key for a sealed bundle. On any failure everything is rolled back,
 * and the error says exactly what state the data dir is in.
 *
 * Crash points: before the renames, only gatehouse.db.import-tmp is new and
 * gatehouse.db is untouched. Between the two renames, the previous db is at
 * gatehouse.db.pre-import-STAMP and the restored one at gatehouse.db.import-tmp.
 * After them, the restored db is in place and the previous one is kept.
 * Internal: exported for tests only.
 */
export function _swapIntoPlace(
  a: {
    dataDir: string;
    db: Uint8Array;
    stamp: string;
    keyHex: string | null;
    keyFingerprint: string;
    log: (s: string) => void;
    /** Re-checked right before anything is moved; true refuses with exit 3. */
    isLive?: () => boolean;
  },
  ops: SwapOps = realSwapOps
): { preImport: string | null } {
  const dbPath = join(a.dataDir, DB_FILE_NAME);
  const tmpPath = join(a.dataDir, `${DB_FILE_NAME}.import-tmp`);
  const renames: Array<[string, string]> = []; // [from, to], for rollback
  let createdTmp: string | null = null;
  let restoredDb: string | null = null;
  let preImport: string | null = null;
  try {
    mkdirSync(a.dataDir, { recursive: true });

    // 4. Write and fsync the restored db beside the live one. Nothing else moves yet.
    try {
      (ops.writeFile ?? writeFsynced)(tmpPath, a.db);
    } catch (e) {
      // A partial temp file is ours to remove; anything else at that path is not.
      try { if (statSync(tmpPath).isFile()) createdTmp = tmpPath; } catch {}
      throw e;
    }
    createdTmp = tmpPath;

    // A server may have started while the bundle was being decrypted.
    if (a.isLive?.()) {
      fail("the Gatehouse server started on this data dir during the import. Stop it, then run import again", 3);
    }

    // 5. Keep the previous db (and its WAL, which may hold committed pages),
    // clear stale sidecars, and move the restored db into place.
    if (existsSync(dbPath)) {
      preImport = freePath(join(a.dataDir, `${DB_FILE_NAME}.pre-import-${a.stamp}`));
      ops.renameSync(dbPath, preImport);
      renames.push([dbPath, preImport]);
      if (existsSync(`${dbPath}-wal`)) {
        ops.renameSync(`${dbPath}-wal`, `${preImport}-wal`);
        renames.push([`${dbPath}-wal`, `${preImport}-wal`]);
      }
    }
    rmSync(`${dbPath}-wal`, { force: true });
    rmSync(`${dbPath}-shm`, { force: true });
    ops.renameSync(tmpPath, dbPath);
    createdTmp = null;
    restoredDb = dbPath;
    fsyncDir(a.dataDir);

    // 6. A sealed bundle's key goes to master.key when env does not override it.
    if (a.keyHex) {
      const keyPath = join(a.dataDir, KEY_FILE_NAME);
      if (existsSync(keyPath) && !keyFileMatches(keyPath, a.keyFingerprint)) {
        const keep = freePath(join(a.dataDir, `${KEY_FILE_NAME}.pre-import-${a.stamp}`));
        ops.renameSync(keyPath, keep);
        renames.push([keyPath, keep]);
        a.log(`the previous master.key was kept as ${keep}`);
      }
      if (!existsSync(keyPath)) {
        const res = ops.persistKeyFile(a.dataDir, keyPath, a.keyHex);
        if (!res.ok) fail(`cannot write ${keyPath}: ${"error" in res ? res.error : "file exists"}`);
      }
    }
    return { preImport };
  } catch (e) {
    const cause = e instanceof CliExit ? e.message : `import failed: ${msgOf(e)}`;
    const problems = _rollbackImport({ createdTmp, restoredDb, renames }, ops.renameSync);
    if (problems.length === 0) throw new CliExit(e instanceof CliExit ? e.code : 1, `${cause}. Nothing was changed.`);
    throw new CliExit(1, `${cause}. rollback incomplete: ${problems.join("; ")}`);
  }
}

/**
 * Undo import steps 4 to 6. The restored db is reproducible from the bundle;
 * the previous files are not, so every failure to put one back is reported
 * with its real location. Returns those problems; empty means fully undone.
 * Internal: exported for tests only.
 */
export function _rollbackImport(
  st: { createdTmp: string | null; restoredDb: string | null; renames: Array<[string, string]> },
  rename: (from: string, to: string) => void = renameSync
): string[] {
  const problems: string[] = [];
  if (st.createdTmp) {
    try { rmSync(st.createdTmp, { force: true }); } catch (e) {
      problems.push(`could not remove ${st.createdTmp} (${msgOf(e)}); delete it`);
    }
  }
  let restoredLeft: string | null = null;
  if (st.restoredDb) {
    try { rmSync(st.restoredDb, { force: true }); } catch (e) {
      restoredLeft = msgOf(e);
    }
  }
  for (const [from, to] of [...st.renames].reverse()) {
    try {
      rename(to, from);
      // Putting the previous db back replaces a restored db that could not be removed.
      if (from === st.restoredDb) restoredLeft = null;
    } catch (e) {
      const what = from.endsWith(KEY_FILE_NAME) ? "previous master key" : from.endsWith("-wal") ? "previous database WAL" : "previous database";
      problems.push(`${what} is at ${to}; move it back to ${from} before starting the server (${msgOf(e)})`);
    }
  }
  if (restoredLeft !== null) {
    problems.unshift(`the restored database is still at ${st.restoredDb} (${restoredLeft})`);
  }
  return problems;
}

function keyFileMatches(keyPath: string, fingerprint: string): boolean {
  try {
    const hex = readFileSync(keyPath, "utf8").trim();
    if (hex.length < 64 || !/^[0-9a-fA-F]+$/.test(hex)) return false;
    return keyFingerprint(Buffer.from(hex, "hex")) === fingerprint;
  } catch {
    return false;
  }
}

function fsyncDir(dir: string): void {
  try {
    const fd = openSync(dir, "r");
    try { fsyncSync(fd); } finally { closeSync(fd); }
  } catch {
    // not supported on every platform; the file itself was fsynced
  }
}

async function cmdVerify(args: string[], io: CliIo): Promise<number> {
  const p = parseArgs(args, [], []);
  if (p.help) return usage(io, 0);
  const key = loadKey(io);
  const fp = keyFingerprint(key);
  io.out(`key fingerprint: ${fp}`);
  const dbPath = join(dataDirOf(io), DB_FILE_NAME);
  if (!existsSync(dbPath)) fail(`no database at ${dbPath}`);
  const v = safeVerify(dbPath, key);
  if (!v.result) fail(`verify: FAILED: ${v.error}`);
  if (!v.result!.ok) fail(`verify: ${describeVerify(v.result!)}`);
  io.out(`verify: ${describeVerify(v.result!)}`);
  return 0;
}

function usage(io: CliIo, code: number): number {
  io.err(USAGE);
  return code;
}

export async function runCli(argv: string[], io: CliIo): Promise<number> {
  const [cmd, ...rest] = argv;
  try {
    switch (cmd) {
      case "backup":
        return await cmdBackup(rest, io);
      case "export":
        return await cmdExport(rest, io);
      case "import":
        return await cmdImport(rest, io);
      case "verify":
        return await cmdVerify(rest, io);
      case "--help":
      case "-h":
      case "help":
        return usage(io, 0);
      default:
        return usage(io, 1);
    }
  } catch (e) {
    if (e instanceof CliExit) {
      io.err(`gatehouse ${cmd}: ${e.message}`);
      return e.code;
    }
    io.err(`gatehouse ${cmd}: unexpected error: ${msgOf(e)}`);
    return 1;
  }
}

// ── process wiring ────────────────────────────────────

/**
 * Read a line from the TTY without echoing it. Fails closed: if echo cannot
 * be turned off, it rejects before the user types anything.
 */
function promptHidden(label: string): Promise<string> {
  return new Promise((resolvePrompt, reject) => {
    const stdin = process.stdin;
    try {
      if (typeof stdin.setRawMode !== "function") throw new Error("no raw mode");
      stdin.setRawMode(true);
    } catch {
      reject(new Error("cannot turn off echo on this terminal. Use --passphrase-env VAR instead"));
      return;
    }
    process.stderr.write(label);
    let buf = "";
    const done = () => {
      stdin.off("data", onData);
      try { stdin.setRawMode?.(false); } catch {}
      stdin.pause();
      process.stderr.write("\n");
    };
    const onData = (chunk: Buffer | string) => {
      for (const ch of chunk.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          done();
          resolvePrompt(buf);
          return;
        }
        if (ch === "\u0003" || ch === "\u0004") {
          done();
          reject(new Error("cancelled"));
          return;
        }
        if (ch === "\u007f" || ch === "\b") {
          buf = Array.from(buf).slice(0, -1).join("");
          continue;
        }
        buf += ch;
      }
    };
    stdin.resume();
    stdin.on("data", onData);
  });
}

const realIo: CliIo = {
  env: process.env,
  out: (s) => process.stdout.write(s + "\n"),
  err: (s) => process.stderr.write(s + "\n"),
  isTTY: Boolean(process.stdin.isTTY),
  prompt: promptHidden,
};

if (import.meta.main) {
  // Backups, exports and temp files are never group or world readable.
  process.umask(0o077);
  process.exit(await runCli(process.argv.slice(2), realIo));
}
