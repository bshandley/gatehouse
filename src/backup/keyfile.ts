import { randomBytes } from "crypto";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  constants as fsConstants,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeSync,
} from "fs";
import { join } from "path";

export const KEY_FILE_NAME = "master.key";
/** The new key during a rotation, before it replaces master.key. */
export const NEXT_KEY_FILE_NAME = "master.key.next";
const DB_FILE_NAME = "gatehouse.db";
const RULE = "=".repeat(60);

export type MasterKeySource = "env" | "file" | "generated" | "generated-unpersisted";

export class MasterKeyError extends Error {
  code: "missing" | "invalid_env" | "invalid_file";
  constructor(code: MasterKeyError["code"], message: string) {
    super(message);
    this.name = "MasterKeyError";
    this.code = code;
  }
}

function parseHexKey(raw: string): Buffer | null {
  const hex = raw.trim();
  if (hex.length < 64 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  return Buffer.from(hex, "hex");
}

function readKeyFile(keyPath: string): Buffer {
  const key = parseHexKey(readFileSync(keyPath, "utf8"));
  if (!key) {
    throw new MasterKeyError("invalid_file", `${keyPath} does not contain a valid 64-char hex key`);
  }
  return key;
}

export type PersistResult = { ok: true } | { ok: false; exists: true } | { ok: false; exists: false; error: string };

type WriteFn = (fd: number, data: Uint8Array) => void;
const writeAll: WriteFn = (fd, data) => {
  let off = 0;
  while (off < data.length) off += writeSync(fd, data, off, data.length - off);
};

/**
 * Exclusively create path (0600) holding hex, fsynced. Throws on any failure;
 * a file this call created is removed first. A file that already existed
 * (EEXIST) is never touched.
 */
function writeKeyExclusive(path: string, hex: string, write: WriteFn): void {
  const fd = openSync(path, "wx", 0o600);
  try {
    write(fd, Buffer.from(hex + "\n", "utf8"));
    fsyncSync(fd);
    closeSync(fd);
    chmodSync(path, 0o600);
  } catch (e) {
    try { closeSync(fd); } catch {}
    try { unlinkSync(path); } catch {}
    throw e;
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

/**
 * Exclusively create the key file (0600). Removes a half-written file this call created.
 * `write` is a test seam for simulating a failed write.
 */
export function persistKeyFile(dataDir: string, keyPath: string, hex: string, write: WriteFn = writeAll): PersistResult {
  try {
    mkdirSync(dataDir, { recursive: true });
    writeKeyExclusive(keyPath, hex, write);
    fsyncDir(dataDir);
    return { ok: true };
  } catch (e: any) {
    if (e?.code === "EEXIST") return { ok: false, exists: true };
    return { ok: false, exists: false, error: e?.message ?? String(e) };
  }
}

// ── key rotation: master.key.next, then swap ─────────────

/**
 * Rotation step 1: write the new key to master.key.next (0600, fsynced),
 * replacing a leftover from an earlier failed rotation. Throws on failure and
 * leaves no partial file. Returns the path written.
 */
export function writeNextKeyFile(dataDir: string, hex: string, write: WriteFn = writeAll): string {
  const nextPath = join(dataDir, NEXT_KEY_FILE_NAME);
  rmSync(nextPath, { force: true });
  writeKeyExclusive(nextPath, hex, write);
  fsyncDir(dataDir);
  return nextPath;
}

/** Remove master.key.next (rotation aborted before any data changed). Never throws. */
export function discardNextKeyFile(dataDir: string): void {
  try { rmSync(join(dataDir, NEXT_KEY_FILE_NAME), { force: true }); } catch {}
}

export class KeyInstallError extends Error {
  /** The file that holds the new key. */
  newKeyPath: string;
  constructor(newKeyPath: string, message: string) {
    super(message);
    this.name = "KeyInstallError";
    this.newKeyPath = newKeyPath;
  }
}

type InstallOps = {
  linkSync: (existing: string, newPath: string) => void;
  copyFileSync: (src: string, dest: string, mode: number) => void;
  renameSync: (from: string, to: string) => void;
};

/**
 * Rotation step 3: keep the current master.key as master.key.pre-rotate-STAMP
 * and move master.key.next into place.
 *
 * The previous key is kept by a hard link (or an exclusive 0600 copy where
 * links are unsupported), then master.key.next is renamed over master.key in
 * one atomic step. There is no moment without a master.key: a crash at any
 * point leaves either the old key or the new key there, and the new key in
 * master.key.next until the final rename.
 *
 * Throws KeyInstallError naming the file that holds the new key.
 */
export function installNextKeyFile(
  dataDir: string,
  stamp: string,
  opsIn: Partial<InstallOps> = {}
): { keyPath: string; previous: string | null } {
  const ops: InstallOps = { linkSync, copyFileSync, renameSync, ...opsIn };
  const keyPath = join(dataDir, KEY_FILE_NAME);
  const nextPath = join(dataDir, NEXT_KEY_FILE_NAME);
  let previous: string | null = null;
  if (existsSync(keyPath)) {
    previous = join(dataDir, `${KEY_FILE_NAME}.pre-rotate-${stamp}`);
    for (let n = 2; existsSync(previous); n++) previous = join(dataDir, `${KEY_FILE_NAME}.pre-rotate-${stamp}-${n}`);
    try {
      try {
        ops.linkSync(keyPath, previous);
      } catch {
        ops.copyFileSync(keyPath, previous, fsConstants.COPYFILE_EXCL);
        chmodSync(previous, 0o600);
      }
    } catch (e: any) {
      throw new KeyInstallError(
        nextPath,
        `could not keep the previous key as ${previous} (${e?.message ?? e}). ` +
          `${keyPath} still holds the OLD key; the NEW key is in ${nextPath}. ` +
          `Before restarting: rename ${keyPath} to ${keyPath}.old and keep it, then move ${nextPath} to ${keyPath}.`
      );
    }
  }
  try {
    ops.renameSync(nextPath, keyPath);
  } catch (e: any) {
    throw new KeyInstallError(
      nextPath,
      `could not move ${nextPath} to ${keyPath} (${e?.message ?? e}). ` +
        `${keyPath} still holds the OLD key; the NEW key is in ${nextPath}. ` +
        `Before restarting: rename ${keyPath} to ${keyPath}.old and keep it, then move ${nextPath} to ${keyPath}.`
    );
  }
  fsyncDir(dataDir);
  return { keyPath, previous };
}

/** Timestamp for file names: 20261119T123456Z. */
export function fileStamp(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z").replace(/[-:]/g, "");
}

function banner(keyPath: string, dataDir: string, hex: string, persisted: boolean, error?: string): string[] {
  const saved = persisted
    ? ` Saved to: ${keyPath}`
    : ` NOT SAVED: ${dataDir} is not writable${error ? ` (${error})` : ""}. Set GATEHOUSE_MASTER_KEY to this value or the vault is lost on restart.`;
  const lines = [
    RULE,
    " GATEHOUSE GENERATED A NEW MASTER KEY",
    saved,
    "",
    " This key encrypts every secret in this vault.",
    " If you lose it, the data is unrecoverable ciphertext.",
    "",
    " BACK IT UP NOW, somewhere other than this host:",
    `   ${hex}`,
    "",
  ];
  if (persisted) {
    lines.push(
      " Stronger posture: set GATEHOUSE_MASTER_KEY to this value",
      ` in your environment and delete ${keyPath}.`
    );
  }
  lines.push(RULE);
  return lines;
}

/**
 * Resolve the master key: env (always wins), then key file, then first-boot
 * generation on a fresh data dir. Never generates over an existing db.
 */
export function resolveMasterKey(opts: {
  envKey: string | undefined;
  dataDir: string;
  allowGenerate?: boolean;
  log?: (line: string) => void;
}): { key: Buffer; source: MasterKeySource } {
  const { envKey, dataDir } = opts;
  const allowGenerate = opts.allowGenerate ?? true;
  const log = opts.log ?? ((l: string) => console.error(l));

  // Empty or whitespace-only counts as unset: compose's
  // GATEHOUSE_MASTER_KEY=${GATEHOUSE_MASTER_KEY} yields "" when the variable is unset.
  if (envKey !== undefined && envKey.trim() !== "") {
    if (envKey.length < 64) {
      throw new MasterKeyError(
        "invalid_env",
        "GATEHOUSE_MASTER_KEY must be a 64-char hex string, e.g. openssl rand -hex 32"
      );
    }
    // Legacy acceptance: any value of 64+ chars boots exactly as before (untrimmed Buffer.from hex).
    // Trailing whitespace (a newline from a secrets file) decodes fine and is not worth a warning.
    // Leading whitespace is NOT trimmed: the legacy decode stops at it and yields a short or empty
    // key, which must keep its warning.
    const trimmed = envKey.trimEnd();
    if (!/^[0-9a-fA-F]+$/.test(trimmed)) {
      log(
        "WARNING: GATEHOUSE_MASTER_KEY is not valid hex and is being used as the old version used it (decoded up to the first non-hex pair). Export your vault and re-key with a proper 64-char hex key."
      );
    } else if (trimmed.length !== 64) {
      log(
        "WARNING: GATEHOUSE_MASTER_KEY is hex but not 64 characters (32 bytes), and is being used as the old version used it. Export your vault and re-key with a proper 64-char hex key."
      );
    }
    return { key: Buffer.from(envKey, "hex"), source: "env" };
  }

  const keyPath = join(dataDir, KEY_FILE_NAME);
  if (existsSync(keyPath)) {
    const nextPath = join(dataDir, NEXT_KEY_FILE_NAME);
    if (existsSync(nextPath)) {
      log(
        `WARNING: ${nextPath} exists: a master key rotation did not finish. Booting with ${keyPath}. ` +
          `If gatehouse verify fails, data is under the key in ${nextPath}: rename ${keyPath} to ${keyPath}.old and KEEP it ` +
          `(dynamic provider configs may still need the old key), then move ${nextPath} to ${keyPath} and restart.`
      );
    }
    return { key: readKeyFile(keyPath), source: "file" };
  }

  if (existsSync(join(dataDir, DB_FILE_NAME))) {
    throw new MasterKeyError(
      "missing",
      `GATEHOUSE_MASTER_KEY must be set (64-char hex string, e.g. openssl rand -hex 32). ` +
        `${join(dataDir, DB_FILE_NAME)} exists but no key was found in the environment or ${keyPath}`
    );
  }
  if (!allowGenerate) {
    throw new MasterKeyError(
      "missing",
      "GATEHOUSE_MASTER_KEY must be set (64-char hex string, e.g. openssl rand -hex 32)"
    );
  }

  const key = randomBytes(32);
  const hex = key.toString("hex");
  const res = persistKeyFile(dataDir, keyPath, hex);
  if (!res.ok && res.exists) {
    // Another process created master.key after our existence check: use theirs.
    return { key: readKeyFile(keyPath), source: "file" };
  }
  const persisted = res.ok;
  for (const line of banner(keyPath, dataDir, hex, persisted, res.ok ? undefined : (res as any).error)) log(line);
  return { key, source: persisted ? "generated" : "generated-unpersisted" };
}
