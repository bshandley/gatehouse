import { createHash, randomBytes } from "crypto";
import { chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, unlinkSync, writeSync } from "fs";
import { join } from "path";
import type { Database } from "bun:sqlite";

export const BOOTSTRAP_TOKEN_FILE = "bootstrap-root.token";
const RULE = "=".repeat(60);

// SHA-256 of the root token the pre-0.23.0 reference compose file defaulted
// to. Stored as a hash so the literal never appears in src/.
const OLD_DEFAULT_TOKEN_SHA256 = "51f6482245d6f7b245e172c13be91638a253e5258381bc6d2939ada5d60b3136";

export type BootstrapSource = "env" | "file" | "generated" | "generated-unpersisted" | "none";

/** True when an enabled admin user or a non-suspended AppRole holding the "admin" policy exists. */
export function hasAdminPrincipal(db: Database): boolean {
  const user = db.query("SELECT 1 AS x FROM users WHERE role = 'admin' AND enabled = 1 LIMIT 1").get();
  if (user) return true;
  const roles = db.query("SELECT policies FROM app_roles WHERE COALESCE(suspended, 0) = 0").all() as { policies: string | null }[];
  for (const r of roles) {
    try {
      const p = JSON.parse(r.policies ?? "[]");
      if (Array.isArray(p) && p.includes("admin")) return true;
    } catch {
      // malformed policies never grant admin
    }
  }
  return false;
}

function writeExclusive(path: string, data: string): void {
  const fd = openSync(path, "wx", 0o600);
  try {
    let buf = Buffer.from(data, "utf8");
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
    closeSync(fd);
    chmodSync(path, 0o600);
  } catch (e) {
    try { closeSync(fd); } catch {}
    try { unlinkSync(path); } catch {}
    throw e;
  }
}

function banner(path: string, token: string, where: string, persisted: boolean, error?: string): string[] {
  const saved = persisted
    ? ` Saved to: ${path}`
    : ` NOT SAVED: the data directory is not writable${error ? ` (${error})` : ""}. This token is lost on restart.`;
  return [
    RULE,
    " GATEHOUSE BOOTSTRAP ROOT TOKEN",
    saved,
    "",
    `   ${token}`,
    "",
    ` Open ${where} and sign in with this token to create`,
    " your first admin user. It stops working, and this file is",
    " removed, on the first restart after an admin exists.",
    RULE,
  ];
}

/**
 * Decide the root token. Env always wins. With an admin present there is no
 * root token at all (and a stale token file is deleted). Otherwise a one-time
 * token is read from, or generated into, ${dataDir}/bootstrap-root.token.
 */
export function resolveBootstrapRootToken(opts: {
  db: Database;
  dataDir: string;
  envToken: string | undefined;
  /** GATEHOUSE_PUBLIC_URL, or undefined when it is not configured. */
  publicUrl: string | undefined;
  port?: number;
  log?: (line: string) => void;
}): { token: string | null; source: BootstrapSource } {
  const { db, dataDir, envToken } = opts;
  const log = opts.log ?? ((l: string) => console.error(l));
  const where = opts.publicUrl ? opts.publicUrl : `port ${opts.port ?? 3100} on this host`;

  // A whitespace-only value counts as unset. A real env token is used as is.
  if (envToken !== undefined && envToken.trim() !== "") {
    if (createHash("sha256").update(envToken).digest("hex") === OLD_DEFAULT_TOKEN_SHA256) {
      log(RULE);
      log(" WARNING: GATEHOUSE_ROOT_TOKEN is the old compose default.");
      log(" A publicly known root token is active. Anyone who can reach");
      log(" this server has full admin. Replace it with a random value,");
      log(" or remove it once an admin exists, and restart.");
      log(RULE);
    }
    return { token: envToken, source: "env" };
  }

  const path = join(dataDir, BOOTSTRAP_TOKEN_FILE);

  if (hasAdminPrincipal(db)) {
    if (existsSync(path)) {
      try {
        unlinkSync(path);
        log(`[gatehouse] removed stale ${BOOTSTRAP_TOKEN_FILE} (an admin exists)`);
      } catch (e: any) {
        log(`[gatehouse] WARNING: could not remove stale ${path} (${e?.message ?? e}). It is not loaded; delete it by hand.`);
      }
    }
    return { token: null, source: "none" };
  }

  if (existsSync(path)) {
    try {
      const existing = readFileSync(path, "utf8").trim();
      if (/^[0-9a-f]{32}$/.test(existing)) {
        try { chmodSync(path, 0o600); } catch {}
        log(`[gatehouse] bootstrap root token active, read from ${path}. Create an admin user, then restart to retire it.`);
        return { token: existing, source: "file" };
      }
    } catch {
      // unreadable: replace below
    }
    try { unlinkSync(path); } catch {}
  }

  const token = randomBytes(16).toString("hex");
  try {
    mkdirSync(dataDir, { recursive: true });
    writeExclusive(path, token + "\n");
  } catch (e: any) {
    for (const l of banner(path, token, where, false, e?.message ?? String(e))) log(l);
    return { token, source: "generated-unpersisted" };
  }
  for (const l of banner(path, token, where, true)) log(l);
  return { token, source: "generated" };
}
