import type { Database } from "bun:sqlite";
import { createHash } from "crypto";
import { ipMatchesAllowlist } from "../auth/cidr";
import type { BearerResult } from "../auth/verifyBearer";

export const PASSTHROUGH_KEY_PREFIX = "gatehouse_pt_";

const INVALID: BearerResult = { ok: false, status: 401, error: "Invalid credentials" };

/** `gatehouse_pt_` + base64url (no padding) of `role_id:secret_id`. */
export function encodePassthroughKey(roleId: string, secretId: string): string {
  return PASSTHROUGH_KEY_PREFIX + Buffer.from(`${roleId}:${secretId}`, "utf8").toString("base64url");
}

/** Split on the first colon. Returns null for anything that is not canonical. */
export function parsePassthroughKey(key: string): { roleId: string; secretId: string } | null {
  if (typeof key !== "string" || !key.startsWith(PASSTHROUGH_KEY_PREFIX)) return null;
  const body = key.slice(PASSTHROUGH_KEY_PREFIX.length);
  if (!body) return null;
  // Node's decoder skips invalid characters, so insist on an exact round trip.
  const bytes = Buffer.from(body, "base64url");
  if (bytes.toString("base64url") !== body) return null;
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) return null; // not valid UTF-8
  const i = text.indexOf(":");
  if (i <= 0 || i === text.length - 1) return null;
  return { roleId: text.slice(0, i), secretId: text.slice(i + 1) };
}

interface CacheEntry {
  secretHash: string;
  expiresAt: number;
}

// sha256(key) -> entry. Never holds the key or the secret_id. Map iteration
// order is insertion order, so the first key is the oldest.
const cache = new Map<string, CacheEntry>();

export function _resetPassthroughKeyCacheForTests(): void {
  cache.clear();
}

/**
 * Verify a passthrough key the way /v1/auth/approle/login verifies a
 * role_id/secret_id pair. Does not touch the login limiter (the caller does)
 * and never logs the key.
 */
export function createPassthroughKeyVerifier(
  db: Database,
  opts: { ttlMs?: number; maxEntries?: number; now?: () => number } = {}
): (key: string, sourceIp: string) => Promise<BearerResult> {
  const ttlMs = opts.ttlMs ?? 300_000;
  const maxEntries = opts.maxEntries ?? 1000;
  const now = opts.now ?? Date.now;

  return async (key, sourceIp) => {
    const parsed = parsePassthroughKey(key);
    if (!parsed) return INVALID;
    const { roleId, secretId } = parsed;

    const role = db.query("SELECT * FROM app_roles WHERE role_id = ?").get(roleId) as any;
    const cacheKey = createHash("sha256").update(key).digest("hex");
    if (!role) {
      cache.delete(cacheKey);
      return INVALID;
    }

    const entry = cache.get(cacheKey);
    const hit = !!entry && now() < entry.expiresAt && entry.secretHash === role.secret_hash;
    if (!hit) {
      if (entry) cache.delete(cacheKey);
      if (!(await Bun.password.verify(secretId, role.secret_hash))) return INVALID;
    }

    // Suspension and the allowlist are checked after the secret is proven, and
    // on every request, from the row. Never cached.
    if (role.suspended) {
      return { ok: false, status: 403, error: "AppRole is suspended" };
    }
    let allowlist: string[];
    let policies: string[];
    try {
      allowlist = role.ip_allowlist ? JSON.parse(role.ip_allowlist) : [];
      policies = JSON.parse(role.policies);
      if (!Array.isArray(allowlist) || !Array.isArray(policies)) throw new Error("shape");
    } catch {
      return { ok: false, status: 403, error: "AppRole configuration is unreadable" };
    }
    if (allowlist.length > 0 && !ipMatchesAllowlist(sourceIp || "unknown", allowlist)) {
      return { ok: false, status: 403, error: "Source IP not permitted for this AppRole" };
    }

    if (!hit) {
      db.query("UPDATE app_roles SET last_used = datetime('now') WHERE role_id = ?").run(roleId);
      while (cache.size >= maxEntries) {
        const oldest = cache.keys().next().value;
        if (oldest === undefined) break;
        cache.delete(oldest);
      }
      cache.set(cacheKey, { secretHash: role.secret_hash, expiresAt: now() + ttlMs });
    }

    return {
      ok: true,
      auth: { identity: `approle:${role.display_name}`, policies, source: "approle", role_id: roleId },
    };
  };
}
