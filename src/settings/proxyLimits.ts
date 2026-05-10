import type { Database } from "bun:sqlite";
import type { AuditLog } from "../audit/logger";

export interface ProxyLimits {
  max_timeout_ms: number;
  max_body_bytes: number;
}

/** Defaults applied when no settings row exists or the stored value is invalid. */
export const DEFAULT_PROXY_LIMITS: ProxyLimits = {
  max_timeout_ms: 120_000,          // 120 seconds
  max_body_bytes: 10 * 1024 * 1024, // 10 MiB
};

/**
 * Hard ceilings. The Settings UI clamps inputs to these values; the API and
 * the validator both reject anything above them. Operators cannot set higher.
 */
export const PROXY_LIMITS_HARD_CEILING: ProxyLimits = {
  max_timeout_ms: 30 * 60 * 1000,    // 30 minutes
  max_body_bytes: 100 * 1024 * 1024, // 100 MiB
};

/** Hard floors. */
export const PROXY_LIMITS_HARD_FLOOR: ProxyLimits = {
  max_timeout_ms: 1_000, // 1 second
  max_body_bytes: 1_024, // 1 KiB
};

export type ValidationResult =
  | { ok: true; value: ProxyLimits }
  | { ok: false; errors: string[] };

/**
 * Validate a candidate ProxyLimits object. Both fields must be positive
 * integers within the hard floor/ceiling range. Returns explicit errors so
 * the API can surface them to admins.
 */
export function validateProxyLimits(input: unknown): ValidationResult {
  const errors: string[] = [];
  if (input === null || typeof input !== "object") {
    return { ok: false, errors: ["body must be an object"] };
  }
  const o = input as Partial<ProxyLimits>;
  const t = o.max_timeout_ms;
  const b = o.max_body_bytes;

  if (typeof t !== "number" || !Number.isInteger(t)) {
    errors.push("max_timeout_ms must be an integer");
  } else if (t < PROXY_LIMITS_HARD_FLOOR.max_timeout_ms) {
    errors.push(`max_timeout_ms must be >= ${PROXY_LIMITS_HARD_FLOOR.max_timeout_ms} (1s)`);
  } else if (t > PROXY_LIMITS_HARD_CEILING.max_timeout_ms) {
    errors.push(`max_timeout_ms must be <= ${PROXY_LIMITS_HARD_CEILING.max_timeout_ms} (30 min)`);
  }

  if (typeof b !== "number" || !Number.isInteger(b)) {
    errors.push("max_body_bytes must be an integer");
  } else if (b < PROXY_LIMITS_HARD_FLOOR.max_body_bytes) {
    errors.push(`max_body_bytes must be >= ${PROXY_LIMITS_HARD_FLOOR.max_body_bytes} (1 KiB)`);
  } else if (b > PROXY_LIMITS_HARD_CEILING.max_body_bytes) {
    errors.push(`max_body_bytes must be <= ${PROXY_LIMITS_HARD_CEILING.max_body_bytes} (100 MiB)`);
  }

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, value: { max_timeout_ms: t as number, max_body_bytes: b as number } };
}

// Module-level cache. The proxy is in the hot path; we don't query SQLite per
// request. Invalidated by setProxyLimits and by _resetProxyLimitsCacheForTests.
let cachedLimits: ProxyLimits | null = null;

/** Test-only: drop the cache so a fresh DB read is required. */
export function _resetProxyLimitsCacheForTests(): void {
  cachedLimits = null;
}

/**
 * Read current proxy limits. Returns DEFAULT_PROXY_LIMITS if no row exists,
 * the row is malformed, or the stored value fails validation. Cached after
 * the first read until setProxyLimits or _resetProxyLimitsCacheForTests.
 */
export function getProxyLimits(db: Database): ProxyLimits {
  if (cachedLimits !== null) return cachedLimits;

  const row = db.query("SELECT value FROM settings WHERE key = 'proxy_limits'").get() as
    | { value: string }
    | null;

  if (!row) {
    cachedLimits = DEFAULT_PROXY_LIMITS;
    return cachedLimits;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(row.value);
  } catch {
    cachedLimits = DEFAULT_PROXY_LIMITS;
    return cachedLimits;
  }

  const validated = validateProxyLimits(parsed);
  cachedLimits = validated.ok ? validated.value : DEFAULT_PROXY_LIMITS;
  return cachedLimits;
}

export type SetResult =
  | { ok: true; previous: ProxyLimits; current: ProxyLimits }
  | { ok: false; errors: string[] };

/**
 * Validate, persist, audit, and invalidate the cache. Returns explicit errors
 * if validation fails (no DB write, no audit row).
 */
export function setProxyLimits(
  db: Database,
  audit: AuditLog,
  identity: string,
  source_ip: string | null,
  input: unknown
): SetResult {
  const validated = validateProxyLimits(input);
  if (!validated.ok) return { ok: false, errors: validated.errors };

  const previous = getProxyLimits(db);
  const next = validated.value;

  db.query(
    `INSERT INTO settings (key, value) VALUES ('proxy_limits', ?)
     ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')`
  ).run(JSON.stringify(next), JSON.stringify(next));

  // Invalidate cache so the next getProxyLimits reads the new row.
  cachedLimits = null;

  audit.log({
    identity,
    action: "settings.proxy_limits.update",
    source_ip: source_ip || undefined,
    metadata: {
      old_max_timeout_ms: String(previous.max_timeout_ms),
      new_max_timeout_ms: String(next.max_timeout_ms),
      old_max_body_bytes: String(previous.max_body_bytes),
      new_max_body_bytes: String(next.max_body_bytes),
    },
  });

  return { ok: true, previous, current: next };
}
