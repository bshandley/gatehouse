import { Hono } from "hono";
import type { AuditLog } from "../audit/logger";
import type { SecretsEngine } from "../secrets/engine";
import type { PolicyEngine } from "../policy/engine";
import type { AuthContext } from "../auth/middleware";

/**
 * Parse a window string like "7d", "30d", or "24h" into a normalized label
 * and a "since" timestamp. Unparseable input falls back to 7 days. Magnitude
 * is clamped to 365 days so a hostile value cannot widen the scan.
 *
 * The since timestamp is formatted as SQLite's "YYYY-MM-DD HH:MM:SS" (UTC, the
 * same shape datetime('now') writes into audit_log.timestamp). Using the raw
 * ISO "...T...Z" form would make the lexical "timestamp >= since" comparison
 * exclude the entire oldest boundary day, because space sorts before "T".
 */
export function parseWindow(raw: string | undefined): { label: string; since: string } {
  const def = 7 * 24 * 60 * 60 * 1000;
  let ms = def;
  let label = "7d";
  const m = (raw || "").trim().match(/^(\d+)([dh])$/);
  if (m) {
    const n = parseInt(m[1], 10);
    const unit = m[2];
    let candidate = unit === "h" ? n * 60 * 60 * 1000 : n * 24 * 60 * 60 * 1000;
    const maxMs = 365 * 24 * 60 * 60 * 1000;
    if (candidate > maxMs) candidate = maxMs;
    if (candidate > 0) {
      ms = candidate;
      label = `${n}${unit}`;
    }
  }
  const since = new Date(Date.now() - ms)
    .toISOString()
    .replace("T", " ")
    .replace(/\.\d{3}Z$/, "");
  return { label, since };
}

export function statsRouter(
  audit: AuditLog,
  secrets: SecretsEngine,
  policies: PolicyEngine
) {
  const router = new Hono();

  // GET /v1/stats/posture?window=7d - the posture and value view (admin only).
  router.get("/posture", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const { label, since } = parseWindow(c.req.query("window"));

    const redactionCount = audit.sumRedactions(since);
    const blocked = audit.blockedEgress(since);
    const hygiene = secrets.hygieneCounts();

    return c.json({
      redactions: { window: label, count: redactionCount },
      blocked_egress: { window: label, total: blocked.total, by_reason: blocked.by_reason },
      hygiene,
    });
  });

  return router;
}
