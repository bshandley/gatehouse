import { Database } from "bun:sqlite";
import type { EventBus } from "../events/bus";

/**
 * Normalize a caller-supplied `since` value to the shape SQLite's
 * datetime('now') writes into audit_log.timestamp ("YYYY-MM-DD HH:MM:SS").
 * An ISO string ("YYYY-MM-DDTHH:MM:SS.sssZ") would otherwise lose the entire
 * boundary day in a lexical "timestamp >= ?" comparison, because the "T"
 * separator (0x54) sorts after the stored space (0x20). The transform is a
 * no-op on values already in SQLite form, on date-only values, and on the
 * "2000-..." style literals used in tests.
 */
function normalizeSqliteSince(s: string): string {
  return s.replace("T", " ").replace(/\.\d{1,3}/, "").replace(/Z$/, "");
}

export interface AuditEntry {
  identity: string;
  action: string;
  path?: string;
  lease_id?: string;
  source_ip?: string | null;
  metadata?: Record<string, string>;
  success?: boolean;
}

export interface AuditRecord extends AuditEntry {
  id: number;
  timestamp: string;
}

export class AuditLog {
  private db: Database;
  private bus?: EventBus;

  constructor(db: Database, bus?: EventBus) {
    this.db = db;
    this.bus = bus;
  }

  attachBus(bus: EventBus) {
    this.bus = bus;
  }

  log(entry: AuditEntry) {
    const record = {
      identity: entry.identity,
      action: entry.action,
      path: entry.path || null,
      lease_id: entry.lease_id || null,
      source_ip: entry.source_ip || null,
      metadata: JSON.stringify(entry.metadata || {}),
      success: entry.success !== false ? 1 : 0,
    };

    this.db
      .query(
        `INSERT INTO audit_log (identity, action, path, lease_id, source_ip, metadata, success)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
      )
      .run(
        record.identity,
        record.action,
        record.path,
        record.lease_id,
        record.source_ip,
        record.metadata,
        record.success
      );

    const timestamp = new Date().toISOString();

    // Also emit to stdout for container log aggregation
    console.log(
      JSON.stringify({
        type: "audit",
        ...record,
        timestamp,
      })
    );

    // Fan out to SSE subscribers. metadata is re-parsed so consumers get
    // an object (matching the /v1/audit query response shape).
    if (this.bus) {
      this.bus.emit({
        type: "audit",
        record: {
          ...record,
          metadata: JSON.parse(record.metadata),
          success: record.success === 1,
          timestamp,
        },
      });
    }
  }

  query(opts: {
    identity?: string;
    action?: string;
    path?: string;
    since?: string;
    limit?: number;
  }): AuditRecord[] {
    let sql = "SELECT * FROM audit_log WHERE 1=1";
    const params: any[] = [];

    if (opts.identity) {
      sql += " AND identity = ?";
      params.push(opts.identity);
    }
    if (opts.action) {
      sql += " AND action = ?";
      params.push(opts.action);
    }
    if (opts.path) {
      sql += " AND path LIKE ?";
      params.push(`${opts.path}%`);
    }
    if (opts.since) {
      sql += " AND timestamp >= ?";
      params.push(normalizeSqliteSince(opts.since));
    }

    sql += ` ORDER BY timestamp DESC LIMIT ?`;
    params.push(Math.min(Math.max(1, opts.limit || 100), 10000));

    return (this.db.query(sql).all(...params) as any[]).map((r) => ({
      ...r,
      metadata: JSON.parse(r.metadata),
      success: !!r.success,
    }));
  }

  /**
   * Get the configured retention period in days (0 = keep forever).
   */
  getRetention(): { retention_days: number } {
    const row = this.db
      .query("SELECT value FROM settings WHERE key = 'audit_retention_days'")
      .get() as { value: string } | null;
    return { retention_days: row ? parseInt(row.value, 10) : 0 };
  }

  /**
   * Set the retention period in days (0 = keep forever).
   */
  setRetention(days: number) {
    this.db
      .query(
        `INSERT INTO settings (key, value) VALUES ('audit_retention_days', ?)
         ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = datetime('now')`
      )
      .run(String(days), String(days));
  }

  /**
   * Purge audit entries older than the configured retention period.
   * Returns the number of entries deleted.
   */
  purgeExpired(): number {
    const { retention_days } = this.getRetention();
    if (retention_days <= 0) return 0;

    const result = this.db
      .query(
        `DELETE FROM audit_log WHERE timestamp < datetime('now', '-' || ? || ' days')`
      )
      .run(retention_days);

    return result.changes;
  }

  /**
   * Get the total count of audit entries.
   */
  count(): number {
    const row = this.db
      .query("SELECT COUNT(*) as cnt FROM audit_log")
      .get() as { cnt: number };
    return row.cnt;
  }

  /**
   * Sum the redaction counts recorded on proxy and scrub audit rows since the
   * given ISO timestamp. proxy.forward* rows store the count under
   * metadata.redaction_count; scrub.redact rows store it under metadata.count.
   * Powers the "credentials kept out of agent context" posture stat.
   */
  sumRedactions(since: string): number {
    const row = this.db
      .query(
        `SELECT COALESCE(SUM(
           CAST(COALESCE(
             json_extract(metadata, '$.redaction_count'),
             json_extract(metadata, '$.count'),
             '0'
           ) AS INTEGER)
         ), 0) AS total
         FROM audit_log
         WHERE timestamp >= ?
           AND action IN ('proxy.forward', 'proxy.forward.mcp', 'scrub.redact')`
      )
      .get(since) as { total: number };
    return row.total;
  }

  /**
   * Count blocked outbound proxy attempts since the given ISO timestamp,
   * broken down by reason. Two sources: dedicated blocked actions
   * (proxy.blocked.rate_limit, proxy.blocked.approval) and failed proxy
   * forwards carrying a blocking metadata.reason. Powers the posture
   * "blocked egress" stat.
   */
  blockedEgress(since: string): { total: number; by_reason: Record<string, number> } {
    const by_reason: Record<string, number> = {};

    const blockedActions = this.db
      .query(
        `SELECT action, COUNT(*) AS cnt FROM audit_log
         WHERE timestamp >= ?
           AND action IN ('proxy.blocked.rate_limit', 'proxy.blocked.approval')
         GROUP BY action`
      )
      .all(since) as { action: string; cnt: number }[];
    for (const r of blockedActions) {
      const key = r.action === "proxy.blocked.rate_limit" ? "rate_limit" : "approval";
      by_reason[key] = (by_reason[key] || 0) + r.cnt;
    }

    const failedForwards = this.db
      .query(
        `SELECT json_extract(metadata, '$.reason') AS reason, COUNT(*) AS cnt FROM audit_log
         WHERE timestamp >= ?
           AND action IN ('proxy.forward', 'proxy.forward.mcp')
           AND success = 0
           AND json_extract(metadata, '$.reason') IN
             ('ssrf_blocked', 'domain_blocked', 'path_prefix_blocked', 'policy_denied')
         GROUP BY reason`
      )
      .all(since) as { reason: string; cnt: number }[];
    for (const r of failedForwards) {
      by_reason[r.reason] = (by_reason[r.reason] || 0) + r.cnt;
    }

    const total = Object.values(by_reason).reduce((a, b) => a + b, 0);
    return { total, by_reason };
  }
}
