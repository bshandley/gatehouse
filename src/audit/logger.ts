import { Database } from "bun:sqlite";
import type { EventBus } from "../events/bus";

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
      params.push(opts.since);
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
}
