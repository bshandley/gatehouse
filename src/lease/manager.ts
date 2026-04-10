import { Database } from "bun:sqlite";
import { v4 as uuid } from "uuid";
import type { SecretsEngine } from "../secrets/engine";
import type { AuditLog } from "../audit/logger";

export interface Lease {
  id: string;
  secret_path: string;
  identity: string;
  ttl_seconds: number;
  created_at: string;
  expires_at: string;
  revoked: boolean;
}

export class LeaseManager {
  private db: Database;
  private secrets: SecretsEngine;
  private audit: AuditLog;
  private reaperInterval: ReturnType<typeof setInterval> | null = null;

  constructor(db: Database, secrets: SecretsEngine, audit: AuditLog) {
    this.db = db;
    this.secrets = secrets;
    this.audit = audit;
  }

  /**
   * Create a lease for a secret. Returns the lease ID and the decrypted value.
   * The value is only available at checkout time — subsequent reads require a new lease.
   */
  checkout(
    secretPath: string,
    identity: string,
    ttlSeconds: number = 300
  ): { lease: Lease; value: string } | null {
    const value = this.secrets.get(secretPath);
    if (value === null) return null;

    const id = `lease-${uuid()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

    this.db
      .query(
        `INSERT INTO leases (id, secret_path, identity, ttl_seconds, expires_at)
       VALUES (?, ?, ?, ?, ?)`
      )
      .run(id, secretPath, identity, ttlSeconds, expiresAt.toISOString());

    const lease: Lease = {
      id,
      secret_path: secretPath,
      identity,
      ttl_seconds: ttlSeconds,
      created_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
      revoked: false,
    };

    this.audit.log({
      identity,
      action: "lease.checkout",
      path: secretPath,
      lease_id: id,
      metadata: { ttl: ttlSeconds.toString() },
    });

    return { lease, value };
  }

  revoke(leaseId: string, identity: string): boolean {
    const result = this.db
      .query("UPDATE leases SET revoked = 1 WHERE id = ? AND revoked = 0")
      .run(leaseId);

    if (result.changes > 0) {
      this.audit.log({
        identity,
        action: "lease.revoke",
        lease_id: leaseId,
      });
      return true;
    }
    return false;
  }

  revokeByPath(secretPath: string, identity: string): number {
    const result = this.db
      .query(
        "UPDATE leases SET revoked = 1 WHERE secret_path = ? AND revoked = 0"
      )
      .run(secretPath);

    if (result.changes > 0) {
      this.audit.log({
        identity,
        action: "lease.revoke_all",
        path: secretPath,
        metadata: { count: result.changes.toString() },
      });
    }
    return result.changes;
  }

  getLease(leaseId: string): Lease | null {
    const row = this.db
      .query("SELECT * FROM leases WHERE id = ?")
      .get(leaseId) as any;
    if (!row) return null;
    return { ...row, revoked: !!row.revoked };
  }

  listActive(identity?: string): Lease[] {
    let query =
      "SELECT * FROM leases WHERE revoked = 0 AND expires_at > datetime('now')";
    const params: string[] = [];

    if (identity) {
      query += " AND identity = ?";
      params.push(identity);
    }

    query += " ORDER BY expires_at ASC";

    return (this.db.query(query).all(...params) as any[]).map((r) => ({
      ...r,
      revoked: !!r.revoked,
    }));
  }

  /**
   * Reap expired leases — mark them as revoked.
   * Called periodically by the reaper interval.
   */
  reapExpired(): number {
    const result = this.db
      .query(
        "UPDATE leases SET revoked = 1 WHERE revoked = 0 AND expires_at <= datetime('now')"
      )
      .run();

    if (result.changes > 0) {
      this.audit.log({
        identity: "system:reaper",
        action: "lease.reap",
        metadata: { expired_count: result.changes.toString() },
      });
    }

    return result.changes;
  }

  startReaper(intervalMs: number = 30_000) {
    this.reaperInterval = setInterval(() => {
      const count = this.reapExpired();
      if (count > 0) {
        console.log(`[gatehouse:reaper] revoked ${count} expired lease(s)`);
      }
    }, intervalMs);
  }

  stopReaper() {
    if (this.reaperInterval) {
      clearInterval(this.reaperInterval);
      this.reaperInterval = null;
    }
  }
}
