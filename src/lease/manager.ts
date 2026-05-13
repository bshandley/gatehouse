import { Database } from "bun:sqlite";
import { v4 as uuid } from "uuid";
import type { SecretsEngine } from "../secrets/engine";
import type { AuditLog } from "../audit/logger";
import type { EventBus } from "../events/bus";
import { sendLeaseRequestWebhook } from "./webhook";

export type LeaseStatus = "pending" | "approved" | "denied" | "expired";

export interface Lease {
  id: string;
  secret_path: string;
  identity: string;
  ttl_seconds: number;
  created_at: string;
  expires_at: string;
  revoked: boolean;
  status: LeaseStatus;
  justification: string | null;
  approved_by: string | null;
  approved_at: string | null;
  denied_reason: string | null;
  request_expires_at: string | null;
}

const JUSTIFICATION_MIN = 10;
const JUSTIFICATION_MAX = 2000;
const REQUEST_TTL_MIN = 60;
const REQUEST_TTL_MAX = 86400;
const REQUEST_TTL_DEFAULT = 3600;
/** Cap on justification text stored in audit metadata. Full text stays on the lease row. */
const AUDIT_JUSTIFICATION_MAX = 200;

export class LeaseValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LeaseValidationError";
  }
}

interface LeaseRow {
  id: string;
  secret_path: string;
  identity: string;
  ttl_seconds: number;
  created_at: string;
  expires_at: string;
  revoked: number;
  status: string | null;
  justification: string | null;
  approved_by: string | null;
  approved_at: string | null;
  denied_reason: string | null;
  request_expires_at: string | null;
}

function rowToLease(row: LeaseRow): Lease {
  return {
    id: row.id,
    secret_path: row.secret_path,
    identity: row.identity,
    ttl_seconds: row.ttl_seconds,
    created_at: row.created_at,
    expires_at: row.expires_at,
    revoked: !!row.revoked,
    status: (row.status as LeaseStatus) || "approved",
    justification: row.justification,
    approved_by: row.approved_by,
    approved_at: row.approved_at,
    denied_reason: row.denied_reason,
    request_expires_at: row.request_expires_at,
  };
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}

export class LeaseManager {
  private db: Database;
  private secrets: SecretsEngine;
  private audit: AuditLog;
  private bus: EventBus | null = null;
  private serverBaseUrl = "http://localhost:3100";
  private reaperInterval: ReturnType<typeof setInterval> | null = null;

  constructor(db: Database, secrets: SecretsEngine, audit: AuditLog) {
    this.db = db;
    this.secrets = secrets;
    this.audit = audit;
  }

  attachBus(bus: EventBus): void {
    this.bus = bus;
  }

  setServerBaseUrl(url: string): void {
    this.serverBaseUrl = url.replace(/\/+$/, "");
  }

  /**
   * Create a lease for a secret. For approval-gated secrets, this REUSES an
   * existing approved access window and audits `lease.access`. For ordinary
   * secrets, behaviour is unchanged: a new row is inserted per call.
   */
  checkout(
    secretPath: string,
    identity: string,
    ttlSeconds: number = 300
  ): { lease: Lease; value: string } | null {
    const meta = this.secrets.getMeta(secretPath);
    if (meta?.metadata?.requires_approval === "true") {
      // Unified model: an approved lease IS the access window. We do not mint
      // a second row on each checkout against an approval-gated secret;
      // instead we audit `lease.access` against the existing approval row so
      // revocation can atomically kill all downstream access.
      const existing = this.findActiveApprovedLease(identity, secretPath);
      if (!existing) return null;
      const value = this.secrets.get(secretPath);
      if (value === null) return null;
      this.audit.log({
        identity,
        action: "lease.access",
        path: secretPath,
        lease_id: existing.id,
      });
      return { lease: existing, value };
    }

    const value = this.secrets.get(secretPath);
    if (value === null) return null;

    const id = `lease-${uuid()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);

    this.db
      .query(
        `INSERT INTO leases (id, secret_path, identity, ttl_seconds, expires_at, status)
       VALUES (?, ?, ?, ?, ?, 'approved')`
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
      status: "approved",
      justification: null,
      approved_by: null,
      approved_at: null,
      denied_reason: null,
      request_expires_at: null,
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

  /**
   * Create a pending lease awaiting human approval. If the (identity, path)
   * already has a non-expired pending lease, return that one (dedup). Fires
   * the optional webhook and emits a bus event after the row is committed.
   */
  requestAccess(
    secretPath: string,
    identity: string,
    ttlSeconds: number,
    justification: string,
    requestTtlSeconds: number = REQUEST_TTL_DEFAULT
  ): Lease {
    const trimmed = justification.trim();
    if (trimmed.length < JUSTIFICATION_MIN || trimmed.length > JUSTIFICATION_MAX) {
      throw new LeaseValidationError(
        `justification must be ${JUSTIFICATION_MIN} to ${JUSTIFICATION_MAX} characters`
      );
    }
    if (!Number.isFinite(ttlSeconds) || ttlSeconds < 10 || ttlSeconds > REQUEST_TTL_MAX) {
      throw new LeaseValidationError(`ttl must be between 10 and ${REQUEST_TTL_MAX}`);
    }
    const reqTtl = Math.max(REQUEST_TTL_MIN, Math.min(REQUEST_TTL_MAX, requestTtlSeconds | 0));

    // Dedup: an existing pending row for the same (identity, path) wins.
    const existing = this.db
      .query(
        `SELECT * FROM leases
         WHERE identity = ? AND secret_path = ? AND status = 'pending'
         AND revoked = 0 AND request_expires_at > datetime('now')`
      )
      .get(identity, secretPath) as LeaseRow | null;
    if (existing) return rowToLease(existing);

    const id = `lease-${uuid()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    const requestExpiresAt = new Date(now.getTime() + reqTtl * 1000);

    this.db
      .query(
        `INSERT INTO leases
         (id, secret_path, identity, ttl_seconds, expires_at, status, justification, request_expires_at)
         VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`
      )
      .run(
        id,
        secretPath,
        identity,
        ttlSeconds,
        expiresAt.toISOString(),
        trimmed,
        requestExpiresAt.toISOString()
      );

    this.audit.log({
      identity,
      action: "lease.request_created",
      path: secretPath,
      lease_id: id,
      metadata: {
        ttl: ttlSeconds.toString(),
        request_ttl: reqTtl.toString(),
        justification: truncate(trimmed, AUDIT_JUSTIFICATION_MAX),
      },
    });

    const lease = this.getLease(id);
    if (!lease) throw new Error("lease vanished after insert");

    if (this.bus) {
      this.bus.emit({
        type: "lease_request_created",
        lease: {
          id: lease.id,
          secret_path: lease.secret_path,
          identity: lease.identity,
          ttl_seconds: lease.ttl_seconds,
          justification: lease.justification,
          request_expires_at: lease.request_expires_at,
          expires_at: lease.expires_at,
          created_at: lease.created_at,
          status: lease.status,
        },
      });
    }

    sendLeaseRequestWebhook({
      lease_id: lease.id,
      identity: lease.identity,
      secret_path: lease.secret_path,
      justification: lease.justification || "",
      ttl_seconds: lease.ttl_seconds,
      request_expires_at: lease.request_expires_at || "",
      server_base_url: this.serverBaseUrl,
    });

    return lease;
  }

  /**
   * Flip a pending lease to approved. Resets expires_at to (now + ttl_seconds)
   * so the access window starts at approval time, not request time.
   * Returns null if the lease is missing or not pending.
   */
  approve(leaseId: string, approverIdentity: string): Lease | null {
    const existing = this.getLease(leaseId);
    if (!existing || existing.status !== "pending" || existing.revoked) return null;

    const now = new Date();
    const newExpiresAt = new Date(now.getTime() + existing.ttl_seconds * 1000);

    this.db
      .query(
        `UPDATE leases
         SET status = 'approved', approved_by = ?, approved_at = ?, expires_at = ?
         WHERE id = ? AND status = 'pending'`
      )
      .run(approverIdentity, now.toISOString(), newExpiresAt.toISOString(), leaseId);

    this.audit.log({
      identity: approverIdentity,
      action: "lease.approved",
      path: existing.secret_path,
      lease_id: leaseId,
      metadata: {
        agent_identity: existing.identity,
        ttl: existing.ttl_seconds.toString(),
      },
    });

    if (this.bus) {
      this.bus.emit({
        type: "lease_status_changed",
        lease_id: leaseId,
        status: "approved",
        identity: existing.identity,
        approved_by: approverIdentity,
      });
    }

    return this.getLease(leaseId);
  }

  /**
   * Flip a pending lease to denied. Stores the reason on the row.
   * Returns null if the lease is missing or not pending.
   */
  deny(leaseId: string, approverIdentity: string, reason: string): Lease | null {
    const existing = this.getLease(leaseId);
    if (!existing || existing.status !== "pending" || existing.revoked) return null;

    const r = (reason || "").slice(0, 500);

    this.db
      .query(
        `UPDATE leases
         SET status = 'denied', denied_reason = ?, approved_by = ?, approved_at = datetime('now')
         WHERE id = ? AND status = 'pending'`
      )
      .run(r, approverIdentity, leaseId);

    this.audit.log({
      identity: approverIdentity,
      action: "lease.denied",
      path: existing.secret_path,
      lease_id: leaseId,
      metadata: {
        agent_identity: existing.identity,
        reason: r.slice(0, AUDIT_JUSTIFICATION_MAX),
      },
    });

    if (this.bus) {
      this.bus.emit({
        type: "lease_status_changed",
        lease_id: leaseId,
        status: "denied",
        identity: existing.identity,
        approved_by: approverIdentity,
      });
    }

    return this.getLease(leaseId);
  }

  /**
   * Create an approved lease directly without going through the pending state.
   * Used by the IP-allowlist auto-approve path.
   */
  autoApprove(
    secretPath: string,
    identity: string,
    ttlSeconds: number,
    approvedBy: string,
    justification: string
  ): Lease {
    const id = `lease-${uuid()}`;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    const trimmed = (justification || "").slice(0, JUSTIFICATION_MAX);

    this.db
      .query(
        `INSERT INTO leases
         (id, secret_path, identity, ttl_seconds, expires_at, status, justification, approved_by, approved_at)
         VALUES (?, ?, ?, ?, ?, 'approved', ?, ?, ?)`
      )
      .run(
        id,
        secretPath,
        identity,
        ttlSeconds,
        expiresAt.toISOString(),
        trimmed,
        approvedBy,
        now.toISOString()
      );

    this.audit.log({
      identity,
      action: "lease.auto_approved",
      path: secretPath,
      lease_id: id,
      metadata: {
        approved_by: approvedBy,
        ttl: ttlSeconds.toString(),
      },
    });

    const lease = this.getLease(id);
    if (!lease) throw new Error("lease vanished after insert");
    return lease;
  }

  listPending(identity?: string): Lease[] {
    let query =
      "SELECT * FROM leases WHERE status = 'pending' AND revoked = 0 AND request_expires_at > datetime('now')";
    const params: string[] = [];
    if (identity) {
      query += " AND identity = ?";
      params.push(identity);
    }
    query += " ORDER BY created_at DESC";
    return (this.db.query(query).all(...params) as LeaseRow[]).map(rowToLease);
  }

  hasActiveApprovedLease(identity: string, secretPath: string): boolean {
    return this.findActiveApprovedLease(identity, secretPath) !== null;
  }

  findActiveApprovedLease(identity: string, secretPath: string): Lease | null {
    const row = this.db
      .query(
        `SELECT * FROM leases
         WHERE identity = ? AND secret_path = ? AND status = 'approved'
         AND revoked = 0 AND expires_at > datetime('now')
         ORDER BY expires_at DESC LIMIT 1`
      )
      .get(identity, secretPath) as LeaseRow | null;
    return row ? rowToLease(row) : null;
  }

  /**
   * Extend a lease's expiry to now + ttlSeconds. Only valid for approved
   * leases. Returns null if the lease is missing, not approved, revoked, or
   * already expired.
   */
  renew(leaseId: string, ttlSeconds: number, identity: string): Lease | null {
    const existing = this.getLease(leaseId);
    if (!existing) return null;
    if (existing.revoked) return null;
    if (existing.status !== "approved") return null;
    if (new Date(existing.expires_at).getTime() <= Date.now()) return null;

    const newExpiresAt = new Date(Date.now() + ttlSeconds * 1000);
    this.db
      .query("UPDATE leases SET expires_at = ?, ttl_seconds = ? WHERE id = ? AND revoked = 0")
      .run(newExpiresAt.toISOString(), ttlSeconds, leaseId);

    this.audit.log({
      identity,
      action: "lease.renew",
      path: existing.secret_path,
      lease_id: leaseId,
      metadata: { ttl: ttlSeconds.toString() },
    });

    return { ...existing, ttl_seconds: ttlSeconds, expires_at: newExpiresAt.toISOString() };
  }

  revoke(leaseId: string, identity: string): boolean {
    const result = this.db
      .query("UPDATE leases SET revoked = 1 WHERE id = ? AND revoked = 0")
      .run(leaseId);

    if (result.changes > 0) {
      const lease = this.getLease(leaseId);
      this.audit.log({
        identity,
        action: "lease.revoke",
        lease_id: leaseId,
      });
      if (lease && this.bus) {
        this.bus.emit({
          type: "lease_status_changed",
          lease_id: leaseId,
          status: lease.status,
          identity: lease.identity,
        });
      }
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

  /**
   * Bulk-delete pending leases for an identity. Used when an AppRole is
   * deleted so its pending requests don't clutter the approval queue.
   */
  deletePendingForIdentity(identity: string): number {
    const result = this.db
      .query(
        "DELETE FROM leases WHERE identity = ? AND status = 'pending'"
      )
      .run(identity);
    return result.changes;
  }

  getLease(leaseId: string): Lease | null {
    const row = this.db
      .query("SELECT * FROM leases WHERE id = ?")
      .get(leaseId) as LeaseRow | null;
    if (!row) return null;
    return rowToLease(row);
  }

  listActive(identity?: string): Lease[] {
    let query =
      "SELECT * FROM leases WHERE revoked = 0 AND status = 'approved' AND expires_at > datetime('now')";
    const params: string[] = [];

    if (identity) {
      query += " AND identity = ?";
      params.push(identity);
    }

    query += " ORDER BY expires_at ASC";

    return (this.db.query(query).all(...params) as LeaseRow[]).map(rowToLease);
  }

  /**
   * Reap expired leases - mark approved leases past expiry as revoked, and
   * pending requests past their request_expires_at as expired.
   * Called periodically by the reaper interval.
   */
  reapExpired(): number {
    // Approved past expiry: existing semantics (revoke).
    const approvedExpired = this.db
      .query(
        "UPDATE leases SET revoked = 1 WHERE revoked = 0 AND status = 'approved' AND expires_at <= datetime('now')"
      )
      .run();

    // Pending past request_expires_at: flip to expired and revoke.
    const pendingExpiredRows = this.db
      .query(
        `SELECT id, identity, secret_path FROM leases
         WHERE revoked = 0 AND status = 'pending'
         AND request_expires_at IS NOT NULL AND request_expires_at <= datetime('now')`
      )
      .all() as { id: string; identity: string; secret_path: string }[];

    if (pendingExpiredRows.length > 0) {
      const ids = pendingExpiredRows.map((r) => r.id);
      const placeholders = ids.map(() => "?").join(",");
      this.db
        .query(
          `UPDATE leases SET status = 'expired', revoked = 1 WHERE id IN (${placeholders})`
        )
        .run(...ids);

      for (const r of pendingExpiredRows) {
        this.audit.log({
          identity: "system:reaper",
          action: "lease.request_expired",
          path: r.secret_path,
          lease_id: r.id,
          metadata: { agent_identity: r.identity },
        });
        if (this.bus) {
          this.bus.emit({
            type: "lease_status_changed",
            lease_id: r.id,
            status: "expired",
            identity: r.identity,
          });
        }
      }
    }

    const total = approvedExpired.changes + pendingExpiredRows.length;
    if (approvedExpired.changes > 0) {
      this.audit.log({
        identity: "system:reaper",
        action: "lease.reap",
        metadata: { expired_count: approvedExpired.changes.toString() },
      });
    }

    return total;
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
