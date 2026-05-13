/**
 * Shared gating logic for proxy and lease calls. REST proxy and MCP proxy
 * both consume this so the rate-limit + approval enforcement stays
 * consistent across surfaces.
 *
 * Three gates run in order:
 *   1. AppRole rate limits (skipped for root and user JWTs).
 *   2. Per-secret minute limits read from secret metadata.
 *   3. Approval check: each secret with metadata.requires_approval=true
 *      must have an active approved lease for the caller, OR match its
 *      auto_approve_from_ip allowlist (in which case we mint an approved
 *      lease and continue).
 *
 * Returns either an allow result (carrying the AppRole role_id for
 * recordCall) or a structured block result the caller turns into the
 * HTTP / MCP response.
 */

import type { Database } from "bun:sqlite";
import type { AuthContext } from "../auth/middleware";
import type { RateLimiter, AppRoleLimits } from "../rateLimits/limiter";
import type { LeaseManager } from "../lease/manager";
import type { SecretsEngine } from "../secrets/engine";
import type { AuditLog } from "../audit/logger";
import { ipMatchesAllowlist } from "../auth/cidr";

export interface GatesContext {
  auth: AuthContext;
  secretPaths: string[];
  sourceIp: string;
  db: Database;
  rateLimiter: RateLimiter;
  leases: LeaseManager;
  secrets: SecretsEngine;
  audit: AuditLog;
  requestId?: string;
}

export interface GatesAllowed {
  allowed: true;
  /** AppRole role_id, or empty string for root/user (used by recordCall). */
  roleId: string;
  /** Map of path -> lease_id when an approval lease authorized the call. */
  leaseIds: Record<string, string>;
}

export interface GatesBlocked {
  allowed: false;
  status: 429 | 403;
  headers?: Record<string, string>;
  body: Record<string, unknown>;
}

interface AppRoleLimitsRow {
  rate_limit_per_minute: number | null;
  rate_limit_per_hour: number | null;
  rate_limit_per_day: number | null;
}

export function enforceProxyGates(ctx: GatesContext): GatesAllowed | GatesBlocked {
  // Gate 1: AppRole rate limits. Root and user JWTs are exempt.
  let roleId = "";
  let approleLimits: AppRoleLimits | null = null;
  if (ctx.auth.source === "approle" && ctx.auth.role_id) {
    roleId = ctx.auth.role_id;
    const row = ctx.db
      .query(
        "SELECT rate_limit_per_minute, rate_limit_per_hour, rate_limit_per_day FROM app_roles WHERE role_id = ?"
      )
      .get(roleId) as AppRoleLimitsRow | null;
    if (row) {
      approleLimits = {
        per_minute: row.rate_limit_per_minute,
        per_hour: row.rate_limit_per_hour,
        per_day: row.rate_limit_per_day,
      };
    }
  }

  if (approleLimits) {
    const d = ctx.rateLimiter.checkApprole(roleId, approleLimits);
    if (!d.allowed) {
      ctx.audit.log({
        identity: ctx.auth.identity,
        action: "proxy.blocked.rate_limit",
        path: ctx.secretPaths.join(",") || undefined,
        source_ip: ctx.sourceIp || null,
        metadata: {
          limit_kind: d.limitKind || "approle_minute",
          limit: String(d.limit ?? 0),
          current: String(d.current ?? 0),
        },
        success: false,
      });
      return {
        allowed: false,
        status: 429,
        headers: { "Retry-After": String(d.retryAfterSeconds || 1) },
        body: {
          error: d.reason || "Rate limit exceeded",
          retry_after: d.retryAfterSeconds || 1,
          limit_kind: d.limitKind,
          request_id: ctx.requestId,
        },
      };
    }
  }

  // Gate 2: per-secret minute limits from metadata.
  for (const p of ctx.secretPaths) {
    const meta = ctx.secrets.getMeta(p);
    if (!meta) continue;
    const raw = meta.metadata?.rate_limit_per_minute;
    const perMinute = raw ? parseInt(raw, 10) : NaN;
    if (Number.isFinite(perMinute) && perMinute > 0) {
      const d = ctx.rateLimiter.checkSecret(p, perMinute);
      if (!d.allowed) {
        ctx.audit.log({
          identity: ctx.auth.identity,
          action: "proxy.blocked.rate_limit",
          path: p,
          source_ip: ctx.sourceIp || null,
          metadata: {
            limit_kind: "secret_minute",
            limit: String(d.limit ?? perMinute),
            current: String(d.current ?? 0),
          },
          success: false,
        });
        return {
          allowed: false,
          status: 429,
          headers: { "Retry-After": String(d.retryAfterSeconds || 1) },
          body: {
            error: d.reason || `Rate limit exceeded for ${p}`,
            retry_after: d.retryAfterSeconds || 1,
            limit_kind: "secret_minute",
            request_id: ctx.requestId,
          },
        };
      }
    }
  }

  // Gate 3: approval check.
  const leaseIds: Record<string, string> = {};
  const blockedByApproval: string[] = [];
  for (const p of ctx.secretPaths) {
    const meta = ctx.secrets.getMeta(p);
    if (meta?.metadata?.requires_approval !== "true") continue;

    const existing = ctx.leases.findActiveApprovedLease(ctx.auth.identity, p);
    if (existing) {
      leaseIds[p] = existing.id;
      continue;
    }

    const allowlistRaw = meta.metadata.auto_approve_from_ip;
    if (allowlistRaw) {
      const cidrs = allowlistRaw.split(",").map((s) => s.trim()).filter(Boolean);
      if (ipMatchesAllowlist(ctx.sourceIp, cidrs)) {
        const autoTtl = parseInt(meta.metadata.auto_approve_ttl_seconds || "300", 10);
        const lease = ctx.leases.autoApprove(
          p,
          ctx.auth.identity,
          Number.isFinite(autoTtl) && autoTtl > 0 ? autoTtl : 300,
          "system:auto_approve_from_ip",
          `Auto-approved from ${ctx.sourceIp}`
        );
        leaseIds[p] = lease.id;
        continue;
      }
    }

    blockedByApproval.push(p);
  }

  if (blockedByApproval.length > 0) {
    ctx.audit.log({
      identity: ctx.auth.identity,
      action: "proxy.blocked.approval",
      path: blockedByApproval.join(","),
      source_ip: ctx.sourceIp || null,
      metadata: {
        requires_approval: blockedByApproval.join(","),
      },
      success: false,
    });
    return {
      allowed: false,
      status: 403,
      body: {
        error: `These secrets require an approved lease: ${blockedByApproval.join(", ")}`,
        requires_approval: blockedByApproval,
        hint: "Call gatehouse_request_access(path, ttl, justification) and wait for human approval.",
        request_id: ctx.requestId,
      },
    };
  }

  return { allowed: true, roleId, leaseIds };
}
