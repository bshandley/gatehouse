import { Hono } from "hono";
import type { LeaseManager } from "../lease/manager";
import { LeaseValidationError } from "../lease/manager";
import type { DynamicSecretsManager } from "../dynamic/manager";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { AuthContext } from "../auth/middleware";
import type { SecretsEngine } from "../secrets/engine";
import { ipMatchesAllowlist } from "../auth/cidr";

export function leaseRouter(
  leases: LeaseManager,
  policies: PolicyEngine,
  audit: AuditLog,
  dynamic?: DynamicSecretsManager,
  secrets?: SecretsEngine
) {
  const router = new Hono();

  // The greedy matcher dispatches checkout, /renew, /request, /approve, /deny
  // by suffix. Lease IDs are always "lease-"-prefixed so suffix collisions
  // with a real secret path are impossible.
  router.post("/:path{.+}", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const rawPath = c.req.param("path");

    // /approve and /deny: admin-only operations on a known lease ID.
    if (rawPath.endsWith("/approve")) {
      const leaseId = rawPath.slice(0, -"/approve".length);
      if (!leaseId.startsWith("lease-")) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
      const isAdmin = policies.check(auth.policies, "*", "admin");
      if (!isAdmin) {
        return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
      }
      const lease = leases.getLease(leaseId);
      if (!lease) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
      if (lease.status !== "pending" || lease.revoked) {
        return c.json(
          { error: `Lease is ${lease.revoked ? "revoked" : lease.status}, cannot approve`, request_id: c.get("requestId") },
          409
        );
      }
      const updated = leases.approve(leaseId, auth.identity);
      if (!updated) {
        return c.json({ error: "Approve failed", request_id: c.get("requestId") }, 409);
      }
      return c.json({ lease: updated });
    }

    if (rawPath.endsWith("/deny")) {
      const leaseId = rawPath.slice(0, -"/deny".length);
      if (!leaseId.startsWith("lease-")) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
      const isAdmin = policies.check(auth.policies, "*", "admin");
      if (!isAdmin) {
        return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
      }
      const lease = leases.getLease(leaseId);
      if (!lease) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
      if (lease.status !== "pending" || lease.revoked) {
        return c.json(
          { error: `Lease is ${lease.revoked ? "revoked" : lease.status}, cannot deny`, request_id: c.get("requestId") },
          409
        );
      }
      const body = await c.req.json<{ reason?: string }>().catch(() => ({}));
      const reason = typeof body.reason === "string" ? body.reason : "";
      const updated = leases.deny(leaseId, auth.identity, reason);
      if (!updated) {
        return c.json({ error: "Deny failed", request_id: c.get("requestId") }, 409);
      }
      return c.json({ lease: updated });
    }

    if (rawPath.endsWith("/renew")) {
      const leaseId = rawPath.slice(0, -"/renew".length);
      const lease = leases.getLease(leaseId);
      if (lease) {
        const isAdmin = policies.check(auth.policies, "*", "admin");
        if (lease.identity !== auth.identity && !isAdmin) {
          return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
        }
        if (lease.status !== "approved") {
          return c.json(
            { error: `Cannot renew a ${lease.status} lease`, request_id: c.get("requestId") },
            409
          );
        }
        const body = await c.req.json<{ ttl?: number }>().catch(() => ({}));
        const ttl = body.ttl || lease.ttl_seconds || 300;
        if (typeof ttl !== "number" || ttl < 10 || ttl > 86400) {
          return c.json(
            { error: "TTL must be between 10 and 86400 seconds", request_id: c.get("requestId") },
            400
          );
        }
        const renewed = leases.renew(leaseId, ttl, auth.identity);
        if (!renewed) {
          return c.json({ error: "Lease is revoked or expired", request_id: c.get("requestId") }, 409);
        }
        return c.json({ lease: renewed });
      }
      if (leaseId.startsWith("lease-")) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
    }

    if (rawPath.endsWith("/request")) {
      const secretPath = rawPath.slice(0, -"/request".length);
      if (!policies.check(auth.policies, secretPath, "lease")) {
        return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
      }
      const body = await c.req
        .json<{ ttl?: number; justification?: string; request_ttl?: number }>()
        .catch(() => ({} as { ttl?: number; justification?: string; request_ttl?: number }));
      const ttl = typeof body.ttl === "number" ? body.ttl : 300;
      const justification = typeof body.justification === "string" ? body.justification : "";
      const requestTtl = typeof body.request_ttl === "number" ? body.request_ttl : 3600;
      try {
        if (secrets) {
          const meta = secrets.getMeta(secretPath);
          if (!meta) {
            return c.json({ error: "Secret not found", request_id: c.get("requestId") }, 404);
          }
        }
        const lease = leases.requestAccess(secretPath, auth.identity, ttl, justification, requestTtl);
        const isDedup = lease.created_at && Date.now() - new Date(lease.created_at).getTime() > 1000;
        return c.json(
          {
            lease_id: lease.id,
            status: lease.status,
            request_expires_at: lease.request_expires_at,
            expires_at_if_approved: lease.expires_at,
          },
          isDedup ? 200 : 202
        );
      } catch (err) {
        if (err instanceof LeaseValidationError) {
          return c.json({ error: err.message, request_id: c.get("requestId") }, 400);
        }
        throw err;
      }
    }

    // Otherwise: treat rawPath as a secret path for checkout.
    if (!policies.check(auth.policies, rawPath, "lease")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const body = await c.req.json<{ ttl?: number }>().catch(() => ({}));
    const ttl = body.ttl || 300;

    if (typeof ttl !== "number" || ttl < 10 || ttl > 86400) {
      return c.json({ error: "TTL must be between 10 and 86400 seconds", request_id: c.get("requestId") }, 400);
    }

    // Approval-gated check before checkout.
    const meta = secrets?.getMeta(rawPath);
    if (meta?.metadata?.requires_approval === "true") {
      if (!leases.hasActiveApprovedLease(auth.identity, rawPath)) {
        // Try IP-allowlist auto-approve.
        const allowlistRaw = meta.metadata.auto_approve_from_ip;
        const sourceIp = (c.get("sourceIp") as string | undefined) || "";
        if (allowlistRaw) {
          const cidrs = allowlistRaw.split(",").map((s) => s.trim()).filter(Boolean);
          if (ipMatchesAllowlist(sourceIp, cidrs)) {
            const autoTtl = parseInt(meta.metadata.auto_approve_ttl_seconds || "300", 10);
            leases.autoApprove(
              rawPath,
              auth.identity,
              Number.isFinite(autoTtl) && autoTtl > 0 ? autoTtl : 300,
              "system:auto_approve_from_ip",
              `Auto-approved from ${sourceIp}`
            );
            // Fall through to checkout (which will now find the approved lease).
          } else {
            return c.json(
              {
                error: `Secret ${rawPath} requires an approved lease`,
                requires_approval: true,
                hint: `Use POST /v1/lease/${rawPath}/request`,
                request_id: c.get("requestId"),
              },
              403
            );
          }
        } else {
          return c.json(
            {
              error: `Secret ${rawPath} requires an approved lease`,
              requires_approval: true,
              hint: `Use POST /v1/lease/${rawPath}/request`,
              request_id: c.get("requestId"),
            },
            403
          );
        }
      }
    }

    const result = leases.checkout(rawPath, auth.identity, ttl);
    if (!result) {
      return c.json({ error: "Secret not found", request_id: c.get("requestId") }, 404);
    }

    return c.json({
      lease: result.lease,
      value: result.value,
    });
  });

  // Pending leases. Admin sees all; non-admin sees only their own.
  router.get("/pending", (c) => {
    const auth = c.get("auth") as AuthContext;
    const isAdmin = policies.check(auth.policies, "*", "admin");
    const pending = leases.listPending(isAdmin ? undefined : auth.identity);
    return c.json({ leases: pending });
  });

  // Single lease lookup. Owner or admin.
  router.get("/:leaseId{lease-.+}", (c) => {
    const auth = c.get("auth") as AuthContext;
    const leaseId = c.req.param("leaseId");
    const lease = leases.getLease(leaseId);
    if (!lease) {
      return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
    }
    const isAdmin = policies.check(auth.policies, "*", "admin");
    if (lease.identity !== auth.identity && !isAdmin) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }
    return c.json({ lease });
  });

  // List active leases - merged static + dynamic. Each entry carries a
  // kind discriminator and a normalized `path` field. Admin sees all
  // identities; everyone else sees only their own. Sorted by expires_at asc.
  router.get("/", (c) => {
    const auth = c.get("auth") as AuthContext;
    const isAdmin = policies.check(auth.policies, "*", "admin");
    const filterIdentity = isAdmin ? undefined : auth.identity;

    const staticActive = leases.listActive(filterIdentity).map((l) => ({
      id: l.id,
      kind: "static" as const,
      path: l.secret_path,
      identity: l.identity,
      ttl_seconds: l.ttl_seconds,
      created_at: l.created_at,
      expires_at: l.expires_at,
      status: l.status,
      approved_by: l.approved_by,
      justification: l.justification,
    }));

    const dynamicActive = dynamic
      ? dynamic
          .listActiveLeases()
          .filter((l) => !filterIdentity || l.identity === filterIdentity)
          .map((l) => ({
            id: l.lease_id,
            kind: "dynamic" as const,
            path: l.path,
            identity: l.identity,
            provider_type: l.provider_type,
            ttl_seconds: l.ttl_seconds,
            created_at: l.created_at,
            expires_at: l.expires_at,
          }))
      : [];

    const merged = [...staticActive, ...dynamicActive].sort((a, b) => {
      if (a.expires_at < b.expires_at) return -1;
      if (a.expires_at > b.expires_at) return 1;
      return 0;
    });

    return c.json({ leases: merged });
  });

  // Revoke a lease. Static and dynamic lease IDs are disambiguated by
  // prefix (`lease-` vs `dlease-`) so a single endpoint dispatches to
  // the right manager. Owner-or-admin authz applies to both.
  router.delete("/:leaseId", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const leaseId = c.req.param("leaseId");
    const isAdmin = policies.check(auth.policies, "*", "admin");

    if (leaseId.startsWith("dlease-")) {
      if (!dynamic) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
      const dynLease = dynamic.getLease(leaseId);
      if (!dynLease) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
      if (dynLease.identity !== auth.identity && !isAdmin) {
        return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
      }
      await dynamic.revokeLease(leaseId, auth.identity);
      return c.json({ revoked: true });
    }

    const lease = leases.getLease(leaseId);
    if (!lease) {
      return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
    }
    if (lease.identity !== auth.identity && !isAdmin) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }
    leases.revoke(leaseId, auth.identity);
    return c.json({ revoked: true });
  });

  return router;
}
