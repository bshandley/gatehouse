import { Hono } from "hono";
import type { LeaseManager } from "../lease/manager";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { AuthContext } from "../auth/middleware";

export function leaseRouter(
  leases: LeaseManager,
  policies: PolicyEngine,
  audit: AuditLog
) {
  const router = new Hono();

  // Checkout (POST /v1/lease/<secret/path>) vs. Renew (POST /v1/lease/<leaseId>/renew)
  // share a greedy matcher; disambiguate by /renew suffix on a known lease ID.
  router.post("/:path{.+}", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const rawPath = c.req.param("path");

    if (rawPath.endsWith("/renew")) {
      const leaseId = rawPath.slice(0, -6);
      const lease = leases.getLease(leaseId);
      if (lease) {
        const isAdmin = policies.check(auth.policies, "*", "admin");
        if (lease.identity !== auth.identity && !isAdmin) {
          return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
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
      // Lease IDs are always "lease-"-prefixed; a miss here is definitively not-found,
      // not a secret path that happens to end in /renew.
      if (leaseId.startsWith("lease-")) {
        return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
      }
    }

    if (!policies.check(auth.policies, rawPath, "lease")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const body = await c.req.json<{ ttl?: number }>().catch(() => ({}));
    const ttl = body.ttl || 300;

    if (typeof ttl !== "number" || ttl < 10 || ttl > 86400) {
      return c.json({ error: "TTL must be between 10 and 86400 seconds", request_id: c.get("requestId") }, 400);
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

  // List active leases
  router.get("/", (c) => {
    const auth = c.get("auth") as AuthContext;
    const isAdmin = policies.check(auth.policies, "*", "admin");
    const active = leases.listActive(isAdmin ? undefined : auth.identity);
    return c.json({ leases: active });
  });

  // Revoke a lease
  router.delete("/:leaseId", (c) => {
    const auth = c.get("auth") as AuthContext;
    const leaseId = c.req.param("leaseId");

    const lease = leases.getLease(leaseId);
    if (!lease) {
      return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
    }

    // Only the lease owner or admin can revoke
    const isAdmin = policies.check(auth.policies, "*", "admin");
    if (lease.identity !== auth.identity && !isAdmin) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    leases.revoke(leaseId, auth.identity);
    return c.json({ revoked: true });
  });

  return router;
}
