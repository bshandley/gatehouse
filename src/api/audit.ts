import { Hono } from "hono";
import type { AuditLog } from "../audit/logger";
import type { PolicyEngine } from "../policy/engine";
import type { AuthContext } from "../auth/middleware";

export function auditRouter(audit: AuditLog, policies: PolicyEngine) {
  const router = new Hono();

  router.get("/", (c) => {
    const auth = c.get("auth") as AuthContext;
    const isAdmin = policies.check(auth.policies, "*", "admin");

    const opts = {
      identity: isAdmin ? c.req.query("identity") : auth.identity,
      action: c.req.query("action"),
      path: c.req.query("path"),
      since: c.req.query("since"),
      limit: parseInt(c.req.query("limit") || "100", 10),
    };

    return c.json({ entries: audit.query(opts) });
  });

  // GET /retention — view current retention policy
  router.get("/retention", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const retention = audit.getRetention();
    const count = audit.count();
    return c.json({ ...retention, total_entries: count });
  });

  // POST /retention — set retention policy
  router.post("/retention", async (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    let body: { retention_days: number };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const days = body.retention_days;
    if (typeof days !== "number" || days < 0 || !Number.isInteger(days)) {
      return c.json({ error: "retention_days must be a non-negative integer (0 = keep forever)", request_id: c.get("requestId") }, 400);
    }

    audit.setRetention(days);

    audit.log({
      identity: auth.identity,
      action: "audit.retention.update",
      metadata: { retention_days: String(days) },
      source_ip: c.get("sourceIp"),
    });

    return c.json({ retention_days: days, saved: true });
  });

  // POST /purge — manually trigger purge of old entries
  router.post("/purge", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const purged = audit.purgeExpired();

    if (purged > 0) {
      audit.log({
        identity: auth.identity,
        action: "audit.purge",
        metadata: { purged_count: String(purged) },
        source_ip: c.get("sourceIp"),
      });
    }

    return c.json({ purged });
  });

  return router;
}
