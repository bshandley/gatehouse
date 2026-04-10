// src/api/patterns.ts
import { Hono } from "hono";
import type { PatternEngine } from "../patterns/engine";
import type { PolicyEngine } from "../policy/engine";

export function patternsRouter(patterns: PatternEngine, policies: PolicyEngine) {
  const router = new Hono();

  // GET / — query patterns by secret (agent) or list all (admin)
  router.get("/", (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    const secret = c.req.query("secret");

    if (secret) {
      // Agent query: requires proxy or read on the secret path
      if (
        !policies.check(auth.policies, secret, "proxy") &&
        !policies.check(auth.policies, secret, "read")
      ) {
        return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
      }
      return c.json({ patterns: patterns.query(secret) });
    }

    // No secret filter: admin only
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }
    return c.json({ patterns: patterns.listAll() });
  });

  // DELETE /:id — delete a pattern (admin only)
  router.delete("/:id", (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const id = c.req.param("id");
    const deleted = patterns.delete(id);
    if (!deleted) {
      return c.json({ error: "Pattern not found", request_id: c.get("requestId") }, 404);
    }
    return c.json({ deleted: true });
  });

  // PUT /:id/pin — toggle pin (admin only)
  router.put("/:id/pin", (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const id = c.req.param("id");
    const toggled = patterns.togglePin(id);
    if (!toggled) {
      return c.json({ error: "Pattern not found", request_id: c.get("requestId") }, 404);
    }

    // Return new pin state
    const all = patterns.listAll();
    const pattern = all.find((p) => p.id === id);
    return c.json({ pinned: pattern?.pinned ?? false });
  });

  return router;
}
