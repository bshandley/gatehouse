import { Hono } from "hono";
import type { Database } from "bun:sqlite";
import type { PolicyEngine } from "../policy/engine";
import { verifyVault } from "../backup/verify";

/**
 * GET / : admin only. Reports whether the loaded master key decrypts the data.
 * Takes a getter so it follows a key rotation.
 */
export function keyVerifyRouter(db: Database, getMasterKey: () => Buffer, policies: PolicyEngine) {
  const router = new Hono();
  router.get("/", (c) => {
    const auth = c.get("auth") as any;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }
    return c.json(verifyVault(db, getMasterKey()));
  });
  return router;
}
