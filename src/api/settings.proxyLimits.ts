import type { Context } from "hono";
import type { Database } from "bun:sqlite";
import type { AuditLog } from "../audit/logger";
import type { PolicyEngine } from "../policy/engine";
import { getProxyLimits, setProxyLimits } from "../settings/proxyLimits";

function adminGate(c: Context, policies: PolicyEngine): boolean {
  const auth = c.get("auth") as any;
  return policies.check(auth?.policies || [], "*", "admin");
}

export function handleGetProxyLimits(c: Context, db: Database, policies: PolicyEngine) {
  if (!adminGate(c, policies)) {
    return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
  }
  return c.json(getProxyLimits(db));
}

export async function handlePostProxyLimits(
  c: Context,
  db: Database,
  policies: PolicyEngine,
  audit: AuditLog
) {
  if (!adminGate(c, policies)) {
    return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
  }

  // Strip extra fields so attackers cannot smuggle keys into the stored row.
  const o = body as { max_timeout_ms?: unknown; max_body_bytes?: unknown };
  const sanitized = {
    max_timeout_ms: o?.max_timeout_ms,
    max_body_bytes: o?.max_body_bytes,
  };

  const auth = c.get("auth") as any;
  const result = setProxyLimits(
    db,
    audit,
    auth?.identity || "anonymous",
    c.get("sourceIp") || null,
    sanitized
  );
  if (!result.ok) {
    return c.json({ errors: result.errors, request_id: c.get("requestId") }, 400);
  }
  return c.json({ saved: true, ...result.current });
}
