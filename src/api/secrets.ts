import { Hono } from "hono";
import type { SecretsEngine } from "../secrets/engine";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { AuthContext } from "../auth/middleware";

const PATH_REGEX = /^[a-zA-Z0-9/_-]+$/;
const MAX_METADATA_VALUE_SIZE = 1024; // 1KB per value

function validatePath(path: string): string | null {
  if (!path || path.length === 0) return "Path is required";
  if (path.length > 256) return "Path must be under 256 characters";
  if (!PATH_REGEX.test(path)) return "Path must match ^[a-zA-Z0-9/_-]+$";
  return null;
}

export function secretsRouter(
  secrets: SecretsEngine,
  policies: PolicyEngine,
  audit: AuditLog
) {
  const router = new Hono();

  // List secrets (metadata only, no values)
  // Returns only secrets the caller has read or list access to.
  router.get("/", (c) => {
    const auth = c.get("auth") as AuthContext;
    const prefix = c.req.query("prefix") || "";
    const allResults = secrets.list(prefix);

    // Filter to secrets the agent can actually access
    const results = allResults.filter(
      (s) =>
        policies.check(auth.policies, s.path, "list") ||
        policies.check(auth.policies, s.path, "read")
    );

    if (results.length === 0 && allResults.length > 0) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    audit.log({
      identity: auth.identity,
      action: "secret.list",
      path: prefix || "*",
      source_ip: c.get("sourceIp"),
    });

    return c.json({ secrets: results });
  });

  // Get secret value or metadata.
  // Route /:path{.+}/value does not work reliably in Hono when the path contains
  // slashes (the greedy .+ consumes the /value suffix). Handle both in one route
  // by detecting the /value suffix on the raw path parameter.
  router.get("/:path{.+}", (c) => {
    const auth = c.get("auth") as AuthContext;
    const rawPath = c.req.param("path");

    const isValueRequest = rawPath.endsWith("/value");
    const path = isValueRequest ? rawPath.slice(0, -6) : rawPath;

    const pathError = validatePath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "read")) {
      audit.log({ identity: auth.identity, action: "secret.read", path, success: false,
        source_ip: c.get("sourceIp") });
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    if (isValueRequest) {
      const value = secrets.get(path);
      if (value === null) {
        return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
      }

      audit.log({
        identity: auth.identity,
        action: "secret.read",
        path,
        source_ip: c.get("sourceIp"),
      });

      // Return raw value for exec-based secret providers (e.g. OpenClaw)
      if (c.req.header("Accept") === "text/plain") {
        return c.text(value);
      }
      return c.json({ path, value });
    }

    // Metadata only (no value)
    const meta = secrets.getMeta(path);
    if (!meta) {
      return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
    }
    return c.json(meta);
  });

  // Create or update a secret
  router.post("/:path{.+}", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const path = c.req.param("path");

    const pathError = validatePath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "write")) {
      audit.log({ identity: auth.identity, action: "secret.write", path, success: false });
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    let body: { value: string; metadata?: Record<string, string> };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    if (!body.value || typeof body.value !== "string") {
      return c.json({ error: "Missing 'value' field", request_id: c.get("requestId") }, 400);
    }

    // Validate metadata
    if (body.metadata) {
      if (typeof body.metadata !== "object" || Array.isArray(body.metadata)) {
        return c.json({ error: "metadata must be an object", request_id: c.get("requestId") }, 400);
      }
      for (const [k, v] of Object.entries(body.metadata)) {
        if (typeof v !== "string") {
          return c.json({ error: `metadata value for "${k}" must be a string`, request_id: c.get("requestId") }, 400);
        }
        if (v.length > MAX_METADATA_VALUE_SIZE) {
          return c.json({ error: `metadata value for "${k}" exceeds 1KB limit`, request_id: c.get("requestId") }, 400);
        }
      }
    }

    const result = secrets.put(path, body.value, body.metadata);

    audit.log({
      identity: auth.identity,
      action: "secret.write",
      path,
      source_ip: c.get("sourceIp"),
    });

    return c.json(result, 201);
  });

  // Delete a secret
  router.delete("/:path{.+}", (c) => {
    const auth = c.get("auth") as AuthContext;
    const path = c.req.param("path");

    const pathError = validatePath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "delete")) {
      audit.log({ identity: auth.identity, action: "secret.delete", path, success: false });
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const deleted = secrets.delete(path);
    if (!deleted) {
      return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
    }

    audit.log({
      identity: auth.identity,
      action: "secret.delete",
      path,
      source_ip: c.get("sourceIp"),
    });

    return c.json({ deleted: true });
  });

  return router;
}
