import { Hono } from "hono";
import { execSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { DynamicSecretsManager } from "../dynamic/manager";
import type { PolicyEngine } from "../policy/engine";
import type { AuditLog } from "../audit/logger";

const PATH_REGEX = /^[a-zA-Z0-9/_-]+$/;
function validateDynamicPath(path: string): string | null {
  if (!path || path.length === 0) return "Path is required";
  if (path.length > 256) return "Path must be under 256 characters";
  if (!PATH_REGEX.test(path)) return "Path must match ^[a-zA-Z0-9/_-]+$";
  return null;
}

export function dynamicRouter(
  dynamic: DynamicSecretsManager,
  policies: PolicyEngine,
  audit: AuditLog
) {
  const router = new Hono();

  /**
   * GET /v1/dynamic/providers
   * List available dynamic secret provider types.
   */
  router.get("/providers", (c) => {
    return c.json({ providers: dynamic.getProviderTypes() });
  });

  /**
   * POST /v1/dynamic/generate-ca-keypair
   * Generate an SSH CA keypair (admin only). Returns private + public key.
   */
  router.post("/generate-ca-keypair", (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const workDir = mkdtempSync(join(tmpdir(), "gh-ca-gen-"));
    try {
      const keyPath = join(workDir, "ca_key");
      execSync(`ssh-keygen -t ed25519 -f ${keyPath} -N "" -q -C "gatehouse-ca"`, {
        timeout: 10_000,
      });
      const privateKey = readFileSync(keyPath, "utf-8");
      const publicKey = readFileSync(`${keyPath}.pub`, "utf-8").trim();

      audit.log({
        identity: auth.identity,
        action: "dynamic.generate_ca_keypair",
        source_ip: c.get("sourceIp"),
      });

      return c.json({ private_key: privateKey, public_key: publicKey });
    } catch (err: any) {
      return c.json(
        { error: `Failed to generate keypair: ${err.message}`, request_id: c.get("requestId") },
        500
      );
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  /**
   * GET /v1/dynamic
   * List all dynamic secret configs (no sensitive data).
   */
  router.get("/", (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const configs = dynamic.listConfigs();
    return c.json({ configs });
  });

  /**
   * GET /v1/dynamic/:path
   * Get a dynamic secret config (admin only, redacts sensitive config values).
   */
  router.get("/:path{.+}", (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    const path = c.req.param("path");

    // Check for special sub-routes
    if (path.endsWith("/ca-pubkey")) {
      // Derive CA public key from stored private key (SSH cert configs only)
      const secretPath = path.replace(/\/ca-pubkey$/, "");
      const pathError = validateDynamicPath(secretPath);
      if (pathError) {
        return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
      }
      if (!policies.check(auth.policies, secretPath, "admin")) {
        return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
      }
      const cfg = dynamic.getConfig(secretPath);
      if (!cfg) return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
      if (cfg.provider_type !== "ssh-cert") {
        return c.json({ error: "Not an SSH cert config", request_id: c.get("requestId") }, 400);
      }
      const caWorkDir = mkdtempSync(join(tmpdir(), "gh-ca-pub-"));
      try {
        const caKeyPath = join(caWorkDir, "ca_key");
        writeFileSync(caKeyPath, cfg.config.ca_private_key.replace(/\r/g, "").trim() + "\n", { mode: 0o600 });
        const pubKey = execSync(`ssh-keygen -y -f ${caKeyPath}`, { encoding: "utf-8", timeout: 5_000 }).trim();
        return c.json({ public_key: pubKey, path: secretPath });
      } catch (err: any) {
        return c.json({ error: `Failed to derive public key: ${err.message}`, request_id: c.get("requestId") }, 500);
      } finally {
        rmSync(caWorkDir, { recursive: true, force: true });
      }
    }

    if (path.endsWith("/leases")) {
      // List active leases for this dynamic secret
      const secretPath = path.replace(/\/leases$/, "");
      const pathError = validateDynamicPath(secretPath);
      if (pathError) {
        return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
      }
      if (!policies.check(auth.policies, secretPath, "admin")) {
        return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
      }
      const leases = dynamic.listActiveLeases(secretPath);
      // Strip credentials from lease list
      return c.json({
        leases: leases.map((l) => ({
          lease_id: l.lease_id,
          path: l.path,
          identity: l.identity,
          provider_type: l.provider_type,
          ttl_seconds: l.ttl_seconds,
          created_at: l.created_at,
          expires_at: l.expires_at,
          // Only show username, not password
          credential_username: l.credential.username || l.credential.role_name,
        })),
      });
    }

    const pathError = validateDynamicPath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const config = dynamic.getConfig(path);
    if (!config) {
      return c.json({ error: "Dynamic secret not found", request_id: c.get("requestId") }, 404);
    }

    // Redact sensitive values — only show host/database/port, not password
    const safeConfig: Record<string, string> = {};
    for (const [key, value] of Object.entries(config.config)) {
      if (key === "password" || key === "secret" || key === "private_key" || key === "ca_private_key") {
        safeConfig[key] = "***";
      } else {
        safeConfig[key] = value;
      }
    }

    return c.json({
      path: config.path,
      provider_type: config.provider_type,
      config: safeConfig,
      created_at: config.created_at,
      updated_at: config.updated_at,
    });
  });

  /**
   * POST /v1/dynamic
   * Create or update a dynamic secret config (admin only).
   */
  router.post("/", async (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    let body: { path: string; provider_type: string; config: Record<string, string> };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const { path, provider_type, config: providerConfig } = body;

    const pathError = validateDynamicPath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }
    if (!provider_type) {
      return c.json({ error: "provider_type is required", request_id: c.get("requestId") }, 400);
    }
    if (!providerConfig || typeof providerConfig !== "object") {
      return c.json({ error: "config object is required", request_id: c.get("requestId") }, 400);
    }

    // When updating an existing config, preserve sensitive fields that were omitted or empty
    const sensitiveKeys = ["password", "secret", "ca_private_key"];
    const existing = dynamic.getConfig(path);
    if (existing) {
      for (const key of sensitiveKeys) {
        if ((!providerConfig[key] || providerConfig[key].trim() === "") && existing.config[key]) {
          providerConfig[key] = existing.config[key];
        }
      }
    }

    try {
      const saved = dynamic.saveConfig(path, provider_type, providerConfig);

      audit.log({
        identity: auth.identity,
        action: "dynamic.config.save",
        path,
        source_ip: c.get("sourceIp"),
        metadata: { provider: provider_type },
      });

      return c.json(
        {
          path: saved.path,
          provider_type: saved.provider_type,
          created_at: saved.created_at,
          updated_at: saved.updated_at,
        },
        201
      );
    } catch (err: any) {
      return c.json({ error: err.message, request_id: c.get("requestId") }, 400);
    }
  });

  /**
   * POST /v1/dynamic/:path/validate
   * Test the connection config for a dynamic secret.
   */
  router.post("/:path{.+}/validate", async (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    const path = c.req.param("path").replace(/\/validate$/, "");

    const pathError = validateDynamicPath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const result = await dynamic.validateConfig(path);
    return c.json(result);
  });

  /**
   * POST /v1/dynamic/:path/checkout
   * Create a dynamic credential (agent-facing).
   * Requires "lease" capability on the path.
   */
  router.post("/:path{.+}/checkout", async (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    const fullPath = c.req.param("path").replace(/\/checkout$/, "");

    const pathError = validateDynamicPath(fullPath);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, fullPath, "lease")) {
      audit.log({
        identity: auth.identity,
        action: "dynamic.checkout",
        path: fullPath,
        source_ip: c.get("sourceIp"),
        success: false,
      });
      return c.json({ error: "Forbidden: no lease capability", request_id: c.get("requestId") }, 403);
    }

    let body: { ttl?: number } = {};
    try {
      body = await c.req.json();
    } catch {
      // Body is optional — use defaults
    }

    const ttl = Math.max(10, Math.min(86400, body.ttl || 300));

    try {
      const lease = await dynamic.checkout(fullPath, auth.identity, ttl);
      if (!lease) {
        return c.json(
          { error: "Dynamic secret not found", request_id: c.get("requestId") },
          404
        );
      }

      return c.json({
        lease_id: lease.lease_id,
        path: lease.path,
        provider_type: lease.provider_type,
        credential: lease.credential,
        ttl_seconds: lease.ttl_seconds,
        expires_at: lease.expires_at,
      });
    } catch (err: any) {
      return c.json(
        { error: `Failed to create credential: ${err.message}`, request_id: c.get("requestId") },
        502
      );
    }
  });

  /**
   * DELETE /v1/dynamic/lease/:leaseId
   * Revoke a dynamic lease (destroys the temp credential at the provider).
   */
  router.delete("/lease/:leaseId", async (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    const leaseId = c.req.param("leaseId");

    const lease = dynamic.getLease(leaseId);
    if (!lease) {
      return c.json({ error: "Lease not found", request_id: c.get("requestId") }, 404);
    }

    // Owner or admin can revoke
    if (
      lease.identity !== auth.identity &&
      !policies.check(auth.policies, "*", "admin")
    ) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    await dynamic.revokeLease(leaseId, auth.identity);
    return c.json({ revoked: true });
  });

  /**
   * DELETE /v1/dynamic/:path
   * Delete a dynamic secret config (admin only).
   * Revokes all active leases for this path first.
   */
  router.delete("/:path{.+}", async (c) => {
    const auth = c.get("auth") as { identity: string; policies: string[] };
    const path = c.req.param("path");

    const pathError = validateDynamicPath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const deleted = dynamic.deleteConfig(path);
    if (!deleted) {
      return c.json({ error: "Dynamic secret not found", request_id: c.get("requestId") }, 404);
    }

    audit.log({
      identity: auth.identity,
      action: "dynamic.config.delete",
      path,
      source_ip: c.get("sourceIp"),
    });

    return c.json({ deleted: true });
  });

  return router;
}
