import { Hono } from "hono";
import type { SecretsEngine } from "../secrets/engine";
import type { PolicyEngine } from "../policy/engine";
import { ALL_CAPABILITIES } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { AuthContext } from "../auth/middleware";
import type { PatternEngine } from "../patterns/engine";
import type { DynamicSecretsManager } from "../dynamic/manager";

const PATH_REGEX = /^[a-zA-Z0-9/_-]+$/;
const MAX_METADATA_VALUE_SIZE = 1024; // 1KB per value

function validatePath(path: string): string | null {
  if (!path || path.length === 0) return "Path is required";
  if (path.length > 256) return "Path must be under 256 characters";
  if (!PATH_REGEX.test(path)) return "Path must match ^[a-zA-Z0-9/_-]+$";
  return null;
}

/**
 * Parse a .env-style block into key/value pairs.
 * Supports KEY=value, quoted values, blank lines, # comments, and "export KEY=value".
 */
function parseEnvBlock(text: string): { entries: Record<string, string>; errors: string[] } {
  const entries: Record<string, string> = {};
  const errors: string[] = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, i) => {
    let line = raw.trim();
    if (!line || line.startsWith("#")) return;
    if (line.startsWith("export ")) line = line.slice(7).trim();
    const eq = line.indexOf("=");
    if (eq <= 0) {
      errors.push(`line ${i + 1}: missing '=' or empty key`);
      return;
    }
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      errors.push(`line ${i + 1}: invalid key "${key}"`);
      return;
    }
    entries[key] = val;
  });
  return { entries, errors };
}

/** ENV_VAR_NAME → env-var-name (lowercase, underscores to dashes) */
function envKeyToSegment(k: string): string {
  return k.toLowerCase().replace(/_/g, "-");
}

export function bulkSecretsRouter(
  secrets: SecretsEngine,
  policies: PolicyEngine,
  audit: AuditLog
) {
  const router = new Hono();

  // POST /v1/secrets-bulk
  // Body: { prefix?: string, env_text?: string, secrets?: Array<{path,value,metadata?}>, dry_run?: bool }
  router.post("/", async (c) => {
    const auth = c.get("auth") as AuthContext;

    let body: {
      prefix?: string;
      env_text?: string;
      secrets?: Array<{ path: string; value: string; metadata?: Record<string, string> }>;
      dry_run?: boolean;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const prefix = (body.prefix || "").replace(/^\/+|\/+$/g, "");
    const items: Array<{ path: string; value: string; metadata?: Record<string, string> }> = [];

    if (body.env_text) {
      const { entries, errors } = parseEnvBlock(body.env_text);
      if (errors.length) {
        return c.json({ error: "env parse errors", details: errors, request_id: c.get("requestId") }, 400);
      }
      for (const [k, v] of Object.entries(entries)) {
        const seg = envKeyToSegment(k);
        const fullPath = prefix ? `${prefix}/${seg}` : seg;
        items.push({ path: fullPath, value: v, metadata: { source: "env_import", env_key: k } });
      }
    }

    if (Array.isArray(body.secrets)) {
      for (const s of body.secrets) {
        if (!s.path || typeof s.value !== "string") {
          return c.json({ error: "each secret needs {path, value}", request_id: c.get("requestId") }, 400);
        }
        const fullPath = prefix ? `${prefix}/${s.path.replace(/^\/+/, "")}` : s.path;
        items.push({ path: fullPath, value: s.value, metadata: s.metadata });
      }
    }

    if (items.length === 0) {
      return c.json({ error: "no secrets to import (provide env_text or secrets)", request_id: c.get("requestId") }, 400);
    }

    // Validate every path + policy up front so we don't half-import.
    for (const it of items) {
      const perr = validatePath(it.path);
      if (perr) {
        return c.json({ error: `${it.path}: ${perr}`, request_id: c.get("requestId") }, 400);
      }
      if (!policies.check(auth.policies, it.path, "write")) {
        return c.json({ error: `${it.path}: write forbidden`, request_id: c.get("requestId") }, 403);
      }
    }

    if (body.dry_run) {
      return c.json({ dry_run: true, would_import: items.map((i) => i.path) });
    }

    const imported: string[] = [];
    for (const it of items) {
      secrets.put(it.path, it.value, it.metadata || {});
      imported.push(it.path);
    }

    audit.log({
      identity: auth.identity,
      action: "secret.bulk_import",
      source_ip: c.get("sourceIp"),
      metadata: { count: String(imported.length) },
    });

    return c.json({ imported_count: imported.length, paths: imported }, 201);
  });

  return router;
}

export function secretsRouter(
  secrets: SecretsEngine,
  policies: PolicyEngine,
  audit: AuditLog,
  patterns?: PatternEngine,
  dynamic?: DynamicSecretsManager
) {
  const router = new Hono();

  // List secrets (metadata only, no values).
  // Returns every secret (static + dynamic) the caller can use via any
  // capability. Static entries carry kind: "static", dynamic configs carry
  // kind: "dynamic" + provider_type. Agents filter by caps or kind.
  router.get("/", (c) => {
    const auth = c.get("auth") as AuthContext;
    const prefix = c.req.query("prefix") || "";

    const USABLE_CAPS = ["list", "read", "proxy", "lease"] as const;
    const capsFor = (path: string) =>
      ALL_CAPABILITIES.filter((cap) => policies.check(auth.policies, path, cap));

    const allStatic = secrets.list(prefix);
    const staticWithCaps = allStatic.map((s) => ({ s, caps: capsFor(s.path) }));
    const staticResults = staticWithCaps.filter(({ caps }) =>
      USABLE_CAPS.some((cap) => caps.includes(cap))
    );

    const allDynamic = dynamic ? dynamic.listConfigs(prefix) : [];
    const dynamicWithCaps = allDynamic.map((d) => ({ d, caps: capsFor(d.path) }));
    const dynamicResults = dynamicWithCaps.filter(
      ({ caps }) => caps.includes("lease") || caps.includes("admin")
    );

    // Only 403 if both sides had candidates but policy filtered everything out.
    const totalCandidates = allStatic.length + allDynamic.length;
    const totalVisible = staticResults.length + dynamicResults.length;
    if (totalVisible === 0 && totalCandidates > 0) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    audit.log({
      identity: auth.identity,
      action: "secret.list",
      path: prefix || "*",
      source_ip: c.get("sourceIp"),
    });

    const summary = patterns?.summaryByPath();
    const staticEnriched = staticResults.map(({ s, caps }) => {
      const hit = summary?.get(s.path);
      return {
        ...s,
        kind: "static" as const,
        caps,
        pattern_count: hit?.count ?? 0,
        ...(hit ? { top_pattern: hit.top } : {}),
      };
    });
    const dynamicEnriched = dynamicResults.map(({ d, caps }) => ({
      path: d.path,
      kind: "dynamic" as const,
      provider_type: d.provider_type,
      metadata: d.metadata,
      updated_at: d.updated_at,
      caps,
    }));

    const merged = [...staticEnriched, ...dynamicEnriched].sort((a, b) =>
      a.path < b.path ? -1 : a.path > b.path ? 1 : 0
    );

    return c.json({ secrets: merged });
  });

  // Get secret value or metadata.
  // Route /:path{.+}/value does not work reliably in Hono when the path contains
  // slashes (the greedy .+ consumes the /value suffix). Handle both in one route
  // by detecting the /value suffix on the raw path parameter.
  router.get("/:path{.+}", (c) => {
    const auth = c.get("auth") as AuthContext;
    const rawPath = c.req.param("path");

    const isValueRequest = rawPath.endsWith("/value");
    const isVersionsRequest = rawPath.endsWith("/versions");
    const versionMatch = rawPath.match(/^(.+)\/versions\/(\d+)$/);
    let path = rawPath;
    if (isValueRequest) path = rawPath.slice(0, -6);
    else if (isVersionsRequest) path = rawPath.slice(0, -9);
    else if (versionMatch) path = versionMatch[1]!;

    const pathError = validatePath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    // Metadata-only reads (no /value, /versions, or /versions/N) are gated on
    // any usable capability - proxy/lease/list callers need to see metadata
    // like header_name and allowed_domains to construct requests, without
    // that being grantable as a value read. Raw value reads still require
    // `read` specifically.
    const needsReadCap = isValueRequest || isVersionsRequest || !!versionMatch;
    const allowed = needsReadCap
      ? policies.check(auth.policies, path, "read")
      : policies.check(auth.policies, path, "read") ||
        policies.check(auth.policies, path, "proxy") ||
        policies.check(auth.policies, path, "lease") ||
        policies.check(auth.policies, path, "list");
    if (!allowed) {
      audit.log({
        identity: auth.identity,
        action: isValueRequest ? "secret.reveal_value" : "secret.read_metadata",
        path,
        success: false,
        source_ip: c.get("sourceIp"),
      });
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    if (isValueRequest) {
      const value = secrets.get(path);
      if (value === null) {
        return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
      }

      audit.log({
        identity: auth.identity,
        action: "secret.reveal_value",
        path,
        source_ip: c.get("sourceIp"),
      });

      // Return raw value for exec-based secret providers (e.g. OpenClaw)
      if (c.req.header("Accept") === "text/plain") {
        return c.text(value);
      }
      return c.json({ path, value });
    }

    if (isVersionsRequest) {
      if (!secrets.exists(path)) {
        return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
      }
      return c.json({ versions: secrets.listVersions(path) });
    }

    if (versionMatch) {
      const v = parseInt(versionMatch[2]!, 10);
      const value = secrets.getVersion(path, v);
      if (value === null) {
        return c.json({ error: "Version not found", request_id: c.get("requestId") }, 404);
      }
      audit.log({
        identity: auth.identity,
        action: "secret.reveal_value",
        path,
        metadata: { version: String(v) },
        source_ip: c.get("sourceIp"),
      });
      if (c.req.header("Accept") === "text/plain") return c.text(value);
      return c.json({ path, version: v, value });
    }

    // Metadata only (no value)
    const meta = secrets.getMeta(path);
    if (!meta) {
      return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
    }
    audit.log({
      identity: auth.identity,
      action: "secret.read_metadata",
      path,
      source_ip: c.get("sourceIp"),
    });
    return c.json(meta);
  });

  // Create or update a secret (or rollback to a prior version)
  router.post("/:path{.+}", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const rawPath = c.req.param("path");

    const isRollback = rawPath.endsWith("/rollback");
    const path = isRollback ? rawPath.slice(0, -9) : rawPath;

    const pathError = validatePath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "write")) {
      audit.log({ identity: auth.identity, action: "secret.write", path, success: false });
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    if (isRollback) {
      let rbBody: { version?: number };
      try {
        rbBody = await c.req.json();
      } catch {
        return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
      }
      const v = rbBody.version;
      if (typeof v !== "number" || v < 1) {
        return c.json({ error: "version (positive integer) is required", request_id: c.get("requestId") }, 400);
      }
      const result = secrets.rollback(path, v);
      if (!result) {
        return c.json({ error: "Version not found", request_id: c.get("requestId") }, 404);
      }
      audit.log({
        identity: auth.identity,
        action: "secret.rollback",
        path,
        metadata: { rolled_back_to: String(v), new_version: String(result.version) },
        source_ip: c.get("sourceIp"),
      });
      return c.json(result);
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

  // Update only the metadata of an existing secret (no value rotation).
  router.patch("/:path{.+}", async (c) => {
    const auth = c.get("auth") as AuthContext;
    const path = c.req.param("path");

    const pathError = validatePath(path);
    if (pathError) {
      return c.json({ error: pathError, request_id: c.get("requestId") }, 400);
    }

    if (!policies.check(auth.policies, path, "write")) {
      audit.log({ identity: auth.identity, action: "secret.metadata_update", path, success: false });
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    let body: { metadata?: Record<string, string> };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const metadata = body.metadata;
    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
      return c.json({ error: "metadata (object) is required", request_id: c.get("requestId") }, 400);
    }
    for (const [k, v] of Object.entries(metadata)) {
      if (typeof v !== "string") {
        return c.json({ error: `metadata value for "${k}" must be a string`, request_id: c.get("requestId") }, 400);
      }
      if (v.length > MAX_METADATA_VALUE_SIZE) {
        return c.json({ error: `metadata value for "${k}" exceeds 1KB limit`, request_id: c.get("requestId") }, 400);
      }
    }

    const result = secrets.setMetadata(path, metadata);
    if (!result) {
      return c.json({ error: "Not found", request_id: c.get("requestId") }, 404);
    }

    audit.log({
      identity: auth.identity,
      action: "secret.metadata_update",
      path,
      source_ip: c.get("sourceIp"),
    });

    return c.json(result);
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
