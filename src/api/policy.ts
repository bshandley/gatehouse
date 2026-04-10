import { Hono } from "hono";
import type { PolicyEngine, PolicyRule, Capability } from "../policy/engine";
import { ALL_CAPABILITIES } from "../policy/engine";
import type { AuditLog } from "../audit/logger";
import type { AuthContext } from "../auth/middleware";

const NAME_REGEX = /^[a-zA-Z0-9_-]+$/;

function validatePolicyName(name: string): string | null {
  if (!name || name.length === 0) return "Policy name is required";
  if (name.length > 64) return "Policy name must be under 64 characters";
  if (!NAME_REGEX.test(name)) return "Policy name must match ^[a-zA-Z0-9_-]+$";
  if (name === "admin") return "Cannot modify built-in admin policy";
  return null;
}

function validateRules(rules: unknown): string | null {
  if (!Array.isArray(rules)) return "rules must be an array";
  if (rules.length === 0) return "rules must have at least one entry";
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i] as any;
    // Accept either paths (array) or path (string, legacy)
    const hasPaths = Array.isArray(rule.paths) && rule.paths.length > 0;
    const hasPath = rule.path && typeof rule.path === "string";
    if (!hasPaths && !hasPath) return `rules[${i}] must have "paths" (array) or "path" (string)`;
    if (hasPaths) {
      for (let j = 0; j < rule.paths.length; j++) {
        if (typeof rule.paths[j] !== "string" || !rule.paths[j])
          return `rules[${i}].paths[${j}] must be a non-empty string`;
      }
    }
    if (!Array.isArray(rule.capabilities) || rule.capabilities.length === 0)
      return `rules[${i}].capabilities must be a non-empty array`;
    for (const cap of rule.capabilities) {
      if (!ALL_CAPABILITIES.includes(cap as Capability))
        return `rules[${i}].capabilities contains invalid value "${cap}"`;
    }
  }
  return null;
}

export function policyRouter(policies: PolicyEngine, audit: AuditLog) {
  const router = new Hono();

  // List all policies with details
  router.get("/", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }
    return c.json({ policies: policies.listPoliciesDetailed() });
  });

  // Get single policy detail
  router.get("/:name", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const name = c.req.param("name");
    // Don't match the "reload" action as a policy name
    if (name === "reload") return c.notFound();

    const policy = policies.getPolicyDetailed(name);
    if (!policy) {
      return c.json({ error: "Policy not found", request_id: c.get("requestId") }, 404);
    }
    return c.json(policy);
  });

  // Create or update a policy
  router.post("/", async (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    let body: { name: string; rules: PolicyRule[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const nameError = validatePolicyName(body.name);
    if (nameError) {
      return c.json({ error: nameError, request_id: c.get("requestId") }, 400);
    }

    const rulesError = validateRules(body.rules);
    if (rulesError) {
      return c.json({ error: rulesError, request_id: c.get("requestId") }, 400);
    }

    try {
      const result = policies.savePolicy(body.name, body.rules);
      audit.log({
        identity: auth.identity,
        action: "policy.save",
        path: body.name,
        source_ip: c.get("sourceIp"),
      });
      return c.json(result, 201);
    } catch (e: any) {
      return c.json({ error: e.message, request_id: c.get("requestId") }, 400);
    }
  });

  // Update a policy by name
  router.put("/:name", async (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const name = c.req.param("name");
    const nameError = validatePolicyName(name);
    if (nameError) {
      return c.json({ error: nameError, request_id: c.get("requestId") }, 400);
    }

    let body: { rules: PolicyRule[] };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    const rulesError = validateRules(body.rules);
    if (rulesError) {
      return c.json({ error: rulesError, request_id: c.get("requestId") }, 400);
    }

    try {
      const result = policies.savePolicy(name, body.rules);
      audit.log({
        identity: auth.identity,
        action: "policy.update",
        path: name,
        source_ip: c.get("sourceIp"),
      });
      return c.json(result);
    } catch (e: any) {
      return c.json({ error: e.message, request_id: c.get("requestId") }, 400);
    }
  });

  // Delete a policy
  router.delete("/:name", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }

    const name = c.req.param("name");

    try {
      const deleted = policies.deletePolicy(name);
      if (!deleted) {
        return c.json({ error: "Policy not found", request_id: c.get("requestId") }, 404);
      }
      audit.log({
        identity: auth.identity,
        action: "policy.delete",
        path: name,
        source_ip: c.get("sourceIp"),
      });
      return c.json({ deleted: true });
    } catch (e: any) {
      return c.json({ error: e.message, request_id: c.get("requestId") }, 400);
    }
  });

  // Import new YAML policies into DB (does not overwrite existing)
  router.post("/reload", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!policies.check(auth.policies, "*", "admin")) {
      return c.json({ error: "Forbidden", request_id: c.get("requestId") }, 403);
    }
    const result = policies.importFromYaml();
    audit.log({
      identity: auth.identity,
      action: "policy.import",
      metadata: { imported: result.imported.join(", ") || "none" },
    });
    return c.json({
      imported: result.imported,
      policies: policies.listPolicies(),
    });
  });

  return router;
}
