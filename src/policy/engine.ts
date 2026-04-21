import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import YAML from "yaml";
import type { Database } from "bun:sqlite";

export type Capability = "read" | "write" | "delete" | "list" | "lease" | "proxy" | "admin";

export const ALL_CAPABILITIES: Capability[] = ["read", "write", "delete", "list", "lease", "proxy", "admin"];

export interface PolicyRule {
  paths: string[]; // glob patterns, e.g. ["api-keys/*", "services/*"]
  capabilities: Capability[];
}

/** Normalize a rule that might have legacy `path` (string) to `paths` (array) */
function normalizeRule(rule: any): PolicyRule {
  if (rule.paths && Array.isArray(rule.paths)) {
    return { paths: rule.paths, capabilities: rule.capabilities };
  }
  if (rule.path && typeof rule.path === "string") {
    return { paths: [rule.path], capabilities: rule.capabilities };
  }
  return { paths: [], capabilities: rule.capabilities || [] };
}

export interface Policy {
  name: string;
  rules: PolicyRule[];
}

export interface PolicyDetailed extends Policy {
  source: "yaml" | "db";
  created_at?: string;
  updated_at?: string;
}

export class PolicyEngine {
  private policies: Map<string, Policy> = new Map();
  private policySources: Map<string, "yaml" | "db"> = new Map();
  private patternCache: Map<string, RegExp> = new Map();
  private configDir: string;
  private db: Database | null;

  constructor(configDir: string, db?: Database) {
    this.configDir = configDir;
    this.db = db || null;
    this.loadPolicies();
  }

  /**
   * Scan the YAML policy directory and insert any new policies into the DB.
   * Returns the list of policy names that were newly imported.
   */
  private seedYamlPolicies(): string[] {
    if (!this.db) return [];
    const policyDir = join(this.configDir, "policies");
    if (!existsSync(policyDir)) return [];

    const imported: string[] = [];
    const files = readdirSync(policyDir).filter(
      (f) => f.endsWith(".yaml") || f.endsWith(".yml")
    );

    for (const file of files) {
      try {
        const content = readFileSync(join(policyDir, file), "utf-8");
        const policy = YAML.parse(content) as Policy;
        if (policy.name && policy.rules && policy.name !== "admin") {
          const normalizedRules = policy.rules.map(normalizeRule);
          const existing = this.db
            .query("SELECT name FROM policies WHERE name = ?")
            .get(policy.name);
          if (!existing) {
            const rulesJson = JSON.stringify(normalizedRules);
            this.db
              .query("INSERT INTO policies (name, rules) VALUES (?, ?)")
              .run(policy.name, rulesJson);
            imported.push(policy.name);
            console.log(`[gatehouse:policy] imported YAML policy to DB: ${policy.name}`);
          }
        }
      } catch (e) {
        console.error(`[gatehouse:policy] failed to load ${file}:`, e);
      }
    }

    return imported;
  }

  private loadPolicies() {
    const policyDir = join(this.configDir, "policies");
    if (this.db) {
      this.seedYamlPolicies();
    } else if (existsSync(policyDir)) {
      const files = readdirSync(policyDir).filter(
        (f) => f.endsWith(".yaml") || f.endsWith(".yml")
      );
      for (const file of files) {
        try {
          const content = readFileSync(join(policyDir, file), "utf-8");
          const policy = YAML.parse(content) as Policy;
          if (policy.name && policy.rules) {
            policy.rules = policy.rules.map(normalizeRule);
            this.policies.set(policy.name, policy);
            this.policySources.set(policy.name, "yaml");
            console.log(`[gatehouse:policy] loaded policy: ${policy.name}`);
          }
        } catch (e) {
          console.error(`[gatehouse:policy] failed to load ${file}:`, e);
        }
      }
    }

    if (this.db) {
      const rows = this.db.query("SELECT name, rules FROM policies").all() as {
        name: string;
        rules: string;
      }[];
      for (const row of rows) {
        try {
          const rules = (JSON.parse(row.rules) as any[]).map(normalizeRule);
          this.policies.set(row.name, { name: row.name, rules });
          this.policySources.set(row.name, "db");
        } catch (e) {
          console.error(`[gatehouse:policy] failed to parse db policy ${row.name}:`, e);
        }
      }
    }

    this.policies.set("admin", {
      name: "admin",
      rules: [{ paths: ["*"], capabilities: ["read", "write", "delete", "list", "lease", "proxy", "admin"] }],
    });
    this.policySources.set("admin", "yaml");
  }

  reload() {
    this.policies.clear();
    this.policySources.clear();
    this.patternCache.clear();
    this.loadPolicies();
  }

  /**
   * Re-import YAML policies that don't exist in DB.
   * Does NOT overwrite existing DB policies.
   */
  importFromYaml(): { imported: string[] } {
    if (!this.db) return { imported: [] };
    const imported = this.seedYamlPolicies();

    if (imported.length > 0) {
      this.policies.clear();
      this.policySources.clear();
      this.loadPolicies();
    }

    return { imported };
  }

  getPolicy(name: string): Policy | undefined {
    return this.policies.get(name);
  }

  getPolicyDetailed(name: string): PolicyDetailed | undefined {
    const policy = this.policies.get(name);
    if (!policy) return undefined;

    const source = this.policySources.get(name) || "yaml";
    const detailed: PolicyDetailed = { ...policy, source };

    if (source === "db" && this.db) {
      const row = this.db
        .query("SELECT created_at, updated_at FROM policies WHERE name = ?")
        .get(name) as { created_at: string; updated_at: string } | null;
      if (row) {
        detailed.created_at = row.created_at;
        detailed.updated_at = row.updated_at;
      }
    }

    return detailed;
  }

  listPolicies(): string[] {
    return Array.from(this.policies.keys());
  }

  listPoliciesDetailed(): PolicyDetailed[] {
    return this.listPolicies().map((name) => this.getPolicyDetailed(name)!);
  }

  savePolicy(name: string, rules: PolicyRule[]): PolicyDetailed {
    if (name === "admin") throw new Error("Cannot modify built-in admin policy");
    if (!this.db) throw new Error("Database not available for policy storage");

    const normalizedRules = rules.map(normalizeRule);
    const rulesJson = JSON.stringify(normalizedRules);
    this.db
      .query(
        `INSERT INTO policies (name, rules) VALUES (?, ?)
         ON CONFLICT(name) DO UPDATE SET rules = ?, updated_at = datetime('now')`
      )
      .run(name, rulesJson, rulesJson);

    this.policies.set(name, { name, rules: normalizedRules });
    this.policySources.set(name, "db");

    return this.getPolicyDetailed(name)!;
  }

  deletePolicy(name: string): boolean {
    if (name === "admin") throw new Error("Cannot delete built-in admin policy");
    if (!this.db) throw new Error("Database not available for policy storage");

    const existing = this.db.query("SELECT name FROM policies WHERE name = ?").get(name);
    if (!existing) return false;

    this.db.query("DELETE FROM policies WHERE name = ?").run(name);
    this.policies.delete(name);
    this.policySources.delete(name);
    return true;
  }

  /**
   * Check if a set of policy names grants a capability on a path.
   * Uses glob matching: "secrets/api-keys/*" matches "secrets/api-keys/openai"
   */
  /**
   * Flattened rules for a set of policy names. Unknown policy names are
   * silently skipped. Useful for introspection (e.g. "does this role grant
   * `lease` on any path starting with `db/`?") without exposing the internal
   * policies map.
   */
  rulesFor(policyNames: string[]): PolicyRule[] {
    const out: PolicyRule[] = [];
    for (const name of policyNames) {
      const policy = this.policies.get(name);
      if (!policy) continue;
      out.push(...policy.rules);
    }
    return out;
  }

  /**
   * True if any rule in the given policies grants `capability` on any path
   * that begins with `prefix`. Path prefixes are compared literally (no glob
   * expansion); a rule path of `db/*` with prefix `db/` matches.
   */
  hasCapabilityOnPrefix(
    policyNames: string[],
    prefix: string,
    capability: Capability
  ): boolean {
    for (const rule of this.rulesFor(policyNames)) {
      if (!rule.capabilities.includes(capability)) continue;
      if (rule.paths.some((p) => p.startsWith(prefix) || p === "*")) return true;
    }
    return false;
  }

  check(
    policyNames: string[],
    path: string,
    capability: Capability
  ): boolean {
    for (const name of policyNames) {
      const policy = this.policies.get(name);
      if (!policy) continue;

      for (const rule of policy.rules) {
        if (
          rule.paths.some(p => this.matchPath(p, path)) &&
          rule.capabilities.includes(capability)
        ) {
          return true;
        }
      }
    }
    return false;
  }

  private matchPath(pattern: string, path: string): boolean {
    if (pattern === "*") return true;

    let regex = this.patternCache.get(pattern);
    if (!regex) {
      const escaped = pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".");
      regex = new RegExp("^" + escaped + "$");
      this.patternCache.set(pattern, regex);
    }
    return regex.test(path);
  }
}
