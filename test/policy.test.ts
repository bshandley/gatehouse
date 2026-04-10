import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Database } from "bun:sqlite";
import { PolicyEngine } from "../src/policy/engine";
import { initDB } from "../src/db/init";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

describe("PolicyEngine", () => {
  let engine: PolicyEngine;
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-policy-"));
    const policyDir = join(dir, "policies");
    mkdirSync(policyDir);
    writeFileSync(
      join(policyDir, "test.yaml"),
      `name: test
rules:
  - path: "api-keys/*"
    capabilities: [read, lease]
  - path: "db/prod"
    capabilities: [read]
  - path: "services/*"
    capabilities: [read, list, lease]
`
    );
    writeFileSync(
      join(policyDir, "writer.yaml"),
      `name: writer
rules:
  - path: "api-keys/*"
    capabilities: [read, write, delete]
  - path: "config/*"
    capabilities: [read, write, list]
`
    );
    engine = new PolicyEngine(dir);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test("loads policies from YAML", () => {
    const names = engine.listPolicies();
    expect(names).toContain("test");
    expect(names).toContain("writer");
    expect(names).toContain("admin");
  });

  test("getPolicy returns loaded policy with paths array", () => {
    const policy = engine.getPolicy("test");
    expect(policy).toBeDefined();
    expect(policy!.name).toBe("test");
    expect(policy!.rules.length).toBe(3);
    expect(policy!.rules[0].paths).toEqual(["api-keys/*"]);
  });

  test("getPolicy returns undefined for unknown", () => {
    expect(engine.getPolicy("nope")).toBeUndefined();
  });

  test("wildcard match grants access", () => {
    expect(engine.check(["test"], "api-keys/openai", "read")).toBe(true);
    expect(engine.check(["test"], "api-keys/openai", "lease")).toBe(true);
  });

  test("wildcard matches nested paths", () => {
    expect(engine.check(["test"], "services/stripe/key", "read")).toBe(true);
  });

  test("exact path match works", () => {
    expect(engine.check(["test"], "db/prod", "read")).toBe(true);
  });

  test("exact path does not match sub-paths", () => {
    expect(engine.check(["test"], "db/prod/extra", "read")).toBe(false);
  });

  test("denies unmatched paths", () => {
    expect(engine.check(["test"], "git/token", "read")).toBe(false);
  });

  test("denies unmatched capabilities", () => {
    expect(engine.check(["test"], "api-keys/openai", "delete")).toBe(false);
    expect(engine.check(["test"], "api-keys/openai", "write")).toBe(false);
  });

  test("admin policy grants everything", () => {
    expect(engine.check(["admin"], "anything/at/all", "delete")).toBe(true);
    expect(engine.check(["admin"], "foo", "admin")).toBe(true);
  });

  test("multi-policy resolution merges permissions", () => {
    // test policy gives read+lease on api-keys/*, writer gives read+write+delete
    expect(engine.check(["test", "writer"], "api-keys/openai", "read")).toBe(true);
    expect(engine.check(["test", "writer"], "api-keys/openai", "lease")).toBe(true);
    expect(engine.check(["test", "writer"], "api-keys/openai", "delete")).toBe(true);
    expect(engine.check(["test", "writer"], "api-keys/openai", "write")).toBe(true);
  });

  test("empty policies array denies everything", () => {
    expect(engine.check([], "api-keys/openai", "read")).toBe(false);
  });

  test("unknown policy name is safely ignored", () => {
    expect(engine.check(["nonexistent"], "api-keys/openai", "read")).toBe(false);
  });

  test("reload reloads policies from disk", () => {
    // Add a new policy file
    writeFileSync(
      join(dir, "policies", "new.yaml"),
      `name: new-policy
rules:
  - path: "new/*"
    capabilities: [read]
`
    );
    engine.reload();
    expect(engine.listPolicies()).toContain("new-policy");
    expect(engine.check(["new-policy"], "new/path", "read")).toBe(true);
  });

  test("handles missing policy directory gracefully", () => {
    const emptyDir = mkdtempSync(join(tmpdir(), "gatehouse-empty-"));
    const eng = new PolicyEngine(emptyDir);
    // Admin policy should always be present even without a policies dir
    expect(eng.listPolicies()).toContain("admin");
    expect(eng.listPolicies().length).toBe(1);
    rmSync(emptyDir, { recursive: true, force: true });
  });
});

describe("PolicyEngine (DB-backed CRUD)", () => {
  let engine: PolicyEngine;
  let dir: string;
  let db: Database;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-policy-db-"));
    mkdirSync(join(dir, "policies"));
    db = initDB(dir);
    engine = new PolicyEngine(dir, db);
  });

  afterEach(() => {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("savePolicy creates a new policy in DB", () => {
    const result = engine.savePolicy("my-policy", [
      { paths: ["secrets/*"], capabilities: ["read", "list"] },
    ]);
    expect(result.name).toBe("my-policy");
    expect(result.source).toBe("db");
    expect(result.rules).toHaveLength(1);
    expect(result.rules[0].paths).toEqual(["secrets/*"]);
    expect(engine.check(["my-policy"], "secrets/foo", "read")).toBe(true);
    expect(engine.check(["my-policy"], "secrets/foo", "write")).toBe(false);
  });

  test("savePolicy updates an existing DB policy", () => {
    engine.savePolicy("my-policy", [{ paths: ["a/*"], capabilities: ["read"] }]);
    engine.savePolicy("my-policy", [{ paths: ["b/*"], capabilities: ["write"] }]);
    expect(engine.check(["my-policy"], "a/x", "read")).toBe(false);
    expect(engine.check(["my-policy"], "b/x", "write")).toBe(true);
  });

  test("deletePolicy removes a DB policy", () => {
    engine.savePolicy("deleteme", [{ paths: ["*"], capabilities: ["read"] }]);
    expect(engine.listPolicies()).toContain("deleteme");
    const deleted = engine.deletePolicy("deleteme");
    expect(deleted).toBe(true);
    expect(engine.listPolicies()).not.toContain("deleteme");
  });

  test("deletePolicy returns false for nonexistent policy", () => {
    expect(engine.deletePolicy("nope")).toBe(false);
  });

  test("cannot delete admin policy", () => {
    expect(() => engine.deletePolicy("admin")).toThrow("Cannot delete built-in admin policy");
  });

  test("cannot modify admin policy", () => {
    expect(() => engine.savePolicy("admin", [{ paths: ["*"], capabilities: ["read"] }])).toThrow("Cannot modify built-in admin policy");
  });

  test("DB policies override YAML policies with same name", () => {
    writeFileSync(
      join(dir, "policies", "overlap.yaml"),
      `name: overlap\nrules:\n  - path: "yaml/*"\n    capabilities: [read]\n`
    );
    engine.reload();
    // YAML should be loaded first, then overridden by DB
    engine.savePolicy("overlap", [{ paths: ["db/*"], capabilities: ["write"] }]);
    engine.reload();
    expect(engine.check(["overlap"], "yaml/x", "read")).toBe(false);
    expect(engine.check(["overlap"], "db/x", "write")).toBe(true);
  });

  test("getPolicyDetailed returns source and timestamps", () => {
    engine.savePolicy("detailed", [{ paths: ["*"], capabilities: ["read"] }]);
    const detail = engine.getPolicyDetailed("detailed");
    expect(detail).toBeDefined();
    expect(detail!.source).toBe("db");
    expect(detail!.created_at).toBeDefined();
    expect(detail!.updated_at).toBeDefined();
  });

  test("listPoliciesDetailed returns all policies with metadata", () => {
    engine.savePolicy("extra", [{ paths: ["*"], capabilities: ["list"] }]);
    const all = engine.listPoliciesDetailed();
    expect(all.length).toBeGreaterThanOrEqual(2); // admin + extra
    const extra = all.find(p => p.name === "extra");
    expect(extra).toBeDefined();
    expect(extra!.source).toBe("db");
  });

  test("YAML-sourced policies are auto-imported and deletable", () => {
    writeFileSync(
      join(dir, "policies", "fromyaml.yaml"),
      `name: fromyaml\nrules:\n  - path: "*"\n    capabilities: [read]\n`
    );
    engine.reload();
    const detail = engine.getPolicyDetailed("fromyaml");
    expect(detail).toBeDefined();
    expect(detail!.source).toBe("db");
    expect(engine.deletePolicy("fromyaml")).toBe(true);
  });

  test("auto-imports YAML policies into DB on boot", () => {
    writeFileSync(
      join(dir, "policies", "auto-import.yaml"),
      `name: auto-import\nrules:\n  - path: "keys/*"\n    capabilities: [read, lease]\n`
    );
    const fresh = new PolicyEngine(dir, db);
    const detail = fresh.getPolicyDetailed("auto-import");
    expect(detail).toBeDefined();
    expect(detail!.source).toBe("db");
    expect(detail!.rules).toHaveLength(1);
    expect(detail!.rules[0].paths).toEqual(["keys/*"]);
    expect(fresh.check(["auto-import"], "keys/foo", "read")).toBe(true);
  });

  test("auto-import does not overwrite existing DB policy", () => {
    engine.savePolicy("no-overwrite", [{ paths: ["db-version/*"], capabilities: ["write"] }]);
    writeFileSync(
      join(dir, "policies", "no-overwrite.yaml"),
      `name: no-overwrite\nrules:\n  - path: "yaml-version/*"\n    capabilities: [read]\n`
    );
    const fresh = new PolicyEngine(dir, db);
    expect(fresh.check(["no-overwrite"], "db-version/x", "write")).toBe(true);
    expect(fresh.check(["no-overwrite"], "yaml-version/x", "read")).toBe(false);
  });

  test("importFromYaml returns list of newly imported policy names", () => {
    writeFileSync(
      join(dir, "policies", "import-me.yaml"),
      `name: import-me\nrules:\n  - path: "foo/*"\n    capabilities: [read]\n`
    );
    const result = engine.importFromYaml();
    expect(result.imported).toContain("import-me");
    const second = engine.importFromYaml();
    expect(second.imported).toHaveLength(0);
  });

  test("all non-admin policies are deletable after auto-import", () => {
    writeFileSync(
      join(dir, "policies", "deletable.yaml"),
      `name: deletable\nrules:\n  - path: "*"\n    capabilities: [read]\n`
    );
    const fresh = new PolicyEngine(dir, db);
    expect(fresh.listPolicies()).toContain("deletable");
    const deleted = fresh.deletePolicy("deletable");
    expect(deleted).toBe(true);
    expect(fresh.listPolicies()).not.toContain("deletable");
  });

  test("savePolicy accepts paths array format", () => {
    const result = engine.savePolicy("multi-path", [
      { paths: ["api-keys/*", "services/*"], capabilities: ["read", "lease"] },
    ]);
    expect(result.name).toBe("multi-path");
    expect(result.rules[0].paths).toEqual(["api-keys/*", "services/*"]);
    expect(engine.check(["multi-path"], "api-keys/openai", "read")).toBe(true);
    expect(engine.check(["multi-path"], "services/stripe", "lease")).toBe(true);
    expect(engine.check(["multi-path"], "db/prod", "read")).toBe(false);
  });

  test("normalizes legacy path string to paths array on load", () => {
    db.query("INSERT INTO policies (name, rules) VALUES (?, ?)").run(
      "legacy-format",
      JSON.stringify([{ path: "old/*", capabilities: ["read"] }])
    );
    const fresh = new PolicyEngine(dir, db);
    const policy = fresh.getPolicy("legacy-format");
    expect(policy).toBeDefined();
    expect(policy!.rules[0].paths).toEqual(["old/*"]);
    expect(fresh.check(["legacy-format"], "old/secret", "read")).toBe(true);
  });

  test("check iterates all paths in a multi-path rule", () => {
    engine.savePolicy("broad", [
      { paths: ["a/*", "b/*", "c/*"], capabilities: ["read"] },
    ]);
    expect(engine.check(["broad"], "a/1", "read")).toBe(true);
    expect(engine.check(["broad"], "b/2", "read")).toBe(true);
    expect(engine.check(["broad"], "c/3", "read")).toBe(true);
    expect(engine.check(["broad"], "d/4", "read")).toBe(false);
  });

  test("admin policy uses paths array format", () => {
    const admin = engine.getPolicy("admin");
    expect(admin).toBeDefined();
    expect(admin!.rules[0].paths).toEqual(["*"]);
  });
});
