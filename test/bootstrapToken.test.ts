import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { mkdtempSync, rmSync, existsSync, statSync, readFileSync, writeFileSync, chmodSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import type { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { resolveBootstrapRootToken, hasAdminPrincipal, BOOTSTRAP_TOKEN_FILE } from "../src/auth/bootstrapToken";

let dir: string;
let db: Database;
const URL_ = "http://localhost:3100";

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "gh-bootstrap-"));
  db = initDB(dir);
});
afterEach(() => {
  try { db.close(); } catch {}
  try { chmodSync(dir, 0o700); } catch {}
  rmSync(dir, { recursive: true, force: true });
});

const file = () => join(dir, BOOTSTRAP_TOKEN_FILE);
const run = (envToken: string | undefined, lines: string[] = []) =>
  resolveBootstrapRootToken({ db, dataDir: dir, envToken, publicUrl: URL_, log: (l) => lines.push(l) });
const addUser = (enabled: number, role = "admin") =>
  db.query("INSERT INTO users (username, password_hash, display_name, role, enabled) VALUES ('u1', 'x', 'U', ?, ?)").run(role, enabled);

describe("bootstrap root token", () => {
  test("env token wins and no file is written", () => {
    const r = run("from-env");
    expect(r).toEqual({ token: "from-env", source: "env" });
    expect(existsSync(file())).toBe(false);
  });

  test("env token with an admin present is still used and a stale file is untouched", () => {
    addUser(1);
    writeFileSync(file(), "a".repeat(32));
    expect(run("from-env").source).toBe("env");
    expect(existsSync(file())).toBe(true);
  });

  test("fresh vault generates a 32-hex token, 0600, and logs it with the URL", () => {
    const lines: string[] = [];
    const r = run(undefined, lines);
    expect(r.source).toBe("generated");
    expect(r.token).toMatch(/^[0-9a-f]{32}$/);
    expect(statSync(file()).mode & 0o777).toBe(0o600);
    expect(readFileSync(file(), "utf8").trim()).toBe(r.token!);
    expect(lines.join("\n")).toContain(r.token!);
    expect(lines.join("\n")).toContain(URL_);
  });

  test("second call with no admin reuses the file and does not log the token", () => {
    const first = run(undefined);
    const lines: string[] = [];
    const second = run(undefined, lines);
    expect(second.source).toBe("file");
    expect(second.token).toBe(first.token!);
    expect(lines.join("\n")).not.toContain(first.token!);
    expect(lines.join("\n")).toContain(file());
  });

  test("enabled admin user: no token, stale file deleted and never loaded", () => {
    const stale = "b".repeat(32);
    writeFileSync(file(), stale);
    addUser(1);
    const lines: string[] = [];
    const r = run(undefined, lines);
    expect(r).toEqual({ token: null, source: "none" });
    expect(existsSync(file())).toBe(false);
    expect(lines.join("\n")).toContain("removed stale bootstrap-root.token (an admin exists)");
  });

  test("admin with no env token and no file: no root token at all", () => {
    addUser(1);
    expect(run(undefined)).toEqual({ token: null, source: "none" });
    expect(existsSync(file())).toBe(false);
  });

  test("admin AppRole counts as an admin principal", () => {
    db.query("INSERT INTO app_roles (role_id, secret_hash, display_name, policies) VALUES ('r1', 'x', 'R', '[\"admin\"]')").run();
    expect(hasAdminPrincipal(db)).toBe(true);
    expect(run(undefined).source).toBe("none");
  });

  test("an AppRole whose policy is named 'administrator-readonly' does not count", () => {
    db.query("INSERT INTO app_roles (role_id, secret_hash, display_name, policies) VALUES ('r1', 'x', 'R', '[\"administrator-readonly\"]')").run();
    expect(hasAdminPrincipal(db)).toBe(false);
  });

  test("malformed AppRole policies do not count and do not throw", () => {
    db.query("INSERT INTO app_roles (role_id, secret_hash, display_name, policies) VALUES ('r1', 'x', 'R', 'not json')").run();
    expect(hasAdminPrincipal(db)).toBe(false);
  });

  test("non-admin user does not count", () => {
    addUser(1, "viewer");
    expect(hasAdminPrincipal(db)).toBe(false);
  });

  test("disabled admin does not count, a fresh token is minted", () => {
    addUser(0);
    expect(run(undefined).source).toBe("generated");
  });

  test("deleted last admin: next boot mints a fresh token", () => {
    addUser(1);
    expect(run(undefined).source).toBe("none");
    db.query("DELETE FROM users").run();
    const r = run(undefined);
    expect(r.source).toBe("generated");
    expect(r.token).toMatch(/^[0-9a-f]{32}$/);
  });

  test("empty-string env token is treated as unset", () => {
    expect(run("").source).toBe("generated");
  });

  test("corrupt token file is replaced by a fresh token", () => {
    writeFileSync(file(), "x");
    const r = run(undefined);
    expect(r.source).toBe("generated");
    expect(readFileSync(file(), "utf8").trim()).toMatch(/^[0-9a-f]{32}$/);
  });

  test("unwritable data dir returns generated-unpersisted and still logs the token", () => {
    if (process.getuid?.() === 0) return;
    chmodSync(dir, 0o500);
    const lines: string[] = [];
    const r = run(undefined, lines);
    expect(r.source).toBe("generated-unpersisted");
    expect(r.token).toMatch(/^[0-9a-f]{32}$/);
    expect(lines.join("\n")).toContain(r.token!);
    expect(lines.join("\n")).toContain("NOT SAVED");
    expect(existsSync(file())).toBe(false);
  });

  test("whitespace-only env token is treated as unset", () => {
    const r = run("   \t ");
    expect(r.source).toBe("generated");
    expect(r.token).toMatch(/^[0-9a-f]{32}$/);
  });

  test("old compose default env token logs a loud warning and still wins", () => {
    const lines: string[] = [];
    const r = run("gatehouse-root-changeme", lines);
    expect(r).toEqual({ token: "gatehouse-root-changeme", source: "env" });
    const out = lines.join("\n");
    expect(out).toContain("WARNING");
    expect(out).toContain("publicly known");
    expect(out).not.toContain("gatehouse-root-changeme");
    expect(existsSync(file())).toBe(false);
  });

  test("another env token logs no warning", () => {
    const lines: string[] = [];
    expect(run("a-different-token", lines).source).toBe("env");
    expect(lines.join("\n")).not.toContain("WARNING");
  });

  test("reusing the token file tightens its mode to 0600", () => {
    const first = run(undefined);
    chmodSync(file(), 0o644);
    const second = run(undefined);
    expect(second).toEqual({ token: first.token, source: "file" });
    expect(statSync(file()).mode & 0o777).toBe(0o600);
  });

  test("banner names port 3100 on this host when no public URL is configured", () => {
    const lines: string[] = [];
    const r = resolveBootstrapRootToken({ db, dataDir: dir, envToken: undefined, publicUrl: undefined, port: 3100, log: (l) => lines.push(l) });
    expect(r.source).toBe("generated");
    const out = lines.join("\n");
    expect(out).toContain("port 3100 on this host");
    expect(out).not.toContain("localhost");
    expect(out).toContain(r.token!);
  });

  test("suspended admin AppRole does not count, a fresh token is minted", () => {
    db.query("INSERT INTO app_roles (role_id, secret_hash, display_name, policies, suspended) VALUES ('r1', 'x', 'R', '[\"admin\"]', 1)").run();
    expect(hasAdminPrincipal(db)).toBe(false);
    expect(run(undefined).source).toBe("generated");
  });

  test("deleted last admin AppRole: next boot mints a fresh token", () => {
    db.query("INSERT INTO app_roles (role_id, secret_hash, display_name, policies) VALUES ('r1', 'x', 'R', '[\"admin\"]')").run();
    expect(run(undefined).source).toBe("none");
    db.query("DELETE FROM app_roles").run();
    const r = run(undefined);
    expect(r.source).toBe("generated");
    expect(r.token).toMatch(/^[0-9a-f]{32}$/);
  });
});
