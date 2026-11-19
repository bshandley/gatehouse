import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { Hono } from "hono";
import { Database } from "bun:sqlite";
import { initDB } from "../src/db/init";
import { AuditLog } from "../src/audit/logger";
import { PolicyEngine } from "../src/policy/engine";
import { DynamicSecretsManager } from "../src/dynamic/manager";
import { dynamicRouter } from "../src/api/dynamic";
import type { DynamicProvider, DynamicCredential } from "../src/dynamic/provider";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

class FakeProvider implements DynamicProvider {
  readonly type = "fake-mock";
  requiredConfig(): string[] {
    return ["host"];
  }
  async create(): Promise<DynamicCredential> {
    return { credential: { username: "u", password: "p" }, revocation_handle: "h" };
  }
  async revoke(): Promise<void> {}
  async validate(): Promise<{ ok: boolean; error?: string }> {
    return { ok: true };
  }
}

describe("Dynamic API", () => {
  let db: Database;
  let dir: string;
  let dynamic: DynamicSecretsManager;
  let app: Hono;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "gatehouse-dynamic-api-"));
    db = initDB(dir);
    const audit = new AuditLog(db);
    const policies = new PolicyEngine(dir);
    dynamic = new DynamicSecretsManager(db, audit, Buffer.from("c".repeat(64), "hex"));
    dynamic.registerProvider(new FakeProvider());
    dynamic.saveConfig("db/fake", "fake-mock", { host: "h" });

    app = new Hono();
    app.use("*", async (c, next) => {
      c.set("requestId", "test-req-id");
      c.set("sourceIp", "127.0.0.1");
      c.set("auth", { identity: "root", policies: ["admin"] });
      await next();
    });
    app.route("/v1/dynamic", dynamicRouter(dynamic, policies, audit));
  });

  afterEach(() => {
    dynamic.stopReaper();
    db.close();
    rmSync(dir, { recursive: true, force: true });
  });

  test("DELETE /v1/dynamic/:path deletes an existing config", async () => {
    const res = await app.request("/v1/dynamic/db/fake", { method: "DELETE" });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ deleted: true });
  });

  test("DELETE /v1/dynamic/:path returns 404 for a config that does not exist", async () => {
    const res = await app.request("/v1/dynamic/db/nope", { method: "DELETE" });
    expect(res.status).toBe(404);
  });
});
