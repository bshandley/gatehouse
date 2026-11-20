import { describe, test, expect, afterEach } from "bun:test";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { isServerLive } from "../src/backup/snapshot";

const BANNER = "GATEHOUSE GENERATED A NEW MASTER KEY";
const ROOT = join(import.meta.dir, "..");

let procs: ReturnType<typeof Bun.spawn>[] = [];
let dirs: string[] = [];

afterEach(() => {
  for (const p of procs) { try { p.kill("SIGKILL"); } catch {} }
  procs = [];
  for (const d of dirs) rmSync(d, { recursive: true, force: true });
  dirs = [];
});

function freePort(): number {
  const s = Bun.serve({ port: 0, fetch: () => new Response("") });
  const port = s.port as number;
  s.stop(true);
  return port;
}

function boot(dataDir: string, configDir: string) {
  const port = freePort();
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.GATEHOUSE_MASTER_KEY;
  delete env.GATEHOUSE_ROOT_TOKEN;
  env.GATEHOUSE_DATA_DIR = dataDir;
  env.GATEHOUSE_CONFIG_DIR = configDir;
  env.GATEHOUSE_PORT = String(port);
  const proc = Bun.spawn(["bun", "run", "src/index.ts"], {
    cwd: ROOT, env, stdout: "pipe", stderr: "pipe",
  });
  procs.push(proc);
  const stdout = new Response(proc.stdout as ReadableStream).text();
  const stderr = new Response(proc.stderr as ReadableStream).text();
  return { proc, port, stdout, stderr };
}

async function waitHealthy(port: number, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/health`);
      if (r.status === 200) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("server did not become healthy");
}

async function stopAndRead(b: ReturnType<typeof boot>) {
  b.proc.kill("SIGTERM");
  await b.proc.exited;
  return { stdout: await b.stdout, stderr: await b.stderr };
}

function mkdirs() {
  const dir = mkdtempSync(join(tmpdir(), "gh-boot-data-"));
  const cfg = mkdtempSync(join(tmpdir(), "gh-boot-cfg-"));
  dirs.push(dir, cfg);
  return { dir, cfg };
}

describe("first boot", () => {
  test("bare boot generates a key, serves /health, and holds the lock", async () => {
    const { dir, cfg } = mkdirs();
    const b = boot(dir, cfg);
    await waitHealthy(b.port);
    expect(existsSync(join(dir, "master.key"))).toBe(true);
    expect(isServerLive(dir)).toBe(true);
    const { stdout, stderr } = await stopAndRead(b);
    expect(stderr).toContain(BANNER);
    expect(stdout).not.toContain(readFileSync(join(dir, "master.key"), "utf8").trim());
  }, 15_000);

  test("second boot on the same dir prints no banner and keeps the key", async () => {
    const { dir, cfg } = mkdirs();
    const first = boot(dir, cfg);
    await waitHealthy(first.port);
    await stopAndRead(first);
    const before = readFileSync(join(dir, "master.key"));

    const second = boot(dir, cfg);
    await waitHealthy(second.port);
    const { stderr } = await stopAndRead(second);
    expect(stderr).not.toContain(BANNER);
    expect(readFileSync(join(dir, "master.key")).equals(before)).toBe(true);
  }, 15_000);

  test("SIGTERM removes the lock", async () => {
    const { dir, cfg } = mkdirs();
    const b = boot(dir, cfg);
    await waitHealthy(b.port);
    expect(existsSync(join(dir, "gatehouse.lock"))).toBe(true);
    await stopAndRead(b);
    expect(existsSync(join(dir, "gatehouse.lock"))).toBe(false);
  }, 15_000);
});

describe("CORS", () => {
  test("preflight allows PATCH, which PATCH /v1/secrets/:path needs", async () => {
    const { dir, cfg } = mkdirs();
    const b = boot(dir, cfg);
    await waitHealthy(b.port);
    const res = await fetch(`http://127.0.0.1:${b.port}/v1/secrets/api-keys/example`, {
      method: "OPTIONS",
      headers: {
        Origin: `http://localhost:${b.port}`,
        "Access-Control-Request-Method": "PATCH",
        "Access-Control-Request-Headers": "authorization,content-type",
      },
    });
    const allowed = (res.headers.get("access-control-allow-methods") || "").split(",").map((m) => m.trim());
    await stopAndRead(b);
    expect(res.headers.get("access-control-allow-origin")).toBe(`http://localhost:${b.port}`);
    for (const m of ["GET", "POST", "PUT", "PATCH", "DELETE"]) expect(allowed).toContain(m);
  });
});

describe("bootstrap root token", () => {
  const tokenFile = (dir: string) => join(dir, "bootstrap-root.token");
  const get = (port: number, token: string, path = "/v1/config") =>
    fetch(`http://127.0.0.1:${port}${path}`, { headers: { Authorization: `Bearer ${token}` } });

  test("bare boot prints a bootstrap token that authenticates as root", async () => {
    const { dir, cfg } = mkdirs();
    const b = boot(dir, cfg);
    await waitHealthy(b.port);
    const token = readFileSync(tokenFile(dir), "utf8").trim();
    expect(token).toMatch(/^[0-9a-f]{32}$/);
    const r = await get(b.port, token);
    expect(r.status).toBe(200);
    const body = (await r.json()) as any;
    expect(body.root_token_source).toBe("bootstrap");
    expect(body.root_token_set).toBe(true);
    const { stdout, stderr } = await stopAndRead(b);
    expect(stderr).toContain("GATEHOUSE BOOTSTRAP ROOT TOKEN");
    expect(stderr).toContain(token);
    expect(stdout).not.toContain(token);
  }, 15_000);

  test("the old default token does not authenticate", async () => {
    const { dir, cfg } = mkdirs();
    const b = boot(dir, cfg);
    await waitHealthy(b.port);
    expect((await get(b.port, "gatehouse-root-changeme")).status).toBe(401);
    await stopAndRead(b);
  }, 15_000);

  test("after an admin user is created, a restart retires the token", async () => {
    const { dir, cfg } = mkdirs();
    const first = boot(dir, cfg);
    await waitHealthy(first.port);
    const token = readFileSync(tokenFile(dir), "utf8").trim();
    const created = await fetch(`http://127.0.0.1:${first.port}/v1/auth/users`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin1", password: "correct-horse-1", display_name: "Admin" }),
    });
    expect(created.status).toBe(201);
    await stopAndRead(first);
    expect(existsSync(tokenFile(dir))).toBe(true);

    const second = boot(dir, cfg);
    await waitHealthy(second.port);
    expect(existsSync(tokenFile(dir))).toBe(false);
    expect((await get(second.port, token)).status).toBe(401);
    const login = await fetch(`http://127.0.0.1:${second.port}/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin1", password: "correct-horse-1" }),
    });
    expect(login.status).toBe(200);
    const jwt = ((await login.json()) as any).token;
    const cfgRes = await get(second.port, jwt);
    expect(cfgRes.status).toBe(200);
    const body = (await cfgRes.json()) as any;
    expect(body.root_token_set).toBe(false);
    expect(body.root_token_source).toBeNull();
    const { stderr } = await stopAndRead(second);
    expect(stderr).toContain("removed stale bootstrap-root.token");
  }, 20_000);

  test("GATEHOUSE_ROOT_TOKEN in the environment wins and no file is written", async () => {
    const { dir, cfg } = mkdirs();
    const port = freePort();
    const env: Record<string, string | undefined> = { ...process.env, GATEHOUSE_ROOT_TOKEN: "env-root-token-value" };
    delete env.GATEHOUSE_MASTER_KEY;
    env.GATEHOUSE_DATA_DIR = dir;
    env.GATEHOUSE_CONFIG_DIR = cfg;
    env.GATEHOUSE_PORT = String(port);
    const proc = Bun.spawn(["bun", "run", "src/index.ts"], { cwd: ROOT, env, stdout: "pipe", stderr: "pipe" });
    procs.push(proc);
    await waitHealthy(port);
    const r = await get(port, "env-root-token-value");
    expect(r.status).toBe(200);
    expect(((await r.json()) as any).root_token_source).toBe("env");
    expect(existsSync(tokenFile(dir))).toBe(false);
  }, 15_000);
});
