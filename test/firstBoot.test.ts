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
