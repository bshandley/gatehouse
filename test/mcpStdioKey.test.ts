import { test, expect } from "bun:test";
import { mkdtempSync, rmSync, readdirSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const ROOT = join(import.meta.dir, "..");

test("stdio MCP on a fresh data dir with no key exits 1 and creates nothing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "gh-mcp-stdio-"));
  try {
    const env: Record<string, string | undefined> = { ...process.env, GATEHOUSE_DATA_DIR: dir, GATEHOUSE_CONFIG_DIR: dir };
    delete env.GATEHOUSE_MASTER_KEY;
    const proc = Bun.spawn(["bun", "run", "src/mcp-stdio.ts"], {
      cwd: ROOT,
      env,
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    });
    const code = await proc.exited;
    const stderr = await new Response(proc.stderr as ReadableStream).text();
    const stdout = await new Response(proc.stdout as ReadableStream).text();
    expect(code).toBe(1);
    expect(stderr).toContain("GATEHOUSE_MASTER_KEY must be set");
    expect(stderr).not.toContain("GENERATED A NEW MASTER KEY");
    expect(stdout).toBe("");
    expect(readdirSync(dir)).toEqual([]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
