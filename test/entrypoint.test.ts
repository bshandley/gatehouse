import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { mkdtempSync, writeFileSync, chmodSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join, resolve } from "path";

// Runs docker-entrypoint.sh with a stub `bun` first on PATH that prints its arguments.
const SCRIPT = resolve(import.meta.dir, "..", "docker-entrypoint.sh");
let stubDir: string;

beforeAll(() => {
  stubDir = mkdtempSync(join(tmpdir(), "gh-entry-"));
  writeFileSync(join(stubDir, "bun"), '#!/bin/sh\necho "$@"\n');
  chmodSync(join(stubDir, "bun"), 0o755);
});
afterAll(() => rmSync(stubDir, { recursive: true, force: true }));

function route(...args: string[]): string {
  const r = Bun.spawnSync(["sh", SCRIPT, ...args], {
    env: { ...process.env, PATH: `${stubDir}:${process.env.PATH}` },
  });
  expect(r.exitCode).toBe(0);
  return r.stdout.toString().trim();
}

describe("docker-entrypoint.sh", () => {
  test("parses cleanly", () => {
    expect(Bun.spawnSync(["sh", "-n", SCRIPT]).exitCode).toBe(0);
  });

  test("help, --help and -h go to the CLI", () => {
    for (const a of ["help", "--help", "-h"]) expect(route(a)).toBe(`run src/cli.ts ${a}`);
  });

  test("CLI commands, mcp, no args, and passthrough keep their routes", () => {
    expect(route("verify")).toBe("run src/cli.ts verify");
    expect(route("export", "--out", "/backup/x")).toBe("run src/cli.ts export --out /backup/x");
    expect(route("mcp", "--x")).toBe("run src/mcp-stdio.ts --x");
    expect(route()).toBe("run src/index.ts");
    expect(route("src/index.ts")).toBe("run src/index.ts");
  });
});
