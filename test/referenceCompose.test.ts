import { describe, expect, test } from "bun:test";
import { readFileSync } from "fs";
import { join } from "path";
import { parse } from "yaml";

const root = join(import.meta.dir, "..");
const composeText = readFileSync(join(root, "docker-compose.yml"), "utf8");
const compose = parse(composeText);
const dev = parse(readFileSync(join(root, "docker-compose.dev.yml"), "utf8"));

describe("reference docker-compose.yml", () => {
  const svc = compose.services.gatehouse;

  test("uses the published image and has no build", () => {
    expect(svc.image).toStartWith("ghcr.io/bshandley/gatehouse:");
    expect(svc.build).toBeUndefined();
  });

  test("forwards the key and token with empty defaults", () => {
    const env: string[] = svc.environment;
    expect(env).toContain("GATEHOUSE_MASTER_KEY=${GATEHOUSE_MASTER_KEY:-}");
    expect(env).toContain("GATEHOUSE_ROOT_TOKEN=${GATEHOUSE_ROOT_TOKEN:-}");
    expect(env.filter((e) => /^GATEHOUSE_(MASTER_KEY|ROOT_TOKEN)=/.test(e))).toHaveLength(2);
  });

  test("no literal value for the key or token", () => {
    for (const e of svc.environment as string[]) {
      const m = e.match(/^(GATEHOUSE_MASTER_KEY|GATEHOUSE_ROOT_TOKEN)=(.*)$/);
      if (m) expect(m[2]).toMatch(/^\$\{[A-Z_]+:-\}$/);
    }
  });

  test("carries the single-instance sentence", () => {
    expect(composeText).toContain(
      "Gatehouse is single-instance by design (in-memory rate limiting and an in-process event bus). Run one. It is built for a homelab, not a cluster."
    );
  });

  test("has no default root token", () => {
    expect(composeText).not.toContain("changeme");
  });
});

describe("docker-compose.dev.yml", () => {
  test("builds from the working tree", () => {
    expect(dev.services.gatehouse.build).toBe(".");
  });
});
