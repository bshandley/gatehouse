#!/usr/bin/env bun
// Regenerate marketing screenshots at docs/screenshots/.
// Spins up a disposable Gatehouse, seeds demo data, then drives Chromium
// through the UI. Cleans everything up at the end.
//
// Usage: bun run scripts/screenshots.ts

import { chromium } from "playwright";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn, type Subprocess } from "bun";
import { randomUUID } from "node:crypto";

const PORT = 3199;
const BASE = `http://127.0.0.1:${PORT}`;
const ROOT_TOKEN = "demo-root-token-screenshots";
const MASTER_KEY = "a".repeat(64);
// Write to the Astro public dir so `bun run site:build` picks them up and
// publishes them into docs/screenshots/. Writing straight to docs/ would be
// clobbered by the next site build.
const OUT_DIR = join(import.meta.dir, "..", "site", "public", "screenshots");
const VIEWPORT = { width: 1600, height: 1000 };

async function waitForHealth(): Promise<void> {
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`${BASE}/health`);
      if (r.ok) return;
    } catch {}
    await Bun.sleep(200);
  }
  throw new Error("gatehouse failed to start");
}

async function seedSecrets(): Promise<void> {
  const secrets = [
    { path: "api-keys/openai", value: "sk-proj-demo-openai-key-do-not-use", meta: { provider: "openai", note: "gpt-4 + embeddings" } },
    { path: "api-keys/anthropic", value: "sk-ant-demo-anthropic-key-do-not-use", meta: { provider: "anthropic" } },
    { path: "api-keys/github", value: "ghp_demoDemoDemoDemoDemoDemo", meta: { provider: "github", scopes: "repo,read:org" } },
    { path: "api-keys/stripe", value: "sk_test_demoStripeKeyForScreenshots", meta: { provider: "stripe", env: "test" } },
    { path: "services/postgres/primary", value: "postgres://demo:demo@db.internal:5432/app", meta: { env: "prod" } },
    { path: "services/redis/cache", value: "redis://:demo@cache.internal:6379/0", meta: { env: "prod" } },
    { path: "services/smtp/postmark", value: "postmark-demo-token", meta: { purpose: "transactional email" } },
    { path: "agents/ingest-bot/jwt", value: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo.demo", meta: { owner: "data-team" } },
  ];
  for (const s of secrets) {
    const r = await fetch(`${BASE}/v1/secrets/${s.path}`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${ROOT_TOKEN}`, "Content-Type": "application/json" },
      body: JSON.stringify({ value: s.value, metadata: s.meta }),
    });
    if (!r.ok) throw new Error(`seed secret ${s.path}: ${r.status} ${await r.text()}`);
  }
}

function seedPatterns(dataDir: string): void {
  const db = new Database(join(dataDir, "gatehouse.db"));
  const now = new Date().toISOString();
  const rows = [
    {
      secret_path: "api-keys/openai", method: "POST", url_template: "https://api.openai.com/v1/chat/completions",
      host: "api.openai.com",
      request_headers: ["authorization", "content-type"],
      request_body: { model: "string", messages: "array", temperature: "number" },
      response_body: { id: "string", object: "string", choices: "array", usage: "object" },
      successes: 47, failures: 1, agents: ["ingest-bot", "summarizer"],
    },
    {
      secret_path: "api-keys/openai", method: "POST", url_template: "https://api.openai.com/v1/embeddings",
      host: "api.openai.com",
      request_headers: ["authorization", "content-type"],
      request_body: { model: "string", input: "string" },
      response_body: { data: "array", model: "string", usage: "object" },
      successes: 132, failures: 0, agents: ["ingest-bot"],
    },
    {
      secret_path: "api-keys/anthropic", method: "POST", url_template: "https://api.anthropic.com/v1/messages",
      host: "api.anthropic.com",
      request_headers: ["x-api-key", "anthropic-version", "content-type"],
      request_body: { model: "string", max_tokens: "number", messages: "array" },
      response_body: { id: "string", type: "string", content: "array", usage: "object" },
      successes: 89, failures: 2, agents: ["summarizer", "ingest-bot"],
    },
    {
      secret_path: "api-keys/github", method: "GET", url_template: "https://api.github.com/repos/:id/:id/issues?state=",
      host: "api.github.com",
      request_headers: ["authorization", "accept"],
      request_body: null,
      response_body: null,
      successes: 24, failures: 0, agents: ["triage-bot"],
    },
    {
      secret_path: "api-keys/github", method: "POST", url_template: "https://api.github.com/repos/:id/:id/issues/:num/comments",
      host: "api.github.com",
      request_headers: ["authorization", "accept", "content-type"],
      request_body: { body: "string" },
      response_body: { id: "number", html_url: "string", body: "string" },
      successes: 18, failures: 1, agents: ["triage-bot"],
    },
    {
      secret_path: "api-keys/stripe", method: "GET", url_template: "https://api.stripe.com/v1/customers/:id",
      host: "api.stripe.com",
      request_headers: ["authorization"],
      request_body: null,
      response_body: { id: "string", object: "string", email: "string", subscriptions: "object" },
      successes: 11, failures: 0, agents: ["billing-bot"],
    },
  ];

  const stmt = db.prepare(`
    INSERT INTO proxy_patterns
    (id, secret_path, method, url_template, host, request_headers, request_body_schema,
     response_status, response_body_schema, recent_outcomes, agents,
     total_successes, total_failures, pinned, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 200, ?, ?, ?, ?, ?, 0, ?, ?)
  `);
  for (const r of rows) {
    const outcomes = Array(20).fill(1).map((_, i) => (i < r.failures ? 0 : 1));
    stmt.run(
      randomUUID(),
      r.secret_path, r.method, r.url_template, r.host,
      JSON.stringify(r.request_headers),
      r.request_body ? JSON.stringify(r.request_body) : null,
      r.response_body ? JSON.stringify(r.response_body) : null,
      JSON.stringify(outcomes),
      JSON.stringify(r.agents),
      r.successes, r.failures,
      now, now,
    );
  }
  db.close();
}

async function main(): Promise<void> {
  const dataDir = mkdtempSync(join(tmpdir(), "gatehouse-shots-"));
  let server: Subprocess | null = null;
  try {
    console.log(`[shots] data dir: ${dataDir}`);
    server = spawn({
      cmd: ["bun", "run", "src/index.ts"],
      cwd: join(import.meta.dir, ".."),
      env: {
        ...process.env,
        GATEHOUSE_MASTER_KEY: MASTER_KEY,
        GATEHOUSE_ROOT_TOKEN: ROOT_TOKEN,
        GATEHOUSE_DATA_DIR: dataDir,
        GATEHOUSE_CONFIG_DIR: join(import.meta.dir, "..", "config"),
        GATEHOUSE_PORT: String(PORT),
        GATEHOUSE_LOG_LEVEL: "error",
      },
      stdout: "ignore",
      stderr: "inherit",
    });

    await waitForHealth();
    console.log("[shots] server healthy, seeding...");
    await seedSecrets();
    seedPatterns(dataDir);
    console.log("[shots] seeded, launching browser...");

    const browser = await chromium.launch();
    const ctx = await browser.newContext({ viewport: VIEWPORT, deviceScaleFactor: 2 });
    const page = await ctx.newPage();

    await page.goto(BASE, { waitUntil: "networkidle" });
    await page.click("#login-tab-token");
    await page.fill("#login-token", ROOT_TOKEN);
    await page.click("#login-submit-btn");
    await page.waitForSelector(".nav-item.active[data-page=dashboard]", { state: "visible" });
    await page.waitForTimeout(500);

    const shots: Array<[string, string]> = [
      ["dashboard", "dashboard"],
      ["secrets", "secrets"],
      ["patterns", "patterns"],
    ];
    for (const [page_name, file] of shots) {
      await page.click(`.nav-item[data-page=${page_name}]`);
      await page.waitForTimeout(800);
      if (page_name === "secrets") {
        // Expand the api-keys group and open the openai secret so the detail panel renders.
        const leaf = page.locator(".tree-item", { hasText: "openai" }).first();
        if (await leaf.count()) await leaf.click();
        await page.waitForTimeout(600);
      }
      const out = join(OUT_DIR, `${file}.png`);
      await page.screenshot({ path: out, fullPage: false });
      console.log(`[shots] wrote ${out}`);
    }

    await browser.close();
  } finally {
    if (server) {
      server.kill();
      await server.exited;
    }
    rmSync(dataDir, { recursive: true, force: true });
  }
}

await main();
