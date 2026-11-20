// End to end: the real OpenAI SDK, unmodified, pointed at a real Gatehouse
// server's /p/<alias> base URL, against a fake OpenAI-compatible upstream.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import OpenAI from "openai";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { initDB } from "../src/db/init";
import { SecretsEngine } from "../src/secrets/engine";
import { PolicyEngine } from "../src/policy/engine";
import { encodePassthroughKey } from "../src/proxy/passthroughKey";

const ROOT = join(import.meta.dir, "..");
const MASTER_HEX = "ab".repeat(32);
const SECRET = "sk-example-sdk-upstream-0123456789";
const KEY = encodePassthroughKey("role-sdk", "sid-example-sdk-1");

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function chunk(content: string, finish: string | null = null): string {
  return (
    "data: " +
    JSON.stringify({
      id: "chatcmpl-example",
      object: "chat.completion.chunk",
      created: 1,
      model: "example-model",
      choices: [{ index: 0, delta: { content }, finish_reason: finish }],
    }) +
    "\n\n"
  );
}

let upstream: ReturnType<typeof Bun.serve>;
let proc: ReturnType<typeof Bun.spawn>;
let port: number;
let dataDir: string;
let configDir: string;
const authSeen: (string | null)[] = [];

function freePort(): number {
  const s = Bun.serve({ port: 0, fetch: () => new Response("") });
  const p = s.port as number;
  s.stop(true);
  return p;
}

beforeAll(async () => {
  upstream = Bun.serve({
    port: 0,
    hostname: "127.0.0.1",
    idleTimeout: 60,
    async fetch(req) {
      const url = new URL(req.url);
      if (req.method !== "POST" || url.pathname !== "/v1/chat/completions") {
        return new Response("not found", { status: 404 });
      }
      authSeen.push(req.headers.get("authorization"));
      const body = (await req.json()) as { model: string; stream?: boolean };
      if (!body.stream) {
        return Response.json({
          id: "chatcmpl-example",
          object: "chat.completion",
          created: 1,
          model: body.model,
          choices: [
            { index: 0, message: { role: "assistant", content: "hello from the fake upstream" }, finish_reason: "stop" },
          ],
          usage: { prompt_tokens: 1, completion_tokens: 5, total_tokens: 6 },
        });
      }
      const pause = body.model === "pause-model";
      const enc = new TextEncoder();
      return new Response(
        new ReadableStream({
          async start(c) {
            c.enqueue(enc.encode(chunk("Hel")));
            await sleep(pause ? 12_000 : 10);
            c.enqueue(enc.encode(chunk("lo")));
            await sleep(10);
            c.enqueue(enc.encode(chunk("", "stop")));
            c.enqueue(enc.encode("data: [DONE]\n\n"));
            c.close();
          },
        }),
        { headers: { "content-type": "text/event-stream" } }
      );
    },
  });

  dataDir = mkdtempSync(join(tmpdir(), "gh-pt-sdk-data-"));
  configDir = mkdtempSync(join(tmpdir(), "gh-pt-sdk-cfg-"));

  // Seed the vault before boot, with the same master key the server will use.
  const db = initDB(dataDir);
  const secrets = new SecretsEngine(db, Buffer.from(MASTER_HEX, "hex"));
  const policies = new PolicyEngine(configDir, db);
  policies.savePolicy("sdk-agent", [{ paths: ["api-keys/*"], capabilities: ["proxy"] }]);
  db.query("INSERT INTO app_roles (role_id, secret_hash, display_name, policies) VALUES (?, ?, ?, ?)").run(
    "role-sdk",
    await Bun.password.hash("sid-example-sdk-1"),
    "sdk-agent",
    JSON.stringify(["sdk-agent"])
  );
  secrets.put("api-keys/example", SECRET, {
    passthrough_alias: "example",
    upstream_url: `http://127.0.0.1:${upstream.port}`,
  });
  db.close();

  port = freePort();
  const env: Record<string, string | undefined> = { ...process.env };
  env.GATEHOUSE_DATA_DIR = dataDir;
  env.GATEHOUSE_CONFIG_DIR = configDir;
  env.GATEHOUSE_PORT = String(port);
  env.GATEHOUSE_MASTER_KEY = MASTER_HEX;
  env.GATEHOUSE_ROOT_TOKEN = "root-token-example-not-real-0123456789";
  env.GATEHOUSE_LOG_LEVEL = "error";
  delete env.GATEHOUSE_PROXY_ALLOW_PRIVATE;
  proc = Bun.spawn(["bun", "run", "src/index.ts"], { cwd: ROOT, env, stdout: "ignore", stderr: "ignore" });

  const deadline = Date.now() + 10_000;
  for (;;) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/health`)).status === 200) break;
    } catch {}
    if (Date.now() > deadline) throw new Error("server did not become healthy");
    await sleep(50);
  }
}, 20_000);

afterAll(async () => {
  try {
    proc.kill("SIGTERM");
    await proc.exited;
  } catch {}
  upstream.stop(true);
  rmSync(dataDir, { recursive: true, force: true });
  rmSync(configDir, { recursive: true, force: true });
});

function client() {
  return new OpenAI({ apiKey: KEY, baseURL: `http://127.0.0.1:${port}/p/example/v1`, maxRetries: 0 });
}

describe("OpenAI SDK through /p/<alias>", () => {
  test("non-streaming call returns the fake completion; upstream saw the real secret", async () => {
    const res = await client().chat.completions.create({
      model: "example-model",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.choices[0].message.content).toBe("hello from the fake upstream");
    expect(authSeen.at(-1)).toBe(`Bearer ${SECRET}`);
  });

  test("streaming call yields chunks", async () => {
    const stream = await client().chat.completions.create({
      model: "example-model",
      messages: [{ role: "user", content: "hi" }],
      stream: true,
    });
    const parts: string[] = [];
    for await (const c of stream) parts.push(c.choices[0]?.delta?.content ?? "");
    expect(parts.join("")).toBe("Hello");
    expect(parts.length).toBeGreaterThanOrEqual(2);
    expect(authSeen.at(-1)).toBe(`Bearer ${SECRET}`);
  });

  test("a stream that pauses 12 seconds between events still completes", async () => {
    const stream = await client().chat.completions.create({
      model: "pause-model",
      messages: [{ role: "user", content: "hi" }],
      stream: true,
    });
    const parts: string[] = [];
    for await (const c of stream) parts.push(c.choices[0]?.delta?.content ?? "");
    expect(parts.join("")).toBe("Hello");
  }, 30_000);

  test("a wrong key is a Gatehouse 401 the SDK surfaces as an authentication error", async () => {
    const bad = new OpenAI({
      apiKey: encodePassthroughKey("role-sdk", "sid-wrong"),
      baseURL: `http://127.0.0.1:${port}/p/example/v1`,
      maxRetries: 0,
    });
    let err: any;
    try {
      await bad.chat.completions.create({ model: "example-model", messages: [{ role: "user", content: "hi" }] });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(OpenAI.AuthenticationError);
    expect(err.status).toBe(401);
    expect(err.headers.get?.("x-gatehouse-error") ?? err.headers["x-gatehouse-error"]).toBe("1");
  });
});
