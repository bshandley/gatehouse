import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { createServer, type Server, type IncomingMessage } from "node:http";
import { createHmac } from "node:crypto";
import { AddressInfo } from "node:net";
import {
  sendLeaseRequestWebhook,
  _resetWebhookWarnedForTests,
  type LeaseRequestPayload,
} from "../src/lease/webhook";

interface CapturedRequest {
  body: string;
  headers: IncomingMessage["headers"];
}

interface Capture {
  requests: CapturedRequest[];
}

function startCaptureServer(): Promise<{ server: Server; port: number; capture: Capture }> {
  return new Promise((resolve) => {
    const capture: Capture = { requests: [] };
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        capture.requests.push({
          body: Buffer.concat(chunks).toString("utf8"),
          headers: req.headers,
        });
        res.statusCode = 200;
        res.end("ok");
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const port = (server.address() as AddressInfo).port;
      resolve({ server, port, capture });
    });
  });
}

function stopServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function basePayload(): LeaseRequestPayload {
  return {
    lease_id: "lease-abc-123",
    identity: "agent-a",
    secret_path: "secret/gated",
    justification: "Need access to debug",
    ttl_seconds: 600,
    request_expires_at: "2030-01-01T00:00:00.000Z",
    server_base_url: "http://gatehouse.example",
  };
}

// Snapshot + restore env between tests so each case starts clean.
const ENV_KEYS = [
  "GATEHOUSE_APPROVAL_WEBHOOK_URL",
  "GATEHOUSE_APPROVAL_WEBHOOK_SECRET",
  "GATEHOUSE_PROXY_ALLOW_PRIVATE",
];

describe("lease webhook", () => {
  let saved: Record<string, string | undefined>;
  let server: Server | null = null;
  let port: number = 0;
  let capture: Capture = { requests: [] };

  beforeEach(async () => {
    saved = {};
    for (const k of ENV_KEYS) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    _resetWebhookWarnedForTests();
    const s = await startCaptureServer();
    server = s.server;
    port = s.port;
    capture = s.capture;
  });

  afterEach(async () => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    if (server) {
      await stopServer(server);
      server = null;
    }
  });

  test("no-op when GATEHOUSE_APPROVAL_WEBHOOK_URL is unset", async () => {
    expect(process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL).toBeUndefined();
    sendLeaseRequestWebhook(basePayload());
    await new Promise((r) => setTimeout(r, 200));
    expect(capture.requests.length).toBe(0);
  });

  test("fires webhook when URL set and ALLOW_PRIVATE=true (local server)", async () => {
    process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL = `http://127.0.0.1:${port}/hook`;
    process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE = "true";

    sendLeaseRequestWebhook(basePayload());
    await new Promise((r) => setTimeout(r, 200));

    expect(capture.requests.length).toBe(1);
    const req = capture.requests[0];
    const parsed = JSON.parse(req.body);
    expect(parsed.event).toBe("lease_request_created");
    expect(parsed.lease_id).toBe("lease-abc-123");
    expect(parsed.identity).toBe("agent-a");
    expect(parsed.secret_path).toBe("secret/gated");
    expect(parsed.justification).toBe("Need access to debug");
    expect(parsed.ttl_seconds).toBe(600);
    expect(parsed.request_expires_at).toBe("2030-01-01T00:00:00.000Z");
    expect(parsed.approve_url).toBe(
      "http://gatehouse.example/v1/lease/lease-abc-123/approve"
    );
    expect(parsed.ui_url).toBe("http://gatehouse.example/#leases");
  });

  test("HMAC signature headers when SECRET is set", async () => {
    process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL = `http://127.0.0.1:${port}/hook`;
    process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE = "true";
    process.env.GATEHOUSE_APPROVAL_WEBHOOK_SECRET = "shhh-test-secret";

    sendLeaseRequestWebhook(basePayload());
    await new Promise((r) => setTimeout(r, 200));

    expect(capture.requests.length).toBe(1);
    const req = capture.requests[0];

    const ts = req.headers["x-gatehouse-timestamp"];
    const sig = req.headers["x-gatehouse-signature"];
    expect(typeof ts).toBe("string");
    expect(typeof sig).toBe("string");
    expect(sig as string).toStartWith("sha256=");

    // Recompute and compare.
    const expected =
      "sha256=" +
      createHmac("sha256", "shhh-test-secret")
        .update(`${ts}.${req.body}`)
        .digest("hex");
    expect(sig).toBe(expected);
  });

  test("no signature headers when SECRET is unset", async () => {
    process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL = `http://127.0.0.1:${port}/hook`;
    process.env.GATEHOUSE_PROXY_ALLOW_PRIVATE = "true";

    sendLeaseRequestWebhook(basePayload());
    await new Promise((r) => setTimeout(r, 200));

    expect(capture.requests.length).toBe(1);
    const req = capture.requests[0];
    expect(req.headers["x-gatehouse-timestamp"]).toBeUndefined();
    expect(req.headers["x-gatehouse-signature"]).toBeUndefined();
  });

  test("private host refused without ALLOW_PRIVATE", async () => {
    process.env.GATEHOUSE_APPROVAL_WEBHOOK_URL = `http://127.0.0.1:${port}/hook`;
    // GATEHOUSE_PROXY_ALLOW_PRIVATE is intentionally NOT set.

    sendLeaseRequestWebhook(basePayload());
    await new Promise((r) => setTimeout(r, 200));

    expect(capture.requests.length).toBe(0);
  });
});
