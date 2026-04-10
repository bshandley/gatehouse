import { Hono } from "hono";
import { scrubValue, containsCredentials } from "../scrub/scrubber";
import type { AuthContext } from "../auth/middleware";

export function scrubRouter() {
  const router = new Hono();

  // POST /v1/scrub — redact credentials from text
  router.post("/", async (c) => {
    let body: { text: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    if (!body.text || typeof body.text !== "string") {
      return c.json({ error: "Missing 'text' field", request_id: c.get("requestId") }, 400);
    }

    const result = scrubValue(body.text);
    return c.json(result);
  });

  // POST /v1/scrub/check — quick boolean check for credential patterns
  router.post("/check", async (c) => {
    let body: { text: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body", request_id: c.get("requestId") }, 400);
    }

    if (!body.text || typeof body.text !== "string") {
      return c.json({ error: "Missing 'text' field", request_id: c.get("requestId") }, 400);
    }

    return c.json({ contains_credentials: containsCredentials(body.text) });
  });

  return router;
}
