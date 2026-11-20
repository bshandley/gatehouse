/**
 * Global request middleware mounted by src/index.ts, kept here so it can be
 * tested without starting the server.
 */

import type { MiddlewareHandler } from "hono";
import { logger } from "hono/logger";

const DEFAULT_MAX_BODY_SIZE = 1048576;

/** GATEHOUSE_MAX_BODY_SIZE as a positive integer; anything else is the default (fail closed). */
export function parseMaxBodySize(raw: string | undefined): number {
  if (raw === undefined || !/^\s*\d+\s*$/.test(raw)) return DEFAULT_MAX_BODY_SIZE;
  const n = Number(raw.trim());
  return Number.isSafeInteger(n) && n > 0 ? n : DEFAULT_MAX_BODY_SIZE;
}

/**
 * The configured body cap, read once at startup. A value that is set but is
 * not a positive integer is rejected with one warning line, and the default
 * applies: a typo must never turn the cap off.
 */
export function maxBodySizeFromEnv(raw: string | undefined, warn: (line: string) => void = console.warn): number {
  const max = parseMaxBodySize(raw);
  if (raw !== undefined && raw.trim() !== "" && String(max) !== raw.trim()) {
    warn(`[gatehouse] GATEHOUSE_MAX_BODY_SIZE is not a positive integer; using the default of ${DEFAULT_MAX_BODY_SIZE} bytes`);
  }
  return max;
}

const isPassthroughPath = (path: string) => path === "/p" || path.startsWith("/p/");

/**
 * Hono's logger, except that a passthrough (/p) request is logged by path
 * only: its query string belongs to the upstream and may carry anything
 * (spec D8: the query string is never logged). Other routes are unchanged.
 */
export function requestLogger(print: (line: string) => void = console.log): MiddlewareHandler {
  const plain = logger(print);
  return async (c, next) => {
    if (!isPassthroughPath(c.req.path)) return plain(c, next);
    // Hono builds its line from the URL after the host: path plus query.
    const url = c.req.url;
    const full = url.slice(url.indexOf("/", 8));
    const q = full.indexOf("?");
    if (q < 0) return plain(c, next);
    const pathOnly = full.slice(0, q);
    return logger((line) => print(line.replace(full, () => pathOnly)))(c, next);
  };
}

/** Request body cap on the declared Content-Length. Passthrough (/p) enforces its own. */
export function bodySizeLimit(maxBytes: number): MiddlewareHandler {
  return async (c, next) => {
    if (isPassthroughPath(c.req.path)) return next();
    const contentLength = c.req.header("content-length");
    if (contentLength && parseInt(contentLength, 10) > maxBytes) {
      return c.json({ error: "Request body too large", request_id: c.get("requestId") }, 413);
    }
    await next();
  };
}
