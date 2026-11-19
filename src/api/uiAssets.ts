import { Hono } from "hono";
import { readdirSync } from "node:fs";

/**
 * Static assets for the web UI: the helper modules index.html loads with
 * <script type="module">, and the bundled fonts. Mounted at /ui, before the
 * auth middleware (the UI handles its own login).
 *
 * Nothing here is derived from the request path: modules come from a fixed
 * list and fonts from the directory listing taken at startup, so a crafted
 * path can only ever select one of those files.
 */

/** Content-Security-Policy for the UI page. Everything is same-origin. */
export const UI_CSP =
  "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; img-src 'self' data:;";

const MODULES = ["secret-form-metadata.js", "secret-detail-render.js", "list-validate.js", "list-input.js", "shell.js"];

const UI_DIR = new URL("../ui/", import.meta.url).pathname;

function bundledFonts(): Set<string> {
  try {
    return new Set(readdirSync(`${UI_DIR}fonts`).filter((f) => /^[a-z0-9-]+\.woff2$/.test(f)));
  } catch {
    return new Set();
  }
}

export function uiAssetsRouter() {
  const router = new Hono();
  const fonts = bundledFonts();

  for (const name of MODULES) {
    router.get(`/${name}`, async (c) => {
      try {
        const js = await Bun.file(`${UI_DIR}${name}`).text();
        c.header("Content-Type", "application/javascript; charset=utf-8");
        // Revalidate every time so an upgrade never leaves a stale module
        // running against a new index.html.
        c.header("Cache-Control", "no-cache, must-revalidate");
        return c.body(js);
      } catch {
        return c.text("Not found", 404);
      }
    });
  }

  router.get("/fonts/:file", async (c) => {
    const file = c.req.param("file");
    if (!fonts.has(file)) return c.text("Not found", 404);
    const bytes = await Bun.file(`${UI_DIR}fonts/${file}`).arrayBuffer();
    c.header("Content-Type", "font/woff2");
    c.header("Cache-Control", "public, max-age=2592000");
    return c.body(bytes);
  });

  return router;
}
