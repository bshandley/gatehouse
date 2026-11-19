import { describe, test, expect } from "bun:test";
import { Hono } from "hono";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { uiAssetsRouter, UI_CSP } from "../src/api/uiAssets";

const app = new Hono();
app.route("/ui", uiAssetsRouter());

describe("UI assets", () => {
  for (const name of ["secret-form-metadata.js", "secret-detail-render.js", "list-validate.js", "list-input.js", "shell.js"]) {
    test(`serves /ui/${name} as JavaScript`, async () => {
      const res = await app.request(`/ui/${name}`);
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("application/javascript");
      expect((await res.text()).length).toBeGreaterThan(100);
    });
  }

  test("does not serve other files from the ui directory", async () => {
    expect((await app.request("/ui/index.html")).status).toBe(404);
    expect((await app.request("/ui/nope.js")).status).toBe(404);
  });

  test("serves a bundled font with a long cache lifetime", async () => {
    const res = await app.request("/ui/fonts/dm-sans-latin-400-normal.woff2");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("font/woff2");
    expect(res.headers.get("cache-control")).toContain("max-age=");
    expect((await res.arrayBuffer()).byteLength).toBeGreaterThan(5000);
  });

  test("rejects font names outside the bundled set, including traversal", async () => {
    for (const p of [
      "/ui/fonts/nope.woff2",
      "/ui/fonts/LICENSE-dm-sans.txt",
      "/ui/fonts/..%2Findex.html",
      "/ui/fonts/%2e%2e%2f%2e%2e%2fversion.ts",
      "/ui/fonts/../index.html",
    ]) {
      const res = await app.request(p);
      expect(res.status).toBe(404);
    }
  });

  test("every font the page declares is bundled, and the page calls no third party", async () => {
    const html = readFileSync(join(import.meta.dir, "../src/ui/index.html"), "utf8");
    const declared = [...html.matchAll(/url\("\/ui\/fonts\/([a-z0-9-]+\.woff2)"\)/g)].map((m) => m[1]);
    expect(declared.length).toBe(8);
    for (const f of declared) {
      expect((await app.request(`/ui/fonts/${f}`)).status).toBe(200);
    }
    const external = [...html.matchAll(/(?:href|src)="(https?:\/\/[^"]+)"/g)]
      .map((m) => m[1])
      .filter((u) => /<(link|script|img)/.test(html.slice(Math.max(0, html.indexOf(u) - 200), html.indexOf(u))) && !/<a /.test(html.slice(Math.max(0, html.indexOf(u) - 60), html.indexOf(u))));
    expect(external).toEqual([]);
  });

  test("the page CSP allows only same-origin fonts and styles", () => {
    expect(UI_CSP).not.toContain("googleapis");
    expect(UI_CSP).not.toContain("gstatic");
    expect(UI_CSP).toContain("font-src 'self'");
  });
});
