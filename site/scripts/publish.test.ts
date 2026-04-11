import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { publish } from "./publish";

const tmp = join(import.meta.dir, "__tmp_publish__");
const distDir = join(tmp, "dist");
const docsDir = join(tmp, "docs");

describe("publish", () => {
  beforeEach(() => {
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(distDir, { recursive: true });
    mkdirSync(docsDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("copies dist contents into docs", () => {
    writeFileSync(join(distDir, "index.html"), "<html>landing</html>");
    mkdirSync(join(distDir, "_assets"), { recursive: true });
    writeFileSync(join(distDir, "_assets", "style.css"), "body{}");

    publish({ distDir, docsDir, preserve: [] });

    expect(readFileSync(join(docsDir, "index.html"), "utf8")).toBe("<html>landing</html>");
    expect(readFileSync(join(docsDir, "_assets", "style.css"), "utf8")).toBe("body{}");
  });

  it("preserves listed files and directories in docs", () => {
    writeFileSync(join(docsDir, "agent-api-reference.md"), "CANONICAL");
    writeFileSync(join(docsDir, "integrations.md"), "CANONICAL INT");
    mkdirSync(join(docsDir, "superpowers", "specs"), { recursive: true });
    writeFileSync(join(docsDir, "superpowers", "specs", "old.md"), "SPEC");
    writeFileSync(join(distDir, "index.html"), "NEW");

    publish({
      distDir,
      docsDir,
      preserve: ["agent-api-reference.md", "integrations.md", "superpowers"],
    });

    expect(readFileSync(join(docsDir, "agent-api-reference.md"), "utf8")).toBe("CANONICAL");
    expect(readFileSync(join(docsDir, "integrations.md"), "utf8")).toBe("CANONICAL INT");
    expect(readFileSync(join(docsDir, "superpowers", "specs", "old.md"), "utf8")).toBe("SPEC");
    expect(readFileSync(join(docsDir, "index.html"), "utf8")).toBe("NEW");
  });

  it("removes stale non-preserved files from docs before copying", () => {
    writeFileSync(join(docsDir, "stale.html"), "OLD");
    writeFileSync(join(distDir, "index.html"), "NEW");

    publish({ distDir, docsDir, preserve: [] });

    expect(existsSync(join(docsDir, "stale.html"))).toBe(false);
    expect(readFileSync(join(docsDir, "index.html"), "utf8")).toBe("NEW");
  });
});
