import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { syncDoc } from "./sync-docs";

const tmp = join(import.meta.dir, "__tmp_sync__");
const srcDir = join(tmp, "src-docs");
const dstDir = join(tmp, "dst-docs");

describe("syncDoc", () => {
  beforeEach(() => {
    rmSync(tmp, { recursive: true, force: true });
    mkdirSync(srcDir, { recursive: true });
    mkdirSync(dstDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("copies markdown and prepends frontmatter", () => {
    const srcPath = join(srcDir, "source.md");
    const dstPath = join(dstDir, "target.mdx");
    writeFileSync(srcPath, "# Source Title\n\nBody text.\n");

    syncDoc({
      src: srcPath,
      dst: dstPath,
      frontmatter: {
        title: "Target Title",
        description: "A description",
        sidebar_order: 1,
        sidebar_group: "REFERENCE",
      },
    });

    expect(existsSync(dstPath)).toBe(true);
    const out = readFileSync(dstPath, "utf8");
    expect(out).toStartWith("---\n");
    expect(out).toContain('title: "Target Title"');
    expect(out).toContain('description: "A description"');
    expect(out).toContain("sidebar_order: 1");
    expect(out).toContain('sidebar_group: "REFERENCE"');
    expect(out).toContain("Body text.");
  });

  it("strips any existing H1 from the source since the layout renders the title", () => {
    const srcPath = join(srcDir, "source.md");
    const dstPath = join(dstDir, "target.mdx");
    writeFileSync(srcPath, "# The Original H1\n\nBody.\n");

    syncDoc({
      src: srcPath,
      dst: dstPath,
      frontmatter: {
        title: "New Title",
        description: "d",
        sidebar_order: 1,
        sidebar_group: "REFERENCE",
      },
    });

    const out = readFileSync(dstPath, "utf8");
    expect(out).not.toContain("# The Original H1");
    expect(out).toContain("Body.");
  });

  it("escapes double quotes in frontmatter values", () => {
    const srcPath = join(srcDir, "source.md");
    const dstPath = join(dstDir, "target.mdx");
    writeFileSync(srcPath, "Body\n");

    syncDoc({
      src: srcPath,
      dst: dstPath,
      frontmatter: {
        title: 'Title with "quotes"',
        description: "desc",
        sidebar_order: 1,
        sidebar_group: "REFERENCE",
      },
    });

    const out = readFileSync(dstPath, "utf8");
    expect(out).toContain('title: "Title with \\"quotes\\""');
  });
});
