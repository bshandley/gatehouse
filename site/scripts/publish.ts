import { readdirSync, statSync, mkdirSync, copyFileSync, rmSync, existsSync } from "node:fs";
import { join, relative } from "node:path";

export interface PublishOptions {
  distDir: string;
  docsDir: string;
  preserve: string[];
}

function removeStaleExcept(dir: string, preserve: Set<string>, root: string): void {
  if (!existsSync(dir)) return;
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name);
    const rel = relative(root, abs);
    if (preserve.has(rel) || preserve.has(name)) continue;
    rmSync(abs, { recursive: true, force: true });
  }
}

function copyDirRecursive(src: string, dst: string): void {
  mkdirSync(dst, { recursive: true });
  for (const name of readdirSync(src)) {
    const s = join(src, name);
    const d = join(dst, name);
    const stat = statSync(s);
    if (stat.isDirectory()) {
      copyDirRecursive(s, d);
    } else {
      copyFileSync(s, d);
    }
  }
}

export function publish(opts: PublishOptions): void {
  const preserveSet = new Set(opts.preserve);
  removeStaleExcept(opts.docsDir, preserveSet, opts.docsDir);
  copyDirRecursive(opts.distDir, opts.docsDir);
}

if (import.meta.main) {
  const siteRoot = new URL("..", import.meta.url).pathname;
  const repoRoot = new URL("../..", import.meta.url).pathname;
  const distDir = `${siteRoot}dist`;
  const docsDir = `${repoRoot}docs`;

  if (!existsSync(distDir)) {
    console.error(`publish: ${distDir} does not exist. Run 'astro build' first.`);
    process.exit(1);
  }

  publish({
    distDir,
    docsDir,
    preserve: ["agent-api-reference.md", "integrations.md", "superpowers"],
  });
  console.log(`publish: copied ${distDir} to ${docsDir} (preserving canonical markdown + superpowers)`);
}
