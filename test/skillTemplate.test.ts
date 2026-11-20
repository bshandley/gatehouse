import { describe, test, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// GET /v1/skill substitutes exactly one placeholder (see src/api/skill.ts).
// Any other {{UPPER_CASE}} token in the template reaches agents as literal text.
describe("skill template", () => {
  test("contains no placeholders the skill route does not substitute", () => {
    const tpl = readFileSync(join(import.meta.dir, "../src/templates/skill.md"), "utf8");
    const tokens = [...tpl.matchAll(/\{\{[A-Z_]+\}\}/g)].map((m) => m[0]);
    const unknown = tokens.filter((t) => t !== "{{SITUATION_TABLE}}");
    expect(unknown).toEqual([]);
  });

  test("has a short passthrough section", () => {
    const tpl = readFileSync(join(import.meta.dir, "../src/templates/skill.md"), "utf8");
    const i = tpl.indexOf("## Passthrough");
    expect(i).toBeGreaterThan(-1);
    const next = tpl.indexOf("\n## ", i + 5);
    const section = tpl.slice(i, next === -1 ? undefined : next);
    expect(section).toContain("/p/<alias>/");
    expect(section).toContain("passthrough_alias");
    expect(section).toContain("gatehouse_list");
    expect(section).toContain("Authorization: Bearer");
    expect(section.split("\n").length).toBeLessThan(25);
    // The pasteable command carries no placeholder a shell would choke on.
    const code = section.split("\n").filter((l) => l.startsWith("    "));
    expect(code.join("\n")).toContain("$GATEHOUSE_URL/p/$ALIAS/");
    for (const l of code) expect(l).not.toContain("<alias>");
    expect(section).toContain("five failed passthrough keys");
  });
});
