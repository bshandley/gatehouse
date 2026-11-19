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
});
