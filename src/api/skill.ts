import { Hono } from "hono";
import type { PolicyEngine } from "../policy/engine";
import type { AuthContext } from "../auth/middleware";
import type { AuditLog } from "../audit/logger";
import { renderSituationTable } from "./onboard";

/**
 * Skill self-update endpoint.
 *
 * Any authenticated agent can fetch the current Gatehouse skill body
 * rendered for its policies. The agent overwrites its installed skill
 * file with the response. Lets agents pick up skill template
 * improvements without re-onboarding (which would side-effect a
 * secret_id rotation).
 *
 * The response is the content between the GATEHOUSE-SKILL-BEGIN /
 * -END markers in src/templates/onboard.md, with {{SITUATION_TABLE}}
 * substituted for the caller's policies. No bootstrap-token
 * substitution happens; this endpoint is purely about delivering the
 * skill body.
 */

const SKILL_BEGIN_MARKER = "<!-- GATEHOUSE-SKILL-BEGIN -->";
const SKILL_END_MARKER = "<!-- GATEHOUSE-SKILL-END -->";

export function skillRouter(policies: PolicyEngine, audit: AuditLog) {
  const router = new Hono();

  // Load the template once at module init (mirrors onboard.ts pattern).
  const templateUrl = new URL("../templates/onboard.md", import.meta.url).pathname;
  let templateContent = "";
  let skillBodyTemplate = "";
  Bun.file(templateUrl)
    .text()
    .then((t) => {
      templateContent = t;
      // The template both *describes* the markers in prose (Step 3) and
      // *uses* them as actual delimiters (Step 5). Use lastIndexOf so we
      // pick the real markers, not the backtick-wrapped prose mentions.
      const begin = t.lastIndexOf(SKILL_BEGIN_MARKER);
      const end = t.lastIndexOf(SKILL_END_MARKER);
      if (begin === -1 || end === -1 || end <= begin) {
        console.error(
          `[gatehouse:skill] skill markers not found in template ${templateUrl}; /v1/skill will return 500`
        );
        return;
      }
      skillBodyTemplate = t.slice(begin + SKILL_BEGIN_MARKER.length, end).trim();
    })
    .catch((e) => {
      console.error(`[gatehouse:skill] failed to load template from ${templateUrl}:`, e);
    });

  router.get("/", (c) => {
    const auth = c.get("auth") as AuthContext;
    if (!auth) {
      return c.json({ error: "Unauthorized", request_id: c.get("requestId") }, 401);
    }

    if (!skillBodyTemplate) {
      return c.json({ error: "Skill template not available", request_id: c.get("requestId") }, 500);
    }

    const situationTable = renderSituationTable(policies, auth.policies);
    const body = skillBodyTemplate.replaceAll("{{SITUATION_TABLE}}", situationTable);

    audit.log({
      identity: auth.identity,
      action: "skill.fetch",
      source_ip: (c.get("sourceIp") as string) || null,
      metadata: { policies: auth.policies.join(",") },
    });

    c.header("Content-Type", "text/markdown; charset=utf-8");
    c.header("Cache-Control", "no-store");
    return c.body(body);
  });

  return router;
}
