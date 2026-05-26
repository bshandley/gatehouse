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
 * The body lives in src/templates/skill.md and is also the canonical
 * source the onboarding flow points agents at (Step 3 of onboard.md
 * tells the agent to curl this endpoint).
 */

export function skillRouter(policies: PolicyEngine, audit: AuditLog) {
  const router = new Hono();

  const templateUrl = new URL("../templates/skill.md", import.meta.url).pathname;
  let skillBodyTemplate = "";
  Bun.file(templateUrl)
    .text()
    .then((t) => {
      skillBodyTemplate = t.trim();
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
