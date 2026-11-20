import type { SecretsEngine } from "./engine";
import type { PolicyEngine } from "../policy/engine";

/**
 * Message for a 409 when `alias` belongs to a secret other than `ownPath`, or
 * null when the alias is free (or already this secret's own). The other
 * secret's path is named only if the writer could `list` it, so a 409 does not
 * reveal secrets the writer cannot see.
 */
export function aliasConflictMessage(
  secrets: SecretsEngine,
  policies: PolicyEngine,
  authPolicies: string[],
  alias: unknown,
  ownPath: string
): string | null {
  if (typeof alias !== "string" || alias === "") return null;
  const other = secrets.findByAlias(alias);
  if (!other || other.path === ownPath) return null;
  return genericOrNamed(policies, authPolicies, other.path);
}

function genericOrNamed(policies: PolicyEngine, authPolicies: string[], otherPath: string): string {
  return policies.check(authPolicies, otherPath, "list")
    ? `passthrough_alias is already in use by "${otherPath}"`
    : "passthrough_alias is already in use";
}

/** Message for a conflict caught from the unique index (race or rollback). */
export function aliasConflictFromError(
  secrets: SecretsEngine,
  policies: PolicyEngine,
  authPolicies: string[],
  alias: string | undefined,
  ownPath: string
): string {
  return (
    aliasConflictMessage(secrets, policies, authPolicies, alias, ownPath) ??
    "passthrough_alias is already in use"
  );
}
