import type { AppRoleLimits } from "./limiter";

export const HARD_CEILING_PER_MINUTE = 10_000;
export const HARD_CEILING_PER_HOUR = 100_000;
export const HARD_CEILING_PER_DAY = 1_000_000;
export const HARD_FLOOR = 1;

export type AppRoleLimitsValidation =
  | { ok: true; limits: AppRoleLimits }
  | { ok: false; error: string };

interface RawInput {
  rate_limit_per_minute?: unknown;
  rate_limit_per_hour?: unknown;
  rate_limit_per_day?: unknown;
}

// Returns null when the caller meant "no limit on this axis" — absent field,
// explicit null/undefined, or empty string. Returns a parsed integer otherwise.
// Returns the symbol `INVALID` when the value is present but unusable.
const INVALID = Symbol("invalid");

function coerceOptionalInt(value: unknown): number | null | typeof INVALID {
  if (value === undefined || value === null) return null;
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed === "") return null;
    if (!/^-?\d+$/.test(trimmed)) return INVALID;
    const n = Number(trimmed);
    return Number.isInteger(n) ? n : INVALID;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isInteger(value)) return INVALID;
    return value;
  }
  return INVALID;
}

function validateAxis(name: string, raw: unknown, ceiling: number): { value: number | null } | { error: string } {
  const coerced = coerceOptionalInt(raw);
  if (coerced === INVALID) {
    return { error: `${name} must be between ${HARD_FLOOR} and ${ceiling}` };
  }
  if (coerced === null) return { value: null };
  if (coerced < HARD_FLOOR || coerced > ceiling) {
    return { error: `${name} must be between ${HARD_FLOOR} and ${ceiling}` };
  }
  return { value: coerced };
}

/**
 * Parse and validate optional rate-limit fields from a request body.
 * Returns the cleaned AppRoleLimits or the first axis violation as an error
 * string for the API layer to surface as 400.
 */
export function validateAppRoleLimits(input: RawInput): AppRoleLimitsValidation {
  const minute = validateAxis("rate_limit_per_minute", input.rate_limit_per_minute, HARD_CEILING_PER_MINUTE);
  if ("error" in minute) return { ok: false, error: minute.error };

  const hour = validateAxis("rate_limit_per_hour", input.rate_limit_per_hour, HARD_CEILING_PER_HOUR);
  if ("error" in hour) return { ok: false, error: hour.error };

  const day = validateAxis("rate_limit_per_day", input.rate_limit_per_day, HARD_CEILING_PER_DAY);
  if ("error" in day) return { ok: false, error: day.error };

  return {
    ok: true,
    limits: {
      per_minute: minute.value,
      per_hour: hour.value,
      per_day: day.value,
    },
  };
}
