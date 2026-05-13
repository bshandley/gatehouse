export interface AppRoleLimits {
  per_minute: number | null;
  per_hour: number | null;
  per_day: number | null;
}

export type LimitKind = "approle_minute" | "approle_hour" | "approle_day" | "secret_minute";

export interface RateLimitDecision {
  allowed: boolean;
  reason?: string;
  limitKind?: LimitKind;
  retryAfterSeconds?: number;
  current?: number;
  limit?: number;
}

// Fixed windows keyed on Math.floor(now / window_ms): when the epoch rolls,
// counter resets to zero. Cheaper than a sliding window and the burst-at-the-
// boundary behaviour is acceptable for proxy throttling at this scale.
const MINUTE_MS = 60_000;
const HOUR_MS = 3_600_000;
const DAY_MS = 86_400_000;

interface WindowCounter {
  epoch: number;
  count: number;
}

interface ApproleCounters {
  minute: WindowCounter;
  hour: WindowCounter;
  day: WindowCounter;
}

interface SecretCounters {
  minute: WindowCounter;
}

function freshCounter(epoch: number): WindowCounter {
  return { epoch, count: 0 };
}

function retryAfterFor(epoch: number, windowMs: number, now: number): number {
  return Math.max(1, Math.ceil(((epoch + 1) * windowMs - now) / 1000));
}

function labelForWindow(windowMs: number): string {
  if (windowMs === MINUTE_MS) return "minute";
  if (windowMs === HOUR_MS) return "hour";
  return "day";
}

export class RateLimiter {
  private approles = new Map<string, ApproleCounters>();
  private secrets = new Map<string, SecretCounters>();

  checkApprole(roleId: string, limits: AppRoleLimits): RateLimitDecision {
    if (limits.per_minute === null && limits.per_hour === null && limits.per_day === null) {
      return { allowed: true };
    }

    const now = Date.now();
    const counters = this.approles.get(roleId);

    const axes: Array<{
      limit: number | null;
      windowMs: number;
      current: WindowCounter | undefined;
      kind: LimitKind;
    }> = [
      { limit: limits.per_minute, windowMs: MINUTE_MS, current: counters?.minute, kind: "approle_minute" },
      { limit: limits.per_hour, windowMs: HOUR_MS, current: counters?.hour, kind: "approle_hour" },
      { limit: limits.per_day, windowMs: DAY_MS, current: counters?.day, kind: "approle_day" },
    ];

    for (const axis of axes) {
      if (axis.limit === null) continue;
      const epoch = Math.floor(now / axis.windowMs);
      const live = axis.current && axis.current.epoch === epoch ? axis.current.count : 0;
      if (live >= axis.limit) {
        return {
          allowed: false,
          reason: `Rate limit exceeded: ${live} calls in the last ${labelForWindow(axis.windowMs)} (limit: ${axis.limit})`,
          limitKind: axis.kind,
          retryAfterSeconds: retryAfterFor(epoch, axis.windowMs, now),
          current: live,
          limit: axis.limit,
        };
      }
    }

    return { allowed: true };
  }

  checkSecret(path: string, perMinute: number | null): RateLimitDecision {
    // null or non-positive means "no limit" — skip state entirely so we don't
    // allocate a counter for unlimited secrets.
    if (perMinute === null || perMinute <= 0) return { allowed: true };

    const now = Date.now();
    const epoch = Math.floor(now / MINUTE_MS);
    const counters = this.secrets.get(path);
    const live = counters && counters.minute.epoch === epoch ? counters.minute.count : 0;

    if (live >= perMinute) {
      return {
        allowed: false,
        reason: `Rate limit exceeded: ${live} calls in the last minute (limit: ${perMinute})`,
        limitKind: "secret_minute",
        retryAfterSeconds: retryAfterFor(epoch, MINUTE_MS, now),
        current: live,
        limit: perMinute,
      };
    }

    return { allowed: true };
  }

  recordCall(roleId: string, paths: string[]): void {
    const now = Date.now();
    const minuteEpoch = Math.floor(now / MINUTE_MS);
    const hourEpoch = Math.floor(now / HOUR_MS);
    const dayEpoch = Math.floor(now / DAY_MS);

    // Empty roleId means root or user token — exempt, no AppRole counter.
    if (roleId !== "") {
      let counters = this.approles.get(roleId);
      if (!counters) {
        counters = {
          minute: freshCounter(minuteEpoch),
          hour: freshCounter(hourEpoch),
          day: freshCounter(dayEpoch),
        };
        this.approles.set(roleId, counters);
      }
      if (counters.minute.epoch !== minuteEpoch) counters.minute = freshCounter(minuteEpoch);
      if (counters.hour.epoch !== hourEpoch) counters.hour = freshCounter(hourEpoch);
      if (counters.day.epoch !== dayEpoch) counters.day = freshCounter(dayEpoch);
      counters.minute.count++;
      counters.hour.count++;
      counters.day.count++;
    }

    for (const path of paths) {
      let counters = this.secrets.get(path);
      if (!counters) {
        counters = { minute: freshCounter(minuteEpoch) };
        this.secrets.set(path, counters);
      }
      if (counters.minute.epoch !== minuteEpoch) counters.minute = freshCounter(minuteEpoch);
      counters.minute.count++;
    }
  }

  /** Test-only: drop all counters. */
  _reset(): void {
    this.approles.clear();
    this.secrets.clear();
  }
}

// Module-level singleton mirrors the cache pattern in src/settings/proxyLimits.ts.
// The proxy is in the hot path; one shared limiter keeps state global without
// threading it through every call site.
let sharedLimiter: RateLimiter | null = null;

export function getSharedRateLimiter(): RateLimiter {
  if (sharedLimiter === null) sharedLimiter = new RateLimiter();
  return sharedLimiter;
}

/** Test-only: drop the shared limiter so each test starts clean. */
export function _resetRateLimitsForTests(): void {
  sharedLimiter = null;
}
