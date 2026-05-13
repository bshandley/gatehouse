import { describe, test, expect, beforeEach } from "bun:test";
import { RateLimiter, getSharedRateLimiter, _resetRateLimitsForTests } from "../src/rateLimits/limiter";
import { validateAppRoleLimits, HARD_CEILING_PER_MINUTE } from "../src/rateLimits/rateLimitValidation";

describe("RateLimiter.checkApprole", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    _resetRateLimitsForTests();
    limiter = new RateLimiter();
  });

  test("allows when all three limits are null", () => {
    const decision = limiter.checkApprole("role-x", {
      per_minute: null,
      per_hour: null,
      per_day: null,
    });
    expect(decision.allowed).toBe(true);
  });

  test("blocks once per_minute is exceeded", () => {
    const limits = { per_minute: 2, per_hour: null, per_day: null };

    // Two calls consume the budget.
    limiter.recordCall("role1", []);
    limiter.recordCall("role1", []);

    const blocked = limiter.checkApprole("role1", limits);
    expect(blocked.allowed).toBe(false);
    expect(blocked.limitKind).toBe("approle_minute");
    expect(blocked.current).toBe(2);
    expect(blocked.limit).toBe(2);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
    expect(blocked.retryAfterSeconds).toBeLessThanOrEqual(61);
  });

  test("checks each axis independently", () => {
    const limits = { per_minute: null, per_hour: 100, per_day: null };
    for (let i = 0; i < 100; i++) limiter.recordCall("role-h", []);
    const decision = limiter.checkApprole("role-h", limits);
    expect(decision.allowed).toBe(false);
    expect(decision.limitKind).toBe("approle_hour");
    expect(decision.limit).toBe(100);
  });

  test("empty roleId means no AppRole tracking", () => {
    // recordCall with "" should NOT track the AppRole counter.
    for (let i = 0; i < 5; i++) limiter.recordCall("", []);
    const decision = limiter.checkApprole("", { per_minute: 1, per_hour: null, per_day: null });
    expect(decision.allowed).toBe(true);
  });
});

describe("RateLimiter.checkSecret", () => {
  let limiter: RateLimiter;

  beforeEach(() => {
    _resetRateLimitsForTests();
    limiter = new RateLimiter();
  });

  test("null perMinute means allowed regardless of state", () => {
    for (let i = 0; i < 50; i++) limiter.recordCall("role", ["k/x"]);
    const d = limiter.checkSecret("k/x", null);
    expect(d.allowed).toBe(true);
  });

  test("blocks when perMinute reached", () => {
    for (let i = 0; i < 3; i++) limiter.recordCall("role", ["k/x"]);
    const d = limiter.checkSecret("k/x", 3);
    expect(d.allowed).toBe(false);
    expect(d.limitKind).toBe("secret_minute");
    expect(d.current).toBe(3);
    expect(d.limit).toBe(3);
  });

  test("zero or negative perMinute treated as no limit", () => {
    for (let i = 0; i < 10; i++) limiter.recordCall("role", ["k/y"]);
    expect(limiter.checkSecret("k/y", 0).allowed).toBe(true);
    expect(limiter.checkSecret("k/y", -1).allowed).toBe(true);
  });
});

describe("RateLimiter._reset and shared limiter", () => {
  test("_resetRateLimitsForTests clears shared state", () => {
    const a = getSharedRateLimiter();
    a.recordCall("role-shared", []);
    _resetRateLimitsForTests();
    const b = getSharedRateLimiter();
    // After reset, a fresh limiter is returned. Verify it has zero state.
    const d = b.checkApprole("role-shared", { per_minute: 1, per_hour: null, per_day: null });
    expect(d.allowed).toBe(true);
  });

  test("instance _reset() drops all counters", () => {
    const limiter = new RateLimiter();
    for (let i = 0; i < 3; i++) limiter.recordCall("r", ["s"]);
    limiter._reset();
    expect(limiter.checkApprole("r", { per_minute: 1, per_hour: null, per_day: null }).allowed).toBe(true);
    expect(limiter.checkSecret("s", 1).allowed).toBe(true);
  });
});

describe("validateAppRoleLimits", () => {
  test("empty input -> ok, all nulls", () => {
    const v = validateAppRoleLimits({});
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.limits).toEqual({ per_minute: null, per_hour: null, per_day: null });
    }
  });

  test("per_minute=5 -> ok, others null", () => {
    const v = validateAppRoleLimits({ rate_limit_per_minute: 5 });
    expect(v.ok).toBe(true);
    if (v.ok) {
      expect(v.limits.per_minute).toBe(5);
      expect(v.limits.per_hour).toBeNull();
      expect(v.limits.per_day).toBeNull();
    }
  });

  test("per_minute=0 rejected", () => {
    const v = validateAppRoleLimits({ rate_limit_per_minute: 0 });
    expect(v.ok).toBe(false);
  });

  test("per_minute above ceiling rejected", () => {
    const v = validateAppRoleLimits({ rate_limit_per_minute: HARD_CEILING_PER_MINUTE + 1 });
    expect(v.ok).toBe(false);
  });

  test("negative per_minute rejected", () => {
    const v = validateAppRoleLimits({ rate_limit_per_minute: -1 });
    expect(v.ok).toBe(false);
  });

  test("numeric string per_minute parsed", () => {
    const v = validateAppRoleLimits({ rate_limit_per_minute: "5" });
    expect(v.ok).toBe(true);
    if (v.ok) expect(v.limits.per_minute).toBe(5);
  });

  test("non-numeric string per_minute rejected", () => {
    const v = validateAppRoleLimits({ rate_limit_per_minute: "abc" });
    expect(v.ok).toBe(false);
  });
});
